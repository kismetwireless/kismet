/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"
#include "gpsd.h"

#include <string>
#include <vector>

#include "util.h"
#include "timetracker.h"

extern Timetracker timetracker;

int GpsPollEvent(Timetracker::timer_event *evt, void *parm) {
	((GPSD *) parm)->WritePoll();

	return 1;
}

GPSD::GPSD(char *in_host, int in_port) {
    sock = -1;
    lat = lon = alt = spd = hed = 0;
    mode = 0;
	last_mode = -1;
    last_lat = last_lon = last_hed = 0;

	poll_timer = -1;

    sock = -1;
	memset(errstr, 0, 1024);
	memset(data, 0, 1024);

    host = strdup(in_host);
    port = in_port;
}

GPSD::~GPSD(void) {
    if (sock >= 0) {
        close(sock);
		sock = -1;
	}

	if (poll_timer >= 0) {
		timetracker.RemoveTimer(poll_timer);
		poll_timer = -1;
	}
}

char *GPSD::FetchError() {
    return errstr;
}

int GPSD::OpenGPSD() {
    if (sock >= 0)
        close(sock);

    // Find our host
    h = gethostbyname(host);
    if (h == NULL) {
        snprintf(errstr, 1024, "GPSD unknown host '%s'", host);
        return -1;
    }

    // Fill in our server
    servaddr.sin_family = h->h_addrtype;
    memcpy((char *) &servaddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    servaddr.sin_port = htons(port);

    // Create the socket
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "GPSD cannot open socket: %s", strerror(errno));
        return -1;
    }

    // Bind to any local port
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port = htons(0);

    if (bind(sock, (struct sockaddr *) &localaddr, sizeof(localaddr)) < 0) {
        snprintf(errstr, 1024, "GPSD cannot bind port: %s", strerror(errno));
		CloseGPSD();
        return -1;
    }

    // Connect
    if (connect(sock, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        snprintf(errstr, 1024, "GPSD cannot connect: %s", strerror(errno));
        return -1;
    }

    // Set nonblocking mode
    int save_mode = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, save_mode | O_NONBLOCK);

    if (write(sock, gpsd_init_command, sizeof(gpsd_init_command)) < 0) {
        if (errno != EAGAIN) {
            snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
            CloseGPSD();
            return -1;
        }
    }

	data_pos = 0;
	poll_mode = 0;

	last_hed_time = 0;

    return 1;
}

int GPSD::CloseGPSD() {
    if (sock != -1)
        close(sock);

    sock = -1;

    return 1;
}

void GPSD::WritePoll() {
	if (write(sock, gpsd_poll_command, sizeof(gpsd_poll_command)) < 0) {
		if (errno != EAGAIN) {
			snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
			CloseGPSD();
		}
	}
}

unsigned int GPSD::MergeSet(fd_set *in_rset, fd_set *in_wset,
							unsigned int in_max) {

	if (sock < 0)
		return in_max;

	FD_SET(sock, in_rset);

	if ((int) in_max < sock)
		return (unsigned int) sock;

    return in_max;
}
// The guts of it
int GPSD::Poll(fd_set *in_rset, fd_set *in_wset) {
    int ret;
	float in_lat, in_lon, in_alt, in_spd, in_hed;
	int in_mode, use_alt = 1, use_spd = 1, use_hed = 1, use_data = 0,
		use_mode = 0, use_coord = 0;

    if (sock < 0) {
        lat = lon = alt = spd = 0;
        mode = 0;
        hed = 0;
        return -1;
    }

	if (FD_ISSET(sock, in_rset) == 0)
		return 0;

    // Read as much as we have
	if (data_pos == GPSD_MAX_DATASIZE)
		data_pos = 0;

	ret = read(sock, data, GPSD_MAX_DATASIZE - data_pos);
    if (ret <= 0 && errno != EAGAIN) {
        snprintf(errstr, 1024, "GPSD error reading data, aborting GPS");
        sock = -1;
		mode = 0;
        return -1;
    }

	data_pos += ret;

	// Terminate the buf, which is +1 the read size so terminating on the
	// read len is safe.
	data[data_pos] = '\0';

	// Tokenize it on \n and process each line
	vector<string> gpslines = StrTokenize(data, "\n", 0);
	
	if (gpslines.size() == 0)
		return 0;

	for (unsigned int x = 0; x < gpslines.size() && data_pos > 0; x++) {
		// Wipe out the previous buffer
		memmove(data, data + gpslines[x].length() + 1, 
				data_pos - (gpslines[x].length() + 1));
		data_pos -= (gpslines[x].length() + 1);

		if (gpslines[x] == "GPSD\r" && poll_mode == 0) {
			// Look for a really old gpsd which doesn't do anything useful
			// with the L command.  Only do it once, though, if we're already
			// in poll mode then this is probably from something else and we
			// don't need to keep flooding it with position requests
			poll_mode = 1;

			WritePoll();

			if (poll_timer < 0) 
				poll_timer = 
					timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &GpsPollEvent, this);
		} else if (gpslines[x].substr(0, 15) == "GPSD,L=2 1.0-25") {
			// Maemo ships a broken, broken, broken GPS which doesn't seem to
			// parse NMEA properly - Alt and Fix are not available in watcher
			// or polling modes, so we're going to have to kick it into "R" mode
			// and do NMEA locally
			if (write(sock, "R=1\n", 4) < 0) {
				if (errno != EAGAIN) {
					snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
					CloseGPSD();
					return -1;
				}
			}
		} else if (gpslines[x].substr(0, 7) == "GPSD,L=") {
			// Look for the version response
			vector<string> lvec = StrTokenize(gpslines[x], " ");
			int gma, gmi;

			if (lvec.size() < 3) {
				poll_mode = 1;
			} else if (sscanf(lvec[1].c_str(), "%d.%d", &gma, &gmi) != 2) {
				poll_mode = 1;
			} else if (gma < 2 || (gma == 2 && gmi < 34)) {
				poll_mode = 1;
			}

			// We got the version reply, write the optional setup commands, 
			// we don't care if they fail
			if (write(sock, gpsd_opt_commands, sizeof(gpsd_opt_commands)) < 0) {
				if (errno != EAGAIN) {
					snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
					CloseGPSD();
					return -1;
				}
			}

			// And then write the poll command if we need to
			if (poll_mode) {
				if (poll_timer < 0) 
					poll_timer = 
						timetracker.RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
												  &GpsPollEvent, this);
			} else {
				if (write(sock, gpsd_watch_command, sizeof(gpsd_watch_command)) < 0) {
					if (errno != EAGAIN) {
						snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
						CloseGPSD();
						return -1;
					}
				}
			}
				
			use_data = 0;
		} else if (gpslines[x].substr(0, 7) == "GPSD,P=") {
			// Poll lines
			vector<string> pollvec = StrTokenize(gpslines[x], ",");

			// Re-issue the poll command - throttled in stable by the
			// gpsevent timer in kismet_server/drone so this shouldn't flood
			if (write(sock, gpsd_poll_command, sizeof(gpsd_poll_command)) < 0) {
				if (errno != EAGAIN) {
					snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
					CloseGPSD();
					return -1;
				}
			}

			if (pollvec.size() < 5) {
				continue;
			}

			if (sscanf(pollvec[1].c_str(), "P=%f %f", &in_lat, &in_lon) != 2) {
				continue;
			}

			if (sscanf(pollvec[4].c_str(), "M=%d", &in_mode) != 1) {
				continue;
			}

			if (sscanf(pollvec[2].c_str(), "A=%f", &in_alt) != 1)
				use_alt = 0;

			if (sscanf(pollvec[3].c_str(), "V=%f", &in_spd) != 1)
				use_spd = 0;

			use_hed = 0;
			use_mode = 1;
			use_coord = 1;
			use_data = 1;

		} else if (gpslines[x].substr(0, 7) == "GPSD,O=") {
			// Look for O= watch lines
			vector<string> ggavec = StrTokenize(gpslines[x], " ");

			if (ggavec.size() < 15) {
				continue;
			}

			// Total fail if we can't get lat/lon/mode
			if (sscanf(ggavec[3].c_str(), "%f", &in_lat) != 1)
				continue;

			if (sscanf(ggavec[4].c_str(), "%f", &in_lon) != 1)
				continue;

			if (sscanf(ggavec[14].c_str(), "%d", &in_mode) != 1)
				continue;

			if (sscanf(ggavec[5].c_str(), "%f", &in_alt) != 1)
				use_alt = 0;

			if (sscanf(ggavec[8].c_str(), "%f", &in_hed) != 1)
				use_hed = 0;

			if (sscanf(ggavec[9].c_str(), "%f", &in_spd) != 1)
				use_spd = 0;

			use_mode = 1;
			use_coord = 1;
			use_data = 1;
		} else if (gpslines[x].substr(0, 6) == "$GPGSA") {
			vector<string> savec = StrTokenize(gpslines[x], ",");

			if (savec.size() != 18)
				continue;

			if (sscanf(savec[2].c_str(), "%d", &in_mode) != 1)
				continue;

			use_mode = 1;
			use_data = 1;
		} else if (gpslines[x].substr(0, 6) == "$GPVTG") {
			vector<string> vtvec = StrTokenize(gpslines[x], ",");

			if (vtvec.size() != 10)
				continue;

			if (sscanf(vtvec[7].c_str(), "%f", &in_spd) != 1)
				continue;

			use_spd = 1;
			use_data = 1;
		} else if (gpslines[x].substr(0, 6) == "$GPGGA") {
			vector<string> gavec = StrTokenize(gpslines[x], ",");
			int tint;
			float tfloat;

			if (gavec.size() != 15)
				continue;

			if (sscanf(gavec[2].c_str(), "%2d%f", &tint, &tfloat) != 2)
				continue;
			in_lat = (float) tint + (tfloat / 60);
			if (gavec[3] == "S")
				in_lat = in_lat * -1;

			if (sscanf(gavec[4].c_str(), "%3d%f", &tint, &tfloat) != 2)
				continue;
			in_lon = (float) tint + (tfloat / 60);
			if (gavec[5] == "W")
				in_lon = in_lon * -1;

			if (sscanf(gavec[9].c_str(), "%f", &tfloat) != 1)
				continue;
			in_alt = tfloat;

			use_coord = 1;
			use_alt = 1;
			use_data = 1;
		} 
	}

	if (use_data == 0)
		return 1;

    // Override mode && clean up the mode var
    if ((options & GPSD_OPT_FORCEMODE) && in_mode < 2) {
		in_mode = 2;
	} else if (in_mode < 2) {
		in_mode = 0;
	}

	// Some internal mode jitter protection, means our mode is slightly lagged
	if (use_mode) {
		if (in_mode >= last_mode) {
			last_mode = in_mode;
			mode = in_mode;
		} else {
			last_mode = in_mode;
		}
	} 

	if (use_alt && mode >= 3)
		alt = in_alt * 3.3;
	else if (mode < 3)
		alt = 0;

	if (use_spd)
		spd = in_spd * (6076.12 / 5280);

	if (use_hed) {
		last_hed = hed;
		hed = in_hed;
	} else if (poll_mode && use_coord) {
		// We only do manual heading calcs in poll mode
		if (last_hed_time == 0) {
			last_hed_time = time(0);
		} else if (time(0) - last_hed_time > 1) {
			// It's been more than a second since we updated the heading, so we
			// can back up the lat/lon and do hed calcs
			last_lat = lat;
			last_lon = lon;
			last_hed = hed;

			hed = CalcHeading(in_lat, in_lon, last_lat, last_lon);
			last_hed_time = time(0);
		}
	}

	// We always get these...  But we get them at the end so that we can
	// preserve our heading calculations
	if (use_coord) {
		lat = in_lat;
		lon = in_lon;
	}

    return 1;
}

int GPSD::FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, float *in_hed, int *in_mode) {
    *in_lat = lat;
    *in_lon = lon;
    *in_alt = alt;
    *in_spd = spd;
    *in_mode = mode;
    *in_hed = hed;

    return mode;
}

float GPSD::CalcHeading(float in_lat, float in_lon, float in_lat2, float in_lon2) {
	/* Liberally stolen from gpsdrives heading calculations */

    float r = CalcRad((float) in_lat2);

	float dir = 0.0;

	float tx =
		(2 * r * M_PI / 360) * cos (M_PI * in_lat / 180.0) *
		(in_lon - in_lon2);
	float ty = (2 * r * M_PI / 360) * (in_lat - in_lat2);

	if (((fabs(tx)) > 4.0) || (((fabs(ty)) > 4.0))) {
		if (ty == 0) {
			dir = 0.0;
		} else {
			dir = atan(tx / ty);
		}

		if (!finite(dir))
			dir = 0.0;
		if (ty < 0)
			dir = M_PI + dir;
		if (dir >= (2 * M_PI))
			dir -= 2 * M_PI;
		if (dir < 0)
			dir += 2 * M_PI;
	}

    return (float) Rad2Deg(dir);
	
#if 0
    float lat1 = Deg2Rad((float) in_lat);
    float lon1 = Deg2Rad((float) in_lon);
    float lat2 = Deg2Rad((float) in_lat2);
    float lon2 = Deg2Rad((float) in_lon2);

    float angle = 0;

	
    if (lat1 == lat2) {
        if (lon2 > lon1) {
            angle = M_PI/2;
        } else if (lon2 < lon1) {
            angle = 3 * M_PI / 2;
        } else {
            return 0;
        }
    } else if (lon1 == lon2) {
        if (lat2 > lat1) {
            angle = 0;
        } else if (lat2 < lat1) {
            angle = M_PI;
        }
    } else {
        float tx = r * cos((double) lat1) * (lon2 - lon1);
        float ty = r * (lat2 - lat1);
        angle = atan((double) (tx/ty));

        if (ty < 0) {
            angle += M_PI;
        }

        if (angle >= (2 * M_PI)) {
            angle -= (2 * M_PI);
        }

        if (angle < 0) {
            angle += 2 * M_PI;
        }

    }

    return (float) Rad2Deg(angle);
#endif
}

double GPSD::Rad2Deg(double x) {
    return (x/M_PI) * 180.0;
}

double GPSD::Deg2Rad(double x) {
    return 180/(x*M_PI);
}

double GPSD::EarthDistance(double in_lat, double in_lon, double in_lat2, 
						   double in_lon2) {
#if 0
    double x1 = CalcRad(in_lat) * cos(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double x2 = CalcRad(in_lat2) * cos(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double y1 = CalcRad(in_lat) * sin(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double y2 = CalcRad(in_lat2) * sin(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double z1 = CalcRad(in_lat) * cos(Deg2Rad(90-in_lat));
    double z2 = CalcRad(in_lat2) * cos(Deg2Rad(90-in_lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(CalcRad((double) (in_lat+in_lat2)/2),2));
    return CalcRad((double) (in_lat+in_lat2) / 2) * a;
#endif

	double x1 = in_lat * M_PI / 180;
	double y1 = in_lon * M_PI / 180;
	double x2 = in_lat2 * M_PI / 180;
	double y2 = in_lon2 * M_PI / 180;

	double dist = 0;

	if (x1 != x2 && y1 != y2) {
		dist = sin(x1) * sin(x2) + cos(x1) * cos(x2) * cos(y2 - y1);

		dist = CalcRad((double) (in_lat + in_lat2) / 2) * 
			(-1 * atan(dist / sqrt(1 - dist * dist)) + M_PI / 2);
	}

	return dist;
}

double GPSD::CalcRad(double lat) {
    double a = 6378.137, r, sc, x, y, z;
    double e2 = 0.081082 * 0.081082;
    /*
     the radius of curvature of an ellipsoidal Earth in the plane of the
     meridian is given by

     R' = a * (1 - e^2) / (1 - e^2 * (sin(lat))^2)^(3/2)

     where a is the equatorial radius,
     b is the polar radius, and
     e is the eccentricity of the ellipsoid = sqrt(1 - b^2/a^2)

     a = 6378 km (3963 mi) Equatorial radius (surface to center distance)
     b = 6356.752 km (3950 mi) Polar radius (surface to center distance)
     e = 0.081082 Eccentricity
     */

    lat = lat * M_PI / 180.0;
    sc = sin (lat);
    x = a * (1.0 - e2);
    z = 1.0 - e2 * sc * sc;
    y = pow (z, 1.5);
    r = x / y;

    r = r * 1000.0;
    return r;
}

