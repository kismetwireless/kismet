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

#ifdef HAVE_GPS

GPSD::GPSD(char *in_host, int in_port) {
    sock = -1;
    lat = lon = alt = spd = hed = 0;
    mode = -1;
    last_lat = last_lon = last_hed = 0;

    sock = -1;
    errstr[0] = '\0';
    data[0] = '\0';

    host = strdup(in_host);
    port = in_port;
}

GPSD::~GPSD(void) {
    if (sock != -1)
        close(sock);

    sock = -1;
}

char *GPSD::FetchError() {
    return errstr;
}

int GPSD::OpenGPSD() {
    if (sock)
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

    // Kick a command off into the system, too
    if (write(sock, gpsd_command, sizeof(gpsd_command)) < 0) {
        if (errno != EAGAIN) {
            snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
            CloseGPSD();
            return -1;
        }
    }

    return 1;
}

int GPSD::CloseGPSD() {
    if (sock != -1)
        close(sock);

    sock = -1;

    return 1;
}

// The guts of it
int GPSD::Scan() {
    char buf[1024];
    int ret;

    if (sock < 0) {
        lat = lon = alt = spd = 0;
        mode = 0;
        hed = 0;
        return -1;
    }

    // Read as much as we have
    ret = read(sock, buf, 1024);
    if (ret <= 0 && errno != EAGAIN) {
        snprintf(errstr, 1024, "GPSD error reading data, aborting GPS");
        sock = -1;
		mode = 0;
        return -1;
    }

    // And reissue a command
    if (write(sock, gpsd_command, sizeof(gpsd_command)) < 0) {
        if (errno != EAGAIN) {
            snprintf(errstr, 1024, "GPSD error while writing data: %s", 
					 strerror(errno));
            CloseGPSD();
            return -1;
        }
    }

    // Combine it
    // What's wrong with this?  That's right, we're appending maxbuf to whatever the
    // buf was before.  Very much bad.
    //
    //    strncat(data, buf, 1024);

    // Instead, we'll munge them together safely, AND we'll catch if we've filled the
    // data buffer last time and still didn't get anything, if we did, we eliminate it
    // and we only work from the new data buffer.
	// and we only work from the new data buffer
    if (strlen(data) == 1024)
        data[0] = '\0';

    char concat[1024];
    snprintf(concat, 1024, "%s%s", data, buf);
    strncpy(data, concat, 1024);

    char *live;
    int scanret;

    if ((live = strstr(data, "GPSD,")) == NULL) {
        return 1;
    }

	// PAVMH (NAVLOCK,BU303) ->
	// GPSD,P=41.711592 -73.931137,A=49.500000,V=0.000000,M=x,M=x
    if ((scanret = sscanf(live, "GPSD,P=%f %f,A=%f,V=%f,M=%d,H=%f",
               &lat, &lon, &alt, &spd, &mode, &hed)) < 5) {

        lat = lon = spd = alt = hed = 0;
        mode = 0;
		data[0] = '\0';

        return 0;
    }

    spd = spd * (6076.12 / 5280);
    alt = alt * 3.3;

    // Blow up on nonsensical values
    if (finite(lat) == 0 || finite(lon) == 0 || finite(alt) == 0 ||
        finite(spd) == 0 || spd < 0 || spd > 150) {
        lat = lon = spd = alt = hed = 0;
        mode = 0;

        return 0;
    }

    if (last_lat == 0 && last_lon == 0) {
        last_lat = lat;
        last_lon = lon;
    }

    if (scanret == 5) {
        // Calculate the heading
        hed = last_hed;

        // Update the last lat and heading if we've moved more than 10 meters
        if (EarthDistance(lat, lon, last_lat, last_lon) > 10) {
            hed = CalcHeading(lat, lon, last_lat, last_lon);

            last_lat = lat;
            last_lon = lon;
        }
    }

    // Override mode
    if ((options & GPSD_OPT_FORCEMODE) && mode == 0)
        mode = 2;

    // Zero the buffer
    buf[0] = '\0';
    data[0] = '\0';

    // And reissue a command
	/*
    if (write(sock, gpsd_command, sizeof(gpsd_command)) < 0) {
        if (errno != EAGAIN) {
            snprintf(errstr, 1024, "GPSD error while writing data: %s", 
					 strerror(errno));
            CloseGPSD();
            return -1;
        }
    }
	*/

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
    float r = CalcRad((float) in_lat2);

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
}

double GPSD::Rad2Deg(double x) {
    return (x/M_PI) * 180.0;
}

double GPSD::Deg2Rad(double x) {
    return 180/(x*M_PI);
}

double GPSD::EarthDistance(double in_lat, double in_lon, double in_lat2, double in_lon2) {
    double x1 = CalcRad(in_lat) * cos(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double x2 = CalcRad(in_lat2) * cos(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double y1 = CalcRad(in_lat) * sin(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double y2 = CalcRad(in_lat2) * sin(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double z1 = CalcRad(in_lat) * cos(Deg2Rad(90-in_lat));
    double z2 = CalcRad(in_lat2) * cos(Deg2Rad(90-in_lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(CalcRad((double) (in_lat+in_lat2)/2),2));
    return CalcRad((double) (in_lat+in_lat2) / 2) * a;
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

#endif
