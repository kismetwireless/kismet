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

// CURRENTLY DISABLED
//
// libgps has some stability issues which are being addressed, until then, this
// is disabled and normal gpsdclient code is used

#include "config.h"

#ifdef HAVE_LIBGPS

#include "gpsdlibgps.h"
#include "configfile.h"
#include "soundcontrol.h"
#include "packetchain.h"

int LibGpsEvent(Timetracker::timer_event *evt, void *parm,
			 GlobalRegistry *globalreg) {
	GPSLibGPS *gps = (GPSLibGPS *) parm;

	return gps->Timer();
}

GPSLibGPS::GPSLibGPS() {
    fprintf(stderr, "FATAL OOPS: gpslibgps called with no globalreg\n");
	exit(-1);
}

GPSLibGPS::GPSLibGPS(GlobalRegistry *in_globalreg) : GPSCore(in_globalreg) {
	lgpst = NULL;
	lgpst_started = 0;

	last_disconnect = globalreg->timestamp.tv_sec;

	char temphost[129];
	char tempport[6];
	if (sscanf(globalreg->kismet_config->FetchOpt("gpshost").c_str(), 
			   "%128[^:]:%6s", temphost, tempport) != 2) {
		globalreg->messagebus->InjectMessage("Invalid GPS host in config, "
											 "host:port required",
											 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}
	host = string(temphost);
	port = string(tempport);

	ScanOptions();
	RegisterComponents();

	gpseventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
											  &LibGpsEvent, (void *) this);

	if (Reconnect() < 0)
		return;

	last_mode = -1;

	if (last_disconnect == 0)
		_MSG("Using GPSD on " + host + " " + port, MSGFLAG_INFO);
}

GPSLibGPS::~GPSLibGPS() {
	// Unregister ourselves from the main tcp service loop
	globalreg->RemovePollableSubsys(this);

	if (lgpst) {
		gps_close(lgpst);
		lgpst = NULL;
	}
}

int GPSLibGPS::Shutdown() {
	if (lgpst) {
		gps_close(lgpst);
		lgpst = NULL;
	}

    return 1;
}

int GPSLibGPS::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
	if (lgpst) {
		FD_SET(lgpst->gps_fd, out_rset);

		if (lgpst_started == 0)
			FD_SET(lgpst->gps_fd, out_wset);

		if (lgpst->gps_fd > in_max_fd)
			return lgpst->gps_fd;
	}

	return in_max_fd;
}

int GPSLibGPS::Poll(fd_set& in_rset, fd_set& in_wset) {
	int ret;
	float in_lat, in_lon, in_alt, in_spd, in_hed, in_hdop, in_vdop;
	int in_mode, use_alt = 1, use_spd = 1, use_hed = 1, use_data = 0,
		use_mode = 0, use_coord = 0, use_dop = 0;;

	if (lgpst == NULL)
		return -1;

	if (FD_ISSET(lgpst->gps_fd, &in_wset)) {
		gps_stream(lgpst, WATCH_ENABLE, NULL);
		lgpst_started = 1;
	}

	if (FD_ISSET(lgpst->gps_fd, &in_rset)) {
		if ((ret = gps_poll(lgpst)) < 0) {
			_MSG("Failed to fetch GPS data: " + string(gps_errstr(ret)),
				 MSGFLAG_ERROR);
			gps_close(lgpst);
			lgpst = NULL;
			last_disconnect = globalreg->timestamp.tv_sec;
		}

		if (lgpst->set & LATLON_SET) {
			use_mode = 1;
			in_mode = lgpst->fix.mode;

			use_data = 1;
			use_coord = 1;

			in_lat = lgpst->fix.latitude;
			in_lon = lgpst->fix.longitude;
		} 

		if ((lgpst->set & HERR_SET) && (lgpst->set & VERR_SET) &&
			isnan(lgpst->fix.epy) == 0 && isnan(lgpst->fix.epx)) {
			use_dop = 1;

			in_hdop = lgpst->fix.epx;
			in_vdop = lgpst->fix.epy;
		}

		if (lgpst->set & TRACK_SET) {
			use_hed = 1;

			in_hed = lgpst->fix.track;
		}

		if (lgpst->set & ALTITUDE_SET) {
			use_alt = 1;
			in_alt = lgpst->fix.altitude;
		}

		if (lgpst->set & SPEED_SET) {
			use_spd = 1;
			in_spd = lgpst->fix.speed;
		}

		if (lgpst->set & SATELLITE_SET) {
			GPSCore::sat_pos sp;
			sat_pos_map.clear();

			for (int x = 0; x < lgpst->satellites_visible; x++) {
				sp.prn = lgpst->PRN[x];
				sp.elevation = lgpst->elevation[x];
				sp.azimuth = lgpst->azimuth[x];
				sp.snr = (int) lgpst->ss[x];

				sat_pos_map[sp.prn] = sp;
			}
		}
	}

	if (in_alt == 0 && in_lat == 0 && in_lon == 0)
		use_data = 0;

	if (use_data == 0)
		return 1;

	if ((gps_options & GPSD_OPT_FORCEMODE) && in_mode < 2) {
		in_mode = 2;
	} else if (in_mode < 2) {
		in_mode = 0;
	}

	if (use_dop) {
		hdop = in_hdop;
		vdop = in_vdop;
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

	// Return metric for now
	if (use_alt)
		alt = in_alt; // * 3.3;

	if (use_hed) {
		last_hed = hed;
		hed = in_hed;
	} else if (use_coord) {
		if (last_hed_time == 0) {
			last_hed_time = globalreg->timestamp.tv_sec;
		} else if (globalreg->timestamp.tv_sec - last_hed_time > 1) {
			// It's been more than a second since we updated the heading, so we
			// can back up the lat/lon and do hed calcs
			last_lat = lat;
			last_lon = lon;
			last_hed = hed;

			hed = CalcHeading(in_lat, in_lon, last_lat, last_lon);
			last_hed_time = globalreg->timestamp.tv_sec;
		}
	}

	// We always get these...  But we get them at the end so that we can
	// preserve our heading calculations
	if (use_coord) {
		lat = in_lat;
		lon = in_lon;
		
		// Update the "did we ever get anything" so we say "no fix" not "no gps"
		// as soon as we get a valid sentence of any sort
		gps_ever_lock = 1;
	}

	return 0;
}

int GPSLibGPS::ParseData() {
	// This all gets done in poll

	return 0;
}

int GPSLibGPS::Reconnect() {
	if (lgpst) {
		gps_close(lgpst);
	}

	lgpst_started = 0;

	if ((lgpst = gps_open(host.c_str(), port.c_str())) == NULL) {
		_MSG("GPSD: Could not connect to " + host + ":" + port + " - " + 
			 string(gps_errstr(errno)), MSGFLAG_ERROR);

		last_disconnect = globalreg->timestamp.tv_sec;

		return 0;
	}

	last_disconnect = 0;
	reconnect_attempt = 1;
	last_hed_time = 0;

	Timer();

    return 1;
}

int GPSLibGPS::Timer() {
    // Timed backoff up to 30 seconds
	if (lgpst == NULL && reconnect_attempt >= 0 &&
        (globalreg->timestamp.tv_sec - last_disconnect >= 
		 (kismin(reconnect_attempt, 6) * 5))) {

        if (Reconnect() <= 0) {
			reconnect_attempt++;
            return 1;
		}
    }

	GPSCore::Timer();

	return 1;
}

#endif

