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
#include "gpsserial.h"
#include "configfile.h"
#include "soundcontrol.h"
#include "packetchain.h"

int SerialGpsEvent(Timetracker::timer_event *evt, void *parm,
			 GlobalRegistry *globalreg) {
	GPSSerial *gps = (GPSSerial *) parm;

	return gps->Timer();
}

GPSSerial::GPSSerial() {
    fprintf(stderr, "FATAL OOPS: gpsserial called with no globalreg\n");
	exit(-1);
}

GPSSerial::GPSSerial(GlobalRegistry *in_globalreg) : GPSCore(in_globalreg) {
	// Make a serial port object
	sercli = new SerialClient(globalreg);
	netclient = sercli;

	last_disconnect = 0;
	last_hed_time = 0;

    // Attach it to ourselves and opposite
    RegisterNetworkClient(sercli);
    sercli->RegisterClientFramework(this);

	if (globalreg->kismet_config->FetchOpt("gpsdevice") == "") {
		_MSG("Missing 'gpsdevice' option in config, but gpstype set to serial",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	ScanOptions();
	RegisterComponents();

	gpseventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
											  &SerialGpsEvent, (void *) this);

	snprintf(device, 128, "%s", 
			 globalreg->kismet_config->FetchOpt("gpsdevice").c_str());

	if (Reconnect() < 0)
		return;

	last_mode = -1;

	if (last_disconnect == 0)
		_MSG("Using GPS device on " + string(device), MSGFLAG_INFO);
}

GPSSerial::~GPSSerial() {
	// Unregister ourselves from the main tcp service loop
	globalreg->RemovePollableSubsys(this);
}

int GPSSerial::Shutdown() {
    if (sercli != NULL) {
        sercli->FlushRings();
        sercli->KillConnection();
    }

    return 1;
}

int GPSSerial::Reconnect() {
	if (sercli->Connect(device, 0, NULL, NULL) < 0) {
		_MSG("GPSSerial: Could not open serial port " + string(device),
			 MSGFLAG_ERROR);
		if (reconnect_attempt < 0) {
			_MSG("GPSSerial: Reconnection not enabled (gpsreconnect), disabling "
				 "GPS", MSGFLAG_ERROR);

			last_disconnect = globalreg->timestamp.tv_sec;
			gps_connected = 0;

			return 0;
		}

	}

	// Reset the device options
	struct termios options;

	sercli->GetOptions(&options);

	options.c_oflag = 0;
	options.c_iflag = 0;
	options.c_iflag &= (IXON | IXOFF | IXANY);
	options.c_cflag |= CLOCAL | CREAD;
	options.c_cflag &= ~HUPCL;

	cfsetispeed(&options, B4800);
	cfsetospeed(&options, B4800);

	sercli->SetOptions(TCSANOW, &options);

	last_hed_time = 0;
	reconnect_attempt = 1;
	last_disconnect = 0;

	Timer();

    return 1;
}

int GPSSerial::ParseData() {
	int len, rlen;
	char *buf;

	double in_lat = 0, in_lon = 0, in_spd = 0, in_alt = 0;
	int in_mode = 0, set_data = 0, set_spd = 0, set_mode = 0;

	if (netclient == NULL)
		return 0;

	if (netclient->Valid() == 0)
		return 0;

	len = netclient->FetchReadLen();
	buf = new char[len + 1];

	if (netclient->ReadData(buf, len, &rlen) < 0) {
		_MSG("GPSSerial parser failed to get data from the serial port",
			 MSGFLAG_ERROR);
    delete[] buf;
		return -1;
	}

	buf[len] = '\0';

	vector<string> inptok = StrTokenize(buf, "\n", 0);
	delete[] buf;

	if (inptok.size() < 1) {
		return 0;
	}

	set_data = 0;
	set_spd = 0;
	set_mode = 0;

	for (unsigned int it = 0; it < inptok.size(); it++) {
		if (netclient->Valid()) {
			netclient->MarkRead(inptok[it].length() + 1);
		}

		// If we've seen anything off the serial declare that we've seen the
		// gps in some state so we report that we have one
		gps_ever_lock = 1;

		if (inptok[it].length() < 4)
			continue;

		// $GPGGA,012527.000,4142.6918,N,07355.8711,W,1,07,1.2,57.8,M,-34.0,M,,0000*57

		vector<string> gpstoks = StrTokenize(inptok[it], ",");

		if (gpstoks.size() == 0)
			continue;

		if (gpstoks[0] == "$GPGGA") {
			int tint;
			float tfloat;

			gps_connected = 1;

			if (gpstoks.size() < 15)
				continue;

			// Parse the basic gps coodinate string
			// $GPGGA,time,lat,NS,lon,EW,quality,#sats,hdop,alt,M,geopos,M,
			// dgps1,dgps2,checksum

			if (sscanf(gpstoks[2].c_str(), "%2d%f", &tint, &tfloat) != 2)
				continue;
			in_lat = (float) tint + (tfloat / 60);
			if (gpstoks[3] == "S")
				in_lat = in_lat * -1;

			if (sscanf(gpstoks[4].c_str(), "%3d%f", &tint, &tfloat) != 2)
				continue;
			in_lon = (float) tint + (tfloat / 60);
			if (gpstoks[5] == "W")
				in_lon = in_lon * -1;

			if (sscanf(gpstoks[9].c_str(), "%f", &tfloat) != 1)
				continue;
			in_alt = tfloat;

			// printf("debug - %f, %f alt %f\n", in_lat, in_lon, in_alt);
			set_data = 1;

			continue;
		}

		if (gpstoks[0] == "$GPRMC") {
			// recommended minimum
			// $GPRMC,time,valid,lat,lathemi,lon,lonhemi,speed-knots,bearing,utc,,checksum
			int tint;
			float tfloat;
			
			gps_connected = 1;

			if (gpstoks.size() < 12)
				continue;

			if (gpstoks[2] == "A") {
				// Kluge - if we have a 3d fix, we're getting another sentence
				// which contains better information, so we don't override it. 
				// If we < a 2d fix, we up it to 2d.
				if (last_mode < 3) {
					in_mode = 2;
					set_mode = 1;
				} 
			} else {
				continue;
			}

			if (sscanf(gpstoks[3].c_str(), "%2d%f", &tint, &tfloat) != 2)
				continue;
			in_lat = (float) tint + (tfloat / 60);
			if (gpstoks[4] == "S")
				in_lat = in_lat * -1;

			if (sscanf(gpstoks[5].c_str(), "%3d%f", &tint, &tfloat) != 2)
				continue;
			in_lon = (float) tint + (tfloat / 60);
			if (gpstoks[6] == "W")
				in_lon = in_lon * -1;

			if (sscanf(gpstoks[7].c_str(), "%f", &tfloat) != 1) 
				continue;
			in_spd = tfloat;
			set_spd = 1;

			// Inherit the altitude we had before since this sentence doesn't
			// have any alt records
			in_alt = alt;

			// printf("debug - %f, %f spd %f\n", in_lat, in_lon, in_spd);
			set_data = 1;

			continue;
		}

		// GPS DOP and active sats
		if (gpstoks[0] == "$GPGSA") {
			/*
			http://www.gpsinformation.org/dale/nmea.htm#GSA
		    $GPGSA,A,3,04,05,,09,12,,,24,,,,,2.5,1.3,2.1*39

			Where:
			GSA      Satellite status
			A        Auto selection of 2D or 3D fix (M = manual) 
			3        3D fix - values include: 1 = no fix
			2 = 2D fix
			3 = 3D fix
			04,05... PRNs of satellites used for fix (space for 12) 
			2.5      PDOP (dilution of precision) 
			1.3      Horizontal dilution of precision (HDOP) 
			2.1      Vertical dilution of precision (VDOP)
		    *39      the checksum data, always begins with *
			 */
			int tint;

			gps_connected = 1;

			if (gpstoks.size() < 18)
				continue;

			if (sscanf(gpstoks[2].c_str(), "%d", &tint) != 1)
				continue;

			/* Account for jitter after the first set */
			if (tint >= last_mode) {
				in_mode = tint;
				last_mode = tint;
				set_mode = 1;
				// printf("debug - mode %d\n", in_mode);
			} else {
				last_mode = tint;
			}
		}

		// Travel made good
		if (gpstoks[0] == "$GPVTG") {
			// $GPVTG,,T,,M,0.00,N,0.0,K,A*13
			float tfloat;

			if (gpstoks.size() < 10) {
				continue;
			}

			if (set_spd == 0) {
				if (sscanf(gpstoks[7].c_str(), "%f", &tfloat) != 1) 
					continue;
				in_spd = tfloat;
				set_spd = 1;
			}

			continue;
		} else if (inptok[it].substr(0, 6) == "$GPGSV") {
			// $GPGSV,3,1,09,22,80,170,40,14,58,305,19,01,46,291,,18,44,140,33*7B
			// $GPGSV,3,2,09,05,39,105,31,12,34,088,32,30,31,137,31,09,26,047,34*72
			// $GPGSV,3,3,09,31,26,222,31*46
			//
			// # of sentences for data
			// sentence #
			// # of sats in view
			//
			// sat #
			// elevation
			// azimuth
			// snr

			vector<string> svvec = StrTokenize(inptok[it], ",");
			GPSCore::sat_pos sp;

			gps_connected = 1;

			if (svvec.size() < 6) {
				continue;
			}

			// If we're on the last sentence, move the new vec to the transmitted one
			if (svvec[1] == svvec[2]) {
				sat_pos_map = sat_pos_map_tmp;
				sat_pos_map_tmp.clear();
			}

			unsigned int pos = 4;
			while (pos + 4 < svvec.size()) {
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.prn) != 1) 
					break;
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.elevation) != 1)
					break;
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.azimuth) != 1)
					break;
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.snr) != 1)
					sp.snr = 0;

				sat_pos_map_tmp[sp.prn] = sp;
			}

			continue;
		}

	}

	if (set_data) {
		last_lat = lat;
		lat = in_lat;
		last_lon = lon;
		lon = in_lon;

		alt = in_alt;

		last_hed = hed;
		hed = CalcHeading(lat, lon, last_lat, last_lon);
	}

	if (set_mode) {
        if (mode < 2 && (gps_options & GPSD_OPT_FORCEMODE)) {
            mode = 2;
        } else {
            if (mode < 2 && in_mode >= 2) {
                    globalreg->soundctl->SayText("Got G P S position fix");
                    globalreg->soundctl->PlaySound("gpslock");
            } else if (mode >= 2 && in_mode < 2) {
                    globalreg->soundctl->SayText("Lost G P S position fix");
                    globalreg->soundctl->PlaySound("gpslost");
            }
            mode = in_mode;
        }
	}

	// This is always in knots from nmea, convert to meters/sec like gpsd uses */
	if (set_spd)
		spd = in_spd * 0.514;

	if (set_data) {
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


    return 1;
}

int GPSSerial::Timer() {
	// fprintf(stderr, "debug - serial timer valid %d attempt %d last time %d\n", netclient->Valid(), reconnect_attempt, last_disconnect);
    // Timed backoff up to 30 seconds
    if (netclient->Valid() == 0 && reconnect_attempt >= 0 &&
        (globalreg->timestamp.tv_sec - last_disconnect >= 
		 (kismin(reconnect_attempt, 6) * 5))) {
		// fprintf(stderr, "debug - serial reconnect?\n");
        if (Reconnect() <= 0)
            return 1;
    }

	GPSCore::Timer();

	return 1;
}

