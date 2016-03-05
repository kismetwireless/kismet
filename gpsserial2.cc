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

#include "gpsserial2.h"
#include "util.h"

GPSSerialV2::GPSSerialV2(GlobalRegistry *in_globalreg) : Kis_Gps(in_globalreg) {
    globalreg = in_globalreg;

    // Defer making buffers until open, because we might be used to make a 
    // builder instance
    
    serialclient = NULL;
    serialhandler = NULL;
}

GPSSerialV2::~GPSSerialV2() {
    delete(serialclient);
    delete(serialhandler);
}

Kis_Gps *GPSSerialV2::BuildGps(string in_opts) {
    GPSSerialV2 *new_gps = new GPSSerialV2(globalreg);

    if (new_gps->OpenGps(in_opts) < 0) {
        delete new_gps;
        return NULL;
    }

    return new_gps;
}

int GPSSerialV2::OpenGps(string in_opts) {
    // Delete any existing serial interface before we parse options
    if (serialhandler != NULL) {
        delete serialhandler;
        serialhandler = NULL;
    }

    if (serialclient != NULL) {
        delete serialclient;
        serialclient = NULL;
    }

    // Now figure out if our options make sense... 
    vector<opt_pair> optvec;
    StringToOpts(in_opts, ",", &optvec);

    string proto_device;
    string proto_baud_s;
    string proto_name;
    unsigned int proto_baud;

    proto_device = FetchOpt("device", &optvec);
    proto_baud_s = FetchOpt("baud", &optvec);
    proto_name = FetchOpt("name", &optvec);

    if (proto_device == "") {
        _MSG("GPSSerial expected device= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_baud_s != "") {
        if (sscanf(proto_baud_s.c_str(), "%u", &proto_baud) != 1) {
            _MSG("GPSSerial expected baud rate in baud= option.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_baud = 4800;
        _MSG("GPSSerial defaulting to 4800 baud for GPS device, specify baud= option "
                "if your device uses a different speed.", MSGFLAG_INFO);
    }

    if (proto_name != "")
        name = proto_name;

    // We never write to a serial gps so don't make a write buffer
    serialhandler = new RingbufferHandler(2048, 0);
    // Set the read handler to us
    serialhandler->SetReadBufferInterface(this);
    // Link it to a serial port
    serialclient = new SerialClientV2(globalreg, serialhandler);
    serialclient->OpenDevice(proto_device, proto_baud);

    serial_device = proto_device;
    baud = proto_baud;

    return 1;
}

string GPSSerialV2::FetchGpsDescription() {
    stringstream str;

    str << "Serial " << serial_device << "@" << baud;

    return str.str();
}

bool GPSSerialV2::FetchGpsLocationValid() {
    return false;
}

bool GPSSerialV2::FetchGpsConnected() {
    if (serialclient == NULL)
        return false;

    return serialclient->FetchConnected();
}

void GPSSerialV2::BufferAvailable(size_t in_amt) {
    char *buf = new char[in_amt + 1];

    // Peek at the data
    serialhandler->PeekReadBufferData(buf, in_amt);

    // Force a null termination
    buf[in_amt] = 0;

	double in_lat = 0, in_lon = 0, in_spd = 0, in_alt = 0;
	int in_mode = 0, set_data = 0, set_spd = 0, set_mode = 0;
    int last_mode;
    bool gps_connected = false;

	vector<string> inptok = StrTokenize(buf, "\n", 0);
	delete[] buf;

	if (inptok.size() < 1) {
        return;
	}

	set_data = 0;
	set_spd = 0;
	set_mode = 0;

	for (unsigned int it = 0; it < inptok.size(); it++) {
        // Consume the data
        serialhandler->GetReadBufferData(NULL, inptok[it].length() + 1);

		if (inptok[it].length() < 4)
			continue;

		// $GPGGA,012527.000,4142.6918,N,07355.8711,W,1,07,1.2,57.8,M,-34.0,M,,0000*57

		vector<string> gpstoks = StrTokenize(inptok[it], ",");

		if (gpstoks.size() == 0)
			continue;

		if (gpstoks[0] == "$GPGGA") {
			int tint;
			float tfloat;

			gps_connected = true;

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
            // TODO alt
			in_alt = 0;

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

#if 0
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
#endif

			continue;
		}

	}

    if (set_data) {
        printf("lat %f lon %f alt %f speed %f\n", in_lat, in_lon, in_alt, in_spd);
    }

#if 0
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
#endif
}

