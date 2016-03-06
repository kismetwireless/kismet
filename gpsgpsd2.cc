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

#include "gpsgpsd2.h"
#include "util.h"
#include "gps_manager.h"
#include "kismet_json.h"

GPSGpsdV2::GPSGpsdV2(GlobalRegistry *in_globalreg) : Kis_Gps(in_globalreg) {
    globalreg = in_globalreg;

    // Defer making buffers until open, because we might be used to make a 
    // builder instance
   
    tcpclient = NULL;
    tcphandler = NULL;

    last_heading_time = globalreg->timestamp.tv_sec;

    poll_mode = 0;
    si_units = 0;
    si_raw = 0;
}

GPSGpsdV2::~GPSGpsdV2() {
    delete(tcpclient);
    delete(tcphandler);
}

Kis_Gps *GPSGpsdV2::BuildGps(string in_opts) {
    GPSGpsdV2 *new_gps = new GPSGpsdV2(globalreg);

    if (new_gps->OpenGps(in_opts) < 0) {
        delete new_gps;
        return NULL;
    }

    return new_gps;
}

int GPSGpsdV2::OpenGps(string in_opts) {
    // Delete any existing serial interface before we parse options
    if (tcphandler != NULL) {
        delete tcphandler;
        tcphandler = NULL;
    }

    if (tcpclient != NULL) {
        delete tcpclient;
        tcpclient = NULL;
    }

    // Now figure out if our options make sense... 
    vector<opt_pair> optvec;
    StringToOpts(in_opts, ",", &optvec);

    string proto_host;
    string proto_port_s;
    unsigned int proto_port;

    proto_host = FetchOpt("host", &optvec);
    proto_port_s = FetchOpt("port", &optvec);

    if (proto_host == "") {
        _MSG("GPSGpsdV2 expected host= option, none found.", MSGFLAG_ERROR);
        return -1;
    }

    if (proto_port_s != "") {
        if (sscanf(proto_port_s.c_str(), "%u", &proto_port) != 1) {
            _MSG("GPSGpsdV2 expected port in port= option.", MSGFLAG_ERROR);
            return -1;
        }
    } else {
        proto_port = 2947;
        _MSG("GPSGpsdV2 defaulting to port 2947, set the port= option if "
                "your gpsd is on a different port", MSGFLAG_INFO);
    }

    // GPSD network connection writes data as well as reading, but most of it is
    // inbound data
    tcphandler = new RingbufferHandler(4096, 512);
    // Set the read handler to us
    tcphandler->SetReadBufferInterface(this);
    // Link it to a tcp connection
    tcpclient = new TcpClientV2(globalreg, tcphandler);
    tcpclient->Connect(proto_host, proto_port);

    host = proto_host;
    port = proto_port;

    stringstream msg;
    msg << "GPSGpsdV2 connecting to GPSD server on " << host << ":" << port;
    _MSG(msg.str(), MSGFLAG_INFO);

    return 1;
}

string GPSGpsdV2::FetchGpsDescription() {
    stringstream str;

    str << "GPSD " << host << ":" << port;

    return str.str();
}

bool GPSGpsdV2::FetchGpsLocationValid() {
    if (gps_location == NULL) {
        return false;
    }

    if (gps_location->fix < 2) {
        return false;
    }

    // If a location is older than 10 seconds, it's no good anymore
    if (globalreg->timestamp.tv_sec - gps_location->time > 10) {
        return false;
    }

    return true;
}

bool GPSGpsdV2::FetchGpsConnected() {
    if (tcpclient == NULL)
        return false;

    return tcpclient->FetchConnected();
}

void GPSGpsdV2::BufferAvailable(size_t in_amt) {
    char *buf = new char[in_amt + 1];

    // Peek at the data
    tcphandler->PeekReadBufferData(buf, in_amt);

    // Force a null termination
    buf[in_amt] = 0;

    // Aggregate into a new location; then copy into the main location
    // depending on what we found.  Locations can come in multiple sentences
    // so if we're within a second of the previous one we can aggregate them
    kis_gps_packinfo *new_location = new kis_gps_packinfo;
    bool set_lat_lon;
    bool set_alt;
    bool set_speed;
    bool set_fix;
    bool set_heading;

	vector<string> inptok = StrTokenize(buf, "\n", 0);
	delete[] buf;

	if (inptok.size() < 1) {
        return;
	}

    set_lat_lon = false;
    set_alt = false;
    set_speed = false;
    set_fix = false;
    set_heading = false;

	for (unsigned int it = 0; it < inptok.size(); it++) {
        // Consume the data from the ringbuffer
        tcphandler->GetReadBufferData(NULL, inptok[it].length() + 1);

        // Trip the garbage out of it
        inptok[it] = StrPrintable(inptok[it]);

        // We don't know what we're going to get from GPSD.  If it starts with 
        // { then it probably is json, try to parse it
		if (inptok[it][0] == '{') {
			struct JSON_value *json;
			string err;

			json = JSON_parse(inptok[it], err);

			if (err.length() != 0) {
				_MSG("GPSGpsdV2 - Invalid JSON data block from GPSD: " + err, 
                        MSGFLAG_ERROR);
				continue;
			}  

#if 0
			fprintf(stderr, "debug - GPS JSON:\n");
			JSON_dump(json, "", 0);
#endif

			string msg_class = JSON_dict_get_string(json, "class", err);

			if (msg_class == "VERSION") {
				_MSG("GPSGpsdV2 connected to a JSON-enabled GPSD version " +
					 MungeToPrintable(JSON_dict_get_string(json, "release", err)) + 
					 ", turning on JSON mode", MSGFLAG_INFO);
				// Set JSON mode
				poll_mode = 10;
				// We get speed in meters/sec
				si_units = 1;

                // Send a JSON message that we want future communication in JSON
                string json_msg = "?WATCH={\"json\":true};\n";

                if (tcphandler->PutWriteBufferData((void *) json_msg.c_str(), 
                            json_msg.length()) < json_msg.length()) {
                    _MSG("GPSGpsdV2 could not not write JSON enable command",
                            MSGFLAG_ERROR);
                }
			} else if (msg_class == "TPV") {
				float n;

				n = JSON_dict_get_number(json, "mode", err);
				if (err.length() == 0) {
                    new_location->fix = (int) n;
                    set_fix = true;
				}

				// If we have a valid alt, use it
				if (set_fix && new_location->fix > 2) {
					n = JSON_dict_get_number(json, "alt", err);
					if (err.length() == 0) {
                        new_location->alt = n;
                        set_alt = true;
					}
				} 

				if (set_fix && new_location->fix >= 2) {
					// If we have LAT and LON, use them
					n = JSON_dict_get_number(json, "lat", err);
					if (err.length() == 0) {
                        new_location->lat = n;

						n = JSON_dict_get_number(json, "lon", err);
						if (err.length() == 0) {
                            new_location->lon = n;

                            set_lat_lon = true;
						}
					}

#if 0
					// If we have HDOP and VDOP, use them
					n = JSON_dict_get_number(json, "epx", err);
					if (err.length() == 0) {
						in_hdop = n;

						n = JSON_dict_get_number(json, "epy", err);
						if (err.length() == 0) {
							in_vdop = n;

							use_dop = 1;
						}
					}
#endif

					// Heading (track in gpsd speak)
					n = JSON_dict_get_number(json, "track", err);
					if (err.length() == 0) {
                        new_location->heading = n;
                        set_heading = true;
					}

					// Speed
					n = JSON_dict_get_number(json, "speed", err);
					if (err.length() == 0) {
                        new_location->speed = n;
                        set_speed = true;
					} 
				}
#if 0
			} else if (msg_class == "SKY") {
				GPSCore::sat_pos sp;
				struct JSON_value *v = NULL, *s = NULL;

				gps_connected = 1;

				v = JSON_dict_get_value(json, "satellites", err);

				if (err.length() == 0 && v != NULL) {
					sat_pos_map.clear();

					if (v->value.tok_type == JSON_arrstart) {
						for (unsigned int z = 0; z < v->value_array.size(); z++) {
							float prn, ele, az, snr;
							int valid = 1;

							s = v->value_array[z];

							// If we're not a dictionary in the sat array, skip
							if (s->value.tok_type != JSON_start) {
								continue;
							}

							prn = JSON_dict_get_number(s, "PRN", err);
							if (err.length() != 0) 
								valid = 0;

							ele = JSON_dict_get_number(s, "el", err);
							if (err.length() != 0)
								valid = 0;

							az = JSON_dict_get_number(s, "az", err);
							if (err.length() != 0)
								valid = 0;

							snr = JSON_dict_get_number(s, "ss", err);
							if (err.length() != 0)
								valid = 0;

							if (valid) {
								sp.prn = prn;
								sp.elevation = ele;
								sp.azimuth = az;
								sp.snr = snr;

								sat_pos_map[prn] = sp;
							}
						}

					}

				}
#endif
			}

			JSON_delete(json);
		} else if (poll_mode == 0 && inptok[it] == "GPSD") {
			// Look for a really old gpsd which doesn't do anything intelligent
			// with the L (version) command.  Only do this once, if we've already
			// figured out a poll mode then there's not much point in hammering
			// the server.  Force us into watch mode.

			poll_mode = 1;

            string init_cmd = "L\n";
            if (tcphandler->PutWriteBufferData((void *) init_cmd.c_str(), 
                        init_cmd.length()) < init_cmd.length()) {
                _MSG("GPSGpsdV2 could not not write NMEA enable command",
                        MSGFLAG_ERROR);
            }

			continue;
		} else if (poll_mode < 10 && inptok[it].substr(0, 15) == "GPSD,L=2 1.0-25") {
			// Maemo ships a broken,broken GPS which doesn't parse NMEA correctly
			// and results in no alt or fix in watcher or polling modes, so we
			// have to detect this version and kick it into debug R=1 mode
			// and do NMEA ourselves.
            string cmd = "R=1\n";
            if (tcphandler->PutWriteBufferData((void *) cmd.c_str(), 
                        cmd.length()) < cmd.length()) {
                _MSG("GPSGpsdV2 could not not write NMEA enable command",
                        MSGFLAG_ERROR);
            }

			// Use raw for position
			si_raw = 1;
		} else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,L=") {
			// Look for the version response
			vector<string> lvec = StrTokenize(inptok[it], " ");
			int gma, gmi;

			if (lvec.size() < 3) {
				poll_mode = 1;
			} else if (sscanf(lvec[1].c_str(), "%d.%d", &gma, &gmi) != 2) {
				poll_mode = 1;
			} else {
				if (gma < 2 || (gma == 2 && gmi < 34)) {
					poll_mode = 1;
				}
				// Since GPSD r2368 'O' gives the speed as m/s instead of knots
				if (gma > 2 || (gma == 2 && gmi >= 31)) {
					si_units = 1;
				}
			}

			// Don't use raw for position
			si_raw = 0;

			// If we're still in poll mode 0, write the watcher command.
			// This has been merged into one command because gpsd apparently
			// silently drops the second command sent too quickly
            string watch_cmd = "J=1,W=1,R=1\n";
            if (tcphandler->PutWriteBufferData((void *) watch_cmd.c_str(), 
                        watch_cmd.length()) < watch_cmd.length()) {
                _MSG("GPSGpsdV2 could not not write GPSD watch command",
                        MSGFLAG_ERROR);
            }

            // Go into poll mode
            string poll_cmd = "PAVM\n";
            if (tcphandler->PutWriteBufferData((void *) poll_cmd.c_str(), 
                        poll_cmd.length()) < poll_cmd.length()) {
                _MSG("GPSGpsdV2 could not not write GPSD watch command",
                        MSGFLAG_ERROR);
            }
            

		} else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,P=") {
			// Poll lines
			vector<string> pollvec = StrTokenize(inptok[it], ",");

			if (pollvec.size() < 5) {
				continue;
			}

			if (sscanf(pollvec[1].c_str(), "P=%lf %lf", 
                        &(new_location->lat), &(new_location->lon)) != 2) {
				continue;
			}

			if (sscanf(pollvec[4].c_str(), "M=%d", &(new_location->fix)) != 1) {
				continue;
			}

			if (sscanf(pollvec[2].c_str(), "A=%lf", &(new_location->alt)) != 1)
                set_alt = false;
            else
                set_alt = true;

			if (sscanf(pollvec[3].c_str(), "V=%lf", &(new_location->speed)) != 1)
                set_speed = false;
            else 
                set_speed = true;

            if (set_alt && new_location->fix < 3)
                new_location->fix = 3;

            if (!set_alt && new_location->fix < 2)
                new_location->fix = 2;

            set_heading = false;
            set_fix = true;
            set_lat_lon = true;

		} else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,O=") {
			// Look for O= watch lines
			vector<string> ggavec = StrTokenize(inptok[it], " ");

			if (ggavec.size() < 15) {
				continue;
			}

			// Total fail if we can't get lat/lon/mode
			if (sscanf(ggavec[3].c_str(), "%lf", &(new_location->lat)) != 1)
				continue;

			if (sscanf(ggavec[4].c_str(), "%lf", &(new_location->lon)) != 1)
				continue;

			if (sscanf(ggavec[14].c_str(), "%d", &(new_location->fix)) != 1)
				continue;

			if (sscanf(ggavec[5].c_str(), "%lf", &(new_location->alt)) != 1)
                set_alt = false;
            else
                set_alt = true;

#if 0
			if (sscanf(ggavec[6].c_str(), "%f", &in_hdop) != 1) 
				use_dop = 0;

			if (sscanf(ggavec[7].c_str(), "%f", &in_vdop) != 1)
				use_dop = 0;
#endif

			if (sscanf(ggavec[8].c_str(), "%lf", &(new_location->heading)) != 1)
                set_heading = false;
            else
                set_heading = true;

			if (sscanf(ggavec[9].c_str(), "%lf", &(new_location->speed)) != 1)
                set_speed = false;
            else
                set_speed = true;

#if 0
			if (si_units == 0)
				in_spd *= 0.514; /* Speed in meters/sec from knots */
#endif

            if (set_alt && new_location->fix < 3)
                new_location->fix = 3;

            if (!set_alt && new_location->fix < 2)
                new_location->fix = 2;


            set_fix = true;
            set_lat_lon = true;
		} else if (poll_mode < 10 && si_raw && inptok[it].substr(0, 6) == "$GPGSA") {
			vector<string> savec = StrTokenize(inptok[it], ",");

			if (savec.size() != 18)
				continue;

			if (sscanf(savec[2].c_str(), "%d", &(new_location->fix)) != 1)
				continue;

            set_fix = true;
		} else if (si_raw && inptok[it].substr(0, 6) == "$GPVTG") {
			vector<string> vtvec = StrTokenize(inptok[it], ",");

			if (vtvec.size() != 10)
				continue;

			if (sscanf(vtvec[7].c_str(), "%lf", &(new_location->speed)) != 1)
				continue;

            set_speed = true;
		} else if (poll_mode < 10 && si_raw && inptok[it].substr(0, 6) == "$GPGGA") {
			vector<string> gavec = StrTokenize(inptok[it], ",");
			int tint;
			float tfloat;

			if (gavec.size() != 15)
				continue;

			if (sscanf(gavec[2].c_str(), "%2d%f", &tint, &tfloat) != 2)
				continue;
			new_location->lat = (float) tint + (tfloat / 60);
			if (gavec[3] == "S")
				new_location->lat *= -1;

			if (sscanf(gavec[4].c_str(), "%3d%f", &tint, &tfloat) != 2)
				continue;
			new_location->lon = (float) tint + (tfloat / 60);
			if (gavec[5] == "W")
				new_location->lon *= -1;

			if (sscanf(gavec[9].c_str(), "%f", &tfloat) != 1)
				continue;
			new_location->alt = tfloat;

            if (new_location->fix < 3)
                new_location->fix = 3;
            
            set_fix = 3;
            set_alt = true;
            set_lat_lon = true;
#if 0
		} else if (poll_mode < 10 && inptok[it].substr(0, 6) == "$GPGSV") {
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

			gps_connected = 1;

			vector<string> svvec = StrTokenize(inptok[it], ",");
			GPSCore::sat_pos sp;

			if (svvec.size() < 6)
				continue;

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
#endif
		} 
    }

    // fprintf(stderr, "gps set loc %d alt %d spd %d fix %d heading %d\n", set_lat_lon, set_alt, set_speed, set_fix, set_heading);

    if (set_alt || set_speed || set_lat_lon || set_fix || set_heading) {
        if (gps_location != NULL) {
            // Copy the current location to the last one
            if (gps_last_location != NULL)
                delete gps_last_location;
            gps_last_location = new kis_gps_packinfo(gps_location);
        } else {
            gps_location = new kis_gps_packinfo();
        }

        // Copy whatever we know about the new location into the current
        if (set_lat_lon) {
            gps_location->lat = new_location->lat;
            gps_location->lon = new_location->lon;
        }

        if (set_alt)
            gps_location->alt = new_location->alt;

        if (set_speed) {
            gps_location->speed = new_location->speed;
            // NMEA reports speed in knots, convert
            gps_location->speed *= 0.514;
        }

        if (set_fix) {
            gps_location->fix = new_location->fix;
        }

        if (set_heading) {
            gps_location->heading = new_location->heading;
        }

        gps_location->time = globalreg->timestamp.tv_sec;

		if (!set_heading && globalreg->timestamp.tv_sec - last_heading_time > 5 &&
                gps_last_location->fix >= 2) {
			gps_location->heading = 
                GpsCalcHeading(gps_location->lat, gps_location->lon, 
                        gps_last_location->lat, gps_last_location->lon);
            last_heading_time = gps_location->time;
		}
    }
}

