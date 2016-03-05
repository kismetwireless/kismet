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

#ifndef HAVE_LIBGPS

#include "gpsdclient.h"
#include "configfile.h"
#include "soundcontrol.h"
#include "packetchain.h"
#include "kismet_json.h"

int GpsdGpsEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg) {
	GPSDClient *gps = (GPSDClient *) parm;

	return gps->Timer();
}

GPSDClient::GPSDClient() {
    fprintf(stderr, "FATAL OOPS: gpsdclient called with no globalreg\n");
	exit(-1);
}

void gpsdc_connect_hook(GlobalRegistry *globalreg, int status, void *auxptr) {
	((GPSDClient *) auxptr)->ConnectCB(status);
}

void GPSDClient::ConnectCB(int status) {
	ostringstream osstr;

	if (status != 0) {
		if (reconnect_attempt < 0) {
			globalreg->messagebus->InjectMessage("Could not connect to GPSD server",
												 MSGFLAG_ERROR);

			globalreg->messagebus->InjectMessage("GPSD reconnection not enabled, "
												 "disabling GPSD", MSGFLAG_ERROR);
			return;
		} 

		/*
		snprintf(errstr, STATUS_MAX, "Could not connect to the GPSD server, will "
				 "reconnect in %d seconds", kismin(reconnect_attempt + 1, 6) * 5);
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		*/
		reconnect_attempt++;
		last_disconnect = globalreg->timestamp.tv_sec;

		return;
	}

	// Set the poll mode to initial setup and call the timer
	poll_mode = -1;
	last_hed_time = 0;
	si_units = 0;
	reconnect_attempt = 1;
	last_disconnect = 0;
	gps_connected = 0;

	return;
}

GPSDClient::GPSDClient(GlobalRegistry *in_globalreg) : GPSCore(in_globalreg) {
    // The only GPSD connection method we support is a plain 
    // old TCP connection so we can generate it all internally
    tcpcli = new TcpClient(globalreg);
	netclient = tcpcli;

    // Attach it to ourselves and opposite
    RegisterNetworkClient(tcpcli);
    tcpcli->RegisterClientFramework(this);

    gpseventid = -1;
	poll_mode = -1;
	last_hed_time = 0;
	si_units = 0;

	ScanOptions();
	RegisterComponents();

	gpseventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
											  &GpsdGpsEvent, (void *) this);

	char temphost[129];
	if (sscanf(globalreg->kismet_config->FetchOpt("gpshost").c_str(), 
			   "%128[^:]:%d", temphost, &port) != 2) {
		globalreg->messagebus->InjectMessage("Invalid GPS host in config, "
											 "host:port required",
											 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}
	snprintf(host, MAXHOSTNAMELEN, "%s", temphost);

	last_mode = -1;

	last_tpv = last_update = globalreg->timestamp.tv_sec;

	snprintf(errstr, STATUS_MAX, "Using GPSD server on %s:%d", host, port);
	globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

	tcpcli->Connect(host, port, gpsdc_connect_hook, this);
}

GPSDClient::~GPSDClient() {
	// Unregister ourselves from the main tcp service loop
	globalreg->RemovePollableSubsys(this);

	KillConnection();
}

int GPSDClient::Shutdown() {
    if (tcpcli != NULL) {
        tcpcli->FlushRings();
        tcpcli->KillConnection();
    }

    return 1;
}

int GPSDClient::Timer() {
	int ret = 0;

    // Timed backoff up to 30 seconds
    if (netclient->Valid() == 0 && reconnect_attempt >= 0 &&
        (globalreg->timestamp.tv_sec - last_disconnect >= 
		 (kismin(reconnect_attempt, 6) * 5))) {
		Reconnect();
    }

	// Send version probe if we're setting up a new connection
	// Send the poll command if we're stuck in older polling mode
	if (netclient->Valid()) {
		if (globalreg->timestamp.tv_sec - last_tpv > 3) {
			// Assume we lost link, gpsd doens't properly tell us
			mode = 0;
		}

		if (globalreg->timestamp.tv_sec - last_update > 15) {
			_MSG("No update from GPSD in 15 seconds or more, attempting to "
				 "reconnect", MSGFLAG_ERROR);

			mode = 0;
			netclient->KillConnection();
			last_update = last_disconnect = globalreg->timestamp.tv_sec;
			GPSCore::Timer();
			return 1;
		}

		if (poll_mode < 0) {
			ret = netclient->WriteData((void *) gpsd_init_command,
									   strlen(gpsd_init_command));
			poll_mode = 0;
			netclient->FlushRings();
		} else if (poll_mode == 1) {
			ret = netclient->WriteData((void *) gpsd_poll_command,
									   strlen(gpsd_poll_command));
			netclient->FlushRings();
		}

		if (ret < 0 || globalreg->fatal_condition) {
			last_disconnect = globalreg->timestamp.tv_sec;
			return -1;
		}
	}

	GPSCore::Timer();

	return 1;
}

int GPSDClient::Reconnect() {
    tcpcli->Connect(host, port, gpsdc_connect_hook, this);
    return 1;
}

int GPSDClient::ParseData() {
    int len, rlen, roft = 0;
    char *buf;
    string strbuf;
	float in_lat = 0, in_lon = 0, in_alt = 0, 
		  in_spd = 0, in_hed = 0, in_hdop = 0, in_vdop = 0;
	int in_mode, use_alt = 1, use_spd = 1, use_hed = 1, use_data = 0,
		use_mode = 0, use_coord = 0, use_dop = 0;;

    len = netclient->FetchReadLen();
    buf = new char[len + 1];

    if (netclient->ReadData(buf, len, &rlen) < 0) {
        globalreg->messagebus->InjectMessage("GPSDClient::ParseData failed to "
											 "fetch data from the tcp connection.", 
											 MSGFLAG_ERROR);
        delete[] buf;
        return -1;
    }

	if (rlen <= 0) {
		return 0;
	}

    buf[rlen] = '\0';

	for (roft = 0; roft < rlen; roft++) {
		if (buf[roft] != 0) {
			break;
		}
	}

    // Parse without including partials, so we don't get a fragmented command 
    // out of the buffer
    vector<string> inptok = StrTokenize(buf + roft, "\n", 0);
    delete[] buf;

    // Bail on no useful data
    if (inptok.size() <= 0) {
        return 0;
    }

    for (unsigned int it = 0; it < inptok.size(); it++) {
        // No matter what we've dealt with this data block
        netclient->MarkRead(inptok[it].length() + 1 + roft);

		// Trim garbage out of it
		inptok[it] = StrPrintable(inptok[it]);

		last_update = globalreg->timestamp.tv_sec;

		// Do we look like JSON?  If it is, we process it independently of the normal
		// methods...
		if (inptok[it][0] == '{') {
			struct JSON_value *json;
			string err;

			json = JSON_parse(inptok[it], err);

			if (err.length() != 0) {
				_MSG("Invalid JSON data block from GPSD: " + err, MSGFLAG_ERROR);
				continue;
			}  

			// printf("debug - GPS JSON:\n");
			// JSON_dump(json, "", 0);

			string msg_class = JSON_dict_get_string(json, "class", err);

			if (msg_class == "VERSION") {
				_MSG("Connected to a JSON-enabled GPSD version " +
					 MungeToPrintable(JSON_dict_get_string(json, "release", err)) + 
					 ", turning on JSON mode", MSGFLAG_INFO);
				// Set JSON mode
				poll_mode = 10;
				// We get speed in meters/sec
				si_units = 1;

				if (netclient->WriteData((void *) "?WATCH={\"json\":true};\n", 22) < 0 ||
					globalreg->fatal_condition) {
					last_disconnect = globalreg->timestamp.tv_sec;
					return 0;
				}
			} else if (msg_class == "TPV") {
				float n;

				last_tpv = globalreg->timestamp.tv_sec;

				gps_connected = 1;

				n = JSON_dict_get_number(json, "mode", err);
				if (err.length() == 0) {
					in_mode = (int) n;
					use_mode = 1;
				}

				// If we have a valid alt, use it
				if (use_mode && in_mode > 2) {
					n = JSON_dict_get_number(json, "alt", err);
					if (err.length() == 0) {
						in_alt = n;
						use_alt = 1;
					}
				} 

				if (use_mode && in_mode >= 2) {
					// If we have LAT and LON, use them
					n = JSON_dict_get_number(json, "lat", err);
					if (err.length() == 0) {
						in_lat = n;

						n = JSON_dict_get_number(json, "lon", err);
						if (err.length() == 0) {
							in_lon = n;

							use_coord = 1;
							use_data = 1;
						}
					}

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

					// Heading (track in gpsd speak)
					n = JSON_dict_get_number(json, "track", err);
					if (err.length() == 0) {
						in_hed = n;
						use_hed = 1;
					}

					// Speed
					n = JSON_dict_get_number(json, "speed", err);
					if (err.length() == 0) {
						in_spd = n;
						use_spd = 1;
					} 
				}
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
			}

			JSON_delete(json);
		} else if (poll_mode == 0 && inptok[it] == "GPSD") {
			// Look for a really old gpsd which doesn't do anything intelligent
			// with the L (version) command.  Only do this once, if we've already
			// figured out a poll mode then there's not much point in hammering
			// the server.  Force us into watch mode.

			poll_mode = 1;

			Timer();
			continue;
		} else if (poll_mode < 10 && inptok[it].substr(0, 15) == "GPSD,L=2 1.0-25") {
			// Maemo ships a broken,broken GPS which doesn't parse NMEA correctly
			// and results in no alt or fix in watcher or polling modes, so we
			// have to detect this version and kick it into debug R=1 mode
			// and do NMEA ourselves.
			if (netclient->WriteData((void *) "R=1\n", 4) < 0 ||
				globalreg->fatal_condition) {
				last_disconnect = globalreg->timestamp.tv_sec;
				return 0;
			}

			// Use raw for position
			si_raw = 1;
		} else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,L=") {
			// Look for the version response
			vector<string> lvec = StrTokenize(inptok[it], " ");
			int gma, gmi;

			gps_connected = 1;

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
			if (netclient->WriteData((void *) gpsd_watch_command, 
									 strlen(gpsd_watch_command)) < 0 ||
				globalreg->fatal_condition) {
				last_disconnect = globalreg->timestamp.tv_sec;
				return 0;
			}

		} else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,P=") {
			gps_connected = 1;

			// Poll lines
			vector<string> pollvec = StrTokenize(inptok[it], ",");

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

		} else if (poll_mode < 10 && inptok[it].substr(0, 7) == "GPSD,O=") {
			gps_connected = 1;

			// Look for O= watch lines
			vector<string> ggavec = StrTokenize(inptok[it], " ");

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

			if (sscanf(ggavec[6].c_str(), "%f", &in_hdop) != 1) 
				use_dop = 0;

			if (sscanf(ggavec[7].c_str(), "%f", &in_vdop) != 1)
				use_dop = 0;

			if (sscanf(ggavec[8].c_str(), "%f", &in_hed) != 1)
				use_hed = 0;

			if (sscanf(ggavec[9].c_str(), "%f", &in_spd) != 1)
				use_spd = 0;

#if 0
			if (si_units == 0)
				in_spd *= 0.514; /* Speed in meters/sec from knots */
#endif

			use_mode = 1;
			use_coord = 1;
			use_data = 1;
		} else if (poll_mode < 10 && si_raw && inptok[it].substr(0, 6) == "$GPGSA") {
			gps_connected = 1;

			vector<string> savec = StrTokenize(inptok[it], ",");

			if (savec.size() != 18)
				continue;

			if (sscanf(savec[2].c_str(), "%d", &in_mode) != 1)
				continue;

			use_mode = 1;
			use_data = 1;
			/*
		} else if (si_raw && inptok[it].substr(0, 6) == "$GPVTG") {
			vector<string> vtvec = StrTokenize(inptok[it], ",");

			if (vtvec.size() != 10)
				continue;

			if (sscanf(vtvec[7].c_str(), "%f", &in_spd) != 1)
				continue;

			use_spd = 1;
			use_data = 1;
			*/
		} else if (poll_mode < 10 && si_raw && inptok[it].substr(0, 6) == "$GPGGA") {
			gps_connected = 1;

			vector<string> gavec = StrTokenize(inptok[it], ",");
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

	// If we're using speed,and if we're in the older gpsd that provides it in
	// knots, convert it, otherwise it's already meters/sec
	if (use_spd) {
		if (si_units == 0)
			in_spd *= 0.514; /* Speed in meters/sec from knots */
		spd = in_spd;
	}

	if (use_hed) {
		last_hed = hed;
		hed = in_hed;
	} else if (poll_mode && use_coord) {
		// We only do manual heading calcs in poll mode
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

	return 1;
}

#endif

