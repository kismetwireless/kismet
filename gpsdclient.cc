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
#include "gpsdclient.h"
#include "configfile.h"
#include "speechcontrol.h"
#include "soundcontrol.h"
#include "packetchain.h"

GPSDClient::GPSDClient() {
    fprintf(stderr, "FATAL OOPS: gpsdclient called with no globalreg\n");
	exit(-1);
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

	if (tcpcli->Connect(host, port) < 0) {
		globalreg->messagebus->InjectMessage("Could not create initial "
											 "connection to the GPSD server", 
											 MSGFLAG_ERROR);
		if (reconnect_attempt < 0) {
			globalreg->messagebus->InjectMessage("GPSD Reconnection not enabled, "
												 "disabling GPSD", MSGFLAG_ERROR);
			return;
		}
		last_disconnect = time(0);
	} else {
		// Start a command
		Timer();
	}

	last_mode = -1;

	snprintf(errstr, STATUS_MAX, "Using GPSD server on %s:%d", host, port);
	globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
}

GPSDClient::~GPSDClient() {
	// Unregister ourselves from the main tcp service loop
	globalreg->RemovePollableSubsys(this);
	
    if (tcpcli != NULL && tcpcli->Valid()) {
        tcpcli->KillConnection();
        delete tcpcli;
    }
}

int GPSDClient::KillConnection() {
    if (tcpcli != NULL && tcpcli->Valid())
        tcpcli->KillConnection();

    return 1;
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
        (time(0) - last_disconnect >= (kismin(reconnect_attempt, 6) * 5))) {
        if (Reconnect() <= 0)
            return 0;
    }

	// Send version probe if we're setting up a new connection
	// Send the poll command if we're stuck in older polling mode
	if (netclient->Valid()) {
		if (poll_mode < 0) {
			ret = netclient->WriteData((void *) gpsd_init_command,
									   strlen(gpsd_init_command));
			poll_mode = 0;
		} else if (poll_mode == 1) {
			ret = netclient->WriteData((void *) gpsd_poll_command,
									   strlen(gpsd_poll_command));
		}

		if (ret < 0 || globalreg->fatal_condition) {
			last_disconnect = time(0);
			return -1;
		}
	}

	return GPSCore::Timer();
}

int GPSDClient::Reconnect() {
    if (tcpcli->Connect(host, port) < 0) {
        snprintf(errstr, STATUS_MAX, "Could not connect to the GPSD server, will "
                 "reconnect in %d seconds", kismin(reconnect_attempt + 1, 6) * 5);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        reconnect_attempt++;
        last_disconnect = time(0);
        return 0;
    } else {
		// Set the poll mode to initial setup and call the timer
		poll_mode = -1;
		last_hed_time = 0;
		si_units = 0;
		Timer();
	}
    
    return 1;
}

int GPSDClient::ParseData() {
    int len, rlen, roft = 0;
    char *buf;
    string strbuf;
	float in_lat, in_lon, in_alt, in_spd, in_hed;
	int in_mode, use_alt = 1, use_spd = 1, use_hed = 1, use_data = 0,
		use_mode = 0, use_coord = 0;

    len = netclient->FetchReadLen();
    buf = new char[len + 1];

    if (netclient->ReadData(buf, len, &rlen) < 0) {
        globalreg->messagebus->InjectMessage("GPSDClient::ParseData failed to "
											 "fetch data from the tcp connection.", 
											 MSGFLAG_ERROR);
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

		if (poll_mode == 0 && inptok[it] == "GPSD") {
			// Look for a really old gpsd which doesn't do anything intelligent
			// with the L (version) command.  Only do this once, if we've already
			// figured out a poll mode then there's not much point in hammering
			// the server.  Force us into watch mode.

			poll_mode = 1;

			Timer();
			continue;
		} else if (inptok[it].substr(0, 15) == "GPSD,L=2 1.0-25") {
			// Maemo ships a broken,broken GPS which doesn't parse NMEA correctly
			// and results in no alt or fix in watcher or polling modes, so we
			// have to detect this version and kick it into debug R=1 mode
			// and do NMEA ourselves.
			if (netclient->WriteData((void *) "R=1\n", 4) < 0 ||
				globalreg->fatal_condition) {
				last_disconnect = time(0);
				return 0;
			}

			// Use raw for position
			si_raw = 1;
		} else if (inptok[it].substr(0, 7) == "GPSD,L=") {
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
			if (netclient->WriteData((void *) gpsd_watch_command, 
									 strlen(gpsd_watch_command)) < 0 ||
				globalreg->fatal_condition) {
				last_disconnect = time(0);
				return 0;
			}

		} else if (inptok[it].substr(0, 7) == "GPSD,P=") {
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

		} else if (inptok[it].substr(0, 7) == "GPSD,O=") {
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

			if (sscanf(ggavec[8].c_str(), "%f", &in_hed) != 1)
				use_hed = 0;

			if (sscanf(ggavec[9].c_str(), "%f", &in_spd) != 1)
				use_spd = 0;
			else if (si_units)
				in_spd *= 1.9438445;	/*new gpsd uses m/s intead of knots*/

			use_mode = 1;
			use_coord = 1;
			use_data = 1;
		} else if (si_raw && inptok[it].substr(0, 6) == "$GPGSA") {
			vector<string> savec = StrTokenize(inptok[it], ",");

			if (savec.size() != 18)
				continue;

			if (sscanf(savec[2].c_str(), "%d", &in_mode) != 1)
				continue;

			use_mode = 1;
			use_data = 1;
		} else if (si_raw && inptok[it].substr(0, 6) == "$GPVTG") {
			vector<string> vtvec = StrTokenize(inptok[it], ",");

			if (vtvec.size() != 10)
				continue;

			if (sscanf(vtvec[7].c_str(), "%f", &in_spd) != 1)
				continue;

			use_spd = 1;
			use_data = 1;
		} else if (si_raw && inptok[it].substr(0, 6) == "$GPGGA") {
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

			if (svvec.size() < 6)
				continue;

			// We don't care about # of sentences and sentence number

			unsigned int pos = 4;
			while (pos + 4 < svvec.size()) {
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.prn) != 1) 
					break;
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.elevation) != 1)
					break;
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.azimuth) != 1)
					break;
				if (sscanf(svvec[pos++].c_str(), "%d", &sp.snr) != 1)
					break;

				sat_pos_map[sp.prn] = sp;
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

	// For some reason this is reported in KNOTS.  Great.  So turn it into 
	// feet and then meters so we report metric internally
	if (use_spd)
		spd = (in_spd * 6076.12) / 3.2808;

		//spd = in_spd * (6076.12 / 5280);

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
		
		// Update the "did we ever get anything" so we say "no fix" not "no gps"
		// as soon as we get a valid sentence of any sort
		gps_ever_lock = 1;
	}

	return 1;
}

