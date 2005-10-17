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

int GpsInjectEvent(Timetracker::timer_event *evt, void *parm, 
                   GlobalRegistry *globalreg) {
    GPSDClient *cli = (GPSDClient *) parm;

    int ret = cli->InjectCommand();

    if (ret < 0 && cli->reconnect_attempt < 0)
        return -1;

    return 1;
}

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

    if (globalreg->kismet_config->FetchOpt("gps") == "true") {
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
													 "disabling GPS", MSGFLAG_ERROR);
                return;
            }
            last_disconnect = time(0);
        } else {
            // Start a command
            InjectCommand();
        }

        // Spawn the tick event
        gpseventid = 
			globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
												  &GpsInjectEvent, (void *) this);

        snprintf(errstr, STATUS_MAX, "Using GPSD server on %s:%d", host, port);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
	}
}

GPSDClient::~GPSDClient() {
    if (gpseventid >= 0 && globalreg != NULL)
        globalreg->timetracker->RemoveTimer(gpseventid);

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

int GPSDClient::InjectCommand() {
    // Timed backoff up to 30 seconds
    if (netclient->Valid() == 0 && reconnect_attempt >= 0 &&
        (time(0) - last_disconnect >= (kismin(reconnect_attempt, 6) * 5))) {
        if (Reconnect() <= 0)
            return 0;
    }

    if (netclient->Valid() && netclient->WriteData((void *) gpsd_command, 
												   strlen(gpsd_command)) < 0 ||
		globalreg->fatal_condition) {
        last_disconnect = time(0);
        return -1;
    }

    return 1;
}

int GPSDClient::Reconnect() {
    if (tcpcli->Connect(host, port) < 0) {
        snprintf(errstr, STATUS_MAX, "Could not connect to the GPSD server, will "
                 "reconnect in %d seconds", kismin(reconnect_attempt + 1, 6) * 5);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        reconnect_attempt++;
        last_disconnect = time(0);
        return 0;
    }
    
    return 1;
}

int GPSDClient::ParseData() {
    // Old GPSD:
    // PAVMH
    // GPSD,P=0.000000 0.000000,A=0.000000,V=0.000000,M=0
    //
    // New ESR gpsd that changed the protocol:
    // GPSD,P=?,A=?,V=?,M=1

    int len, rlen, roft = 0;
    char *buf;
    string strbuf;

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
    if (inptok.size() < 1) {
        return 0;
    }

    double in_lat, in_lon, in_spd, in_alt, in_hed;
    int in_mode, set_pos = 0, set_spd = 0, set_alt = 0,
        set_hed = 0, set_mode = 0, newgpsd_invalid = 0;
    
    for (unsigned int it = 0; it < inptok.size(); it++) {
        // No matter what we've dealt with this data block
        netclient->MarkRead(inptok[it].length() + 1 + roft);
 
        // Split it on the commas
        vector<string> lintok = StrTokenize(inptok[it], ",");

        // Try to not error out entirely and just throw up an error about
        // not being able to understand it
        if (lintok.size() < 1) {
            _MSG("GPSDClient unable to parse string from GPSD: '" + inptok[it] + "'", 
				 MSGFLAG_ERROR);
            return 0;
        }

        if (lintok[0] != "GPSD") {
            globalreg->messagebus->InjectMessage("GPSDClient unable to parse string "
												 "from GPSD, no 'GPSD' header",
                                                 MSGFLAG_ERROR);
            return 0;
        }

        for (unsigned int x = 1; x < lintok.size(); x++) {
            // This is a lot of tokenizing but it's a pretty cheap operation to do
            vector<string> values = StrTokenize(lintok[x], "=");
            
            if (values.size() != 2) {
				_MSG("GPSDClient unable to parse string from GPSD: '" + 
					 inptok[it] + "'", MSGFLAG_ERROR);
                return 0;
            }

			if (values[2].length() == 0) {
				_MSG("GPSDClient unable to parse string from GPSD: '" + 
					 inptok[it] + "'", MSGFLAG_ERROR);
                return 0;
			}

            if (values[0] == "P") {
                if (values[1][0] == '?') {
                    newgpsd_invalid = 1;
					continue;
                } else if (sscanf(values[1].c_str(), "%lf %lf", 
								  &in_lat, &in_lon) != 2) {
                    in_lat = in_lon = -1;
					_MSG("GPSDClient unable to parse string from GPSD: '" + 
						 inptok[it] + "'", MSGFLAG_ERROR);
                    return 0;
                }
                set_pos = 1;        
				continue;
            }

            if (values[0] == "A") {
                if (values[1][0] == '?') {
                    newgpsd_invalid = 1;
					continue;
                } else if (sscanf(values[1].c_str(), "%lf", &in_alt) != 1) {
                    in_alt = -1;
					_MSG("GPSDClient unable to parse string from GPSD: '" + 
						 inptok[it] + "'", MSGFLAG_ERROR);
                    return 0;
                }
                set_alt = 1;
				continue;
            }

            if (values[0] == "V") {
                if (values[1][0] == '?') {
                    newgpsd_invalid = 1;
					continue;
                } else if (sscanf(values[1].c_str(), "%lf", &in_spd) != 1) {
                    in_spd = -1;
					_MSG("GPSDClient unable to parse string from GPSD: '" + 
						 inptok[it] + "'", MSGFLAG_ERROR);
                    return 0;
                }
                set_spd = 1;
				continue;
            }

            if (values[0] == "H") {
                if (values[1][0] == '?') {
                    newgpsd_invalid = 1;
					continue;
                } else if (sscanf(values[1].c_str(), "%lf", &in_hed) != 1) {
                    in_hed = -1;
					_MSG("GPSDClient unable to parse string from GPSD: '" + 
						 inptok[it] + "'", MSGFLAG_ERROR);
                    return 0;
                }
                set_hed = 1;
				continue;
            }

            if (values[0] == "M") {
                if (values[1][0] == '?') {
                    newgpsd_invalid = 1;
					continue;
                } else if (sscanf(values[1].c_str(), "%d", &in_mode) != 1) {
                    in_mode = -1;
					_MSG("GPSDClient unable to parse string from GPSD: '" + 
						 inptok[it] + "'", MSGFLAG_ERROR);
                    return 0;
                }
                set_mode = 1;
				continue;
            }
        }
    }

    if (set_pos) {
        last_lat = lat;
        lat = in_lat;
        last_lon = lon;
        lon = in_lon;
    }

    if (set_spd)
        spd = in_spd;

    if (set_alt)
        alt = in_alt;

    if (set_hed) {
        last_hed = hed;
        hed = in_hed;
    } else if (set_pos) {
        last_hed = hed;
        hed = CalcHeading(lat, lon, last_lat, last_lon);
    }

    if (set_mode) {
        if (mode < 2 && (gps_options & GPSD_OPT_FORCEMODE) && 
            newgpsd_invalid == 0) {
            mode = 2;
        } else {
            if (mode < 2 && in_mode >= 2) {
                    globalreg->speechctl->SayText("Got G P S position fix");
                    globalreg->soundctl->PlaySound("gpslock");
            } else if (mode >= 2 && in_mode < 2) {
                    globalreg->speechctl->SayText("Lost G P S position fix");
                    globalreg->soundctl->PlaySound("gpslost");
            }

            mode = in_mode;
        }
    }

    // Send it to the client
    GPS_data gdata;

    snprintf(errstr, 32, "%lf", lat);
    gdata.lat = errstr;
    snprintf(errstr, 32, "%lf", lon);
    gdata.lon = errstr;
    snprintf(errstr, 32, "%lf", alt);
    gdata.alt = errstr;
    snprintf(errstr, 32, "%lf", spd);
    gdata.spd = errstr;
    snprintf(errstr, 32, "%lf", hed);
    gdata.heading = errstr;
    snprintf(errstr, 32, "%d", mode);
    gdata.mode = errstr;

    globalreg->kisnetserver->SendToAll(gps_proto_ref, (void *) &gdata);

	// Make an empty packet w/ just GPS data for the gpsxml logger to catch
	kis_packet *newpack = globalreg->packetchain->GeneratePacket();
	kis_gps_packinfo *gpsdat = new kis_gps_packinfo;
	newpack->ts.tv_sec = globalreg->timestamp.tv_sec;
	newpack->ts.tv_usec = globalreg->timestamp.tv_usec;
	globalreg->gpsd->FetchLoc(&(gpsdat->lat), &(gpsdat->lon), &(gpsdat->alt),
							  &(gpsdat->spd), &(gpsdat->heading), &(gpsdat->gps_fix));
	newpack->insert(_PCM(PACK_COMP_GPS), gpsdat);
	globalreg->packetchain->ProcessPacket(newpack);

    return 1;
}

