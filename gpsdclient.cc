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

#ifdef HAVE_GPS

char *GPS_fields_text[] = {
    "lat", "lon", "alt", "spd", "heading", "fix",
    NULL
};

int Protocol_GPS(PROTO_PARMS) {
    GPS_data *gdata = (GPS_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        switch ((GPS_fields) (*field_vec)[x]) {
        case GPS_lat:
            out_string += gdata->lat;
            break;
        case GPS_lon:
            out_string += gdata->lon;
            break;
        case GPS_alt:
            out_string += gdata->alt;
            break;
        case GPS_spd:
            out_string += gdata->spd;
            break;
        case GPS_heading:
            out_string += gdata->heading;
            break;
        case GPS_fix:
            out_string += gdata->mode;
            break;
        default:
            out_string = "Unknown field requested.";
            return -1;
            break;
        }

        out_string += " ";
    }

    return 1;
}

int GpsInjectEvent(Timetracker::timer_event *evt, void *parm, 
                   GlobalRegistry *globalreg) {
    GPSDClient *cli = (GPSDClient *) parm;

    int ret = cli->InjectCommand();

    if (ret < 0 && cli->reconnect_attempt < 0)
        return -1;

    return 1;
}

int kis_gpspack_hook(CHAINCALL_PARMS) {
	// Simple packet insertion of current GPS coordinates
	kis_gps_packinfo *gpsdat = new kis_gps_packinfo;

	globalreg->gpsd->FetchLoc(&(gpsdat->lat), &(gpsdat->lon), &(gpsdat->alt),
							  &(gpsdat->spd), &(gpsdat->heading), &(gpsdat->gps_fix));
	
	in_pack->insert(_PCM(PACK_COMP_GPS), gpsdat);

	return 1;
}

GPSDClient::GPSDClient() {
    fprintf(stderr, "*** gpsdclient called with no global registry reference\n");
    globalreg = NULL;
    tcpcli = NULL;
}

GPSDClient::GPSDClient(GlobalRegistry *in_globalreg) : ClientFramework(in_globalreg) {
    // The only GPSD connection method we support is a plain 
    // old TCP connection so we can generate it all internally
    tcpcli = new TcpClient(globalreg);

    // Attach it to ourselves and opposite
    RegisterNetworkClient(tcpcli);
    tcpcli->RegisterClientFramework(this);

	// Register GPS packet info components
	_PCM(PACK_COMP_GPS) =
		globalreg->packetchain->RegisterPacketComponent("gps");
	
    gpseventid = -1;

    reconnect_attempt = -1;

    mode = 0;
    lat = lon = alt = spd = hed = last_lat = last_lon = last_hed = 0;

	// Register the network protocol
	gps_proto_ref = 
		globalreg->kisnetserver->RegisterProtocol("GPS", 0, GPS_fields_text, 
												  &Protocol_GPS, NULL);

	// Register the gps component and packetchain hooks to include it
	_PCM(PACK_COMP_GPS) =
		globalreg->packetchain->RegisterPacketComponent("gps");
	globalreg->packetchain->RegisterHandler(&kis_gpspack_hook, this,
											CHAINPOS_POSTCAP, -100);

    // Parse the config file and enable the tcpclient
    
    if (globalreg->kismet_config->FetchOpt("gps") == "true") {
        char temphost[128];
        if (sscanf(globalreg->kismet_config->FetchOpt("gpshost").c_str(), 
				   "%128[^:]:%d", temphost, &port) != 2) {
            globalreg->messagebus->InjectMessage("Invalid GPS host in config, "
												 "host:port required",
                                                 MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return;
        }
        snprintf(host, MAXHOSTNAMELEN, "%s", temphost);

        // Lock GPS position
        if (globalreg->kismet_config->FetchOpt("gpsmodelock") == "true") {
            globalreg->messagebus->InjectMessage("Enabling GPS position information "
												 "override (override broken GPS "
												 "units that always report 0 "
                                                 "in the NMEA stream)", MSGFLAG_INFO);
            SetOptions(GPSD_OPT_FORCEMODE);
        }

        if (globalreg->kismet_config->FetchOpt("gpsreconnect") == "true") {
            globalreg->messagebus->InjectMessage("Enabling reconnection to the GPSD "
												 "server if the link is lost", 
												 MSGFLAG_INFO);
            reconnect_attempt = 0;
        }

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
			globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, 
												  NULL, 1, &GpsInjectEvent, 
												  (void *) this);

        snprintf(errstr, STATUS_MAX, "Using GPSD server on %s:%d", host, port);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
        
    } else {
        globalreg->messagebus->InjectMessage("GPS support not enabled", MSGFLAG_INFO);
    }

	// Register the TCP component of the GPS system with the main service loop
	globalreg->RegisterPollableSubsys(this);
}

GPSDClient::~GPSDClient() {
    if (gpseventid >= 0 && globalreg != NULL)
        globalreg->timetracker->RemoveTimer(gpseventid);

	// Unregister ourselves from the main tcp service loop
	globalreg->RemovePollableSubsys(this);
	
    if (tcpcli != NULL) {
        tcpcli->KillConnection();
        delete tcpcli;
    }
}

int GPSDClient::KillConnection() {
    if (tcpcli != NULL)
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
    if (tcpcli->Valid() == 0 && reconnect_attempt &&
        (time(0) - last_disconnect >= (kismin(reconnect_attempt, 6) * 5))) {
        if (Reconnect() <= 0)
            return 0;
    }

    if (tcpcli->Valid() && tcpcli->WriteData((void *) gpsd_command, strlen(gpsd_command)) < 0 ||
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

    int len, rlen;
    char *buf;
    string strbuf;

    len = netclient->FetchReadLen();
    buf = new char[len + 1];
    
    if (netclient->ReadData(buf, len, &rlen) < 0) {
        globalreg->messagebus->InjectMessage("GPSDClient::ParseData failed to fetch data from "
                                             "the tcp connection.", MSGFLAG_ERROR);
        return -1;
    }
    buf[len] = '\0';

    // Parse without including partials, so we don't get a fragmented command 
    // out of the buffer
    vector<string> inptok = StrTokenize(buf, "\n", 0);
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
        netclient->MarkRead(inptok[it].length() + 1);
 
        // Split it on the commas
        vector<string> lintok = StrTokenize(inptok[it], ",");

        // Try to not error out entirely and just throw up an error about
        // not being able to understand it
        if (lintok.size() < 1) {
            globalreg->messagebus->InjectMessage("GPSDClient unable to parse string "
												 "from GPSD", MSGFLAG_ERROR);
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
                globalreg->messagebus->InjectMessage("GPSDClient unable to parse "
													 "string from GPSD",
                                                     MSGFLAG_ERROR);
                return 0;
            }

            if (values[0] == "P") {
                if (values[1] == "?") {
                    newgpsd_invalid = 1;
                } else if (sscanf(values[1].c_str(), "%lf %lf", 
								  &in_lat, &in_lon) != 2) {
                    in_lat = in_lon = -1;
                    globalreg->messagebus->InjectMessage("GPSDClient unable to parse "
														 "string from GPSD",
                                                         MSGFLAG_ERROR);
                    return 0;
                }
                set_pos = 1;        
				continue;
            }

            if (values[0] == "A") {
                if (values[1] == "?") {
                    newgpsd_invalid = 1;
                } else if (sscanf(values[1].c_str(), "%lf", &in_alt) != 1) {
                    in_alt = -1;
                    globalreg->messagebus->InjectMessage("GPSDClient unable to parse "
														 "string from GPSD",
                                                         MSGFLAG_ERROR);
                    return 0;
                }
                set_alt = 1;
				continue;
            }

            if (values[0] == "V") {
                if (values[1] == "?") {
                    newgpsd_invalid = 1;
                } else if (sscanf(values[1].c_str(), "%lf", &in_spd) != 1) {
                    in_spd = -1;
                    globalreg->messagebus->InjectMessage("GPSDClient unable to parse "
														 "string from GPSD",
                                                         MSGFLAG_ERROR);
                    return 0;
                }
                set_spd = 1;
				continue;
            }

            if (values[0] == "H") {
                if (values[1] == "?") {
                    newgpsd_invalid = 1;
                } else if (sscanf(values[1].c_str(), "%lf", &in_hed) != 1) {
                    in_hed = -1;
                    globalreg->messagebus->InjectMessage("GPSDClient unable to parse "
														 "string from GPSD",
                                                         MSGFLAG_ERROR);
                    return 0;
                }
                set_hed = 1;
				continue;
            }

            if (values[0] == "M") {
                if (values[1] == "?") {
                    newgpsd_invalid = 1;
                } else if (sscanf(values[1].c_str(), "%d", &in_mode) != 1) {
                    in_mode = -1;
                    globalreg->messagebus->InjectMessage("GPSDClient unable to parse "
														 "string from GPSD",
                                                         MSGFLAG_ERROR);
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

    return 1;
}

int GPSDClient::FetchLoc(double *in_lat, double *in_lon, double *in_alt, 
                         double *in_spd, double *in_hed, int *in_mode) {
    *in_lat = lat;
    *in_lon = lon;
    *in_alt = alt;
    *in_spd = spd;
    *in_mode = mode;
    *in_hed = hed;

    return mode;
}

double GPSDClient::CalcHeading(double in_lat, double in_lon, double in_lat2, 
							   double in_lon2) {
    double r = CalcRad((double) in_lat2);

    double lat1 = Deg2Rad((double) in_lat);
    double lon1 = Deg2Rad((double) in_lon);
    double lat2 = Deg2Rad((double) in_lat2);
    double lon2 = Deg2Rad((double) in_lon2);

    double angle = 0;

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
        double tx = r * cos((double) lat1) * (lon2 - lon1);
        double ty = r * (lat2 - lat1);
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

    return (double) Rad2Deg(angle);
}

double GPSDClient::Rad2Deg(double x) {
    return (x/M_PI) * 180.0;
}

double GPSDClient::Deg2Rad(double x) {
    return 180/(x*M_PI);
}

double GPSDClient::EarthDistance(double in_lat, double in_lon, double in_lat2, double in_lon2) {
    double x1 = CalcRad(in_lat) * cos(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double x2 = CalcRad(in_lat2) * cos(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double y1 = CalcRad(in_lat) * sin(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double y2 = CalcRad(in_lat2) * sin(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double z1 = CalcRad(in_lat) * cos(Deg2Rad(90-in_lat));
    double z2 = CalcRad(in_lat2) * cos(Deg2Rad(90-in_lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(CalcRad((double) (in_lat+in_lat2)/2),2));
    return CalcRad((double) (in_lat+in_lat2) / 2) * a;
}

double GPSDClient::CalcRad(double lat) {
    double a = 6378.137, r, sc, x, y, z;
    double e2 = 0.081082 * 0.081082;

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

