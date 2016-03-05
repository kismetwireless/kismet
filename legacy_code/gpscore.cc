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
#include "gpscore.h"
#include "configfile.h"
#include "soundcontrol.h"
#include "packetchain.h"

const char *GPS_fields_text[] = {
    "lat", "lon", "alt", "spd", "heading", "fix", "satinfo", "hdop", "vdop",
	"connected",
    NULL
};

int Protocol_GPS(PROTO_PARMS) {
    GPS_data *gdata = (GPS_data *) data;

    for (unsigned int x = 0; x < field_vec->size(); x++) {
		if ((*field_vec)[x] >= GPS_maxfield) {
			out_string += "Unknown field requested";
			return -1;
		}

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
		case GPS_satinfo:
			out_string += gdata->satinfo;
			break;
		case GPS_hdop:
			out_string += gdata->hdop;
			break;
		case GPS_vdop:
			out_string += gdata->vdop;
			break;
		case GPS_connected:
			out_string += gdata->connected;
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

int kis_gpspack_hook(CHAINCALL_PARMS) {
	// Simple packet insertion of current GPS coordinates
	GPSCore *cli = (GPSCore *) auxdata;
	
	// Don't bother attaching data if we're no good
	if (cli->FetchMode() <= 0)
		return 0;

	kis_gps_packinfo *gpsdat = new kis_gps_packinfo;

	// Don't override if we already have a tagged packet (like from a drone)
	if (in_pack->fetch(_PCM(PACK_COMP_GPS)) != NULL)
		return 1;

	cli->FetchLoc(&(gpsdat->lat), &(gpsdat->lon), &(gpsdat->alt),
				  &(gpsdat->spd), &(gpsdat->heading), &(gpsdat->gps_fix));
	
	in_pack->insert(_PCM(PACK_COMP_GPS), gpsdat);

	return 1;
}

GPSCore::GPSCore() {
    fprintf(stderr, "FATAL OOPS: GPSCore called with no globalreg\n");
	exit(-1);
}

GPSCore::GPSCore(GlobalRegistry *in_globalreg) : ClientFramework(in_globalreg) {
	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  GPSCore called before packetchain\n");
		exit(1);
	}

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  GPSCore called before kismet_config\n");
		exit(1);
	}

	last_disconnect = 0;
    reconnect_attempt = -1;

    mode = -1;
    lat = lon = alt = spd = hed = last_lat = last_lon = last_hed = 0;
	hdop = vdop = 0;
	gps_ever_lock = 0;

	gps_connected = 0;

	gpseventid = -1;
}

GPSCore::~GPSCore() {
	if (gpseventid >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(gpseventid);

	// Unregister ourselves from the main tcp service loop
	globalreg->RemovePollableSubsys(this);
}

int GPSCore::ScanOptions() {
	// Lock GPS position
	if (globalreg->kismet_config->FetchOpt("gpsmodelock") == "true") {
		_MSG("Enabling GPS position information override (override broken GPS "
			 "units that always report 0 in the NMEA stream)", MSGFLAG_INFO);
		SetOptions(GPSD_OPT_FORCEMODE);
	}

	if (globalreg->kismet_config->FetchOpt("gpsreconnect") == "true") {
		_MSG("Enabling reconnection to the GPS device if the link is lost", 
			 MSGFLAG_INFO);
		reconnect_attempt = 0;
	}

	return 1;
}

int GPSCore::RegisterComponents() {
	// Register the network protocol
	gps_proto_ref = 
		globalreg->kisnetserver->RegisterProtocol("GPS", 0, 0, GPS_fields_text, 
												  &Protocol_GPS, NULL, this);

	// Register the gps component and packetchain hooks to include it
	_PCM(PACK_COMP_GPS) =
		globalreg->packetchain->RegisterPacketComponent("gps");
	globalreg->packetchain->RegisterHandler(&kis_gpspack_hook, this,
											CHAINPOS_POSTCAP, -100);

	return 1;
}

int GPSCore::FetchLoc(double *in_lat, double *in_lon, double *in_alt, 
                         double *in_spd, double *in_hed, int *in_mode) {
    *in_lat = lat;
    *in_lon = lon;
    *in_alt = alt;
    *in_spd = spd;
    *in_mode = mode;
    *in_hed = hed;

    return mode;
}

double GPSCore::CalcHeading(double in_lat, double in_lon, double in_lat2, 
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

double GPSCore::Rad2Deg(double x) {
    return (x/M_PI) * 180.0;
}

double GPSCore::Deg2Rad(double x) {
    return 180/(x*M_PI);
}

double GPSCore::EarthDistance(double in_lat, double in_lon, double in_lat2, double in_lon2) {
    double x1 = CalcRad(in_lat) * cos(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double x2 = CalcRad(in_lat2) * cos(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double y1 = CalcRad(in_lat) * sin(Deg2Rad(in_lon)) * sin(Deg2Rad(90-in_lat));
    double y2 = CalcRad(in_lat2) * sin(Deg2Rad(in_lon2)) * sin(Deg2Rad(90-in_lat2));
    double z1 = CalcRad(in_lat) * cos(Deg2Rad(90-in_lat));
    double z2 = CalcRad(in_lat2) * cos(Deg2Rad(90-in_lat2));
    double a = acos((x1*x2 + y1*y2 + z1*z2)/pow(CalcRad((double) (in_lat+in_lat2)/2),2));
    return CalcRad((double) (in_lat+in_lat2) / 2) * a;
}

double GPSCore::CalcRad(double lat) {
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

int GPSCore::Timer() {
	// Pick up if we've ever locked in
	if (mode >= 2)
		gps_ever_lock = 1;

	// Always send info
	GPS_data gdata;

	gdata.lat = NtoString<double>(lat, 6).Str();
	gdata.lon = NtoString<double>(lon, 6).Str();
	gdata.alt = NtoString<double>(alt).Str();
	gdata.spd = NtoString<double>(spd).Str();
	gdata.heading = NtoString<double>(hed).Str();
	gdata.mode = last_disconnect == 0 ? IntToString(mode) : "0";
	gdata.hdop = NtoString<double>(hdop).Str();
	gdata.vdop = NtoString<double>(vdop).Str();
	gdata.connected = (gps_connected == 1 && last_disconnect == 0) ? "1" : "0";

	gdata.satinfo = "\001";
	for (map<int, sat_pos>::iterator x = sat_pos_map.begin(); 
		 x != sat_pos_map.end(); ++x) {
		gdata.satinfo += IntToString(x->second.prn) + string(":") +
			IntToString(x->second.elevation) + string(":") +
			IntToString(x->second.azimuth) + string(":") +
			IntToString(x->second.snr) + string(",");
	}
	gdata.satinfo += "\001";

	globalreg->kisnetserver->SendToAll(gps_proto_ref, (void *) &gdata);

	// Make an empty packet w/ just GPS data for the gpsxml logger to catch
	kis_packet *newpack = globalreg->packetchain->GeneratePacket();
	kis_gps_packinfo *gpsdat = new kis_gps_packinfo;
	newpack->ts.tv_sec = globalreg->timestamp.tv_sec;
	newpack->ts.tv_usec = globalreg->timestamp.tv_usec;
	FetchLoc(&(gpsdat->lat), &(gpsdat->lon), &(gpsdat->alt),
			 &(gpsdat->spd), &(gpsdat->heading), &(gpsdat->gps_fix));
	newpack->insert(_PCM(PACK_COMP_GPS), gpsdat);
	globalreg->packetchain->ProcessPacket(newpack);

	return 1;
}

