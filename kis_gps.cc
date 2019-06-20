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
#include "kis_gps.h"

#include "messagebus.h"
#include "timetracker.h"

KisGps::KisGps(SharedGpsBuilder in_builder) : 
    tracker_component() {

    gps_mutex = std::make_shared<kis_recursive_timed_mutex>();

    register_fields();
    reserve_fields(NULL);

    // Force the ID
    set_id(Globalreg::globalreg->entrytracker->RegisterField("kismet.gps.instance", 
            TrackerElementFactory<TrackerElementMap>(), "GPS"));

    // Link the builder
    gps_prototype = in_builder;
    insert(gps_prototype);

    gps_location = new kis_gps_packinfo();
    gps_last_location = new kis_gps_packinfo();
}

KisGps::~KisGps() {

}

bool KisGps::open_gps(std::string in_definition) {
    local_locker lock(gps_mutex);

    set_int_device_connected(false);
    set_int_gps_definition(in_definition);

    // Source extraction modeled on datasource
    // We already had to extract the type= option in the gps tracker to get to
    // here but it's easier to just do it again and happens very very rarely

    // gps=type:name=whatever,etc=something
   
    size_t cpos = in_definition.find(":");

    // Turn the rest into an opt vector
    std::vector<opt_pair> options;

    std::string types;

    // If there's no ':' then there are no options
    if (cpos == std::string::npos) {
        types = in_definition;
    } else {
        types = in_definition.substr(0, cpos);

        // Blow up if we fail parsing
        if (StringToOpts(in_definition.substr(cpos + 1, 
                        in_definition.size() - cpos - 1), ",", &options) < 0) {
            return false;
        }

        for (auto i = options.begin(); i != options.end(); ++i) {
            source_definition_opts[StrLower((*i).opt)] = (*i).val;
        }
    }

    std::string sname = FetchOpt("name", source_definition_opts);
    if (sname != "") {
        set_int_gps_name(sname);
    } else {
        set_int_gps_name(gps_prototype->get_default_name());
    }

    std::string suuid = FetchOpt("uuid", source_definition_opts);
    if (suuid != "") {
        // Use the static UUID from the defintion
        uuid u(suuid);

        if (u.error) {
            _MSG("Invalid UUID passed in GPS definition as uuid=... for " + 
                    get_gps_name(), MSGFLAG_FATAL);
            return false;
        }

        set_int_gps_uuid(u);
    } else {
        // Otherwise combine the server name and the definition, checksum it, and 
        // munge it into a UUID like we do for datasources
        std::string id = Globalreg::globalreg->servername + in_definition;
        char ubuf[40];

        snprintf(ubuf, 40, "%08X-0000-0000-0000-0000%08X",
                Adler32Checksum("kismet_gps", strlen("kismet_gps")) & 0xFFFFFFFF,
                Adler32Checksum(id.c_str(), id.length()) & 0xFFFFFFFF);
        uuid u(ubuf);

        set_int_gps_uuid(u);
    }

    std::string sprio = FetchOpt("priority", source_definition_opts);
    if (sprio != "") {
        int priority;

        if (sscanf(sprio.c_str(), "%d", &priority) != 1) {
            _MSG("Invalid priority passed in GPS definition as priority=... for " + 
                    get_gps_name(), MSGFLAG_FATAL);
            set_int_gps_priority(priority);
        }
    } else {
        set_int_gps_priority(gps_prototype->get_gps_priority());
    }

    set_int_gps_data_only(FetchOptBoolean("dataonly", source_definition_opts, false));

    set_int_device_connected(true);

    return true;
}

double KisGps::GpsCalcHeading(double in_lat, double in_lon, double in_lat2, 
							   double in_lon2) {
    double r = GpsCalcRad((double) in_lat2);

    double lat1 = GpsDeg2Rad((double) in_lat);
    double lon1 = GpsDeg2Rad((double) in_lon);
    double lat2 = GpsDeg2Rad((double) in_lat2);
    double lon2 = GpsDeg2Rad((double) in_lon2);

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

    return (double) GpsRad2Deg(angle);
}

double KisGps::GpsRad2Deg(double x) {
    return (x/M_PI) * 180.0;
}

double KisGps::GpsDeg2Rad(double x) {
    return 180/(x*M_PI);
}

double KisGps::GpsEarthDistance(double in_lat, double in_lon, 
        double in_lat2, double in_lon2) {
    double x1 = GpsCalcRad(in_lat) * cos(GpsDeg2Rad(in_lon)) * sin(GpsDeg2Rad(90-in_lat));
    double x2 = 
        GpsCalcRad(in_lat2) * cos(GpsDeg2Rad(in_lon2)) * sin(GpsDeg2Rad(90-in_lat2));
    double y1 = GpsCalcRad(in_lat) * sin(GpsDeg2Rad(in_lon)) * sin(GpsDeg2Rad(90-in_lat));
    double y2 = 
        GpsCalcRad(in_lat2) * sin(GpsDeg2Rad(in_lon2)) * sin(GpsDeg2Rad(90-in_lat2));
    double z1 = GpsCalcRad(in_lat) * cos(GpsDeg2Rad(90-in_lat));
    double z2 = GpsCalcRad(in_lat2) * cos(GpsDeg2Rad(90-in_lat2));
    double a = 
        acos((x1*x2 + y1*y2 + z1*z2)/pow(GpsCalcRad((double) (in_lat+in_lat2)/2),2));
    return GpsCalcRad((double) (in_lat+in_lat2) / 2) * a;
}

double KisGps::GpsCalcRad(double lat) {
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

void KisGps::update_locations() {
    tracked_last_location->set_lat(gps_last_location->lat);
    tracked_last_location->set_lon(gps_last_location->lon);
    tracked_last_location->set_alt(gps_last_location->alt);
    tracked_last_location->set_speed(gps_last_location->speed);
    tracked_last_location->set_heading(gps_last_location->heading);
    tracked_last_location->set_fix(gps_last_location->fix);
    tracked_last_location->set_time_sec(gps_last_location->tv.tv_sec);
    tracked_last_location->set_time_usec(gps_last_location->tv.tv_usec);

    tracked_location->set_lat(gps_location->lat);
    tracked_location->set_lon(gps_location->lon);
    tracked_location->set_alt(gps_location->alt);
    tracked_location->set_speed(gps_location->speed);
    tracked_location->set_heading(gps_location->heading);
    tracked_location->set_fix(gps_location->fix);
    tracked_location->set_time_sec(gps_location->tv.tv_sec);
    tracked_location->set_time_usec(gps_location->tv.tv_usec);
}

