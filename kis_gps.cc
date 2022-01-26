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
#include "gpstracker.h"

kis_gps::kis_gps(shared_gps_builder in_builder) : 
    tracker_component() {

    register_fields();
    reserve_fields(NULL);

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    gpstracker = Globalreg::fetch_mandatory_global_as<gps_tracker>();

    // Force the ID
    set_id(Globalreg::globalreg->entrytracker->register_field("kismet.gps.instance", 
            tracker_element_factory<tracker_element_map>(), "GPS"));

    // Link the builder
    gps_prototype = in_builder;
    insert(gps_prototype);

    gps_location = packetchain->new_packet_component<kis_gps_packinfo>();
    gps_last_location = packetchain->new_packet_component<kis_gps_packinfo>();
}

kis_gps::~kis_gps() {

}

bool kis_gps::open_gps(std::string in_definition) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "kis_gps open_gps");

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
        if (string_to_opts(in_definition.substr(cpos + 1, 
                        in_definition.size() - cpos - 1), ",", &options) < 0) {
            return false;
        }

        for (auto i = options.begin(); i != options.end(); ++i) {
            source_definition_opts[str_lower((*i).opt)] = (*i).val;
        }
    }

    std::string sname = fetch_opt("name", source_definition_opts);
    if (sname != "") {
        set_int_gps_name(gpstracker->find_next_name(sname));
    } else {
        set_int_gps_name(gpstracker->find_next_name(gps_prototype->get_default_name()));
    }

    std::string suuid = fetch_opt("uuid", source_definition_opts);
    if (suuid != "") {
        // Use the static UUID from the definition
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
                adler32_checksum("kismet_gps", strlen("kismet_gps")) & 0xFFFFFFFF,
                adler32_checksum(id.c_str(), id.length()) & 0xFFFFFFFF);
        uuid u(ubuf);

        set_int_gps_uuid(u);
    }

    std::string sprio = fetch_opt("priority", source_definition_opts);
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

    set_int_gps_data_only(fetch_opt_bool("dataonly", source_definition_opts, false));

    set_int_gps_reconnect(fetch_opt_bool("reconnect", source_definition_opts, true));

    set_int_device_connected(true);

    return true;
}

double kis_gps::gps_calc_heading(double in_lat, double in_lon, double in_lat2, 
							   double in_lon2) {
    double r = gps_calc_rad((double) in_lat2);

    double lat1 = gps_deg_to_rad((double) in_lat);
    double lon1 = gps_deg_to_rad((double) in_lon);
    double lat2 = gps_deg_to_rad((double) in_lat2);
    double lon2 = gps_deg_to_rad((double) in_lon2);

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

    return (double) gps_rad_to_deg(angle);
}

double kis_gps::gps_rad_to_deg(double x) {
    return (x/M_PI) * 180.0;
}

double kis_gps::gps_deg_to_rad(double x) {
    return 180/(x*M_PI);
}

double kis_gps::gps_earth_distance(double in_lat, double in_lon, 
        double in_lat2, double in_lon2) {
    double x1 = gps_calc_rad(in_lat) * cos(gps_deg_to_rad(in_lon)) * sin(gps_deg_to_rad(90-in_lat));
    double x2 = 
        gps_calc_rad(in_lat2) * cos(gps_deg_to_rad(in_lon2)) * sin(gps_deg_to_rad(90-in_lat2));
    double y1 = gps_calc_rad(in_lat) * sin(gps_deg_to_rad(in_lon)) * sin(gps_deg_to_rad(90-in_lat));
    double y2 = 
        gps_calc_rad(in_lat2) * sin(gps_deg_to_rad(in_lon2)) * sin(gps_deg_to_rad(90-in_lat2));
    double z1 = gps_calc_rad(in_lat) * cos(gps_deg_to_rad(90-in_lat));
    double z2 = gps_calc_rad(in_lat2) * cos(gps_deg_to_rad(90-in_lat2));
    double a = 
        acos((x1*x2 + y1*y2 + z1*z2)/pow(gps_calc_rad((double) (in_lat+in_lat2)/2),2));
    return gps_calc_rad((double) (in_lat+in_lat2) / 2) * a;
}

double kis_gps::gps_calc_rad(double lat) {
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

void kis_gps::update_locations() {
    kis_lock_guard<kis_mutex> lk(data_mutex);
    set_int_gps_data_time(time(0));
    set_int_gps_signal_time(time(0));

    tracked_last_location->set_location(gps_last_location->lat, gps_last_location->lon);
    tracked_last_location->set_alt(gps_last_location->alt);
    tracked_last_location->set_speed(gps_last_location->speed);
    tracked_last_location->set_heading(gps_last_location->heading);
    tracked_last_location->set_fix(gps_last_location->fix);
    tracked_last_location->set_time_sec(gps_last_location->tv.tv_sec);
    tracked_last_location->set_time_usec(gps_last_location->tv.tv_usec);

    tracked_location->set_location(gps_location->lat, gps_location->lon);
    tracked_location->set_alt(gps_location->alt);
    tracked_location->set_speed(gps_location->speed);
    tracked_location->set_heading(gps_location->heading);
    tracked_location->set_fix(gps_location->fix);
    tracked_location->set_time_sec(gps_location->tv.tv_sec);
    tracked_location->set_time_usec(gps_location->tv.tv_usec);
}

