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

#include <time.h>

#include "globalregistry.h"
#include "messagebus.h"
#include "gpstracker.h"
#include "kis_gps.h"
#include "configfile.h"

#include "gpsserial_v3.h"
#include "gpstcp_v2.h"
#include "gpsgpsd_v3.h"
#include "gpsfake.h"
#include "gpsweb.h"
#include "kis_databaselogfile.h"

gps_tracker::gps_tracker() :
    lifetime_global() {

    gpsmanager_mutex.set_name("gps_tracker");

    timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    tracked_uuid_addition_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.common.location.gps_uuid", 
                tracker_element_factory<tracker_element_uuid>(),
                "UUID of GPS reporting location");

    // Register the gps component
    pack_comp_gps =
        Globalreg::globalreg->packetchain->register_packet_component("GPS");
    pack_comp_no_gps =
        Globalreg::globalreg->packetchain->register_packet_component("NOGPS");

    // Register the packet chain hook
    Globalreg::globalreg->packetchain->register_handler(&kis_gpspack_hook, this,
            CHAINPOS_POSTCAP, -100);

    gps_prototypes_vec = std::make_shared<tracker_element_vector>();
    gps_instances_vec = std::make_shared<tracker_element_vector>();

    // Manage logging
    log_snapshot_timer = -1;

    database_logging = 
        Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_gps_track", true);

    if (database_logging) {
        _MSG("GPS track will be logged to the Kismet logfile", MSGFLAG_INFO);

        log_snapshot_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 1, 
                    [this](int) -> int { log_snapshot_gps(); return 1; });
    } else {
        _MSG("GPS track logging disabled", MSGFLAG_INFO);
    }

    // Register the built-in GPS drivers
    register_gps_builder(shared_gps_builder(new gps_serial_v3_builder()));
    register_gps_builder(shared_gps_builder(new gps_tcp_v2_builder()));
    register_gps_builder(shared_gps_builder(new gps_gpsd_v3_builder()));
    register_gps_builder(shared_gps_builder(new gps_fake_builder()));
    register_gps_builder(shared_gps_builder(new gps_web_builder()));

    // Process any gps options in the config file
    std::vector<std::string> gpsvec = Globalreg::globalreg->kismet_config->fetch_opt_vec("gps");
    for (auto g : gpsvec) {
        create_gps(g);
    }

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/gps/drivers", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(gps_prototypes_vec, gpsmanager_mutex));
    httpd->register_route("/gps/all_gps", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(gps_instances_vec, gpsmanager_mutex));
    httpd->register_route("/gps/location", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    local_shared_locker l(&gpsmanager_mutex, "/gps/location");
                    auto loctrip = std::make_shared<kis_tracked_location_full>();
                    auto ue = std::make_shared<tracker_element_uuid>(tracked_uuid_addition_id);

                    auto pi = std::unique_ptr<kis_gps_packinfo>(get_best_location());
                    if (pi != nullptr) {
                        ue->set(pi->gpsuuid);
                        loctrip->set_location(pi->lat, pi->lon);
                        loctrip->set_alt(pi->alt);
                        loctrip->set_speed(pi->speed);
                        loctrip->set_heading(pi->heading);
                        loctrip->set_fix(pi->fix);
                        loctrip->set_time_sec(pi->tv.tv_sec);
                        loctrip->set_time_usec(pi->tv.tv_usec);
                        loctrip->insert(ue);
                    }

                    return loctrip;
                }));

    event_timer_id = 
        timetracker->register_timer(std::chrono::seconds(1), true, 
                [this](int) -> int {
                local_shared_locker l(&gpsmanager_mutex, "location event");
                auto loctrip = std::make_shared<kis_tracked_location_full>();
                auto ue = std::make_shared<tracker_element_uuid>(tracked_uuid_addition_id);

                auto pi = std::unique_ptr<kis_gps_packinfo>(get_best_location());
                if (pi != nullptr) {
                    ue->set(pi->gpsuuid);
                    loctrip->set_location(pi->lat, pi->lon);
                    loctrip->set_alt(pi->alt);
                    loctrip->set_speed(pi->speed);
                    loctrip->set_heading(pi->heading);
                    loctrip->set_fix(pi->fix);
                    loctrip->set_time_sec(pi->tv.tv_sec);
                    loctrip->set_time_usec(pi->tv.tv_usec);
                    loctrip->insert(ue);
                }

                auto evt = eventbus->get_eventbus_event(event_gps_location());
                evt->get_event_content()->insert(event_gps_location(), loctrip);
                eventbus->publish(evt);

                return 1;
                });
}

gps_tracker::~gps_tracker() {
    Globalreg::globalreg->remove_global("GPSTRACKER");

    Globalreg::globalreg->packetchain->remove_handler(&kis_gpspack_hook, CHAINPOS_POSTCAP);

    timetracker->remove_timer(log_snapshot_timer);
    timetracker->remove_timer(event_timer_id);
}

void gps_tracker::log_snapshot_gps() {
    // Look for the log file driver, if it's not available, we
    // just exit until the next time
    std::shared_ptr<kis_database_logfile> dbf =
        Globalreg::fetch_global_as<kis_database_logfile>("DATABASELOG");

    if (dbf == NULL)
        return;

    local_shared_locker lock(&gpsmanager_mutex);

    // Log each GPS
    for (auto d : *gps_instances_vec) {
        struct timeval tv;
        gettimeofday(&tv, NULL);

        std::stringstream ss;
        Globalreg::globalreg->entrytracker->serialize("json", ss, d, NULL);

        dbf->log_snapshot(NULL, tv, "GPS", ss.str());
    }

    return;
}

void gps_tracker::register_gps_builder(shared_gps_builder in_builder) {
    local_locker lock(&gpsmanager_mutex);

    for (auto x : *gps_prototypes_vec) {
        shared_gps_builder gb = std::static_pointer_cast<kis_gps_builder>(x);

        if (gb->get_gps_class() == in_builder->get_gps_class()) {
            _MSG("GPSTRACKER - tried to register a duplicate GPS driver for '" +
                    in_builder->get_gps_class() + "'", MSGFLAG_ERROR);
            return;
        }
    }

    gps_prototypes_vec->push_back(in_builder);
}

std::shared_ptr<kis_gps> gps_tracker::create_gps(std::string in_definition) {
    local_locker lock(&gpsmanager_mutex);

    shared_gps gps;
    shared_gps_builder builder;

    size_t cpos = in_definition.find(":");
    std::string types;

    // Extract the type string
    if (cpos == std::string::npos) {
        types = in_definition;
    } else {
        types = in_definition.substr(0, cpos);
    }

    // Find a driver
    for (auto p : *gps_prototypes_vec) {
        shared_gps_builder optbuilder = std::static_pointer_cast<kis_gps_builder>(p);

        if (optbuilder->get_gps_class() == types) {
            builder = optbuilder;
            break;
        }
    }

    // Didn't find a builder... 
    if (builder == NULL) {
        _MSG("GPSTRACKER - Failed to find driver for gps type '" + types + "'",
                MSGFLAG_ERROR);
        return NULL;
    }

    // If it's a singleton make sure we don't have something built already
    if (builder->get_singleton()) {
        for (auto d : *gps_instances_vec) {
            shared_gps igps = std::static_pointer_cast<kis_gps>(d);

            if (igps->get_gps_prototype()->get_gps_class() == types) {
                _MSG("GPSTRACKER - Already defined a GPS of type '" + types + "', this "
                        "GPS driver cannot be defined multiple times.", MSGFLAG_ERROR);
                return NULL;
            }
        }
    }

    // Fetch an instance
    gps = builder->build_gps(builder);

    // Open it
    if (!gps->open_gps(in_definition)) {
        _MSG("GPSTRACKER - Failed to open GPS '" + gps->get_gps_name() + "'", MSGFLAG_ERROR);
        return NULL;
    }

    // Add it to the running GPS list
    gps_instances_vec->push_back(gps);

    // Sort running GPS by priority
    sort(gps_instances_vec->begin(), gps_instances_vec->end(), 
            [](const shared_tracker_element a, const shared_tracker_element b) -> bool {
                shared_gps ga = std::static_pointer_cast<kis_gps>(a);
                shared_gps gb = std::static_pointer_cast<kis_gps>(b);

                return ga->get_gps_priority() < gb->get_gps_priority();
            });

    return gps;
}

kis_gps_packinfo *gps_tracker::get_best_location() {
    local_shared_locker lock(&gpsmanager_mutex);

    // Iterate 
    for (auto d : *gps_instances_vec) {
        shared_gps gps = std::static_pointer_cast<kis_gps>(d);

        if (gps->get_gps_data_only())
            continue;

        if (gps->get_location_valid()) {
            kis_gps_packinfo *pi = new kis_gps_packinfo(gps->get_location());

            pi->gpsuuid = gps->get_gps_uuid();
            pi->gpsname  = gps->get_gps_name();

            return pi;
        }
    }

    return NULL;
}

int gps_tracker::kis_gpspack_hook(CHAINCALL_PARMS) {
    // We're an 'external user' of gps_tracker despite being inside it,
    // so don't do thread locking - that's up to gps_tracker internals
    
    gps_tracker *gpstracker = (gps_tracker *) auxdata;

    // Don't override if this packet already has a location, which could
    // come from a drone or from a PPI file
    if (in_pack->fetch(gpstracker->pack_comp_gps) != NULL)
        return 1;

    if (in_pack->fetch(gpstracker->pack_comp_no_gps) != NULL)
        return 1;

    kis_gps_packinfo *gpsloc = gpstracker->get_best_location();

    if (gpsloc == NULL)
        return 0;

    // Insert into chain; we were given a new location
    in_pack->insert(gpstracker->pack_comp_gps, gpsloc);

    return 1;
}

