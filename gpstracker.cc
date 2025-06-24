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
#include "gpsmeta.h"
#include "kis_databaselogfile.h"

gps_tracker::gps_tracker() :
    lifetime_global() {

    gpsmanager_mutex.set_name("gps_tracker");

    Globalreg::enable_pool_type<kis_tracked_location_triplet>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<kis_tracked_location>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<kis_tracked_location_full>([](auto *a) { a->reset(); });

    gps_prototypes_vec = std::make_shared<tracker_element_vector>();
    gps_instances_vec = std::make_shared<tracker_element_vector>();

}

gps_tracker::~gps_tracker() {
    Globalreg::globalreg->remove_global("GPSTRACKER");

    // Globalreg::globalreg->packetchain->remove_handler(&kis_gpspack_hook, CHAINPOS_POSTCAP);

    timetracker->remove_timer(log_snapshot_timer);
    timetracker->remove_timer(event_timer_id);
}

void gps_tracker::trigger_deferred_startup() {
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

    // Register the packet chain hook - deprecated, now handled in datasources
    // Globalreg::globalreg->packetchain->register_handler(&kis_gpspack_hook, this, CHAINPOS_POSTCAP, -100);

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
    register_gps_builder(shared_gps_builder(new gps_meta_builder()));

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
                    auto loctrip = Globalreg::globalreg->entrytracker->new_from_pool<kis_tracked_location_full>();
                    auto ue = Globalreg::globalreg->entrytracker->new_from_pool<tracker_element_uuid>();
                    ue->set_id(tracked_uuid_addition_id);

                    auto pi = get_best_location();
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
                }, gpsmanager_mutex));

    httpd->register_route("/gps/by-uuid/:uuid/location", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto gpsuuid = string_to_n<uuid>(con->uri_params()[":uuid"]);
                    if (gpsuuid.error)
                        throw std::runtime_error("invalid UUID");

                    auto gps = find_gps(gpsuuid);

                    if (gps == nullptr)
                        throw std::runtime_error("unknown GPS");

                    auto loctrip = std::make_shared<kis_tracked_location_full>();
                    auto ue = std::make_shared<tracker_element_uuid>(tracked_uuid_addition_id);

                    auto pi = gps->get_location();
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
                }, gpsmanager_mutex));

    httpd->register_route("/gps/all_locations", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    auto ret = std::make_shared<tracker_element_uuid_map>();
                
                    for (const auto& g : *gps_instances_vec) {
                        auto gps = static_cast<kis_gps *>(g.get());
                        auto loctrip = std::make_shared<kis_tracked_location_full>();

                        auto pi = gps->get_location();
                        if (pi != nullptr) {
                            loctrip->set_location(pi->lat, pi->lon);
                            loctrip->set_alt(pi->alt);
                            loctrip->set_speed(pi->speed);
                            loctrip->set_heading(pi->heading);
                            loctrip->set_fix(pi->fix);
                            loctrip->set_time_sec(pi->tv.tv_sec);
                            loctrip->set_time_usec(pi->tv.tv_usec);
                        }

                        ret->insert(gps->get_gps_uuid(), loctrip);
                    }

                    return ret;
                }, gpsmanager_mutex));

    httpd->register_route("/gps/add_gps", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) -> std::shared_ptr<tracker_element> {
                    std::shared_ptr<kis_gps> new_gps;

                    auto definition = con->json()["definition"].get<std::string>();

                    new_gps = create_gps(definition);

                    if (new_gps == nullptr) {
                        con->set_status(500);
                        return std::make_shared<tracker_element_map>();
                    }

                    return new_gps;
                }));

    httpd->register_route("/gps/by-uuid/:uuid/remove_gps", {"GET"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    std::ostream stream(&con->response_stream());

                    auto gpsuuid = string_to_n<uuid>(con->uri_params()[":uuid"]);
                    if (gpsuuid.error)
                        throw std::runtime_error("invalid UUID");

                    auto gps = find_gps(gpsuuid);

                    if (gps == nullptr)
                        throw std::runtime_error("unknown GPS");

                    if (!remove_gps(gpsuuid))
                        throw std::runtime_error("could not remove specified GPS");

                    _MSG_INFO("GPS {} ({}) removed", gps->get_gps_name(), gpsuuid);

                    stream << "Removed GPS\n";
                }));

    event_timer_id = 
        timetracker->register_timer(std::chrono::seconds(1), true, 
                [this](int) -> int {
                    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "gps_tracker location event");

                    auto loctrip = Globalreg::globalreg->entrytracker->new_from_pool<kis_tracked_location_full>();
                    auto ue = Globalreg::globalreg->entrytracker->new_from_pool<tracker_element_uuid>();
                    ue->set_id(tracked_uuid_addition_id);

                    auto pi = get_best_location();
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

void gps_tracker::log_snapshot_gps() {
    // Look for the log file driver, if it's not available, we
    // just exit until the next time
    std::shared_ptr<kis_database_logfile> dbf =
        Globalreg::fetch_global_as<kis_database_logfile>("DATABASELOG");

    if (dbf == NULL)
        return;

    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "gps_tracker log_snapshot_gps");

    // Log each GPS
    for (auto d : *gps_instances_vec) {
        auto dg = static_cast<kis_gps *>(d.get());

        struct timeval tv;
        gettimeofday(&tv, NULL);

        std::stringstream ss;
        Globalreg::globalreg->entrytracker->serialize("json", ss, d, NULL);

        dbf->log_snapshot(dg->get_location(), tv, "GPS", ss.str());
    }

    return;
}

void gps_tracker::register_gps_builder(shared_gps_builder in_builder) {
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "gps_tracker register_gps_builder");

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
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "create_gps");

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
                auto ga = static_cast<kis_gps *>(a.get());
                auto gb = static_cast<kis_gps *>(b.get());

                return ga->get_gps_priority() < gb->get_gps_priority();
            });

    return gps;
}

std::string gps_tracker::find_next_name(const std::string& in_name) {
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "gps_tracker find_next_name");

    auto found_name = [this](const std::string& name) -> bool {
        for (const auto& g : *gps_instances_vec) {
            auto gps = static_cast<kis_gps *>(g.get());
            if (gps->get_gps_name() == name)
                return true;
        }

        return false;
    };

    if (!found_name(in_name))
        return in_name;

    for (unsigned int num = 1; num < 1000; num++) {
        auto proposed = fmt::format("{}{}", in_name, num);

        if (!found_name(proposed))
            return proposed;
    }

    _MSG_FATAL("Could not form a unique GPS name within 1000 attempts for a "
            "GPS called {}.  Check your configs, and provide GPS names.",
            in_name);

    return "ERROR";
}

bool gps_tracker::remove_gps(uuid in_uuid) {
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "remove_gps");

    if (gps_instances_vec == nullptr)
        return false;

    for (unsigned int i = 0; i < gps_instances_vec->size(); i++) {
        auto gps = static_cast<kis_gps *>((*gps_instances_vec)[i].get());

        if (gps->get_gps_uuid() == in_uuid) {
            gps_instances_vec->erase(gps_instances_vec->begin() + i);

            return true;
        }
    }

    return false;
}

std::shared_ptr<kis_gps> gps_tracker::find_gps(uuid in_uuid) {
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "find_gps");

    if (gps_instances_vec == nullptr)
        return nullptr;

    for (const auto& g : *gps_instances_vec) {
        auto gps = std::static_pointer_cast<kis_gps>(g);

        if (gps->get_gps_uuid() == in_uuid) {
            return gps;
        }
    }

    return nullptr;
}

std::shared_ptr<kis_gps> gps_tracker::find_gps_by_name(const std::string& in_name) {
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "find_gps_by_name");

    if (gps_instances_vec == nullptr)
        return nullptr;

    for (const auto& g : *gps_instances_vec) {
        auto gps = std::static_pointer_cast<kis_gps>(g);

        if (gps->get_gps_name() == in_name)
            return gps;
    }

    return nullptr;
}

std::shared_ptr<kis_gps_packinfo> gps_tracker::get_best_location() {
    kis_lock_guard<kis_mutex> lk(gpsmanager_mutex, "get_best_location");

    if (gps_instances_vec == nullptr)
        return nullptr;

    // Iterate 
    for (const auto& d : *gps_instances_vec) {
        auto gps = static_cast<kis_gps *>(d.get());

        if (gps->get_gps_data_only())
            continue;

        if (gps->get_location_valid()) {
            return gps->get_location();
        }
    }

    return nullptr;
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

    auto gpsloc = gpstracker->get_best_location();

    if (gpsloc == nullptr)
        return 0;

    // Insert into chain; we were given a new location
    in_pack->insert(gpstracker->pack_comp_gps, std::move(gpsloc));

    return 1;
}

