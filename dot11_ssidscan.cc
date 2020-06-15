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

#include "configfile.h"
#include "datasourcetracker.h"
#include "devicetracker.h"
#include "dot11_ssidscan.h"
#include "entrytracker.h"

dot11_ssid_scan::dot11_ssid_scan() {
    mutex.set_name("dot11_ssid_scan");

    timetracker = 
        Globalreg::fetch_mandatory_global_as<time_tracker>();
    hopping_mode_end_timer = -1;
    capture_mode_end_timer = -1;

    auto entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();

    auto devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    eventbus =
        Globalreg::fetch_mandatory_global_as<event_bus>();
    eventbus_id = 0;

    databaselog =
        Globalreg::fetch_mandatory_global_as<kis_database_logfile>();

    // We aren't a tracked component so we register our sub elements directly
    ssidscan_enabled =
        entrytracker->register_and_get_field_as<tracker_element_uint8>("dot11.ssidscan.enabled",
                tracker_element_factory<tracker_element_uint8>(),
                "SSIDScan module enabled");

    target_ssids =
        entrytracker->register_and_get_field_as<tracker_element_vector_string>("dot11.ssidscan.targets",
                tracker_element_factory<tracker_element_vector_string>(),
                "Target SSID regexes");

    ssidscan_datasources_uuids =
        entrytracker->register_and_get_field_as<tracker_element_vector>("dot11.ssidscan.datasources",
                tracker_element_factory<tracker_element_vector>(),
                "Usable datasource pool (UUIDs)");

    ssidscan_datasources =
        entrytracker->register_and_get_field_as<tracker_element_vector>("dot11.ssidscan.datasources",
                tracker_element_factory<tracker_element_vector>(),
                "Active datasource pool");

    ignore_after_handshake =
        entrytracker->register_and_get_field_as<tracker_element_uint8>("dot11.ssidscan.ignore_after_handshake",
            tracker_element_factory<tracker_element_uint8>(),
            "Ignore a device after a WPA handshake is captured");

    max_contend_cap_seconds =
        entrytracker->register_and_get_field_as<tracker_element_uint32>("dot11.ssidscan.max_cap_seconds",
            tracker_element_factory<tracker_element_uint32>(),
            "Maximum number of seconds to capture before returning to hop");

    min_scan_seconds =
        entrytracker->register_and_get_field_as<tracker_element_uint32>("dot11.ssidscan.min_scan_seconds",
            tracker_element_factory<tracker_element_uint32>(),
            "Minimum number of seconds to scan before locking to a channel if a device is present");

    initial_log_filters =
        entrytracker->register_and_get_field_as<tracker_element_uint8>("dot11.ssidscan.set_initial_log_filters",
            tracker_element_factory<tracker_element_uint8>(),
            "Automatically set the log to only pass target devices");

    filter_logs =
        entrytracker->register_and_get_field_as<tracker_element_uint8>("dot11.ssidscan.filter_logs",
            tracker_element_factory<tracker_element_uint8>(),
            "Automatically configure log filters to pass target devices");

    auto config = Globalreg::globalreg->kismet_config;

    ssidscan_enabled->set(config->fetch_opt_bool("dot11_ssidscan_enabled", false));

    for (auto s : config->fetch_opt_vec("dot11_ssidscan_ssid")) {
        target_ssids->push_back(s);
    }

    for (auto hu : config->fetch_opt_vec("dot11_ssidscan_datasource")) {
        auto hu_uuid = 
            std::make_shared<tracker_element_uuid>(uuid(hu));
        ssidscan_datasources->push_back(hu_uuid);
    }

    ignore_after_handshake->set(config->fetch_opt_bool("dot11_ssidscan_ignore_after_handshake", true));

    initial_log_filters->set(config->fetch_opt_bool("dot11_ssidscan_block_logging", false));
    filter_logs->set(config->fetch_opt_bool("dot11_ssidscan_dynamic_logging", true));

    min_scan_seconds->set(config->fetch_opt_uint("dot11_ssidscan_minimum_hop", 30));
    max_contend_cap_seconds->set(config->fetch_opt_uint("dot11_ssidscan_maximum_lock", 30));

    dot11_ssidscan_status_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/phy/phy80211/ssidscan/status", true,
                [this]() -> std::shared_ptr<tracker_element> {
                    auto retmap = std::make_shared<tracker_element_map>();

                    retmap->insert(ssidscan_enabled);
                    retmap->insert(target_ssids);
                    retmap->insert(ssidscan_datasources_uuids);
                    retmap->insert(ignore_after_handshake);
                    retmap->insert(initial_log_filters);
                    retmap->insert(filter_logs);
                    retmap->insert(min_scan_seconds);
                    retmap->insert(max_contend_cap_seconds);

                    return retmap;
                }, &mutex);

    dot11_ssidscan_config_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/phy/phy80211/ssidscan/config", true,
                [this](std::ostream& stream, const std::string& url,
                    const Json::Value& json, 
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return config_endp_handler(stream, url, json, variable_cache);
                }, &mutex);

    // Make the views with no completion functions, we maintain them manually
    target_devices_view =
        std::make_shared<device_tracker_view>(
                "phydot11_ssidscan_targets",
                "Devices matching ssid scan targets",
                nullptr, nullptr);
    devicetracker->add_view(target_devices_view);

    completed_device_view =
        std::make_shared<device_tracker_view>(
                "phydot11_ssidscan_completed",
                "SSID scan targets with completed handshakes",
                nullptr, nullptr);
    devicetracker->add_view(completed_device_view);

    eventbus_id =
        eventbus->register_listener("NEW_DATASOURCE",
                [this](std::shared_ptr<eventbus_event> evt) { handle_eventbus_evt(evt); });

}

dot11_ssid_scan::~dot11_ssid_scan() {
    eventbus->remove_listener(eventbus_id);
    timetracker->remove_timer(hopping_mode_end_timer);
    timetracker->remove_timer(capture_mode_end_timer);

}

void dot11_ssid_scan::handle_eventbus_evt(std::shared_ptr<eventbus_event> evt) {
    auto source_evt = 
        std::static_pointer_cast<datasource_tracker::event_new_datasource>(evt);

}

unsigned int dot11_ssid_scan::config_endp_handler(std::ostream& stream, const std::string& url,
        const Json::Value& json, kis_net_httpd_connection::variable_cache_map& variable_cache) {

    try {
        if (!json["ssidscan_enabled"].isNull()) {
            auto enabled = json["ssidscan_enabled"].asBool();

            if (enabled != ssidscan_enabled->get()) {
                if (enabled) {
                    _MSG_INFO("Enabling ssidscan module, this will change the behavior of datasources and logs.");
                    enable_ssidscan();
                } else {
                    _MSG_INFO("Disabling ssidscan module, data sources may remain in unexpected states.");
                    disable_ssidscan();
                }
            }
        }

        if (!json["ignore_after_handshake"].isNull())
            ignore_after_handshake->set(json["ignore_after_handshake"].asBool());

        if (!json["max_capture_seconds"].isNull()) 
            max_contend_cap_seconds->set(json["max_capture_seconds"].asBool());

        if (!json["min_scan_seconds"].isNull()) 
            min_scan_seconds->set(json["min_scan_seconds"].asBool());

        if (json["restrict_log_filters"].isNull()) {
            auto enabled = json["restrict_log_filters"].asBool();

            if (enabled != filter_logs->get()) {
                filter_logs->set(enabled);

                // TODO set filters for all existing devices
            } 
        }

    } catch (const std::exception& e) {
        stream << "Unable to configure: " << e.what() << "\n";
        return 500;
    }

    stream << "Unimplemented\n";
    return 500;
}

bool dot11_ssid_scan::enable_ssidscan() {
    local_locker l(&mutex);

    ssidscan_enabled->set(true);


    return false;
}

bool dot11_ssid_scan::disable_ssidscan() {
    local_locker l(&mutex);

    ssidscan_enabled->set(true);

    return false;
}

