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

Dot11_SsidScan::Dot11_SsidScan() {
    timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>();
    hopping_mode_end_timer = -1;
    capture_mode_end_timer = -1;

    auto entrytracker = 
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>();

    auto devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>();

    eventbus =
        Globalreg::FetchMandatoryGlobalAs<Eventbus>();
    eventbus_id = 0;

    databaselog =
        Globalreg::FetchMandatoryGlobalAs<KisDatabaseLogfile>();

    // We aren't a tracked component so we register our sub elements directly
    ssidscan_enabled =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt8>("dot11.ssidscan.enabled",
                TrackerElementFactory<TrackerElementUInt8>(),
                "SSIDScan module enabled");

    target_ssids =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVectorString>("dot11.ssidscan.targets",
                TrackerElementFactory<TrackerElementVectorString>(),
                "Target SSID regexes");

    ssidscan_datasources_uuids =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("dot11.ssidscan.datasources",
                TrackerElementFactory<TrackerElementVector>(),
                "Usable datasource pool (UUIDs)");

    ssidscan_datasources =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("dot11.ssidscan.datasources",
                TrackerElementFactory<TrackerElementVector>(),
                "Active datasource pool");

    ignore_after_handshake =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt8>("dot11.ssidscan.ignore_after_handshake",
            TrackerElementFactory<TrackerElementUInt8>(),
            "Ignore a device after a WPA handshake is captured");

    max_contend_cap_seconds =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt32>("dot11.ssidscan.max_cap_seconds",
            TrackerElementFactory<TrackerElementUInt32>(),
            "Maximum number of seconds to capture before returning to hop");

    min_scan_seconds =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt32>("dot11.ssidscan.min_scan_seconds",
            TrackerElementFactory<TrackerElementUInt32>(),
            "Minimum number of seconds to scan before locking to a channel if a device is present");

    initial_log_filters =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt8>("dot11.ssidscan.set_initial_log_filters",
            TrackerElementFactory<TrackerElementUInt8>(),
            "Automatically set the log to only pass target devices");

    filter_logs =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt8>("dot11.ssidscan.filter_logs",
            TrackerElementFactory<TrackerElementUInt8>(),
            "Automatically configure log filters to pass target devices");

    auto config = Globalreg::globalreg->kismet_config;

    ssidscan_enabled->set(config->FetchOptBoolean("dot11_ssidscan_enabled", false));

    for (auto s : config->FetchOptVec("dot11_ssidscan_ssid")) {
        target_ssids->push_back(s);
    }

    for (auto hu : config->FetchOptVec("dot11_ssidscan_datasource")) {
        auto hu_uuid = 
            std::make_shared<TrackerElementUUID>(uuid(hu));
        ssidscan_datasources->push_back(hu_uuid);
    }

    ignore_after_handshake->set(config->FetchOptBoolean("dot11_ssidscan_ignore_after_handshake", true));

    initial_log_filters->set(config->FetchOptBoolean("dot11_ssidscan_block_logging", false));
    filter_logs->set(config->FetchOptBoolean("dot11_ssidscan_dynamic_logging", true));

    min_scan_seconds->set(config->FetchOptUInt("dot11_ssidscan_minimum_hop", 30));
    max_contend_cap_seconds->set(config->FetchOptUInt("dot11_ssidscan_maximum_lock", 30));

    dot11_ssidscan_status_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/phy/phy80211/ssidscan/status", true,
                [this]() -> std::shared_ptr<TrackerElement> {
                    auto retmap = std::make_shared<TrackerElementMap>();

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
        std::make_shared<Kis_Net_Httpd_Simple_Post_Endpoint>("/phy/phy80211/ssidscan/config", true,
                [this](std::ostream& stream, const std::string& url,
                    SharedStructured post_structured, 
                    Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) -> unsigned int {
                    return config_endp_handler(stream, url, post_structured, variable_cache);
                }, &mutex);

    // Make the views with no completion functions, we maintain them manually
    target_devices_view =
        std::make_shared<DevicetrackerView>(
                "phydot11_ssidscan_targets",
                "Devices matching ssid scan targets",
                nullptr, nullptr);
    devicetracker->add_view(target_devices_view);

    completed_device_view =
        std::make_shared<DevicetrackerView>(
                "phydot11_ssidscan_completed",
                "SSID scan targets with completed handshakes",
                nullptr, nullptr);
    devicetracker->add_view(completed_device_view);

    eventbus_id =
        eventbus->register_listener("NEW_DATASOURCE",
                [this](std::shared_ptr<EventbusEvent> evt) { handle_eventbus_evt(evt); });

}

Dot11_SsidScan::~Dot11_SsidScan() {
    eventbus->remove_listener(eventbus_id);
    timetracker->RemoveTimer(hopping_mode_end_timer);
    timetracker->RemoveTimer(capture_mode_end_timer);

}

void Dot11_SsidScan::handle_eventbus_evt(std::shared_ptr<EventbusEvent> evt) {
    auto source_evt = 
        std::static_pointer_cast<Datasourcetracker::EventNewDatasource>(evt);

}

unsigned int Dot11_SsidScan::config_endp_handler(std::ostream& stream, const std::string& url,
        SharedStructured post_structured, Kis_Net_Httpd_Connection::variable_cache_map& variable_cache) {

    try {
        if (post_structured->hasKey("ssidscan_enabled")) {
            auto enabled = post_structured->getKeyAsBool("ssidscan_enabled");

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

        if (post_structured->hasKey("ignore_after_handshake"))
            ignore_after_handshake->set(post_structured->getKeyAsBool("ignore_after_handshake"));

        if (post_structured->hasKey("max_capture_seconds")) 
            max_contend_cap_seconds->set(post_structured->getKeyAsNumber("max_capture_seconds"));

        if (post_structured->hasKey("min_scan_seconds")) 
            min_scan_seconds->set(post_structured->getKeyAsNumber("min_scan_seconds"));

        if (post_structured->hasKey("restrict_log_filters")) {
            auto enabled = post_structured->getKeyAsBool("restrict_log_filters");

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

bool Dot11_SsidScan::enable_ssidscan() {
    local_locker l(&mutex);

    ssidscan_enabled->set(true);


    return false;
}

bool Dot11_SsidScan::disable_ssidscan() {
    local_locker l(&mutex);

    ssidscan_enabled->set(true);

    return false;
}

