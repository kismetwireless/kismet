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

#include "dot11_ssidscan.h"
#include "configfile.h"
#include "devicetracker.h"
#include "entrytracker.h"

Dot11_SsidScan::Dot11_SsidScan() {
    timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>();

    auto entrytracker = 
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>();

    auto devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>();

    // We aren't a tracked component so we register our sub elements directly
    ssidscan_enabled =
        entrytracker->RegisterAndGetFieldAs<TrackerElementUInt8>("dot11.ssidscan.enabled",
                TrackerElementFactory<TrackerElementUInt8>(),
                "SSIDScan module enabled");

    target_ssids =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVectorString>("dot11.ssidscan.targets",
                TrackerElementFactory<TrackerElementVectorString>(),
                "Target SSID regexes");

    hopping_datasources_uuids =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("dot11.ssidscan.hopping_ds_uuids",
                TrackerElementFactory<TrackerElementVector>(),
                "Hopping datasource pool (UUIDs)");

    locking_datasources_uuids =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("dot11.ssidscan.locking_ds_uuids",
                TrackerElementFactory<TrackerElementVector>(),
                "Locking datasource pool (UUIDs)");

    hopping_datasources =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("dot11.ssidscan.locking_ds",
                TrackerElementFactory<TrackerElementVector>(),
                "Hopping datasource pool");

    locking_datasources =
        entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("dot11.ssidscan.hopping_ds",
                TrackerElementFactory<TrackerElementVector>(),
                "Locking datasource pool");

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

    set_ssidscan_enabled(config->FetchOptBoolean("dot11_ssidscan_enabled", false));

    for (auto s : config->FetchOptVec("dot11_ssidscan_ssid")) {
        target_ssids->push_back(s);
    }

    for (auto hu : config->FetchOptVec("dot11_ssidscan_hop_datasource")) {
        auto hu_uuid = 
            std::make_shared<TrackerElementUUID>(uuid(hu));
        hopping_datasources_uuids->push_back(hu_uuid);
    }

    for (auto lu : config->FetchOptVec("dot11_ssidscan_lock_datasource")) {
        auto lu_uuid = 
            std::make_shared<TrackerElementUUID>(uuid(lu));
        locking_datasources_uuids->push_back(lu_uuid);
    }

    set_ignore_after_handshake(config->FetchOptBoolean("dot11_ssidscan_ignore_after_handshake", true));

    set_initial_log_filters(config->FetchOptBoolean("dot11_ssidscan_block_logging", false));
    set_filter_logs(config->FetchOptBoolean("dot11_ssidscan_dynamic_logging", true));

    set_min_scan_seconds(config->FetchOptUInt("dot11_ssidscan_minimum_hop", 30));
    set_max_contend_cap_seconds(config->FetchOptUInt("dot11_ssidscan_maximum_lock", 30));

    dot11_ssidscan_status_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/phy/phy80211/ssidscan/status", true,
                [this]() -> std::shared_ptr<TrackerElement> {
                    auto retmap = std::make_shared<TrackerElementMap>();

                    retmap->insert(ssidscan_enabled);
                    retmap->insert(target_ssids);
                    retmap->insert(hopping_datasources_uuids);
                    retmap->insert(locking_datasources_uuids);
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
                "phydot11_ssidtrack_targets",
                "Devices matching SSIDTrack targets",
                nullptr,
                nullptr);
    devicetracker->add_view(target_devices_view);

    completed_device_view =
        std::make_shared<DevicetrackerView>(
                "phydot11_ssidtrack_completed",
                "Devices with completed handshakes",
                nullptr,
                nullptr);
    devicetracker->add_view(completed_device_view);

}

