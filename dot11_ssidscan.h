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

#ifndef __PHY_80211_SSIDSCAN__
#define __PHY_80211_SSIDSCAN__ 

#include "config.h"

#include "kis_net_microhttpd.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_microhttpd.h"
#include "devicetracker_view.h"
#include "timetracker.h"

/* SSID scan mode
 *
 * 1.  Take a list of SSIDs (or SSID regexes), and optionally a list of 
 *     hopping and locking sources
 * 2.  Channel hop looking for devices advertising the SSID
 * 3.  Lock a source to the channel, set a log filter to enable logging the 
 *     target bssid device and packets, and capture data about the target 
 *     bssid until a WPA handshake is seen or the maximum lock time has
 *     expired
 * 4.  Continue hopping
 *
 *
 * Configuration options:
 *
 * Enable ssidscan mode at all
 * bool: dot11_ssidscan_enabled=true
 *
 * Target SSIDs
 * multiple/vector: dot11_ssidscan_ssid=....(regex) 
 *
 * Datasource UUIDs to use for hopping
 * multiple/vector: dot11_ssidscan_hop_datasource=...
 *
 * Datasource UUIDs to use for locking
 * multiple/vector: dot11_ssidscan_lock_datasource=...
 *
 * Block initial logging of devices & packets and only log ours
 * bool: dot11_ssidscan_block_logging=true
 *
 * Manipulate logging to log target devices and packets
 * bool: dot11_ssidscan_dynamic_logging=true
 *
 * Ignore a device entirely once we've captured a handshake:
 * bool: dot11_ssidscan_ignore_after_handshake=true
 *
 * Minimum amount of time to spend scanning even if a target is nearby
 * uint: dot11_ssidscan_minimum_hop=123
 *
 * Maximum amount of time to spend locked to a device, even if we don't
 * capture a handshake
 * uint: dot11_ssidscan_maximum_lock=123
 *
 *
 * Endpoints
 * GET  AUTH /phy/phy80211/ssidscan/status.json
 * POST AUTH /phy/phy80211/ssidscan/config.cmd
 *
 * VIEW      /devices/view/ssidscan/devices.json etc
 *
 */

class Dot11_SsidScan : public LifetimeGlobal {
public:
    static std::string global_name() { return "DOT11_SSIDSCAN"; }

    static std::shared_ptr<Dot11_SsidScan> create_ssidscan() {
        std::shared_ptr<Dot11_SsidScan> shared(new Dot11_SsidScan());
        Globalreg::globalreg->RegisterLifetimeGlobal(shared);
        Globalreg::globalreg->InsertGlobal(global_name(), shared);
        return shared;
    }

private:
    Dot11_SsidScan();

public:
    virtual ~Dot11_SsidScan();

protected:
    __Proxy(ssidscan_enabled, uint8_t, bool, bool, ssidscan_enabled);
    __Proxy(ignore_after_handshake, uint8_t, bool, bool, ignore_after_handshake);
    __Proxy(max_contend_cap_seconds, uint32_t, uint32_t, uint32_t, max_contend_cap_seconds);
    __Proxy(min_scan_seconds, uint32_t, uint32_t, uint32_t, min_scan_seconds);
    __Proxy(initial_log_filters, uint8_t, bool, bool, initial_log_filters);
    __Proxy(filter_logs, uint8_t, bool, bool, filter_logs);

    kis_recursive_timed_mutex mutex;

    // Are we active at all?
    std::shared_ptr<TrackerElementUInt8> ssidscan_enabled;

    // Target SSIDs
    std::shared_ptr<TrackerElementVectorString> target_ssids;

    // Pool of sources (if multiple are available)
    std::shared_ptr<TrackerElementVector> hopping_datasources_uuids;
    std::shared_ptr<TrackerElementVector> locking_datasources_uuids;

    std::shared_ptr<TrackerElementVector> hopping_datasources;
    std::shared_ptr<TrackerElementVector> locking_datasources;

    // Do we ignore a target bssid after we think we got a handshake?
    std::shared_ptr<TrackerElementUInt8> ignore_after_handshake;

    // Maximum time spent capturing if no free source is in the 'hopping' pool
    // or if there are multiple target bssids
    std::shared_ptr<TrackerElementUInt32> max_contend_cap_seconds;

    // Minimum time spent hopping looking for targets if no free source is in the 
    // 'locked' pool, even if there are targets in view
    std::shared_ptr<TrackerElementUInt32> min_scan_seconds;

    // Automatically set the log filters on startup to exclude all devices and 
    // packets except the ones we specify
    std::shared_ptr<TrackerElementUInt8> initial_log_filters;

    // Filter logging; otherwise log all packets (or whatever the user configured)
    // and just manipulate the sources
    std::shared_ptr<TrackerElementUInt8> filter_logs;

    // Status/config view endp
    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> dot11_ssidscan_status_endp;

    // Configure set endp
    std::shared_ptr<Kis_Net_Httpd_Simple_Post_Endpoint> dot11_ssidscan_config_endp;
    unsigned int config_endp_handler(std::ostream& stream, const std::string& url,
            SharedStructured post_structured, Kis_Net_Httpd_Connection::variable_cache_map& variable_cache);

    // Reference we hold to the device view we populate with matched devices which may
    // include completed devices
    std::shared_ptr<DevicetrackerView> target_devices_view;

    // Reference we h old to the device view we populate with 'completed' devices that have
    // seen a wpa handshake
    std::shared_ptr<DevicetrackerView> completed_device_view;

    std::shared_ptr<Timetracker> timetracker;
    int hopping_mode_end_timer;
    int capture_mode_end_timer;

};

#endif /* ifndef PHY_80211_SSIDSCAN */
