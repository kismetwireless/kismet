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

#ifndef __DEVICE_TRACKER_H__
#define __DEVICE_TRACKER_H__

#include "config.h"

#include <atomic>
#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdexcept>
#include <utility>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packetchain.h"
#include "timetracker.h"
#include "uuid.h"
#include "configfile.h"
#include "kis_datasource.h"
#include "packinfo_signal.h"
#include "devicetracker_component.h"
#include "trackercomponent_legacy.h"
#include "timetracker.h"
#include "kis_net_beast_httpd.h"
#include "devicetracker_view.h"
#include "devicetracker_view_workers.h"
#include "kis_database.h"
#include "eventbus.h"
#include "unordered_dense.h"
#include "streamtracker.h"

#define KIS_PHY_ANY	-1
#define KIS_PHY_UNKNOWN -2

class kis_phy_handler;
class kis_packet;

class device_tracker : public lifetime_global, public kis_database, 
    public deferred_startup, public std::enable_shared_from_this<device_tracker> {

public:
    static std::string global_name() { return "DEVICETRACKER"; }

    static std::shared_ptr<device_tracker> create_device_tracker() {
        std::shared_ptr<device_tracker> mon(new device_tracker());
        Globalreg::globalreg->devicetracker = mon.get();
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
	device_tracker();

public:
	virtual ~device_tracker();

    virtual void trigger_deferred_startup() override;

	// Register a phy handler weak class, used to instantiate the strong class
	// inside devtracker
	int register_phy_handler(kis_phy_handler *in_weak_handler);

	kis_phy_handler *fetch_phy_handler(int in_phy);
    kis_phy_handler *fetch_phy_handler_by_name(const std::string& in_name);

    static std::string event_new_phy() {
        return "NEW_PHY";
    }

    static std::string event_new_device() {
        return "NEW_DEVICE";
    }

    std::string fetch_phy_name(int in_phy);

	int fetch_num_devices();
	int fetch_num_packets();

	int add_filter(std::string in_filter);
	int add_net_cli_filter(std::string in_filter);

    // Flag that we've altered the device structure in a way that a client should
    // perform a full pull.  For instance, removing devices or device record
    // components due to timeouts / max device cleanup
    void update_full_refresh();

	// Look for an existing device record under read-only shared lock
    std::shared_ptr<kis_tracked_device_base> fetch_device(const device_key& in_key);

    // Fetch one or more devices by mac address or mac mask
    std::vector<std::shared_ptr<kis_tracked_device_base>> fetch_devices(const mac_addr& in_mac);

    // Look for an existing device record, without lock - must be called under some form of existing
    // lock to be safely used
    std::shared_ptr<kis_tracked_device_base> fetch_device_nr(const device_key& in_key);

    // Do work on all devices, this applies to the 'all' device view
    std::shared_ptr<tracker_element_vector> do_device_work(device_tracker_view_worker& worker);
    std::shared_ptr<tracker_element_vector> do_readonly_device_work(device_tracker_view_worker& worker);

    // Do work on all devices, but using a limited sub-section vector.  This does NOT
    // make an immutable copy of the vector.
    std::shared_ptr<tracker_element_vector> do_device_work(device_tracker_view_worker& worker, 
            std::shared_ptr<tracker_element_vector> source_vec);
    // Perform a readonly filter, MUST NOT modify devices
    std::shared_ptr<tracker_element_vector> do_readonly_device_work(device_tracker_view_worker& worker, 
            std::shared_ptr<tracker_element_vector> source_vec);

    using device_map_t = ankerl::unordered_dense::map<device_key, std::shared_ptr<kis_tracked_device_base>>;
    using device_itr = device_map_t::iterator;
    using const_device_itr = device_map_t::const_iterator;

	static void usage(char *argv);

    // Add common into to a device.  If necessary, create the new device.
    //
    // The specified mac is used to create the device; for phys with multiple devices
    // per packet (such as dot11), this is uses to specify which address the
    // device is linked to
    //
    // This will update location, signal, manufacturer, and seenby values.
    // It will NOT update packet count, data size, or encryption options:  The
    // Phy handler should update those values itself.
    //
    // Phy handlers should call this to populate associated devices when a phy
    // packet is encountered.
    //
    // It is recommended that plugin developers look at the update_common_device
    // implementation in devicetracker.cc as well as the reference implementations
    // in phy80211 and other native code, as this is one of the most complex
    // functions a phy handler will interact with when building trackable devices.
    //
    // Accepts a bitset of flags for what attributes of the device should be
    // automatically updated based on the known packet data.
    //
    // Returns the device.
// Update signal levels in common device
#define UCD_UPDATE_SIGNAL       1
// Update frequency/channel and the seenby maps in common device
#define UCD_UPDATE_FREQUENCIES  (1 << 1)
// Update packet counts in common device
#define UCD_UPDATE_PACKETS      (1 << 2)
// Update GPS data in common device
#define UCD_UPDATE_LOCATION     (1 << 3)
// Update device seenby records
#define UCD_UPDATE_SEENBY       (1 << 4)
// Update encryption options
#define UCD_UPDATE_ENCRYPTION   (1 << 5)
// Never create a new device, only update an existing one
#define UCD_UPDATE_EXISTING_ONLY    (1 << 6)
// Only update signal if we have no existing data
#define UCD_UPDATE_EMPTY_SIGNAL     (1 << 7)
// Only update location if we have no existing location
#define UCD_UPDATE_EMPTY_LOCATION   (1 << 8)

    std::shared_ptr<kis_tracked_device_base> update_common_device(
            const std::shared_ptr<kis_common_info>& pack_common,
            const mac_addr& in_mac, kis_phy_handler *phy,
            const std::shared_ptr<kis_packet>& in_pack, unsigned int in_flags,
            const std::string& in_basic_type);

    // Set the common name of a device (and log it in the database for future runs)
    void set_device_user_name(std::shared_ptr<kis_tracked_device_base> in_dev,
            const std::string& in_username);

    // Set an arbitrary tag (and log it in the database for future runs)
    void set_device_tag(std::shared_ptr<kis_tracked_device_base> in_dev,
            const std::string& in_tag, const std::string& in_content);

    // CLI extension
    static void usage(const char *name);

    void lock_devicelist();
    void unlock_devicelist();

    std::shared_ptr<kis_tracked_rrd<> > get_packets_rrd() {
        return packets_rrd;
    }

    // Database API
    virtual int database_upgrade_db() override;

    // Store all devices to the database
    virtual void databaselog_write_devices();

    // View API
    virtual bool add_view(std::shared_ptr<device_tracker_view> in_view);
    virtual void remove_view(const std::string& in_view_id);

    virtual void new_view_device(std::shared_ptr<kis_tracked_device_base> in_device);
    virtual void update_view_device(std::shared_ptr<kis_tracked_device_base> in_device);
    virtual void remove_view_device(std::shared_ptr<kis_tracked_device_base> in_device);

    // Get phy views
    std::shared_ptr<device_tracker_view> get_phy_view(int in_phy);

    // Get a cached device type; use this to de-dup thousands of devices of the same types.
    std::shared_ptr<tracker_element_string> get_cached_devicetype(const std::string& type);

    // Get a cached phyname; use this to de-dup thousands of devices phynames
    std::shared_ptr<tracker_element_string> get_cached_phyname(const std::string& phyname);

    // Expose to devicelist mutex for external batch locking
    kis_mutex& get_devicelist_mutex() {
        return devicelist_mutex;
    }

protected:
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<event_bus> eventbus;
    std::shared_ptr<alert_tracker> alertracker;
    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<stream_tracker> streamtracker;

    void timetracker_event(int eventid);

	// Common classifier for keeping phy counts
	int common_tracker(const std::shared_ptr<kis_packet>&);

    unsigned long new_datasource_evt_id, new_device_evt_id;

    int packetchain_common_id, packetchain_tracking_done_id;

    std::shared_ptr<device_tracker_view> all_view;

    // Map of seen-by views
    bool map_seenby_views;
    ankerl::unordered_dense::map<uuid, std::shared_ptr<device_tracker_view>> seenby_view_map;

    // Map of phy views
    bool map_phy_views;
    ankerl::unordered_dense::map<int, std::shared_ptr<device_tracker_view>> phy_view_map;

    // Base IDs for tracker components
    int device_list_base_id, device_base_id;
    int device_summary_base_id;
    int device_update_required_id, device_update_timestamp_id;

    int dt_length_id, dt_filter_id, dt_draw_id;

	// Total # of packets
    std::atomic<int> num_packets;
	std::atomic<int> num_datapackets;
	std::atomic<int> num_errorpackets;
	std::atomic<int> num_filterpackets;

	// Per-phy #s of packets
    std::map<int, std::atomic<int>> phy_packets;
	std::map<int, std::atomic<int>> phy_datapackets;
	std::map<int, std::atomic<int>> phy_errorpackets;
	std::map<int, std::atomic<int>> phy_filterpackets;

    // Total packet history
    std::shared_ptr<kis_tracked_rrd<> > packets_rrd;

    // Timeout of idle devices
    int device_idle_expiration;
    int device_idle_timer;

    // Minimum number of packets a device may have to be eligible for
    // being timed out
    unsigned int device_idle_min_packets;

    // Maximum number of devices
    unsigned int max_num_devices;
    int max_devices_timer;

    // Timer event for storing devices
    int device_storage_timer;

    // Timestamp for the last time we removed a device
    std::atomic<time_t> full_refresh_time;

    bool track_history_cloud;
    bool track_persource_history;

	// Common device component
	int devcomp_ref_common;

    // Packet components we add or interact with
    int pack_comp_device, pack_comp_common, pack_comp_basicdata,
        pack_comp_radiodata, pack_comp_gps, pack_comp_datasrc,
        pack_comp_mangleframe, pack_comp_devicetag;


    // Generic device alert based on flagged MACs
    int alert_macdevice_found_ref, alert_macdevice_lost_ref;
    // Timeouts
    int devicefound_timeout;
    int devicelost_timeout;
    // Configuration map for devices we look for
    // 1 = seen only
    // 2 = lost only
    // 3 = seen and lost
    std::map<mac_addr, unsigned int> macdevice_alert_conf_map;
    // Timeout event
    int macdevice_alert_timeout_timer;
    // Trigger event called to see if we need to alert devices have
    // stopped transmitting
    void macdevice_timer_event();
    // Devices we've flagged for timeout alerts
    std::vector<std::shared_ptr<kis_tracked_device_base>> macdevice_flagged_vec;

    // Signal threshold
    int device_location_signal_threshold;

	// Tracked devices
    device_map_t tracked_map;

    // MAC address lookups are incredibly expensive from the webui if we don't
    // track by map; in theory multiple objects in different PHYs could have the
    // same MAC so it's not a simple 1:1 map
    std::multimap<mac_addr, std::shared_ptr<kis_tracked_device_base> > tracked_mac_multimap;

    // Immutable vector, one entry per device; may never be sorted.  Devices
    // which are removed are set to 'null'.  Each position corresponds to the
    // device ID.
    std::shared_ptr<tracker_element_vector> immutable_tracked_vec;

    // List of views using new API as we transition the rest to the new API
    std::shared_ptr<tracker_element_vector> view_vec;

    using shared_con = std::shared_ptr<kis_net_beast_httpd_connection>;
    std::shared_ptr<tracker_element> multimac_endp_handler(shared_con con);
    std::shared_ptr<tracker_element> all_phys_endp_handler(shared_con con);

    int phy_phyentry_id, phy_phyname_id, phy_devices_count_id, 
        phy_packets_count_id, phy_phyid_id;

    // Multikey endpoint
    std::shared_ptr<tracker_element> multikey_endp_handler(shared_con con, bool as_object);

	// Registered PHY types
	int next_phy_id;
    ankerl::unordered_dense::map<int, kis_phy_handler *> phy_handler_map;
    kis_mutex phy_mutex;

    // New multimutex primitive
    kis_mutex devicelist_mutex;

    kis_mutex storing_mutex;
    std::atomic<bool> devices_storing;

    // If we log devices to the kismet database...
    int databaselog_timer;
    time_t last_database_logged;
    std::atomic<bool> databaselog_logging;

    // Do we constrain memory by not tracking RRD data?
    bool ram_no_rrd;

    // Handle new datasources and create endpoints for them
    void handle_new_datasource_event(std::shared_ptr<eventbus_event> evt);

    // Handle a new device & add it to views, trigger alerts, etc
    void handle_new_device_event(std::shared_ptr<eventbus_event> evt);

    // Insert a device directly into the records
    void add_device(std::shared_ptr<kis_tracked_device_base> device);

    // Load stored username
    void load_stored_username(std::shared_ptr<kis_tracked_device_base> in_dev);

    // Load stored tags
    void load_stored_tags(std::shared_ptr<kis_tracked_device_base> in_dev);

    // Cached device type map
    std::map<std::string, std::shared_ptr<tracker_element_string>> device_type_cache;
    kis_mutex device_type_cache_mutex;

    // Cached phyname map
    std::map<std::string, std::shared_ptr<tracker_element_string>> device_phy_name_cache;
    kis_mutex device_phy_name_cache_mutex;

    std::shared_ptr<kis_tracked_device_base> device_builder;

};

class devicelist_scope_locker {
public:
    devicelist_scope_locker(device_tracker *in_tracker) {
        in_tracker->lock_devicelist();
        tracker = in_tracker;
    }

    devicelist_scope_locker(std::shared_ptr<device_tracker> in_tracker) {
        in_tracker->lock_devicelist();
        sharedtracker = in_tracker;
        tracker = NULL;
    }

    ~devicelist_scope_locker() {
        if (tracker != NULL)
            tracker->unlock_devicelist();
        else if (sharedtracker != NULL)
            sharedtracker->unlock_devicelist();
    }

private:
    device_tracker *tracker;
    std::shared_ptr<device_tracker> sharedtracker;
};

struct pcapng_devicetracker_accept_ftor {
    pcapng_devicetracker_accept_ftor(device_key in_devkey) :
		devkey{in_devkey} {
            auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
			pack_comp_device = packetchain->register_packet_component("DEVICE");
        }

    bool operator()(std::shared_ptr<kis_packet> in_pack) {
		const auto devinfo = in_pack->fetch<kis_tracked_device_info>(pack_comp_device);

		if (devinfo == nullptr)
			return false;

		for (const auto& dri : devinfo->devrefs) {
			if (dri.second->get_key() == devkey)
				return true;
		}

		return false;
    }

	int pack_comp_device;
	device_key devkey;
};

#endif

