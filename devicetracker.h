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
#include "packet.h"
#include "packetchain.h"
#include "timetracker.h"
#include "uuid.h"
#include "configfile.h"
#include "kis_datasource.h"
#include "packinfo_signal.h"
#include "devicetracker_component.h"
#include "trackercomponent_legacy.h"
#include "timetracker.h"
#include "kis_net_microhttpd.h"
#include "structured.h"
#include "devicetracker_view.h"
#include "devicetracker_workers.h"
#include "kis_database.h"
#include "eventbus.h"

#define KIS_PHY_ANY	-1
#define KIS_PHY_UNKNOWN -2

class Kis_Phy_Handler;

// Small database helper class for the state store; we need to be able to 
// segregate it from the devicetracker store
class DevicetrackerStateStore : public KisDatabase {
public:
    DevicetrackerStateStore(GlobalRegistry *in_globalreg, Devicetracker *in_devicetracker);
    virtual ~DevicetrackerStateStore() { }

    virtual int Database_UpgradeDB();

    // Store a selection of devices
    virtual int store_devices(std::shared_ptr<TrackerElementVector> devices);

    // Iterate over all phys and load from the database
    virtual int load_devices();

    // Clear out devices too old
    virtual int clear_old_devices();

    // Clear all devices
    virtual int clear_all_devices();

    // Load a specific device
    std::shared_ptr<kis_tracked_device_base> load_device(Kis_Phy_Handler *in_phy,
            mac_addr in_mac);

protected:
    Devicetracker *devicetracker;
};


class Devicetracker : public Kis_Net_Httpd_Chain_Stream_Handler,
    public TimetrackerEvent, public LifetimeGlobal, public KisDatabase {

// Allow direct access for the state storing class
friend class DevicetrackerStateStore;

public:
    static std::string global_name() { return "DEVICETRACKER"; }

    static std::shared_ptr<Devicetracker> create_devicetracker(GlobalRegistry *in_globalreg) {
        std::shared_ptr<Devicetracker> mon(new Devicetracker(in_globalreg));
        in_globalreg->devicetracker = mon.get();
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
	Devicetracker(GlobalRegistry *in_globalreg);

public:
	virtual ~Devicetracker();

	// Register a phy handler weak class, used to instantiate the strong class
	// inside devtracker
	int RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler);

	Kis_Phy_Handler *FetchPhyHandler(int in_phy);
    Kis_Phy_Handler *FetchPhyHandlerByName(std::string in_name);

    // Eventbus event we inject when a new phy is added
    class EventNewPhy : public EventbusEvent {
    public:
        EventNewPhy(Kis_Phy_Handler *handler) :
            EventbusEvent("NEW_PHY"),
            phy{handler} { }
        virtual ~EventNewPhy() {}

        Kis_Phy_Handler *phy;
    };

    std::string FetchPhyName(int in_phy);

	int FetchNumDevices();
	int FetchNumPackets();

	int AddFilter(std::string in_filter);
	int AddNetCliFilter(std::string in_filter);

    // Flag that we've altered the device structure in a way that a client should
    // perform a full pull.  For instance, removing devices or device record
    // components due to timeouts / max device cleanup
    void UpdateFullRefresh();

	// Look for an existing device record
    std::shared_ptr<kis_tracked_device_base> FetchDevice(device_key in_key);

    // Perform a device filter.  Pass a subclassed filter instance.
    //
    // If "batch" is true, Kismet will sort the devices based on the internal ID 
    // and batch this processing in several groups to allow other threads time 
    // to operate.
    //
    // Typically used to build a subset of devices for serialization
    void MatchOnDevices(std::shared_ptr<DevicetrackerFilterWorker> worker, bool batch = true);
    // Perform a read-only match; MAY NOT edit devices in the worker!
    void MatchOnReadonlyDevices(std::shared_ptr<DevicetrackerFilterWorker> worker, bool batch = true);

    // Perform a device filter as above, but provide a source vec rather than the
    // list of ALL devices.  The source vector is duplicated under mutex and then processed.
    void MatchOnDevices(std::shared_ptr<DevicetrackerFilterWorker> worker, 
            std::shared_ptr<TrackerElementVector> source_vec, bool batch = true);
    // Perform a readonly filter, MUST NOT modify devices
    void MatchOnReadonlyDevices(std::shared_ptr<DevicetrackerFilterWorker> worker, 
            std::shared_ptr<TrackerElementVector> source_vec, bool batch = true);

    // Perform a device filter as above, but provide a source vec rather than the
    // list of ALL devices.  The source vector is NOT duplicated, caller must ensure this is
    // a safe operation (the vector must not be modified during execution of the worker)
    void MatchOnDevicesRaw(std::shared_ptr<DevicetrackerFilterWorker> worker, 
            std::shared_ptr<TrackerElementVector> source_vec, bool batch = true);
    // Perform a readonly match
    void MatchOnReadonlyDevicesRaw(std::shared_ptr<DevicetrackerFilterWorker> worker, 
            std::shared_ptr<TrackerElementVector> source_vec, bool batch = true);

    // Perform a device filter as above, but provide a stl vector instead of the list of
    // ALL devices in the system; the source vector is duplicated under mutex and then processed.
    void MatchOnDevices(std::shared_ptr<DevicetrackerFilterWorker> worker,
            const std::vector<std::shared_ptr<kis_tracked_device_base>>& source_vec,
            bool batch = true);
    // RO only
    void MatchOnReadonlyDevices(std::shared_ptr<DevicetrackerFilterWorker> worker,
            const std::vector<std::shared_ptr<kis_tracked_device_base>>& source_vec,
            bool batch = true);

    // Perform a device filter as above, but provide a stl vector instead of the list of
    // ALL devices in the system; the source vector is not duplicated, the caller must ensure
    // this is a safe operation (the vector must not be modified during execution of the worker)
    void MatchOnDevicesRaw(std::shared_ptr<DevicetrackerFilterWorker> worker,
            const std::vector<std::shared_ptr<kis_tracked_device_base>>& source_vec,
            bool batch = true);
    // RO only
    void MatchOnReadonlyDevicesRaw(std::shared_ptr<DevicetrackerFilterWorker> worker,
            const std::vector<std::shared_ptr<kis_tracked_device_base>>& source_vec,
            bool batch = true);

    using device_map_t = std::map<device_key, std::shared_ptr<kis_tracked_device_base>>;
    using device_itr = device_map_t::iterator;
    using const_device_itr = device_map_t::const_iterator;

	static void Usage(char *argv);

	// Common classifier for keeping phy counts
	int CommonTracker(kis_packet *in_packet);

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
    // It is recommended that plugin developers look at the UpdateCommonDevice
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

    std::shared_ptr<kis_tracked_device_base> UpdateCommonDevice(kis_common_info *pack_common,
            mac_addr in_mac, Kis_Phy_Handler *phy, kis_packet *in_pack, unsigned int in_flags,
            std::string in_basic_type);

    // Set the common name of a device (and log it in the database for future runs)
    void SetDeviceUserName(std::shared_ptr<kis_tracked_device_base> in_dev,
            std::string in_username);

    // Set an arbitrary tag (and log it in the database for future runs)
    void SetDeviceTag(std::shared_ptr<kis_tracked_device_base> in_dev,
            std::string in_tag, std::string in_content);

    // HTTP handlers
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual int Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls);
    
    // Timetracker event handler
    virtual int timetracker_event(int eventid);

    // CLI extension
    static void usage(const char *name);

    void lock_devicelist();
    void unlock_devicelist();

    std::shared_ptr<kis_tracked_rrd<> > get_packets_rrd() {
        return packets_rrd;
    }

    // Database API
    virtual int Database_UpgradeDB();

    // Store all devices to the database
    virtual int store_devices();
    virtual int store_all_devices();
    virtual int store_devices(std::shared_ptr<TrackerElementVector> devices);

    // Store all devices to the database
    virtual void databaselog_write_devices();
    virtual void databaselog_write_devices(std::shared_ptr<TrackerElementVector> devices);

    // Iterate over all phys and load from the database
    virtual int load_devices();

    // View API
    virtual bool add_view(std::shared_ptr<DevicetrackerView> in_view);
    virtual void remove_view(const std::string& in_view_id);

    virtual void new_view_device(std::shared_ptr<kis_tracked_device_base> in_device);
    virtual void update_view_device(std::shared_ptr<kis_tracked_device_base> in_device);
    virtual void remove_view_device(std::shared_ptr<kis_tracked_device_base> in_device);

protected:
	GlobalRegistry *globalreg;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<Eventbus> eventbus;

    unsigned long new_datasource_evt_id;

    // Map of seen-by views
    bool map_seenby_views;
    std::map<uuid, std::shared_ptr<DevicetrackerView>> seenby_view_map;

    // Map of phy views
    bool map_phy_views;
    std::map<int, std::shared_ptr<DevicetrackerView>> phy_view_map;

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
    std::map<int, int> phy_packets;
	std::map<int, int> phy_datapackets;
	std::map<int, int> phy_errorpackets;
	std::map<int, int> phy_filterpackets;

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

    // Do we track history clouds?
    bool track_history_cloud;
    bool track_persource_history;

	// Common device component
	int devcomp_ref_common;

    // Packet components we add or interact with
    int pack_comp_device, pack_comp_common, pack_comp_basicdata,
        pack_comp_radiodata, pack_comp_gps, pack_comp_datasrc,
        pack_comp_mangleframe;

	// Tracked devices
    device_map_t tracked_map;
	// Vector of tracked devices so we can iterate them quickly
    std::vector<std::shared_ptr<kis_tracked_device_base> > tracked_vec;
    // MAC address lookups are incredibly expensive from the webui if we don't
    // track by map; in theory multiple objects in different PHYs could have the
    // same MAC so it's not a simple 1:1 map
    std::multimap<mac_addr, std::shared_ptr<kis_tracked_device_base> > tracked_mac_multimap;

    // Immutable vector, one entry per device; may never be sorted.  Devices
    // which are removed are set to 'null'.  Each position corresponds to the
    // device ID.
    std::shared_ptr<TrackerElementVector> immutable_tracked_vec;

    // List of views using new API as we transition the rest to the new API
    kis_recursive_timed_mutex view_mutex;
    std::shared_ptr<TrackerElementVector> view_vec;
    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> view_endp;

    // Multimac endpoint using new http API
    std::shared_ptr<Kis_Net_Httpd_Simple_Post_Endpoint> multimac_endp;
    unsigned int multimac_endp_handler(std::ostream& stream, const std::string& uri,
            SharedStructured structured, Kis_Net_Httpd_Connection::variable_cache_map& variable_cache);

    // /phys/all_phys.json endpoint using new simple endpoint API
    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> all_phys_endp;
    std::shared_ptr<TrackerElement> all_phys_endp_handler();
    int phy_phyentry_id, phy_phyname_id, phy_devices_count_id, 
        phy_packets_count_id, phy_phyid_id;

	// Registered PHY types
	int next_phy_id;
    std::map<int, Kis_Phy_Handler *> phy_handler_map;

    kis_recursive_timed_mutex devicelist_mutex;

    // Timestamp of the last time we wrote the device list, if we're storing state
    std::atomic<time_t> last_devicelist_saved;

    kis_recursive_timed_mutex storing_mutex;
    std::atomic<bool> devices_storing;

    // Do we store devices?
    bool persistent_storage;

    unsigned long persistent_storage_timeout;

    // Persistent database (independent of our tags, etc db)
    DevicetrackerStateStore *statestore;

    // Loading mode
    enum persistent_mode_e {
        MODE_ONSTART, MODE_ONDEMAND
    };
    persistent_mode_e persistent_mode;

    // Do we use persistent compression when storing
    bool persistent_compression;

    // If we log devices to the kismet database...
    int databaselog_timer;
    time_t last_database_logged;
    kis_recursive_timed_mutex databaselog_mutex;
    bool databaselog_logging;

    // Do we constrain memory by not tracking RRD data?
    bool ram_no_rrd;

protected:
    // Handle new datasources and create endpoints for them
    void HandleNewDatasourceEvent(std::shared_ptr<EventbusEvent> evt);

    // Insert a device directly into the records
    void AddDevice(std::shared_ptr<kis_tracked_device_base> device);

    // Load a specific device
    virtual std::shared_ptr<kis_tracked_device_base> load_device(Kis_Phy_Handler *phy, 
            mac_addr mac);

    // Common device interpretation layer
    virtual std::shared_ptr<kis_tracked_device_base> 
        convert_stored_device(mac_addr macaddr, 
                const unsigned char *raw_stored_data, unsigned long stored_len);

    // Load stored username
    void load_stored_username(std::shared_ptr<kis_tracked_device_base> in_dev);

    // Load stored tags
    void load_stored_tags(std::shared_ptr<kis_tracked_device_base> in_dev);
};

class devicelist_scope_locker {
public:
    devicelist_scope_locker(Devicetracker *in_tracker) {
        in_tracker->lock_devicelist();
        tracker = in_tracker;
    }

    devicelist_scope_locker(std::shared_ptr<Devicetracker> in_tracker) {
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
    Devicetracker *tracker;
    std::shared_ptr<Devicetracker> sharedtracker;
};

#endif

