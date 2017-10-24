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
#include <pthread.h>

#include <stdexcept>

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packet.h"
#include "packetchain.h"
#include "timetracker.h"
#include "filtercore.h"
#include "uuid.h"
#include "configfile.h"
#include "phyhandler.h"
#include "kis_datasource.h"
#include "packinfo_signal.h"
#include "devicetracker_component.h"
#include "trackercomponent_legacy.h"
#include "timetracker.h"
#include "kis_net_microhttpd.h"
#include "structured.h"
#include "devicetracker_httpd_pcap.h"
#include "kis_database.h"

// How big the main vector of components is, if we ever get more than this
// many tracked components we'll need to expand this but since it ties to
// memory and track record creation it starts relatively low
#define MAX_TRACKER_COMPONENTS	64

#define KIS_PHY_ANY	-1
#define KIS_PHY_UNKNOWN -2

// fwd
class Devicetracker;

// Bitfield of basic types a device is classified as.  The device may be multiple
// of these depending on the phy.  The UI will display them based on the type
// in the display filter.
//
// Generic device.  Everything is a device.  If the phy has no
// distinguishing factors for classifying it as anything else, this is
// what it gets to be.
#define KIS_DEVICE_BASICTYPE_DEVICE		0
// Access point (in wifi terms) or otherwise central coordinating device
// (if available in other PHYs)
#define KIS_DEVICE_BASICTYPE_AP			1
// Wireless client device (up to the implementor if a peer-to-peer phy
// classifies all as clients, APs, or simply devices)
#define KIS_DEVICE_BASICTYPE_CLIENT		2
// Bridged/wired client, something that isn't itself homed on the wireless
// medium
#define KIS_DEVICE_BASICTYPE_WIRED		4
// Adhoc/peer network
#define KIS_DEVICE_BASICTYPE_PEER		8
// Common mask of client types
#define KIS_DEVICE_BASICTYPE_CLIENTMASK	6

// Basic encryption types
#define KIS_DEVICE_BASICCRYPT_NONE		0
#define KIS_DEVICE_BASICCRYPT_ENCRYPTED	(1 << 1)
// More detailed encryption data if available
#define KIS_DEVICE_BASICCRYPT_L2		(1 << 2)
#define KIS_DEVICE_BASICCRYPT_L3		(1 << 3)
#define KIS_DEVICE_BASICCRYPT_WEAKCRYPT	(1 << 4)
#define KIS_DEVICE_BASICCRYPT_DECRYPTED	(1 << 5)

// Base of all device tracking under the new trackerentry system
class kis_tracked_device_base : public tracker_component {
public:
    kis_tracked_device_base(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_device_base(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
        
        register_fields();
        reserve_fields(e);
    }

    virtual ~kis_tracked_device_base() {

    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new kis_tracked_device_base(globalreg, get_id()));
    }

    __Proxy(key, TrackedDeviceKey, TrackedDeviceKey, TrackedDeviceKey, key);

    __Proxy(macaddr, mac_addr, mac_addr, mac_addr, macaddr);

    __Proxy(phyname, std::string, std::string, std::string, phyname);

    __Proxy(devicename, std::string, std::string, std::string, devicename);
    __Proxy(username, std::string, std::string, std::string, username);

    __Proxy(type_string, std::string, std::string, std::string, type_string);

    __Proxy(basic_type_set, uint64_t, uint64_t, uint64_t, basic_type_set);
    __ProxyBitset(basic_type_set, uint64_t, basic_type_set);

    __Proxy(crypt_string, std::string, std::string, std::string, crypt_string);

    __Proxy(basic_crypt_set, uint64_t, uint64_t, uint64_t, basic_crypt_set);
    void add_basic_crypt(uint64_t in) { (*basic_crypt_set) |= in; }

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    // Simple management of last modified time
    __Proxy(mod_time, uint64_t, time_t, time_t, mod_time);
    void update_modtime() {
        set_mod_time(time(0));
    }

    __Proxy(packets, uint64_t, uint64_t, uint64_t, packets);
    __ProxyIncDec(packets, uint64_t, uint64_t, packets);

    __Proxy(rx_packets, uint64_t, uint64_t, uint64_t, rx_packets);
    __ProxyIncDec(rx_packets, uint64_t, uint64_t, rx_packets);

    __Proxy(tx_packets, uint64_t, uint64_t, uint64_t, tx_packets);
    __ProxyIncDec(tx_packets, uint64_t, uint64_t, tx_packets);

    __Proxy(llc_packets, uint64_t, uint64_t, uint64_t, llc_packets);
    __ProxyIncDec(llc_packets, uint64_t, uint64_t, llc_packets);

    __Proxy(error_packets, uint64_t, uint64_t, uint64_t, error_packets);
    __ProxyIncDec(error_packets, uint64_t, uint64_t, error_packets);

    __Proxy(data_packets, uint64_t, uint64_t, uint64_t, data_packets);
    __ProxyIncDec(data_packets, uint64_t, uint64_t, data_packets);

    __Proxy(crypt_packets, uint64_t, uint64_t, uint64_t, crypt_packets);
    __ProxyIncDec(crypt_packets, uint64_t, uint64_t, crypt_packets);

    __Proxy(filter_packets, uint64_t, uint64_t, uint64_t, filter_packets);
    __ProxyIncDec(filter_packets, uint64_t, uint64_t, filter_packets);

    __Proxy(datasize, uint64_t, uint64_t, uint64_t, datasize);
    __ProxyIncDec(datasize, uint64_t, uint64_t, datasize);

    typedef kis_tracked_rrd<> rrdt;
    __ProxyTrackable(packets_rrd, rrdt, packets_rrd);

    __ProxyDynamicTrackable(location, kis_tracked_location, location, location_id);
    __ProxyDynamicTrackable(data_rrd, rrdt, data_rrd, data_rrd_id);
    __ProxyDynamicTrackable(location_cloud, kis_location_history, location_cloud, 
            location_cloud_id);

    typedef kis_tracked_minute_rrd<> mrrdt;
    __ProxyDynamicTrackable(packet_rrd_bin_250, mrrdt, packet_rrd_bin_250, 
            packet_rrd_bin_250_id);
    __ProxyDynamicTrackable(packet_rrd_bin_500, mrrdt, packet_rrd_bin_500,
            packet_rrd_bin_500_id);
    __ProxyDynamicTrackable(packet_rrd_bin_1000, mrrdt, packet_rrd_bin_1000,
            packet_rrd_bin_1000_id);
    __ProxyDynamicTrackable(packet_rrd_bin_1500, mrrdt, packet_rrd_bin_1500,
            packet_rrd_bin_1500_id);
    __ProxyDynamicTrackable(packet_rrd_bin_jumbo, mrrdt, packet_rrd_bin_jumbo,
            packet_rrd_bin_jumbo_id);

    __Proxy(channel, std::string, std::string, std::string, channel);
    __Proxy(frequency, double, double, double, frequency);

    __Proxy(manuf, std::string, std::string, std::string, manuf);

    __Proxy(num_alerts, uint32_t, unsigned int, unsigned int, alert);

    __ProxyTrackable(signal_data, kis_tracked_signal_data, signal_data);

    // Intmaps need special care by the caller
    SharedTrackerElement get_freq_khz_map() { return freq_khz_map; }

    void inc_frequency_count(double frequency);

    SharedTrackerElement get_seenby_map() {
        return seenby_map;
    }

    void inc_seenby_count(KisDatasource *source, time_t tv_sec, int frequency,
            Packinfo_Sig_Combo *siginfo);

    __ProxyTrackable(tag_map, TrackerElement, tag_map);

    // Non-exported internal counter used for structured sorting
    uint64_t get_kis_internal_id() {
        return kis_internal_id;
    }

    void set_kis_internal_id(uint64_t in_id) {
        kis_internal_id = in_id;
    }

protected:
    virtual void register_fields();
    virtual void reserve_fields(SharedTrackerElement e);

    // Unique, meaningless, incremental ID.  Practically, this is the order
    // in which kismet saw devices; it has no purpose other than a sorting
    // key which will always preserve order - time, etc, will not.  Used for breaking
    // up long-running queries.
    uint64_t kis_internal_id;

    // Unique key
    SharedTrackerElement key;

    // Mac address (probably the key, but could be different)
    SharedTrackerElement macaddr;

    // Phy type (integer index)
    SharedTrackerElement phyname;

    // Printable name for UI summary.  For APs could be latest SSID, for BT the UAP
    // guess, etc.
    SharedTrackerElement devicename;

    // User name for arbitrary naming
    SharedTrackerElement username;

    // Printable basic type relevant to the phy, ie "Wired", "AP", "Bluetooth", etc.
    // This can be set per-phy and is treated as a printable interpretation.
    // This should be empty if the phy layer is unable to add something intelligent
    SharedTrackerElement type_string;

    // Basic phy-neutral type for sorting and classification
    SharedTrackerElement basic_type_set;

    // Printable crypt string, which is set by the phy and is the best printable
    // representation of the phy crypt options.  This should be empty if the phy
    // layer hasn't added something intelligent.
    SharedTrackerElement crypt_string;

    // Bitset of basic phy-neutral crypt options
    SharedTrackerElement basic_crypt_set;

    // First and last seen
    SharedTrackerElement first_time, last_time, mod_time;

    // Packet counts
    SharedTrackerElement packets, tx_packets, rx_packets,
                   // link-level packets
                   llc_packets,
                   // known-bad packets
                   error_packets,
                   // data packets
                   data_packets,
                   // Encrypted data packets (double-counted with data)
                   crypt_packets,
                   // Excluded / filtered packets
                   filter_packets;

    // Data seen in bytes
    SharedTrackerElement datasize;

    // Packets and data RRDs
    int packets_rrd_id;
    std::shared_ptr<kis_tracked_rrd<> > packets_rrd;

    int data_rrd_id;
    std::shared_ptr<kis_tracked_rrd<> > data_rrd;

    // Data bins divided by size we track, named by max size
    int packet_rrd_bin_250_id;
    std::shared_ptr<kis_tracked_minute_rrd<> > packet_rrd_bin_250;
    int packet_rrd_bin_500_id;
    std::shared_ptr<kis_tracked_minute_rrd<> > packet_rrd_bin_500;
    int packet_rrd_bin_1000_id;
    std::shared_ptr<kis_tracked_minute_rrd<> > packet_rrd_bin_1000;
    int packet_rrd_bin_1500_id;
    std::shared_ptr<kis_tracked_minute_rrd<> > packet_rrd_bin_1500;
    int packet_rrd_bin_jumbo_id;
    std::shared_ptr<kis_tracked_minute_rrd<> > packet_rrd_bin_jumbo;

	// Channel and frequency as per PHY type
    SharedTrackerElement channel, frequency;

    // Signal data
    std::shared_ptr<kis_tracked_signal_data> signal_data;
    int signal_data_id;

    // Global frequency distribution
    SharedTrackerElement freq_khz_map;

    // Manufacturer, if we're able to derive, either from OUI or 
    // from other data (phy-dependent)
    SharedTrackerElement manuf;

    // Alerts triggered on this device
    SharedTrackerElement alert;

    // Stringmap of tags
    SharedTrackerElement tag_map;
    // Entry ID for tag map
    int tag_entry_id;

    // Location min/max/avg
    std::shared_ptr<kis_tracked_location> location;
    int location_id;

    std::shared_ptr<kis_location_history> location_cloud;
    int location_cloud_id;

    // Seenby map (mapped by int16 device id)
    SharedTrackerElement seenby_map;
    int seenby_map_id;

    // Non-exported local value for frequency count
    int frequency_val_id;

    // Non-exported local value for seenby content
    int seenby_val_id;
};

// Packinfo references
class kis_tracked_device_info : public packet_component {
public:
	kis_tracked_device_info() {
		self_destruct = 1;
		devref = NULL;
	}

    std::shared_ptr<kis_tracked_device_base> devref;
};

// Filter-handler class.  Subclassed by a filter supplicant to be passed to the
// device filter functions.
class DevicetrackerFilterWorker {
public:
    DevicetrackerFilterWorker() { };
    virtual ~DevicetrackerFilterWorker() { };

    // Perform a match on a device
    virtual void MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> base) = 0;

    // Finalize operations
    virtual void Finalize(Devicetracker *devicetracker) { }

protected:
    pthread_mutex_t worker_mutex;
};

// Small database helper class for the state store; we need to be able to 
// segregate it from the devicetracker store
class DevicetrackerStateStore : public KisDatabase {
public:
    DevicetrackerStateStore(GlobalRegistry *in_globalreg, Devicetracker *in_devicetracker);
    virtual ~DevicetrackerStateStore() { }

    virtual int Database_UpgradeDB();

    // Store a selection of devices
    virtual int store_devices(TrackerElementVector devices);

    // Iterate over all phys and load from the database
    virtual int load_devices();

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
    static std::shared_ptr<Devicetracker> create_devicetracker(GlobalRegistry *in_globalreg) {
        std::shared_ptr<Devicetracker> mon(new Devicetracker(in_globalreg));
        in_globalreg->devicetracker = mon.get();
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("DEVICE_TRACKER", mon);
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
    Kis_Phy_Handler *FetchPhyHandlerByName(string in_name);

    std::string FetchPhyName(int in_phy);

	int FetchNumDevices();
	int FetchNumPackets();

	int AddFilter(string in_filter);
	int AddNetCliFilter(string in_filter);

    // Flag that we've altered the device structure in a way that a client should
    // perform a full pull.  For instance, removing devices or device record
    // components due to timeouts / max device cleanup
    void UpdateFullRefresh();

	// Look for an existing device record
    std::shared_ptr<kis_tracked_device_base> FetchDevice(TrackedDeviceKey in_key);

    // Perform a device filter.  Pass a subclassed filter instance.
    //
    // If "batch" is true, Kismet will sort the devices based on the internal ID 
    // and batch this processing in several groups to allow other threads time 
    // to operate.
    //
    // Typically used to build a subset of devices for serialization
    void MatchOnDevices(DevicetrackerFilterWorker *worker, bool batch = true);

    // Perform a device filter as above, but provide a source vec rather than the
    // list of ALL devices
    void MatchOnDevices(DevicetrackerFilterWorker *worker, 
            TrackerElementVector source_vec, bool batch = true);

	typedef std::map<TrackedDeviceKey, std::shared_ptr<kis_tracked_device_base> >::iterator device_itr;
	typedef std::map<TrackedDeviceKey, std::shared_ptr<kis_tracked_device_base> >::const_iterator const_device_itr;

	static void Usage(char *argv);

	// Common classifier for keeping phy counts
	int CommonTracker(kis_packet *in_packet);

    // Add common into to a device.  If necessary, create the new device.
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
    shared_ptr<kis_tracked_device_base> UpdateCommonDevice(mac_addr in_mac, 
            Kis_Phy_Handler *phy, kis_packet *in_pack, unsigned int in_flags);

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
    
    // Generate a list of all phys, serialized appropriately.  If specified,
    // wrap it in a dictionary and name it with the key in in_wrapper, which
    // is required for some js libs like datatables.
    void httpd_all_phys(string url, std::ostream &stream, 
            std::string in_wrapper_key = "");

    // Generate a device summary, serialized.  Optionally provide an existing
    // vector to generate a summary of devices matching a given criteria via
    // a worker.  Also optionally, wrap the results in a dictionary named via
    // the in_wrapper key, which is required for some js libs like datatables
    void httpd_device_summary(string url, std::ostream &stream, 
            shared_ptr<TrackerElementVector> subvec, 
            std::vector<SharedElementSummary> summary_vec,
            std::string in_wrapper_key = "");

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
    virtual int store_devices(TrackerElementVector devices);

    // Store all devices to the database
    virtual void databaselog_write_devices();
    virtual void databaselog_write_all_devices();
    virtual void databaselog_write_devices(TrackerElementVector devices);

    // Iterate over all phys and load from the database
    virtual int load_devices();

protected:
	GlobalRegistry *globalreg;
    std::shared_ptr<EntryTracker> entrytracker;
    std::shared_ptr<Packetchain> packetchain;

    // Base IDs for tracker components
    int device_list_base_id, device_base_id, phy_base_id, phy_entry_id;
    int device_summary_base_id;
    int device_update_required_id, device_update_timestamp_id;

    int dt_length_id, dt_filter_id, dt_draw_id;

	// Total # of packets
	int num_packets;
	int num_datapackets;
	int num_errorpackets;
	int num_filterpackets;

	// Per-phy #s of packets
    std::map<int, int> phy_packets;
	std::map<int, int> phy_datapackets;
	std::map<int, int> phy_errorpackets;
	std::map<int, int> phy_filterpackets;

    // Total packet history
    int packets_rrd_id;
    std::shared_ptr<kis_tracked_rrd<> > packets_rrd;

    // Timeout of idle devices
    int device_idle_expiration;
    int device_idle_timer;

    // Maximum number of devices
    unsigned int max_num_devices;
    int max_devices_timer;

    // Timer event for storing devices
    int device_storage_timer;

    // Timestamp for the last time we removed a device
    time_t full_refresh_time;

    // Do we track history clouds?
    bool track_history_cloud;
    bool track_persource_history;

	// Common device component
	int devcomp_ref_common;

    // Packet components we add or interact with
	int pack_comp_device, pack_comp_common, pack_comp_basicdata,
		pack_comp_radiodata, pack_comp_gps, pack_comp_datasrc;

	// Tracked devices
    std::map<TrackedDeviceKey, std::shared_ptr<kis_tracked_device_base> > tracked_map;
	// Vector of tracked devices so we can iterate them quickly
    std::vector<std::shared_ptr<kis_tracked_device_base> > tracked_vec;
    // MAC address lookups are incredibly expensive from the webui if we don't
    // track by map; in theory multiple objects in different PHYs could have the
    // same MAC so it's not a simple 1:1 map
    std::multimap<mac_addr, std::shared_ptr<kis_tracked_device_base> > tracked_mac_multimap;

    // Immutable vector, one entry per device; may never be sorted.  Devices
    // which are removed are set to 'null'.  Each position corresponds to the
    // device ID.
    TrackerElementVector immutable_tracked_vec;

	// Filtering
	FilterCore *track_filter;

	// Registered PHY types
	int next_phy_id;
    std::map<int, Kis_Phy_Handler *> phy_handler_map;

	// Populate the common components of a device
	int PopulateCommon(std::shared_ptr<kis_tracked_device_base> device, kis_packet *in_pack);

    // Insert a device directly into the records
    void AddDevice(std::shared_ptr<kis_tracked_device_base> device);

    pthread_mutex_t devicelist_mutex;

    std::shared_ptr<Devicetracker_Httpd_Pcap> httpd_pcap;

    // Load a specific device
    virtual std::shared_ptr<kis_tracked_device_base> load_device(Kis_Phy_Handler *phy, 
            mac_addr mac);

    // Common device interpretation layer
    virtual std::shared_ptr<kis_tracked_device_base> 
        convert_stored_device(mac_addr macaddr, 
                const unsigned char *raw_stored_data, unsigned long stored_len);

    // Timestamp of the last time we wrote the device list, if we're storing state
    time_t last_devicelist_saved;

    std::recursive_timed_mutex storing_mutex;
    bool devices_storing;

    // Do we store devices?
    bool persistent_storage;

    // Persistent database (independent of our tags, etc db)
    DevicetrackerStateStore *statestore;

    // Loading mode
    enum persistent_mode_e {
        MODE_ONSTART, MODE_ONDEMAND
    };
    persistent_mode_e persistent_mode;

    // Do we use persistent compression when storing
    bool persistent_compression;

    // Load stored username
    void load_stored_username(std::shared_ptr<kis_tracked_device_base> in_dev);

    // Load stored tags
    void load_stored_tags(std::shared_ptr<kis_tracked_device_base> in_dev);

    // If we log devices to the kismet database...
    int databaselog_timer;
    time_t last_database_logged;
    std::recursive_timed_mutex databaselog_mutex;
    bool databaselog_logging;
};

class kis_tracked_phy : public tracker_component {
public:
    kis_tracked_phy(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_phy(GlobalRegistry *in_globalreg, int in_id,
            SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new kis_tracked_phy(globalreg, get_id()));
    }

    __Proxy(phy_id, int32_t, int32_t, int32_t, phy_id);
    __Proxy(phy_name, std::string, std::string, std::string, phy_name);

    void set_from_phy(Devicetracker *devicetracker, int phy) {
        set_phy_id(phy);
        set_phy_name(devicetracker->FetchPhyName(phy));
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.phy.id", TrackerInt32,
                "phy id", &phy_id);
        RegisterField("kismet.phy.name", TrackerString,
                "phy name", &phy_name);
    }

    SharedTrackerElement phy_id;
    SharedTrackerElement phy_name;
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

// C++ lambda matcher
class devicetracker_function_worker : public DevicetrackerFilterWorker {
public:
    devicetracker_function_worker(GlobalRegistry *in_globalreg,
            function<bool (Devicetracker *, 
                std::shared_ptr<kis_tracked_device_base>)> in_mcb,
            function<void (Devicetracker *, 
                std::vector<std::shared_ptr<kis_tracked_device_base> >)> in_fcb);
    virtual ~devicetracker_function_worker();

    virtual void MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device);

    virtual void Finalize(Devicetracker *devicetracker);

protected:
    GlobalRegistry *globalreg;

    std::vector<std::shared_ptr<kis_tracked_device_base> > matched_devices;

    function<bool (Devicetracker *, 
            std::shared_ptr<kis_tracked_device_base>)> mcb;
    function<void (Devicetracker *,
            std::vector<std::shared_ptr<kis_tracked_device_base> >)> fcb;
};

// Matching worker to match fields against a string search term

class devicetracker_stringmatch_worker : public DevicetrackerFilterWorker {
public:
    // Prepare the worker with the query and the vector of paths we
    // query against.  The vector of paths is equivalent to a field
    // summary/request field path, and can be extracted directly from 
    // that object.
    // in_devvec_object is the object the responses are placed into.
    // in_devvec_object must be a vector object.
    devicetracker_stringmatch_worker(GlobalRegistry *in_globalreg,
            std::string in_query,
            std::vector<std::vector<int> > in_paths,
            SharedTrackerElement in_devvec_object);

    virtual ~devicetracker_stringmatch_worker();

    virtual void MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device);

    virtual void Finalize(Devicetracker *devicetracker);

protected:
    GlobalRegistry *globalreg;
    std::shared_ptr<EntryTracker> entrytracker;

    std::string query;
    std::vector<vector<int> > fieldpaths;

    // Make a macaddr query out of it, too
    uint64_t mac_query_term;
    unsigned int mac_query_term_len;

    SharedTrackerElement return_dev_vec;
};

#ifdef HAVE_LIBPCRE
// Retrieve a list of devices based on complex field paths and
// return them in a vector sharedtrackerelement
class devicetracker_pcre_worker : public DevicetrackerFilterWorker {
public:
    class pcre_filter {
    public:
        pcre_filter() {
            re = NULL;
            study = NULL;
        }

        ~pcre_filter() {
            if (re != NULL)
                pcre_free(re);
            if (study != NULL)
                pcre_free(study);
        }

        std::string target;
        pcre *re;
        pcre_extra *study;
    };

    // Prepare the worker with a set of filters and the object we fill our
    // results into.  in_devvec_object must be a vector object.
    devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
            std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter> > in_filter_vec,
            SharedTrackerElement in_devvec_object);

    // Shortcut function for building a PCRE from an incoming standard filter
    // description on a POST event:
    // Prepare the worker with a set of filters contained in a raw Structured 
    // object, which is expected to be a vector of [field, regex] pairs.
    // Results are filled into in_devvec_object which is expected to be a vector object
    // This MAY THROW EXCEPTIONS from structured parsing or the PCRE parsing!
    devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
            SharedStructured raw_pcre_vec,
            SharedTrackerElement in_devvec_object);

    // Shortcut function for building a PCRE worker from an incoming list of
    // filters, targeting a single field (such as a SSID match):
    // Prepare the worker with a set of filters referencing a single field
    // target.  The filters should be contained in a raw Structured object, which
    // is expected to be a vector of filter strings.  Results are filled into
    // in_devvec_object which is expected to be a vector object.
    // This MAY THROW EXCEPTIONS from structured parsing or the PCRE parsing!
    devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
            std::string in_target,
            SharedStructured raw_pcre_vec,
            SharedTrackerElement in_devvec_object);

    virtual ~devicetracker_pcre_worker();

    bool get_error() { return error; }

    virtual void MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device);

    virtual void Finalize(Devicetracker *devicetracker);

protected:
    GlobalRegistry *globalreg;
    std::shared_ptr<EntryTracker> entrytracker;

    int pcre_match_id;

    std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter> > filter_vec;
    bool error;

    SharedTrackerElement return_dev_vec;
};
#else
class devicetracker_pcre_worker : public DevicetrackerFilterWorker {
public:
    class pcre_filter {
    public:
        pcre_filter() { }
    };

    // Prepare the worker with a set of filters and the object we fill our
    // results into.  in_devvec_object must be a vector object.
    devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
            std::vector<std::shared_ptr<devicetracker_pcre_worker::pcre_filter> > in_filter_vec,
            SharedTrackerElement in_devvec_object) {
        throw std::runtime_error("Kismet not compiled with PCRE support");
    }

    devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
            SharedStructured raw_pcre_vec,
            SharedTrackerElement in_devvec_object) {
        throw std::runtime_error("Kismet not compiled with PCRE support");
    }

    devicetracker_pcre_worker(GlobalRegistry *in_globalreg,
            std::string in_target,
            SharedStructured raw_pcre_vec,
            SharedTrackerElement in_devvec_object) {
        throw std::runtime_error("Kismet not compiled with PCRE support");
    }

    virtual ~devicetracker_pcre_worker() { };

    bool get_error() { return true; }

    virtual void MatchDevice(Devicetracker *devicetracker,
            std::shared_ptr<kis_tracked_device_base> device) { };

    virtual void Finalize(Devicetracker *devicetracker) { };
};


#endif

#endif
