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

#ifndef __DEVICETRACKER_COMPONENT_H__
#define __DEVICETRACKER_COMPONENT_H__

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

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packet.h"
#include "uuid.h"
#include "trackedlocation.h"
#include "trackedrrd.h"
#include "packinfo_signal.h"

class KisDatasource;

enum kis_ipdata_type {
	ipdata_unknown = 0,
	ipdata_factoryguess = 1,
	ipdata_udptcp = 2,
	ipdata_arp = 3,
	ipdata_dhcp = 4,
	ipdata_group = 5
};

// New component-based ip data
class kis_tracked_ip_data : public tracker_component {
public:
    kis_tracked_ip_data();
    kis_tracked_ip_data(int in_id);
    kis_tracked_ip_data(int in_id, std::shared_ptr<TrackerElementMap> e);

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(ip_type, int32_t, kis_ipdata_type, kis_ipdata_type, ip_type);
    __Proxy(ip_addr, uint64_t, uint64_t, uint64_t, ip_addr_block);
    __Proxy(ip_netmask, uint64_t, uint64_t, uint64_t, ip_netmask);
    __Proxy(ip_gateway, uint64_t, uint64_t, uint64_t, ip_gateway);

protected:
    virtual void register_fields() override;

    std::shared_ptr<TrackerElementInt32> ip_type;
    std::shared_ptr<TrackerElementUInt64> ip_addr_block;
    std::shared_ptr<TrackerElementUInt64> ip_netmask;
    std::shared_ptr<TrackerElementUInt64> ip_gateway;
};

// Component-tracker based signal data
// TODO operator overloading once rssi/dbm fixed upstream
class kis_tracked_signal_data : public tracker_component {
public:
    kis_tracked_signal_data();
    kis_tracked_signal_data(int in_id);
    kis_tracked_signal_data(int in_id, std::shared_ptr<TrackerElementMap> e);

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    void append_signal(const kis_layer1_packinfo& lay1, bool update_rrd = true);
    void append_signal(const Packinfo_Sig_Combo& in, bool update_rrd = true);

    __ProxyGet(signal_type, std::string, std::string, signal_type);

    __ProxyGet(last_signal, int32_t, int, last_signal);
    __ProxyGet(min_signal, int32_t, int, min_signal);
    __ProxyGet(max_signal, int32_t, int, max_signal);

    __ProxyGet(last_noise, int32_t, int, last_noise);
    __ProxyGet(min_noise, int32_t, int, min_noise);
    __ProxyGet(max_noise, int32_t, int, max_noise);

    __ProxyGet(maxseenrate, double, double, maxseenrate);
    __ProxyGet(encodingset, uint64_t, uint64_t, encodingset);
    __ProxyGet(carrierset, uint64_t, uint64_t, carrierset);

    typedef kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> msig_rrd;
    __ProxyDynamicTrackable(signal_min_rrd, msig_rrd, signal_min_rrd, signal_min_rrd_id);

    __ProxyDynamicTrackable(peak_loc, kis_tracked_location_triplet, peak_loc, peak_loc_id);

protected:
    virtual void register_fields() override;

    std::shared_ptr<TrackerElementInt32> last_signal;
    std::shared_ptr<TrackerElementInt32> last_noise;

    std::shared_ptr<TrackerElementInt32> min_signal;
    std::shared_ptr<TrackerElementInt32> min_noise;

    std::shared_ptr<TrackerElementInt32> max_signal;
    std::shared_ptr<TrackerElementInt32> max_noise;

    std::shared_ptr<TrackerElementString> signal_type;

    int peak_loc_id;
    std::shared_ptr<kis_tracked_location_triplet> peak_loc;

    std::shared_ptr<TrackerElementDouble> maxseenrate;
    std::shared_ptr<TrackerElementUInt64> encodingset;
    std::shared_ptr<TrackerElementUInt64> carrierset;

    // Signal record over the past minute, either rssi or dbm.  Devices
    // should not mix rssi and dbm signal reporting.
    int signal_min_rrd_id;
    std::shared_ptr<kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> > signal_min_rrd;

    int sig_type;
};

class kis_tracked_seenby_data : public tracker_component {
public:
    kis_tracked_seenby_data();
    kis_tracked_seenby_data(int in_id);
    kis_tracked_seenby_data(int in_id, std::shared_ptr<TrackerElementMap> e);

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(src_uuid, uuid, uuid, uuid, src_uuid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
    __ProxyIncDec(num_packets, uint64_t, uint64_t, num_packets);

    __ProxyTrackable(freq_khz_map, TrackerElementDoubleMapDouble, freq_khz_map);
    __ProxyDynamicTrackable(signal_data, kis_tracked_signal_data, signal_data, signal_data_id);

    void inc_frequency_count(int frequency);

protected:
    virtual void register_fields() override;

    std::shared_ptr<TrackerElementUUID> src_uuid;
    std::shared_ptr<TrackerElementUInt64> first_time;
    std::shared_ptr<TrackerElementUInt64> last_time;
    std::shared_ptr<TrackerElementUInt64> num_packets;

    std::shared_ptr<TrackerElementDoubleMapDouble> freq_khz_map;
    int frequency_val_id;

    std::shared_ptr<kis_tracked_signal_data> signal_data;
    int signal_data_id;
};


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
    kis_tracked_device_base() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_device_base(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_device_base(int in_id, std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual ~kis_tracked_device_base() { }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("kis_tracked_device_base");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(key, device_key, device_key, device_key, key);

    __ProxyL(macaddr, mac_addr, mac_addr, mac_addr, macaddr,
            [this](mac_addr m) -> bool {

            // Only set the mac as the common name to the mac if it's empty
            if (get_commonname() == "")
                set_commonname(m.Mac2String());

            return true;
            
            });

    __Proxy(phyname, std::string, std::string, std::string, phyname);
	__Proxy(phyid, int32_t, int32_t, int32_t, phyid);

    __ProxyL(devicename, std::string, std::string, std::string, devicename, 
            [this](std::string i) -> bool {

            // Override the common name if there's no username
            if (has_username()) {
                if (get_username() == "")
                    set_commonname(i);
            } else {
                set_commonname(i);
            }

            return true;
            });

    __ProxyDynamicL(username, std::string, std::string, std::string, username, username_id,
            [this](std::string i) -> bool {

            // Always override the common name
            set_commonname(i);
            return true;
            });

    __Proxy(commonname, std::string, std::string, std::string, commonname);

    __Proxy(type_string, std::string, std::string, std::string, type_string);

    __Proxy(basic_type_set, uint64_t, uint64_t, uint64_t, basic_type_set);
    __ProxyBitset(basic_type_set, uint64_t, basic_type_set);

    // Set the type string if any of the matching set are found
    void set_type_string_if(std::string in_type, uint64_t if_set) {
        if (get_basic_type_set() & if_set) 
            set_type_string(in_type);
    }

    // Set the type string if only the matching set is found
    void set_type_string_ifonly(std::string in_type, uint64_t if_set) {
        if (get_basic_type_set() == if_set)
            set_type_string(in_type);
    }

    // Set the type string if the matching set is NOT found
    void set_type_string_ifnot(std::string in_type, uint64_t if_set) {
        if (!(get_basic_type_set() & if_set))
            set_type_string(in_type);
    }


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
    __ProxyDynamicTrackable(packets_rrd, rrdt, packets_rrd, packets_rrd_id);

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

    __ProxyTrackable(manuf, TrackerElementString, manuf);
    __Proxy(manuf, std::string, std::string, std::string, manuf);

    __Proxy(num_alerts, uint32_t, unsigned int, unsigned int, alert);

    __ProxyDynamicTrackable(signal_data, kis_tracked_signal_data, signal_data,
            signal_data_id);

    __ProxyTrackable(freq_khz_map, TrackerElementDoubleMapDouble, freq_khz_map);

    void inc_frequency_count(double frequency);

    __ProxyTrackable(seenby_map, TrackerElementIntMap, seenby_map);

    void inc_seenby_count(KisDatasource *source, time_t tv_sec, int frequency,
            Packinfo_Sig_Combo *siginfo, bool update_rrd);

    __ProxyTrackable(tag_map, TrackerElementStringMap, tag_map);

    __Proxy(server_uuid, uuid, uuid, uuid, server_uuid);

    // Non-exported internal counter used for structured sorting
    uint64_t get_kis_internal_id() {
        return kis_internal_id;
    }

    void set_kis_internal_id(uint64_t in_id) {
        kis_internal_id = in_id;
    }

    // Lock our device around serialization
    virtual void pre_serialize() override {
        local_eol_shared_locker lock(&device_mutex);
    }

    virtual void post_serialize() override {
        local_shared_unlocker unlock(&device_mutex);
    }

    // Protective per-device mutex, should be managed by pre/post serialization
    // functions, and by anything modifying the device or any of the per-phy records
    // inside it
    kis_recursive_timed_mutex device_mutex;

protected:
    virtual void register_fields() override;
    virtual void reserve_fields(std::shared_ptr<TrackerElementMap> e) override;

    // Unique, meaningless, incremental ID.  Practically, this is the order
    // in which kismet saw devices; it has no purpose other than a sorting
    // key which will always preserve order - time, etc, will not.  Used for breaking
    // up long-running queries.
    uint64_t kis_internal_id;

    // Unique key
    std::shared_ptr<TrackerElementDeviceKey> key;

    // Mac address (probably the key, but could be different)
    std::shared_ptr<TrackerElementMacAddr> macaddr;

    // Phy name
    std::shared_ptr<TrackerElementString> phyname;
	std::shared_ptr<TrackerElementInt32> phyid;

    // Printable name for UI summary.  For APs could be latest SSID, for BT the UAP guess, etc.
    std::shared_ptr<TrackerElementString> devicename;

    // User name for arbitrary naming
    std::shared_ptr<TrackerElementString> username;
    int username_id;

    // Common name connected via preserialize
    std::shared_ptr<TrackerElementString> commonname;

    // Printable basic type relevant to the phy, ie "Wired", "AP", "Bluetooth", etc.
    // This can be set per-phy and is treated as a printable interpretation.
    // This should be empty if the phy layer is unable to add something intelligent
    std::shared_ptr<TrackerElementString> type_string;

    // Basic phy-neutral type for sorting and classification
    std::shared_ptr<TrackerElementUInt64> basic_type_set;

    // Printable crypt string, which is set by the phy and is the best printable
    // representation of the phy crypt options.  This should be empty if the phy
    // layer hasn't added something intelligent.
    std::shared_ptr<TrackerElementString> crypt_string;

    // Bitset of basic phy-neutral crypt options
    std::shared_ptr<TrackerElementUInt64> basic_crypt_set;

    // First and last seen
    std::shared_ptr<TrackerElementUInt64> first_time;
    std::shared_ptr<TrackerElementUInt64> last_time;
    std::shared_ptr<TrackerElementUInt64> mod_time;

    // Packet counts
    std::shared_ptr<TrackerElementUInt64> packets;
    std::shared_ptr<TrackerElementUInt64> tx_packets;
    std::shared_ptr<TrackerElementUInt64> rx_packets;
    std::shared_ptr<TrackerElementUInt64> llc_packets;
    std::shared_ptr<TrackerElementUInt64> error_packets;
    std::shared_ptr<TrackerElementUInt64> data_packets;
    std::shared_ptr<TrackerElementUInt64> crypt_packets;
    std::shared_ptr<TrackerElementUInt64> filter_packets;

    std::shared_ptr<TrackerElementUInt64> datasize;

    // Packets and data RRDs
    int packets_rrd_id;
    std::shared_ptr<kis_tracked_rrd<>> packets_rrd;

    int data_rrd_id;
    std::shared_ptr<kis_tracked_rrd<>> data_rrd;

    // Data bins divided by size we track, named by max size
    int packet_rrd_bin_250_id;
    std::shared_ptr<kis_tracked_minute_rrd<>> packet_rrd_bin_250;
    int packet_rrd_bin_500_id;
    std::shared_ptr<kis_tracked_minute_rrd<>> packet_rrd_bin_500;
    int packet_rrd_bin_1000_id;
    std::shared_ptr<kis_tracked_minute_rrd<>> packet_rrd_bin_1000;
    int packet_rrd_bin_1500_id;
    std::shared_ptr<kis_tracked_minute_rrd<>> packet_rrd_bin_1500;
    int packet_rrd_bin_jumbo_id;
    std::shared_ptr<kis_tracked_minute_rrd<>> packet_rrd_bin_jumbo;

	// Channel and frequency as per PHY type
    std::shared_ptr<TrackerElementString> channel;
    std::shared_ptr<TrackerElementDouble> frequency;

    // Signal data
    int signal_data_id;
    std::shared_ptr<kis_tracked_signal_data> signal_data;

    // Global frequency distribution
    std::shared_ptr<TrackerElementDoubleMapDouble> freq_khz_map;

    // Manufacturer, if we're able to derive, either from OUI or 
    // from other data (phy-dependent)
    std::shared_ptr<TrackerElementString> manuf;

    // Alerts triggered on this device
    std::shared_ptr<TrackerElementUInt32> alert;

    // Stringmap of tags
    std::shared_ptr<TrackerElementStringMap> tag_map;
    // Entry ID for tag map
    int tag_entry_id;

    // Location min/max/avg
    std::shared_ptr<kis_tracked_location> location;
    int location_id;

    std::shared_ptr<kis_location_history> location_cloud;
    int location_cloud_id;

    // Seenby map (mapped by int16 device id)
    std::shared_ptr<TrackerElementIntMap> seenby_map;
    int seenby_map_id;

    // Server UUID which generated this device
    std::shared_ptr<TrackerElementUUID> server_uuid;

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
	}

    std::map<mac_addr, std::shared_ptr<kis_tracked_device_base> > devrefs;
};

#endif

