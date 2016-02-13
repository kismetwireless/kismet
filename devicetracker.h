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

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packetsource.h"
#include "packet.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gpscore.h"
#include "uuid.h"
#include "configfile.h"
#include "phyhandler.h"
#include "devicetracker_component.h"
#include "trackercomponent_legacy.h"
#include "packinfo_signal.h"

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

        dirty = false;

        // printf("debug - kis_tracked_device_base(globalreg, id=%d)\n", in_id);
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_device_base(GlobalRegistry *in_globalreg, int in_id, 
            TrackerElement *e) : tracker_component(in_globalreg, in_id) {

        dirty = false;

        // printf("debug - kis_tracked_device_base(globalreg, id=%d, element=%p)\n", in_id, e);
        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        // printf("debug - clone()ing a kis_tracked_device_base\n");
        return new kis_tracked_device_base(globalreg, get_id());
    }

    __Proxy(key, mac_addr, mac_addr, mac_addr, key);

    __Proxy(macaddr, mac_addr, mac_addr, mac_addr, macaddr);
    
    __Proxy(phytype, int64_t, int64_t, int64_t, phytype);

    __Proxy(name, string, string, string, name);
    __Proxy(type_string, string, string, string, type_string);

    __Proxy(basic_type_set, uint64_t, uint64_t, uint64_t, basic_type_set);
    void add_basic_type(uint64_t in) { (*basic_type_set) |= in; }

    __Proxy(crypt_string, string, string, string, crypt_string);

    __Proxy(basic_crypt_set, uint64_t, uint64_t, uint64_t, basic_crypt_set);
    void add_basic_crypt(uint64_t in) { (*basic_crypt_set) |= in; }

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

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

    __Proxy(datasize_tx, uint64_t, uint64_t, uint64_t, datasize_tx);
    __ProxyAddSub(datasize_tx, uint64_t, uint64_t, datasize_tx);

    __Proxy(datasize_rx, uint64_t, uint64_t, uint64_t, datasize_rx);
    __ProxyAddSub(datasize_rx, uint64_t, uint64_t, datasize_rx);

    __Proxy(new_packets, uint64_t, uint64_t, uint64_t, new_packets);
    __ProxyIncDec(new_packets, uint64_t, uint64_t, new_packets);

    __Proxy(channel, uint64_t, uint64_t, uint64_t, channel);
    __Proxy(frequency, uint64_t, uint64_t, uint64_t, frequency);

    __Proxy(manuf, string, string, string, manuf);
    
    __Proxy(num_alerts, uint32_t, unsigned int, unsigned int, alert);

    kis_tracked_signal_data *get_signal_data() { return signal_data; }

    // Intmaps need special care by the caller
    TrackerElement *get_freq_mhz_map() { return freq_mhz_map; }

    string get_tag() { return tag->get_value(); }
    void set_tag(string in_tag) {
        tag->set_value(in_tag);
        tag->set_dirty(true);
    }

    bool get_tag_dirty() { return tag->get_dirty(); };
    void set_tag_dirty(bool in_dirty) { tag->set_dirty(in_dirty); };

    kis_tracked_location *get_location() { return location; }

    bool get_dirty() { return dirty; }
    void set_dirty(bool d) { dirty = d; }

    void inc_frequency_count(int frequency) {
        if (frequency <= 0)
            return;

        TrackerElement::map_iterator i = freq_mhz_map->find(frequency);

        if (i == freq_mhz_map->end()) {
            TrackerElement *e = 
                globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
            e->set((uint64_t) 1);
            freq_mhz_map->add_intmap(frequency, e);
        } else {
            (*(i->second))++;
        }
    }

    kis_tracked_seenby_data *get_seenby_map() { 
        return (kis_tracked_seenby_data *) seenby_map; 
    }

    void inc_seenby_count(KisPacketSource *source, time_t tv_sec, int frequency) {
        TrackerElement::map_iterator seenby_iter;
        kis_tracked_seenby_data *seenby;

        seenby_iter = seenby_map->find(source->FetchSourceID());

        // Make a new seenby record
        if (seenby_iter == seenby_map->end()) {
            seenby = new kis_tracked_seenby_data(globalreg, seenby_val_id);
                // (kis_tracked_seenby_data *) entrytracker->GetTrackedInstance(seenby_val_id);

            seenby->set_src_uuid(source->FetchUUID());
            seenby->set_first_time(tv_sec);
            seenby->set_last_time(tv_sec);
            seenby->set_num_packets(1);

            if (frequency > 0)
                seenby->inc_frequency_count(frequency);
        } else {
            seenby = (kis_tracked_seenby_data *) seenby_iter->second;

            seenby->set_last_time(tv_sec);
            seenby->inc_num_packets();

            if (frequency > 0)
                seenby->inc_frequency_count(frequency);
        }

    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        // printf("debug - kis_tracked_device_base register_fields\n");

        key_id =
            RegisterField("kismet.device.base.key", TrackerMac,
                    "unique integer key", (void **) &key);

        macaddr_id =
            RegisterField("kismet.device.base.macaddr", TrackerMac,
                    "mac address", (void **) &macaddr);

        phytype_id =
            RegisterField("kismet.device.base.phytype", TrackerInt64,
                    "phy type index", (void **) &phytype);

        name_id = 
            RegisterField("kismet.device.base.name", TrackerString,
                    "printable device name", (void **) &name);

        type_string_id = 
            RegisterField("kismet.device.base.type", TrackerString,
                    "printable device type", (void **) &type_string);

        basic_type_set_id =
            RegisterField("kismet.device.base.basic_type_set", TrackerUInt64,
                    "bitset of basic type", (void **) &basic_type_set);

        crypt_string_id =
            RegisterField("kismet.device.base.crypt", TrackerString,
                    "printable encryption type", (void **) &crypt_string);

        basic_crypt_set_id =
            RegisterField("kismet.device.base.basic_crypt_set", TrackerUInt64,
                    "bitset of basic encryption", (void **) &basic_crypt_set);

        first_time_id = 
            RegisterField("kismet.device.base.first_time", TrackerUInt64,
                    "first time seen time_t", (void **) &first_time);
        last_time_id =
            RegisterField("kismet.device.base.last_time", TrackerUInt64,
                    "last time seen time_t", (void **) &last_time);

        packets_id =
            RegisterField("kismet.device.base.packets.total", TrackerUInt64,
                    "total packets seen of all types", (void **) &packets);
        rx_packets_id =
            RegisterField("kismet.device.base.packets.rx", TrackerUInt64,
                        "observed packets sent to device", (void **) &rx_packets);
        tx_packets_id =
            RegisterField("kismet.device.base.packets.tx", TrackerUInt64,
                        "observed packets from device", (void **) &tx_packets);
        llc_packets_id =
            RegisterField("kismet.device.base.packets.llc", TrackerUInt64,
                        "observed protocol control packets", (void **) &llc_packets);
        error_packets_id =
            RegisterField("kismet.device.base.packets.error", TrackerUInt64,
                        "corrupt/error packets", (void **) &error_packets);
        data_packets_id =
            RegisterField("kismet.device.base.packets.data", TrackerUInt64,
                        "data packets", (void **) &data_packets);
        crypt_packets_id =
            RegisterField("kismet.device.base.packets.crypt", TrackerUInt64,
                        "data packets using encryption", (void **) &crypt_packets);
        filter_packets_id =
            RegisterField("kismet.device.base.packets.filtered", TrackerUInt64,
                        "packets dropped by filter", (void **) &filter_packets);

        datasize_tx_id =
            RegisterField("kismet.device.base.datasize.tx", TrackerUInt64,
                        "transmitted data in bytes", (void **) &datasize_tx);
        datasize_rx_id =
            RegisterField("kismet.device.base.datasize.rx", TrackerUInt64,
                        "received data in bytes", (void **) &datasize_rx);

        new_packets_id =
            RegisterField("kismet.device.base.packets.new", TrackerUInt64,
                        "new packets since last report", (void **) &new_packets);

        kis_tracked_signal_data *sig_builder = new kis_tracked_signal_data(globalreg, 0);
        signal_data_id =
            RegisterComplexField("kismet.device.base.signal", sig_builder,
                    "signal data");

        freq_mhz_map_id =
            RegisterField("kismet.device.base.freq_mhz_map", TrackerIntMap,
                    "packets seen per frequency (mhz)", (void **) &freq_mhz_map);

        channel_id =
            RegisterField("kismet.device.base.channel", TrackerUInt64,
                        "channel (phy specific)", (void **) &channel);
        frequency_id =
            RegisterField("kismet.device.base.frequency", TrackerUInt64,
                        "frequency", (void **) &frequency);

        manuf_id =
            RegisterField("kismet.device.base.manuf", TrackerString,
                        "manufacturer name", (void **) &manuf);

        alert_id =
            RegisterField("kismet.device.base.num_alerts", TrackerUInt32,
                        "number of alerts on this device", (void **) &alert);

        kis_tracked_tag *tag_builder = new kis_tracked_tag(globalreg, 0);
        tag_id =
            RegisterComplexField("kismet.device.base.tag", tag_builder,
                    "arbitrary tag");

        kis_tracked_location *loc_builder = new kis_tracked_location(globalreg, 0);
        location_id =
            RegisterComplexField("kismet.device.base.location", loc_builder,
                    "location");

        seenby_map_id =
            RegisterField("kismet.device.base.seenby", TrackerIntMap,
                    "sources that have seen this device", (void **) &seenby_map);

        frequency_val_id =
            globalreg->entrytracker->RegisterField("kismet.device.base.frequency.count",
                    TrackerUInt64, "frequency packet count");

        kis_tracked_seenby_data *seenby_builder = new kis_tracked_seenby_data(globalreg, 0);
        seenby_val_id =
            globalreg->entrytracker->RegisterField("kismet.device.base.seenby.data", 
                    seenby_builder, "seen-by data");

    }

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        // printf("debug - kis_tracked_device_base reservefields seed %p\n", e);

        if (e != NULL) {
            signal_data = new kis_tracked_signal_data(globalreg, signal_data_id,
                    e->get_map_value(signal_data_id));
            tag = new kis_tracked_tag(globalreg, tag_id,
                    e->get_map_value(tag_id));
            location = new kis_tracked_location(globalreg, location_id,
                    e->get_map_value(location_id));
        } else {
            signal_data = new kis_tracked_signal_data(globalreg, signal_data_id);
            tag = new kis_tracked_tag(globalreg, tag_id);
            location = new kis_tracked_location(globalreg, location_id);
        }
    }


    // Unique key
    TrackerElement *key;
    int key_id;

    // Mac address (probably the key, but could be different)
    TrackerElement *macaddr;
    int macaddr_id;

    // Phy type (integer index)
    TrackerElement *phytype;
    int phytype_id;

    // Printable name for UI summary.  For APs could be latest SSID, for BT the UAP
    // guess, etc.
    TrackerElement *name;
    int name_id;

    // Printable basic type relevant to the phy, ie "Wired", "AP", "Bluetooth", etc.
    // This can be set per-phy and is treated as a printable interpretation.  This should
    // be empty if the phy layer is unable to add something intelligent
    TrackerElement *type_string;
    int type_string_id;

    // Basic phy-neutral type for sorting and classification
    TrackerElement *basic_type_set;
    int basic_type_set_id;

    // Printable crypt string, which is set by the phy and is the best printable
    // representation of the phy crypt options.  This should be empty if the phy
    // layer hasn't added something intelligent.
    TrackerElement *crypt_string;
    int crypt_string_id;

    // Bitset of basic phy-neutral crypt options
    TrackerElement *basic_crypt_set;
    int basic_crypt_set_id;

    // First and last seen
    TrackerElement *first_time, *last_time;
    int first_time_id, last_time_id;

    // Packet counts
    TrackerElement *packets, *tx_packets, *rx_packets,
                   // link-level packets
                   *llc_packets, 
                   // known-bad packets
                   *error_packets,
                   // data packets
                   *data_packets, 
                   // Encrypted data packets (double-counted with data)
                   *crypt_packets,
                   // Excluded / filtered packets
                   *filter_packets;
    int packets_id, tx_packets_id, rx_packets_id,
        llc_packets_id, error_packets_id, data_packets_id,
        crypt_packets_id, filter_packets_id;

    // Data seen in bytes
    TrackerElement *datasize_tx, *datasize_rx;
    int datasize_tx_id, datasize_rx_id;

    // New # of packets and amount of data bytes since last tick
    TrackerElement *new_packets;
    int new_packets_id;

	// Channel and frequency as per PHY type
    TrackerElement *channel, *frequency;
    int channel_id, frequency_id;

    // Signal data
    kis_tracked_signal_data *signal_data;
    int signal_data_id;

    // Global frequency distribution
    TrackerElement *freq_mhz_map;
    int freq_mhz_map_id;

    // Manufacturer, if we're able to derive, either from OUI or from other data (phy-dependent)
    TrackerElement *manuf;
    int manuf_id;

    // Alerts triggered on this device
    TrackerElement *alert;
    int alert_id;

    // Device tag
    kis_tracked_tag *tag;
    int tag_id;

    // Location min/max/avg
    kis_tracked_location *location;
    int location_id;

    // Seenby map (mapped by int16 device id)
    TrackerElement *seenby_map;
    int seenby_map_id;

    // Non-exported local tracking, is device dirty?
    bool dirty;

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

    kis_tracked_device_base *devref;
};

class Devicetracker {
public:
	Devicetracker() { fprintf(stderr, "FATAL OOPS: Kis_Tracker()\n"); exit(0); }
	Devicetracker(GlobalRegistry *in_globalreg);
	~Devicetracker();

	// Register a phy handler weak class, used to instantiate the strong class
	// inside devtracker
	int RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler);
	// Register a tracked device component
	int RegisterDeviceComponent(string in_component);
	// Get a device component name
	string FetchDeviceComponentName(int in_id);

	vector<kis_tracked_device_base *> *FetchDevices(int in_phy);

	Kis_Phy_Handler *FetchPhyHandler(int in_phy);

	int FetchNumDevices(int in_phy);
	int FetchNumPackets(int in_phy);
	int FetchNumDatapackets(int in_phy);
	int FetchNumCryptpackets(int in_phy);
	int FetchNumErrorpackets(int in_phy);
	int FetchNumFilterpackets(int in_phy);
	int FetchPacketRate(int in_phy);

	int AddFilter(string in_filter);
	int AddNetCliFilter(string in_filter);

	int SetDeviceTag(mac_addr in_device, string in_data);
	int ClearDeviceTag(mac_addr in_device);
	string FetchDeviceTag(mac_addr in_device);

	// Look for an existing device record
	kis_tracked_device_base *FetchDevice(mac_addr in_device);
	kis_tracked_device_base *FetchDevice(mac_addr in_device, unsigned int in_phy);
	
	// Make or find a device record for a mac
	kis_tracked_device_base *MapToDevice(mac_addr in_device, kis_packet *in_pack);

	typedef map<mac_addr, kis_tracked_device_base *>::iterator device_itr;
	typedef map<mac_addr, kis_tracked_device_base *>::const_iterator const_device_itr;

	static void Usage(char *argv);

	// Kick the timer event to update the network clients
	int TimerKick();

	// Common classifier for keeping phy counts
	int CommonTracker(kis_packet *in_packet);

	// Scrape detected strings and push them out to the client
	int StringCollector(kis_packet *in_packet);

	// Send all devices to everyone
	void BlitDevices(int in_fd);

	// send all phy records to everyone
	void BlitPhy(int in_fd);

	// Initiate a logging cycle
	int LogDevices(string in_logclass, string in_logtype, FILE *in_logfile);

	// Populate the common components of a device
	int PopulateCommon(kis_tracked_device_base *device, kis_packet *in_pack);
protected:
	void SaveTags();

	GlobalRegistry *globalreg;

    // Device base field id
    int device_base_id;

	int next_componentid;
	map<string, int> component_str_map;
	map<int, string> component_id_map;

	// Total # of packets
	int num_packets;
	int num_datapackets;
	int num_errorpackets;
	int num_filterpackets;
	int num_packetdelta;

	// Per-phy #s of packets
	map<int, int> phy_packets;
	map<int, int> phy_datapackets;
	map<int, int> phy_errorpackets;
	map<int, int> phy_filterpackets;
	map<int, int> phy_packetdelta;

	// Per-phy device list
	map<int, vector<kis_tracked_device_base *> *> phy_device_vec;

	// Per-phy dirty list
	map<int, vector<kis_tracked_device_base *> *> phy_dirty_vec;

	// Common device component
	int devcomp_ref_common;

	// Timer id for main timer kick
	int timerid;

	// Network protocols
	int proto_ref_phymap, proto_ref_commondevice, proto_ref_trackinfo,
		proto_ref_devtag, proto_ref_string, proto_ref_devicedone;

	int pack_comp_device, pack_comp_common, pack_comp_string, pack_comp_basicdata,
		pack_comp_radiodata, pack_comp_gps, pack_comp_capsrc;

	int cmd_adddevtag, cmd_deldevtag;

	// Tracked devices
	map<mac_addr, kis_tracked_device_base *> tracked_map;
	// Vector of tracked devices so we can iterate them quickly
	vector<kis_tracked_device_base *> tracked_vec;

	// Vector of dirty elements for pushing to clients, better than walking
	// the map every tick, looking for dirty records
	vector<kis_tracked_device_base *> dirty_device_vec;

	// Filtering
	FilterCore *track_filter;

	// Tag records as a config file
	ConfigFile *tag_conf;
	time_t conf_save;

	// Registered PHY types
	int next_phy_id;
	map<int, Kis_Phy_Handler *> phy_handler_map;

	// Log helpers
	void WriteXML(FILE *in_logfile);
	void WriteTXT(FILE *in_logfile);

	// Build a device record
	kis_tracked_device_base *BuildDevice(mac_addr in_device, kis_packet *in_pack);
};

#endif

