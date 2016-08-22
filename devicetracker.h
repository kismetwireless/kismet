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

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packetsource.h"
#include "packet.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "uuid.h"
#include "configfile.h"
#include "phyhandler.h"
#include "packinfo_signal.h"
#include "devicetracker_component.h"
#include "trackercomponent_legacy.h"
#include "timetracker.h"
#include "kis_net_microhttpd.h"

// How big the main vector of components is, if we ever get more than this
// many tracked components we'll need to expand this but since it ties to
// memory and track record creation it starts relatively low
#define MAX_TRACKER_COMPONENTS	64

#define KIS_PHY_ANY	-1
#define KIS_PHY_UNKNOWN -2

// Helper for making keys
//
// Device keys are phy and runtime specific.
//
// A device key should not be exported to file with the phy component.
// A device key may be exported to a client with the phy component intact,
// with the understanding that the phy component is valid for the current
// session only.
//
class DevicetrackerKey {
public:
    static void SetPhy(uint64_t &key, int16_t phy) {
        key &= ~(0xFFFFL << 48);
        key |= ((phy & 0xFFFFL) << 48);
    }

    static void SetDevice(uint64_t &key, uint64_t device) {
        key &= ~(0xFFFFFFFFFFFF);
        key |= (device & 0xFFFFFFFFFFFF);
    }

    static uint16_t GetPhy(uint64_t key) {
        return ((key >> 48) & 0xFFFFL);
    }

    static uint64_t GetDevice(uint64_t key) {
        return (key & 0xFFFFFFFFFFFF);
    }

    static uint64_t MakeKey(mac_addr in_mac, int16_t in_phy) {
        uint64_t r = 0L;

        SetPhy(r, in_phy);
        SetDevice(r, in_mac.GetAsLong());

        return r;
    }
};

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

    __Proxy(key, uint64_t, uint64_t, uint64_t, key);

    __Proxy(macaddr, mac_addr, mac_addr, mac_addr, macaddr);

    __Proxy(phyname, string, string, string, phyname);

    __Proxy(devicename, string, string, string, devicename);
    __Proxy(username, string, string, string, username);

    __Proxy(type_string, string, string, string, type_string);

    __Proxy(basic_type_set, uint64_t, uint64_t, uint64_t, basic_type_set);
    __ProxyBitset(basic_type_set, uint64_t, basic_type_set);

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

    __Proxy(datasize, uint64_t, uint64_t, uint64_t, datasize);
    __ProxyIncDec(datasize, uint64_t, uint64_t, datasize);

    typedef kis_tracked_rrd<uint64_t, TrackerUInt64> uint64_rrd;
    __ProxyTrackable(packets_rrd, uint64_rrd, packets_rrd);

    __ProxyTrackable(data_rrd, uint64_rrd, data_rrd);

    __Proxy(channel, string, string, string, channel);
    __Proxy(frequency, double, double, double, frequency);

    __Proxy(manuf, string, string, string, manuf);

    __Proxy(num_alerts, uint32_t, unsigned int, unsigned int, alert);

    __ProxyTrackable(signal_data, kis_tracked_signal_data, signal_data);

    // Intmaps need special care by the caller
    TrackerElement *get_freq_khz_map() { return freq_khz_map; }

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

    void inc_frequency_count(double frequency) {
        if (frequency <= 0)
            return;

        TrackerElement::double_map_iterator i = freq_khz_map->double_find(frequency);

        if (i == freq_khz_map->double_end()) {
            TrackerElement *e =
                globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
            e->set((uint64_t) 1);
            freq_khz_map->add_doublemap(frequency, e);
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

            seenby->set_src_uuid(source->FetchUUID());
            seenby->set_first_time(tv_sec);
            seenby->set_last_time(tv_sec);
            seenby->set_num_packets(1);

            if (frequency > 0)
                seenby->inc_frequency_count(frequency);

            seenby_map->add_intmap(source->FetchSourceID(), seenby);

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
            RegisterField("kismet.device.base.key", TrackerUInt64,
                    "unique integer key", (void **) &key);

        macaddr_id =
            RegisterField("kismet.device.base.macaddr", TrackerMac,
                    "mac address", (void **) &macaddr);

        phyname_id =
            RegisterField("kismet.device.base.phyname", TrackerString,
                    "phy name", (void **) &phyname);

        devicename_id =
            RegisterField("kismet.device.base.name", TrackerString,
                    "printable device name", (void **) &devicename);

        username_id =
            RegisterField("kismet.device.base.username", TrackerString,
                    "user name", (void **) &username);

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

        datasize_id =
            RegisterField("kismet.device.base.datasize", TrackerUInt64,
                        "transmitted data in bytes", (void **) &datasize);

        kis_tracked_rrd<uint64_t, TrackerUInt64> *packets_rrd_builder =
            new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 0);
        packets_rrd_id =
            globalreg->entrytracker->RegisterField("kismet.device.base.packets.rrd",
                    packets_rrd_builder, "packet rate rrd");
        delete(packets_rrd_builder);

        kis_tracked_rrd<uint64_t, TrackerUInt64> *data_rrd_builder =
            new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 0);
        data_rrd_id =
            globalreg->entrytracker->RegisterField("kismet.device.base.datasize.rrd",
                    data_rrd_builder, "packet size rrd");
        delete(data_rrd_builder);

        kis_tracked_signal_data *sig_builder =
            new kis_tracked_signal_data(globalreg, 0);
        signal_data_id =
            RegisterComplexField("kismet.device.base.signal", sig_builder,
                    "signal data");
        delete(sig_builder);

        freq_khz_map_id =
            RegisterField("kismet.device.base.freq_khz_map", TrackerDoubleMap,
                    "packets seen per frequency (khz)", (void **) &freq_khz_map);

        channel_id =
            RegisterField("kismet.device.base.channel", TrackerString,
                        "channel (phy specific)", (void **) &channel);
        frequency_id =
            RegisterField("kismet.device.base.frequency", TrackerDouble,
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
        delete(tag_builder);

        kis_tracked_location *loc_builder = new kis_tracked_location(globalreg, 0);
        location_id =
            RegisterComplexField("kismet.device.base.location", loc_builder,
                    "location");
        delete(loc_builder);

        seenby_map_id =
            RegisterField("kismet.device.base.seenby", TrackerIntMap,
                    "sources that have seen this device", (void **) &seenby_map);

        // Packet count, not actual frequency, so uint64 not double
        frequency_val_id =
            globalreg->entrytracker->RegisterField("kismet.device.base.frequency.count",
                    TrackerUInt64, "frequency packet count");

        kis_tracked_seenby_data *seenby_builder =
            new kis_tracked_seenby_data(globalreg, 0);
        seenby_val_id =
            globalreg->entrytracker->RegisterField("kismet.device.base.seenby.data",
                    seenby_builder, "seen-by data");
        delete(seenby_builder);

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

            packets_rrd = new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg,
                    packets_rrd_id, e->get_map_value(packets_rrd_id));
            data_rrd = new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg,
                    data_rrd_id, e->get_map_value(data_rrd_id));
        } else {
            signal_data = new kis_tracked_signal_data(globalreg, signal_data_id);
            add_map(signal_data);

            tag = new kis_tracked_tag(globalreg, tag_id);
            add_map(tag);

            location = new kis_tracked_location(globalreg, location_id);
            add_map(location);

            packets_rrd = new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg,
                    packets_rrd_id);
            add_map(packets_rrd);
            data_rrd = new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg,
                   data_rrd_id);
            add_map(data_rrd);
        }
    }


    // Unique key
    TrackerElement *key;
    int key_id;

    // Mac address (probably the key, but could be different)
    TrackerElement *macaddr;
    int macaddr_id;

    // Phy type (integer index)
    TrackerElement *phyname;
    int phyname_id;

    // Printable name for UI summary.  For APs could be latest SSID, for BT the UAP
    // guess, etc.
    TrackerElement *devicename;
    int devicename_id;

    // User name for arbitrary naming
    TrackerElement *username;
    int username_id;

    // Printable basic type relevant to the phy, ie "Wired", "AP", "Bluetooth", etc.
    // This can be set per-phy and is treated as a printable interpretation.
    // This should be empty if the phy layer is unable to add something intelligent
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
    TrackerElement *datasize;
    int datasize_id;

    // Packets and data RRDs
    int packets_rrd_id;
    kis_tracked_rrd<uint64_t, TrackerUInt64> *packets_rrd;

    int data_rrd_id;
    kis_tracked_rrd<uint64_t, TrackerUInt64> *data_rrd;

	// Channel and frequency as per PHY type
    TrackerElement *channel, *frequency;
    int channel_id, frequency_id;

    // Signal data
    kis_tracked_signal_data *signal_data;
    int signal_data_id;

    // Global frequency distribution
    TrackerElement *freq_khz_map;
    int freq_khz_map_id;

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

// Filter-handler class.  Subclassed by a filter supplicant to be passed to the
// device filter functions.
class DevicetrackerFilterWorker {
public:
    DevicetrackerFilterWorker() { };

    // Perform a match on a device
    virtual void MatchDevice(Devicetracker *devicetracker,
            kis_tracked_device_base *base) = 0;

    // Finalize operations
    virtual void Finalize(Devicetracker *devicetracker) { }
};

class Devicetracker : public Kis_Net_Httpd_Stream_Handler,
    public TimetrackerEvent {
public:
	Devicetracker(GlobalRegistry *in_globalreg);
	virtual ~Devicetracker();

	// Register a phy handler weak class, used to instantiate the strong class
	// inside devtracker
	int RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler);

	Kis_Phy_Handler *FetchPhyHandler(int in_phy);
	Kis_Phy_Handler *FetchPhyHandler(uint64_t in_key);

    string FetchPhyName(int in_phy);

	int FetchNumDevices(int in_phy);
	int FetchNumPackets(int in_phy);
	int FetchNumDatapackets(int in_phy);
	int FetchNumCryptpackets(int in_phy);
	int FetchNumErrorpackets(int in_phy);
	int FetchNumFilterpackets(int in_phy);

	int AddFilter(string in_filter);
	int AddNetCliFilter(string in_filter);

#if 0
	int SetDeviceTag(mac_addr in_device, string in_data);
	int ClearDeviceTag(mac_addr in_device);
	string FetchDeviceTag(mac_addr in_device);
#endif

	// Look for an existing device record
	kis_tracked_device_base *FetchDevice(uint64_t in_key);
	kis_tracked_device_base *FetchDevice(mac_addr in_device, unsigned int in_phy);

    // Perform a device filter.  Pass a subclassed filter instance.  It is not
    // thread safe to retain a vector/copy of devices, so all work should be
    // done inside the worker
    void MatchOnDevices(DevicetrackerFilterWorker *worker);

	typedef map<uint64_t, kis_tracked_device_base *>::iterator device_itr;
	typedef map<uint64_t, kis_tracked_device_base *>::const_iterator const_device_itr;

	static void Usage(char *argv);

	// Common classifier for keeping phy counts
	int CommonTracker(kis_packet *in_packet);

	// Initiate a logging cycle
	int LogDevices(string in_logclass, string in_logtype, FILE *in_logfile);

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
    kis_tracked_device_base *UpdateCommonDevice(mac_addr in_mac, int in_phy,
            kis_packet *in_pack, unsigned int in_flags);

    // HTTP handlers
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    void httpd_all_phys(TrackerElementSerializer *serializer);

    void httpd_device_summary(TrackerElementSerializer *serializer,
            TrackerElementVector *subvec = NULL);

    // TODO merge this into a normal serializer call
    void httpd_xml_device_summary(std::stringstream &stream);

    // Timetracker event handler
    virtual int timetracker_event(int eventid);

    // CLI extension
    static void usage(const char *name);

protected:
	void SaveTags();

	GlobalRegistry *globalreg;

    // Base IDs for tracker components
    int device_list_base_id, device_base_id, phy_base_id, phy_entry_id;
    int device_summary_base_id, device_summary_entry_id;

	// Total # of packets
	int num_packets;
	int num_datapackets;
	int num_errorpackets;
	int num_filterpackets;

	// Per-phy #s of packets
	map<int, int> phy_packets;
	map<int, int> phy_datapackets;
	map<int, int> phy_errorpackets;
	map<int, int> phy_filterpackets;

    // Total packet history
    int packets_rrd_id;
    kis_tracked_rrd<uint64_t, TrackerUInt64> *packets_rrd;

    // Timeout of idle devices
    int device_idle_expiration;
    int device_idle_timer;

    // Maximum number of devices
    unsigned int max_num_devices;
    int max_devices_timer;

	// Common device component
	int devcomp_ref_common;

    // Packet components we add or interact with
	int pack_comp_device, pack_comp_common, pack_comp_basicdata,
		pack_comp_radiodata, pack_comp_gps, pack_comp_capsrc;

	// Tracked devices
	map<uint64_t, kis_tracked_device_base *> tracked_map;
	// Vector of tracked devices so we can iterate them quickly
	vector<kis_tracked_device_base *> tracked_vec;

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

	// Populate the common components of a device
	int PopulateCommon(kis_tracked_device_base *device, kis_packet *in_pack);

    pthread_mutex_t devicelist_mutex;
};

class kis_tracked_device_summary : public tracker_component {
public:
    kis_tracked_device_summary(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_device_summary(GlobalRegistry *in_globalreg, int in_id,
            TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    // Build a summary by grabbing values out of a base device
    kis_tracked_device_summary(GlobalRegistry *in_globalreg, int in_id,
            kis_tracked_device_base *base) : tracker_component(in_globalreg, in_id) {

        // We don't register or reserve fields because we grab them directly out of
        // an existing component
        add_map(base->get_tracker_key());
        add_map(base->get_tracker_macaddr());
        add_map(base->get_tracker_phyname());
        add_map(base->get_tracker_devicename());
        add_map(base->get_tracker_type_string());
        add_map(base->get_tracker_crypt_string());
        add_map(base->get_tracker_first_time());
        add_map(base->get_tracker_last_time());
        add_map(base->get_tracker_packets());
        add_map(base->get_tracker_signal_data());
        add_map(base->get_tracker_channel());
        add_map(base->get_tracker_frequency());
        add_map(base->get_tracker_manuf());
        add_map(base->get_tracker_packets_rrd());
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_device_summary(globalreg, get_id());
    }
};

class kis_tracked_phy : public tracker_component {
public:
    kis_tracked_phy(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_phy(GlobalRegistry *in_globalreg, int in_id,
            TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_phy(globalreg, get_id());
    }

    __Proxy(phy_id, int32_t, int32_t, int32_t, phy_id);
    __Proxy(phy_name, string, string, string, phy_name);
    __Proxy(num_devices, uint64_t, uint64_t, uint64_t, num_devices);
    __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
    __Proxy(num_data_packets, uint64_t, uint64_t, uint64_t, num_data_packets);
    __Proxy(num_crypt_packets, uint64_t, uint64_t, uint64_t, num_crypt_packets);
    __Proxy(num_error_packets, uint64_t, uint64_t, uint64_t, num_error_packets);
    __Proxy(num_filter_packets, uint64_t, uint64_t, uint64_t, num_filter_packets);

    void set_from_phy(Devicetracker *devicetracker, int phy) {
        set_phy_id(phy);
        set_phy_name(devicetracker->FetchPhyName(phy));
        set_num_devices(devicetracker->FetchNumDevices(phy));
        set_num_packets(devicetracker->FetchNumPackets(phy));
        set_num_data_packets(devicetracker->FetchNumDatapackets(phy));
        set_num_crypt_packets(devicetracker->FetchNumCryptpackets(phy));
        set_num_error_packets(devicetracker->FetchNumErrorpackets(phy));
        set_num_filter_packets(devicetracker->FetchNumFilterpackets(phy));
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        phy_id_id = RegisterField("kismet.phy.id", TrackerInt32,
                "phy id", (void **) &phy_id);
        phy_name_id = RegisterField("kismet.phy.name", TrackerString,
                "phy name", (void **) &phy_name);
        num_devices_id = RegisterField("kismet.phy.devices", TrackerUInt64,
                "number of devices", (void **) &num_devices);
        num_packets_id = RegisterField("kismet.phy.packets", TrackerUInt64,
                "number of packets", (void **) &num_packets);
        num_data_packets_id = RegisterField("kismet.phy.packets.data", TrackerUInt64,
                "number of data packets", (void **) &num_data_packets);
        num_crypt_packets_id =
            RegisterField("kismet.phy.packets.crypt", TrackerUInt64,
                    "number of encrypted packets", (void **) &num_crypt_packets);
        num_error_packets_id =
            RegisterField("kismet.phy.packets.error", TrackerUInt64,
                    "number of error packets", (void **) &num_error_packets);
        num_filter_packets_id =
            RegisterField("kismet.phy.packets.filtered", TrackerUInt64,
                    "number of filtered packets", (void **) &num_filter_packets);
    }

    int phy_id_id;
    TrackerElement *phy_id;

    int phy_name_id;
    TrackerElement *phy_name;

    int num_devices_id;
    TrackerElement *num_devices;

    int num_packets_id;
    TrackerElement *num_packets;

    int num_data_packets_id;
    TrackerElement *num_data_packets;

    int num_crypt_packets_id;
    TrackerElement *num_crypt_packets;

    int num_error_packets_id;
    TrackerElement *num_error_packets;

    int num_filter_packets_id;
    TrackerElement *num_filter_packets;

};

#endif
