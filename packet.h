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

#ifndef __PACKET_H__
#define __PACKET_H__

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include "eventbus.h"
#include "globalregistry.h"
#include "macaddr.h"
#include "packet_ieee80211.h"
#include "packetchain.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

#include "string_view.hpp"
#include "unordered_dense.h"

#include "boost/asio/streambuf.hpp"

// This is the main switch for how big the vector is.  If something ever starts
// bumping up against this we'll need to increase it, but that'll slow down 
// generating a packet (slightly) so I'm leaving it relatively low.
#define MAX_PACKET_COMPONENTS	64

// Maximum length of a frame
#define MAX_PACKET_LEN			8192

// Same as defined in libpcap/system, but we need to know the basic dot11 DLT
// even when we don't have pcap
#define KDLT_IEEE802_11			105

class packet_component {
public:
    packet_component() { };
    virtual ~packet_component() { }

    // Is this component unique?  Unique components are preserved when aliasing duplicate
    // packets.  For instance, datasource, location, and l1 radio info should be considered
    // unique.
    virtual bool unique() { return false; }
};

// Overall packet container that holds packet information
class kis_packet {
public:
    // Time of packet creation
    struct timeval ts;

    // Assignment identifier (different from hash); used to map packets to processing
    // threads.  Should be formed from the device MAC (or MACs) in a way to assign
    // packets from the same device the same identifier as consistently as possible.
    uint32_t assignment_id;

    // Unique number of this packet
    uint64_t packet_no;

    // Do we know this is in error from the capture source itself?
    int error;

    // Do we know this packet is OK and don't have to run a CRC check on 
    // it inside a data layer?
    int crc_ok;

    // Have we been filtered for some reason?
    int filtered;

    // Are we a duplicate?
    int duplicate;

    // What hash has been calculated, if any?
    uint32_t hash;

    // if packet is based on raw data, this contains the data backing and data is a
    // view into it that other components should slice
    std::string raw_data;
    // if packet is based on network data, this contains the original network buffer
    // which must be returned as part of the reset/destructor process, and data is
    // a view into it that other components should slice
    std::shared_ptr<boost::asio::streambuf> raw_streambuf;

    // immutable data slice of packet contents
    nonstd::string_view data;

    // Original length of capture, if truncated
    uint64_t original_len;

    // Did this packet trigger creation of a new device?  Since a 
    // single packet can create multiple devices in some phys, maintain
    // a vector of device events to publish when all devices are done
    // processing
    std::vector<std::shared_ptr<eventbus_event>> process_complete_events;

    // pre-allocated vector of broken down packet components
    std::shared_ptr<packet_component> content_vec[MAX_PACKET_COMPONENTS];

    kis_packet();
    ~kis_packet();

    void reset();

    void set_data(const std::string& sdata) {
        raw_data = sdata;
        data = nonstd::string_view{raw_data};
    }

    // set just the streambuf, the data can be set as views of this later
    void set_streambuf(std::shared_ptr<boost::asio::streambuf> streambuf) {
        raw_streambuf = streambuf;
        data = nonstd::string_view{};
    }
    // take both a buffer and a subview of that buffer; packets are a sub-portion of the total
    // stream buffer of an external packet, but we need to track the total buffer as well
    void set_streambuf(std::shared_ptr<boost::asio::streambuf> streambuf, const nonstd::string_view& view) {
        raw_streambuf = streambuf;
        data = view;
    }

    // take a raw byte range and assign it to the raw data string, then create a string view
    template<typename T>
    void set_data(const T* tdata, size_t len) {
        raw_data = std::string(tdata, len);
        data = nonstd::string_view{raw_data};
    }

    // take a raw stringview and assign it to the data view.  either the lifecycle
    // MUST BE MANAGED EXTERNALLY, or the stringview must be into the data held
    // by the raw data string or the packet buffer associated with this packet
    void set_data(const nonstd::string_view& view) {
        data = view;
    }

    // Preferred smart pointers
    void insert(const unsigned int index, std::shared_ptr<packet_component> data);

    std::shared_ptr<packet_component> fetch(const unsigned int index) const;

    template<class T>
    std::shared_ptr<T> fetch() {
        return nullptr;
    }

    template<class T, typename... Pn>
    std::shared_ptr<T> fetch(const unsigned int index, const Pn& ... args) {
        auto k = std::static_pointer_cast<T>(this->fetch(index));

        if (k != nullptr)
            return k;

        return this->fetch<T>(args...);
    }

    template<class T, typename... Pn>
    std::shared_ptr<T> fetch_or_add(const unsigned int index) {
        auto k = std::static_pointer_cast<T>(this->fetch(index));

        if (k != nullptr)
            return k;

        k = Globalreg::globalreg->packetchain->new_packet_component<T>();
        this->insert(index, k);
        return k;
    }

    void erase(const unsigned int index);

    bool has(const unsigned int index) const {
        if (index >= MAX_PACKET_COMPONENTS)
            throw std::runtime_error(fmt::format("invalid packet component index {} greater than {}",
                        index, MAX_PACKET_COMPONENTS));

        return content_vec[index] != nullptr;
    }

    // Tags applied to the packet
    ankerl::unordered_dense::map<std::string, bool> tag_map;

    // Original packet if we're a duplicate
    std::shared_ptr<kis_packet> original;

    // Packet lock
    kis_mutex mutex;
};


// A generic tracked packet, which allows us to save some frames in a way we
// can recall and expose via the REST interface, for instance
class kis_tracked_packet : public tracker_component {
public:
    kis_tracked_packet() :
        tracker_component() {
            register_fields();
            reserve_fields(NULL);
        }

    kis_tracked_packet(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    kis_tracked_packet(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    kis_tracked_packet(const kis_tracked_packet *p) :
        tracker_component{p} {
            __ImportField(ts_sec, p);
            __ImportField(ts_usec, p);
            __ImportField(dlt, p);
            __ImportField(source, p);
            __ImportField(data, p);
            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_tracked_packet");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::globalreg->entrytracker->new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(ts_sec, uint64_t, time_t, time_t, ts_sec);
    __Proxy(ts_usec, uint64_t, uint64_t, uint64_t, ts_usec);
    __Proxy(dlt, uint64_t, uint64_t, uint64_t, dlt);
    __Proxy(source, uint64_t, uint64_t, uint64_t, source);

    __ProxyTrackable(data, tracker_element_byte_array, data);

    virtual void copy_packet(std::shared_ptr<kis_tracked_packet> in) {
        set_ts_sec(in->get_ts_sec());
        set_ts_usec(in->get_ts_usec());
        set_dlt(in->get_dlt());
        set_source(in->get_source());
        set_data(in->get_data());
    }

    void reset() {
        ts_sec->reset();
        ts_usec->reset();
        dlt->reset();
        source->reset();
        data->reset();
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.packet.ts_sec", "packet timestamp (second)", &ts_sec);
        register_field("kismet.packet.ts_usec", "packet timestamp (usec)", &ts_usec);
        register_field("kismet.packet.dlt", "packet DLT linktype", &dlt);
        register_field("kismet.packet.source", "packetsource id", &source);
        register_field("kismet.packet.data", "packet data", &data);
    }

    std::shared_ptr<tracker_element_uint64> ts_sec;
    std::shared_ptr<tracker_element_uint64> ts_usec;
    std::shared_ptr<tracker_element_uint64> dlt;
    std::shared_ptr<tracker_element_uint64> source;
    std::shared_ptr<tracker_element_byte_array> data;
};

// Arbitrary data chunk, decapsulated from the link headers
class kis_datachunk : public packet_component, public nonstd::string_view {
public:
    // Underlying raw data if this isn't a subset of another chunk
    std::string raw_data_;

    int dlt;
    uint16_t source_id;

    kis_datachunk() {
        source_id = 0;
    }

    virtual ~kis_datachunk() { }

    virtual void reset() {
        raw_data_.clear();
        nonstd::string_view::operator=(raw_data_);
    }

    // set a stringview as the data block; the lifetime of the backing data of this
    // view is not managed here, and MUST BE MANAGED BY THE CALLER.  typically this
    // would be a sub-view of the encapsulating packet data.
    virtual void set_data(const nonstd::string_view& view) {
        nonstd::string_view::operator=(view);
    }

    virtual void set_data(std::string& data) {
        nonstd::string_view::operator=(data);
    }

    virtual void copy_raw_data(const std::string& sdata) {
        raw_data_ = sdata;
        nonstd::string_view::operator=(raw_data_);
    }

    template<typename T>
    void copy_raw_data(const T* rd, size_t sz) {
        raw_data_ = std::string(rd, sz);
        nonstd::string_view::operator=(raw_data_);
    }

    std::string& raw() {
        return raw_data_;
    }
};

// Arbitrary data blob which gets logged into the DATA table in the kismet log
class packet_metablob : public packet_component {
public:
    std::string meta_type;
    std::string meta_data;

    packet_metablob(const std::string& in_type, const std::string& in_data) :
        meta_type{in_type},
        meta_data{in_data} { }

    packet_metablob() {  }

    void set_data(const std::string& in_type, const std::string& in_data) {
        meta_type = in_type;
        meta_data= in_data;
    }

    void reset() {
        meta_type.clear();
        meta_data.clear();
    }
};

class kis_packet_checksum : public kis_datachunk {
public:
    int checksum_valid;

    kis_packet_checksum() : kis_datachunk() {
        checksum_valid = 0;
    }

    void reset() {
        kis_datachunk::reset();
        checksum_valid = 0;
    }
};

enum kis_packet_basictype {
    packet_basic_unknown = 0,
    packet_basic_mgmt = 1,
    packet_basic_data = 2,
    packet_basic_phy = 3
};

// Common info
// Extracted by phy-specific dissectors, used by the common classifier
// to build phy-neutral devices and tracking records.
class kis_tracked_device_base;

enum kis_packet_direction {
    packet_direction_unknown = 0,

    // From device
    packet_direction_from = 1,

    // To device
    packet_direction_to = 2,

    // Intra-carrier (WDS for instance)
    packet_direction_carrier = 3
};

// Common info item which is aggregated into a packet under 
// the packet_info_map type
class kis_common_info : public packet_component {
public:
    kis_common_info() {
        reset();
    }

    void reset() {
        type = packet_basic_unknown;
        direction = packet_direction_unknown;

        phyid = -1;
        error = 0;
        datasize = 0;
        channel = "0";
        freq_khz = 0;
        basic_crypt_set = 0;

        source = mac_addr(0);
        dest = mac_addr(0);
        network = mac_addr(0);
        transmitter = mac_addr(0);
    }

    // Source - origin of packet
    // Destination - dest of packet
    // Network - Associated network device (such as ap bssid)
    // Transmitter - Independent transmitter, if not source or network
    // (wifi wds for instance)
    mac_addr source, dest, network, transmitter;

    kis_packet_basictype type;
    kis_packet_direction direction;

    int phyid;
    // Some sort of phy-level error 
    int error;
    // Data size if applicable
    int datasize;
    // Encryption if applicable
    uint32_t basic_crypt_set;
    // Phy-specific numeric channel, freq is held in l1info.  Channel is
    // represented as a string to carry whatever special attributes, ie
    // 6HT20 or 6HT40+ for wifi
    std::string channel;
    // Frequency in khz
    double freq_khz;
};

// String reference
class kis_string_info : public packet_component {
public:
    kis_string_info() { }
    std::vector<std::string> extracted_strings;
};

typedef struct {
    std::string text;
    mac_addr bssid;
    mac_addr source;
    mac_addr dest;
} string_proto_info;

// some protocols we do try to track
enum kis_protocol_info_type {
    proto_unknown,
    proto_udp, 
    proto_tcp, 
    proto_arp, 
    proto_dhcp_offer,
    proto_dhcp_discover,
    proto_cdp,
    proto_turbocell,
    proto_netstumbler_probe,
    proto_lucent_probe,
    proto_iapp,
    proto_isakmp,
    proto_pptp,
    proto_eap
};

class kis_data_packinfo : public packet_component {
public:
    kis_data_packinfo() {
        reset();
    }

    void reset() {
        proto = proto_unknown;
        ip_source_port = 0;
        ip_dest_port = 0;
        ip_source_addr.s_addr = 0;
        ip_dest_addr.s_addr = 0;
        ip_netmask_addr.s_addr = 0;
        ip_gateway_addr.s_addr = 0;
        field1 = 0;
        ivset[0] = ivset[1] = ivset[2] = 0;
    }

    kis_protocol_info_type proto;

    // IP info, we re-use a subset of the kis_protocol_info_type enum to fill
    // in where we got our IP data from.  A little klugey, but really no reason
    // not to do it
    int ip_source_port;
    int ip_dest_port;
    in_addr ip_source_addr;
    in_addr ip_dest_addr;
    in_addr ip_netmask_addr;
    in_addr ip_gateway_addr;
    kis_protocol_info_type ip_type;

    // The two CDP fields we really care about for anything
    std::string cdp_dev_id;
    std::string cdp_port_id;

    // DHCP Discover data
    std::string discover_host, discover_vendor;

    // IV
    uint8_t ivset[3];

    // An extra field that can be filled in
    int field1;

    // A string field that can be filled in
    std::string auxstring;

};

// Layer 1 radio info record for kismet
enum kis_layer1_packinfo_signal_type {
    kis_l1_signal_type_none,
    kis_l1_signal_type_dbm,
    kis_l1_signal_type_rssi
};

class kis_layer1_packinfo : public packet_component {
public:
    kis_layer1_packinfo() {
        reset();
    }

    virtual bool unique() override { return true; }

    void reset() {
        signal_type = kis_l1_signal_type_none;
        signal_dbm = noise_dbm = 0;
        signal_rssi = noise_rssi = 0;
        carrier = carrier_unknown;
        encoding = encoding_unknown;
        datarate = 0;
        freq_khz = 0;
        accuracy = 0;
        channel = "0";
    }

    // How "accurate" are we?  Higher == better.  Nothing uses this yet
    // but we might as well track it here.
    int accuracy;

    // Frequency seen on
    double freq_khz;

    // Logical channel
    std::string channel;

    // Connection info
    kis_layer1_packinfo_signal_type signal_type;
    int signal_dbm, signal_rssi;
    int noise_dbm, noise_rssi;

    // Per-antenna info, mapped to the antenna number
    std::map<uint8_t, int> antenna_signal_map;

    // What carrier brought us this packet?
    phy_carrier_type carrier;

    // What encoding?
    phy_encoding_type encoding;

    // What data rate?
    double datarate;

    // Checksum, if checksumming is enabled; Only of the non-header 
    // data
    uint32_t content_checkum;
};

// Combined list of signal levels collected over time for tracking signal levels of the
// same transmission over multiple datasources, collected by the content deduper phase
class kis_layer1_aggregate_packinfo : public packet_component {
public:
    kis_layer1_aggregate_packinfo() {
        reset();
    }

    // We're not unique - multiple packets can insert l1 signals into the same
    // aggregated list
    virtual bool unique() override { return false; }

    void reset() {
        source_l1_map.clear();
    }

    std::unordered_map<uuid, std::shared_ptr<kis_layer1_packinfo>> source_l1_map;
};

// JSON as a raw string; parsing happens in the DS code; currently supports one JSON report
// per packet, which is fine for the current design
class kis_json_packinfo : public packet_component {
public:
    kis_json_packinfo() { }

    void reset() {
        type.clear();
        json_string.clear();
    }

    std::string type;
    std::string json_string;
};

// Protobuf record as a raw string-like record; parsing happens in the DS code; currently
// supports one protobuf report per packet, which is fine for the current design.
class kis_protobuf_packinfo : public packet_component {
public:
    kis_protobuf_packinfo() { }

    void reset() {
        type.clear();
        buffer_string.clear();
    }

    std::string type;
    std::string buffer_string;
};

// Device tags added at capture time by the capture or scan engine 
class kis_devicetag_packetinfo : public packet_component { 
public: 
    kis_devicetag_packetinfo() { }

    void reset() { 
        tagmap.clear();
    }

    std::map<std::string, std::string> tagmap;
};

#endif

