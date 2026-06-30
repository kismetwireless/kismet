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

#ifndef __DEVICETRACKER_COMPONENT_V2__
#define __DEVICETRACKER_COMPONENT_V2__

#include <string>

#include <memory>
#include <stdint.h>

#include "fmt/base.h"
#include "json_adapter_v2.h"
#include "macaddr.h"
#include "packet.h"
#include "packinfo_signal.h"
#include "kis_datasource.h"
#include "rrd_v2.h"
#include "trackedlocation_v2.h"

class device_key_v2 {
public:
    device_key_v2();
    device_key_v2(const device_key_v2& k);
    device_key_v2(const device_key_v2&& k);

    // Create a key from a computed phy hash and a mac address
    device_key_v2(uint32_t in_pkey, mac_addr in_device);
    // Create a key from a computed phy hash and a computed mac address
    device_key_v2(uint32_t in_pkey, uint64_t in_device);

    // Create a key from an incoming string/exported key; this should only happen during
    // deserialization and rest queries; it's fairly expensive otherwise
    device_key_v2(const std::string& in_keystr);

    device_key_v2& operator =(const device_key_v2& op) {
        spkey_ = op.spkey_;
        dkey_ = op.dkey_;
        error_ = op.error_;
        return *this;
    }

    void reset();

    std::string as_string() const;

    // Generate a cached phykey component; phyhandlers do this to cache
    static uint32_t gen_pkey(const std::string& in_phy);
    static uint32_t gen_pkey(const std::string_view& in_phy);

    // Generate a cached SP key combination
    static uint64_t gen_spkey(uuid s_uuid, const std::string& phy);

    constexpr17 auto error() const { return error_; }
    constexpr17 auto spkey() const { return spkey_; }
    constexpr17 auto dkey() const { return dkey_; }

protected:
    uint64_t spkey_, dkey_;
    bool error_;

    friend bool operator <(const device_key_v2& x, const device_key_v2& y);
    friend bool operator ==(const device_key_v2& x, const device_key_v2& y);
};

bool operator <(const device_key_v2& x, const device_key_v2& y);
bool operator ==(const device_key_v2& x, const device_key_v2& y);
std::ostream& operator<<(std::ostream& os, const device_key_v2& k);
std::istream& operator>>(std::istream& is, device_key_v2& k);

template <> struct fmt::formatter<device_key_v2>: formatter<std::string_view> {
  auto format(const device_key_v2& k, format_context& ctx) const -> format_context::iterator;
};

namespace std {
    template<> struct hash<device_key_v2> {
        std::size_t operator()(device_key_v2 const& m) const noexcept {
            auto h = std::hash<uint64_t>{}(m.spkey());
            h = h ^ std::hash<uint64_t>{}(m.dkey());
            return h;
        }
    };
}

template<> struct json_adapter_v2::json_encode<device_key_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *, const device_key_v2& k) {
        fmt::print(os, "\"{}\"", k.as_string());
    }
    void operator()(std::ostream& os, json_adapter_v2::opts *, const device_key_v2 *k) {
        fmt::print(os, "\"{}\"", k->as_string());
    }
};

class kis_tracked_signal_data_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_signal_data_v2() :
        sig_type{0},
        last_signal{0},
        min_signal{0},
        max_signal{0},
        last_noise{0},
        min_noise{0},
        max_noise{0},
        maxseenrate{0},
        encodingset{0},
        carrierset{0} { }

    virtual ~kis_tracked_signal_data_v2() { }

    void reset() {
        sig_type = 0;
        last_signal = 0;
        min_signal = 0;
        max_signal = 0;
        last_noise = 0;
        min_noise = 0;
        max_noise = 0;
        maxseenrate = 0;
        encodingset = 0;
        carrierset = 0;
    }

    void append_signal(const kis_layer1_packinfo& lay1, bool update_rrd, time_t rrd_ts);
    void append_signal(const packinfo_sig_combo& in, bool update_rrd, time_t rrd_ts);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    unsigned int sig_type;
    int32_t last_signal, min_signal, max_signal;
    int32_t last_noise, min_noise, max_noise;
    double maxseenrate;
    uint64_t encodingset, carrierset;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_signal_data_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class kis_tracked_seenby_data_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_seenby_data_v2(std::shared_ptr<kis_datasource> datasource, uint64_t time) :
        json_adapter_v2::jsonable(),
        datasource_{datasource},
        first_time_{time},
        last_time_{0},
        num_packets_{0},
        signal_data_{} { }

    void reset() {
        datasource_.reset();
        first_time_ = 0;
        last_time_ = 0;
        num_packets_ = 0;
        freq_khz_map_ = {};
        signal_data_.reset();
    }

    auto datasource() const { return datasource_; }
    void set_datasource(std::shared_ptr<kis_datasource> datasource, time_t time) {
        datasource_ = datasource;
        first_time_ = time;
    }

    void inc_seenby(uint64_t frequency, uint64_t time, const kis_tracked_signal_data_v2& signal);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    std::shared_ptr<kis_datasource> datasource_;

    uint64_t first_time_;
    uint64_t last_time_;

    uint64_t num_packets_;

    using freq_khz_map_iter_t = std::unordered_map<uint64_t, uint64_t>::iterator;
    std::unordered_map<uint64_t, uint64_t> freq_khz_map_;

    kis_tracked_signal_data_v2 signal_data_;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_seenby_data_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_seenby_data_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_seenby_data_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_seenby_data_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_seenby_data_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

#if 0 // masked before migration to prevent duplicates
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
#endif

// contains internal mutex, but with caveats:
// 1.  callers are expected to lock the mutex before calling any
//     access/set functions directly, since most callers are
//     expected to need multiple function calls
// 2.  the mutex must be locked by the caller before adding a
//     subcomponent
// 3.  the mutex is locked automatically as a shared read during
//     serialization ops
// 4.  the mutex is exclusively locked during destruction and reset
//     automatically
class kis_tracked_device_base_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_device_base_v2();
    ~kis_tracked_device_base_v2();

    void reset();

    // Expose mutex for external locking; most accessors will be using multiple
    // methods so let them manage lock
    auto& mutex() { return mutex_; }

    const auto internal_id() const { return internal_id_; }
    void set_internal_id(auto id) { internal_id_ = id; }

    const auto key() const { return key_; }
    void set_key(const auto& k) { key_ = k; }

    const auto phyname() { return phyname_; }
    void set_phyname(const auto& phy) { phyname_ = phy; }

    const auto phyid() { return phyid_; }
    void set_phyid(auto phy) { phyid_ = phy; }

    const auto& commonname() {
        if (username() != "") {
            return username();
        }

        return commonname_;
    }
    void set_commonname(const auto& name) { commonname_ = name; }

    const auto& devicename() { return devicename_; }
    void set_devicename(const auto& name) {
        devicename_ = name;
        commonname_ = "";
    }

    const std::string& username() { return username_; }
    void set_username(const auto& name) { username_ = name; }

    const auto& type_string() { return type_string_; }
    void set_type_string(const auto& type) { type_string_ = type; }
    void set_type_string_if(const auto& type, uint64_t ifset) {
        if (basic_type_set_ & ifset) {
            type_string_ = type;
        }
    }
    void set_type_string_ifonly(const auto& type, uint64_t ifset) {
        if (basic_type_set_ == ifset) {
            type_string_ = type;
        }
    }
    void set_type_string_ifnot(const auto& type, uint64_t ifset) {
        if ((basic_type_set_ & ifset) != ifset) {
            type_string_ = type;
        }
    }
    void set_type_string_ifnotany(const auto& type, uint64_t ifset) {
        if (!(basic_type_set_ & ifset)) {
            type_string_ = type;
        }
    }
    void set_type_string_ifany(const auto& type, uint64_t ifset) {
        if ((basic_type_set_ & ifset)) {
            type_string_ = type;
        }
    }

    const auto& basic_type_set() { return basic_type_set_; }
    void set_basic_type_set(auto set) { basic_type_set_ = set; }

    const auto& mac_addr() { return mac_addr_; }
    void set_mac_addr(const auto& mac) {
        mac_addr_ = mac;
        if (commonname() == "") {
            set_commonname(mac.to_string());
        }
    }

    const auto first_time() { return first_time_; }
    void set_first_time(auto time) { first_time_ = time; }
    void set_first_time_ifless(auto time) {
        if (time < first_time_) {
            first_time_ = time;
        }
    }

    const auto last_time() { return last_time_; }
    void set_last_time(auto time) { last_time_ = time; }
    void set_last_time_ifgreater(auto time) {
        if (last_time_ < time) {
            last_time_ = time;
        }
    }

    const auto mod_time() { return mod_time_; }
    void set_mod_time(auto time) { mod_time_ = time; }
    void set_mod_time_now() { mod_time_ = Globalreg::globalreg->last_tv_sec; }

    const auto& crypt_string() { return crypt_string_; }
    void set_crypt_string(const std::string& crypt) { crypt_string_ = crypt; }

    const auto basic_crypt_set() { return basic_crypt_set_; }
    void set_basic_crypt_set(const auto set) { basic_crypt_set_ = set; }
    void add_basic_crypt_set(const auto set) { basic_crypt_set_ |= set; }

    const auto packets() { return packets_; }
    void set_packets(uint64_t packets) { packets_ = packets; }
    void increment_packets(uint64_t inc) { packets_ += inc; }

    const auto tx_packets() { return tx_packets_; }
    void set_tx_packets(uint64_t tx_packets) { tx_packets_ = tx_packets; }
    void increment_tx_packets(uint64_t inc) { tx_packets_ += inc; }

    const auto rx_packets() { return rx_packets_; }
    void set_rx_packets(uint64_t rx_packets) { rx_packets_ = rx_packets; }
    void increment_rx_packets(uint64_t inc) { rx_packets_ += inc; }

    const auto llc_packets() { return llc_packets_; }
    void set_llc_packets(uint64_t llc_packets) { llc_packets_ = llc_packets; }
    void increment_llc_packets(uint64_t inc) { llc_packets_ += inc; }

    const auto error_packets() { return error_packets_; }
    void set_error_packets(uint64_t error_packets) { error_packets_ = error_packets; }
    void increment_error_packets(uint64_t inc) { error_packets_ += inc; }

    const auto data_packets() { return data_packets_; }
    void set_data_packets(uint64_t data_packets) { data_packets_ = data_packets; }
    void increment_data_packets(uint64_t inc) { data_packets_ += inc; }

    const auto crypt_packets() { return crypt_packets_; }
    void set_crypt_packets(uint64_t crypt_packets) { crypt_packets_ = crypt_packets; }
    void increment_crypt_packets(uint64_t inc) { crypt_packets_ += inc; }

    const auto filter_packets() { return filter_packets_; }
    void set_filter_packets(uint64_t filter_packets) { filter_packets_ = filter_packets; }
    void increment_filter_packets(uint64_t inc) { filter_packets_ += inc; }

    const auto duplicate_packets() { return duplicate_packets_; }
    void set_duplicate_packets(uint64_t duplicate_packets) { duplicate_packets_ = duplicate_packets; }
    void increment_duplicate_packets(uint64_t inc) { duplicate_packets_ += inc; }

    const auto datasize() { return datasize_; }
    void set_datasize(uint64_t datasize) { datasize_ = datasize; }
    void increment_datasize(uint64_t inc) { datasize_ += inc; }

    auto& packets_rrd() { return packets_rrd_; }
    void inc_packets_rrd(time_t time) { packets_rrd_.add_sample(1, time); }

    auto& data_rrd() { return data_rrd_; }
    void inc_data_rrd(uint64_t data, time_t time) { data_rrd_.add_sample(data, time); }

    auto& packets_rx_rrd() { return packets_rx_rrd_; }
    void inc_packets_rx_rrd(time_t time) { packets_rx_rrd_.add_sample(1, time); }

    auto& packets_tx_rrd() { return packets_tx_rrd_; }
    void inc_packets_tx_rrd(time_t time) { packets_tx_rrd_.add_sample(1, time); }

    const auto& channel() { return channel_; }
    void set_channel(const auto& channel) { channel_ = channel; }

    const auto frequency_khz() { return frequency_khz_; }
    void set_frequency_khz(auto freq) { frequency_khz_ = freq; }

    auto& freq_khz_distribution() { return freq_khz_distribution_; }
    void inc_freq_khz_distribution(uint64_t freq) { freq_khz_distribution_[freq]++; }

    auto& signal() { return signal_; }

    const auto& manuf() { return manuf_; }
    void set_manuf(const auto& manuf) { manuf_ = manuf; }

    auto& tag_map() { return tag_map_; }

    auto& location() { return location_; }
    auto& location_history() { return location_history_; }

    auto& seenby_map() { return seenby_map_; }

    auto& related_devices() { return related_devices_; }
    void add_related_device(const std::string& key, const device_key_v2& device) {
        related_devices_[key][device] = true;
    }

    const auto num_alerts() { return num_alerts_; }
    void set_num_alerts(auto num) { num_alerts_ = num; }
    void inc_num_alerts() { num_alerts_++; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

    using subcomponent_encoder_fn_t =
        std::function<void (std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable *sub,
                const json_adapter_v2::field_group_map& fields)>;

    // throws a std::runtime error if there is a component already using that name
    void add_subcomponent(const std::string& field, subcomponent_encoder_fn_t encoder,
            json_adapter_v2::jsonable *obj);

    template<typename T>
    T *get_subcomponent(const std::string& field) {
        auto lg = kis_shared_lock(mutex_, __func__);
        const auto& i = sub_component_map_.find(json_adapter_v2::consthash(field));

        if (i == sub_component_map_.end()) {
            return nullptr;
        }

        return dynamic_cast<T *>(i->second);
    }

protected:
    kis_shared_mutex mutex_;

    uint64_t internal_id_;
    device_key_v2 key_;
    struct mac_addr mac_addr_;

    std::string_view phyname_;
    int phyid_;

    std::string devicename_;
    std::string username_;
    std::string commonname_;

    std::string_view type_string_;
    uint64_t basic_type_set_;

    std::string crypt_string_;
    uint64_t basic_crypt_set_;

    uint64_t first_time_;
    uint64_t last_time_;
    uint64_t mod_time_;

    uint64_t packets_;
    uint64_t rx_packets_;
    uint64_t tx_packets_;
    uint64_t llc_packets_;
    uint64_t data_packets_;
    uint64_t error_packets_;
    uint64_t crypt_packets_;
    uint64_t filter_packets_;
    uint64_t duplicate_packets_;

    uint64_t datasize_;

    kis_rrd_v2<> packets_rrd_;
    kis_rrd_v2<> data_rrd_;
    kis_rrd_v2<> packets_rx_rrd_;
    kis_rrd_v2<> packets_tx_rrd_;

    std::string channel_;
    uint64_t frequency_khz_;

    kis_tracked_signal_data_v2 signal_;

    using freq_khz_distribution_iter_t_ = std::unordered_map<uint64_t, uint64_t>::iterator;
    std::unordered_map<uint64_t, uint64_t> freq_khz_distribution_;

    // manufs are cached elsewhere & referenced as a string view
    std::string_view manuf_;

    using tag_map_iter_t_ = std::map<std::string, std::string>::iterator;
    std::map<std::string, std::string> tag_map_;

    kis_tracked_location_full_v2 location_;
    kis_historic_location_v2 location_history_;

    // seenby map indexed by datasource id #
    using seenby_map_iter_t_ = std::unordered_map<unsigned int, kis_tracked_seenby_data_v2>::iterator;
    std::unordered_map<unsigned int, kis_tracked_seenby_data_v2> seenby_map_;

    // related devices are a map related key to devicekey map, for speedy lookups.
    // will be serialized as a vector.
    using related_devices_iter_t_ = std::unordered_map<std::string, std::unordered_map<device_key_v2, bool>>::iterator;
    using related_devices_sub_t_ = std::unordered_map<device_key_v2, bool>;
    std::unordered_map<std::string, std::unordered_map<device_key_v2, bool>> related_devices_;

    // number of alerts over time
    uint64_t num_alerts_;

    // expandable device subcomponents
    struct sub_component {
        std::string field_;
        json_adapter_v2::jsonable *sub_component_;
        subcomponent_encoder_fn_t encode_fn_;
    };

    std::unordered_map<ssize_t, sub_component> sub_component_map_;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_device_base_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_device_base_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_device_base_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_device_base_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_device_base_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

#endif /* __DEVICETRACKER_COMPONENT_V2__ */
