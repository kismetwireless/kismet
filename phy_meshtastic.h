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

#ifndef __PHY_MESHTASTIC_H__
#define __PHY_MESHTASTIC_H__

#include "config.h"

#include <array>
#include <optional>
#include <string_view>
#include <unordered_map>

#include "datasourcetracker.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "json_adapter_v2.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "phyhandler.h"
#include "trackedelement.h"

#include "aes_ctr.h"
#include "base64.h"
#include "protobuf_decode.h"


// meshtastic messages are an aes-ctr-128 or aes-ctr-256 encrypted protobuf
//
// we decode the protobuf piecemeal from the wire, we don't want to touch
// packaging protobufs back into kismet
//
// because this is being written at a difficult transition time in kismet
// trying to push towards the new more efficient json formatter, the device
// records will be in traditional tracked json but the new channel and message
// endpoints will use the new json api

// Channel key handling per the meshtastic firmware Channels::getKey() and
// Channels::generateHash()
namespace meshtastic_crypto {
    inline constexpr std::array<uint8_t, 16> default_psk{
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
    };

    inline constexpr size_t max_channel_name_len = 11;

    // Unnamed channels use the modem preset display name
    inline constexpr std::array<std::string_view, 10> preset_channel_names{
        "LongFast", "LongSlow", "LongMod", "LongTurbo",
        "MediumFast", "MediumSlow", "MediumTurbo",
        "ShortFast", "ShortSlow", "ShortTurbo",
    };

    enum class psk_type : uint8_t {
        none,
        aes128,
        aes256,
    };

    struct psk {
        psk_type type;
        std::string key;
    };

    // Empty or index 0 disables encryption, a 1 byte index selects a variant of the
    // default key, and short keys are zero padded to aes128 or aes256
    inline std::optional<psk> expand_psk(std::string_view raw) {
        if (raw.size() == 0)
            return psk{psk_type::none, ""};

        if (raw.size() == 1) {
            const auto index = static_cast<uint8_t>(raw[0]);

            if (index == 0)
                return psk{psk_type::none, ""};

            std::string k(reinterpret_cast<const char *>(default_psk.data()), default_psk.size());
            k.back() = static_cast<char>(static_cast<uint8_t>(k.back() + index - 1));
            return psk{psk_type::aes128, std::move(k)};
        }

        if (raw.size() <= 16) {
            std::string k{raw};
            k.resize(16, '\0');
            return psk{psk_type::aes128, std::move(k)};
        }

        if (raw.size() <= 32) {
            std::string k{raw};
            k.resize(32, '\0');
            return psk{psk_type::aes256, std::move(k)};
        }

        return std::nullopt;
    }

    constexpr uint8_t xor_hash(std::string_view s) {
        uint8_t h = 0;
        for (const auto c : s)
            h ^= static_cast<uint8_t>(c);
        return h;
    }

    constexpr uint8_t xor_hash(const std::array<uint8_t, 16>& a) {
        uint8_t h = 0;
        for (const auto c : a)
            h ^= c;
        return h;
    }

    constexpr uint8_t channel_hash(std::string_view name, std::string_view key) {
        return xor_hash(name) ^ xor_hash(key);
    }

    static_assert((xor_hash("LongFast") ^ xor_hash(default_psk)) == 0x08,
            "default LongFast channel hash must be 0x08");
}


class tracked_meshtastic_node : public tracker_component {
public:
    tracked_meshtastic_node() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_meshtastic_node(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_meshtastic_node(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_meshtastic_node");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(nodeid, std::string, std::string, std::string, nodeid_);

    __Proxy(role, uint32_t, uint32_t, uint32_t, role_);

    __Proxy(longname, std::string, std::string, std::string, longname_);
    __Proxy(shortname, std::string, std::string, std::string, shortname_);

    __Proxy(manuf_id, uint32_t, uint32_t, uint32_t, manuf_id_);

    __Proxy(licensed, uint8_t, bool, bool, licensed_);

    __Proxy(telem_ts, uint64_t, uint64_t, uint64_t, telem_ts_);
    __Proxy(telem_battery_perc, uint8_t, uint8_t, uint8_t, telem_battery_perc_);
    __Proxy(telem_battery_voltage, float, float, float, telem_battery_voltage_);
    __Proxy(telem_channel_util, float, float, float, telem_chan_util_);
    __Proxy(telem_channel_tx_util, float, float, float, telem_chan_tx_util_);

    __Proxy(telem_uptime_sec, uint64_t, uint64_t, uint64_t, telem_uptime_sec_);


protected:
    virtual void register_fields() override {

        register_field("meshtastic.node.nodeid", "Node id", &nodeid_);
        register_field("meshtastic.node.longname", "Node long name", &longname_);
        register_field("meshtastic.node.shortname", "Node short name", &shortname_);

        register_field("meshtastic.node.role", "Meshtastic role (raw int)", &role_);

        register_field("meshtastic.node.manuf", "Manufacturer (raw int id)", &manuf_id_);

        register_field("meshtastic.node.licensed", "Licensed operator", &licensed_);

        register_field("meshtastic.node.telem.timestamp", "Epoch timestamp", &telem_ts_);
        register_field("meshtastic.node.telem.battery", "Battery percentage", &telem_battery_perc_);
        register_field("meshtastic.node.telem.voltage", "Battery voltage", &telem_battery_voltage_);
        register_field("meshtastic.node.telem.chan_util", "Channel utilization", &telem_chan_util_);
        register_field("meshtastic.node.telem.chan_tx_util", "Channel tx utilization", &telem_chan_tx_util_);
        register_field("meshtastic.node.telem.uptime", "Uptime (seconds)", &telem_uptime_sec_);
    }

    std::shared_ptr<tracker_element_string> nodeid_;

    std::shared_ptr<tracker_element_uint32> role_;

    std::shared_ptr<tracker_element_string> longname_;
    std::shared_ptr<tracker_element_string> shortname_;

    std::shared_ptr<tracker_element_uint32> manuf_id_;

    std::shared_ptr<tracker_element_uint8> licensed_;

    std::shared_ptr<tracker_element_uint64> telem_ts_;
    std::shared_ptr<tracker_element_uint16> telem_battery_perc_;
    std::shared_ptr<tracker_element_float> telem_battery_voltage_;
    std::shared_ptr<tracker_element_float> telem_chan_util_;
    std::shared_ptr<tracker_element_float> telem_chan_tx_util_;
    std::shared_ptr<tracker_element_uint64> telem_uptime_sec_;

    friend class kis_meshtastic_phy;
};

class meshtastic_message : public json_adapter_v2::jsonable {
    friend class kis_meshtastic_phy;
public:
    meshtastic_message() : json_adapter_v2::jsonable() { }

    meshtastic_message(const std::string_view& nodeid, const std::string_view& channel,
            const std::string_view& message) :
        json_adapter_v2::jsonable(),
        nodeid_{nodeid.data(), nodeid.length()},
        channel_{channel.data(), channel.length()},
        message_{message.data(), message.length()} { }

    meshtastic_message& operator=(const meshtastic_message& t) {
        nodeid_ = t.nodeid_;
        channel_ = t.channel_;
        message_ = t.message_;
        return *this;
    }

    auto nodeid() const { return nodeid_; }
    void set_nodeid(auto v) { nodeid_ = v; }

    auto channel() const { return channel_; }
    void set_channel(auto v) { channel_ = v; }

    auto message() const { return message_; }
    void set_message(auto v) { message_ = v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {

        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshtastic.message.nodeid", opts, nodeid());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshtastic.message.channel", opts, channel());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshtastic.message.message", opts, message());

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("meshtastic.message.nodeid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, nodeid());
                    break;
                case json_adapter_v2::consthash("meshtastic.message.channel"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel());
                    break;
                case json_adapter_v2::consthash("meshtastic.message.message"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, message());
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;

    }

protected:
    // TBD - cache nodeid and channel?  It would be more ram-efficient but
    // meshtastic is so low load it probably doesn't matter
    std::string nodeid_;
    std::string channel_;
    std::string message_;
};

template<> struct json_adapter_v2::json_encode<meshtastic_message> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_message& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_message *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_message& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_message *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class meshtastic_channel : public json_adapter_v2::jsonable {
    friend class kis_meshtastic_phy;
public:
    meshtastic_channel(const std::string_view channel, const meshtastic_crypto::psk& psk,
            size_t max_messages) :
        json_adapter_v2::jsonable(),
        max_messages_{max_messages},
        channel_{channel.data(), channel.length()},
        key_{base64::encode(psk.key)},
        psk_{psk},
        hash_{meshtastic_crypto::channel_hash(channel, psk.key)} { }

    meshtastic_channel(meshtastic_channel&& m) :
        json_adapter_v2::jsonable(),
        max_messages_{m.max_messages_},
        channel_{std::move(m.channel_)},
        key_{std::move(m.key_)},
        psk_{std::move(m.psk_)},
        hash_{m.hash_},
        messages_{std::move(m.messages_)} { }

    meshtastic_channel& operator=(const meshtastic_channel& t) {
        max_messages_ = t.max_messages_;
        channel_ = t.channel_;
        key_ = t.key_;
        psk_ = t.psk_;
        hash_ = t.hash_;
        messages_ = t.messages_;

        return *this;
    }

    auto channel() const { return channel_; }
    auto key() const { return key_; }
    const auto& psk() const { return psk_; }
    auto hash() const { return hash_; }

    auto max_messages() {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);
        return max_messages_;
    }

    void set_max_messages(size_t sz) {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);
        max_messages_ = sz;
        if (messages_.size() > sz) {
            messages_.erase(messages_.begin() + sz, messages_.end());
        }
    }

    void add_message(const std::string_view& nodeid, const std::string_view& message) {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);
        messages_.emplace_back(nodeid, channel(), message);
        if (messages_.size() > max_messages()) {
            messages_.erase(messages_.begin() + max_messages(), messages_.end());
        }
    }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);

        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshtastic.channel.channel", opts, channel());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshtastic.channel.key", opts, key());
        json_adapter_v2::json_encode_keyed_array<messages_iter_t>{}(os, "meshtastic.channel.messages", opts, messages_.begin(), messages_.end());

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);

        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("meshtastic.channel.channel"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel());
                    break;
                case json_adapter_v2::consthash("meshtastic.channel.key"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, key());
                    break;
                case json_adapter_v2::consthash("meshtastic.channel.messages"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed_array<messages_iter_t>{}(os, f.second.rename, opts, messages_.begin(), messages_.end(), subgroup);
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }

protected:
    kis_mutex mutex_;

    size_t max_messages_;

    std::string channel_;
    std::string key_;
    meshtastic_crypto::psk psk_;
    uint8_t hash_;

    using messages_iter_t = std::vector<meshtastic_message>::iterator;
    std::vector<meshtastic_message> messages_;
};

template<> struct json_adapter_v2::json_encode<meshtastic_channel> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_channel& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_channel *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_channel& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshtastic_channel *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class kis_meshtastic_phy : public kis_phy_handler {
public:
    virtual ~kis_meshtastic_phy();

    kis_meshtastic_phy() : kis_phy_handler() { }

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_meshtastic_phy(in_phyid);
    }

    kis_meshtastic_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    kis_mutex mutex_;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int pack_comp_linkframe, pack_comp_decap;

    int dlt_meshtastic;

    uint16_t mesh_node_id;

    const static mac_addr mesh_to_mac(uint32_t meshid) {
        struct {
            uint8_t prefix_[2];
            uint32_t meshid_;
        } __attribute__((packed)) macbytes;

        macbytes.prefix_[0] = 0x2;
        macbytes.prefix_[1] = 0;
        macbytes.meshid_ = meshid;

        return mac_addr((uint8_t *) &macbytes, 6);
    }

    void handle_telemetry_pb(const std::string_view& pbuf,
            const std::shared_ptr<kis_packet>& packet,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node);
    void handle_devicemetrics_pb(const std::string_view& pbuf,
            const std::shared_ptr<kis_packet>& packet,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node);
    void handle_position_pb(const std::string_view& pbuf,
            const std::shared_ptr<kis_packet>& packet,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node);
    void handle_user_pb(const std::string_view& pbuf,
            const std::shared_ptr<kis_packet>& packet,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node);
    void handle_nodeinfo_pb(const std::string_view& pbuf,
            const std::shared_ptr<kis_packet>& packet,
            std::shared_ptr<kis_tracked_device_base> base,
            std::shared_ptr<tracked_meshtastic_node> node);

    // tracked channels
    using channels_map_t = std::unordered_map<std::string, meshtastic_channel>;
    channels_map_t channels;
    size_t max_live_messages;

    std::shared_ptr<tracker_element_string> generic_manuf;

    // obnoxious huge list of model names
    std::shared_ptr<tracker_element_string> model_tlora_v2;
    std::shared_ptr<tracker_element_string> model_tlora_v1;
    std::shared_ptr<tracker_element_string> model_tlora_v2_1_1p6;
    std::shared_ptr<tracker_element_string> model_tbeam;
    std::shared_ptr<tracker_element_string> model_heltec_v2_0;
    std::shared_ptr<tracker_element_string> model_tbeam_v0p7;
    std::shared_ptr<tracker_element_string> model_t_echo;
    std::shared_ptr<tracker_element_string> model_tlora_v1_1p3;
    std::shared_ptr<tracker_element_string> model_rak4631;
    std::shared_ptr<tracker_element_string> model_heltec_v2_1;
    std::shared_ptr<tracker_element_string> model_heltec_v1;
    std::shared_ptr<tracker_element_string> model_lilygo_tbeam_s3_core;
    std::shared_ptr<tracker_element_string> model_rak11200;
    std::shared_ptr<tracker_element_string> model_nano_g1;
    std::shared_ptr<tracker_element_string> model_tlora_v2_1_1p8;
    std::shared_ptr<tracker_element_string> model_tlora_t3_s3;
    std::shared_ptr<tracker_element_string> model_nano_g1_explorer;
    std::shared_ptr<tracker_element_string> model_nano_g2_ultra;
    std::shared_ptr<tracker_element_string> model_lora_type;
    std::shared_ptr<tracker_element_string> model_station_g1;
    std::shared_ptr<tracker_element_string> model_rak11310;
    std::shared_ptr<tracker_element_string> model_senselora_s3;
    std::shared_ptr<tracker_element_string> model_canaryone;
    std::shared_ptr<tracker_element_string> model_rp2040_lora;
    std::shared_ptr<tracker_element_string> model_station_g2;
    std::shared_ptr<tracker_element_string> model_lora_relay_v1;
    std::shared_ptr<tracker_element_string> model_nrf52840dk;
    std::shared_ptr<tracker_element_string> model_ppr;
    std::shared_ptr<tracker_element_string> model_genieblocks;
    std::shared_ptr<tracker_element_string> model_nrf52_unknown;
    std::shared_ptr<tracker_element_string> model_portuino;
    std::shared_ptr<tracker_element_string> model_android_sim;
    std::shared_ptr<tracker_element_string> model_diy_v1;
    std::shared_ptr<tracker_element_string> model_nrf52840_pca10059;
    std::shared_ptr<tracker_element_string> model_dr_dev;
    std::shared_ptr<tracker_element_string> model_m5stack;
    std::shared_ptr<tracker_element_string> model_heltec_v3;
    std::shared_ptr<tracker_element_string> model_heltec_wsl_v3;
    std::shared_ptr<tracker_element_string> model_betafpv_2400_tx;
    std::shared_ptr<tracker_element_string> model_betafpv_900_nano_tx;
    std::shared_ptr<tracker_element_string> model_rpi_pico;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_tracker;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_paper;
    std::shared_ptr<tracker_element_string> model_t_deck;
    std::shared_ptr<tracker_element_string> model_t_watch_s3;
    std::shared_ptr<tracker_element_string> model_picomputer_s3;
    std::shared_ptr<tracker_element_string> model_heltec_ht62;
    std::shared_ptr<tracker_element_string> model_ebyte_esp32_s3;
    std::shared_ptr<tracker_element_string> model_esp32_s3_pico;
    std::shared_ptr<tracker_element_string> model_chatter2;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_paper_v1_0;
    std::shared_ptr<tracker_element_string> model_heltec_wireless_tracker_v1_0;
    std::shared_ptr<tracker_element_string> model_private_hw;

    std::shared_ptr<tracker_element_string> model_id_to_string(int hw);

public:
    const mac_addr mesh_broadcast{mesh_to_mac(0xFFFFFFFF)};

    // default meshtastic key
    typedef struct {
        uint32_t dest_id;
        uint32_t source_id;
        uint32_t pkt_id;
        uint8_t flag;
        uint8_t channel;
        uint8_t nh;
        uint8_t relay_node;
    } __attribute__((packed)) meshtastic_frame_t;

    static_assert(sizeof(meshtastic_frame_t) == 16, "meshtastic header must be 16 bytes");

    enum class meshtastic_portnum {
        unknown = 0,
        text_message = 1,
        remote_hardware = 2,
        position = 3,
        nodeinfo = 4,
        routing = 5,
        admin = 6,
        text_message_compressed = 7,
        waypoint = 8,
        audio = 9,
        detection_sensor = 10,
        reply = 32,
        ip_tunnel = 33,
        paxcounter = 34,
        serial = 64,
        store_forward = 65,
        range_test = 66,
        telemetry = 67,
        zps = 68,
        simulator = 69,
        traceroute = 70,
        neighborinfo = 71,
        atak = 72,
        map_report = 73,
        private_app = 256,
        atak_forwarder = 257,
        max = 511,
    };

    enum class meshtastic_data_pb {
        fn_unknown = 0,

        fn_portnum = 1, // int, meshtastic_portnum enum
        fn_payload = 2, // bytes
        fn_want_response = 3, // int(bool)
        fn_dest = 4, // int32
        fn_source = 5, // int32
        fn_request_id = 6, // int32
        fn_reply_id = 7, // int32
        fn_emoji = 8, // int32
    };

    enum class meshtastic_hw_model {
        unset = 0,
        tlora_v2 = 1,
        tlora_v1 = 2,
        tlora_v2_1_1p6 = 3,
        tbeam = 4,
        heltec_v2_0 = 5,
        tbeam_v0p7 = 6,
        t_echo = 7,
        tlora_v1_1p3 = 8,
        rak4631 = 9,
        heltec_v2_1 = 10,
        heltec_v1 = 11,
        lilygo_tbeam_s3_core = 12,
        rak11200 = 13,
        nano_g1 = 14,
        tlora_v2_1_1p8 = 15,
        tlora_t3_s3 = 16,
        nano_g1_explorer = 17,
        nano_g2_ultra = 18,
        lora_type = 19,
        station_g1 = 25,
        rak11310 = 26,
        senselora_s3 = 28,
        canaryone = 29,
        rp2040_lora = 30,
        station_g2 = 31,
        lora_relay_v1 = 32,
        nrf52840dk = 33,
        ppr = 34,
        genieblocks = 35,
        nrf52_unknown = 36,
        portuino = 37,
        android_sim = 38,
        diy_v1 = 39,
        nrf52840_pca10059 = 40,
        dr_dev = 41,
        m5stack = 42,
        heltec_v3 = 43,
        heltec_wsl_v3 = 44,
        betafpv_2400_tx = 45,
        betafpv_900_nano_tx = 46,
        rpi_pico = 47,
        heltec_wireless_tracker = 48,
        heltec_wireless_paper = 49,
        t_deck = 50,
        t_watch_s3 = 51,
        picomputer_s3 = 52,
        heltec_ht62 = 53,
        ebyte_esp32_s3 = 54,
        esp32_s3_pico = 55,
        chatter2 = 56,
        heltec_wireless_paper_v1_0 = 57,
        heltec_wireless_tracker_v1_0 = 58,
        private_hw = 255,
    };

    enum class meshtastic_user_pb {
        fn_unknown = 0,

        fn_id = 1, // string
        fn_long_name = 2, // string
        fn_short_name = 3, // string
        fn_macaddr = 4, // bytes, deprecated
        fn_hw_model = 5, // int, hw_model enum
        fn_is_licensed = 6, // int(bool)
        fn_role = 7, // enum deviceconfig
    };

    enum class meshtastic_loc_source {
        unset = 0,
        manual = 1,
        internal = 2,
        external = 3,
    };

    enum class meshtastic_alt_source {
        unset = 0,
        manual = 1,
        internal = 2,
        external = 3,
        barometric = 4,
    };

    enum class meshtastic_position_pb {
        fn_unknown = 0,

        fn_latitude_i = 1, // fixed32, multiply by 1e-7
        fn_longitude_i = 2, // fixed32, multiply by 1e-7
        fn_altitude = 3, // int32, meters
        fn_time = 4, // fixed32
        fn_location_source = 5, // int, enum meshtastic_alt_source
        fn_altitude_source = 6, // int, enum meshtastic_alt_source
        fn_timestamp = 7, // fixed32, epoch seconds
        fn_timestamp_millis_adjust = 8, // int32
        fn_altitude_hae = 9, // int32, meters
        fn_altitude_geoidal_separation = 10, // sint32
        fn_pdop = 11, // uint32 1/100 units pdop=sqrt(hdop^2 + vdop^2)
        fn_hdop = 12, // uint32
        fn_vdop = 13, // uint32
        fn_gps_accuracy = 14, // uint32 accuracy in mm
        fn_ground_speed = 15, // uint32 m/s
        fn_ground_track = 16, // uint32 north track in 1/100 degrees
        fn_fix_quality = 17, // uint32 gps fix quality
        fn_fix_type = 18, // uint32 gps 2d/3d gxgsa
        fn_sats_in_view = 19, // uint32
        fn_sensor_id = 20, // uint32
        fn_next_update = 21, // uint32 time in seconds to update
        fn_seq_number = 22, // uint32
        fn_precision_bits = 23, // uint32
    };

    enum class meshtastic_nodeinfo_pb {
        fn_unknown = 0,

        fn_num = 1, // uint32
        fn_user = 2, // bytes meshtastic_user_pb,
        fn_position = 3, // bytes meshtastic_position_pb,
        fn_snr = 4, // float
        fn_last_heard = 5, // fixed32
        fn_device_metrics = 6, // bytes devicemetrics
        fn_channels = 7, // uint32
        fn_via_mqtt = 8, // uint32 (bool)
        fn_via_hops_away = 9, // uint32
    };

    enum class meshtastic_devicemetrics_pb {
        fn_unknown = 0,

        fn_battery_level = 1, // uint32
        fn_voltage = 2, // float
        fn_channel_utilization = 3, // float
        fn_air_util_tx = 4, // float
        fn_uptime_seconds = 5, // uint32
    };

    enum class meshtastic_environmentmetrics_pb {
        fn_unknown = 0,

        fn_temperature = 1, // float
        fn_relative_humidity = 2, // float
        fn_barometric_pressure = 3, // float, hPA
        fn_gas_resistance = 4, // float, mOhm
        fn_voltage = 5, // float, deprecated
        fn_current = 6, // float, deprecated
    };

    enum class meshtastic_powermetrics_pb {
        fn_unknown = 0,

        fn_ch1_voltage = 1, // float
        fn_ch1_current = 2, // float
        fn_ch2_voltage = 3, // float
        fn_ch2_current = 4, // float
        fn_ch3_voltage = 5, // float
        fn_ch3_current = 6, // float
    };

    enum class meshtastic_airqualitymetrics_pb {
        fn_unknown = 0,

        fn_pm10_standard = 1, // uint32
        fn_pm25_standard = 2, // uint32
        fn_pm100_standard = 3, // uint32
        fn_pm10_environmental = 4, // uint32
        fn_pm25_environmental = 5, // uint32
        fn_pm100_environmental = 6, // uint32
        fn_particles_u3um = 7, // uint32
        fn_particles_u5um = 8, // uint32
        fn_particles_10um = 9, // uint32
        fn_particles_25um = 10, // uint32
        fn_particles_50um = 11, // uint32
        fn_particles_100um = 12, // uint32
    };

    enum class meshtastic_telemetry_pb {
        fn_unknown = 0,

        fn_time = 1, // fixed32
        fn_device_metrics = 2, // bytes, meshtastic_devicemetrics_pb
        fn_environment_metrics = 3, // bytes, meshtastic_environmentmetrics_pb
        fn_airquality_metrics = 4, // bytes, meshtastic_airqualitymetrics_pb
        fn_power_metrics = 5, // bytes, meshtastic_powermetrics_pb
    };

};

#endif /* __PHY_MESHTASTIC_H__ */
