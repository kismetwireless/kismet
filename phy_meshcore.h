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

#ifndef __PHY_MESHCORE_H__
#define __PHY_MESHCORE_H__

#include "config.h"

#include <array>
#include <deque>
#include <optional>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "alertracker.h"
#include "datasourcetracker.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "json_adapter_v2.h"
#include "kis_mutex.h"
#include "phyhandler.h"
#include "trackedelement.h"

#include "base64.h"

// MeshCore is a LoRa mesh using sync word 0x12.  Nodes are identified by an Ed25519
// public key; adverts carry the full key, a signature, and the node name, type, and
// location in the clear.  Other packets carry only a 1 byte prefix of the key.
//
// Group channels are AES-128-ECB with a truncated HMAC-SHA256, keyed by a shared
// secret; the public channel and hashtag channels have well known secrets.  Direct
// messages use per-pair ECDH secrets and can't be decoded.
//
// Packet formats from the MeshCore firmware src/Packet.h, src/Mesh.cpp, and
// docs/payloads.md

namespace meshcore {
    // Header byte: version (2 bits), payload type (4 bits), route type (2 bits)
    enum class route_type : uint8_t {
        transport_flood = 0,
        flood = 1,
        direct = 2,
        transport_direct = 3,
    };

    enum class payload_type : uint8_t {
        req = 0x00,
        response = 0x01,
        txt_msg = 0x02,
        ack = 0x03,
        advert = 0x04,
        grp_txt = 0x05,
        grp_data = 0x06,
        anon_req = 0x07,
        path = 0x08,
        trace = 0x09,
        multipart = 0x0A,
        control = 0x0B,
        raw_custom = 0x0F,
    };

    enum class node_type : uint8_t {
        none = 0,
        chat = 1,
        repeater = 2,
        room = 3,
        sensor = 4,
    };

    inline constexpr uint8_t adv_type_mask = 0x0F;
    inline constexpr uint8_t adv_latlon_mask = 0x10;
    inline constexpr uint8_t adv_feat1_mask = 0x20;
    inline constexpr uint8_t adv_feat2_mask = 0x40;
    inline constexpr uint8_t adv_name_mask = 0x80;

    inline constexpr size_t pub_key_size = 32;
    inline constexpr size_t signature_size = 64;
    inline constexpr size_t max_advert_data = 32;
    inline constexpr size_t advert_min_size = pub_key_size + 4 + signature_size;
    inline constexpr size_t cipher_key_size = 16;
    inline constexpr size_t cipher_block_size = 16;
    inline constexpr size_t cipher_mac_size = 2;
    inline constexpr size_t max_path_size = 64;
    inline constexpr size_t max_payload_size = 184;

    // Control payloads; the upper nibble is the subtype
    inline constexpr uint8_t control_discover_resp = 0x90;

    // PUBLIC_GROUP_PSK, izOH6cXN6mrJ5e26oRXNcg==
    inline constexpr std::array<uint8_t, 16> public_psk{
        0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a,
        0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72
    };

    inline constexpr std::string_view public_channel_name = "Public";

    inline constexpr std::string_view node_key_type = "Ed25519";
    // 32 byte channel secrets only lengthen the HMAC key; the cipher is always AES-128
    inline constexpr std::string_view channel_key_type = "AES128";

    constexpr bool payload_known(uint8_t t) {
        return t <= static_cast<uint8_t>(payload_type::control) ||
            t == static_cast<uint8_t>(payload_type::raw_custom);
    }

    constexpr std::string_view payload_type_name(payload_type t) {
        switch (t) {
            case payload_type::req: return "request";
            case payload_type::response: return "response";
            case payload_type::txt_msg: return "text";
            case payload_type::ack: return "ack";
            case payload_type::advert: return "advert";
            case payload_type::grp_txt: return "group text";
            case payload_type::grp_data: return "group data";
            case payload_type::anon_req: return "anonymous request";
            case payload_type::path: return "path";
            case payload_type::trace: return "trace";
            case payload_type::multipart: return "multipart";
            case payload_type::control: return "control";
            case payload_type::raw_custom: return "raw";
        }

        return "unknown";
    }
}

class tracked_meshcore_node : public tracker_component {
public:
    tracked_meshcore_node() {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_meshcore_node(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_meshcore_node(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_meshcore_node");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(pubkey, std::string, std::string, std::string, pubkey_);
    __Proxy(key_type, std::string, std::string, std::string, key_type_);
    __Proxy(node_name, std::string, std::string, std::string, name_);
    __Proxy(node_type, uint8_t, uint8_t, uint8_t, node_type_);

    __Proxy(advert_ts, uint64_t, uint64_t, uint64_t, advert_ts_);
    __Proxy(adverts, uint64_t, uint64_t, uint64_t, adverts_);
    __ProxyIncDec(adverts, uint64_t, uint64_t, adverts_);
    __Proxy(advert_hops, uint8_t, uint8_t, uint8_t, advert_hops_);

    __Proxy(lat, double, double, double, lat_);
    __Proxy(lon, double, double, double, lon_);

    __Proxy(relayed, uint64_t, uint64_t, uint64_t, relayed_);
    __ProxyIncDec(relayed, uint64_t, uint64_t, relayed_);
    __Proxy(last_relayed, uint64_t, uint64_t, uint64_t, last_relayed_);

    __Proxy(bad_signatures, uint64_t, uint64_t, uint64_t, bad_signatures_);
    __ProxyIncDec(bad_signatures, uint64_t, uint64_t, bad_signatures_);

protected:
    virtual void register_fields() override {
        register_field("meshcore.node.pubkey", "Public key (base64)", &pubkey_);
        register_field("meshcore.node.key_type", "Public key type", &key_type_);
        register_field("meshcore.node.name", "Advertised name", &name_);
        register_field("meshcore.node.type", "Advertised node type (raw int)", &node_type_);
        register_field("meshcore.node.advert_ts", "Timestamp of last advert, from the node clock", &advert_ts_);
        register_field("meshcore.node.adverts", "Valid adverts seen", &adverts_);
        register_field("meshcore.node.advert_hops", "Hops taken by the last advert", &advert_hops_);
        register_field("meshcore.node.lat", "Advertised latitude", &lat_);
        register_field("meshcore.node.lon", "Advertised longitude", &lon_);
        register_field("meshcore.node.relayed", "Packets seen relayed by this node", &relayed_);
        register_field("meshcore.node.last_relayed", "Last time this node was seen relaying", &last_relayed_);
        register_field("meshcore.node.bad_signatures", "Adverts for this key with invalid signatures", &bad_signatures_);
    }

    std::shared_ptr<tracker_element_string> pubkey_;
    std::shared_ptr<tracker_element_string> key_type_;
    std::shared_ptr<tracker_element_string> name_;
    std::shared_ptr<tracker_element_uint8> node_type_;
    std::shared_ptr<tracker_element_uint64> advert_ts_;
    std::shared_ptr<tracker_element_uint64> adverts_;
    std::shared_ptr<tracker_element_uint8> advert_hops_;
    std::shared_ptr<tracker_element_double> lat_;
    std::shared_ptr<tracker_element_double> lon_;
    std::shared_ptr<tracker_element_uint64> relayed_;
    std::shared_ptr<tracker_element_uint64> last_relayed_;
    std::shared_ptr<tracker_element_uint64> bad_signatures_;

    friend class kis_meshcore_phy;
};

class meshcore_message : public json_adapter_v2::jsonable {
    friend class kis_meshcore_phy;
public:
    meshcore_message() : json_adapter_v2::jsonable() { }

    meshcore_message(uint64_t timestamp, const std::string_view& channel,
            const std::string_view& sender, const std::string_view& message) :
        json_adapter_v2::jsonable(),
        timestamp_{timestamp},
        channel_{channel.data(), channel.length()},
        sender_{sender.data(), sender.length()},
        message_{message.data(), message.length()} { }

    auto timestamp() const { return timestamp_; }
    auto channel() const { return channel_; }
    auto sender() const { return sender_; }
    auto message() const { return message_; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "meshcore.message.timestamp", opts, timestamp_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshcore.message.channel", opts, channel_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshcore.message.sender", opts, sender_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshcore.message.message", opts, message_);

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("meshcore.message.timestamp"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, timestamp_);
                    break;
                case json_adapter_v2::consthash("meshcore.message.channel"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel_);
                    break;
                case json_adapter_v2::consthash("meshcore.message.sender"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, sender_);
                    break;
                case json_adapter_v2::consthash("meshcore.message.message"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, message_);
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }

protected:
    // Sender clock, which may be wrong or unset
    uint64_t timestamp_;
    std::string channel_;
    // From the "name: message" text, and not authenticated
    std::string sender_;
    std::string message_;
};

template<> struct json_adapter_v2::json_encode<meshcore_message> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_message& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_message *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_message& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_message *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class meshcore_channel : public json_adapter_v2::jsonable {
    friend class kis_meshcore_phy;
public:
    // secret is the 16 or 32 byte channel key
    meshcore_channel(const std::string_view channel, const std::string_view secret,
            uint8_t hash, size_t max_messages) :
        json_adapter_v2::jsonable(),
        max_messages_{max_messages},
        channel_{channel.data(), channel.length()},
        key_{base64::encode(std::string{secret})},
        secret_{secret.data(), secret.length()},
        hash_{hash} {
        // The firmware keeps a 32 byte zero padded secret; AES uses the first 16 bytes and
        // HMAC all 32
        secret_.resize(meshcore::pub_key_size, '\0');
    }

    meshcore_channel(meshcore_channel&& m) :
        json_adapter_v2::jsonable(),
        max_messages_{m.max_messages_},
        channel_{std::move(m.channel_)},
        key_{std::move(m.key_)},
        secret_{std::move(m.secret_)},
        hash_{m.hash_},
        messages_{std::move(m.messages_)} { }

    const auto& channel() const { return channel_; }
    const auto& key() const { return key_; }
    const auto& secret() const { return secret_; }
    auto hash() const { return hash_; }

    // Keeps the newest messages
    void add_message(uint64_t timestamp, const std::string_view& sender, const std::string_view& message) {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);

        if (max_messages_ == 0)
            return;

        while (messages_.size() >= max_messages_)
            messages_.pop_front();

        messages_.emplace_back(timestamp, channel_, sender, message);
    }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
        kis_unique_lock<kis_mutex> lk(mutex_, __func__);

        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshcore.channel.channel", opts, channel_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "meshcore.channel.key", opts, key_);
        json_adapter_v2::json_encode_keyed<std::string_view>{}(os, "meshcore.channel.key_type", opts, meshcore::channel_key_type);
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "meshcore.channel.hash", opts, hash_);
        json_adapter_v2::json_encode_keyed_array<messages_iter_t>{}(os, "meshcore.channel.messages", opts, messages_.begin(), messages_.end());

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
                case json_adapter_v2::consthash("meshcore.channel.channel"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel_);
                    break;
                case json_adapter_v2::consthash("meshcore.channel.key"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, key_);
                    break;
                case json_adapter_v2::consthash("meshcore.channel.key_type"):
                    json_adapter_v2::json_encode_keyed<std::string_view>{}(os, f.second.rename, opts, meshcore::channel_key_type);
                    break;
                case json_adapter_v2::consthash("meshcore.channel.hash"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, hash_);
                    break;
                case json_adapter_v2::consthash("meshcore.channel.messages"):
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
    std::string secret_;
    uint8_t hash_;

    using messages_iter_t = std::deque<meshcore_message>::iterator;
    std::deque<meshcore_message> messages_;
};

template<> struct json_adapter_v2::json_encode<meshcore_channel> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_channel& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_channel *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_channel& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, meshcore_channel *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class kis_meshcore_phy : public kis_phy_handler {
public:
    virtual ~kis_meshcore_phy();

    kis_meshcore_phy() : kis_phy_handler() { }

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_meshcore_phy(in_phyid);
    }

    kis_meshcore_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

    // Parsed outer packet; views point into the packet data
    struct frame {
        meshcore::route_type route;
        meshcore::payload_type type;
        uint8_t path_hash_size;
        uint8_t path_count;
        std::string_view path;
        std::string_view payload;
    };

    // Validates the header, path, and payload length for the type
    static std::optional<frame> parse_frame(std::string_view data);

    static mac_addr pubkey_to_mac(std::string_view pubkey) {
        uint8_t m[6];
        m[0] = 0x06;
        memcpy(m + 1, pubkey.data(), 5);
        return mac_addr(m, 6);
    }

protected:
    kis_mutex mutex_;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<alert_tracker> alertracker;

    int pack_comp_linkframe, pack_comp_decap;

    int dlt_meshcore;

    uint16_t meshcore_node_id;

    int alert_badsig_ref;

    std::shared_ptr<tracker_element_string> generic_manuf;

    // Public keys from validly signed adverts, for resolving the key prefixes used
    // everywhere else; capped so a flood of generated keys can't grow it forever
    static constexpr size_t max_known_keys = 65536;
    std::set<std::string> known_keys;

    void learn_key(const std::string& pubkey);
    bool key_known(const std::string& pubkey);
    // The full key when exactly one known key has this prefix
    std::optional<std::string> resolve_prefix(std::string_view prefix);

    // Recent packet hashes, so flood repeats of a group message are logged once
    static constexpr size_t max_recent_hashes = 512;
    std::deque<std::string> recent_hash_order;
    std::unordered_set<std::string> recent_hashes;

    bool seen_recently(const frame& f);

    using channels_map_t = std::unordered_map<std::string, meshcore_channel>;
    channels_map_t channels;
    size_t max_live_messages;

    void add_channel(const std::string& name, const std::string& secret);

    std::shared_ptr<kis_tracked_device_base> update_node(const std::string& pubkey,
            const std::shared_ptr<kis_packet>& in_pack, int flags, bool& new_device);

    void handle_group(const frame& f, const std::shared_ptr<kis_packet>& in_pack);
};

#endif
