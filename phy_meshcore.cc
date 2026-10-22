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

#include "phy_meshcore.h"

#include <memory>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "configfile.h"
#include "dlttracker.h"
#include "endian_magic.h"
#include "kis_httpd_registry.h"
#include "kis_net_beast_httpd.h"
#include "manuf.h"

namespace {
    std::string_view sv_trim(std::string_view s) {
        const auto ws = " \t\r\n";
        const auto b = s.find_first_not_of(ws);

        if (b == std::string_view::npos)
            return {};

        return s.substr(b, s.find_last_not_of(ws) - b + 1);
    }

    // Accept standard or url-safe base64, with or without padding; the decoder stops
    // silently at unknown characters so reject them here
    std::optional<std::string> normalize_b64(std::string_view in) {
        std::string out;
        out.reserve(in.size());

        bool padding = false;

        for (const auto c : in) {
            if (c == '=') {
                padding = true;
                continue;
            }

            if (padding)
                return std::nullopt;

            if (c == '-')
                out += '+';
            else if (c == '_')
                out += '/';
            else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/')
                out += c;
            else
                return std::nullopt;
        }

        return out;
    }

    std::string to_hex(std::string_view s) {
        std::string r;
        r.reserve(s.size() * 2);

        for (const auto c : s)
            r += fmt::format("{:02x}", static_cast<uint8_t>(c));

        return r;
    }

    uint32_t le32(const char *p) {
        uint32_t v;
        memcpy(&v, p, sizeof(v));
        return kis_letoh32(v);
    }

    std::string sha256(std::string_view data) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        if (EVP_Digest(data.data(), data.size(), md, &md_len, EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("sha256 failed");

        return std::string(reinterpret_cast<const char *>(md), md_len);
    }

    // Encrypt-then-MAC tag: HMAC-SHA256 of the ciphertext with the 32 byte secret,
    // truncated (Utils::encryptThenMAC)
    bool mac_matches(const std::string& secret, std::string_view mac, std::string_view ciphertext) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;

        if (HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
                    reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size(),
                    md, &md_len) == nullptr || md_len < mac.size())
            return false;

        return CRYPTO_memcmp(md, mac.data(), mac.size()) == 0;
    }

    // AES-128-ECB with the first 16 bytes of the secret; the plaintext is zero padded
    std::optional<std::string> aes128_ecb_decrypt(const std::string& secret, std::string_view ciphertext) {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
            ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (ctx == nullptr || ciphertext.size() % meshcore::cipher_block_size != 0)
            return std::nullopt;

        std::string out(ciphertext.size() + meshcore::cipher_block_size, '\0');
        int len = 0, final_len = 0;

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr,
                    reinterpret_cast<const unsigned char *>(secret.data()), nullptr) != 1 ||
                EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1 ||
                EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &len,
                    reinterpret_cast<const unsigned char *>(ciphertext.data()),
                    static_cast<int>(ciphertext.size())) != 1 ||
                EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()) + len,
                    &final_len) != 1)
            return std::nullopt;

        out.resize(len + final_len);
        return out;
    }

    bool ed25519_verify(std::string_view pubkey, std::string_view msg, std::string_view sig) {
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
            pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                        reinterpret_cast<const unsigned char *>(pubkey.data()), pubkey.size()),
                    EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
            ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

        if (pkey == nullptr || ctx == nullptr)
            return false;

        if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
            return false;

        return EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char *>(sig.data()),
                sig.size(), reinterpret_cast<const unsigned char *>(msg.data()), msg.size()) == 1;
    }

    struct advert_info {
        std::string pubkey;
        uint32_t timestamp;
        meshcore::node_type type;
        bool has_location;
        double lat, lon;
        std::string name;
    };

    // Application data: flags, optional location, optional feature words, optional name
    // (AdvertDataParser)
    advert_info parse_advert_appdata(std::string_view app) {
        advert_info a{};

        if (app.empty())
            return a;

        const auto flags = static_cast<uint8_t>(app[0]);
        size_t i = 1;

        a.type = static_cast<meshcore::node_type>(flags & meshcore::adv_type_mask);

        if (flags & meshcore::adv_latlon_mask) {
            if (app.size() < i + 8)
                return a;

            const auto lat = static_cast<int32_t>(le32(app.data() + i));
            const auto lon = static_cast<int32_t>(le32(app.data() + i + 4));
            i += 8;

            if (lat != 0 || lon != 0) {
                a.has_location = true;
                a.lat = lat / 1000000.0;
                a.lon = lon / 1000000.0;
            }
        }

        if (flags & meshcore::adv_feat1_mask)
            i += 2;

        if (flags & meshcore::adv_feat2_mask)
            i += 2;

        if ((flags & meshcore::adv_name_mask) && app.size() > i) {
            auto name = app.substr(i);
            a.name = std::string{name.substr(0, name.find('\0'))};
        }

        return a;
    }

    std::shared_ptr<tracker_element_string> node_type_string(const std::shared_ptr<device_tracker>& dt,
            meshcore::node_type t) {
        switch (t) {
            case meshcore::node_type::chat:
                return dt->get_cached_devicetype("MeshCore Companion");
            case meshcore::node_type::repeater:
                return dt->get_cached_devicetype("MeshCore Repeater");
            case meshcore::node_type::room:
                return dt->get_cached_devicetype("MeshCore Room Server");
            case meshcore::node_type::sensor:
                return dt->get_cached_devicetype("MeshCore Sensor");
            default:
                return dt->get_cached_devicetype("MeshCore");
        }
    }
}

kis_meshcore_phy::kis_meshcore_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    mutex_.set_name("kis_meshcore_phy");

    set_phy_name("MeshCore");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    datasourcetracker =
        Globalreg::fetch_mandatory_global_as<datasource_tracker>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_decap = packetchain->register_packet_component("DECAP");

    auto dltt =
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");

    dlt_meshcore = dltt->register_linktype("MESHCORE");

    generic_manuf = Globalreg::globalreg->manufdb->make_manuf("Lora / MeshCore");

    meshcore_node_id =
        Globalreg::globalreg->entrytracker->register_field("meshcore.node",
                tracker_element_factory<tracked_meshcore_node>(),
                "MeshCore node");

    alert_badsig_ref =
        alertracker->activate_configured_alert("MESHCOREBADSIG",
                "SPOOF", kis_alert_severity::medium,
                "MeshCore adverts are signed by the key they announce.  An advert with an "
                "invalid signature may be an attempt to impersonate a node, or a corrupted "
                "packet.", phyid);

    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_meshcore", "js/kismet.ui.meshcore.js");

    max_live_messages = Globalreg::globalreg->kismet_config->fetch_opt_ulong("meshcore_num_messages", 128);

    add_channel(std::string{meshcore::public_channel_name},
            std::string(reinterpret_cast<const char *>(meshcore::public_psk.data()),
                meshcore::public_psk.size()));

    for (const auto& k : Globalreg::globalreg->kismet_config->fetch_opt_vec("meshcore_key")) {
        auto toks = base_sv_tokenize(k, ",", "");
        if (toks.size() != 2) {
            _MSG_ERROR("Invalid meshcore_key '{}', expected channelname,base64key", k);
            continue;
        }

        auto name = sv_trim(toks[0]);
        if (name.length() == 0) {
            _MSG_ERROR("Invalid meshcore_key '{}', missing channel name", k);
            continue;
        }

        auto b64 = normalize_b64(sv_trim(toks[1]));
        if (!b64) {
            _MSG_ERROR("Invalid meshcore_key for channel '{}', key is not valid base64", name);
            continue;
        }

        auto secret = base64::decode(*b64);
        if (secret.size() != 16 && secret.size() != 32) {
            _MSG_ERROR("Invalid meshcore_key for channel '{}', keys must be 16 or 32 bytes", name);
            continue;
        }

        add_channel(std::string{name}, secret);
    }

    // Hashtag channels use the first 16 bytes of the sha256 of the name, including the #
    for (const auto& h : Globalreg::globalreg->kismet_config->fetch_opt_vec("meshcore_hashtag")) {
        auto name = std::string{sv_trim(h)};

        if (name.length() == 0 || name == "#") {
            _MSG_ERROR("Invalid meshcore_hashtag '{}', expected a channel name", h);
            continue;
        }

        if (name[0] != '#')
            name = "#" + name;

        add_channel(name, sha256(name).substr(0, meshcore::cipher_key_size));
    }

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/meshcore/channels", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_jsonable_endpoint>(std::make_unique<json_adapter_v2::jsonable_map<channels_map_t, channels_map_t::iterator>>(channels, "meshcore.channels"), mutex_));

    packetchain->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -100);
}

kis_meshcore_phy::~kis_meshcore_phy() {

}

void kis_meshcore_phy::add_channel(const std::string& name, const std::string& secret) {
    // The channel hash is the first byte of the sha256 of the 16 or 32 byte secret
    const auto hash = static_cast<uint8_t>(sha256(secret)[0]);

    if (channels.erase(name) > 0) {
        _MSG_INFO("MeshCore channel '{}' redefined", name);
    }

    channels.emplace(name, meshcore_channel{name, secret, hash, max_live_messages});

    _MSG_INFO("MeshCore added channel '{}' (AES128, hash {:02x})", name, hash);
}

std::optional<kis_meshcore_phy::frame> kis_meshcore_phy::parse_frame(std::string_view data) {
    using namespace meshcore;

    if (data.size() < 2)
        return std::nullopt;

    const auto header = static_cast<uint8_t>(data[0]);

    // Only version 1 (0) is defined
    if ((header >> 6) != 0)
        return std::nullopt;

    const auto type_raw = static_cast<uint8_t>((header >> 2) & 0x0F);
    if (!payload_known(type_raw))
        return std::nullopt;

    frame f;
    f.route = static_cast<route_type>(header & 0x03);
    f.type = static_cast<payload_type>(type_raw);

    size_t pos = 1;

    if (f.route == route_type::transport_flood || f.route == route_type::transport_direct)
        pos += 4;

    if (pos >= data.size())
        return std::nullopt;

    const auto path_len = static_cast<uint8_t>(data[pos++]);

    // Hash size 4 is reserved
    if ((path_len >> 6) == 3)
        return std::nullopt;

    f.path_hash_size = (path_len >> 6) + 1;
    f.path_count = path_len & 0x3F;

    const size_t path_bytes = static_cast<size_t>(f.path_count) * f.path_hash_size;

    if (path_bytes > max_path_size || pos + path_bytes > data.size())
        return std::nullopt;

    f.path = data.substr(pos, path_bytes);
    pos += path_bytes;

    f.payload = data.substr(pos);

    if (f.payload.empty() || f.payload.size() > max_payload_size)
        return std::nullopt;

    const auto sz = f.payload.size();

    // Encrypted payloads are a cleartext prefix, the MAC, and whole cipher blocks
    auto encrypted_ok = [sz](size_t prefix) {
        return sz >= prefix + cipher_mac_size + cipher_block_size &&
            (sz - prefix - cipher_mac_size) % cipher_block_size == 0;
    };

    switch (f.type) {
        case payload_type::req:
        case payload_type::response:
        case payload_type::txt_msg:
        case payload_type::path:
            // dest hash, src hash
            if (!encrypted_ok(2))
                return std::nullopt;
            break;
        case payload_type::anon_req:
            // dest hash, sender key
            if (!encrypted_ok(1 + pub_key_size))
                return std::nullopt;
            break;
        case payload_type::grp_txt:
        case payload_type::grp_data:
            // channel hash
            if (!encrypted_ok(1))
                return std::nullopt;
            break;
        case payload_type::advert:
            if (sz < advert_min_size || sz > advert_min_size + max_advert_data)
                return std::nullopt;
            break;
        case payload_type::ack:
            if (sz < 4)
                return std::nullopt;
            break;
        case payload_type::trace:
            // tag, auth code, flags
            if (sz < 9)
                return std::nullopt;
            break;
        case payload_type::multipart:
        case payload_type::control:
        case payload_type::raw_custom:
            break;
    }

    return f;
}

void kis_meshcore_phy::learn_key(const std::string& pubkey) {
    kis_lock_guard<kis_mutex> lk(mutex_, __func__);

    if (known_keys.size() < max_known_keys)
        known_keys.insert(pubkey);
}

bool kis_meshcore_phy::key_known(const std::string& pubkey) {
    kis_lock_guard<kis_mutex> lk(mutex_, __func__);
    return known_keys.find(pubkey) != known_keys.end();
}

std::optional<std::string> kis_meshcore_phy::resolve_prefix(std::string_view prefix) {
    kis_lock_guard<kis_mutex> lk(mutex_, __func__);

    if (prefix.empty())
        return std::nullopt;

    auto i = known_keys.lower_bound(std::string{prefix});

    if (i == known_keys.end() || i->compare(0, prefix.size(), prefix) != 0)
        return std::nullopt;

    auto next = std::next(i);
    if (next != known_keys.end() && next->compare(0, prefix.size(), prefix) == 0)
        return std::nullopt;

    return *i;
}

bool kis_meshcore_phy::seen_recently(const frame& f) {
    // Packet hash per Packet::calculatePacketHash; the path changes as a flood is repeated
    // but this doesn't
    std::string h(1, static_cast<char>(f.type));

    if (f.type == meshcore::payload_type::trace)
        h += static_cast<char>(f.path_count);

    h += f.payload;

    auto hash = sha256(h).substr(0, 8);

    kis_lock_guard<kis_mutex> lk(mutex_, __func__);

    if (recent_hashes.find(hash) != recent_hashes.end())
        return true;

    if (recent_hash_order.size() >= max_recent_hashes) {
        recent_hashes.erase(recent_hash_order.front());
        recent_hash_order.pop_front();
    }

    recent_hash_order.push_back(hash);
    recent_hashes.insert(hash);

    return false;
}

std::shared_ptr<kis_tracked_device_base> kis_meshcore_phy::update_node(const std::string& pubkey,
        const std::shared_ptr<kis_packet>& in_pack, int flags, bool& new_device) {

    new_device = false;

    auto basedev =
        devicetracker->update_common_device(pubkey_to_mac(pubkey), this, in_pack, flags,
                "MeshCore", new_device);

    if (basedev == nullptr)
        return nullptr;

    if (new_device) {
        basedev->set_manuf(generic_manuf);
        basedev->set_tracker_type_string(devicetracker->get_cached_devicetype("MeshCore"));
        basedev->set_devicename(fmt::format("MeshCore {}", to_hex(pubkey.substr(0, 4))));
    }

    auto node = basedev->get_sub_as<tracked_meshcore_node>(meshcore_node_id);
    if (node == nullptr) {
        node = Globalreg::globalreg->entrytracker->get_shared_instance_as<tracked_meshcore_node>(meshcore_node_id);
        node->set_pubkey(base64::encode(pubkey));
        node->set_key_type(std::string{meshcore::node_key_type});
        basedev->insert(node);
    }

    return basedev;
}

int kis_meshcore_phy::packet_handler(CHAINCALL_PARMS) {
    using namespace meshcore;

    auto mphy = static_cast<kis_meshcore_phy *>(auxdata);

    if (in_pack->duplicate || in_pack->filtered) {
        return 1;
    }

    if (in_pack->common_info.common_info_ok) {
        return 0;
    }

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_decap, mphy->pack_comp_linkframe);

    if (packdata == nullptr) {
        return 0;
    }

    if (packdata->dlt != mphy->dlt_meshcore) {
        return 0;
    }

    // Sync word 0x12 is the generic private LoRa sync word, so frames must parse to be
    // treated as MeshCore
    auto f = parse_frame(std::string_view{packdata->data(), packdata->length()});

    if (!f) {
        return 0;
    }

    const auto& payload = f->payload;

    std::optional<std::string> source_key, dest_key, transmitter_key;
    std::optional<advert_info> advert;
    bool bad_signature = false;
    std::string bad_signature_key;

    try {
        switch (f->type) {
            case payload_type::advert: {
                const auto pubkey = payload.substr(0, pub_key_size);
                const auto sig = payload.substr(pub_key_size + 4, signature_size);
                const auto app = payload.substr(advert_min_size);

                // Signed over the key, timestamp, and application data
                std::string msg{payload.substr(0, pub_key_size + 4)};
                msg += app;

                if (!ed25519_verify(pubkey, msg, sig)) {
                    bad_signature = true;
                    bad_signature_key = std::string{pubkey};
                    break;
                }

                advert = parse_advert_appdata(app);
                advert->pubkey = std::string{pubkey};
                advert->timestamp = le32(payload.data() + pub_key_size);

                mphy->learn_key(advert->pubkey);
                source_key = advert->pubkey;
                break;
            }

            case payload_type::req:
            case payload_type::response:
            case payload_type::txt_msg:
            case payload_type::path:
                dest_key = mphy->resolve_prefix(payload.substr(0, 1));
                source_key = mphy->resolve_prefix(payload.substr(1, 1));
                break;

            case payload_type::anon_req:
                // The sender key isn't authenticated without the recipient's secret; only
                // attribute it to a node already known from a signed advert
                dest_key = mphy->resolve_prefix(payload.substr(0, 1));
                if (mphy->key_known(std::string{payload.substr(1, pub_key_size)}))
                    source_key = std::string{payload.substr(1, pub_key_size)};
                break;

            case payload_type::control:
                // Discovery responses carry the responder's key, which is likewise
                // unauthenticated
                if ((static_cast<uint8_t>(payload[0]) & 0xF0) == control_discover_resp &&
                        payload.size() >= 6 + pub_key_size) {
                    if (mphy->key_known(std::string{payload.substr(6, pub_key_size)}))
                        source_key = std::string{payload.substr(6, pub_key_size)};
                }
                break;

            case payload_type::grp_txt:
            case payload_type::grp_data:
                mphy->handle_group(*f, in_pack);
                break;

            default:
                break;
        }
    } catch (const std::exception& e) {
        _MSG_DEBUG("MeshCore failed to process {} packet: {}", payload_type_name(f->type), e.what());
        return 0;
    }

    // The transmitter of a flood is the last repeater in the path, or the source when
    // nothing has repeated it yet.  Direct routes strip each hop as it's used, so the
    // transmitter is only known for zero hop adverts and control packets.
    const bool flood = f->route == route_type::flood || f->route == route_type::transport_flood;

    if (f->type != payload_type::trace) {
        if (flood && f->path_count > 0) {
            transmitter_key =
                mphy->resolve_prefix(f->path.substr(f->path.size() - f->path_hash_size));
        } else if (flood || f->type == payload_type::advert || f->type == payload_type::control) {
            transmitter_key = source_key;
        }
    }

    if (in_pack->signal_info.data_ok) {
        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.phyid = mphy->fetch_phy_id();

        switch (f->type) {
            case payload_type::advert:
            case payload_type::ack:
            case payload_type::path:
            case payload_type::trace:
            case payload_type::control:
                in_pack->common_info.type = packet_basic_mgmt;
                break;
            default:
                in_pack->common_info.type = packet_basic_data;
                in_pack->common_info.datasize = payload.size();
                break;
        }

        in_pack->common_info.freq_khz = in_pack->signal_info.freq_khz;
        in_pack->common_info.channel = in_pack->signal_info.channel;

        if (source_key)
            in_pack->common_info.source = pubkey_to_mac(*source_key);
        if (transmitter_key)
            in_pack->common_info.transmitter = pubkey_to_mac(*transmitter_key);
        if (dest_key)
            in_pack->common_info.dest = pubkey_to_mac(*dest_key);
    }

    if (bad_signature) {
        const auto mac = pubkey_to_mac(bad_signature_key);

        // Only an existing node is touched, so a forged advert can't create devices
        auto key = device_key(mphy->fetch_phyname_hash(), mac);

        kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), __func__);

        auto basedev = mphy->devicetracker->fetch_device_nr(key);
        if (basedev != nullptr) {
            auto node = basedev->get_sub_as<tracked_meshcore_node>(mphy->meshcore_node_id);
            if (node != nullptr)
                node->inc_bad_signatures(1);
        }

        mphy->alertracker->raise_alert(mphy->alert_badsig_ref, in_pack,
                mac_addr{}, mac, mac_addr{}, mac_addr{}, in_pack->common_info.channel,
                fmt::format("MeshCore advert for key {} has an invalid signature; this may be "
                    "a spoofed advert or a corrupted packet", base64::encode(bad_signature_key)));

        return 1;
    }

    if (!source_key && !transmitter_key) {
        return 1;
    }

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), __func__);

    bool new_device = false;
    std::shared_ptr<kis_tracked_device_base> source_dev;

    if (transmitter_key) {
        auto txdev = mphy->update_node(*transmitter_key, in_pack,
                // The transmitter is the node kismet heard, so it's located where kismet was
                UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_SEENBY |
                UCD_UPDATE_LOCATION,
                new_device);

        if (txdev != nullptr && transmitter_key != source_key) {
            auto node = txdev->get_sub_as<tracked_meshcore_node>(mphy->meshcore_node_id);
            if (node != nullptr) {
                node->inc_relayed(1);
                node->set_last_relayed(in_pack->ts.tv_sec);
            }
        }

        if (transmitter_key == source_key)
            source_dev = txdev;
    }

    if (source_key && source_key != transmitter_key) {
        source_dev = mphy->update_node(*source_key, in_pack,
                UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS, new_device);
    }

    if (source_dev == nullptr || !advert) {
        return 1;
    }

    auto node = source_dev->get_sub_as<tracked_meshcore_node>(mphy->meshcore_node_id);
    if (node == nullptr) {
        return 1;
    }

    const bool new_node_info = node->get_adverts() == 0;

    node->inc_adverts(1);

    // Repeats of an old advert can arrive late; only newer ones update the node
    if (advert->timestamp < node->get_advert_ts()) {
        return 1;
    }

    node->set_advert_ts(advert->timestamp);
    node->set_advert_hops(flood ? f->path_count : 0);
    node->set_node_type(static_cast<uint8_t>(advert->type));

    source_dev->set_tracker_type_string(node_type_string(mphy->devicetracker, advert->type));

    if (!advert->name.empty()) {
        node->set_node_name(advert->name);
        source_dev->set_devicename(advert->name);
    }

    if (advert->has_location) {
        node->set_lat(advert->lat);
        node->set_lon(advert->lon);

        // The node's advertised position is its reported location
        in_pack->reported_gps.set_reported(advert->lat, advert->lon, 0, 0, 0, 2, in_pack->ts);

        mphy->devicetracker->update_common_device(source_dev->get_macaddr(), mphy, in_pack,
                UCD_UPDATE_REPORTED_LOCATION, "MeshCore");
    }

    if (new_node_info) {
        _MSG_INFO("Detected new {} \"{}\" ({})",
                source_dev->get_tracker_type_string()->get(), advert->name,
                to_hex(advert->pubkey.substr(0, 4)));
    }

    return 1;
}

void kis_meshcore_phy::handle_group(const frame& f, const std::shared_ptr<kis_packet>& in_pack) {
    using namespace meshcore;

    const auto hash = static_cast<uint8_t>(f.payload[0]);
    const auto mac = f.payload.substr(1, cipher_mac_size);
    const auto ciphertext = f.payload.substr(1 + cipher_mac_size);

    // Several channels can share a hash byte; the MAC picks the right one
    for (auto& [chan_name, chan] : channels) {
        if (chan.hash() != hash)
            continue;

        if (!mac_matches(chan.secret(), mac, ciphertext))
            continue;

        auto plain = aes128_ecb_decrypt(chan.secret(), ciphertext);
        if (!plain)
            return;

        if (f.type != payload_type::grp_txt) {
            _MSG_DEBUG("MeshCore group data on channel \"{}\"", chan_name);
            return;
        }

        // timestamp, text type, "sender: message", zero padded
        if (plain->size() < 5 || (static_cast<uint8_t>((*plain)[4]) >> 2) != 0)
            return;

        // Flood repeats carry the same message
        if (seen_recently(f))
            return;

        const auto timestamp = le32(plain->data());

        std::string_view text{plain->data() + 5, plain->size() - 5};
        text = text.substr(0, text.find('\0'));

        std::string_view sender;
        std::string_view message = text;

        const auto sep = text.find(": ");
        if (sep != std::string_view::npos) {
            sender = text.substr(0, sep);
            message = text.substr(sep + 2);
        }

        _MSG_INFO("MeshCore \"{}\" on channel \"{}\": {}", sender, chan_name, message);

        chan.add_message(timestamp, sender, message);

        return;
    }
}
