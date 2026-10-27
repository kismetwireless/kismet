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

#include "btle_adtypes.h"

#include <iterator>
#include <utility>

namespace btle_adtypes {

namespace {

constexpr char hexdigits[] = "0123456789abcdef";

constexpr size_t max_name_len = 128;
constexpr size_t max_program_info_len = 128;
constexpr size_t max_uri_len = 256;
constexpr size_t max_le_features_len = 32;
constexpr size_t max_tds_blocks = 16;

std::string to_hex(const uint8_t *data, size_t len) {
    std::string r;
    r.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        r.push_back(hexdigits[data[i] >> 4]);
        r.push_back(hexdigits[data[i] & 0x0F]);
    }
    return r;
}

std::string to_uuid(const uint8_t *data) {
    std::string r;
    r.reserve(36);
    for (size_t i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            r.push_back('-');
        r.push_back(hexdigits[data[i] >> 4]);
        r.push_back(hexdigits[data[i] & 0x0F]);
    }
    return r;
}

/* Printable ASCII only; anything else, including each byte of a multibyte UTF-8
 * sequence, becomes '?' */
void append_sanitized(std::string& out, const uint8_t *data, size_t len, size_t cap) {
    for (size_t i = 0; i < len && out.length() < cap; i++) {
        if (data[i] >= 0x20 && data[i] < 0x7F)
            out.push_back((char) data[i]);
        else
            out.push_back('?');
    }
}

uint16_t get_le16(const uint8_t *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

uint16_t get_be16(const uint8_t *p) {
    return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
}

uint32_t get_le32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
        ((uint32_t) p[3] << 24);
}

uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) |
        (uint32_t) p[3];
}

constexpr const char *mesh_oob_names[16] = {
    "other", "uri", "2d_code", "bar_code", "nfc", "number", "string", "certificate",
    "records", nullptr, nullptr, "on_box", "inside_box", "on_paper", "inside_manual",
    "on_device",
};

constexpr const char *audio_context_names[12] = {
    "unspecified", "conversational", "media", "game", "instructional",
    "voice_assistants", "live", "sound_effects", "notifications", "ringtone",
    "alerts", "emergency_alarm",
};

/* Assigned Numbers URI scheme name string mapping, starting at U+0002; U+0001 is the
 * empty scheme */
constexpr const char *uri_schemes[] = {
    "aaa:", "aaas:", "about:", "acap:", "acct:", "cap:", "cid:", "coap:", "coaps:",
    "crid:", "data:", "dav:", "dict:", "dns:", "file:", "ftp:", "geo:", "go:",
    "gopher:", "h323:", "http:", "https:", "iax:", "icap:", "im:", "imap:", "info:",
    "ipp:", "ipps:", "iris:", "iris.beep:", "iris.xpc:", "iris.xpcs:", "iris.lwz:",
    "jabber:", "ldap:", "mailto:", "mid:", "msrp:", "msrps:", "mtqp:", "mupdate:",
    "news:", "nfs:", "ni:", "nih:", "nntp:", "opaquelocktoken:", "pop:", "pres:",
    "reload:", "rtsp:", "rtsps:", "rtspu:", "service:", "session:", "shttp:", "sieve:",
    "sip:", "sips:", "sms:", "snmp:", "soap.beep:", "soap.beeps:", "stun:", "stuns:",
    "tag:", "tel:", "telnet:", "tftp:", "thismessage:", "tn3270:", "tip:", "turn:",
    "turns:", "tv:", "urn:", "vemmi:", "ws:", "wss:", "xcon:", "xcon-userid:",
    "xmlrpc.beep:", "xmlrpc.beeps:", "xmpp:", "z39.50r:", "z39.50s:", "acr:",
    "adiumxtra:", "afp:", "afs:", "aim:", "apt:", "attachment:", "aw:", "barion:",
    "beshare:", "bitcoin:", "bolo:", "callto:", "chrome:", "chrome-extension:",
    "com-eventbrite-attendee:", "content:", "cvs:", "dlna-playsingle:",
    "dlna-playcontainer:", "dtn:", "dvb:", "ed2k:", "facetime:", "feed:", "feedready:",
    "finger:", "fish:", "gg:", "git:", "gizmoproject:", "gtalk:", "ham:", "hcp:",
    "icon:", "ipn:", "irc:", "irc6:", "ircs:", "itms:", "jar:", "jms:", "keyparc:",
    "lastfm:", "ldaps:", "magnet:", "maps:", "market:", "message:", "mms:", "ms-help:",
    "ms-settings-power:", "msnim:", "mumble:", "mvn:", "notes:", "oid:", "palm:",
    "paparazzi:", "pkcs11:", "platform:", "proxy:", "psyc:", "query:", "res:",
    "resource:", "rmi:", "rsync:", "rtmfp:", "rtmp:", "secondlife:", "sftp:", "sgn:",
    "skype:", "smb:", "smtp:", "soldat:", "spotify:", "ssh:", "steam:", "submit:",
    "svn:", "teamspeak:", "teliaeid:", "things:", "udp:", "unreal:", "ut2004:",
    "ventrilo:", "view-source:", "webcal:", "wtai:", "wyciwyg:", "xfire:", "xri:",
    "ymsgr:", "example:", "ms-settings-cloudstorage:", "bluetooth:", "bl:",
};

static_assert(std::size(uri_schemes) == 0xBC - 1, "URI scheme table ends at 0x00BC");

struct tds_org {
    uint8_t id;
    const char *name;
};

constexpr tds_org tds_orgs[] = {
    { 0x01, "Bluetooth SIG" },
    { 0x02, "Wi-Fi Alliance Neighbor Awareness Networking" },
    { 0x03, "Wi-Fi Alliance Service Advertisement" },
};

std::string join_bits(uint32_t v, const char *const *names, size_t n_names) {
    std::string r;
    for (size_t i = 0; i < 32; i++) {
        if ((v & ((uint32_t) 1 << i)) == 0)
            continue;
        if (!r.empty())
            r.push_back(',');
        if (i < n_names && names[i] != nullptr) {
            r += names[i];
        } else {
            r += "bit";
            r += std::to_string(i);
        }
    }
    return r;
}

/* Signed magnitude, 0x80000000 unset */
bool ips_degrees(uint32_t raw, double range, double& out) {
    if (raw == 0x80000000)
        return false;
    const double mag = (double) (raw & 0x7FFFFFFF) / 2147483648.0 * range;
    out = (raw & 0x80000000) ? -mag : mag;
    return true;
}

}

bool decode_mesh_beacon(const uint8_t *data, size_t len, mesh_beacon& out) {
    if (data == nullptr || len < 1)
        return false;

    switch (data[0]) {
        case 0x00:
            /* Type, UUID, OOB, optional URI hash */
            if (len != 19 && len != 23)
                return false;
            out = mesh_beacon{};
            out.type = mesh_beacon_type::unprovisioned;
            out.device_uuid = to_uuid(data + 1);
            out.oob_info = get_be16(data + 17);
            out.has_uri_hash = len == 23;
            return true;

        case 0x01:
            /* Type, flags, network ID, IV index, authentication */
            if (len < 22)
                return false;
            out = mesh_beacon{};
            out.type = mesh_beacon_type::secure_network;
            out.key_refresh = data[1] & 0x01;
            out.iv_update = data[1] & 0x02;
            out.network_id = to_hex(data + 2, 8);
            out.iv_index = get_be32(data + 10);
            return true;

        case 0x02:
            /* Type, random, obfuscated data, authentication tag */
            if (len < 27)
                return false;
            out = mesh_beacon{};
            out.type = mesh_beacon_type::private_beacon;
            return true;

        default:
            return false;
    }
}

bool decode_mesh_proxy(const uint8_t *data, size_t len, mesh_proxy& out) {
    if (data == nullptr || len < 3 || get_le16(data) != uuid_mesh_proxy)
        return false;

    const uint8_t id = data[2];

    if (id == 0x00) {
        if (len != 11)
            return false;
        out = mesh_proxy{};
        out.id_type = mesh_proxy_id::network_id;
        out.network_id = to_hex(data + 3, 8);
        return true;
    }

    /* Hash and random */
    if (id > 0x03 || len != 19)
        return false;

    out = mesh_proxy{};
    out.id_type = static_cast<mesh_proxy_id>(id);
    return true;
}

bool decode_mesh_provisioning(const uint8_t *data, size_t len, mesh_provisioning& out) {
    if (data == nullptr || len != 20 || get_le16(data) != uuid_mesh_provisioning)
        return false;

    out = mesh_provisioning{};
    out.device_uuid = to_uuid(data + 2);
    out.oob_info = get_be16(data + 18);
    return true;
}

const char *mesh_beacon_type_str(mesh_beacon_type t) {
    switch (t) {
        case mesh_beacon_type::unprovisioned:
            return "unprovisioned";
        case mesh_beacon_type::secure_network:
            return "secure_network";
        case mesh_beacon_type::private_beacon:
            return "private";
        default:
            return "unknown";
    }
}

const char *mesh_proxy_id_str(mesh_proxy_id t) {
    switch (t) {
        case mesh_proxy_id::network_id:
            return "network_id";
        case mesh_proxy_id::node_identity:
            return "node_identity";
        case mesh_proxy_id::private_network_identity:
            return "private_network_identity";
        case mesh_proxy_id::private_node_identity:
            return "private_node_identity";
        default:
            return "unknown";
    }
}

std::string mesh_oob_info_str(uint16_t oob) {
    return join_bits(oob, mesh_oob_names, std::size(mesh_oob_names));
}

bool decode_broadcast_name(const uint8_t *data, size_t len, std::string& out) {
    if (data == nullptr || len < 4 || len > max_name_len)
        return false;

    out.clear();
    append_sanitized(out, data, len, max_name_len);
    return true;
}

bool decode_broadcast_audio(const uint8_t *data, size_t len, broadcast_audio& out) {
    if (data == nullptr || len < 5 || get_le16(data) != uuid_broadcast_audio)
        return false;

    out = broadcast_audio{};
    out.broadcast_id = (uint32_t) data[2] | ((uint32_t) data[3] << 8) |
        ((uint32_t) data[4] << 16);

    for (int s = 20; s >= 0; s -= 4)
        out.broadcast_id_hex.push_back(hexdigits[(out.broadcast_id >> s) & 0x0F]);

    return true;
}

bool decode_public_broadcast(const uint8_t *data, size_t len, public_broadcast& out) {
    /* UUID, features, metadata length */
    if (data == nullptr || len < 4 || get_le16(data) != uuid_public_broadcast)
        return false;

    const uint8_t *meta = data + 4;
    const size_t meta_len = data[3];

    if (meta_len > len - 4)
        return false;

    public_broadcast r;
    r.features = data[2];
    r.encrypted = r.features & 0x01;
    r.standard_quality = r.features & 0x02;
    r.high_quality = r.features & 0x04;

    size_t offt = 0;

    while (offt < meta_len) {
        const size_t ltv_len = meta[offt];

        /* Length 0 is an empty entry */
        if (ltv_len == 0) {
            offt++;
            continue;
        }

        if (ltv_len > meta_len - offt - 1)
            return false;

        const uint8_t type = meta[offt + 1];
        const uint8_t *v = meta + offt + 2;
        const size_t vlen = ltv_len - 1;

        if (type == 0x03 && r.program_info.empty())
            append_sanitized(r.program_info, v, vlen, max_program_info_len);
        else if (type == 0x04 && vlen == 3 && r.language.empty())
            append_sanitized(r.language, v, vlen, 3);

        offt += 1 + ltv_len;
    }

    out = std::move(r);
    return true;
}

bool decode_unicast_announcement(const uint8_t *data, size_t len, unicast_announcement& out) {
    if (data == nullptr || len < 3)
        return false;

    const uint16_t uuid = get_le16(data);

    if (uuid != uuid_ascs && uuid != uuid_cas)
        return false;

    if (data[2] > 0x01)
        return false;

    unicast_announcement r;
    r.service = uuid;
    r.type = static_cast<announcement_type>(data[2]);

    if (uuid == uuid_ascs) {
        /* Type, sink and source contexts, metadata length, metadata */
        if (len < 7)
            return false;
        if (len >= 8 && data[7] > len - 8)
            return false;
        r.has_contexts = true;
        r.sink_contexts = get_le16(data + 3);
        r.source_contexts = get_le16(data + 5);
    }

    out = r;
    return true;
}

const char *announcement_type_str(announcement_type t) {
    switch (t) {
        case announcement_type::general:
            return "general";
        case announcement_type::targeted:
            return "targeted";
        default:
            return "unknown";
    }
}

std::string audio_context_str(uint16_t ctx) {
    return join_bits(ctx, audio_context_names, std::size(audio_context_names));
}

bool decode_resolvable_set_id(const uint8_t *data, size_t len, std::string& out) {
    if (data == nullptr || len != 6)
        return false;

    out = to_hex(data, 6);
    return true;
}

bool decode_uri(const uint8_t *data, size_t len, std::string& out) {
    if (data == nullptr || len < 2)
        return false;

    uint32_t cp;
    size_t offt;

    /* The scheme code points top out at U+00BC, so one or two byte UTF-8 */
    if (data[0] < 0x80) {
        cp = data[0];
        offt = 1;
    } else if (data[0] >= 0xC2 && data[0] <= 0xDF) {
        if ((data[1] & 0xC0) != 0x80)
            return false;
        cp = ((uint32_t) (data[0] & 0x1F) << 6) | (data[1] & 0x3F);
        offt = 2;
    } else {
        return false;
    }

    if (cp < 1 || cp > std::size(uri_schemes) + 1 || offt >= len)
        return false;

    std::string r;

    if (cp > 1)
        r = uri_schemes[cp - 2];

    append_sanitized(r, data + offt, len - offt, max_uri_len);

    out = std::move(r);
    return true;
}

bool decode_transport_discovery(const uint8_t *data, size_t len, transport_discovery& out) {
    if (data == nullptr || len < 3)
        return false;

    transport_discovery r;
    size_t offt = 0;

    while (offt < len) {
        /* Org, flags, data length, data */
        if (len - offt < 3 || r.blocks.size() >= max_tds_blocks)
            return false;

        tds_block b;
        b.org_id = data[offt];
        b.role = static_cast<tds_role>(data[offt + 1] & 0x03);
        b.data_incomplete = data[offt + 1] & 0x04;
        b.state = static_cast<tds_state>((data[offt + 1] >> 3) & 0x03);
        b.data_len = data[offt + 2];

        if (b.data_len > len - offt - 3)
            return false;

        b.org_name = "unknown";
        for (const auto& o : tds_orgs) {
            if (o.id == b.org_id) {
                b.org_name = o.name;
                break;
            }
        }

        r.blocks.push_back(b);
        offt += 3 + (size_t) b.data_len;
    }

    out = std::move(r);
    return true;
}

const char *tds_role_str(tds_role r) {
    switch (r) {
        case tds_role::not_specified:
            return "not_specified";
        case tds_role::seeker:
            return "seeker";
        case tds_role::provider:
            return "provider";
        case tds_role::seeker_provider:
            return "seeker_provider";
        default:
            return "unknown";
    }
}

const char *tds_state_str(tds_state s) {
    switch (s) {
        case tds_state::off:
            return "off";
        case tds_state::on:
            return "on";
        case tds_state::temporarily_unavailable:
            return "temporarily_unavailable";
        default:
            return "reserved";
    }
}

bool decode_le_features(const uint8_t *data, size_t len, std::string& out) {
    if (data == nullptr || len < 1 || len > max_le_features_len)
        return false;

    out = to_hex(data, len);
    return true;
}

bool decode_adv_interval(const uint8_t *data, size_t len, uint64_t& out_usec) {
    if (data == nullptr || len != 2)
        return false;

    out_usec = (uint64_t) get_le16(data) * 625;
    return true;
}

bool decode_adv_interval_long(const uint8_t *data, size_t len, uint64_t& out_usec) {
    if (data == nullptr || (len != 3 && len != 4))
        return false;

    uint32_t v = (uint32_t) data[0] | ((uint32_t) data[1] << 8) | ((uint32_t) data[2] << 16);
    if (len == 4)
        v |= (uint32_t) data[3] << 24;

    out_usec = (uint64_t) v * 625;
    return true;
}

bool decode_conn_interval_range(const uint8_t *data, size_t len, conn_interval_range& out) {
    if (data == nullptr || len != 4)
        return false;

    const uint16_t lo = get_le16(data);
    const uint16_t hi = get_le16(data + 2);

    auto valid = [](uint16_t v) { return v == 0xFFFF || (v >= 0x0006 && v <= 0x0C80); };

    if (!valid(lo) || !valid(hi))
        return false;

    if (lo != 0xFFFF && hi != 0xFFFF && hi < lo)
        return false;

    out = conn_interval_range{};
    out.min_specified = lo != 0xFFFF;
    out.max_specified = hi != 0xFFFF;
    if (out.min_specified)
        out.min_usec = (uint32_t) lo * 1250;
    if (out.max_specified)
        out.max_usec = (uint32_t) hi * 1250;
    return true;
}

bool decode_le_role(const uint8_t *data, size_t len, le_role& out) {
    if (data == nullptr || len != 1 || data[0] > 0x03)
        return false;

    out = static_cast<le_role>(data[0]);
    return true;
}

const char *le_role_str(le_role r) {
    switch (r) {
        case le_role::peripheral_only:
            return "peripheral_only";
        case le_role::central_only:
            return "central_only";
        case le_role::both_peripheral_preferred:
            return "both_peripheral_preferred";
        case le_role::both_central_preferred:
            return "both_central_preferred";
        default:
            return "unknown";
    }
}

bool decode_indoor_positioning(const uint8_t *data, size_t len, indoor_positioning& out) {
    if (data == nullptr)
        return false;

    indoor_positioning r;

    /* No flags byte means all flags clear */
    if (len == 0) {
        out = r;
        return true;
    }

    r.flags = data[0];
    r.has_coordinates = r.flags & 0x01;
    r.local_coordinates = r.flags & 0x02;
    r.has_tx_power = r.flags & 0x04;
    r.has_altitude = r.flags & 0x08;
    r.has_floor = r.flags & 0x10;
    r.has_uncertainty = r.flags & 0x20;
    r.location_name_in_gatt = r.flags & 0x40;

    size_t need = 1;
    if (r.has_coordinates)
        need += r.local_coordinates ? 4 : 8;
    if (r.has_tx_power)
        need += 1;
    if (r.has_floor)
        need += 1;
    if (r.has_altitude)
        need += 2;
    if (r.has_uncertainty)
        need += 1;

    if (len != need)
        return false;

    size_t offt = 1;

    if (r.has_coordinates && !r.local_coordinates) {
        const bool lat_set = ips_degrees(get_le32(data + offt), 90.0, r.latitude);
        const bool lon_set = ips_degrees(get_le32(data + offt + 4), 180.0, r.longitude);
        r.coordinates_set = lat_set && lon_set;
        if (!r.coordinates_set)
            r.latitude = r.longitude = 0;
        offt += 8;
    } else if (r.has_coordinates) {
        const uint16_t n = get_le16(data + offt);
        const uint16_t e = get_le16(data + offt + 2);
        r.coordinates_set = n != 0x8000 && e != 0x8000;
        if (r.coordinates_set) {
            r.north_dm = (int16_t) n;
            r.east_dm = (int16_t) e;
        }
        offt += 4;
    }

    if (r.has_tx_power)
        r.tx_power = (int8_t) data[offt++];

    if (r.has_floor) {
        const uint8_t x = data[offt++];
        if (x == 255) {
            r.has_floor = false;
        } else if (x >= 253) {
            r.floor_ground = true;
            r.floor = x == 253 ? 0 : 1;
        } else {
            r.floor = (int) x - 20;
        }
    }

    if (r.has_altitude) {
        const uint16_t x = get_le16(data + offt);
        offt += 2;
        if (x == 65535)
            r.has_altitude = false;
        else
            r.altitude_dm = (int32_t) x - 1000;
    }

    if (r.has_uncertainty) {
        const uint8_t u = data[offt++];
        r.mobile = u & 0x01;
        r.update_time_code = (u >> 1) & 0x07;
        r.precision_code = (u >> 4) & 0x07;
    }

    out = r;
    return true;
}

}
