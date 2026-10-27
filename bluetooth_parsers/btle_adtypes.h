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

#ifndef __BTLE_ADTYPES_H__
#define __BTLE_ADTYPES_H__

/* Mesh, LE Audio, and the less common AD types.  AD type decoders take the AD value
 * (after the length and type), service data decoders the whole 16-bit service data
 * value, UUID first.  Mesh fields are big endian, everything else little endian.
 *
 *   Mesh Beacon (AD 0x2B, Mesh Protocol): a beacon type, then for 0x00
 *   (unprovisioned) the 16 byte device UUID, 16 bit OOB information and an optional
 *   4 byte URI hash; 0x01 (secure network) a flags byte (0x01 key refresh, 0x02 IV
 *   update), 8 byte network ID, 32 bit IV index and 8 byte authentication value;
 *   0x02 (private) 13 random bytes, 5 obfuscated and an 8 byte tag.  Lengths per
 *   Zephyr mesh/beacon.c, OOB bits per BlueZ and Zephyr mesh/main.h.
 *
 *   Mesh Proxy service data (0x1828): an identification type, then for 0x00 an 8
 *   byte network ID; 0x01 node identity and 0x02/0x03 private network/node identity
 *   carry an 8 byte hash and 8 byte random, not kept.  Mesh Provisioning service
 *   data (0x1827): device UUID and OOB information.  Zephyr proxy_srv.c,
 *   pb_gatt_srv.c.
 *
 *   PB-ADV (0x29) and Mesh Message (0x2A) are only flagged by type.
 *
 *   Broadcast_Name (AD 0x30, PBP): UTF-8, 4 to 32 characters (up to 128 octets).
 *   Broadcast Audio Announcement (0x1852, BAP): 24 bit Broadcast_ID.
 *   Public Broadcast Announcement (0x1856, PBP): a features byte (0x01 encrypted,
 *   0x02 standard quality, 0x04 high quality), metadata length, metadata LTVs (the
 *   length covers the type; Assigned Numbers metadata_ltv: 0x03 Program_Info, UTF-8;
 *   0x04 Language, 3 bytes ISO 639-3).  ASCS (0x184E, BAP) targeted/general
 *   announcement: type (0x00 general, 0x01 targeted), available sink and source
 *   contexts (16 bit each), metadata length, metadata.  CAS (0x1853, CAP): the
 *   announcement type alone.  Layouts checked against BlueZ monitor/packet.c and
 *   the Zephyr samples.
 *
 *   Resolvable Set Identifier (AD 0x2E, CSIS): 6 bytes, hash and prand; it can't
 *   be resolved without the SIRK, so it's kept as hex.
 *
 *   URI (AD 0x24, CSS A.1.18): the first UTF-8 code point is a scheme from Assigned
 *   Numbers (core/uri_schemes.yaml); U+0001 is no scheme, the rest is the URI.
 *   Code points over 0x7F take two bytes.
 *
 *   Transport Discovery Data (AD 0x26, TDS): one or more blocks of Organization
 *   ID, TDS flags (bits 0-1 role, bit 2 data incomplete, bits 3-4 transport state),
 *   transport data length and data.  Org IDs from Assigned Numbers
 *   (tds/transport_discovery_service_id.yaml).
 *
 *   LE Supported Features (0x27, CSS A.1.19): the FeatureSet, trailing zero bytes
 *   dropped.  Advertising Interval (0x1A) uint16 and Advertising Interval - long
 *   (0x2F) uint24 or uint32, 0.625 ms units (CSS A.1.15).  Peripheral Connection
 *   Interval Range (0x12, CSS A.1.9): two uint16 in 1.25 ms, 0x0006-0x0C80, 0xFFFF
 *   unspecified.  LE Role (0x1C, CSS A.1.17).
 *
 *   Indoor Positioning (AD 0x25, IPS 2.2 and 3): a flags byte (omitted when zero),
 *   then as flagged: latitude and longitude (sint32 signed magnitude, X / 90 or 180 *
 *   2^31, 0x80000000 unset) or local north and east (sint16 decimeters, 0x8000
 *   unset); Tx power (1 byte); floor (X = N + 20, 253/254 ground floor 0/1, 255
 *   unset); altitude (uint16 decimeters + 1000, 65535 unset); uncertainty (bit 0
 *   mobile, bits 1-3 update time, bits 4-6 precision).
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace btle_adtypes {

constexpr uint8_t ad_peripheral_conn_interval = 0x12;
constexpr uint8_t ad_adv_interval = 0x1A;
constexpr uint8_t ad_le_role = 0x1C;
constexpr uint8_t ad_uri = 0x24;
constexpr uint8_t ad_indoor_positioning = 0x25;
constexpr uint8_t ad_transport_discovery = 0x26;
constexpr uint8_t ad_le_supported_features = 0x27;
constexpr uint8_t ad_pb_adv = 0x29;
constexpr uint8_t ad_mesh_message = 0x2A;
constexpr uint8_t ad_mesh_beacon = 0x2B;
constexpr uint8_t ad_resolvable_set_id = 0x2E;
constexpr uint8_t ad_adv_interval_long = 0x2F;
constexpr uint8_t ad_broadcast_name = 0x30;

constexpr uint16_t uuid_mesh_provisioning = 0x1827;
constexpr uint16_t uuid_mesh_proxy = 0x1828;
constexpr uint16_t uuid_ascs = 0x184E;
constexpr uint16_t uuid_broadcast_audio = 0x1852;
constexpr uint16_t uuid_cas = 0x1853;
constexpr uint16_t uuid_public_broadcast = 0x1856;

/* Mesh */

enum class mesh_beacon_type : uint8_t {
    unprovisioned = 0x00,
    secure_network = 0x01,
    private_beacon = 0x02,
};

struct mesh_beacon {
    mesh_beacon_type type = mesh_beacon_type::unprovisioned;

    /* Unprovisioned */
    std::string device_uuid;
    uint16_t oob_info = 0;
    bool has_uri_hash = false;

    /* Secure network */
    bool key_refresh = false;
    bool iv_update = false;
    std::string network_id;
    uint32_t iv_index = 0;
};

enum class mesh_proxy_id : uint8_t {
    network_id = 0x00,
    node_identity = 0x01,
    private_network_identity = 0x02,
    private_node_identity = 0x03,
};

struct mesh_proxy {
    mesh_proxy_id id_type = mesh_proxy_id::network_id;
    /* Only for network_id */
    std::string network_id;
};

struct mesh_provisioning {
    std::string device_uuid;
    uint16_t oob_info = 0;
};

bool decode_mesh_beacon(const uint8_t *data, size_t len, mesh_beacon& out);
bool decode_mesh_proxy(const uint8_t *data, size_t len, mesh_proxy& out);
bool decode_mesh_provisioning(const uint8_t *data, size_t len, mesh_provisioning& out);

const char *mesh_beacon_type_str(mesh_beacon_type t);
const char *mesh_proxy_id_str(mesh_proxy_id t);
/* Comma separated OOB information flag names, empty if none */
std::string mesh_oob_info_str(uint16_t oob);

/* LE Audio */

struct broadcast_audio {
    uint32_t broadcast_id = 0;
    std::string broadcast_id_hex;
};

struct public_broadcast {
    uint8_t features = 0;
    bool encrypted = false;
    bool standard_quality = false;
    bool high_quality = false;
    std::string program_info;
    std::string language;
};

enum class announcement_type : uint8_t {
    general = 0x00,
    targeted = 0x01,
};

struct unicast_announcement {
    /* uuid_ascs or uuid_cas */
    uint16_t service = 0;
    announcement_type type = announcement_type::general;
    /* ASCS only */
    bool has_contexts = false;
    uint16_t sink_contexts = 0;
    uint16_t source_contexts = 0;
};

bool decode_broadcast_name(const uint8_t *data, size_t len, std::string& out);
bool decode_broadcast_audio(const uint8_t *data, size_t len, broadcast_audio& out);
bool decode_public_broadcast(const uint8_t *data, size_t len, public_broadcast& out);
/* ASCS or CAS service data */
bool decode_unicast_announcement(const uint8_t *data, size_t len, unicast_announcement& out);

const char *announcement_type_str(announcement_type t);
/* Comma separated context type names, empty if none */
std::string audio_context_str(uint16_t ctx);

/* Resolvable Set Identifier, as hex */
bool decode_resolvable_set_id(const uint8_t *data, size_t len, std::string& out);

/* URI */
bool decode_uri(const uint8_t *data, size_t len, std::string& out);

/* Transport Discovery Data */

enum class tds_role : uint8_t {
    not_specified = 0,
    seeker = 1,
    provider = 2,
    seeker_provider = 3,
};

enum class tds_state : uint8_t {
    off = 0,
    on = 1,
    temporarily_unavailable = 2,
    reserved = 3,
};

struct tds_block {
    uint8_t org_id = 0;
    const char *org_name = nullptr;
    tds_role role = tds_role::not_specified;
    tds_state state = tds_state::off;
    bool data_incomplete = false;
    uint8_t data_len = 0;
};

struct transport_discovery {
    std::vector<tds_block> blocks;
};

bool decode_transport_discovery(const uint8_t *data, size_t len, transport_discovery& out);

const char *tds_role_str(tds_role r);
const char *tds_state_str(tds_state s);

/* LE features, intervals, role */

bool decode_le_features(const uint8_t *data, size_t len, std::string& out);
bool decode_adv_interval(const uint8_t *data, size_t len, uint64_t& out_usec);
bool decode_adv_interval_long(const uint8_t *data, size_t len, uint64_t& out_usec);

struct conn_interval_range {
    /* 0xFFFF, no preference */
    bool min_specified = false;
    bool max_specified = false;
    uint32_t min_usec = 0;
    uint32_t max_usec = 0;
};

bool decode_conn_interval_range(const uint8_t *data, size_t len, conn_interval_range& out);

enum class le_role : uint8_t {
    peripheral_only = 0x00,
    central_only = 0x01,
    both_peripheral_preferred = 0x02,
    both_central_preferred = 0x03,
};

bool decode_le_role(const uint8_t *data, size_t len, le_role& out);
const char *le_role_str(le_role r);

/* Indoor Positioning */

struct indoor_positioning {
    uint8_t flags = 0;
    bool location_name_in_gatt = false;

    bool has_coordinates = false;
    bool local_coordinates = false;
    /* False when the device sent the unset value */
    bool coordinates_set = false;
    /* WGS84 degrees */
    double latitude = 0;
    double longitude = 0;
    /* Local, decimeters */
    int16_t north_dm = 0;
    int16_t east_dm = 0;

    bool has_tx_power = false;
    int8_t tx_power = 0;

    bool has_floor = false;
    bool floor_ground = false;
    int floor = 0;

    bool has_altitude = false;
    int32_t altitude_dm = 0;

    bool has_uncertainty = false;
    bool mobile = false;
    /* Update time is round(e^(1.35 x)) s; precision 0 (< 0.1 m) to 6 (> 50 m) */
    uint8_t update_time_code = 0;
    uint8_t precision_code = 0;
};

bool decode_indoor_positioning(const uint8_t *data, size_t len, indoor_positioning& out);

}

#endif

