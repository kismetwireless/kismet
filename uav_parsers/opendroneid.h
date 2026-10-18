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

#ifndef __OPENDRONEID_H__
#define __OPENDRONEID_H__

/* Open Drone ID / Remote ID broadcast messages (ASTM F3411, ASD-STAN EN 4709-002).
 *
 * Every message is a fixed 25 byte record; a message pack bundles up to 9 of them.
 * The same records are carried over BLE4 and BLE5 service data, Wi-Fi beacon vendor
 * IEs, and Wi-Fi NAN service discovery frames.
 *
 * The decoder only depends on the standard library; every field comes from the
 * air and is bounds checked.  Strings are trimmed at the first NUL but not
 * otherwise sanitized.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace odid {

constexpr size_t message_len = 25;
constexpr size_t max_pack_messages = 9;
constexpr size_t max_auth_pages = 16;

/* 16-bit BLE service UUID (ASTM) and Remote ID app code */
constexpr uint16_t ble_service_uuid = 0xFFFA;
constexpr uint8_t app_code = 0x0D;

/* ASD-STAN OUI and vendor type for Wi-Fi beacons */
constexpr uint32_t wifi_oui = 0xFA0BBC;
constexpr uint8_t wifi_oui_type = 0x0D;

/* NAN service ID: first 6 bytes of SHA-256("org.opendroneid.remoteid") */
constexpr uint8_t nan_service_id[6] = { 0x88, 0x69, 0x19, 0x9D, 0x92, 0x09 };

/* Remote ID timestamps in system and auth messages count from 2019-01-01 00:00 UTC */
constexpr uint32_t epoch_offset = 1546300800;

enum class msg_type : uint8_t {
    basic_id = 0x0,
    location = 0x1,
    auth = 0x2,
    self_id = 0x3,
    system = 0x4,
    operator_id = 0x5,
    pack = 0xF,
};

enum class id_type : uint8_t {
    none = 0,
    serial = 1,
    caa_registration = 2,
    utm_uuid = 3,
    session_id = 4,
};

struct basic_id_msg {
    uint8_t id_type = 0;
    uint8_t ua_type = 0;
    /* Printable form: text for serial/registration, hex for UTM UUID and session IDs */
    std::string uas_id;
};

struct location_msg {
    uint8_t status = 0;
    uint8_t height_type = 0;

    bool direction_valid = false;
    double direction = 0;

    bool speed_valid = false;
    double speed_h = 0;

    bool speed_v_valid = false;
    double speed_v = 0;

    bool latlon_valid = false;
    double lat = 0;
    double lon = 0;

    bool alt_baro_valid = false;
    double alt_baro = 0;
    bool alt_geo_valid = false;
    double alt_geo = 0;
    bool height_valid = false;
    double height = 0;

    uint8_t horiz_accuracy = 0;
    uint8_t vert_accuracy = 0;
    uint8_t baro_accuracy = 0;
    uint8_t speed_accuracy = 0;
    uint8_t ts_accuracy = 0;

    /* Seconds past the hour, 0.1s resolution */
    bool timestamp_valid = false;
    double timestamp = 0;
};

struct auth_msg {
    uint8_t auth_type = 0;
    uint8_t page = 0;
    /* Page 0 only */
    uint8_t last_page = 0;
    uint8_t length = 0;
    uint32_t timestamp = 0;
    std::string data;
};

struct self_id_msg {
    uint8_t desc_type = 0;
    std::string desc;
};

struct system_msg {
    uint8_t operator_location_type = 0;
    uint8_t classification_type = 0;

    bool operator_latlon_valid = false;
    double operator_lat = 0;
    double operator_lon = 0;

    uint16_t area_count = 0;
    double area_radius = 0;
    bool area_ceiling_valid = false;
    double area_ceiling = 0;
    bool area_floor_valid = false;
    double area_floor = 0;

    uint8_t eu_category = 0;
    uint8_t eu_class = 0;

    bool operator_alt_valid = false;
    double operator_alt_geo = 0;

    /* Unix time, 0 if not set */
    uint64_t timestamp = 0;
};

struct operator_id_msg {
    uint8_t id_type = 0;
    std::string operator_id;
};

struct message {
    msg_type type = msg_type::basic_id;
    uint8_t version = 0;

    basic_id_msg basic_id;
    location_msg location;
    auth_msg auth;
    self_id_msg self_id;
    system_msg system;
    operator_id_msg operator_id;
};

/* Decode one 25 byte message.  Returns false for short data, packs, and unknown types. */
bool decode_message(const uint8_t *data, size_t len, message& out);

/* Decode a single message or a message pack into out; returns false if nothing decoded */
bool decode_messages(const uint8_t *data, size_t len, std::vector<message>& out);

/* BLE service data payload (the AD record after the 0x16 type byte): UUID, app code,
 * counter, then a message or message pack */
bool decode_ble_service_data(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out);

/* Wi-Fi beacon vendor IE contents after the OUI: type, counter, message pack */
bool decode_wifi_vendor_ie(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out);

/* NAN service discovery frame attributes (after the OUI type byte of the public
 * action frame); looks for the Remote ID service descriptor */
bool decode_nan_attributes(const uint8_t *data, size_t len, uint8_t& counter,
        std::vector<message>& out);

const char *ua_type_str(uint8_t ua_type);
const char *id_type_str(uint8_t id_type);
const char *status_str(uint8_t status);

}

#endif
