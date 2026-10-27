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

#ifndef __BTLE_CONTINUITY_H__
#define __BTLE_CONTINUITY_H__

/* Apple Continuity messages (manufacturer 0x004C): a list of type, length, value
 * entries.  Layouts from the furiousMAC Wireshark dissector and its message notes,
 * Celosia & Cunche (PETS 2020), Martin et al. (PETS 2019), hexway apple_bleee, and
 * Apple's HomeKitADK for HomeKit.
 *
 *   0x10 Nearby Info: high nibble status flags (0x10 primary device, 0x40 AirDrop
 *   receiving), low nibble activity level; then data flags (0x01 AirPods connected
 *   with the screen on, 0x04 Wi-Fi on, 0x10 auth tag follows).  The auth tag is
 *   skipped.
 *
 *   0x0F Nearby Action: action flags (0x80 auth tag follows), action type, the auth
 *   tag, then type specific parameters.  Only the iOS Setup (0x09) device class, the
 *   high nibble of the first parameter, is read; the Wi-Fi Password hashes are not.
 *
 *   0x06 HomeKit: the length byte carries the length in its low 5 bits.  Status
 *   flags (bit 0 set when not paired), 6 byte device ID, category (LE), global state
 *   number (LE), configuration number, compatible version, optional setup hash.
 *
 *   0x09 AirPlay Target: flags, config seed, IPv4 address.
 *
 *   0x03 AirPrint: address type, resource path type, security type, QID or port, a
 *   16 byte IPv4 or IPv6 address, measured power.  The address is given in IPv6
 *   form, as the dissector shows it.
 *
 *   0x0E Tethering Source: version, flags, battery (2 bytes; percent in the first),
 *   network type, signal bars.
 *
 *   Everything else is noted only as present.  AirDrop hashes of phone numbers and
 *   e-mail addresses, Handoff counters and payloads, the Tethering Target iCloud ID,
 *   Hey Siri and Magic Switch data, and every auth tag are never copied.  Proximity
 *   Pairing (0x07), Find My (0x12) and iBeacon (0x02) are handled elsewhere and
 *   skipped.
 */

#include <cstddef>
#include <cstdint>
#include <string>

namespace btle_continuity {

enum class msg_type : uint8_t {
    observed_on_ios = 0x01,
    airprint = 0x03,
    airdrop = 0x05,
    homekit = 0x06,
    hey_siri = 0x08,
    airplay_target = 0x09,
    airplay_source = 0x0A,
    magic_switch = 0x0B,
    handoff = 0x0C,
    tethering_target = 0x0D,
    tethering_source = 0x0E,
    nearby_action = 0x0F,
    nearby_info = 0x10,
    homekit_encrypted = 0x11,
};

enum class activity_level : uint8_t {
    unknown = 0x00,
    reporting_disabled = 0x01,
    idle = 0x03,
    audio_screen_off = 0x05,
    screen_on = 0x07,
    screen_on_video = 0x09,
    watch_on_wrist_unlocked = 0x0A,
    recent_interaction = 0x0B,
    driving = 0x0D,
    phone_call = 0x0E,
};

enum class action_type : uint8_t {
    none = 0x00,
    apple_tv_setup = 0x01,
    mobile_backup = 0x04,
    watch_setup = 0x05,
    apple_tv_pair = 0x06,
    internet_relay = 0x07,
    wifi_password = 0x08,
    ios_setup = 0x09,
    repair = 0x0A,
    speaker_setup = 0x0B,
    apple_pay = 0x0C,
    whole_home_audio_setup = 0x0D,
    developer_tools_pairing = 0x0E,
    answered_call = 0x0F,
    ended_call = 0x10,
    dd_ping = 0x11,
    dd_pong = 0x12,
    remote_auto_fill = 0x13,
    companion_link_prox = 0x14,
    remote_management = 0x15,
    remote_auto_fill_pong = 0x16,
    remote_display = 0x17,
};

enum class homekit_category : uint16_t {
    unknown = 0,
    other = 1,
    bridge = 2,
    fan = 3,
    garage_door_opener = 4,
    lightbulb = 5,
    door_lock = 6,
    outlet = 7,
    switch_ = 8,
    thermostat = 9,
    sensor = 10,
    security_system = 11,
    door = 12,
    window = 13,
    window_covering = 14,
    programmable_switch = 15,
    range_extender = 16,
    ip_camera = 17,
    video_doorbell = 18,
    air_purifier = 19,
    heater = 20,
    air_conditioner = 21,
    humidifier = 22,
    dehumidifier = 23,
    sprinklers = 28,
    faucets = 29,
    shower_systems = 30,
};

enum class cell_service : uint8_t {
    gsm_4g = 0,
    rtt_1x = 1,
    gprs = 2,
    edge = 3,
    evdo_3g = 4,
    umts_3g = 5,
    g4 = 6,
    lte = 7,
};

struct nearby_info {
    bool present = false;
    activity_level activity = activity_level::unknown;
    /* High nibble of the first byte, shifted down */
    uint8_t status_flags = 0;
    bool primary_device = false;
    bool airdrop_receiving = false;
    /* iOS 11 and later */
    bool has_data_flags = false;
    uint8_t data_flags = 0;
    bool wifi_on = false;
    bool airpods_connected = false;
};

struct nearby_action {
    bool present = false;
    uint8_t flags = 0;
    action_type type = action_type::none;
    /* iOS Setup only, 0 when not given */
    uint8_t device_class = 0;
};

struct homekit {
    bool present = false;
    uint8_t status_flags = 0;
    bool paired = false;
    /* 12 hex digits */
    std::string device_id;
    homekit_category category = homekit_category::unknown;
    uint16_t global_state = 0;
    uint8_t config_number = 0;
    uint8_t compatible_version = 0;
};

struct airplay_target {
    bool present = false;
    uint8_t flags = 0;
    uint8_t config_seed = 0;
    std::string ipv4;
};

struct airprint {
    bool present = false;
    uint8_t address_type = 0;
    uint8_t resource_path_type = 0;
    uint8_t security_type = 0;
    std::string address;
};

struct tethering_source {
    bool present = false;
    uint8_t version = 0;
    uint8_t flags = 0;
    bool battery_known = false;
    uint8_t battery = 0;
    cell_service cell = cell_service::gsm_4g;
    uint8_t signal_bars = 0;
};

struct info {
    /* Bit n set when a message of type n was seen */
    uint32_t seen_types = 0;

    struct nearby_info nearby_info;
    struct nearby_action nearby_action;
    struct homekit homekit;
    struct airplay_target airplay_target;
    struct airprint airprint;
    struct tethering_source tethering_source;
};

/* Manufacturer data: the company ID, then the Continuity messages */
bool decode_manuf_data(const uint8_t *data, size_t len, info& out);

const char *type_str(msg_type t);
const char *activity_str(activity_level a);
const char *action_type_str(action_type a);
const char *homekit_category_str(homekit_category c);
const char *cell_service_str(cell_service c);
const char *device_class_str(uint8_t c);

/* Comma separated names of the types in a seen_types mask */
std::string types_str(uint32_t mask);

}

#endif
