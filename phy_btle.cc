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

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <cmath>
#include <memory>
#include <array>
#include <random>

#include <openssl/evp.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"
#include "messagebus.h"
#include "alertracker.h"

#include "phy_btle.h"
#include "phy_uav_drone.h"

#include "kaitai/kaitaistream.h"
#include "bluetooth_parsers/btle.h"
#include "bluetooth_parsers/btle_tracker.h"
#include "bluetooth_parsers/btle_battery.h"
#include "bluetooth_parsers/btle_ranging.h"

#ifndef KDLT_BLUETOOTH_LE_LL
#define KDLT_BLUETOOTH_LE_LL        251
#endif

#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO             256
#endif

class btle_packinfo : public packet_component {
public:
    btle_packinfo() { }

    void reset() {
        btle_decode.reset();
    }

    std::shared_ptr<bluetooth_btle> btle_decode;
};

#define BTLE_ADVDATA_FLAGS                      0x01
#define BTLE_ADVDATA_SERVICE_UUID16_INCOMPLETE  0x02
#define BTLE_ADVDATA_SERVICE_UUID16_COMPLETE    0x03
#define BTLE_ADVDATA_SERVICE_UUID32_INCOMPLETE  0x04
#define BTLE_ADVDATA_SERVICE_UUID32_COMPLETE    0x05
#define BTLE_ADVDATA_SERVICE_UUID128_INCOMPLETE 0x06
#define BTLE_ADVDATA_SERVICE_UUID128_COMPLETE   0x07
#define BTLE_ADVDATA_DEVICE_NAME                0x09
#define BTLE_ADVDATA_TX_POWER_LEVEL             0x0A
#define BTLE_ADVDATA_SERVICE_DATA_UUID16        0x16
#define BTLE_ADVDATA_MANUFACTURER_DATA          0xFF

#define BTLE_ADVDATA_FLAG_LIMITED_DISCOVERABLE      (1 << 0)
#define BTLE_ADVDATA_FLAG_GENERAL_DISCOVERABLE      (1 << 1)
#define BTLE_ADVDATA_FLAG_BREDR_NONSUPP             (1 << 2)
#define BTLE_ADVDATA_FLAG_SIMUL_BREDR_CONTROLLER    (1 << 3)
#define BTLE_ADVDATA_FLAG_SIMUL_BREDR_HOST          (1 << 4)

// Lowercase hex encoding of a byte string.
static std::string btle_bytes_to_hex(const std::string& data) {
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data)
        out += fmt::format("{:02x}", c);
    return out;
}

// On-air 128-bit UUIDs are little-endian; reverse and dash into RFC 4122 form.
static std::string btle_format_uuid128(const std::string& data) {
    if (data.size() != 16)
        return btle_bytes_to_hex(data);

    std::string reversed(data.rbegin(), data.rend());
    std::string hex = btle_bytes_to_hex(reversed);
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
        hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

// Appends uuid to vec unless it's already present.
static void btle_add_unique_uuid(std::shared_ptr<tracker_element_vector_string> vec,
        const std::string& uuid) {
    for (const auto& existing : *vec) {
        if (existing == uuid)
            return;
    }
    vec->push_back(uuid);
}

uint32_t kis_btle_phy::ble_crc24(uint32_t init, const char *buf, size_t len) {
    uint32_t lfsr = init & 0xFFFFFF;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = buf[i];
        for (int j = 0; j < 8; j++) {
            int in = (byte ^ (int)lfsr) & 1;
            lfsr >>= 1;
            byte >>= 1;
            if (in)
                lfsr ^= 0xDA6000u;  /* reflected BLE polynomial */
        }
    }
    return lfsr;
}

kis_btle_phy::kis_btle_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    set_phy_name("BTLE");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_decap = packetchain->register_packet_component("DECAP");
    pack_comp_btle = packetchain->register_packet_component("BTLE");
    pack_comp_remoteid = packetchain->register_packet_component("UAVREMOTEID");

    alert_bleedingtooth_ref =
        alertracker->activate_configured_alert("BLEEDINGTOOTH",
                "EXPLOIT", kis_alert_severity::high,
                "The BleedingTooth attack (CVE-2020-24490) exploits the lack of bounds "
                "checking in the BlueZ stack and may lead to execution in the kernel.  "
                "BleedingTooth attacks use over-sized advertisement packets.",
                phyid);

    // The Bluetooth and BTLE phys both raise FLIPPERZERO; whichever loads second uses the
    // alert the first one registered, registering it again would fail and leave this phy
    // without a valid reference
    alert_flipper_ref = alertracker->find_activated_alert("FLIPPERZERO");
    if (alert_flipper_ref < 0)
        alert_flipper_ref =
            alertracker->activate_configured_alert("FLIPPERZERO",
                    "PROBE", kis_alert_severity::high,
                    "Flipper Zero devices can be used to generate spoofed "
                    "BTLE events which can act as denial of service attacks "
                    "or cause other problems with some Bluetooth devices.", phyid);

    alert_trackerfollow_ref = activate_tracker_follow_alert(alertracker, phyid);

    packetchain->register_handler(&dissector, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&common_classifier, this, CHAINPOS_CLASSIFIER, -100);

    btle_device_id =
        entrytracker->register_field("btle.device",
                tracker_element_factory<btle_tracked_device>(),
                "BTLE device");

    btle_uuid_id =
        entrytracker->register_field("btle.common.uuid_vendor",
                tracker_element_factory<tracker_element_string>(),
                "UUID vendor");

    ignore_random =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("btle_ignore_random", false);

    if (ignore_random)
        _MSG_INFO("Ignoring BTLE devices with random MAC addresses (except Remote ID and "
                "location trackers)");

    distance_exponent = btle_distance_exponent();

    devtype_tracker = devicetracker->get_cached_devicetype("BTLE Tracker");

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_btle", "js/kismet.ui.btle.js");
}

kis_btle_phy::~kis_btle_phy() {
    packetchain->remove_handler(&common_classifier, CHAINPOS_CLASSIFIER);
    packetchain->remove_handler(&dissector, CHAINPOS_LLCDISSECT);
}

bool kis_btle_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return (dev->get_sub_as<btle_tracked_device>(btle_device_id) != nullptr);
}

int kis_btle_phy::dissector(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    if (in_pack->duplicate || in_pack->filtered) {
        return 1;
    }

    // Don't reclassify something that's already been seen
    if (in_pack->common_info.common_info_ok) {
        return 0;
    }

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_decap, mphy->pack_comp_linkframe);

    if (packdata == NULL || (packdata != NULL && packdata->dlt != KDLT_BLUETOOTH_LE_LL))
        return 0;

    // Only advertising channel PDUs, which all use the advertising access address 0x8E89BED6
    // (Core Vol 6 Part B 2.1.2), describe a device.  A data channel PDU (of a connection, or of a
    // connected isochronous stream) parsed as one turns its payload into an advertiser address and
    // advertising data: a device per packet.  The CRC check below rejected them only by accident,
    // with the advertising CRC init, and not when the capture source had checked the CRC already.
    if (packdata->length() < 4)
        return 0;

    const uint32_t access_address =
        (uint32_t) ((uint8_t) packdata->data()[0]) |
        (uint32_t) ((uint8_t) packdata->data()[1]) << 8 |
        (uint32_t) ((uint8_t) packdata->data()[2]) << 16 |
        (uint32_t) ((uint8_t) packdata->data()[3]) << 24;

    if (access_address != 0x8E89BED6)
        return 0;

    // If this packet hasn't been checksummed already at the capture layer,
    // do a checksum now.  We assume the last 3 bytes are the checksum.
    // ticc and nrf don't provide an in-packet checksum, and we rely on the
    // crc_ok from the firmware-specific radio headers that get turned into the
    // bt_radio dlt.
    if (!in_pack->crc_ok) {
        // We need at least the AA, header, and CRC bytes
        if (packdata->length() < (4 + 2 + 3)) {
            in_pack->error = 1;
            return 0;
        }

        uint32_t line_crc;
        line_crc =
            (uint32_t)((uint8_t)(packdata->data()[packdata->length() - 1])) << 16 |
            (uint32_t)((uint8_t)(packdata->data()[packdata->length() - 2])) << 8 |
            (uint32_t)((uint8_t)(packdata->data()[packdata->length() - 3]));

        // Advertising CRC init is 0x555555; the reflected LFSR takes it bit-reversed
        uint32_t packet_crc =
            ble_crc24(0xAAAAAA, packdata->data() + 4, packdata->length() - 7);

        if (packet_crc != line_crc) {
            in_pack->crc_ok = true;
            in_pack->checksum_valid = false;
            return 0;
        }

        in_pack->crc_ok = true;
        in_pack->checksum_valid = true;
    }

    membuf btle_membuf((char *) packdata->data(), (char *) &packdata->data()[packdata->length()]);
    std::istream btle_istream(&btle_membuf);
    auto btle_stream = std::make_shared<kaitai::kstream>(&btle_istream);

    auto btle_info = mphy->packetchain->new_packet_component<btle_packinfo>();

    try {
        auto btle = std::make_shared<bluetooth_btle>();
        btle->parse(btle_stream);

        // Extended advertising headers on the primary channels usually only point
        // at the secondary channel PDU; there's no device to record
        if (!btle->has_advertising_address())
            return 0;

        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.phyid = mphy->fetch_phy_id();
        in_pack->common_info.basic_crypt_set = crypt_none;
        in_pack->common_info.type = packet_basic_mgmt;

        in_pack->common_info.source = btle->advertising_address();
        in_pack->common_info.transmitter = btle->advertising_address();
        // We don't set the channel or freq because it's already in l1info and gets picked
        // up from there automatically

        btle_info->btle_decode = btle;

        in_pack->insert(mphy->pack_comp_btle, btle_info);
    } catch (...) {
        return 0;
    }

    return 0;
}

namespace {

// A separated tracker counts as following once it has been seen this long, at this
// many places this far apart, without a gap long enough to say it was left behind
constexpr time_t follow_min_time = 30 * 60;
constexpr size_t follow_min_locations = 3;
constexpr double follow_min_distance_m = 100.0;
constexpr time_t follow_max_gap = 20 * 60;
constexpr size_t follow_max_points = 8;

double follow_distance_m(double lat1, double lon1, double lat2, double lon2) {
    constexpr double earth_r = 6371000.0;
    constexpr double rad = M_PI / 180.0;

    double dlat = (lat2 - lat1) * rad;
    double dlon = (lon2 - lon1) * rad;
    double a = sin(dlat / 2) * sin(dlat / 2) +
        cos(lat1 * rad) * cos(lat2 * rad) * sin(dlon / 2) * sin(dlon / 2);

    return 2 * earth_r * atan2(sqrt(a), sqrt(1 - a));
}

}

void btle_tracker_frames::manuf_data(const uint8_t *data, size_t len) {
    // Apple devices other than trackers send the same frame when they are lost
    if (!is_findmy)
        is_findmy = btle_tracker::decode_apple_findmy(data, len, findmy) &&
            findmy.location_tracker();
}

void btle_tracker_frames::service_data(const uint8_t *data, size_t len) {
    if (!is_smarttag)
        is_smarttag = btle_tracker::decode_samsung_smarttag(data, len, smarttag);
    if (!is_fmdn)
        is_fmdn = btle_tracker::decode_google_fmdn(data, len, fmdn);
    if (!is_dult)
        is_dult = btle_tracker::decode_dult(data, len, dult);
    if (!is_identified)
        is_identified = btle_tracker::decode_identified_tracker(data, len, identified);
}

void btle_tracker_frames::service_uuid(uint16_t uuid) {
    if (!is_identified)
        is_identified = btle_tracker::identify_service_uuid(uuid, identified);
}

std::string btle_tracker_frames::describe() const {
    if (is_smarttag)
        return fmt::format("Samsung SmartTag, {}", btle_tracker::smarttag_state_str(smarttag.state));
    if (is_findmy)
        return fmt::format("Apple Find My {}, {}",
                btle_tracker::findmy_device_type_str(findmy.device_type()),
                btle_tracker::separated_state_str(findmy.separated()));
    if (is_fmdn)
        return fmt::format("Google FMDN, {}", btle_tracker::fmdn_state_str(fmdn));
    if (is_identified)
        return btle_tracker::tracker_type_str(identified.type);
    if (is_dult)
        return fmt::format("DULT, {}", btle_tracker::separated_state_str(dult.separated()));
    return "unknown";
}

void apply_tracker_frames(btle_tracked_tracker& tracker, const btle_tracker_frames& frames,
        time_t now) {
    // A tracker may send its vendor frame and the DULT frame in turns; the vendor frame
    // names the type, the DULT frame adds the network ID and whether it is separated.
    bool vendor_frame = true;

    if (frames.is_smarttag) {
        const auto& st = frames.smarttag;
        tracker.set_tracker_type(
                btle_tracker::tracker_type_str(btle_tracker::tracker_type::samsung_smarttag));
        tracker.set_state(st.state);
        tracker.set_state_name(btle_tracker::smarttag_state_str(st.state));
        tracker.set_separated(st.separated());
        tracker.set_battery(btle_tracker::battery_level_str(st.battery()));
        tracker.set_flags(st.flags);
        tracker.set_uwb(st.uwb());
        tracker.set_aging_counter(st.aging_counter);
        tracker.set_privacy_id(btle_bytes_to_hex(st.privacy_id));
    } else if (frames.is_findmy) {
        const auto& fm = frames.findmy;
        tracker.set_tracker_type(
                btle_tracker::tracker_type_str(btle_tracker::tracker_type::apple_findmy));
        tracker.set_state(fm.status);
        tracker.set_state_name(btle_tracker::separated_state_str(fm.separated()));
        tracker.set_separated(fm.separated());
        tracker.set_battery(btle_tracker::battery_level_str(fm.battery()));
        tracker.set_flags(fm.status);
        tracker.set_subtype(btle_tracker::findmy_device_type_str(fm.device_type()));
        tracker.set_maintained(fm.maintained());
    } else if (frames.is_fmdn) {
        // The FMDN frame does not say whether the tag is separated; see DULT below
        const auto& fd = frames.fmdn;
        tracker.set_tracker_type(
                btle_tracker::tracker_type_str(btle_tracker::tracker_type::google_fmdn));
        tracker.set_state(fd.frame_type);
        tracker.set_state_name(btle_tracker::fmdn_state_str(fd));
        tracker.set_battery("unknown");
        tracker.set_flags(0);
        tracker.set_ephemeral_id(tracker_privacy_hash(btle_tracker::tracker_type::google_fmdn,
                    fd.ephemeral_id));
    } else if (frames.is_identified) {
        const auto& id = frames.identified;
        tracker.set_tracker_type(btle_tracker::tracker_type_str(id.type));
        tracker.set_state(id.state);
        tracker.set_state_name(id.state_name);
        tracker.set_battery("unknown");
        tracker.set_flags(0);
        if (!id.rotating_id.empty())
            tracker.set_privacy_id(tracker_privacy_hash(id.type, id.rotating_id));
    } else {
        vendor_frame = false;
    }

    if (frames.is_dult) {
        const auto& du = frames.dult;
        tracker.set_network_id(du.network_id);
        tracker.set_separated(du.separated());

        const auto dult_type = btle_tracker::tracker_type_str(btle_tracker::tracker_type::dult);

        if (!vendor_frame && (tracker.get_tracker_type().empty() ||
                    tracker.get_tracker_type() == dult_type)) {
            tracker.set_tracker_type(dult_type);
            tracker.set_state(du.status);
            tracker.set_state_name(btle_tracker::separated_state_str(du.separated()));
            tracker.set_battery("unknown");
            tracker.set_flags(du.status);
        }
    }

    tracker.set_last_time(now);
}

namespace {

const std::array<uint8_t, 16>& tracker_privacy_salt() {
    static const std::array<uint8_t, 16> salt = [] {
        std::array<uint8_t, 16> s;
        std::random_device rd;
        for (auto& b : s)
            b = static_cast<uint8_t>(rd());
        return s;
    }();

    return salt;
}

}

std::string tracker_privacy_hash(btle_tracker::tracker_type type, const std::string& material) {
    if (material.empty())
        return "";

    const auto& salt = tracker_privacy_salt();

    std::string in;
    in.reserve(salt.size() + 1 + material.size());
    in.append(reinterpret_cast<const char *>(salt.data()), salt.size());
    in.push_back(static_cast<char>(type));
    in.append(material);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    if (EVP_Digest(in.data(), in.size(), md, &md_len, EVP_sha256(), nullptr) != 1 || md_len < 8)
        return "";

    return btle_bytes_to_hex(std::string(reinterpret_cast<const char *>(md), 8));
}

bool tracker_follow_check(btle_tracked_tracker& tracker, const kis_gps_packinfo& gps, time_t now) {
    if (!tracker.get_separated() ||
            (tracker.follow_last != 0 && now - tracker.follow_last > follow_max_gap)) {
        tracker.follow_first = 0;
        tracker.follow_alerted = false;
        tracker.follow_points.clear();
    }

    if (!tracker.get_separated()) {
        tracker.follow_last = 0;
        return false;
    }

    if (tracker.follow_first == 0 || now < tracker.follow_first)
        tracker.follow_first = now;
    tracker.follow_last = now;

    if (gps.fix >= 2 && tracker.follow_points.size() < follow_max_points) {
        bool distinct = true;

        for (const auto& p : tracker.follow_points) {
            if (follow_distance_m(p.first, p.second, gps.lat, gps.lon) < follow_min_distance_m) {
                distinct = false;
                break;
            }
        }

        if (distinct)
            tracker.follow_points.emplace_back(gps.lat, gps.lon);
    }

    tracker.set_follow_time(now - tracker.follow_first);
    tracker.set_follow_locations(static_cast<uint8_t>(tracker.follow_points.size()));

    return !tracker.follow_alerted && now - tracker.follow_first >= follow_min_time &&
        tracker.follow_points.size() >= follow_min_locations;
}

std::string tracker_follow_text(btle_tracked_tracker& tracker) {
    auto dc = tracker.get_subtype();

    return fmt::format("A location tracker ({}{}{}) advertising that it is away from its "
            "owner has been seen for {} minutes at {} different places; it may be travelling "
            "with you.", tracker.get_tracker_type(), dc.length() ? ", " : "", dc,
            (tracker.follow_last - tracker.follow_first) / 60,
            tracker.follow_points.size());
}

void apply_battery_info(btle_tracked_battery& battery, const btle_battery::info& info, time_t now) {
    auto pct = [](const btle_battery::level& l) -> int8_t {
        return l.known ? static_cast<int8_t>(l.percent) : -1;
    };

    battery.set_source(info.source != nullptr ? info.source : "unknown");
    battery.set_percent(pct(info.main));
    battery.set_charging(info.main.known && info.main.charging);
    battery.set_last_time(now);

    if (info.millivolts != 0)
        battery.set_millivolts(info.millivolts);

    if (info.has_parts) {
        battery.set_left_percent(pct(info.left));
        battery.set_left_charging(info.left.known && info.left.charging);
        battery.set_right_percent(pct(info.right));
        battery.set_right_charging(info.right.known && info.right.charging);
        battery.set_case_percent(pct(info.case_));
        battery.set_case_charging(info.case_.known && info.case_.charging);
    }
}

// A worse power source only replaces a better one the device stopped sending
constexpr time_t ranging_source_hold = 300;
// Signal smoothing, restarted after a gap
constexpr double ranging_rssi_alpha = 0.25;
constexpr time_t ranging_rssi_gap = 30;

void apply_ranging(btle_tracked_ranging& ranging, const btle_ranging::info& info, int rssi,
        double exponent, time_t now) {
    const auto rank = static_cast<uint8_t>(info.src);

    if (rank == 0)
        return;

    if (rank >= ranging.src_rank || now - ranging.src_time > ranging_source_hold) {
        ranging.src_rank = rank;
        ranging.set_source(btle_ranging::source_str(info.src));
        ranging.set_ref_power(static_cast<int16_t>(info.ref_1m));
    }

    if (rank == ranging.src_rank)
        ranging.src_time = now;

    double avg = rssi;
    auto last = ranging.get_last_time();

    if (last != 0 && now >= last && now - last <= ranging_rssi_gap)
        avg = ranging.get_rssi() + ranging_rssi_alpha * (rssi - ranging.get_rssi());

    ranging.set_rssi(avg);
    ranging.set_distance(btle_ranging::estimate_distance(ranging.get_ref_power(), avg, exponent));
    ranging.set_last_time(now);
}

bool btle_packet_rssi(const kis_packet *in_pack, int& rssi) {
    const auto& sig = in_pack->signal_info;

    // 0 is unset and 127 is the controller's "not available"
    if (sig.signal_type != kis_l1_signal_type_dbm || sig.signal_dbm == 0 ||
            sig.signal_dbm >= 20 || sig.signal_dbm < -127)
        return false;

    rssi = sig.signal_dbm;
    return true;
}

double btle_distance_exponent() {
    double e = 2.0;

    try {
        e = Globalreg::globalreg->kismet_config->fetch_opt_as<double>("btle_distance_exponent", 2.0);
    } catch (const std::runtime_error&) {
        _MSG_ERROR("Invalid btle_distance_exponent, using 2.0");
    }

    if (!(e >= 1.0 && e <= 6.0)) {
        _MSG_ERROR("btle_distance_exponent must be between 1.0 and 6.0, using 2.0");
        e = 2.0;
    }

    return e;
}

int activate_tracker_follow_alert(const std::shared_ptr<alert_tracker>& alertracker, int phyid) {
    auto ref = alertracker->find_activated_alert("TRACKERFOLLOW");

    if (ref < 0)
        ref = alertracker->activate_configured_alert("TRACKERFOLLOW",
                "OTHER", kis_alert_severity::high,
                "A Bluetooth location tracker (AirTag, SmartTag, Find Hub, or another "
                "finding network tag) which advertises that it is away from its owner has "
                "been seen for over 30 minutes at three or more places at least 100 meters "
                "apart.  This needs GPS.  An unknown tracker moving with you may be used to "
                "follow you; check for it with the tracker owner's sound feature or a "
                "tracker detection app.", phyid);

    return ref;
}

int kis_btle_phy::common_classifier(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_btle_phy *>(auxdata);

    if (in_pack->filtered)
        return 1;

    auto btle_info = in_pack->fetch<btle_packinfo>(mphy->pack_comp_btle);
    if (btle_info == nullptr)
        return 0;

    if (!in_pack->common_info.common_info_ok) {
        return 0;
    }

    if (btle_info->btle_decode == nullptr)
        return 0;

    // Remote ID and location trackers ride in 16-bit service data (Apple Find My in
    // manufacturer data); both normally use random addresses, so they're kept even when
    // other random devices are ignored
    std::shared_ptr<uav_remoteid_packinfo> remoteid;

    btle_tracker_frames frames;

    btle_battery::info battery_info;
    bool has_battery = false;

    btle_ranging::info ranging_info;

    for (const auto& ad : *btle_info->btle_decode->advertised_data()) {
        if (ad->type() == BTLE_ADVDATA_TX_POWER_LEVEL && ad->data().length() == 1) {
            if (ranging_info.src == btle_ranging::source::none)
                ranging_info = btle_ranging::from_tx_power((int8_t) ad->data()[0]);
            continue;
        }

        if (ad->type() == BTLE_ADVDATA_MANUFACTURER_DATA) {
            const auto& md = ad->data();
            const auto mdp = (const uint8_t *) md.data();

            frames.manuf_data(mdp, md.length());

            if (!has_battery)
                has_battery = btle_battery::decode_manuf_data(mdp, md.length(), battery_info);

            btle_ranging::info ri;
            if (btle_ranging::decode_manuf_data(mdp, md.length(), ri) && ri.src > ranging_info.src)
                ranging_info = ri;

            continue;
        }

        if (ad->type() == BTLE_ADVDATA_SERVICE_UUID16_INCOMPLETE ||
                ad->type() == BTLE_ADVDATA_SERVICE_UUID16_COMPLETE) {
            const auto& ul = ad->data();
            for (size_t off = 0; off + 2 <= ul.size(); off += 2)
                frames.service_uuid((uint8_t) ul[off] | ((uint16_t)(uint8_t) ul[off + 1] << 8));
            continue;
        }

        if (ad->type() != BTLE_ADVDATA_SERVICE_DATA_UUID16)
            continue;

        const auto& sd = ad->data();

        if (!has_battery)
            has_battery = btle_battery::decode_service_data((const uint8_t *) sd.data(),
                    sd.length(), battery_info);

        {
            btle_ranging::info ri;
            if (btle_ranging::decode_service_data((const uint8_t *) sd.data(), sd.length(), ri) &&
                    ri.src > ranging_info.src)
                ranging_info = ri;
        }

        if (remoteid == nullptr) {
            auto rid = mphy->packetchain->new_packet_component<uav_remoteid_packinfo>();

            if (odid::decode_ble_service_data((const uint8_t *) sd.data(), sd.length(),
                        rid->counter, rid->messages)) {
                rid->transport = btle_info->btle_decode->is_extended() ? "BLE extended" : "BLE legacy";
                rid->device_mac = in_pack->common_info.source;
                in_pack->insert(mphy->pack_comp_remoteid, rid);
                remoteid = rid;
                continue;
            }
        }

        frames.service_data((const uint8_t *) sd.data(), sd.length());
    }

    bool is_tracker = frames.any();

    // Drop randoms
    if (btle_info->btle_decode->is_txaddr_random() && mphy->ignore_random &&
            remoteid == nullptr && !is_tracker)
        return 0;

#if 0
    if (in_pack->duplicate) {
        auto device =
            mphy->devicetracker->update_common_device(common,
                    common->source, mphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_LOCATION | UCD_UPDATE_SEENBY),
                    "BTLE");
        return 1;
    }
#endif

    // Update with all the options in case we can add signal and frequency
    // in the future
    auto device =
        mphy->devicetracker->update_common_device(in_pack->common_info.source, mphy,
                in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "BTLE");

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(), "btle_common_classifier");

    auto new_dev = false;

    auto btle_dev =
        device->get_sub_as<btle_tracked_device>(mphy->btle_device_id);

    if (btle_dev == nullptr) {
        btle_dev = Globalreg::globalreg->entrytracker->get_shared_instance_as<btle_tracked_device>(mphy->btle_device_id);
        device->insert(btle_dev);

        new_dev = true;
    }

    // Store the PDU type from the packet
    btle_dev->set_pdu_type(btle_info->btle_decode->pdu_type());

    if (btle_info->btle_decode->is_txaddr_random())
        device->set_manuf(Globalreg::globalreg->manufdb->get_random_manuf());

    for (auto ad : *btle_info->btle_decode->advertised_data()) {
        if (btle_info->btle_decode->pdu_type() == btle_info->btle_decode->pdu_adv_ind() ||
                btle_info->btle_decode->pdu_type() == btle_info->btle_decode->pdu_adv_scan_ind()) {
            if (ad->length() > 31) {
                auto al = fmt::format("Saw a BTLE advertisement packet with an advertised content "
                        "over 31 bytes; this may indicate a BleedingTooth style attack on the "
                        "Linux BTLE drivers.");
                mphy->alertracker->raise_alert(mphy->alert_bleedingtooth_ref, in_pack,
                        mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                        "FHSS", al);
            }
        }

        if (ad->type() == BTLE_ADVDATA_FLAGS && ad->length() == 2) {
            uint8_t flags = ad->data().data()[0];

            btle_dev->set_le_limited_discoverable(flags & BTLE_ADVDATA_FLAG_LIMITED_DISCOVERABLE);
            btle_dev->set_le_general_discoverable(flags & BTLE_ADVDATA_FLAG_GENERAL_DISCOVERABLE);
            btle_dev->set_br_edr_unsupported(flags & BTLE_ADVDATA_FLAG_BREDR_NONSUPP);
            btle_dev->set_simultaneous_br_edr_host(flags & BTLE_ADVDATA_FLAG_SIMUL_BREDR_HOST);
            btle_dev->set_simultaneous_br_edr_controller(flags & BTLE_ADVDATA_FLAG_SIMUL_BREDR_CONTROLLER);

        } else if (ad->type() == BTLE_ADVDATA_DEVICE_NAME && ad->length() >= 2) {
            device->set_devicename(munge_to_printable(ad->data()));

        } else if ((ad->type() == BTLE_ADVDATA_SERVICE_UUID16_INCOMPLETE ||
                    ad->type() == BTLE_ADVDATA_SERVICE_UUID16_COMPLETE) && ad->length() >= 3) {
            // Concatenated 16-bit UUIDs, little-endian.
            const std::string& payload = ad->data();
            auto uuid_vec = btle_dev->get_service_uuid_vec();
            for (size_t off = 0; off + 2 <= payload.size(); off += 2) {
                uint16_t val = (uint8_t) payload[off] | ((uint16_t)(uint8_t) payload[off + 1] << 8);
                btle_add_unique_uuid(uuid_vec, fmt::format("{:04x}", val));
            }

        } else if ((ad->type() == BTLE_ADVDATA_SERVICE_UUID32_INCOMPLETE ||
                    ad->type() == BTLE_ADVDATA_SERVICE_UUID32_COMPLETE) && ad->length() >= 5) {
            const std::string& payload = ad->data();
            auto uuid_vec = btle_dev->get_service_uuid_vec();
            for (size_t off = 0; off + 4 <= payload.size(); off += 4) {
                uint32_t val = (uint8_t) payload[off] | ((uint32_t)(uint8_t) payload[off + 1] << 8) |
                    ((uint32_t)(uint8_t) payload[off + 2] << 16) |
                    ((uint32_t)(uint8_t) payload[off + 3] << 24);
                btle_add_unique_uuid(uuid_vec, fmt::format("{:08x}", val));
            }

        } else if ((ad->type() == BTLE_ADVDATA_SERVICE_UUID128_INCOMPLETE ||
                    ad->type() == BTLE_ADVDATA_SERVICE_UUID128_COMPLETE) && ad->length() >= 17) {
            const std::string& payload = ad->data();
            auto uuid_vec = btle_dev->get_service_uuid_vec();
            for (size_t off = 0; off + 16 <= payload.size(); off += 16) {
                btle_add_unique_uuid(uuid_vec, btle_format_uuid128(payload.substr(off, 16)));
            }

        } else if (ad->type() == BTLE_ADVDATA_MANUFACTURER_DATA && ad->length() >= 3) {
            // First 2 bytes are the company identifier, little-endian.
            const std::string& payload = ad->data();
            uint16_t company_id = (uint8_t) payload[0] | ((uint16_t)(uint8_t) payload[1] << 8);
            btle_dev->set_manuf_company_id(fmt::format("{:04x}", company_id));
            btle_dev->set_manuf_data(btle_bytes_to_hex(payload.substr(2)));
        }
    }

    // Location trackers: decode only, the values are what the tracker advertises
    if (is_tracker) {
        auto tracker = btle_dev->get_tracker();

        apply_tracker_frames(*tracker, frames, in_pack->ts.tv_sec);
        device->set_tracker_type_string(mphy->devtype_tracker);

        if (tracker_follow_check(*tracker, in_pack->gps_info, in_pack->ts.tv_sec) &&
                mphy->alertracker->potential_alert(mphy->alert_trackerfollow_ref)) {
            tracker->follow_alerted = true;
            mphy->alertracker->raise_alert(mphy->alert_trackerfollow_ref, in_pack,
                    mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                    "FHSS", tracker_follow_text(*tracker));
        }
    }

    if (has_battery)
        apply_battery_info(*btle_dev->get_battery(), battery_info, in_pack->ts.tv_sec);

    int rssi;
    if (ranging_info.src != btle_ranging::source::none && btle_packet_rssi(in_pack.get(), rssi))
        apply_ranging(*btle_dev->get_ranging(), ranging_info, rssi, mphy->distance_exponent,
                in_pack->ts.tv_sec);

    if (new_dev) {
        if (is_tracker)
            _MSG_INFO("Detected new BTLE location tracker {} ({})",
                    in_pack->common_info.source, frames.describe());
        else if (device->get_devicename().length() > 0)
            _MSG_INFO("Detected new BTLE device {} {}",
                    in_pack->common_info.source, device->get_devicename());
        else
            _MSG_INFO("Detected new BTLE device {}",
                    in_pack->common_info.source);

        if (in_pack->common_info.source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x26") ||
                in_pack->common_info.source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x27")) {
            auto al = fmt::format("A BTLE advertisement packet with a source address "
                    "matching a Flipper Zero device was seen; The Flipper device is "
                    "capable of generating BTLE packets which may cause a denial of "
                    "service or other problems with some BTLE devices.");
            mphy->alertracker->raise_alert(mphy->alert_flipper_ref, in_pack,
                    mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                    "FHSS", al);
        }

    }

    return 1;
}

void kis_btle_phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto nrfdevi = storage->find(btle_device_id);

    if (nrfdevi != storage->end()) {
        auto nrfdev =
            std::make_shared<btle_tracked_device>(btle_device_id,
                    std::static_pointer_cast<tracker_element_map>(nrfdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(nrfdev);
    }
}

