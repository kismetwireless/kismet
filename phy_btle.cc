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
#include "kis_net_beast_httpd.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"
#include "messagebus.h"
#include "alertracker.h"
#include "kis_datasource.h"

#include "phy_btle.h"
#include "phy_uav_drone.h"

#include "kaitai/kaitaistream.h"
#include "bluetooth_parsers/btle.h"
#include "xxhash.h"
#include "bluetooth_parsers/btle_tracker.h"
#include "bluetooth_parsers/btle_battery.h"
#include "bluetooth_parsers/btle_beacon.h"
#include "bluetooth_parsers/bt_assigned.h"
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
#define BTLE_ADVDATA_SHORT_NAME                 0x08
#define BTLE_ADVDATA_DEVICE_NAME                0x09
#define BTLE_ADVDATA_TX_POWER_LEVEL             0x0A
#define BTLE_ADVDATA_APPEARANCE                 0x19
#define BTLE_ADVDATA_SERVICE_DATA_UUID16        0x16
#define BTLE_ADVDATA_SERVICE_DATA_UUID32        0x20
#define BTLE_ADVDATA_SERVICE_DATA_UUID128       0x21
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

// Service UUIDs kept per device; a device rarely advertises more than a few
constexpr size_t btle_max_service_data = 8;

// Records the latest payload of a Service Data element, which starts with a uuid_len byte UUID
static void btle_set_service_data(btle_tracked_device *btle_dev, const std::string& payload,
        size_t uuid_len) {
    if (payload.size() < uuid_len)
        return;

    std::string uuid;
    if (uuid_len == 2) {
        uuid = fmt::format("{:04x}", (uint8_t) payload[0] | ((uint16_t)(uint8_t) payload[1] << 8));
    } else if (uuid_len == 4) {
        uuid = fmt::format("{:08x}", (uint8_t) payload[0] | ((uint32_t)(uint8_t) payload[1] << 8) |
                ((uint32_t)(uint8_t) payload[2] << 16) | ((uint32_t)(uint8_t) payload[3] << 24));
    } else {
        uuid = btle_format_uuid128(payload.substr(0, 16));
    }

    auto hex = btle_bytes_to_hex(payload.substr(uuid_len));
    auto sd = btle_dev->get_service_data();
    auto existing = sd->find(uuid);

    if (existing != sd->end()) {
        auto v = std::static_pointer_cast<tracker_element_string>(existing->second);
        if (v->get() != hex)
            v->set(hex);
    } else if (sd->size() < btle_max_service_data) {
        sd->insert(uuid, std::make_shared<tracker_element_string>(hex));
    }
}

// Advertised UUIDs remembered per device; a spoofing advertiser could send endless new ones
constexpr size_t btle_max_service_uuids = 64;

// Appends uuid to vec unless it's already present or the list is full.
static void btle_add_unique_uuid(std::shared_ptr<tracker_element_vector_string> vec,
        const std::string& uuid) {
    if (vec->size() >= btle_max_service_uuids)
        return;

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
    kis_phy_handler(in_phyid),
    random_addrs{random_mode::track},
    related_timer_id{-1} {

    set_phy_name("BTLE");

    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();
    devicetracker->register_type_alias("BTLE Device", "BTLE");
    btmanuf = Globalreg::fetch_global_as<kis_bt_manuf>();
    btoid = Globalreg::fetch_global_as<kis_bt_oid>();

    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();

    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_decap = packetchain->register_packet_component("DECAP");
    pack_comp_btle = packetchain->register_packet_component("BTLE");
    pack_comp_remoteid = packetchain->register_packet_component("UAVREMOTEID");
    pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");

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

    auto conf = Globalreg::globalreg->kismet_config;

    // btle_ignore_random=true is the old way to say btle_random=ignore
    auto mode = conf->fetch_opt("btle_random");
    if (mode.empty() && conf->fetch_opt_bool("btle_ignore_random", false))
        mode = "ignore";

    if (mode == "hide_unmatched") {
        random_addrs = random_mode::hide_unmatched;
    } else if (mode == "ignore") {
        random_addrs = random_mode::ignore;
    } else if (!mode.empty() && mode != "track") {
        _MSG_ERROR("Unknown btle_random={}; expected track, hide_unmatched or ignore.  Tracking "
                "every random address.", mode.substr(0, 32));
    }

    if (random_addrs == random_mode::ignore)
        _MSG_INFO("Ignoring BTLE devices with rotating random MAC addresses (static random "
                "addresses, Remote ID and location trackers are kept)");

    // Hiding the unmatched ones needs to know which match
    const bool want_related = conf->fetch_opt_bool("btle_related", false) ||
        random_addrs == random_mode::hide_unmatched;

    if (want_related && random_addrs != random_mode::ignore) {
        auto quiet = std::clamp(conf->fetch_opt_uint("btle_related_quiet", 60), 1U, 3600U);
        auto max_groups = std::clamp(conf->fetch_opt_uint("btle_related_max_groups", 128), 1U, 65536U);
        auto max_addrs = std::clamp(conf->fetch_opt_uint("btle_related_max_addresses", 64), 2U, 1024U);
        related = std::make_unique<btle_related_tracker>(
                btle_related_tracker::params{(time_t) quiet, max_groups, max_addrs});
        similar = std::make_unique<btle_related_tracker>(
                btle_related_tracker::params{(time_t) quiet, max_groups, max_addrs});

        related_timer_id =
            Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(
                    SERVER_TIMESLICES_SEC * 10, nullptr, 1, [this](int) -> int {
                        std::vector<btle_related_tracker::state> states;
                        kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(),
                                "btle related age");
                        related->age(Globalreg::globalreg->last_tv_sec, states);
                        apply_related_states(states, device_key{});
                        states.clear();
                        similar->age(Globalreg::globalreg->last_tv_sec, states);
                        apply_similar_states(states, device_key{});
                        return 1;
                    });

        _MSG_INFO("Grouping rotating random BTLE addresses which advertise the same payload as "
                "related devices{}", random_addrs == random_mode::hide_unmatched ?
                "; addresses no other address matches are left out of the default device view" : "");
    }

    // Related groups follow a device from address to address, so link them too unless
    // asked not to
    if (conf->fetch_opt_bool("btle_link_randomized", related != nullptr)) {
        // A signal match is within 8 dB, and 4 dB closer than any other candidate
        alias_linker = std::make_unique<randomized_alias_linker>(
                randomized_alias_linker::params{15, 30, 0, "payload", 120, 8, 4});
        _MSG_INFO("Linking random BTLE addresses which appear to be the same device.");
    }

    // The addresses in a device's related or similar group, for the web UI's timeline
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();
    auto group_route = [this, httpd](const std::string& uri,
            std::unique_ptr<btle_related_tracker> kis_btle_phy::*tracker) {
        httpd->register_route(uri, {"GET", "POST"}, httpd->RO_ROLE, {},
                std::make_shared<kis_net_web_tracked_endpoint>(
                    [this, tracker](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                        auto ret = std::make_shared<tracker_element_vector>();
                        auto key = string_to_n<device_key>(con->uri_params()[":key"]);

                        if (key.get_error())
                            throw std::runtime_error("invalid key");

                        if (this->*tracker == nullptr)
                            return ret;

                        for (const auto& k : (this->*tracker)->members_of(key)) {
                            auto d = devicetracker->fetch_device(k);
                            if (d != nullptr)
                                ret->push_back(d);
                        }

                        return ret;
                    }));
    };

    group_route("/phy/btle/related-of/:key/devices", &kis_btle_phy::related);
    group_route("/phy/btle/similar-of/:key/devices", &kis_btle_phy::similar);

    distance_exponent = btle_distance_exponent();

    devtype_tracker = devicetracker->get_cached_display_type("BTLE Tracker");
    continuity_types = std::make_unique<continuity_device_types>(*devicetracker);

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_btadv", "js/kismet.ui.btadv.js");
    httpregistry->register_js_module("kismet_ui_btle", "js/kismet.ui.btle.js");
}

kis_btle_phy::~kis_btle_phy() {
    if (related_timer_id >= 0) {
        auto timetracker = Globalreg::fetch_global_as<time_tracker>();
        if (timetracker != nullptr)
            timetracker->remove_timer(related_timer_id);
    }

    packetchain->remove_handler(&common_classifier, CHAINPOS_CLASSIFIER);
    packetchain->remove_handler(&dissector, CHAINPOS_LLCDISSECT);
}

void kis_btle_phy::apply_similar_states(const std::vector<btle_related_tracker::state>& states,
        const device_key& self) {
    for (const auto& st : states) {
        auto dev = devicetracker->fetch_device(st.key);
        if (dev == nullptr)
            continue;

        auto btle = fetch_btle_record(dev);
        if (btle == nullptr)
            continue;

        btle->set_similar_group(st.group);
        btle->set_similar_count(st.size);
        btle->set_similar_active(st.active);

        if (!(st.key == self))
            dev->update_modtime();
    }
}

void kis_btle_phy::apply_related_states(const std::vector<btle_related_tracker::state>& states,
        const device_key& self) {
    for (const auto& st : states) {
        auto dev = devicetracker->fetch_device(st.key);
        if (dev == nullptr)
            continue;

        auto btle = fetch_btle_record(dev);
        if (btle == nullptr)
            continue;

        btle->set_related_group(st.group);
        btle->set_related_count(st.size);
        btle->set_old_address(st.old);
        btle->set_related_newest(st.newest);
        btle->set_related_truncated(st.truncated);
        btle->set_related_active(st.active);
        // Once an address has shared its payload it stays matched, as its group empties
        if (random_addrs == random_mode::hide_unmatched && (st.size >= 2 || !btle->has_unmatched_random()))
            btle->set_unmatched_random(st.size < 2);

        // Another address's group changed without it sending anything; mark it changed
        // so device rules check it again
        if (!(st.key == self))
            dev->update_modtime();
    }
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

void apply_beacon(btle_tracked_beacon& beacon, const btle_beacon::info& info, time_t now) {
    beacon.set_beacon_type(btle_beacon::type_str(info.type));
    beacon.set_last_time(now);

    switch (info.type) {
        case btle_beacon::beacon_type::ibeacon:
        case btle_beacon::beacon_type::altbeacon:
            beacon.set_uuid(info.uuid);
            beacon.set_major(info.major);
            beacon.set_minor(info.minor);
            break;
        case btle_beacon::beacon_type::eddystone_uid:
            beacon.set_eddystone_namespace(info.eddystone_namespace);
            beacon.set_eddystone_instance(info.eddystone_instance);
            break;
        case btle_beacon::beacon_type::eddystone_url:
            beacon.set_url(info.url);
            break;
        default:
            break;
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

// The parts of an advertisement which stay the same when a device's payload bytes
// change with its address, as Apple Continuity, Fast Pair and Swift Pair payloads do:
// the record types and lengths, the company ID, service UUIDs and names.  0 when
// there's no company or service to tell devices apart by.
static uint64_t btle_structure_fingerprint(const bluetooth_btle& decode) {
    constexpr uint16_t apple_company_id = 0x004c;

    std::string buf;
    bool anchored = false;

    buf.push_back(static_cast<char>(decode.pdu_type()));

    for (const auto& ad : *decode.advertised_data()) {
        const auto type = ad->type();
        const auto& d = ad->data();

        if (type == BTLE_ADVDATA_FLAGS || type == BTLE_ADVDATA_TX_POWER_LEVEL)
            continue;

        buf.push_back(static_cast<char>(type));
        buf.push_back(static_cast<char>(d.length()));

        switch (type) {
            case BTLE_ADVDATA_MANUFACTURER_DATA:
                if (d.length() < 2)
                    break;

                anchored = true;
                buf.append(d, 0, 2);

                // Continuity is a list of type, length, value messages
                if (((uint8_t) d[0] | ((uint16_t) (uint8_t) d[1] << 8)) == apple_company_id) {
                    for (size_t off = 2; off + 2 <= d.length(); off += 2 + (uint8_t) d[off + 1]) {
                        buf.push_back(d[off]);
                        buf.push_back(d[off + 1]);
                    }
                }
                break;

            case BTLE_ADVDATA_SERVICE_UUID16_INCOMPLETE:
            case BTLE_ADVDATA_SERVICE_UUID16_COMPLETE:
            case BTLE_ADVDATA_SERVICE_UUID32_INCOMPLETE:
            case BTLE_ADVDATA_SERVICE_UUID32_COMPLETE:
            case BTLE_ADVDATA_SERVICE_UUID128_INCOMPLETE:
            case BTLE_ADVDATA_SERVICE_UUID128_COMPLETE:
                anchored = anchored || !d.empty();
                buf.append(d);
                break;

            // The service's UUID, not its changing data
            case BTLE_ADVDATA_SERVICE_DATA_UUID16:
                anchored = anchored || d.length() >= 2;
                buf.append(d, 0, std::min<size_t>(d.length(), 2));
                break;
            case BTLE_ADVDATA_SERVICE_DATA_UUID32:
                anchored = anchored || d.length() >= 4;
                buf.append(d, 0, std::min<size_t>(d.length(), 4));
                break;
            case BTLE_ADVDATA_SERVICE_DATA_UUID128:
                anchored = anchored || d.length() >= 16;
                buf.append(d, 0, std::min<size_t>(d.length(), 16));
                break;

            case BTLE_ADVDATA_SHORT_NAME:
            case BTLE_ADVDATA_DEVICE_NAME:
            case BTLE_ADVDATA_APPEARANCE:
                buf.append(d);
                break;

            default:
                break;
        }
    }

    if (!anchored)
        return 0;

    // 0 means no fingerprint
    auto fp = XXH64(buf.data(), buf.length(), 0);
    return fp == 0 ? 1 : fp;
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

// A phone scanning a busy area requests scans from hundreds of advertisers
constexpr size_t btle_related_max = 256;

void btle_add_related(kis_tracked_device_base& dev, const std::string& relationship,
        const device_key& key) {
    auto related = dev.get_related_devices_map();
    auto gi = related->find(relationship);

    if (gi != related->end() &&
            static_cast<tracker_element_device_key_map *>(gi->second.get())->size() >= btle_related_max)
        return;

    dev.add_related_device(relationship, key);
}

// Scan requests, connections and directed advertisements name a second device; record
// the relationship both ways, when both devices are known
void kis_btle_phy::link_peer(kis_tracked_device_base& device, const bluetooth_btle& decode,
        time_t now) {
    if (!decode.has_peer_address())
        return;

    const char *rel, *peer_rel;

    switch (decode.pdu_type()) {
        case 0x1:
            rel = "btle_directed_to";
            peer_rel = "btle_directed_by";
            break;
        case 0x3:
            rel = "btle_scanned";
            peer_rel = "btle_scanned_by";
            break;
        case 0x5:
            rel = "btle_peripheral";
            peer_rel = "btle_central";
            break;
        default:
            return;
    }

    const device_key peer_key(fetch_phyname_hash(), decode.peer_address());

    if (peer_key == device.get_key())
        return;

    auto peer = devicetracker->fetch_device(peer_key);
    if (peer == nullptr)
        return;

    btle_add_related(device, rel, peer_key);
    btle_add_related(*peer, peer_rel, device.get_key());

    if (!decode.has_connect_params())
        return;

    auto pbtle = fetch_btle_record(peer);
    if (pbtle == nullptr)
        return;

    const auto& cp = decode.connect_parameters();
    auto conn = pbtle->get_connection();

    conn->set_central(device.get_macaddr());
    conn->set_access_address(cp.access_address);
    conn->set_interval_us((uint32_t) cp.interval * 1250);
    conn->set_latency(cp.latency);
    conn->set_timeout_ms((uint32_t) cp.timeout * 10);
    conn->set_hop(cp.hop);
    conn->set_last_time(now);
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

    // Another source heard the same frame; it shares the original's decode, which made or
    // updated the device.  Add what this source saw: seen-by, signal, frequency, location.
    if (in_pack->duplicate) {
        if (btle_info->btle_decode == nullptr || !btle_info->btle_decode->has_advertising_address())
            return 1;

        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.phyid = mphy->fetch_phy_id();
        in_pack->common_info.basic_crypt_set = crypt_none;
        in_pack->common_info.type = packet_basic_mgmt;
        in_pack->common_info.source = btle_info->btle_decode->advertising_address();
        in_pack->common_info.transmitter = btle_info->btle_decode->advertising_address();

        mphy->devicetracker->update_common_device(in_pack->common_info.source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_EXISTING_ONLY),
                "BTLE Device");
        return 1;
    }

    if (!in_pack->common_info.common_info_ok) {
        return 0;
    }

    if (btle_info->btle_decode == nullptr)
        return 0;

    return mphy->update_adv_device(in_pack, *btle_info->btle_decode, nullptr) ? 1 : 0;
}

void kis_btle_phy::set_report_info(const std::shared_ptr<kis_packet>& in_pack, const mac_addr& addr) {
    in_pack->common_info.common_info_ok = true;
    in_pack->common_info.phyid = fetch_phy_id();
    in_pack->common_info.basic_crypt_set = crypt_none;
    in_pack->common_info.type = packet_basic_mgmt;
    in_pack->common_info.source = addr;
    in_pack->common_info.transmitter = addr;
    in_pack->common_info.channel = "FHSS";
    in_pack->common_info.freq_khz = 2400000;
}

std::shared_ptr<btle_tracked_device> kis_btle_phy::fetch_btle_device(const mac_addr& addr) {
    auto dev = devicetracker->fetch_device(device_key(fetch_phyname_hash(), addr));
    if (dev == nullptr)
        return nullptr;
    return fetch_btle_record(dev);
}

// The caller fills in_pack->common_info; the signal, location and source come from the packet
bool kis_btle_phy::update_adv_device(const std::shared_ptr<kis_packet>& in_pack,
        const bluetooth_btle& decode, const char *remoteid_transport) {
    // Remote ID and location trackers ride in 16-bit service data (Apple Find My in
    // manufacturer data); both normally use random addresses, so they're kept even when
    // other random devices are ignored
    std::shared_ptr<uav_remoteid_packinfo> remoteid;

    btle_tracker_frames frames;

    btle_battery::info battery_info;
    bool has_battery = false;

    btle_ranging::info ranging_info;

    btle_beacon::info beacon_info;

    int appearance = -1;

    bt_adv_decode adv_decode;

    for (const auto& ad : *decode.advertised_data()) {
        adv_decode.ad(ad->type(), (const uint8_t *) ad->data().data(), ad->data().length());

        if (ad->type() == BTLE_ADVDATA_APPEARANCE && ad->data().length() == 2) {
            appearance = (uint8_t) ad->data()[0] | ((uint8_t) ad->data()[1] << 8);
            continue;
        }

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

            if (beacon_info.type == btle_beacon::beacon_type::none)
                btle_beacon::decode_manuf_data(mdp, md.length(), beacon_info);

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

        if (beacon_info.type == btle_beacon::beacon_type::none)
            btle_beacon::decode_service_data((const uint8_t *) sd.data(), sd.length(), beacon_info);

        if (remoteid == nullptr) {
            auto rid = packetchain->new_packet_component<uav_remoteid_packinfo>();

            if (odid::decode_ble_service_data((const uint8_t *) sd.data(), sd.length(),
                        rid->counter, rid->messages)) {
                rid->transport = remoteid_transport != nullptr ? remoteid_transport :
                    decode.is_extended() ? "BLE extended" : "BLE legacy";
                rid->device_mac = in_pack->common_info.source;
                in_pack->insert(pack_comp_remoteid, rid);
                remoteid = rid;
                continue;
            }
        }

        frames.service_data((const uint8_t *) sd.data(), sd.length());
    }

    bool is_tracker = frames.any();

    // Drop rotating random addresses, the flood of short-lived devices.  Static random
    // addresses last until the device is reset, so fixed devices using them are kept.
    if (decode.is_txaddr_random() && random_addrs == random_mode::ignore &&
            btle_random_address_rotates(in_pack->common_info.source[0]) &&
            remoteid == nullptr && !is_tracker)
        return false;

    // Update with all the options in case we can add signal and frequency
    // in the future
    auto device =
        devicetracker->update_common_device(in_pack->common_info.source, this,
                in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "BTLE");

    if (device == nullptr)
        return false;

    kis_lock_guard<kis_mutex> lk(devicetracker->get_devicelist_mutex(), "btle_common_classifier");

    auto new_dev = false;

    auto btle_dev =
        device->get_sub_as<btle_tracked_device>(btle_device_id);

    if (btle_dev == nullptr) {
        btle_dev = Globalreg::globalreg->entrytracker->get_shared_instance_as<btle_tracked_device>(btle_device_id);
        device->insert(btle_dev);

        new_dev = true;
    }

    // Store the PDU type from the packet
    btle_dev->set_pdu_type(decode.pdu_type());

    if (decode.has_adv_sid())
        btle_dev->set_adv_sid(decode.adv_sid());

    link_peer(*device, decode, in_pack->ts.tv_sec);

    // A company ID names the maker of a random address device, and of a public one with an
    // unlisted OUI; once known it's kept over the random placeholder
    std::shared_ptr<tracker_element_string> company_manuf;
    if (adv_decode.company_id >= 0 && btmanuf != nullptr)
        company_manuf = btmanuf->lookup_device_manuf(adv_decode.company_id);

    if (decode.is_txaddr_random()) {
        if (company_manuf != nullptr) {
            if (device->get_manuf() != company_manuf)
                device->set_manuf(company_manuf);
        } else if (!btle_dev->has_adv() || btle_dev->get_adv()->get_company_name() == nullptr) {
            device->set_manuf(Globalreg::globalreg->manufdb->get_random_manuf());
        }
    } else if (company_manuf != nullptr &&
            Globalreg::globalreg->manufdb->is_unknown_manuf(device->get_manuf())) {
        device->set_manuf(company_manuf);
    }

    if (adv_decode.any())
        apply_adv(*btle_dev->get_adv(), adv_decode, btmanuf.get(), btoid.get(),
                in_pack->ts.tv_sec);

    if (adv_decode.has_continuity)
        continuity_types->apply(*device, adv_decode.continuity);

    if (decode.is_txaddr_random()) {
        const auto rtype = btle_random_address_type(device->get_macaddr()[0]);
        if (!btle_dev->has_random_address_type() || btle_dev->get_random_address_type() != rtype)
            btle_dev->set_random_address_type(rtype);
    }

    for (const auto& ad : *decode.advertised_data()) {
        if (decode.pdu_type() == decode.pdu_adv_ind() ||
                decode.pdu_type() == decode.pdu_adv_scan_ind()) {
            if (ad->length() > 31) {
                auto al = fmt::format("Saw a BTLE advertisement packet with an advertised content "
                        "over 31 bytes; this may indicate a BleedingTooth style attack on the "
                        "Linux BTLE drivers.");
                alertracker->raise_alert(alert_bleedingtooth_ref, in_pack,
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

        } else if (ad->type() == BTLE_ADVDATA_SHORT_NAME && ad->length() >= 2) {
            // A shortened name is a prefix of the complete name; keep a complete name it matches
            auto name = munge_to_printable(ad->data());
            if (device->get_devicename().compare(0, name.length(), name) != 0)
                device->set_devicename(name);

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

        } else if (!is_tracker && ad->type() == BTLE_ADVDATA_SERVICE_DATA_UUID16) {
            // Trackers are left out: their rotating IDs are only kept hashed
            btle_set_service_data(btle_dev.get(), ad->data(), 2);

        } else if (!is_tracker && ad->type() == BTLE_ADVDATA_SERVICE_DATA_UUID32) {
            btle_set_service_data(btle_dev.get(), ad->data(), 4);

        } else if (!is_tracker && ad->type() == BTLE_ADVDATA_SERVICE_DATA_UUID128) {
            btle_set_service_data(btle_dev.get(), ad->data(), 16);
        }
    }

    // Location trackers: decode only, the values are what the tracker advertises
    if (is_tracker) {
        auto tracker = btle_dev->get_tracker();

        apply_tracker_frames(*tracker, frames, in_pack->ts.tv_sec);
        // AirTags and the like keep the type Find My gave them
        if (!continuity_types->is_continuity_type(device->get_display_type()))
            device->set_display_type(devtype_tracker);

        if (tracker_follow_check(*tracker, in_pack->gps_info, in_pack->ts.tv_sec) &&
                alertracker->potential_alert(alert_trackerfollow_ref)) {
            tracker->follow_alerted = true;
            alertracker->raise_alert(alert_trackerfollow_ref, in_pack,
                    mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                    "FHSS", tracker_follow_text(*tracker));
        }
    }

    if (has_battery)
        apply_battery_info(*btle_dev->get_battery(), battery_info, in_pack->ts.tv_sec);

    if (beacon_info.type != btle_beacon::beacon_type::none)
        apply_beacon(*btle_dev->get_beacon(), beacon_info, in_pack->ts.tv_sec);

    if (appearance >= 0 && (!btle_dev->has_appearance() || btle_dev->get_appearance() != appearance)) {
        btle_dev->set_appearance(appearance);
        btle_dev->set_appearance_name(bt_assigned::appearance_name(appearance));
    }

    int rssi;
    if (ranging_info.src != btle_ranging::source::none && btle_packet_rssi(in_pack.get(), rssi))
        apply_ranging(*btle_dev->get_ranging(), ranging_info, rssi, distance_exponent,
                in_pack->ts.tv_sec);

    // The advertising payload of a random address, less what many devices share; 0
    // when there's too little of it to be unique to one device
    const bool rotating = decode.is_txaddr_random() &&
        btle_random_address_rotates(in_pack->common_info.source[0]);
    uint64_t payload_fp = 0;

    if (decode.is_txaddr_random() && (alias_linker != nullptr || (related != nullptr && rotating))) {
        std::string fp_buf;
        fp_buf.push_back(static_cast<char>(decode.pdu_type()));

        for (const auto& ad : *decode.advertised_data()) {
            // Flags and transmit power are the same on many devices
            if (ad->type() == BTLE_ADVDATA_FLAGS || ad->type() == BTLE_ADVDATA_TX_POWER_LEVEL)
                continue;

            fp_buf.push_back(static_cast<char>(ad->type()));
            fp_buf.push_back(static_cast<char>(ad->data().length()));
            fp_buf.append(ad->data());
        }

        if (fp_buf.length() >= 9) {
            payload_fp = XXH64(fp_buf.data(), fp_buf.length(), 0);
            // 0 means no fingerprint
            if (payload_fp == 0)
                payload_fp = 1;
        }
    }

    // Trackers and Remote ID are always shown, and their payloads change with the address
    if (related != nullptr && rotating && !is_tracker && remoteid == nullptr) {
        std::vector<btle_related_tracker::state> states;
        related->observe(payload_fp, device->get_key(), Globalreg::globalreg->last_tv_sec, states);
        apply_related_states(states, device->get_key());

        states.clear();
        similar->observe(btle_structure_fingerprint(decode), device->get_key(),
                Globalreg::globalreg->last_tv_sec, states);
        apply_similar_states(states, device->get_key());
    }

    // Address carryover (Becker et al., PoPETs 2019): a device's advertising payload
    // and its random address change at different times, so the first payload from a
    // new address matching the last one from an address which just went quiet links
    // them
    if (alias_linker != nullptr && payload_fp != 0) {
        // Picks between several devices sending the same payload
        int signal = randomized_alias_linker::no_signal;
        uint64_t source = 0;
        auto ds = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasrc);
        if (ds != nullptr && ds->ref_source != nullptr && btle_packet_rssi(in_pack.get(), rssi)) {
            signal = rssi;
            source = ds->ref_source->get_source_key();
        }

        std::vector<randomized_alias_linker::link> links;
        alias_linker->observe(payload_fp, device->get_key(),
                in_pack->ts.tv_sec, -1, links, signal, source);

        for (const auto& l : links) {
            auto ldev = devicetracker->fetch_device(l.key);
            if (ldev == nullptr)
                continue;

            auto lbtle = fetch_btle_record(ldev);
            if (lbtle == nullptr)
                continue;

            lbtle->set_alias_group(l.group.as_string());

            if (l.method == nullptr)
                continue;

            auto pdev = devicetracker->fetch_device(l.pred);
            auto pbtle = pdev == nullptr ? nullptr : fetch_btle_record(pdev);
            if (pbtle == nullptr)
                continue;

            ldev->add_related_device("btle_randomized_alias", pdev->get_key());
            pdev->add_related_device("btle_randomized_alias", ldev->get_key());
            lbtle->set_alias_method(l.method);

            if (!pbtle->has_alias_group())
                pbtle->set_alias_group(l.group.as_string());
        }
    }

    if (new_dev) {
        if (is_tracker)
            _MSG_INFO("Detected new BTLE location tracker {} ({})",
                    in_pack->common_info.source, frames.describe());
        else if (device->get_devicename().length() > 0)
            _MSG_INFO("Detected new BTLE device {} {}",
                    in_pack->common_info.source, censor::name(device->get_devicename()));
        else
            _MSG_INFO("Detected new BTLE device {}",
                    in_pack->common_info.source);

        if (in_pack->common_info.source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x26") ||
                in_pack->common_info.source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x27")) {
            auto al = fmt::format("A BTLE advertisement packet with a source address "
                    "matching a Flipper Zero device was seen; The Flipper device is "
                    "capable of generating BTLE packets which may cause a denial of "
                    "service or other problems with some BTLE devices.");
            alertracker->raise_alert(alert_flipper_ref, in_pack,
                    mac_addr{}, device->get_macaddr(), mac_addr{}, mac_addr{},
                    "FHSS", al);
        }

    }

    return true;
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

