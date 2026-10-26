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
#include <memory>

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
#include "xxhash.h"
#include "bluetooth_parsers/btle_tracker.h"

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

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("btle_link_randomized", false)) {
        alias_linker = std::make_unique<randomized_alias_linker>(
                randomized_alias_linker::params{15, 30, 0, "payload", 120});
        _MSG_INFO("Linking random BTLE addresses which appear to be the same device.");
    }

    ignore_random =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("btle_ignore_random", false);

    if (ignore_random)
        _MSG_INFO("Ignoring BTLE devices with random MAC addresses (except Remote ID and "
                "location trackers)");

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

    // Remote ID and location trackers ride in 16-bit service data; both normally use
    // random addresses, so they're kept even when other random devices are ignored
    std::shared_ptr<uav_remoteid_packinfo> remoteid;

    btle_tracker::smarttag_info smarttag;
    bool is_smarttag = false;

    for (const auto& ad : *btle_info->btle_decode->advertised_data()) {
        if (ad->type() != BTLE_ADVDATA_SERVICE_DATA_UUID16)
            continue;

        const auto& sd = ad->data();

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

        if (!is_smarttag)
            is_smarttag = btle_tracker::decode_samsung_smarttag((const uint8_t *) sd.data(),
                    sd.length(), smarttag);
    }

    // Drop randoms
    if (btle_info->btle_decode->is_txaddr_random() && mphy->ignore_random &&
            remoteid == nullptr && !is_smarttag)
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
    if (is_smarttag) {
        auto tracker = btle_dev->get_tracker();

        tracker->set_tracker_type(
                btle_tracker::tracker_type_str(btle_tracker::tracker_type::samsung_smarttag));
        tracker->set_state(smarttag.state);
        tracker->set_state_name(btle_tracker::smarttag_state_str(smarttag.state));
        tracker->set_separated(smarttag.separated());
        tracker->set_battery(btle_tracker::battery_level_str(smarttag.battery()));
        tracker->set_flags(smarttag.flags);
        tracker->set_uwb(smarttag.uwb());
        tracker->set_aging_counter(smarttag.aging_counter);
        tracker->set_privacy_id(btle_bytes_to_hex(smarttag.privacy_id));
        tracker->set_last_time(in_pack->ts.tv_sec);

        device->set_tracker_type_string(mphy->devtype_tracker);
    }

    // Address carryover (Becker et al., PoPETs 2019): a device's advertising payload
    // and its random address change at different times, so the first payload from a
    // new address matching the last one from an address which just went quiet links
    // them
    if (mphy->alias_linker != nullptr && btle_info->btle_decode->is_txaddr_random()) {
        std::string fp_buf;
        fp_buf.push_back(static_cast<char>(btle_info->btle_decode->pdu_type()));

        for (const auto& ad : *btle_info->btle_decode->advertised_data()) {
            // Flags and transmit power are the same on many devices
            if (ad->type() == BTLE_ADVDATA_FLAGS || ad->type() == BTLE_ADVDATA_TX_POWER_LEVEL)
                continue;

            fp_buf.push_back(static_cast<char>(ad->type()));
            fp_buf.push_back(static_cast<char>(ad->data().length()));
            fp_buf.append(ad->data());
        }

        // Too little payload to be unique to one device
        if (fp_buf.length() >= 9) {
            std::vector<randomized_alias_linker::link> links;
            mphy->alias_linker->observe(XXH64(fp_buf.data(), fp_buf.length(), 0), device->get_key(),
                    in_pack->ts.tv_sec, -1, links);

            for (const auto& l : links) {
                auto ldev = mphy->devicetracker->fetch_device(l.key);
                if (ldev == nullptr)
                    continue;

                auto lbtle = mphy->fetch_btle_record(ldev);
                if (lbtle == nullptr)
                    continue;

                lbtle->set_alias_group(l.group.as_string());

                if (l.method == nullptr)
                    continue;

                auto pdev = mphy->devicetracker->fetch_device(l.pred);
                auto pbtle = pdev == nullptr ? nullptr : mphy->fetch_btle_record(pdev);
                if (pbtle == nullptr)
                    continue;

                ldev->add_related_device("btle_randomized_alias", pdev->get_key());
                pdev->add_related_device("btle_randomized_alias", ldev->get_key());
                lbtle->set_alias_method(l.method);

                if (!pbtle->has_alias_group())
                    pbtle->set_alias_group(l.group.as_string());
            }
        }
    }

    if (new_dev) {
        if (is_smarttag)
            _MSG_INFO("Detected new BTLE location tracker {} (Samsung SmartTag, {})",
                    in_pack->common_info.source, btle_tracker::smarttag_state_str(smarttag.state));
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

