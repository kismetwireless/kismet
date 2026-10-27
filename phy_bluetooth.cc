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
#include <cstring>
#include <iterator>
#include <unordered_map>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "phy_bluetooth.h"
#include "phy_uav_drone.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "alertracker.h"
#include "kis_datasource.h"

#include "bluetooth_parsers/btle_tracker.h"
#include "bluetooth_parsers/btle_battery.h"
#include "bluetooth_parsers/btle_ranging.h"
#include "bluetooth_parsers/btle_beacon.h"
#include "bluetooth_parsers/bt_assigned.h"



// The class of device rarely changes, so the names are only redone when it does
static void apply_class_of_device(bluetooth_tracked_device& btdev, uint32_t cod) {
    if (!bt_assigned::cod_valid(cod))
        return;

    if (btdev.has_class_of_device() && btdev.get_class_of_device() == cod)
        return;

    const auto major = bt_assigned::cod_major(cod);

    btdev.set_class_of_device(cod);
    btdev.set_major_class(bt_assigned::cod_major_name(major));
    btdev.set_minor_class(bt_assigned::cod_minor_name(major, bt_assigned::cod_minor(cod)));

    auto services = btdev.get_service_classes();
    services->clear();
    for (auto& n : bt_assigned::cod_service_names(cod))
        services->push_back(std::move(n));
}

static void apply_appearance(bluetooth_tracked_device& btdev, uint16_t appearance) {
    if (btdev.has_appearance() && btdev.get_appearance() == appearance)
        return;

    btdev.set_appearance(appearance);
    btdev.set_appearance_name(bt_assigned::appearance_name(appearance));
}

kis_bluetooth_phy::kis_bluetooth_phy(int in_phyid) : 
    kis_phy_handler(in_phyid) {

    alertracker =
        Globalreg::fetch_mandatory_global_as<alert_tracker>();
    packetchain =
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    set_phy_name("Bluetooth");

    bluetooth_device_entry_id =
        entrytracker->register_field("bluetooth.device", 
                tracker_element_factory<bluetooth_tracked_device>(),
                "Bluetooth device");

    packetchain->register_handler(&common_classifier_bluetooth, this, CHAINPOS_CLASSIFIER, -100);
    packetchain->register_handler(&packet_tracker_bluetooth, this, CHAINPOS_TRACKER, -100);
    packetchain->register_handler(&packet_assign_hci, this, CHAINPOS_POSTCAP, 100);
    packetchain->register_handler(&packet_classifier_hci, this, CHAINPOS_CLASSIFIER, -99);
    packetchain->register_handler(&packet_bluetooth_scan_json_classifier, this, CHAINPOS_CLASSIFIER, -99);
    packetchain->register_handler(&packet_bluetooth_hci_json_classifier, this, CHAINPOS_CLASSIFIER, -99);

    pack_comp_btdevice = packetchain->register_packet_component("BTDEVICE");
    pack_comp_meta = packetchain->register_packet_component("METABLOB");
    pack_comp_json = packetchain->register_packet_component("JSON");
    pack_comp_remoteid = packetchain->register_packet_component("UAVREMOTEID");
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");

    btdev_bredr = devicetracker->get_cached_devicetype("BR/EDR");
    btdev_btle = devicetracker->get_cached_devicetype("BTLE");
    btdev_bt = devicetracker->get_cached_devicetype("BT");
    btdev_tracker = devicetracker->get_cached_devicetype("BTLE Tracker");

    alert_trackerfollow_ref = activate_tracker_follow_alert(alertracker, phyid);

    distance_exponent = btle_distance_exponent();

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

    // Register js module for UI
    auto httpregistry = Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_bluetooth", "js/kismet.ui.bluetooth.js");
}

kis_bluetooth_phy::~kis_bluetooth_phy() {
    packetchain->remove_handler(&common_classifier_bluetooth, CHAINPOS_CLASSIFIER);
}

bool kis_bluetooth_phy::device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return (dev->get_sub_as<bluetooth_tracked_device>(bluetooth_device_entry_id) != nullptr);
}

std::shared_ptr<bluetooth_tracked_device> kis_bluetooth_phy::fetch_bluetooth_record(const std::shared_ptr<kis_tracked_device_base>& dev) {
    return dev->get_sub_as<bluetooth_tracked_device>(bluetooth_device_entry_id);
}

int kis_bluetooth_phy::common_classifier_bluetooth(CHAINCALL_PARMS) {
    auto btphy = static_cast<kis_bluetooth_phy *>(auxdata);

    auto btpi = in_pack->fetch<bluetooth_packinfo>(btphy->pack_comp_btdevice);

    if (btpi == NULL) {
        return 0;
    }

    in_pack->common_info.common_info_ok = true;
    in_pack->common_info.phyid = btphy->fetch_phy_id();
    in_pack->common_info.type = packet_basic_mgmt;
    in_pack->common_info.direction = packet_direction_from;
    in_pack->common_info.source = btpi->address;
    in_pack->common_info.transmitter = btpi->address;
    in_pack->common_info.channel = "FHSS";
    in_pack->common_info.freq_khz = 2400000;

    return 0;
}

int kis_bluetooth_phy::packet_bluetooth_hci_json_classifier(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto pack_json =
        in_pack->fetch<kis_json_packinfo>(btphy->pack_comp_json);

    if (pack_json == nullptr)
        return 0;

    if (pack_json->type != "linuxbthci") {
        return 0;
    }

    try {
        std::stringstream newdevstr;
        std::stringstream ss(pack_json->json_string);
        nlohmann::json json;
        ss >> json;

        // auto new_device = false;

        const auto btaddr_j = json["addr"];

        if (btaddr_j.is_null())
            throw std::runtime_error("no btaddr in scan report");

        auto btaddr_mac = mac_addr(btaddr_j.get<std::string>());
        if (btaddr_mac.state.error)
            throw std::runtime_error("invalid btaddr MAC");

        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.phyid = btphy->fetch_phy_id();
        in_pack->common_info.type = packet_basic_mgmt;
        in_pack->common_info.source = btaddr_mac;
        in_pack->common_info.transmitter = btaddr_mac;
        in_pack->common_info.channel = "FHSS";
        in_pack->common_info.freq_khz = 2400000;

        kis_lock_guard<kis_mutex> lk(btphy->devicetracker->get_devicelist_mutex(),
                "packet_bluetooth_hci_json_classifier");

        auto basedev =
            btphy->devicetracker->update_common_device(btaddr_mac, btphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "Bluetooth Device");

        auto btdev =
            basedev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        // Mapped to base name
        auto devname_j = json["name"];

        if (devname_j.is_string())
            basedev->set_devicename(munge_to_printable(devname_j));

        if (btdev == nullptr) {
            std::stringstream ss;
            ss << "Detected new Bluetooth device " << btaddr_mac;
            if (basedev->get_devicename().length() > 0)
                ss << " (" << basedev->get_devicename() << ")";
            _MSG(ss.str(), MSGFLAG_INFO);

            btdev =
                Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

            basedev->insert(btdev);
        }

        // Mapped to base type, a combination of android major/minor
        auto devtype_j = json["type"];

        if (devtype_j.is_number()) {
            switch (devtype_j.get<unsigned int>()) {
                case 0:
                    basedev->set_tracker_type_string(btphy->btdev_bredr);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bredr));
                    break;
                case 1:
                    basedev->set_tracker_type_string(btphy->btdev_btle);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
                    break;
                case 2:
                    basedev->set_tracker_type_string(btphy->btdev_btle);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
                    break;
                default:
                    basedev->set_tracker_type_string(btphy->btdev_bt);
                    btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bt));
                    break;
            }
        }

        // Read connectable flag from HCI capture source
        auto connectable_j = json["connectable"];
        if (connectable_j.is_number()) {
            btdev->set_connectable(connectable_j.get<unsigned int>());
        }

        auto class_j = json["class"];
        if (class_j.is_number_unsigned())
            apply_class_of_device(*btdev, class_j.get<uint32_t>() & 0xFFFFFF);

        auto appearance_j = json["appearance"];
        if (appearance_j.is_number_unsigned() && appearance_j.get<uint32_t>() <= 0xFFFF)
            apply_appearance(*btdev, appearance_j.get<uint16_t>());

        // Service UUIDs and Manufacturer Specific Data, parsed by
        // capture_linux_bluetooth.c's eir_get_uuids_json()/eir_get_manuf().
        // UUIDs accumulate across reports, like phy_btle.cc's
        // service_uuid_vec, since one report's EIR budget may not carry
        // everything advertised.
        btle_tracker_frames frames;

        btle_battery::info battery_info;
        bool has_battery = false;

        btle_ranging::info ranging_info;

        btle_beacon::info beacon_info;

        auto txpower_j = json["txpower"];
        if (txpower_j.is_number_integer()) {
            auto tx = txpower_j.get<int>();
            if (tx >= -127 && tx <= 127) {
                btdev->set_txpower(tx);
                ranging_info = btle_ranging::from_tx_power((int8_t) tx);
            }
        }

        auto uuids_j = json["service_uuids"];
        if (uuids_j.is_array()) {
            auto uuid_vec = btdev->get_service_uuid_strs();
            for (const auto& u : uuids_j) {
                if (!u.is_string())
                    continue;
                auto uuid_str = u.get<std::string>();

                if (uuid_str.length() == 4) {
                    auto ub = hex_to_bytes(uuid_str);
                    if (ub.length() == 2)
                        frames.service_uuid((uint16_t) ((uint8_t) ub[0] << 8 | (uint8_t) ub[1]));
                }

                bool exists = false;
                for (const auto& existing : *uuid_vec) {
                    if (existing == uuid_str) {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                    uuid_vec->push_back(uuid_str);
            }
        }

        auto manuf_company_id_j = json["manuf_company_id"];
        if (manuf_company_id_j.is_string() && manuf_company_id_j.get<std::string>().length() > 0) {
            btdev->set_manuf_company_id(manuf_company_id_j.get<std::string>());
            auto manuf_data_j = json["manuf_data"];
            if (manuf_data_j.is_string()) {
                btdev->set_manuf_data(manuf_data_j.get<std::string>());

                // Reassemble the AD payload, little endian company ID then data
                const auto& cid_hex = manuf_company_id_j.get_ref<const std::string&>();
                const auto& md_hex = manuf_data_j.get_ref<const std::string&>();

                if (cid_hex.length() == 4 && md_hex.length() % 2 == 0) {
                    auto cid = hex_to_bytes(cid_hex);
                    auto md = hex_to_bytes(md_hex);

                    if (cid.length() == 2) {
                        std::string ad;
                        ad.reserve(2 + md.length());
                        ad.push_back(cid[1]);
                        ad.push_back(cid[0]);
                        ad.append(md);

                        frames.manuf_data((const uint8_t *) ad.data(), ad.length());

                        has_battery = btle_battery::decode_manuf_data((const uint8_t *) ad.data(),
                                ad.length(), battery_info);

                        btle_ranging::info ri;
                        if (btle_ranging::decode_manuf_data((const uint8_t *) ad.data(),
                                    ad.length(), ri) && ri.src > ranging_info.src)
                            ranging_info = ri;

                        btle_beacon::decode_manuf_data((const uint8_t *) ad.data(), ad.length(),
                                beacon_info);
                    }
                }
            }
        }

        // 16-bit service data, as hex of the UUID and data; Remote ID goes on to
        // the UAV phy
        auto service_data_j = json["service_data"];
        if (service_data_j.is_array()) {
            for (const auto& sd : service_data_j) {
                if (!sd.is_string())
                    continue;

                const auto& sd_hex = sd.get_ref<const std::string&>();

                if (sd_hex.length() % 2 != 0)
                    continue;

                auto raw = hex_to_bytes(sd_hex);

                if (!has_battery)
                    has_battery = btle_battery::decode_service_data((const uint8_t *) raw.data(),
                            raw.length(), battery_info);

                btle_ranging::info ri;
                if (btle_ranging::decode_service_data((const uint8_t *) raw.data(), raw.length(),
                            ri) && ri.src > ranging_info.src)
                    ranging_info = ri;

                frames.service_data((const uint8_t *) raw.data(), raw.length());

                if (beacon_info.type == btle_beacon::beacon_type::none)
                    btle_beacon::decode_service_data((const uint8_t *) raw.data(), raw.length(),
                            beacon_info);

                // UUID, app code, counter, and at least one message
                if (raw.length() < 4 + odid::message_len)
                    continue;

                auto rid = btphy->packetchain->new_packet_component<uav_remoteid_packinfo>();

                if (odid::decode_ble_service_data((const uint8_t *) raw.data(), raw.length(),
                            rid->counter, rid->messages)) {
                    rid->transport = "BLE (HCI)";
                    rid->device_mac = btaddr_mac;
                    in_pack->insert(btphy->pack_comp_remoteid, rid);
                    break;
                }
            }
        }

        if (frames.any()) {
            auto tracker = btdev->get_tracker();

            apply_tracker_frames(*tracker, frames, in_pack->ts.tv_sec);

            basedev->set_tracker_type_string(btphy->btdev_tracker);

            if (tracker_follow_check(*tracker, in_pack->gps_info, in_pack->ts.tv_sec) &&
                    btphy->alertracker->potential_alert(btphy->alert_trackerfollow_ref)) {
                tracker->follow_alerted = true;
                btphy->alertracker->raise_alert(btphy->alert_trackerfollow_ref, in_pack,
                        mac_addr{}, basedev->get_macaddr(), mac_addr{}, mac_addr{},
                        "FHSS", tracker_follow_text(*tracker));
            }
        }

        if (has_battery)
            apply_battery_info(*btdev->get_battery(), battery_info, in_pack->ts.tv_sec);

        if (beacon_info.type != btle_beacon::beacon_type::none)
            apply_beacon(*btdev->get_beacon(), beacon_info, in_pack->ts.tv_sec);

        int rssi;
        if (ranging_info.src != btle_ranging::source::none &&
                btle_packet_rssi(in_pack.get(), rssi))
            apply_ranging(*btdev->get_ranging(), ranging_info, rssi, btphy->distance_exponent,
                    in_pack->ts.tv_sec);

    } catch (const std::exception& e) {
        in_pack->error = true;
        return 0;
    }

    return 1;
}

int kis_bluetooth_phy::packet_bluetooth_scan_json_classifier(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto pack_json =
        in_pack->fetch<kis_json_packinfo>(btphy->pack_comp_json);

    if (pack_json == nullptr)
        return 0;

    if (pack_json->type != "BLUETOOTHSCAN") { 
        return 0;
    }

    try {
        std::stringstream newdevstr;
        std::stringstream ss(pack_json->json_string);
        nlohmann::json json;
        ss >> json;

        auto btaddr_j = json["btaddr"];

        auto new_device = false;

        if (btaddr_j.is_null()) 
            throw std::runtime_error("no btaddr in scan report");

        auto btaddr_mac = mac_addr(btaddr_j.get<std::string>());
        if (btaddr_mac.state.error)
            throw std::runtime_error("invalid btaddr MAC");

        in_pack->common_info.common_info_ok = true;
        in_pack->common_info.phyid = btphy->fetch_phy_id();
        in_pack->common_info.type = packet_basic_mgmt;
        in_pack->common_info.source = btaddr_mac;
        in_pack->common_info.transmitter = btaddr_mac;
        in_pack->common_info.channel = "FHSS";
        in_pack->common_info.freq_khz = 2400000;

        kis_lock_guard<kis_mutex> lk(btphy->devicetracker->get_devicelist_mutex(),
                "packet_bluetooth_scan_json_classifier");

        auto btdev =
            btphy->devicetracker->update_common_device(btaddr_mac, btphy, in_pack,
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "Bluetooth Device");

        // Mapped to base name
        auto devname_j = json["name"]; 

        // Mapped to base type, a combination of android major/minor
        auto devtype_j = json["devicetype"];

        auto powerlevel_j = json["txpowerlevel"];
        auto pathloss_j = json["pathloss"];

        // Mapped to base signal
        auto signal_j = json["signal"];

        // Scan bytes, hex string, optional
        auto scan_bytes_j = json["scan_data"];

        // Service data bytes, hex string, optional
        auto service_bytes_map_j = json["service_data"];

        if (devname_j.is_string())
            btdev->set_devicename(munge_to_printable(devname_j));

        if (devtype_j.is_string())
            btdev->set_tracker_type_string(btphy->devicetracker->get_cached_devicetype(munge_to_printable(devtype_j)));

        auto btdev_bluetooth =
            btdev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        if (btdev_bluetooth == nullptr) {
            newdevstr << "Detected new HCI Bluetooth device " << btaddr_mac; 

            if (btdev->get_devicename().length() > 0)
                newdevstr << " (" << btdev->get_devicename() << ")";

            if (devtype_j.is_string())
                newdevstr << " " << btdev->get_type_string();

            _MSG_INFO("{}", newdevstr.str());

            btdev_bluetooth = 
                Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

            btdev->insert(btdev_bluetooth);

            new_device = true;
        }

        if (powerlevel_j.is_number())
            btdev_bluetooth->set_txpower(powerlevel_j.get<int>());

        if (pathloss_j.is_number())
            btdev_bluetooth->set_pathloss(pathloss_j.get<int>());

        if (scan_bytes_j.is_string())
            btdev_bluetooth->set_scan_data_from_hex(scan_bytes_j);

        if (service_bytes_map_j.is_object()) {
            for (const auto& u : service_bytes_map_j.items()) {
                auto v = u.value();

                if (!v.is_string())
                    throw std::runtime_error("expected string in service_data map");

                auto bytehex = 
                    std::make_shared<tracker_element_byte_array>();
                bytehex->from_hex(v);

                btdev_bluetooth->get_service_data_bytes()->insert(u.key(), bytehex);
            }
        }

        if (new_device) {
            if (in_pack->common_info.source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x26") ||
                    in_pack->common_info.source.OUI() == mac_addr::OUI((uint8_t *) "\x80\xe1\x27")) {
                auto al = fmt::format("A BTLE advertisement packet with a source address "
                        "matching a Flipper Zero device was seen; The Flipper device is "
                        "capable of generating BTLE packets which may cause a denial of "
                        "service or other problems with some BTLE devices.");
                btphy->alertracker->raise_alert(btphy->alert_flipper_ref, in_pack,
                        mac_addr{}, btdev->get_macaddr(), mac_addr{}, mac_addr{},
                        "FHSS", al);

            }
        }

    } catch (const std::exception& e) {
        _MSG_ERROR("Invalid phybluetooth/BT/BTLE scan report: {}", e.what());
        in_pack->error = true;
        return 0;
    }

    return 1;
}

namespace {

// pcap link types carrying a host's HCI traffic
constexpr int dlt_bluetooth_hci_h4 = 187;
constexpr int dlt_bluetooth_hci_h4_with_phdr = 201;
constexpr int dlt_bluetooth_linux_monitor = 254;

constexpr uint8_t h4_type_event = 0x04;
constexpr uint16_t monitor_opcode_event = 0x03;

namespace hci_event {
constexpr uint8_t inquiry_result = 0x02;
constexpr uint8_t connection_complete = 0x03;
constexpr uint8_t disconnection_complete = 0x05;
constexpr uint8_t remote_name_complete = 0x07;
constexpr uint8_t remote_version_complete = 0x0C;
constexpr uint8_t inquiry_result_rssi = 0x22;
constexpr uint8_t extended_inquiry_result = 0x2F;
constexpr uint8_t le_meta = 0x3E;
}

namespace hci_le_event {
constexpr uint8_t connection_complete = 0x01;
constexpr uint8_t advertising_report = 0x02;
constexpr uint8_t enhanced_connection_complete = 0x0A;
constexpr uint8_t extended_advertising_report = 0x0D;
}

// HCI carries addresses least significant byte first
mac_addr hci_bdaddr(const uint8_t *p) {
    const uint8_t b[6] = {p[5], p[4], p[3], p[2], p[1], p[0]};
    return mac_addr(b, 6);
}

constexpr uint16_t hci_le16(const uint8_t *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

constexpr const char *lmp_version_name(uint8_t v) {
    constexpr const char *names[] = {
        "1.0b", "1.1", "1.2", "2.0", "2.1", "3.0", "4.0", "4.1", "4.2", "5.0", "5.1",
        "5.2", "5.3", "5.4", "6.0", "6.1",
    };
    return v < std::size(names) ? names[v] : nullptr;
}

std::string bytes_hex(const uint8_t *p, size_t len) {
    std::string r;
    r.reserve(len * 2);
    for (size_t i = 0; i < len; i++)
        r += fmt::format("{:02x}", p[i]);
    return r;
}

}

// Applies an advertisement or extended inquiry response: the same records in both
void kis_bluetooth_phy::apply_hci_advdata(const std::shared_ptr<kis_packet>& in_pack,
        kis_tracked_device_base& basedev, bluetooth_tracked_device& btdev,
        const uint8_t *data, size_t len) {
    btle_tracker_frames frames;
    btle_battery::info battery_info;
    bool has_battery = false;
    btle_ranging::info ranging_info;
    btle_beacon::info beacon_info;

    size_t pos = 0;
    while (pos + 2 <= len) {
        const uint8_t rlen = data[pos];

        if (rlen == 0 || pos + 1 + rlen > len)
            break;

        const uint8_t type = data[pos + 1];
        const uint8_t *rd = &data[pos + 2];
        const size_t rdlen = rlen - 1;

        pos += rlen + 1;

        switch (type) {
            case 0x08:
                // Shortened name, only when there's no complete one
                if (basedev.get_devicename().length() == 0)
                    basedev.set_devicename(munge_to_printable(std::string((const char *) rd, rdlen)));
                break;
            case 0x09:
                basedev.set_devicename(munge_to_printable(std::string((const char *) rd, rdlen)));
                break;
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
            case 0x06:
            case 0x07: {
                const size_t ulen = (type <= 0x03) ? 2 : (type <= 0x05) ? 4 : 16;
                auto uuid_vec = btdev.get_service_uuid_strs();

                for (size_t off = 0; off + ulen <= rdlen; off += ulen) {
                    std::string u;

                    if (ulen == 2) {
                        const auto v = hci_le16(rd + off);
                        frames.service_uuid(v);
                        u = fmt::format("{:04x}", v);
                    } else if (ulen == 4) {
                        u = fmt::format("{:08x}", (uint32_t) hci_le16(rd + off) |
                                ((uint32_t) hci_le16(rd + off + 2) << 16));
                    } else {
                        uint8_t be[16];
                        for (size_t b = 0; b < 16; b++)
                            be[b] = rd[off + 15 - b];
                        const auto h = bytes_hex(be, 16);
                        u = fmt::format("{}-{}-{}-{}-{}", h.substr(0, 8), h.substr(8, 4),
                                h.substr(12, 4), h.substr(16, 4), h.substr(20, 12));
                    }

                    if (std::find(uuid_vec->begin(), uuid_vec->end(), u) == uuid_vec->end())
                        uuid_vec->push_back(u);
                }
                break;
            }
            case 0x0A:
                if (rdlen == 1) {
                    btdev.set_txpower((int8_t) rd[0]);
                    if (ranging_info.src == btle_ranging::source::none)
                        ranging_info = btle_ranging::from_tx_power((int8_t) rd[0]);
                }
                break;
            case 0x0D:
                if (rdlen == 3)
                    apply_class_of_device(btdev, (uint32_t) rd[0] | ((uint32_t) rd[1] << 8) |
                            ((uint32_t) rd[2] << 16));
                break;
            case 0x19:
                if (rdlen == 2)
                    apply_appearance(btdev, hci_le16(rd));
                break;
            case 0x16: {
                if (!has_battery)
                    has_battery = btle_battery::decode_service_data(rd, rdlen, battery_info);

                btle_ranging::info ri;
                if (btle_ranging::decode_service_data(rd, rdlen, ri) && ri.src > ranging_info.src)
                    ranging_info = ri;

                if (beacon_info.type == btle_beacon::beacon_type::none)
                    btle_beacon::decode_service_data(rd, rdlen, beacon_info);

                frames.service_data(rd, rdlen);
                break;
            }
            case 0xFF: {
                if (rdlen < 2)
                    break;

                btdev.set_manuf_company_id(fmt::format("{:04x}", hci_le16(rd)));
                btdev.set_manuf_data(bytes_hex(rd + 2, rdlen - 2));

                frames.manuf_data(rd, rdlen);

                if (!has_battery)
                    has_battery = btle_battery::decode_manuf_data(rd, rdlen, battery_info);

                btle_ranging::info ri;
                if (btle_ranging::decode_manuf_data(rd, rdlen, ri) && ri.src > ranging_info.src)
                    ranging_info = ri;

                if (beacon_info.type == btle_beacon::beacon_type::none)
                    btle_beacon::decode_manuf_data(rd, rdlen, beacon_info);
                break;
            }
            default:
                break;
        }
    }

    if (frames.any()) {
        auto tracker = btdev.get_tracker();

        apply_tracker_frames(*tracker, frames, in_pack->ts.tv_sec);
        basedev.set_tracker_type_string(btdev_tracker);

        if (tracker_follow_check(*tracker, in_pack->gps_info, in_pack->ts.tv_sec) &&
                alertracker->potential_alert(alert_trackerfollow_ref)) {
            tracker->follow_alerted = true;
            alertracker->raise_alert(alert_trackerfollow_ref, in_pack,
                    mac_addr{}, basedev.get_macaddr(), mac_addr{}, mac_addr{},
                    "FHSS", tracker_follow_text(*tracker));
        }
    }

    if (has_battery)
        apply_battery_info(*btdev.get_battery(), battery_info, in_pack->ts.tv_sec);

    if (beacon_info.type != btle_beacon::beacon_type::none)
        apply_beacon(*btdev.get_beacon(), beacon_info, in_pack->ts.tv_sec);

    int rssi;
    if (ranging_info.src != btle_ranging::source::none && btle_packet_rssi(in_pack.get(), rssi))
        apply_ranging(*btdev.get_ranging(), ranging_info, rssi, distance_exponent,
                in_pack->ts.tv_sec);
}

// Finds or makes the device a HCI event reports; the caller holds the device list lock
std::shared_ptr<bluetooth_tracked_device> kis_bluetooth_phy::hci_device(
        const std::shared_ptr<kis_packet>& in_pack, const mac_addr& addr, bool le,
        int rssi, std::shared_ptr<kis_tracked_device_base>& basedev) {

    in_pack->common_info.common_info_ok = true;
    in_pack->common_info.phyid = fetch_phy_id();
    in_pack->common_info.type = packet_basic_mgmt;
    in_pack->common_info.source = addr;
    in_pack->common_info.transmitter = addr;
    in_pack->common_info.channel = "FHSS";
    in_pack->common_info.freq_khz = 2400000;

    // 127 is "not available"
    unsigned int flags = UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
        UCD_UPDATE_SEENBY;
    if (rssi < 127) {
        in_pack->signal_info.data_ok = true;
        in_pack->signal_info.signal_type = kis_l1_signal_type_dbm;
        in_pack->signal_info.signal_dbm = rssi;
        in_pack->signal_info.freq_khz = 2400000;
        in_pack->signal_info.channel = "FHSS";
        flags |= UCD_UPDATE_SIGNAL;
    } else {
        in_pack->signal_info.data_ok = false;
    }

    basedev = devicetracker->update_common_device(addr, this, in_pack, flags, "Bluetooth Device");
    if (basedev == nullptr)
        return nullptr;

    auto btdev = basedev->get_sub_as<bluetooth_tracked_device>(bluetooth_device_entry_id);

    if (btdev == nullptr) {
        _MSG_INFO("Detected new Bluetooth device {}", addr);

        btdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(
                bluetooth_device_entry_id);
        basedev->insert(btdev);
    }

    basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

    if (le) {
        basedev->set_tracker_type_string(btdev_btle);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
    } else {
        basedev->set_tracker_type_string(btdev_bredr);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bredr));
    }

    return btdev;
}

// Connection handles are per adapter, so per datasource
uint64_t kis_bluetooth_phy::hci_handle_key(const std::shared_ptr<kis_packet>& in_pack,
        uint16_t handle) {
    uint32_t src = 0;

    auto ds = in_pack->fetch<packetchain_comp_datasource>(pack_comp_datasrc);
    if (ds != nullptr && ds->ref_source != nullptr)
        src = ds->ref_source->get_source_key();

    return ((uint64_t) src << 16) | (handle & 0x0FFF);
}

void kis_bluetooth_phy::hci_handle_set(uint64_t key, const mac_addr& addr) {
    kis_lock_guard<kis_mutex> lk(hci_handle_mutex, "hci_handle_set");

    // A capture missing the disconnects can't grow it forever
    if (hci_handles.size() >= 1024)
        hci_handles.clear();

    hci_handles[key] = addr;
}

bool kis_bluetooth_phy::hci_handle_get(uint64_t key, mac_addr& addr) {
    kis_lock_guard<kis_mutex> lk(hci_handle_mutex, "hci_handle_get");

    auto i = hci_handles.find(key);
    if (i == hci_handles.end())
        return false;

    addr = i->second;
    return true;
}

void kis_bluetooth_phy::hci_handle_clear(uint64_t key) {
    kis_lock_guard<kis_mutex> lk(hci_handle_mutex, "hci_handle_clear");
    hci_handles.erase(key);
}

int kis_bluetooth_phy::packet_assign_hci(CHAINCALL_PARMS) {
    // A version or disconnect only makes sense after the connection that set up its
    // handle, so an adapter's events can't be spread across threads
    auto mphy = static_cast<kis_bluetooth_phy *>(auxdata);

    if (in_pack->assignment_id != 0)
        return 1;

    auto linkchunk = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (linkchunk == nullptr ||
            (linkchunk->dlt != dlt_bluetooth_hci_h4 &&
             linkchunk->dlt != dlt_bluetooth_hci_h4_with_phdr &&
             linkchunk->dlt != dlt_bluetooth_linux_monitor))
        return 1;

    auto ds = in_pack->fetch<packetchain_comp_datasource>(mphy->pack_comp_datasrc);

    if (ds == nullptr || ds->ref_source == nullptr)
        return 1;

    const auto key = ds->ref_source->get_source_key();
    in_pack->assignment_id = key != 0 ? key : 1;

    return 1;
}

int kis_bluetooth_phy::packet_classifier_hci(CHAINCALL_PARMS) {
    // HCI events from a host's controller: what it found scanning, and what it learned
    // connecting to devices
    auto mphy = static_cast<kis_bluetooth_phy *>(auxdata);

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto linkchunk = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (linkchunk == nullptr)
        return 0;

    const auto raw = reinterpret_cast<const uint8_t *>(linkchunk->data());
    const size_t rawlen = linkchunk->length();
    size_t off;

    switch (linkchunk->dlt) {
        case dlt_bluetooth_hci_h4:
            if (rawlen < 1 || raw[0] != h4_type_event)
                return 0;
            off = 1;
            break;
        case dlt_bluetooth_hci_h4_with_phdr:
            // 4 byte direction, then H4
            if (rawlen < 5 || raw[4] != h4_type_event)
                return 0;
            off = 5;
            break;
        case dlt_bluetooth_linux_monitor:
            // Adapter index and opcode, big endian
            if (rawlen < 4 || (((uint16_t) raw[2] << 8) | raw[3]) != monitor_opcode_event)
                return 0;
            off = 4;
            break;
        default:
            return 0;
    }

    // Event code, parameter length, parameters
    if (rawlen < off + 2)
        return 0;

    const uint8_t code = raw[off];
    const size_t plen = raw[off + 1];
    const uint8_t *p = raw + off + 2;

    if (plen > rawlen - off - 2)
        return 0;

    kis_lock_guard<kis_mutex> lk(mphy->devicetracker->get_devicelist_mutex(),
            "packet_classifier_hci");

    std::shared_ptr<kis_tracked_device_base> basedev;

    switch (code) {
        case hci_event::inquiry_result:
        case hci_event::inquiry_result_rssi: {
            // A record per response, as controllers and Linux lay them out: address, page
            // scan modes, class, clock offset, and the RSSI.  Some controllers send the
            // RSSI form with the extra page scan mode byte of the plain one
            const size_t n = plen ? p[0] : 0;

            if (n == 0)
                return 0;

            size_t rec, cod_at, rssi_at = 0;

            if (code == hci_event::inquiry_result) {
                rec = 14;
                cod_at = 9;
            } else if (plen == 1 + n * 15) {
                rec = 15;
                cod_at = 9;
                rssi_at = 14;
            } else {
                rec = 14;
                cod_at = 8;
                rssi_at = 13;
            }

            if (plen < 1 + n * rec)
                return 0;

            for (size_t i = 0; i < n; i++) {
                const uint8_t *r = p + 1 + i * rec;
                const int rssi = rssi_at ? (int8_t) r[rssi_at] : 127;

                auto btdev = mphy->hci_device(in_pack, hci_bdaddr(r), false, rssi, basedev);
                if (btdev == nullptr)
                    continue;

                apply_class_of_device(*btdev, (uint32_t) r[cod_at] | ((uint32_t) r[cod_at + 1] << 8) |
                        ((uint32_t) r[cod_at + 2] << 16));
            }
            break;
        }

        case hci_event::extended_inquiry_result: {
            // One response: address, page scan mode, reserved, class, clock offset, RSSI, EIR
            if (plen < 15 || p[0] != 1)
                return 0;

            auto btdev = mphy->hci_device(in_pack, hci_bdaddr(p + 1), false, (int8_t) p[14],
                    basedev);
            if (btdev == nullptr)
                return 0;

            apply_class_of_device(*btdev, (uint32_t) p[9] | ((uint32_t) p[10] << 8) |
                    ((uint32_t) p[11] << 16));
            mphy->apply_hci_advdata(in_pack, *basedev, *btdev, p + 15, plen - 15);
            break;
        }

        case hci_event::remote_name_complete: {
            if (plen < 7 || p[0] != 0)
                return 0;

            const auto name = reinterpret_cast<const char *>(p + 7);
            const size_t nlen = strnlen(name, plen - 7);

            if (nlen == 0)
                return 0;

            auto btdev = mphy->hci_device(in_pack, hci_bdaddr(p + 1), false, 127, basedev);
            if (btdev == nullptr)
                return 0;

            basedev->set_devicename(munge_to_printable(std::string(name, nlen)));
            break;
        }

        case hci_event::connection_complete:
            // Status, handle, address
            if (plen >= 9 && p[0] == 0)
                mphy->hci_handle_set(mphy->hci_handle_key(in_pack, hci_le16(p + 1)),
                        hci_bdaddr(p + 3));
            return 1;

        case hci_event::disconnection_complete:
            if (plen >= 3 && p[0] == 0)
                mphy->hci_handle_clear(mphy->hci_handle_key(in_pack, hci_le16(p + 1)));
            return 1;

        case hci_event::remote_version_complete: {
            // Status, handle, LMP version, company, subversion
            mac_addr addr;

            if (plen < 8 || p[0] != 0 ||
                    !mphy->hci_handle_get(mphy->hci_handle_key(in_pack, hci_le16(p + 1)), addr))
                return 0;

            // Seen through the host, not the device's own signal
            auto btdev = mphy->hci_device(in_pack, addr, false, 127, basedev);
            if (btdev == nullptr)
                return 0;

            const auto vname = lmp_version_name(p[3]);
            btdev->set_lmp_version(vname != nullptr ? vname : fmt::format("unknown ({})", p[3]));
            btdev->set_chip_manufacturer(fmt::format("{:04x}", hci_le16(p + 4)));
            btdev->set_lmp_subversion(hci_le16(p + 6));
            break;
        }

        case hci_event::le_meta: {
            if (plen < 1)
                return 0;

            const uint8_t sub = p[0];

            if (sub == hci_le_event::connection_complete ||
                    sub == hci_le_event::enhanced_connection_complete) {
                // Subevent, status, handle, role, peer address type, peer address
                if (plen >= 12 && p[1] == 0)
                    mphy->hci_handle_set(mphy->hci_handle_key(in_pack, hci_le16(p + 2)),
                            hci_bdaddr(p + 6));
                return 1;
            }

            if (sub != hci_le_event::advertising_report &&
                    sub != hci_le_event::extended_advertising_report)
                return 0;

            if (plen < 2)
                return 0;

            const size_t n = p[1];
            const bool ext = sub == hci_le_event::extended_advertising_report;
            // Legacy: type, address type, address, data length; extended adds the PHYs,
            // SID, TX power, RSSI, interval and direct address before the length
            const size_t hdr = ext ? 24 : 9;
            size_t pos = 2;

            for (size_t i = 0; i < n; i++) {
                if (pos + hdr > plen)
                    break;

                const uint8_t *r = p + pos;
                const size_t dlen = r[hdr - 1];

                // Legacy reports put the RSSI after the data
                if (pos + hdr + dlen + (ext ? 0 : 1) > plen)
                    break;

                const uint8_t *advdata = r + hdr;
                const int rssi = ext ? (int8_t) r[13] : (int8_t) advdata[dlen];
                const uint8_t addr_type = ext ? r[2] : r[1];

                pos += hdr + dlen + (ext ? 0 : 1);

                // Anonymous extended advertisements have no address
                if (addr_type == 0xFF)
                    continue;

                auto btdev = mphy->hci_device(in_pack, hci_bdaddr(ext ? r + 3 : r + 2), true,
                        rssi, basedev);
                if (btdev == nullptr)
                    continue;

                mphy->apply_hci_advdata(in_pack, *basedev, *btdev, advdata, dlen);
            }
            break;
        }

        default:
            return 0;
    }

    return 1;
}

int kis_bluetooth_phy::packet_tracker_bluetooth(CHAINCALL_PARMS) {
    kis_bluetooth_phy *btphy = (kis_bluetooth_phy *) auxdata;

    auto btpi = in_pack->fetch<bluetooth_packinfo>(btphy->pack_comp_btdevice);

    if (btpi == nullptr)
        return 0;

    if (!in_pack->common_info.common_info_ok) {
        return 0;
    }

    kis_lock_guard<kis_mutex> lk(btphy->devicetracker->get_devicelist_mutex(),
            "packet_tracker_bluetooth");

    std::shared_ptr<kis_tracked_device_base> basedev =
        btphy->devicetracker->update_common_device(in_pack->common_info.source, btphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "Bluetooth");

    if (basedev == nullptr)
        return 0;

    auto btdev =
        basedev->get_sub_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

    if (btdev == nullptr) {
        std::stringstream ss;
        ss << "Detected new Bluetooth device " << btpi->address.mac_to_string();
        if (btpi->name.length() > 0) 
            ss << " (" << btpi->name << ")";
        _MSG(ss.str(), MSGFLAG_INFO);

        btdev = 
            Globalreg::globalreg->entrytracker->get_shared_instance_as<bluetooth_tracked_device>(btphy->bluetooth_device_entry_id);

        basedev->insert(btdev);
    }

    basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

    if (btpi->type == 0) {
        basedev->set_tracker_type_string(btphy->btdev_bredr);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bredr));
    } else if (btpi->type == 1) {
        basedev->set_tracker_type_string(btphy->btdev_btle);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
    } else if (btpi->type == 2) {
        basedev->set_tracker_type_string(btphy->btdev_btle);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::btle));
    } else {
        basedev->set_tracker_type_string(btphy->btdev_bt);
        btdev->set_bt_device_type(static_cast<uint8_t>(bt_device_type::bt));
    }

    // Always set the name, but don't forget a name we used to know
    if (btpi->name.length() > 0)
        basedev->set_devicename(btpi->name);
    else if (basedev->get_devicename().length() == 0) {
        basedev->set_devicename(basedev->get_macaddr().mac_to_string());
    }

    // Set the new tx power
    btdev->set_txpower(btpi->txpower);

    // Reset the service UUID vector
    auto uuid_vec = btdev->get_service_uuid_vec();

    uuid_vec->clear();

    for (auto u : btpi->service_uuid_vec) {
        auto tu = std::make_shared<tracker_element_uuid>(0, u);
        uuid_vec->push_back(tu);
    }

    return 0;
}

void kis_bluetooth_phy::load_phy_storage(shared_tracker_element in_storage, 
        shared_tracker_element in_device) {

    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    // Does the imported record have bt?
    auto btdevi = storage->find(bluetooth_device_entry_id);

    // Adopt it into a dot11
    if (btdevi != storage->end()) {
        auto btdev = 
            std::make_shared<bluetooth_tracked_device>(bluetooth_device_entry_id, 
                    std::static_pointer_cast<tracker_element_map>(btdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(btdev);
    }
}

