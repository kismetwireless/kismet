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

#include "btle_vendor.h"

namespace btle_vendor {

namespace {

constexpr uint16_t microsoft_company_id = 0x0006;
constexpr uint8_t cdp_scenario = 0x01;
constexpr uint8_t swift_pair_beacon_id = 0x03;

constexpr uint16_t fast_pair_uuid = 0xFE2C;
constexpr uint16_t matter_uuid = 0xFFF6;
constexpr uint8_t matter_opcode_commissionable = 0x00;

constexpr size_t max_name_len = 64;

constexpr char hexdigits[] = "0123456789abcdef";

struct name_entry {
    uint16_t id;
    const char *name;
};

/* [MS-CDP] device type SKUs */
constexpr name_entry cdp_device_types[] = {
    { 1, "Xbox One" },
    { 6, "iPhone" },
    { 7, "iPad" },
    { 8, "Android" },
    { 9, "Windows desktop" },
    { 11, "Windows phone" },
    { 12, "Linux" },
    { 13, "Windows IoT" },
    { 14, "Surface Hub" },
    { 15, "Windows laptop" },
    { 16, "Windows tablet" },
};

/* connectedhomeip src/lib/core/CHIPVendorIdentifiers.hpp */
constexpr name_entry matter_vendors[] = {
    { 0x1349, "Apple" },
    { 0x6006, "Google" },
    { 0xFFF1, "Test vendor 1" },
    { 0xFFF2, "Test vendor 2" },
    { 0xFFF3, "Test vendor 3" },
    { 0xFFF4, "Test vendor 4" },
};

/* Bluetooth SIG service_uuids.yaml; member UUIDs from member_uuids.yaml are
 * categorised by what the assignee makes.  ASHA 0xFDF0 is from the Android ASHA
 * specification. */
constexpr name_entry service_classes[] = {
    { 0x1808, "glucose" },
    { 0x1809, "thermometer" },
    { 0x180D, "heart_rate" },
    { 0x1810, "blood_pressure" },
    { 0x1812, "hid" },
    { 0x1814, "running" },
    { 0x1816, "cycling" },
    { 0x1818, "cycling" },
    { 0x181B, "body_composition" },
    { 0x181D, "weight_scale" },
    { 0x181F, "cgm" },
    { 0x1822, "pulse_oximeter" },
    { 0x1826, "fitness_machine" },
    { 0x183A, "insulin" },
    { 0x183E, "activity_monitor" },
    { 0x1840, "health_sensor" },
    { 0x1854, "hearing_aid" },
    { 0x185C, "hid" },
    { 0xFD20, "hearing_aid" },     /* GN Hearing */
    { 0xFD71, "hearing_aid" },     /* GN Hearing */
    { 0xFD75, "insulin" },         /* Insulet */
    { 0xFD76, "insulin" },         /* Insulet */
    { 0xFDE3, "diabetes" },        /* Abbott Diabetes Care */
    { 0xFDF0, "hearing_aid" },     /* ASHA */
    { 0xFDFA, "insulin" },         /* Tandem Diabetes Care */
    { 0xFDFB, "insulin" },         /* Tandem Diabetes Care */
    { 0xFEBC, "cgm" },             /* Dexcom */
    { 0xFEFE, "hearing_aid" },     /* GN Hearing */
};

template<size_t N>
const char *lookup(const name_entry (&table)[N], uint16_t id) {
    for (const auto& e : table) {
        if (e.id == id)
            return e.name;
    }
    return nullptr;
}

/* Printable ASCII only, trailing NULs dropped, capped */
std::string sanitize_name(const uint8_t *data, size_t len) {
    while (len > 0 && data[len - 1] == 0)
        len--;

    if (len > max_name_len)
        len = max_name_len;

    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 0x20 && data[i] < 0x7F)
            r.push_back((char) data[i]);
        else
            r.push_back('?');
    }
    return r;
}

bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

uint16_t le16(const uint8_t *data) {
    return (uint16_t) data[0] | ((uint16_t) data[1] << 8);
}

}

bool decode_microsoft(const uint8_t *data, size_t len, microsoft_info& out) {
    if (data == nullptr || len < 5)
        return false;

    if (le16(data) != microsoft_company_id)
        return false;

    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    if (p[0] == cdp_scenario) {
        /* Scenario, version/device type, version/flags, status */
        if (plen < 4 || (p[1] >> 5) != 1 || (p[2] >> 5) != 1)
            return false;

        out = microsoft_info{};
        out.type = microsoft_type::cdp;
        out.cdp_version = p[1] >> 5;
        out.cdp_device_type = p[1] & 0x1F;
        out.cdp_share_everyone = p[2] & 0x01;
        out.cdp_addr_is_id = p[3] & 0x20;
        out.cdp_status = p[3] & 0x0F;
        return true;
    }

    if (p[0] == swift_pair_beacon_id) {
        /* Beacon ID, sub scenario, RSSI */
        if (plen < 3 || p[1] > 0x02)
            return false;

        const auto mode = static_cast<swift_pair_mode>(p[1]);

        /* BR/EDR only carries the address, then both dual mode forms the CoD */
        size_t offt = mode == swift_pair_mode::bredr ? 9 : 3;

        if (mode != swift_pair_mode::le && offt + 3 > plen)
            return false;

        out = microsoft_info{};
        out.type = microsoft_type::swift_pair;
        out.sp_mode = mode;

        if (mode != swift_pair_mode::le) {
            out.sp_has_cod = true;
            out.sp_cod = (uint32_t) p[offt] | ((uint32_t) p[offt + 1] << 8) |
                ((uint32_t) p[offt + 2] << 16);
            offt += 3;
        }

        out.sp_name = sanitize_name(p + offt, plen - offt);
        return true;
    }

    return false;
}

bool decode_fastpair(const uint8_t *data, size_t len, fastpair_info& out) {
    /* Discoverable is only ever the 3 byte model ID */
    if (data == nullptr || len != 5)
        return false;

    if (le16(data) != fast_pair_uuid)
        return false;

    const uint8_t *p = data + 2;

    out = fastpair_info{};
    out.model_id = ((uint32_t) p[0] << 16) | ((uint32_t) p[1] << 8) | (uint32_t) p[2];
    for (size_t i = 0; i < 3; i++) {
        out.model_id_hex.push_back(hexdigits[p[i] >> 4]);
        out.model_id_hex.push_back(hexdigits[p[i] & 0x0F]);
    }
    return true;
}

bool decode_matter(const uint8_t *data, size_t len, matter_info& out) {
    /* UUID, opcode, discriminator/version, VID, PID, flags */
    if (data == nullptr || len < 10)
        return false;

    if (le16(data) != matter_uuid)
        return false;

    const uint8_t *p = data + 2;

    if (p[0] != matter_opcode_commissionable)
        return false;

    out = matter_info{};
    out.opcode = p[0];
    out.discriminator = ((uint16_t) p[1] | ((uint16_t) p[2] << 8)) & 0x0FFF;
    out.adv_version = p[2] >> 4;
    out.vendor_id = (uint16_t) p[3] | ((uint16_t) p[4] << 8);
    out.product_id = (uint16_t) p[5] | ((uint16_t) p[6] << 8);
    out.additional_data = p[7] & 0x01;
    out.extended_announcement = p[7] & 0x02;
    return true;
}

bool decode_ccc_digital_key(const uint8_t *data, size_t len) {
    if (data == nullptr || len < 2)
        return false;

    return le16(data) == ccc_digital_key_uuid;
}

const char *microsoft_type_str(microsoft_type t) {
    switch (t) {
        case microsoft_type::cdp:
            return "cdp";
        case microsoft_type::swift_pair:
            return "swift_pair";
        default:
            return "none";
    }
}

const char *cdp_device_type_str(uint8_t device_type) {
    const char *n = lookup(cdp_device_types, device_type);
    return n != nullptr ? n : "unknown";
}

const char *swift_pair_mode_str(swift_pair_mode m) {
    switch (m) {
        case swift_pair_mode::le:
            return "le";
        case swift_pair_mode::bredr:
            return "bredr";
        case swift_pair_mode::le_bredr:
            return "le_bredr";
        default:
            return "unknown";
    }
}

const char *matter_vendor_name(uint16_t vendor_id) {
    return lookup(matter_vendors, vendor_id);
}

const char *digital_key_hint(uint16_t uuid16) {
    return uuid16 == ccc_digital_key_uuid ? "ccc_digital_key" : nullptr;
}

const char *vehicle_from_name(const std::string& name) {
    /* S + 16 hex + C */
    if (name.size() != 18 || name.front() != 'S' || name.back() != 'C')
        return nullptr;

    for (size_t i = 1; i < 17; i++) {
        if (!is_hex(name[i]))
            return nullptr;
    }

    return "Tesla";
}

const char *service_class_hint(uint16_t uuid16) {
    return lookup(service_classes, uuid16);
}

}
