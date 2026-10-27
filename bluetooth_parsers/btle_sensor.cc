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

#include <array>
#include <cstring>

#include "btle_sensor.h"

namespace btle_sensor {

namespace {

constexpr uint16_t ruuvi_company_id = 0x0499;
constexpr uint16_t govee_company_id = 0xEC88;
constexpr uint16_t govee_h5179_company_id = 0x8801;

constexpr uint16_t xiaomi_uuid = 0xFE95;
constexpr uint16_t bthome_uuid = 0xFCD2;
constexpr uint16_t env_sensing_uuid = 0x181A;
constexpr uint16_t eddystone_uuid = 0xFEAA;

/* Outside these a reading is garbage, whatever the format allows */
constexpr double min_temperature = -200.0;
constexpr double max_temperature = 200.0;
constexpr double max_humidity = 100.0;
constexpr double min_pressure = 300.0;
constexpr double max_pressure = 1300.0;
constexpr unsigned int max_battery_mv = 20000;

/* govee-ble's limits for the packed thermo-hygrometer value */
constexpr double govee_min_temperature = -40.0;
constexpr double govee_max_temperature = 100.0;

constexpr uint16_t le16(const uint8_t *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

constexpr uint16_t be16(const uint8_t *p) {
    return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
}

constexpr uint32_t le24(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16);
}

bool set_temperature(info& out, double c) {
    if (out.has_temperature || c < min_temperature || c > max_temperature)
        return false;
    out.has_temperature = true;
    out.temperature_c = c;
    return true;
}

bool set_humidity(info& out, double pct) {
    if (out.has_humidity || pct < 0 || pct > max_humidity)
        return false;
    out.has_humidity = true;
    out.humidity_pct = pct;
    return true;
}

bool set_pressure(info& out, double hpa) {
    if (out.has_pressure || hpa < min_pressure || hpa > max_pressure)
        return false;
    out.has_pressure = true;
    out.pressure_hpa = hpa;
    return true;
}

bool set_battery_mv(info& out, unsigned int mv) {
    if (out.has_battery_mv || mv == 0 || mv > max_battery_mv)
        return false;
    out.has_battery_mv = true;
    out.battery_mv = mv;
    return true;
}

bool has_any(const info& out) {
    return out.has_temperature || out.has_humidity || out.has_pressure ||
        out.has_battery_mv;
}

bool finish(info& out, source src) {
    if (!has_any(out))
        return false;
    out.src = src;
    return true;
}

bool decode_ruuvi(const uint8_t *p, size_t plen, info& out) {
    if (plen < 1)
        return false;

    if (p[0] == 0x05 && plen >= 24) {
        const int16_t t = (int16_t) be16(p + 1);
        const uint16_t h = be16(p + 3);
        const uint16_t pr = be16(p + 5);
        const uint16_t mv = be16(p + 13) >> 5;

        if ((uint16_t) t != 0x8000)
            set_temperature(out, t * 0.005);
        if (h != 0xFFFF)
            set_humidity(out, h * 0.0025);
        if (pr != 0xFFFF)
            set_pressure(out, (pr + 50000) / 100.0);
        if (mv != 0x7FF)
            set_battery_mv(out, 1600 + mv);

        return finish(out, source::ruuvi);
    }

    if (p[0] == 0x03 && plen >= 14) {
        const uint8_t frac = p[3];

        if (frac <= 99) {
            const double t = (p[2] & 0x7F) + frac / 100.0;
            set_temperature(out, (p[2] & 0x80) ? -t : t);
        }
        set_humidity(out, p[1] * 0.5);
        set_pressure(out, (be16(p + 4) + 50000) / 100.0);
        set_battery_mv(out, be16(p + 12));

        return finish(out, source::ruuvi);
    }

    return false;
}

bool decode_govee_thermo(info& out, int16_t t, uint16_t h) {
    const double c = t / 100.0;
    if (c >= govee_min_temperature && c <= govee_max_temperature)
        set_temperature(out, c);
    set_humidity(out, h / 100.0);
    return finish(out, source::govee);
}

/* iBeacon with "INTELLI_ROCKS" which some H5075s append to the 6 byte frame */
constexpr uint8_t govee_glued_suffix_hdr[] = { 0x4C, 0x00, 0x02, 0x15 };
constexpr char govee_glued_suffix_tag[] = "INTELLI_ROCKS";
constexpr size_t govee_glued_suffix_len = 25;

bool decode_govee(uint16_t company, const uint8_t *p, size_t plen, info& out) {
    if (company == govee_h5179_company_id) {
        if (plen != 9)
            return false;
        return decode_govee_thermo(out, (int16_t) le16(p + 4), le16(p + 6));
    }

    if (plen == 6 + govee_glued_suffix_len &&
            memcmp(p + 6, govee_glued_suffix_hdr, sizeof(govee_glued_suffix_hdr)) == 0 &&
            memcmp(p + 6 + sizeof(govee_glued_suffix_hdr), govee_glued_suffix_tag,
                sizeof(govee_glued_suffix_tag) - 1) == 0)
        plen = 6;

    if (plen == 6) {
        if (p[4] & 0x80)
            return false;

        const uint32_t v = ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
        const uint32_t mag = v & 0x7FFFFF;
        double c = (mag / 1000) / 10.0;
        if (v & 0x800000)
            c = -c;

        if (c < govee_min_temperature || c > govee_max_temperature)
            return false;

        set_temperature(out, c);
        set_humidity(out, (mag % 1000) / 10.0);
        return finish(out, source::govee);
    }

    if (plen == 7 || plen == 9)
        return decode_govee_thermo(out, (int16_t) le16(p + 1), le16(p + 3));

    return false;
}

bool decode_xiaomi(const uint8_t *p, size_t plen, info& out) {
    if (plen < 5)
        return false;

    const uint16_t fc = le16(p);

    /* Encrypted, mesh, before v2, or no objects */
    if ((fc & 0x0008) || (fc & 0x0080) || (fc >> 12) < 2 || !(fc & 0x0040))
        return false;

    size_t offt = 5;

    if (fc & 0x0010)
        offt += 6;

    if (fc & 0x0020) {
        if (offt >= plen)
            return false;
        if (p[offt] & 0x20)
            offt++;
        offt++;
    }

    while (offt <= plen && plen - offt >= 3) {
        const uint16_t id = le16(p + offt);
        const uint8_t olen = p[offt + 2];
        const uint8_t *v = p + offt + 3;

        if (olen > plen - offt - 3)
            break;

        offt += 3 + olen;

        if (id == 0x1004 && olen == 2) {
            set_temperature(out, (int16_t) le16(v) / 10.0);
        } else if (id == 0x1006 && olen == 2) {
            set_humidity(out, le16(v) / 10.0);
        } else if (id == 0x100D && olen == 4) {
            set_temperature(out, (int16_t) le16(v) / 10.0);
            set_humidity(out, le16(v + 2) / 10.0);
        }
    }

    return finish(out, source::xiaomi);
}

/* Object lengths from the bthome.io table; 0 unknown, 0xFF a length byte follows */
constexpr uint8_t bthome_variable = 0xFF;

constexpr std::array<uint8_t, 256> make_bthome_lengths() {
    std::array<uint8_t, 256> l{};

    constexpr uint8_t one[] = {
        0x00, 0x01, 0x09, 0x0F, 0x10, 0x11, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x3A, 0x3B, 0x46, 0x57, 0x58, 0x59,
        0x60, 0x64, 0x65,
    };
    constexpr uint8_t two[] = {
        0x02, 0x03, 0x06, 0x07, 0x08, 0x0C, 0x0D, 0x0E, 0x12, 0x13, 0x14, 0x3C, 0x3D,
        0x3F, 0x40, 0x41, 0x43, 0x44, 0x45, 0x47, 0x48, 0x49, 0x4A, 0x51, 0x52, 0x56,
        0x5A, 0x5D, 0x5E, 0x5F, 0x61, 0xF0,
    };
    constexpr uint8_t three[] = { 0x04, 0x05, 0x0A, 0x0B, 0x42, 0x4B, 0xF2 };
    constexpr uint8_t four[] = {
        0x3E, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x55, 0x5B, 0x5C, 0x62, 0x63, 0xF1,
    };

    for (auto id : one)
        l[id] = 1;
    for (auto id : two)
        l[id] = 2;
    for (auto id : three)
        l[id] = 3;
    for (auto id : four)
        l[id] = 4;

    l[0x53] = bthome_variable;
    l[0x54] = bthome_variable;

    return l;
}

constexpr std::array<uint8_t, 256> bthome_lengths = make_bthome_lengths();

bool decode_bthome(const uint8_t *p, size_t plen, info& out) {
    if (plen < 3)
        return false;

    /* Encrypted, or not version 2 */
    if ((p[0] & 0x01) || (p[0] >> 5) != 2)
        return false;

    size_t offt = 1;

    while (offt < plen) {
        const uint8_t id = p[offt++];
        size_t olen = bthome_lengths[id];

        if (olen == 0)
            break;

        if (olen == bthome_variable) {
            if (offt >= plen)
                break;
            olen = p[offt++];
        }

        if (olen > plen - offt)
            break;

        const uint8_t *v = p + offt;
        offt += olen;

        switch (id) {
            case 0x02:
                set_temperature(out, (int16_t) le16(v) * 0.01);
                break;
            case 0x45:
                set_temperature(out, (int16_t) le16(v) * 0.1);
                break;
            case 0x57:
                set_temperature(out, (int8_t) v[0]);
                break;
            case 0x58:
                set_temperature(out, (int8_t) v[0] * 0.35);
                break;
            case 0x03:
                set_humidity(out, le16(v) * 0.01);
                break;
            case 0x2E:
                set_humidity(out, v[0]);
                break;
            case 0x04:
                set_pressure(out, le24(v) * 0.01);
                break;
            case 0x0C:
                set_battery_mv(out, le16(v));
                break;
            default:
                break;
        }
    }

    return finish(out, source::bthome);
}

bool decode_env_sensing(const uint8_t *p, size_t plen, info& out) {
    if (plen == 15) {
        set_temperature(out, (int16_t) le16(p + 6) * 0.01);
        set_humidity(out, le16(p + 8) * 0.01);
        set_battery_mv(out, le16(p + 10));
        return finish(out, source::pvvx);
    }

    if (plen == 13) {
        set_temperature(out, (int16_t) be16(p + 6) * 0.1);
        set_humidity(out, p[8]);
        set_battery_mv(out, be16(p + 10));
        return finish(out, source::atc1441);
    }

    return false;
}

bool decode_eddystone_tlm(const uint8_t *p, size_t plen, info& out) {
    if (plen < 14 || p[0] != 0x20 || p[1] != 0x00)
        return false;

    const uint16_t t = be16(p + 4);

    set_battery_mv(out, be16(p + 2));
    if (t != 0x8000)
        set_temperature(out, (int16_t) t / 256.0);

    return finish(out, source::eddystone_tlm);
}

}

bool decode_service_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 3)
        return false;

    const uint16_t uuid = le16(data);
    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    /* Decode into a fresh record so a failed decode leaves out untouched */
    info r;
    bool ok = false;

    switch (uuid) {
        case xiaomi_uuid:
            ok = decode_xiaomi(p, plen, r);
            break;
        case bthome_uuid:
            ok = decode_bthome(p, plen, r);
            break;
        case env_sensing_uuid:
            ok = decode_env_sensing(p, plen, r);
            break;
        case eddystone_uuid:
            ok = decode_eddystone_tlm(p, plen, r);
            break;
        default:
            break;
    }

    if (ok)
        out = r;
    return ok;
}

bool decode_manuf_data(const uint8_t *data, size_t len, info& out) {
    if (data == nullptr || len < 3)
        return false;

    const uint16_t company = le16(data);
    const uint8_t *p = data + 2;
    const size_t plen = len - 2;

    info r;
    bool ok = false;

    switch (company) {
        case ruuvi_company_id:
            ok = decode_ruuvi(p, plen, r);
            break;
        case govee_company_id:
        case govee_h5179_company_id:
            ok = decode_govee(company, p, plen, r);
            break;
        default:
            break;
    }

    if (ok)
        out = r;
    return ok;
}

const char *source_str(source s) {
    switch (s) {
        case source::ruuvi:
            return "ruuvi";
        case source::xiaomi:
            return "xiaomi";
        case source::govee:
            return "govee";
        case source::bthome:
            return "bthome";
        case source::pvvx:
            return "pvvx";
        case source::atc1441:
            return "atc1441";
        case source::eddystone_tlm:
            return "eddystone_tlm";
        default:
            return "none";
    }
}

}
