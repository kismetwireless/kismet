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

#include <cmath>

#include "gpsubx_v1.h"

namespace {
    // UBX is little endian
    uint16_t get_u16(const uint8_t *p) {
        return static_cast<uint16_t>(p[0] | (p[1] << 8));
    }

    uint32_t get_u32(const uint8_t *p) {
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
            (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    }

    int32_t get_i32(const uint8_t *p) {
        return static_cast<int32_t>(get_u32(p));
    }

    // gpsFix / fixType to a Kismet 2d/3d fix; dead reckoning alone is treated as 2d, and
    // a time-only fix has no position
    constexpr int map_fix(uint8_t fix_type) {
        switch (fix_type) {
            case 1:
            case 2:
                return 2;
            case 3:
            case 4:
                return 3;
            default:
                return 0;
        }
    }

    // The receiver reported no usable fix, which invalidates the current location
    gps_ubx_decoder_v1::result no_fix(gps_fix_update& update) {
        update.has_fix = true;
        update.fix_reported = true;
        update.fix = 1;
        return gps_ubx_decoder_v1::result::update;
    }

    constexpr double mm_s_to_kph = 0.0036;
    constexpr double cm_s_to_kph = 0.036;

    // Degrees * 1e7 to a position, if it's on the planet
    bool set_position(int32_t lat_e7, int32_t lon_e7, gps_fix_update& update) {
        const double lat = lat_e7 * 1e-7;
        const double lon = lon_e7 * 1e-7;

        if (lat < -90 || lat > 90 || lon < -180 || lon > 180)
            return false;

        update.has_position = true;
        update.lat = lat;
        update.lon = lon;
        return true;
    }

    // Degrees * 1e5 to 0-360
    double heading_e5(int32_t h) {
        double v = std::fmod(h * 1e-5, 360.0);
        return v < 0 ? v + 360.0 : v;
    }
}

gps_ubx_decoder_v1::result gps_ubx_decoder_v1::decode(std::string_view frame, gps_fix_update& update) {
    update = gps_fix_update{};

    if (frame.size() < header_len + checksum_len)
        return result::malformed;

    const auto *f = reinterpret_cast<const uint8_t *>(frame.data());
    const size_t len = get_u16(f + 4);

    if (frame.size() != header_len + len + checksum_len)
        return result::malformed;

    const uint8_t msg_class = f[2];
    const uint8_t msg_id = f[3];
    const uint8_t *p = f + header_len;

    if (msg_class != class_nav)
        return result::ignored;

    switch (msg_id) {
        case nav_pvt: {
            // 84 bytes on u-blox 7, 92 on later receivers; the fields used are in both
            if (len < 84)
                return result::malformed;

            const int pvt_fix = map_fix(p[20]);
            const bool pvt_fix_ok = (p[21] & 0x01) != 0;

            fix = pvt_fix;
            fix_ok = pvt_fix_ok;

            if (!pvt_fix_ok || pvt_fix < 2)
                return no_fix(update);

            if (!set_position(get_i32(p + 28), get_i32(p + 24), update))
                return result::malformed;

            update.has_fix = true;

            update.fix_reported = true;
            update.fix = pvt_fix;

            if (pvt_fix >= 3) {
                update.has_alt = true;
                update.alt = get_i32(p + 36) / 1000.0;
            }

            const int32_t ground_speed = get_i32(p + 60);
            if (ground_speed >= 0) {
                update.has_speed = true;
                update.speed = ground_speed * mm_s_to_kph;
            }

            update.has_heading = true;
            update.heading = heading_e5(get_i32(p + 64));

            return result::update;
        }

        case nav_status: {
            if (len < 16)
                return result::malformed;

            fix = map_fix(p[4]);
            fix_ok = (p[5] & 0x01) != 0;

            if (!fix_ok || fix < 2)
                return no_fix(update);

            update.has_fix = true;

            update.fix_reported = true;
            update.fix = fix;
            return result::update;
        }

        case nav_sol: {
            if (len < 52)
                return result::malformed;

            fix = map_fix(p[10]);
            fix_ok = (p[11] & 0x01) != 0;

            if (!fix_ok || fix < 2)
                return no_fix(update);

            update.has_fix = true;

            update.fix_reported = true;
            update.fix = fix;
            return result::update;
        }

        case nav_posllh: {
            if (len < 28)
                return result::malformed;

            if (!fix_ok || fix < 2)
                return result::ignored;

            if (!set_position(get_i32(p + 8), get_i32(p + 4), update))
                return result::malformed;

            if (fix >= 3) {
                update.has_alt = true;
                update.alt = get_i32(p + 16) / 1000.0;
            }

            return result::update;
        }

        case nav_velned: {
            if (len < 36)
                return result::malformed;

            if (!fix_ok || fix < 2)
                return result::ignored;

            update.has_speed = true;
            update.speed = get_u32(p + 20) * cm_s_to_kph;

            update.has_heading = true;
            update.heading = heading_e5(get_i32(p + 24));

            return result::update;
        }

        default:
            return result::ignored;
    }
}

bool gps_ubx_decoder_v1::frame_id(std::string_view frame, uint8_t& msg_class, uint8_t& msg_id) {
    if (frame.size() < header_len + checksum_len)
        return false;

    msg_class = static_cast<uint8_t>(frame[2]);
    msg_id = static_cast<uint8_t>(frame[3]);
    return true;
}

bool gps_ubx_decoder_v1::parse_ack(std::string_view frame, ubx_ack& ack) {
    uint8_t c, i;

    if (!frame_id(frame, c, i) || c != class_ack || (i != ack_ack && i != ack_nak) ||
            frame.size() != header_len + 2 + checksum_len)
        return false;

    ack.ack = i == ack_ack;
    ack.msg_class = static_cast<uint8_t>(frame[header_len]);
    ack.msg_id = static_cast<uint8_t>(frame[header_len + 1]);
    return true;
}

int gps_ubx_decoder_v1::parse_protver(std::string_view frame) {
    uint8_t c, i;

    // swVersion and hwVersion, then 30 byte extension strings
    constexpr size_t ext_start = 40;
    constexpr size_t ext_len = 30;

    if (!frame_id(frame, c, i) || c != class_mon || i != mon_ver)
        return -1;

    const auto payload = frame.substr(header_len, frame.size() - header_len - checksum_len);

    if (payload.size() < ext_start)
        return -1;

    for (size_t off = ext_start; off + ext_len <= payload.size(); off += ext_len) {
        auto ext = payload.substr(off, ext_len);
        ext = ext.substr(0, ext.find('\0'));

        // "PROTVER=18.00" on newer receivers, "PROTVER 14.00" on u-blox 7
        if (ext.size() < 9 || ext.substr(0, 7) != "PROTVER")
            continue;

        int major = 0;
        int minor = 0;
        size_t p = 8;

        while (p < ext.size() && ext[p] >= '0' && ext[p] <= '9' && major < 1000)
            major = major * 10 + (ext[p++] - '0');

        if (p < ext.size() && ext[p] == '.') {
            p++;
            for (int d = 0; d < 2 && p < ext.size() && ext[p] >= '0' && ext[p] <= '9'; d++)
                minor = minor * 10 + (ext[p++] - '0');
        }

        if (major > 0)
            return major * 100 + minor;
    }

    return 0;
}

bool gps_ubx_decoder_v1::parse_mon_comms(std::string_view frame, std::vector<ubx_port_stats>& ports) {
    uint8_t c, i;

    constexpr size_t block_start = 8;
    constexpr size_t block_len = 40;

    if (!frame_id(frame, c, i) || c != class_mon || i != mon_comms)
        return false;

    const auto *p = reinterpret_cast<const uint8_t *>(frame.data()) + header_len;
    const size_t len = frame.size() - header_len - checksum_len;

    if (len < block_start || len != block_start + p[1] * block_len)
        return false;

    ports.clear();

    for (size_t n = 0; n < p[1]; n++) {
        const auto *b = p + block_start + n * block_len;
        ubx_port port;

        switch (get_u16(b)) {
            case 0x0000: port = ubx_port::i2c; break;
            case 0x0100: port = ubx_port::uart1; break;
            case 0x0201: port = ubx_port::uart2; break;
            case 0x0300: port = ubx_port::usb; break;
            case 0x0400: port = ubx_port::spi; break;
            default: continue;
        }

        ports.push_back(ubx_port_stats{port, get_u32(b + 4), get_u32(b + 12)});
    }

    return true;
}

bool gps_ubx_decoder_v1::parse_valget(std::string_view frame, uint32_t key, uint32_t& value) {
    uint8_t c, i;

    if (!frame_id(frame, c, i) || c != class_cfg || i != cfg_valget)
        return false;

    const auto *p = reinterpret_cast<const uint8_t *>(frame.data()) + header_len;
    const size_t len = frame.size() - header_len - checksum_len;

    // Version, layer, position, then key/value pairs sized by the key
    for (size_t off = 4; off + 4 <= len; ) {
        const uint32_t k = get_u32(p + off);
        size_t vlen;

        switch ((k >> 28) & 0x7) {
            case 1: case 2: vlen = 1; break;
            case 3: vlen = 2; break;
            case 4: vlen = 4; break;
            case 5: vlen = 8; break;
            default: return false;
        }

        if (off + 4 + vlen > len)
            return false;

        if (k == key) {
            if (vlen > 4)
                return false;

            value = 0;
            for (size_t b = 0; b < vlen; b++)
                value |= static_cast<uint32_t>(p[off + 4 + b]) << (8 * b);

            return true;
        }

        off += 4 + vlen;
    }

    return false;
}

std::string gps_ubx_commands_v1::frame(uint8_t msg_class, uint8_t msg_id, const std::vector<uint8_t>& payload) {
    std::string f;
    f.reserve(gps_ubx_decoder_v1::header_len + payload.size() + gps_ubx_decoder_v1::checksum_len);

    f.push_back(static_cast<char>(gps_ubx_decoder_v1::sync_1));
    f.push_back(static_cast<char>(gps_ubx_decoder_v1::sync_2));
    f.push_back(static_cast<char>(msg_class));
    f.push_back(static_cast<char>(msg_id));
    f.push_back(static_cast<char>(payload.size() & 0xFF));
    f.push_back(static_cast<char>((payload.size() >> 8) & 0xFF));
    f.append(payload.begin(), payload.end());

    const auto ck = gps_ubx_decoder_v1::checksum(reinterpret_cast<const uint8_t *>(f.data()) + 2, f.size() - 2);
    f.push_back(static_cast<char>(ck.first));
    f.push_back(static_cast<char>(ck.second));

    return f;
}

namespace {
    void put_u32(std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; i++)
            v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
    }
}

std::string gps_ubx_commands_v1::poll_mon_ver() {
    return frame(gps_ubx_decoder_v1::class_mon, gps_ubx_decoder_v1::mon_ver, {});
}

std::string gps_ubx_commands_v1::poll_mon_comms() {
    return frame(gps_ubx_decoder_v1::class_mon, gps_ubx_decoder_v1::mon_comms, {});
}

std::string gps_ubx_commands_v1::set_nav_rate_current_port(ubx_nav_msg msg, uint8_t rate) {
    return frame(gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_msg,
            {gps_ubx_decoder_v1::class_nav, static_cast<uint8_t>(msg), rate});
}

std::string gps_ubx_commands_v1::get_pvt_rate(ubx_port port) {
    std::vector<uint8_t> p{0x00, valget_layer_ram, 0x00, 0x00};
    put_u32(p, pvt_rate_key(port));
    return frame(gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_valget, p);
}

std::string gps_ubx_commands_v1::get_uart_baud(ubx_port port) {
    const auto key = uart_baud_key(port);

    if (key == 0)
        return {};

    std::vector<uint8_t> p{0x00, valget_layer_ram, 0x00, 0x00};
    put_u32(p, key);
    return frame(gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_valget, p);
}

std::string gps_ubx_commands_v1::set_pvt_rate(ubx_port port, uint8_t rate) {
    std::vector<uint8_t> p{0x00, valset_layer_ram, 0x00, 0x00};
    put_u32(p, pvt_rate_key(port));
    p.push_back(rate);
    return frame(gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_valset, p);
}
