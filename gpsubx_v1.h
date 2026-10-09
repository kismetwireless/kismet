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

#ifndef __GPSUBX_V1_H__
#define __GPSUBX_V1_H__

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gps_proto.h"

// u-blox receiver ports, in CFG-MSGOUT key order
enum class ubx_port : uint8_t {
    i2c,
    uart1,
    uart2,
    usb,
    spi,
};

// Navigation messages Kismet decodes, by UBX message id
enum class ubx_nav_msg : uint8_t {
    posllh = 0x02,
    status = 0x03,
    sol = 0x06,
    pvt = 0x07,
    velned = 0x12,
};

struct ubx_ack {
    bool ack;
    uint8_t msg_class;
    uint8_t msg_id;
};

struct ubx_port_stats {
    ubx_port port;
    uint32_t tx_bytes;
    uint32_t rx_bytes;
};

// u-blox UBX binary protocol decoder; no I/O.  Frames come from gps_framer_v1 with the
// sync, length, and checksum already checked.
//
// NAV-PVT (u-blox 7 and later) is a complete report on its own.  Older receivers report
// position, fix, and velocity in separate messages, so the last fix status is kept to
// decide if a position is usable.
class gps_ubx_decoder_v1 {
public:
    static constexpr uint8_t sync_1 = 0xB5;
    static constexpr uint8_t sync_2 = 0x62;

    // Sync, class, id, and length
    static constexpr size_t header_len = 6;
    static constexpr size_t checksum_len = 2;

    // Larger messages are never decoded, so they aren't held while waiting for the rest
    static constexpr size_t max_payload = 1024;

    static constexpr uint8_t class_nav = 0x01;
    static constexpr uint8_t class_ack = 0x05;
    static constexpr uint8_t class_cfg = 0x06;
    static constexpr uint8_t class_mon = 0x0A;

    static constexpr uint8_t ack_nak = 0x00;
    static constexpr uint8_t ack_ack = 0x01;
    static constexpr uint8_t cfg_msg = 0x01;
    static constexpr uint8_t cfg_valset = 0x8A;
    static constexpr uint8_t cfg_valget = 0x8B;
    static constexpr uint8_t mon_ver = 0x04;
    static constexpr uint8_t mon_comms = 0x36;
    static constexpr uint8_t nav_posllh = 0x02;
    static constexpr uint8_t nav_status = 0x03;
    static constexpr uint8_t nav_sol = 0x06;
    static constexpr uint8_t nav_pvt = 0x07;
    static constexpr uint8_t nav_velned = 0x12;

    enum class result {
        // Location, or a no fix report (fix 1 only)
        update,
        // Valid message which carries nothing to apply (an unhandled message)
        ignored,
        malformed,
    };

    // 8-bit Fletcher checksum over the class, id, length, and payload
    static constexpr std::pair<uint8_t, uint8_t> checksum(const uint8_t *data, size_t len) {
        uint8_t a = 0;
        uint8_t b = 0;

        for (size_t i = 0; i < len; i++) {
            a = static_cast<uint8_t>(a + data[i]);
            b = static_cast<uint8_t>(b + a);
        }

        return {a, b};
    }

    // Decode one complete frame, from the sync bytes through the checksum
    result decode(std::string_view frame, gps_fix_update& update);

    void reset() {
        fix = 0;
        fix_ok = false;
    }

    // Class and id of a complete frame
    static bool frame_id(std::string_view frame, uint8_t& msg_class, uint8_t& msg_id);

    static bool parse_ack(std::string_view frame, ubx_ack& ack);

    // Protocol version * 100 from MON-VER, 0 if the receiver doesn't report one (u-blox 6
    // and older), or -1 if this isn't MON-VER
    static int parse_protver(std::string_view frame);

    static bool parse_mon_comms(std::string_view frame, std::vector<ubx_port_stats>& ports);

    // Value of one key from a CFG-VALGET response
    static bool parse_valget(std::string_view frame, uint32_t key, uint32_t& value);

protected:
    // From the last NAV-STATUS or NAV-SOL; gates NAV-POSLLH and NAV-VELNED
    int fix = 0;
    bool fix_ok = false;
};

// The only commands Kismet sends to a u-blox receiver: polls, and message output rates set
// in RAM.  Nothing here can save the configuration, change port or baud settings, or reset
// the receiver, so a power cycle always restores the receiver's own settings.
class gps_ubx_commands_v1 {
public:
    // CFG-VALSET layers bitmask; RAM only, never BBR (0x02) or flash (0x04)
    static constexpr uint8_t valset_layer_ram = 0x01;
    static_assert(valset_layer_ram == 0x01 && (valset_layer_ram & 0x06) == 0,
            "configuration changes must only go to RAM");

    // CFG-VALGET reads one layer by index; 0 is RAM
    static constexpr uint8_t valget_layer_ram = 0x00;

    static constexpr uint32_t pvt_rate_key(ubx_port port) {
        return 0x20910006 + static_cast<uint32_t>(port);
    }

    // 0 for ports without a baud rate
    static constexpr uint32_t uart_baud_key(ubx_port port) {
        return port == ubx_port::uart1 ? 0x40520001 : port == ubx_port::uart2 ? 0x40530001 : 0;
    }

    static std::string poll_mon_ver();
    static std::string poll_mon_comms();

    // Legacy CFG-MSG, which only changes the port the command arrives on
    static std::string set_nav_rate_current_port(ubx_nav_msg msg, uint8_t rate);

    // CFG-VALGET from RAM
    static std::string get_pvt_rate(ubx_port port);
    // Empty for ports without a baud rate
    static std::string get_uart_baud(ubx_port port);

    // CFG-VALSET in RAM
    static std::string set_pvt_rate(ubx_port port, uint8_t rate);

protected:
    static std::string frame(uint8_t msg_class, uint8_t msg_id, const std::vector<uint8_t>& payload);
};

#endif
