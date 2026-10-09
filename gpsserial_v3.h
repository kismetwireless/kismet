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

#ifndef __GPSSERIAL_V3_H__
#define __GPSSERIAL_V3_H__

#include "config.h"

#include <array>
#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "globalregistry.h"
#include "gpsframer_v1.h"
#include "gpssirf_v1.h"
#include "gpsubx_v1.h"
#include "kis_gps.h"

#define ASIO_HAS_STD_CHRONO
#define ASIO_HAS_MOVE

#include "boost/asio.hpp"

// Serial-attached GPS (includes USB GPS).  All port I/O, decoding, and timers run on
// the strand.
//
// Unless a baud rate is given, each open probes the common GPS rates until checksummed
// NMEA, UBX, or SiRF binary arrives, starting with the rate that worked last time.  UBX
// and SiRF navigation reports are used in place of NMEA while the device sends them.
//
// A u-blox receiver which only sends NMEA is asked to also send UBX navigation reports.
// Only message output rates are changed, only in the receiver's RAM, and the previous
// rates are restored when the GPS is closed; a power cycle also undoes it.  Nothing is ever
// sent to a SiRF receiver.

class kis_gps_serial_v3 : public kis_gps, public std::enable_shared_from_this<kis_gps_serial_v3> {
public:
    // Which reports are used for the location; nmea and sirf never write to the device
    enum class gps_protocol {
        any,
        nmea,
        ubx,
        sirf,
    };

    // A builder can fix the protocol, so protocol= can't change it
    kis_gps_serial_v3(shared_gps_builder in_builder, uint64_t in_id,
            gps_protocol in_fixed_protocol = gps_protocol::any);
    virtual ~kis_gps_serial_v3();

    // Validates the definition, then opens the port in the background; open failures
    // are logged and retried like any other device error
    virtual bool open_gps(std::string in_opts) override;
    virtual void close_gps() override;

    virtual bool get_location_valid() override;
    virtual bool get_device_connected() override;

protected:
    // Rates GPS units commonly use, then the rest up to 115200, then high speed rates; a
    // rate the platform can't set (such as 460800 on macOS) is skipped
    static constexpr std::array<unsigned int, 9> probe_bauds{
        4800, 9600, 115200,
        19200, 38400, 57600,
        230400, 460800, 921600
    };

    // Data still in flight from the previous rate is dropped for this long after a change
    static constexpr std::chrono::milliseconds probe_settle{100};
    // GPS units report about once a second, so this covers at least two reports
    static constexpr std::chrono::milliseconds probe_dwell{2500};
    // This much data with no valid sentence is the wrong rate, without waiting out the dwell
    static constexpr size_t probe_early_bytes = 2048;
    // Checksummed sentences needed to lock a rate
    static constexpr unsigned int probe_lock_frames = 2;

    // A device that stays silent this long is closed and reopened
    static constexpr std::chrono::seconds data_timeout{30};
    static constexpr std::chrono::seconds data_check_interval{10};

    // Longest close_gps waits for the strand
    static constexpr std::chrono::seconds close_wait{2};

    // A read error usually means the device was unplugged, so the first retry is quick in
    // case it's plugged straight back in
    static constexpr std::chrono::seconds read_error_retry{2};

    // Retry delays after consecutive failures
    static constexpr std::array<std::chrono::seconds, 3> reconnect_backoff{
        std::chrono::seconds{10}, std::chrono::seconds{30}, std::chrono::seconds{60}
    };

    enum class serial_state {
        closed,
        // Baud just changed; input is discarded
        settling,
        // Looking for NMEA at the current probe rate
        probing,
        running,
    };

    // Non-frame bytes with no valid frame before warning that this isn't a supported device
    static constexpr uint64_t garbage_warn_bytes = 4096;

    // NMEA positions are used again when binary reports stop for this long
    static constexpr std::chrono::seconds binary_fix_stale{3};

    // UBX configuration: wait this long for reports the receiver already sends, for a reply
    // to each command, and for reports after enabling them
    static constexpr std::chrono::milliseconds ubx_observe{3000};
    static constexpr std::chrono::milliseconds ubx_reply_timeout{1500};
    static constexpr std::chrono::milliseconds ubx_confirm_wait{3000};
    static constexpr unsigned int ubx_command_tries = 3;

    // Extra polls sent between MON-COMMS readings on each port detection attempt, so the
    // receive count on the port we're attached to is distinctive
    static constexpr std::array<unsigned int, 3> ubx_detect_padding{1, 3, 5};

    // First protocol version with NAV-PVT, MON-COMMS, and without the legacy CFG-MSG
    static constexpr int ubx_protver_pvt = 1400;
    static constexpr int ubx_protver_comms = 2700;
    static constexpr int ubx_protver_no_legacy = 3400;

    enum class ubx_cfg_state {
        idle,
        // Waiting to see if the receiver already sends UBX navigation reports
        observing,
        configuring,
        // Waiting for reports after enabling them
        confirming,
        done,
    };

    enum class ubx_restore_kind {
        none,
        // CFG-MSG on the current port, back to 0
        current_port,
        // CFG-VALSET of one port's NAV-PVT rate, back to the saved value
        port_key,
    };

    // Strand only
    void open_impl();
    void close_impl();
    void close_port();
    void schedule_reconnect(bool after_read_error = false);
    void arm_data_timer();

    void start_probe(size_t index);
    void arm_probe_timer(std::chrono::milliseconds delay);
    void probe_timer_fired();
    void lock_baud(gps_framer_v1::frame_type type);
    void probe_failed();

    void start_read();
    void handle_read(const boost::system::error_code& ec, std::size_t sz);
    void handle_frame(const gps_framer_v1::frame& frame);

    // Queue a frame to the device; strand only
    void queue_write(std::string data);
    void start_write();

    void handle_port_error(const std::string& what, const boost::system::error_code& ec,
            bool read_error);

    // UBX configuration, strand only
    using ubx_reply_cb = std::function<void (bool ok, std::string_view frame)>;

    void ubx_cfg_begin();
    void ubx_cfg_observed();
    void ubx_query_version(unsigned int tries);
    void ubx_enable_current_port(size_t index, unsigned int tries);
    void ubx_detect_port(unsigned int attempt);
    void ubx_detect_compare(unsigned int attempt, std::vector<ubx_port_stats> first,
            uint64_t first_rx, size_t sent);
    void ubx_check_port_baud();
    void ubx_enable_port_key();
    void ubx_confirm();
    void ubx_cfg_failed(const std::string& reason);
    void ubx_check_reply(std::string_view frame);
    void ubx_handle_nmea_hint(std::string_view sentence);
    void ubx_nav_seen(uint8_t msg_id);
    // A SiRF receiver; never write to it
    void sirf_seen();

    // Send a command and wait for its ACK (ack=true) or its reply message
    void ubx_command(std::string cmd, uint8_t msg_class, uint8_t msg_id, bool ack, ubx_reply_cb cb);
    void arm_cfg_timer(std::chrono::milliseconds delay, std::function<void ()> fn);

    // Undo RAM changes; restore_now queues the commands, restore_on_close writes them
    // before the port closes
    std::vector<std::string> ubx_restore_commands();
    void ubx_restore_now();
    void ubx_restore_on_close();

    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    boost::asio::serial_port serialport;
    boost::asio::steady_timer reconnect_timer;
    boost::asio::steady_timer data_timer;
    boost::asio::steady_timer probe_timer;
    boost::asio::steady_timer cfg_timer;

    std::array<uint8_t, 1024> read_buf;
    gps_framer_v1 framer;
    gps_ubx_decoder_v1 ubx_decoder;
    gps_sirf_decoder_v1 sirf_decoder;

    std::deque<std::string> write_queue;
    bool write_active;

    // Set from open_gps under gps_mutex, read on the strand; a fixed baud of 0 probes
    std::string serial_device;
    unsigned int fixed_baud;
    // gps_binary=off never writes to the receiver
    bool binary_allowed;
    gps_protocol protocol;

    // Set by the builder
    const gps_protocol fixed_protocol;

    // Closed by the user; nothing reopens the port
    std::atomic<bool> stopped;
    std::atomic<bool> port_open;
    std::atomic<time_t> last_data_time;

    // Strand only; completions from an earlier open are ignored
    uint64_t generation = 0;
    std::string active_device;
    unsigned int active_baud = 0;

    // Strand only; probe_step changes on every probe transition so a timer which fired
    // before a lock or rate change is ignored
    serial_state state = serial_state::closed;
    std::vector<unsigned int> probe_list;
    // Rates the port accepted this cycle, for the failure message
    std::vector<unsigned int> probe_tried;
    size_t probe_index = 0;
    uint64_t probe_step = 0;
    unsigned int probe_valid = 0;
    size_t probe_bytes = 0;
    unsigned int remembered_baud = 0;
    unsigned int reconnect_failures = 0;
    // Quick read error retry used this outage; a device which fails every read backs off
    bool fast_retry_used = false;

    // Strand only; protocol used for the location in this open
    gps_protocol active_protocol = gps_protocol::any;

    bool protocol_allowed(gps_framer_v1::frame_type type) const;

    // Strand only; UBX configuration of this open
    ubx_cfg_state ubx_cfg = ubx_cfg_state::idle;
    uint64_t cfg_step = 0;
    bool ubx_writes_allowed = false;
    bool ublox_hint = false;
    bool sirf_hint = false;
    int ubx_protver = -1;
    std::vector<ubx_nav_msg> ubx_enable_msgs;
    ubx_port ubx_detected_port = ubx_port::uart1;
    uint64_t rx_total = 0;
    bool logged_ubx_failure = false;

    struct {
        bool active = false;
        bool ack = false;
        uint8_t msg_class = 0;
        uint8_t msg_id = 0;
        ubx_reply_cb cb;
    } ubx_expect;

    // Strand only; what was changed in the receiver, kept across reopens until the GPS is
    // closed
    ubx_restore_kind restore_kind = ubx_restore_kind::none;
    std::vector<ubx_nav_msg> restore_msgs;
    ubx_port restore_port = ubx_port::uart1;
    uint8_t restore_value = 0;

    // Strand only; last binary navigation report, which takes priority over NMEA
    std::chrono::steady_clock::time_point last_binary_fix;
    bool using_binary = false;
    const char *binary_name = "";

    // Strand only
    uint64_t garbage_since_frame;
    bool warned_about_garbage;
    // Failing since the last good frame; retries are quiet until it works again
    bool in_error;
};

class gps_serial_v3_builder : public kis_gps_builder {
public:
    gps_serial_v3_builder() :
        kis_gps_builder() {
        initialize();
    }

    virtual void initialize() override {
        set_int_gps_class("serial");
        set_int_gps_class_description("serial-attached GPS (includes USB GPS) using NMEA, u-blox UBX, "
                "or SiRF binary");
        set_int_gps_priority(-1000);
        set_int_default_name("serial");
        set_int_singleton(false);
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder, uint64_t in_id) override {
        return shared_gps(new kis_gps_serial_v3(in_builder, in_id));
    }
};


// Same driver limited to NMEA; never writes to the device
class gps_nmea_v3_builder : public kis_gps_builder {
public:
    gps_nmea_v3_builder() :
        kis_gps_builder() {
        initialize();
    }

    virtual void initialize() override {
        set_int_gps_class("nmea");
        set_int_gps_class_description("serial-attached NMEA GPS (includes USB GPS); never sends "
                "commands to the GPS");
        set_int_gps_priority(-1000);
        set_int_default_name("nmea");
        set_int_singleton(false);
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder, uint64_t in_id) override {
        return shared_gps(new kis_gps_serial_v3(in_builder, in_id,
                    kis_gps_serial_v3::gps_protocol::nmea));
    }
};

#endif

