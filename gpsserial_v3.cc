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

#include <time.h>

#include <algorithm>
#include <future>

#include "gpsnmea_v3.h"
#include "gpsserial_v3.h"
#include "gpstracker.h"
#include "messagebus.h"
#include "util.h"

static_assert(gps_framer_v1::max_nmea_len >= gps_nmea::max_sentence_len + 2,
        "framer must hold the longest NMEA sentence the decoder accepts");

kis_gps_serial_v3::kis_gps_serial_v3(shared_gps_builder in_builder, uint64_t in_id,
        gps_protocol in_fixed_protocol) :
    kis_gps{in_builder, in_id},
    strand_{Globalreg::globalreg->io.get_executor()},
    serialport{Globalreg::globalreg->io},
    reconnect_timer{strand_},
    data_timer{strand_},
    probe_timer{strand_},
    cfg_timer{strand_},
    write_active{false},
    fixed_baud{0},
    binary_allowed{true},
    protocol{in_fixed_protocol},
    fixed_protocol{in_fixed_protocol},
    stopped{true},
    port_open{false},
    last_data_time{time(0)},
    garbage_since_frame{0},
    warned_about_garbage{false},
    in_error{false} { }

kis_gps_serial_v3::~kis_gps_serial_v3() { }

bool kis_gps_serial_v3::open_gps(std::string in_opts) {
    kis_unique_lock<kis_mutex> lk(gps_mutex, "gps_serial_v3 open_gps");

    if (!kis_gps::open_gps(in_opts))
        return false;

    // Connected once the port is actually open
    set_int_device_connected(false);

    auto proto_device = fetch_opt("device", source_definition_opts);
    auto proto_baud_s = str_lower(fetch_opt("baud", source_definition_opts));
    unsigned int proto_baud = 0;

    if (proto_device == "") {
        _MSG_ERROR("(GPS) Serial GPS expected device= option, none found.");
        return false;
    }

    if (proto_baud_s != "" && proto_baud_s != "auto") {
        if (sscanf(proto_baud_s.c_str(), "%u", &proto_baud) != 1 || proto_baud == 0) {
            _MSG_ERROR("(GPS) Serial GPS expected a baud rate or 'auto' in baud= option, but got "
                    "something else.");
            return false;
        }
    }

    auto proto_binary = str_lower(fetch_opt("gps_binary", source_definition_opts));

    if (proto_binary != "" && proto_binary != "auto" && proto_binary != "off") {
        _MSG_ERROR("(GPS) Serial GPS expected 'auto' or 'off' in gps_binary= option, but got "
                "something else.");
        return false;
    }

    auto proto_protocol_s = str_lower(fetch_opt("protocol", source_definition_opts));
    auto proto_protocol = fixed_protocol;

    if (proto_protocol_s == "" || proto_protocol_s == "auto")
        ;
    else if (proto_protocol_s == "nmea")
        proto_protocol = gps_protocol::nmea;
    else if (proto_protocol_s == "ubx")
        proto_protocol = gps_protocol::ubx;
    else if (proto_protocol_s == "sirf")
        proto_protocol = gps_protocol::sirf;
    else {
        _MSG_ERROR("(GPS) Serial GPS expected 'auto', 'nmea', 'ubx', or 'sirf' in protocol= "
                "option, but got something else.");
        return false;
    }

    if (fixed_protocol != gps_protocol::any && proto_protocol != fixed_protocol) {
        _MSG_ERROR("(GPS) GPS type '{}' only supports NMEA; use type 'serial' for other protocols.",
                gps_prototype->get_gps_class());
        return false;
    }

    serial_device = proto_device;
    fixed_baud = proto_baud;
    protocol = proto_protocol;

    // Only UBX is ever enabled, so a GPS limited to another protocol is never written to
    binary_allowed = proto_binary != "off" &&
        (proto_protocol == gps_protocol::any || proto_protocol == gps_protocol::ubx);
    stopped = false;

    lk.unlock();

    boost::asio::post(strand_,
            [self = shared_from_this()]() {
                self->open_impl();
            });

    return true;
}

void kis_gps_serial_v3::close_gps() {
    stopped = true;

    if (strand_.running_in_this_thread()) {
        close_impl();
        return;
    }

    auto f = boost::asio::post(strand_,
            std::packaged_task<void()>([self = shared_from_this()]() {
                self->close_impl();
            }));

    // If the IO threads aren't running (a fatal error during startup) don't hang shutdown
    f.wait_for(close_wait);
}

void kis_gps_serial_v3::close_impl() {
    reconnect_timer.cancel();
    data_timer.cancel();
    ubx_restore_on_close();
    close_port();
}

void kis_gps_serial_v3::close_port() {
    // Anything still in flight from this port is stale once it completes
    generation++;
    probe_step++;

    state = serial_state::closed;
    probe_timer.cancel();

    // Configuration starts over on the next open; what was changed is kept for restoring
    cfg_step++;
    cfg_timer.cancel();
    ubx_cfg = ubx_cfg_state::idle;
    ubx_expect = {};
    ublox_hint = false;
    sirf_hint = false;
    ubx_protver = -1;
    ubx_seen_pos = false;
    ubx_seen_dop = false;
    ubx_seen_sat = false;
    ubx_enabled_msgs.clear();
    ubx_port_known = false;

    boost::system::error_code ec;

    if (serialport.is_open()) {
        serialport.cancel(ec);
        serialport.close(ec);
    }

    write_queue.clear();
    write_active = false;

    framer.reset();
    nmea_gsv.reset();
    ubx_decoder.reset();
    sirf_decoder.reset();
    last_binary_fix = {};
    using_binary = false;

    clear_quality();

    if (port_open) {
        port_open = false;
        set_int_device_connected(false);
    }
}

void kis_gps_serial_v3::open_impl() {
    if (stopped)
        return;

    close_port();

    std::string device;
    unsigned int rate;

    {
        kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_serial_v3 open_impl");
        device = serial_device;
        rate = fixed_baud;
        ubx_writes_allowed = binary_allowed;
        active_protocol = protocol;
    }

    using spb = boost::asio::serial_port_base;

    boost::system::error_code ec;

    serialport.open(device, ec);

    if (!ec)
        serialport.set_option(spb::character_size(8), ec);
    if (!ec)
        serialport.set_option(spb::parity(spb::parity::none), ec);
    if (!ec)
        serialport.set_option(spb::stop_bits(spb::stop_bits::one), ec);
    if (!ec)
        serialport.set_option(spb::flow_control(spb::flow_control::none), ec);
    if (!ec && rate != 0)
        serialport.set_option(spb::baud_rate(rate), ec);

    if (ec) {
        // Retried until it works, so only say so once
        if (!in_error) {
            in_error = true;
            _MSG_ERROR("(GPS) Serial GPS could not open and configure {}: {}", device, ec.message());
        }

        close_port();
        schedule_reconnect();
        return;
    }

    active_device = device;
    garbage_since_frame = 0;
    last_data_time = time(0);

    port_open = true;
    set_int_device_connected(true);

    start_read();

    if (rate != 0) {
        // A fixed rate is used as-is, so devices which don't checksum their sentences work
        active_baud = rate;
        state = serial_state::running;

        if (!in_error)
            _MSG_INFO("(GPS) Opened serial port {}@{}", device, rate);

        arm_data_timer();
        return;
    }

    probe_list.clear();
    probe_tried.clear();

    if (remembered_baud != 0)
        probe_list.push_back(remembered_baud);

    for (auto b : probe_bauds) {
        if (b != remembered_baud)
            probe_list.push_back(b);
    }

    if (!in_error)
        _MSG_INFO("(GPS) Opened serial port {}, detecting the baud rate", device);

    start_probe(0);
}

void kis_gps_serial_v3::start_probe(size_t index) {
    using spb = boost::asio::serial_port_base;

    // Skip rates the device or driver rejects
    for (probe_index = index; probe_index < probe_list.size(); probe_index++) {
        boost::system::error_code ec;
        serialport.set_option(spb::baud_rate(probe_list[probe_index]), ec);

        if (!ec) {
            probe_tried.push_back(probe_list[probe_index]);
            break;
        }
    }

    if (probe_index >= probe_list.size()) {
        probe_failed();
        return;
    }

    active_baud = probe_list[probe_index];
    state = serial_state::settling;
    probe_valid = 0;
    probe_bytes = 0;
    framer.reset();

    arm_probe_timer(probe_settle);
}

void kis_gps_serial_v3::arm_probe_timer(std::chrono::milliseconds delay) {
    probe_timer.expires_after(delay);
    probe_timer.async_wait(boost::asio::bind_executor(strand_,
                [weak = weak_from_this(), gen = generation, step = ++probe_step]
                (const boost::system::error_code& ec) {
                    auto self = weak.lock();

                    if (ec || self == nullptr || gen != self->generation || step != self->probe_step)
                        return;

                    self->probe_timer_fired();
                }));
}

void kis_gps_serial_v3::probe_timer_fired() {
    if (state == serial_state::settling) {
        state = serial_state::probing;
        framer.reset();
        arm_probe_timer(probe_dwell);
    } else if (state == serial_state::probing) {
        start_probe(probe_index + 1);
    }
}

void kis_gps_serial_v3::lock_baud(gps_framer_v1::frame_type type) {
    probe_step++;
    probe_timer.cancel();

    state = serial_state::running;
    remembered_baud = active_baud;
    reconnect_failures = 0;
    garbage_since_frame = 0;
    last_data_time = time(0);

    if (!in_error)
        _MSG_INFO("(GPS) Serial GPS {} is sending {} at {} baud", active_device,
                type == gps_framer_v1::frame_type::ubx ? "UBX" :
                type == gps_framer_v1::frame_type::sirf ? "SiRF binary" : "NMEA", active_baud);

    arm_data_timer();
}

void kis_gps_serial_v3::probe_failed() {
    if (!in_error) {
        in_error = true;

        std::string rates;
        for (auto b : probe_tried)
            rates += (rates.empty() ? "" : ", ") + std::to_string(b);

        if (rates.empty())
            rates = "(none; the port accepted no baud rate)";

        _MSG_ERROR("(GPS) Could not find NMEA, UBX, or SiRF data from serial GPS {} at any of {} baud.  "
                "Check that the GPS is connected, that you are not running GPSD (it may have "
                "started automatically), and that the GPS outputs standard NMEA; Kismet will keep "
                "trying.",
                active_device, rates);
    }

    close_port();
    schedule_reconnect();
}

void kis_gps_serial_v3::schedule_reconnect(bool after_read_error) {
    if (stopped || !get_gps_reconnect())
        return;

    std::chrono::seconds delay;

    if (after_read_error && !fast_retry_used) {
        fast_retry_used = true;
        delay = read_error_retry;
    } else {
        delay = reconnect_backoff[std::min<size_t>(reconnect_failures, reconnect_backoff.size() - 1)];
        reconnect_failures++;
    }

    reconnect_timer.expires_after(delay);
    reconnect_timer.async_wait(boost::asio::bind_executor(strand_,
                [weak = weak_from_this()](const boost::system::error_code& ec) {
                    auto self = weak.lock();

                    if (ec || self == nullptr)
                        return;

                    self->open_impl();
                }));
}

void kis_gps_serial_v3::arm_data_timer() {
    data_timer.expires_after(data_check_interval);
    data_timer.async_wait(boost::asio::bind_executor(strand_,
                [weak = weak_from_this(), gen = generation](const boost::system::error_code& ec) {
                    auto self = weak.lock();

                    if (ec || self == nullptr || gen != self->generation || self->stopped)
                        return;

                    if (time(0) - self->last_data_time <= data_timeout.count()) {
                        self->arm_data_timer();
                        return;
                    }

                    self->close_port();

                    if (self->get_gps_reconnect()) {
                        _MSG_ERROR("(GPS) No usable data from the serial GPS {} in over {} seconds, check that "
                                "you are not running GPSD (it may have started automatically), the baud rate is "
                                "correct and the GPS outputs standard NMEA.",
                                self->active_device, data_timeout.count());
                        self->open_impl();
                    } else {
                        _MSG_ERROR("(GPS) No usable data from the serial GPS {} in over {} seconds, disconnecting. "
                                "Check that GPSD is not running (it may have started automatically), that the GPS "
                                "baud rate is correct, and that the GPS outputs standard NMEA.",
                                self->active_device, data_timeout.count());
                    }
                }));
}

void kis_gps_serial_v3::start_read() {
    serialport.async_read_some(boost::asio::buffer(read_buf),
            boost::asio::bind_executor(strand_,
                [self = shared_from_this(), gen = generation](const boost::system::error_code& ec,
                    std::size_t sz) {
                    if (gen != self->generation)
                        return;

                    self->handle_read(ec, sz);
                }));
}

void kis_gps_serial_v3::handle_read(const boost::system::error_code& ec, std::size_t sz) {
    if (stopped)
        return;

    if (ec) {
        if (ec == boost::asio::error::operation_aborted)
            return;

        handle_port_error("reading from", ec, true);
        return;
    }

    // Data sent at the previous rate is still arriving
    if (state == serial_state::settling) {
        start_read();
        return;
    }

    rx_total += sz;

    const auto discarded = framer.get_discarded();

    framer.feed(read_buf.data(), sz,
            [this](const gps_framer_v1::frame& frame) {
                handle_frame(frame);
            });

    if (state == serial_state::probing) {
        probe_bytes += sz;

        if (probe_valid == 0 && probe_bytes >= probe_early_bytes)
            start_probe(probe_index + 1);
    } else if (state == serial_state::running) {
        garbage_since_frame += framer.get_discarded() - discarded;

        if (!warned_about_garbage && garbage_since_frame > garbage_warn_bytes) {
            warned_about_garbage = true;
            _MSG_ERROR("(GPS) Serial GPS {} is sending data which isn't NMEA, UBX, or SiRF.  Check that the baud rate "
                    "({}) is correct and that GPSD is not using the device.  If this is a binary-only "
                    "GPS unit, you will need to use gpsd and configure Kismet for gpsd mode.",
                    active_device, active_baud);
        }
    }

    // A failed probe or error may have closed the port
    if (state != serial_state::closed)
        start_read();
}

void kis_gps_serial_v3::handle_frame(const gps_framer_v1::frame& frame) {
    gps_fix_update update;
    bool has_update;
    bool binary;

    if (frame.type == gps_framer_v1::frame_type::nmea) {
        const auto r = gps_nmea::parse(frame.data, update, &nmea_gsv);

        if (r != gps_nmea::result::update && r != gps_nmea::result::ignored)
            return;

        // Random bytes at the wrong rate can look like a sentence without a checksum
        if (state == serial_state::probing && !gps_nmea::has_valid_checksum(frame.data))
            return;

        // Receivers identify themselves at startup, which is often while probing
        ubx_handle_nmea_hint(frame.data);

        has_update = r == gps_nmea::result::update;
        binary = false;
    } else if (frame.type == gps_framer_v1::frame_type::ubx) {
        ublox_hint = true;

        if (state == serial_state::running)
            ubx_check_reply(frame.data);

        const auto r = ubx_decoder.decode(frame.data, update);

        if (r == gps_ubx_decoder_v1::result::malformed)
            return;

        uint8_t msg_class, msg_id;
        if (state == serial_state::running &&
                gps_ubx_decoder_v1::frame_id(frame.data, msg_class, msg_id) &&
                msg_class == gps_ubx_decoder_v1::class_nav)
            ubx_nav_seen(msg_id);

        has_update = r == gps_ubx_decoder_v1::result::update;
        binary = true;
    } else if (frame.type == gps_framer_v1::frame_type::sirf) {
        sirf_seen();

        const auto r = sirf_decoder.decode(frame.data, update);

        if (r == gps_sirf_decoder_v1::result::malformed)
            return;

        has_update = r == gps_sirf_decoder_v1::result::update;
        binary = true;
    } else {
        return;
    }

    if (state == serial_state::probing) {
        if (++probe_valid < probe_lock_frames)
            return;

        lock_baud(frame.type);
    }

    if (state != serial_state::running)
        return;

    // Once the device is talking, at a probed or a fixed rate
    if (ubx_cfg == ubx_cfg_state::idle)
        ubx_cfg_begin();

    // Other protocols still find the baud rate, and for UBX the receiver is asked to enable
    // it, but only the configured protocol is used and counts as data
    if (!protocol_allowed(frame.type))
        return;

    const auto now = std::chrono::steady_clock::now();

    // Location or fix; reports which only carry signal quality don't decide the protocol
    const bool nav = has_update && !update.empty();

    if (binary && nav) {
        last_binary_fix = now;

        if (!using_binary) {
            using_binary = true;
            binary_name = frame.type == gps_framer_v1::frame_type::sirf ? "SiRF" : "UBX";
            _MSG_INFO("(GPS) Serial GPS {} is sending {} navigation reports; using them instead "
                    "of NMEA", active_device, binary_name);
        }
    } else if (!binary && nav && using_binary && now - last_binary_fix > binary_fix_stale) {
        using_binary = false;
        _MSG_INFO("(GPS) Serial GPS {} stopped sending {} navigation reports; using NMEA",
                active_device, binary_name);
    }

    // Binary reports are more complete; NMEA only fills in when they stop, except for
    // signal quality the binary reports don't carry
    if (nav && (binary || !using_binary))
        apply_fix(update);
    else if (has_update && !update.quality.empty())
        apply_quality(update.quality);
    else
        set_int_gps_data_time(time(0));

    garbage_since_frame = 0;
    reconnect_failures = 0;
    fast_retry_used = false;
    last_data_time = time(0);

    if (in_error) {
        in_error = false;
        _MSG_INFO("(GPS) Serial GPS {} is working again at {} baud", active_device, active_baud);
    }
}

void kis_gps_serial_v3::queue_write(std::string data) {
    if (!port_open)
        return;

    write_queue.push_back(std::move(data));

    if (!write_active)
        start_write();
}

void kis_gps_serial_v3::start_write() {
    if (write_queue.empty()) {
        write_active = false;
        return;
    }

    write_active = true;

    // Owned by the handler so closing the port can drop the queue at any time
    auto buf = std::make_shared<std::string>(std::move(write_queue.front()));
    write_queue.pop_front();

    boost::asio::async_write(serialport, boost::asio::buffer(*buf),
            boost::asio::bind_executor(strand_,
                [self = shared_from_this(), gen = generation, buf](const boost::system::error_code& ec,
                    std::size_t) {
                    if (gen != self->generation)
                        return;

                    if (ec) {
                        self->write_active = false;

                        if (ec != boost::asio::error::operation_aborted)
                            self->handle_port_error("writing to", ec, false);

                        return;
                    }

                    self->start_write();
                }));
}

void kis_gps_serial_v3::handle_port_error(const std::string& what, const boost::system::error_code& ec,
        bool read_error) {
    if (!in_error) {
        in_error = true;
        _MSG_ERROR("(GPS) Error {} serial GPS {}: {}", what, active_device, ec.message());
    }

    close_port();
    schedule_reconnect(read_error);
}

void kis_gps_serial_v3::arm_cfg_timer(std::chrono::milliseconds delay, std::function<void ()> fn) {
    cfg_timer.expires_after(delay);
    cfg_timer.async_wait(boost::asio::bind_executor(strand_,
                [weak = weak_from_this(), gen = generation, step = ++cfg_step, fn = std::move(fn)]
                (const boost::system::error_code& ec) {
                    auto self = weak.lock();

                    if (ec || self == nullptr || gen != self->generation || step != self->cfg_step)
                        return;

                    fn();
                }));
}

void kis_gps_serial_v3::ubx_command(std::string cmd, uint8_t msg_class, uint8_t msg_id, bool ack,
        ubx_reply_cb cb) {
    ubx_expect.active = true;
    ubx_expect.ack = ack;
    ubx_expect.msg_class = msg_class;
    ubx_expect.msg_id = msg_id;
    ubx_expect.cb = std::move(cb);

    arm_cfg_timer(ubx_reply_timeout, [this]() {
                if (!ubx_expect.active)
                    return;

                auto cb = std::move(ubx_expect.cb);
                ubx_expect = {};
                cb(false, {});
            });

    queue_write(std::move(cmd));
}

void kis_gps_serial_v3::ubx_check_reply(std::string_view frame) {
    if (!ubx_expect.active)
        return;

    uint8_t msg_class, msg_id;
    if (!gps_ubx_decoder_v1::frame_id(frame, msg_class, msg_id))
        return;

    ubx_ack ack;
    bool ok;

    if (gps_ubx_decoder_v1::parse_ack(frame, ack)) {
        if (ack.msg_class != ubx_expect.msg_class || ack.msg_id != ubx_expect.msg_id)
            return;

        // A NAK also answers a poll
        if (!ubx_expect.ack && ack.ack)
            return;

        ok = ack.ack;
    } else if (!ubx_expect.ack && msg_class == ubx_expect.msg_class && msg_id == ubx_expect.msg_id) {
        ok = true;
    } else {
        return;
    }

    auto cb = std::move(ubx_expect.cb);
    ubx_expect = {};
    cfg_step++;
    cfg_timer.cancel();

    cb(ok, frame);
}

void kis_gps_serial_v3::ubx_handle_nmea_hint(std::string_view sentence) {
    // SiRF receivers send proprietary PSRF sentences in NMEA mode
    if (sentence.substr(0, 5) == "$PSRF") {
        sirf_seen();
        return;
    }

    if (ublox_hint)
        return;

    // u-blox receivers announce themselves in TXT sentences at startup, and send PUBX
    if (sentence.substr(0, 5) == "$PUBX" ||
            (sentence.size() > 6 && sentence.substr(3, 3) == "TXT" &&
             (sentence.find("u-blox") != std::string_view::npos ||
              sentence.find("ublox") != std::string_view::npos)))
        ublox_hint = true;
}

void kis_gps_serial_v3::sirf_seen() {
    sirf_hint = true;

    // Nothing has been sent yet in these states; once configuring, a u-blox has answered
    if (ubx_cfg == ubx_cfg_state::idle || ubx_cfg == ubx_cfg_state::observing) {
        ubx_cfg = ubx_cfg_state::done;
        cfg_step++;
        cfg_timer.cancel();
    }
}

void kis_gps_serial_v3::ubx_cfg_begin() {
    if (!ubx_writes_allowed || sirf_hint || ubx_cfg != ubx_cfg_state::idle)
        return;

    ubx_cfg = ubx_cfg_state::observing;
    arm_cfg_timer(ubx_observe, [this]() { ubx_cfg_observed(); });
}

void kis_gps_serial_v3::ubx_nav_seen(uint8_t msg_id) {
    if (ubx_cfg == ubx_cfg_state::observing) {
        if (msg_id == gps_ubx_decoder_v1::nav_pvt || msg_id == gps_ubx_decoder_v1::nav_posllh)
            ubx_seen_pos = true;
        else if (msg_id == gps_ubx_decoder_v1::nav_dop)
            ubx_seen_dop = true;
        else if (msg_id == gps_ubx_decoder_v1::nav_sat || msg_id == gps_ubx_decoder_v1::nav_svinfo)
            ubx_seen_sat = true;

        // Already sending everything; nothing to change
        if (ubx_seen_pos && ubx_seen_dop && ubx_seen_sat) {
            ubx_cfg = ubx_cfg_state::done;
            cfg_step++;
            cfg_timer.cancel();
        }

        return;
    }

    if (ubx_cfg != ubx_cfg_state::confirming || msg_id != ubx_confirm_id)
        return;

    ubx_cfg = ubx_cfg_state::done;
    cfg_step++;
    cfg_timer.cancel();

    bool nav = false, dop = false, sat = false;

    for (const auto& m : ubx_enabled_msgs) {
        if (m.msg == ubx_nav_msg::dop)
            dop = true;
        else if (m.msg == ubx_nav_msg::sat || m.msg == ubx_nav_msg::svinfo)
            sat = true;
        else
            nav = true;
    }

    std::vector<const char *> names;
    if (nav)
        names.push_back("navigation");
    if (dop)
        names.push_back("DOP");
    if (sat)
        names.push_back("satellite");

    std::string what;
    for (size_t i = 0; i < names.size(); i++) {
        if (i > 0)
            what += names.size() > 2 ? ", " : " ";
        if (i > 0 && i == names.size() - 1)
            what += "and ";
        what += names[i];
    }

    _MSG_INFO("(GPS) Serial GPS {} is now sending UBX {} reports; this was changed in the "
            "receiver's RAM only and is undone when Kismet closes the GPS", active_device, what);
}

void kis_gps_serial_v3::ubx_cfg_observed() {
    if (ubx_cfg != ubx_cfg_state::observing || sirf_hint)
        return;

    ubx_cfg = ubx_cfg_state::configuring;

    // One poll to a receiver with no u-blox hints; it isn't a valid NMEA sentence, so
    // other receivers ignore it
    ubx_query_version(ublox_hint ? ubx_command_tries : 1);
}

std::vector<ubx_msg_rate> kis_gps_serial_v3::ubx_wanted_msgs(bool port_keys, bool uart) {
    std::vector<ubx_msg_rate> msgs;

    if (!ubx_seen_pos) {
        // u-blox 6 and older don't report a protocol version or have NAV-PVT
        if (port_keys || ubx_protver >= ubx_protver_pvt)
            msgs.push_back({ubx_nav_msg::pvt, 1});
        else
            msgs.insert(msgs.end(), {{ubx_nav_msg::status, 1}, {ubx_nav_msg::posllh, 1},
                    {ubx_nav_msg::velned, 1}});
    }

    if (!ubx_seen_dop)
        msgs.push_back({ubx_nav_msg::dop, 1});

    const uint8_t sat_rate = uart ? ubx_sat_rate(active_baud) : 1;

    if (!ubx_seen_sat && sat_rate > 0)
        msgs.push_back({port_keys || ubx_protver >= ubx_protver_sat ?
                ubx_nav_msg::sat : ubx_nav_msg::svinfo, sat_rate});

    return msgs;
}

void kis_gps_serial_v3::ubx_enabled(ubx_nav_msg msg, uint8_t rate) {
    ubx_enabled_msgs.push_back({msg, rate});
}

void kis_gps_serial_v3::ubx_query_version(unsigned int tries) {
    ubx_command(gps_ubx_commands_v1::poll_mon_ver(), gps_ubx_decoder_v1::class_mon,
            gps_ubx_decoder_v1::mon_ver, false,
            [this, tries](bool ok, std::string_view frame) {
                if (!ok) {
                    if (tries > 1) {
                        ubx_query_version(tries - 1);
                        return;
                    }

                    // Not a u-blox receiver
                    if (ublox_hint)
                        ubx_cfg_failed("the receiver didn't answer a version request");
                    else
                        ubx_cfg = ubx_cfg_state::done;

                    return;
                }

                ubx_protver = gps_ubx_decoder_v1::parse_protver(frame);
                ubx_enabled_msgs.clear();

                if (ubx_protver >= ubx_protver_no_legacy) {
                    ubx_detect_port(0, [this](bool found, const char *reason) {
                                ubx_detected_for_port_keys(found, reason);
                            });
                    return;
                }

                // The legacy command changes the port it arrives on; knowing which port that is
                // only decides how often satellite reports fit, so a receiver which can't tell
                // is treated as a serial port at the baud rate Kismet is using
                ubx_detect_port(0, [this](bool found, const char *) {
                            const bool uart = !found || ubx_detected_port == ubx_port::uart1 ||
                                ubx_detected_port == ubx_port::uart2;

                            ubx_enable_msgs = ubx_wanted_msgs(false, uart);
                            ubx_enable_current_port(0, ubx_command_tries);
                        });
            });
}

void kis_gps_serial_v3::ubx_enable_current_port(size_t index, unsigned int tries) {
    if (index >= ubx_enable_msgs.size()) {
        ubx_confirm();
        return;
    }

    const auto m = ubx_enable_msgs[index];

    ubx_command(gps_ubx_commands_v1::set_nav_rate_current_port(m.msg, m.rate),
            gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_msg, true,
            [this, index, tries, m](bool ok, std::string_view frame) {
                if (ok) {
                    // Only this port was changed, and the receiver wasn't sending it, so
                    // restoring sets it back to 0
                    if (std::find(restore_msgs.begin(), restore_msgs.end(), m.msg) == restore_msgs.end())
                        restore_msgs.push_back(m.msg);

                    ubx_enabled(m.msg, m.rate);
                    ubx_enable_current_port(index + 1, ubx_command_tries);
                    return;
                }

                // Timed out; try again
                if (frame.empty() && tries > 1) {
                    ubx_enable_current_port(index, tries - 1);
                    return;
                }

                // Newer receivers may refuse the legacy command; use our port's keys instead
                if (index == 0 && !frame.empty() && ubx_protver >= ubx_protver_comms) {
                    if (ubx_port_known)
                        ubx_detected_for_port_keys(true, "");
                    else
                        ubx_detect_port(0, [this](bool found, const char *reason) {
                                    ubx_detected_for_port_keys(found, reason);
                                });
                    return;
                }

                // Firmware without a quality report refuses it; the location doesn't need it
                if (!frame.empty() && (m.msg == ubx_nav_msg::dop || m.msg == ubx_nav_msg::sat ||
                            m.msg == ubx_nav_msg::svinfo)) {
                    ubx_enable_current_port(index + 1, ubx_command_tries);
                    return;
                }

                ubx_cfg_failed(frame.empty() ? "the receiver didn't answer" :
                        "the receiver refused the change");
            });
}

std::string kis_gps_serial_v3::ubx_port_stats_poll() const {
    return ubx_protver >= ubx_protver_comms ? gps_ubx_commands_v1::poll_mon_comms() :
        gps_ubx_commands_v1::poll_mon_io();
}

bool kis_gps_serial_v3::ubx_parse_port_stats(std::string_view frame,
        std::vector<ubx_port_stats>& ports) const {
    return ubx_protver >= ubx_protver_comms ? gps_ubx_decoder_v1::parse_mon_comms(frame, ports) :
        gps_ubx_decoder_v1::parse_mon_io(frame, ports);
}

void kis_gps_serial_v3::ubx_detect_port(unsigned int attempt, ubx_detect_cb cb) {
    if (attempt >= ubx_detect_padding.size()) {
        cb(false, "couldn't tell which receiver port Kismet is attached to");
        return;
    }

    const uint8_t poll_id = ubx_protver >= ubx_protver_comms ? gps_ubx_decoder_v1::mon_comms :
        gps_ubx_decoder_v1::mon_io;

    ubx_command(ubx_port_stats_poll(), gps_ubx_decoder_v1::class_mon, poll_id, false,
            [this, attempt, cb = std::move(cb)](bool ok, std::string_view frame) mutable {
                std::vector<ubx_port_stats> first;

                if (!ok || !ubx_parse_port_stats(frame, first)) {
                    cb(false, "the receiver didn't report its port statistics");
                    return;
                }

                const auto first_rx = rx_total;

                // Padding plus the second poll is exactly what our port should receive
                // between the two readings
                size_t sent = 0;
                for (unsigned int i = 0; i < ubx_detect_padding[attempt]; i++) {
                    auto pad = gps_ubx_commands_v1::poll_mon_ver();
                    sent += pad.size();
                    queue_write(std::move(pad));
                }

                sent += ubx_port_stats_poll().size();

                ubx_detect_compare(attempt, std::move(first), first_rx, sent, std::move(cb));
            });
}

void kis_gps_serial_v3::ubx_detect_compare(unsigned int attempt, std::vector<ubx_port_stats> first,
        uint64_t first_rx, size_t sent, ubx_detect_cb cb) {
    const uint8_t poll_id = ubx_protver >= ubx_protver_comms ? gps_ubx_decoder_v1::mon_comms :
        gps_ubx_decoder_v1::mon_io;

    ubx_command(ubx_port_stats_poll(), gps_ubx_decoder_v1::class_mon, poll_id, false,
            [this, attempt, first = std::move(first), first_rx, sent, cb = std::move(cb)]
            (bool ok, std::string_view frame) mutable {
                std::vector<ubx_port_stats> second;

                if (!ok || !ubx_parse_port_stats(frame, second)) {
                    cb(false, "the receiver didn't report its port statistics");
                    return;
                }

                // Our port received exactly what we sent, and sent about what we read; the
                // reads are counted per chunk, so allow for data in flight at each reading
                const uint64_t we_read = rx_total - first_rx;
                const uint64_t slack = std::max<uint64_t>(256, we_read / 4);

                unsigned int matches = 0;
                ubx_port found = ubx_port::uart1;

                for (const auto& s : second) {
                    for (const auto& f : first) {
                        if (f.port != s.port)
                            continue;

                        const uint32_t rx = s.rx_bytes - f.rx_bytes;
                        const uint32_t tx = s.tx_bytes - f.tx_bytes;
                        const uint64_t diff = tx > we_read ? tx - we_read : we_read - tx;

                        if (rx == sent && diff <= slack) {
                            matches++;
                            found = s.port;
                        }
                    }
                }

                if (matches != 1) {
                    ubx_detect_port(attempt + 1, std::move(cb));
                    return;
                }

                ubx_detected_port = found;
                ubx_port_known = true;
                cb(true, "");
            });
}

void kis_gps_serial_v3::ubx_detected_for_port_keys(bool found, const char *reason) {
    if (!found) {
        ubx_cfg_failed(reason);
        return;
    }

    ubx_check_port_baud();
}

void kis_gps_serial_v3::ubx_check_port_baud() {
    auto cmd = gps_ubx_commands_v1::get_uart_baud(ubx_detected_port);

    // USB, I2C, and SPI have no baud rate to check
    if (cmd.empty()) {
        ubx_enable_port_key(0);
        return;
    }

    ubx_command(std::move(cmd), gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_valget, false,
            [this](bool ok, std::string_view frame) {
                uint32_t baud = 0;

                if (!ok || !gps_ubx_decoder_v1::parse_valget(frame,
                            gps_ubx_commands_v1::uart_baud_key(ubx_detected_port), baud) ||
                        baud != active_baud) {
                    ubx_cfg_failed("the receiver port doesn't match the baud rate Kismet is using");
                    return;
                }

                ubx_enable_port_key(0);
            });
}

void kis_gps_serial_v3::ubx_enable_port_key(size_t index) {
    const auto port = ubx_detected_port;

    if (index == 0) {
        ubx_enabled_msgs.clear();
        ubx_enable_msgs = ubx_wanted_msgs(true,
                port == ubx_port::uart1 || port == ubx_port::uart2);
    }

    if (index >= ubx_enable_msgs.size()) {
        ubx_confirm();
        return;
    }

    const auto m = ubx_enable_msgs[index];
    const bool required = m.msg == ubx_nav_msg::pvt;

    ubx_command(gps_ubx_commands_v1::get_nav_rate(m.msg, port), gps_ubx_decoder_v1::class_cfg,
            gps_ubx_decoder_v1::cfg_valget, false,
            [this, port, m, index, required](bool ok, std::string_view frame) {
                uint32_t old_rate = 0;

                if (!ok || !gps_ubx_decoder_v1::parse_valget(frame,
                            gps_ubx_commands_v1::nav_rate_key(m.msg, port), old_rate) || old_rate > 0xFF) {
                    if (required) {
                        ubx_cfg_failed("the receiver didn't report its current settings");
                        return;
                    }

                    ubx_enable_port_key(index + 1);
                    return;
                }

                // Already sent, slower than the observing window caught; leave it alone
                if (old_rate != 0) {
                    ubx_enable_port_key(index + 1);
                    return;
                }

                ubx_command(gps_ubx_commands_v1::set_nav_rate(m.msg, port, m.rate),
                        gps_ubx_decoder_v1::class_cfg, gps_ubx_decoder_v1::cfg_valset, true,
                        [this, port, m, index, required, old_rate](bool ok, std::string_view) {
                            if (!ok) {
                                if (required) {
                                    ubx_cfg_failed("the receiver refused the change");
                                    return;
                                }

                                ubx_enable_port_key(index + 1);
                                return;
                            }

                            // Keep the first saved value; a reopen without a power cycle reads
                            // back our own change
                            const bool saved = std::any_of(restore_keys.begin(), restore_keys.end(),
                                    [&](const ubx_restore_key& k) {
                                        return k.msg == m.msg && k.port == port;
                                    });

                            if (!saved)
                                restore_keys.push_back({m.msg, port, static_cast<uint8_t>(old_rate)});

                            ubx_enabled(m.msg, m.rate);
                            ubx_enable_port_key(index + 1);
                        });
            });
}

void kis_gps_serial_v3::ubx_confirm() {
    if (ubx_enabled_msgs.empty()) {
        ubx_cfg = ubx_cfg_state::done;
        return;
    }

    // The position report is what matters most; for u-blox 6 that's POSLLH
    auto confirm = ubx_enabled_msgs.front();

    for (const auto& m : ubx_enabled_msgs) {
        if (m.msg == ubx_nav_msg::pvt || m.msg == ubx_nav_msg::posllh) {
            confirm = m;
            break;
        }
    }

    ubx_confirm_id = static_cast<uint8_t>(confirm.msg);
    ubx_cfg = ubx_cfg_state::confirming;

    // A report sent every n solutions takes n seconds at the usual 1Hz
    arm_cfg_timer(ubx_confirm_wait + std::chrono::seconds(confirm.rate - 1), [this]() {
                if (ubx_cfg != ubx_cfg_state::confirming)
                    return;

                ubx_cfg_failed("the receiver accepted the change but didn't send reports");
            });
}

void kis_gps_serial_v3::ubx_cfg_failed(const std::string& reason) {
    ubx_cfg = ubx_cfg_state::done;
    ubx_expect = {};
    cfg_step++;
    cfg_timer.cancel();

    ubx_restore_now();

    if (!logged_ubx_failure) {
        logged_ubx_failure = true;

        if (ubx_seen_pos)
            _MSG_INFO("(GPS) Serial GPS {} couldn't enable UBX DOP and satellite reports ({}); "
                    "the signal quality comes from what the receiver already sends.",
                    active_device, reason);
        else
            _MSG_INFO("(GPS) Serial GPS {} looks like a u-blox receiver, but Kismet couldn't enable UBX "
                    "navigation reports ({}); using NMEA.", active_device, reason);
    }
}

std::vector<std::string> kis_gps_serial_v3::ubx_restore_commands() {
    std::vector<std::string> cmds;

    for (auto m : restore_msgs)
        cmds.push_back(gps_ubx_commands_v1::set_nav_rate_current_port(m, 0));

    for (const auto& k : restore_keys)
        cmds.push_back(gps_ubx_commands_v1::set_nav_rate(k.msg, k.port, k.value));

    restore_msgs.clear();
    restore_keys.clear();

    return cmds;
}

void kis_gps_serial_v3::ubx_restore_now() {
    for (auto& c : ubx_restore_commands())
        queue_write(std::move(c));
}

void kis_gps_serial_v3::ubx_restore_on_close() {
    auto cmds = ubx_restore_commands();

    if (cmds.empty() || !serialport.is_open())
        return;

    // The port is about to close, so write directly; closing the tty waits for the output
    // to drain
    boost::system::error_code ec;
    serialport.cancel(ec);

    for (const auto& c : cmds) {
        boost::asio::write(serialport, boost::asio::buffer(c), ec);

        if (ec)
            break;
    }
}

bool kis_gps_serial_v3::protocol_allowed(gps_framer_v1::frame_type type) const {
    switch (active_protocol) {
        case gps_protocol::nmea:
            return type == gps_framer_v1::frame_type::nmea;
        case gps_protocol::ubx:
            return type == gps_framer_v1::frame_type::ubx;
        case gps_protocol::sirf:
            return type == gps_framer_v1::frame_type::sirf;
        default:
            return true;
    }
}

bool kis_gps_serial_v3::get_location_valid() {
    kis_lock_guard<kis_mutex> lk(data_mutex, "gps_serial_v3 get_location_valid");

    if (gps_location == nullptr) {
        return false;
    }

    if (gps_location->fix < 2) {
        return false;
    }

    time_t now = time(0);

    if (now - gps_location->tv.tv_sec > 10) {
        return false;
    }

    return true;
}

bool kis_gps_serial_v3::get_device_connected() {
    return port_open;
}
