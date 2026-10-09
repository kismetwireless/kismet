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

#ifndef __GPSNMEA_V3_H__
#define __GPSNMEA_V3_H__

#include "config.h"

#include <cstddef>
#include <string_view>

#include "globalregistry.h"
#include "gps_proto.h"
#include "kis_gps.h"

#define ASIO_HAS_STD_CHRONO
#define ASIO_HAS_MOVE

#include "boost/asio.hpp"

// NMEA 0183 sentence decoder; no I/O or state, so it can be shared by any transport
namespace gps_nmea {
    // Standard sentences are at most 82 bytes; leave room for vendor extensions
    static constexpr size_t max_sentence_len = 128;

    enum class result {
        // Sentence decoded into a location update
        update,
        // Valid sentence which carries no location (no fix yet, or an unhandled type)
        ignored,
        // Not an NMEA sentence
        not_nmea,
        bad_checksum,
        // Non-printable data; probably a binary protocol or the wrong baud rate
        binary,
        malformed,
    };

    // Decode one sentence; trailing CR/LF is ignored
    result parse(std::string_view sentence, gps_fix_update& update);

    // Sentence has an address field (GPGGA, PUBX, ...) and a matching *hh checksum; parse
    // accepts sentences without one, but random bytes rarely produce both
    bool has_valid_checksum(std::string_view sentence);
}

// Line-based NMEA reader shared by the serial and TCP GPS drivers; decoding is
// done by gps_nmea

class kis_gps_nmea_v3 : public kis_gps, public std::enable_shared_from_this<kis_gps_nmea_v3> {
public:
    kis_gps_nmea_v3(shared_gps_builder in_builder, uint64_t in_id) :
        kis_gps(in_builder, in_id),
        in_buf{max_line_buffer},
        strand_{Globalreg::globalreg->io.get_executor()},
        stopped{true},
        warned_about_binary{false},
        last_data_time(time(0)) { }

    virtual ~kis_gps_nmea_v3() { };

    virtual void handle_read(const boost::system::error_code& error, std::size_t sz);

    virtual void close_gps() override {
        close();
    }

protected:
    // A device which never sends a newline fails the read instead of growing the buffer
    static constexpr size_t max_line_buffer = 1024;

    virtual void close() = 0;
    virtual void close_impl() = 0;

    virtual void start_read();
    virtual void start_read_impl() = 0;

    boost::asio::streambuf in_buf;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::atomic<bool> stopped;

    // Only touched on the strand
    bool warned_about_binary;

    std::atomic<time_t> last_data_time;
};

#endif
