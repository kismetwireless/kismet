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

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
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

    // Satellites in view arrive as a group of GSV sentences for each constellation (and
    // each signal, on NMEA 4.1 receivers); this combines the complete groups.  Owned by
    // one reader, and not thread safe.
    class gsv_collector {
    public:
        // One GSV sentence; true when it completes a group, with the satellites in view
        // and signal strength of every current group
        bool add(std::string_view talker, const std::string_view *fields, size_t nf,
                time_t now, gps_quality_update& quality);

        void reset() {
            groups = {};
        }

    protected:
        // Constellations and signals
        static constexpr size_t max_groups = 16;
        // Satellites listed in one group
        static constexpr size_t max_sats = 64;
        // A constellation which stops reporting is dropped
        static constexpr time_t group_expire = 3;

        struct satellites {
            size_t count = 0;
            std::array<uint16_t, max_sats> prn{};
            std::array<uint8_t, max_sats> snr{};
        };

        struct group {
            bool used = false;
            char talker[2] = {0, 0};
            uint8_t signal = 0;

            // Group being received
            unsigned int total = 0;
            unsigned int next = 0;
            unsigned int in_view = 0;
            satellites building;

            // Last complete group
            bool complete = false;
            time_t time = 0;
            unsigned int done_in_view = 0;
            satellites done;
        };

        std::array<group, max_groups> groups;
    };

    // Decode one sentence; trailing CR/LF is ignored.  GSV sentences are only decoded with
    // a collector.
    result parse(std::string_view sentence, gps_fix_update& update, gsv_collector *gsv = nullptr);

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
    gps_nmea::gsv_collector gsv;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::atomic<bool> stopped;

    // Only touched on the strand
    bool warned_about_binary;

    std::atomic<time_t> last_data_time;
};

#endif
