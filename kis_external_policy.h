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

#ifndef __KIS_EXTERNAL_POLICY_H__
#define __KIS_EXTERNAL_POLICY_H__

#include "config.h"

#include <atomic>
#include <optional>
#include <stdint.h>
#include <string>
#include <string_view>

// Which external protocol commands a peer may use, and the checks on what an external
// plugin hands the web server.  No server dependencies, so it can be tested on its own.

// Web route, web login and eventbus commands, which only external plugins Kismet launches
// itself may send; the command name, or empty for any other command
std::string_view kis_external_v3_server_api_cmd(uint16_t command);
bool kis_external_v2_server_api_cmd(std::string_view command);

// What a remote capture connection may send before its NEWSOURCE
bool kis_external_v3_remote_handshake_cmd(uint16_t command);
bool kis_external_v2_remote_handshake_cmd(std::string_view command);

// Rate limit for one kind of log line a peer can trigger: at most burst lines per interval,
// whichever thread asks.  Lines held back are counted and the count goes with the next line
// logged; each is counted once, though one racing a logged line may land in the next count,
// and threads racing a new interval may log a line or two past the burst.
class kis_log_limiter {
public:
    explicit constexpr kis_log_limiter(int64_t interval_s, uint64_t burst = 1) noexcept :
        interval_s_{interval_s},
        burst_{burst},
        used_{burst} { }

    kis_log_limiter(const kis_log_limiter&) = delete;
    kis_log_limiter& operator=(const kis_log_limiter&) = delete;

    // When this line may be logged, how many were held back since the last one; nullopt when
    // it is held back too.  The second form reads the monotonic clock.
    std::optional<uint64_t> due(int64_t now_s);
    std::optional<uint64_t> due();

private:
    const int64_t interval_s_;
    const uint64_t burst_;
    // Start of the current interval, 0 before the first line, and the lines asked for in it;
    // used_ starts full, so a thread racing the first line can't pass before it's counted
    std::atomic<int64_t> window_s_{0};
    std::atomic<uint64_t> used_;
    std::atomic<uint64_t> held_{0};
};

// " (N similar suppressed)" for a line that follows N held back ones, or empty for none
std::string kis_log_suppressed_note(uint64_t suppressed);

constexpr size_t kis_external_max_routes = 64;
constexpr size_t kis_external_max_route_len = 256;
constexpr size_t kis_external_max_event_subs = 256;
constexpr size_t kis_external_max_headers = 32;
constexpr size_t kis_external_max_header_name_len = 64;
constexpr size_t kis_external_max_header_value_len = 4096;

// Why a plugin route can't be registered, or empty when it can.  Routes are literal paths:
// '/' then [A-Za-z0-9/_.~-], no empty or dot-led segments, no regex or :param syntax
std::string external_route_problem(std::string_view path);

// GET, POST, PUT or DELETE
bool external_route_verb_ok(std::string_view verb);

// The route pattern the web server compiles for a checked literal path; '.' is the only
// regex metacharacter the path charset allows
std::string external_route_pattern(std::string_view path);

// Who registered a plugin route: one per external interface, never reused
uint64_t next_external_route_owner();

// Why a route can't be added on a path a plugin route already uses, or empty when it can.  A
// path belongs to the plugin that registered it first, which may add each other verb once
std::string external_route_clash(uint64_t owner, std::string_view verb,
        uint64_t existing_owner, std::string_view existing_verb);

// Why a plugin response header can't be sent, or empty when it can: an RFC 7230 token name
// that isn't a framing or connection header, and a value without control characters
std::string external_header_problem(std::string_view name, std::string_view value);

#endif
