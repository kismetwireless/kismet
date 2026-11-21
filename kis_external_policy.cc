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

#include <chrono>

#include "kis_external_packet.h"
#include "kis_external_policy.h"

std::string_view kis_external_v3_server_api_cmd(uint16_t command) {
    switch (command) {
        case KIS_EXTERNAL_V3_WEB_REGISTERURI:
            return "WEB_REGISTERURI";
        case KIS_EXTERNAL_V3_WEB_RESPONSE:
            return "WEB_RESPONSE";
        case KIS_EXTERNAL_V3_WEB_AUTHREQ:
            return "WEB_AUTHREQ";
        case KIS_EXTERNAL_V3_EVT_REGISTER:
            return "EVT_REGISTER";
        case KIS_EXTERNAL_V3_EVT_PUBLISH:
            return "EVT_PUBLISH";
    }

    return {};
}

bool kis_external_v2_server_api_cmd(std::string_view command) {
    return command == "HTTPREGISTERURI" || command == "HTTPRESPONSE" || command == "HTTPAUTHREQ" ||
        command == "EVENTBUSREGISTER" || command == "EVENTBUSPUBLISH";
}

bool kis_external_v3_remote_handshake_cmd(uint16_t command) {
    switch (command) {
        case KIS_EXTERNAL_V3_CMD_PING:
        case KIS_EXTERNAL_V3_CMD_PONG:
        case KIS_EXTERNAL_V3_CMD_MESSAGE:
        case KIS_EXTERNAL_V3_CMD_SHUTDOWN:
        case KIS_EXTERNAL_V3_KDS_NEWSOURCE:
            return true;
    }

    return false;
}

bool kis_external_v2_remote_handshake_cmd(std::string_view command) {
    return command == "PING" || command == "PONG" || command == "MESSAGE" ||
        command == "SHUTDOWN" || command == "KDSNEWSOURCE";
}

std::optional<uint64_t> kis_log_limiter::due(int64_t now_s) {
    auto start = window_s_.load();

    // Whoever opens a new interval logs; one that loses the race counts against the new one
    if ((start == 0 || now_s - start >= interval_s_) && window_s_.compare_exchange_strong(start, now_s)) {
        used_.store(1);
        return held_.exchange(0);
    }

    if (used_.fetch_add(1) < burst_)
        return held_.exchange(0);

    held_.fetch_add(1);
    return std::nullopt;
}

std::optional<uint64_t> kis_log_limiter::due() {
    const int64_t now_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    return due(now_s);
}

std::string kis_log_suppressed_note(uint64_t suppressed) {
    if (suppressed == 0)
        return {};

    return " (" + std::to_string(suppressed) + " similar suppressed)";
}

namespace {
    constexpr bool ascii_alnum(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }

    constexpr bool route_char(char c) {
        return ascii_alnum(c) || c == '/' || c == '_' || c == '.' || c == '~' || c == '-';
    }

    // RFC 7230 tchar
    constexpr bool token_char(char c) {
        if (ascii_alnum(c))
            return true;

        switch (c) {
            case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
            case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
                return true;
        }

        return false;
    }

    constexpr char ascii_lower(char c) {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    bool iequals(std::string_view a, std::string_view b) {
        if (a.size() != b.size())
            return false;

        for (size_t i = 0; i < a.size(); i++)
            if (ascii_lower(a[i]) != ascii_lower(b[i]))
                return false;

        return true;
    }

    // Headers that set the framing or the connection; the server owns them
    constexpr std::string_view reserved_headers[] = {
        "content-length", "transfer-encoding", "connection", "keep-alive",
        "upgrade", "te", "trailer", "proxy-connection",
    };
}

std::string external_route_problem(std::string_view path) {
    if (path.size() < 2)
        return "route is empty or '/'";

    if (path.size() > kis_external_max_route_len)
        return "route is too long";

    if (path[0] != '/')
        return "route must start with '/'";

    for (size_t i = 0; i < path.size(); i++) {
        if (!route_char(path[i]))
            return "route may only contain A-Z a-z 0-9 / _ . ~ -";

        if (path[i] == '/' && i + 1 < path.size() && (path[i + 1] == '/' || path[i + 1] == '.'))
            return "route has an empty or dot-led path segment";
    }

    return {};
}

bool external_route_verb_ok(std::string_view verb) {
    return verb == "GET" || verb == "POST" || verb == "PUT" || verb == "DELETE";
}

std::string external_route_pattern(std::string_view path) {
    std::string out;
    out.reserve(path.size() + 8);

    for (const auto c : path) {
        if (c == '.')
            out += '\\';
        out += c;
    }

    return out;
}

uint64_t next_external_route_owner() {
    static std::atomic<uint64_t> next_owner{1};
    return next_owner.fetch_add(1, std::memory_order_relaxed);
}

std::string external_route_clash(uint64_t owner, std::string_view verb,
        uint64_t existing_owner, std::string_view existing_verb) {
    if (owner != existing_owner)
        return "path is already registered by another plugin";

    if (verb == existing_verb)
        return "path and method are already registered";

    return {};
}

std::string external_header_problem(std::string_view name, std::string_view value) {
    if (name.empty() || name.size() > kis_external_max_header_name_len)
        return "header name is empty or too long";

    for (const auto c : name)
        if (!token_char(c))
            return "header name has an invalid character";

    for (const auto& r : reserved_headers)
        if (iequals(name, r))
            return "header is set by the server";

    if (value.size() > kis_external_max_header_value_len)
        return "header value is too long";

    // Field content: visible characters, spaces and tabs; bytes >= 0x80 pass as obs-text
    for (const auto c : value) {
        const auto u = static_cast<unsigned char>(c);
        if ((u < 0x20 && u != '\t') || u == 0x7f)
            return "header value has a control character";
    }

    return {};
}
