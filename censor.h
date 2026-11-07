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

#ifndef __CENSOR_H__
#define __CENSOR_H__

// Marked text: message and alert text with the parts that identify a device, a network,
// or a place marked by kind, so the web UI can censor them.  A marked span is
//
//   SOH kind STX value ETX
//
// The plain text is the same with the markers dropped, and is what the console, the logs,
// and the existing endpoints see.  Marker bytes in any text that didn't come from
// censor::format (SSIDs, device names, helper messages, text from the API) are escaped
// as \u0001 etc, so they can't open, close, or forge a span.

#include "config.h"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "fmt.h"

struct mac_addr;
class device_key;
class tracker_element;

namespace censor {

enum class kind : uint8_t {
    mac,
    key,
    ssid,
    name,
    ident,
    ip,
    location,
};

constexpr std::string_view token(kind k) {
    switch (k) {
        case kind::mac: return "mac";
        case kind::key: return "key";
        case kind::ssid: return "ssid";
        case kind::name: return "name";
        case kind::ident: return "id";
        case kind::ip: return "ip";
        case kind::location: return "loc";
    }
    return "id";
}

inline constexpr char span_open = '\x01';
inline constexpr char span_value = '\x02';
inline constexpr char span_close = '\x03';

constexpr bool is_marker(char c) {
    return c == span_open || c == span_value || c == span_close;
}

constexpr bool has_marker(std::string_view s) {
    for (auto c : s)
        if (is_marker(c))
            return true;
    return false;
}

// Append text with any marker bytes escaped
void append_neutral(std::string& out, std::string_view in);
std::string neutralize(std::string_view in);

// The plain text of marked text
std::string strip(std::string_view marked);

// True if marked text is well formed: spans of known kinds, not nested, all closed
bool valid(std::string_view marked);

namespace detail { struct builder; }

// Text that may contain marked spans.  Anything that isn't built by censor::format is
// plain and untrusted, so converting from a string escapes marker bytes; existing
// callers passing a std::string keep working and can't inject spans.
class marked_string {
public:
    marked_string() = default;
    marked_string(std::string_view plain) :
        marked_{neutralize(plain)} { }
    marked_string(const std::string& plain) :
        marked_string(std::string_view{plain}) { }
    marked_string(const char *plain) :
        marked_string(std::string_view{plain == nullptr ? "" : plain}) { }

    const std::string& plain() const {
        return spans_ ? plain_ : marked_;
    }

    // The marked text; the plain text when nothing is marked
    const std::string& marked() const {
        return marked_;
    }

    bool has_spans() const {
        return spans_;
    }

private:
    friend struct detail::builder;

    std::string marked_;
    std::string plain_;
    bool spans_ = false;
};

// Records that also have a marked version, for the marked endpoints and eventbus
class marked_view_source {
public:
    virtual ~marked_view_source() = default;
    virtual std::shared_ptr<tracker_element> marked_view() = 0;
};

// Wrappers naming what a value is: censor::format("probe for {}", censor::ssid(s)).  In a
// plain fmt::format they print only the value.
template <kind K, typename T>
struct span {
    static constexpr kind span_kind = K;
    using value_type = T;
    const T& v;
};

template <typename T> constexpr span<kind::mac, T> mac(const T& v) { return {v}; }
template <typename T> constexpr span<kind::key, T> key(const T& v) { return {v}; }
template <typename T> constexpr span<kind::ssid, T> ssid(const T& v) { return {v}; }
template <typename T> constexpr span<kind::name, T> name(const T& v) { return {v}; }
template <typename T> constexpr span<kind::ident, T> ident(const T& v) { return {v}; }
template <typename T> constexpr span<kind::ip, T> ip(const T& v) { return {v}; }
template <typename T> constexpr span<kind::location, T> loc(const T& v) { return {v}; }

namespace detail {

struct builder {
    static marked_string from_formatted(std::string&& marked);
};

template <typename T> struct is_span : std::false_type { };
template <kind K, typename T> struct is_span<span<K, T>> : std::true_type { };

template <typename T>
constexpr bool is_text_v =
    std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view> ||
    std::is_same_v<std::decay_t<T>, const char *> || std::is_same_v<std::decay_t<T>, char *>;

// A value formatted, then wrapped in markers
template <kind K, typename T>
struct marked_span {
    const T& v;
};

// Text with marker bytes escaped
struct scrubbed_text {
    std::string_view v;
};

// Any other class type, formatted and then escaped
template <typename T>
struct scrubbed {
    const T& v;
};

// Already marked text, written as is
struct raw_marked {
    const marked_string& v;
};

template <typename T>
constexpr decltype(auto) wrap(const T& v) {
    if constexpr (is_span<T>::value) {
        return marked_span<T::span_kind, typename T::value_type>{v.v};
    } else if constexpr (std::is_same_v<T, mac_addr>) {
        return marked_span<kind::mac, mac_addr>{v};
    } else if constexpr (std::is_same_v<T, device_key>) {
        return marked_span<kind::key, device_key>{v};
    } else if constexpr (std::is_same_v<T, marked_string>) {
        return raw_marked{v};
    } else if constexpr (std::is_pointer_v<T> && is_text_v<T>) {
        return scrubbed_text{v == nullptr ? std::string_view{"(null)"} : std::string_view{v}};
    } else if constexpr (is_text_v<T>) {
        return scrubbed_text{std::string_view{v}};
    } else if constexpr (std::is_class_v<T>) {
        return scrubbed<T>{v};
    } else {
        return (v);
    }
}

template <typename T>
using adapt_t = decltype(wrap(std::declval<const T&>()));

// The spec of a replacement field, kept so it can be applied to the value at run time
struct spec_capture {
    std::string_view spec;

    constexpr auto parse_spec(fmt::format_parse_context& ctx) {
        auto it = ctx.begin();
        while (it != ctx.end() && *it != '}')
            ++it;
        spec = std::string_view(ctx.begin(), static_cast<size_t>(it - ctx.begin()));
        return it;
    }

    template <typename T>
    std::string apply(const T& v) const {
        if (spec.empty())
            return fmt::format("{}", v);
        return fmt::format(fmt::runtime(fmt::format("{{:{}}}", spec)), v);
    }
};

}

// Format marked text: mac_addr and device_key values and censor:: wrappers become spans,
// strings and other values are escaped, a marked_string is included as is
template <typename... A>
marked_string format(fmt::format_string<detail::adapt_t<A>...> f, const A&... a) {
    return detail::builder::from_formatted(fmt::format(f, detail::wrap(a)...));
}

}

template <censor::kind K, typename T>
struct fmt::formatter<censor::span<K, T>> : fmt::formatter<T> {
    auto format(const censor::span<K, T>& s, fmt::format_context& ctx) const {
        return fmt::formatter<T>::format(s.v, ctx);
    }
};

template <censor::kind K, typename T>
struct fmt::formatter<censor::detail::marked_span<K, T>> {
    censor::detail::spec_capture sc;

    constexpr auto parse(fmt::format_parse_context& ctx) {
        return sc.parse_spec(ctx);
    }

    auto format(const censor::detail::marked_span<K, T>& s, fmt::format_context& ctx) const {
        std::string out;
        out += censor::span_open;
        out += censor::token(K);
        out += censor::span_value;
        censor::append_neutral(out, sc.apply(s.v));
        out += censor::span_close;
        return fmt::format_to(ctx.out(), "{}", out);
    }
};

template <>
struct fmt::formatter<censor::detail::scrubbed_text> : fmt::formatter<std::string_view> {
    auto format(const censor::detail::scrubbed_text& s, fmt::format_context& ctx) const {
        if (!censor::has_marker(s.v))
            return fmt::formatter<std::string_view>::format(s.v, ctx);
        return fmt::formatter<std::string_view>::format(censor::neutralize(s.v), ctx);
    }
};

template <typename T>
struct fmt::formatter<censor::detail::scrubbed<T>> {
    censor::detail::spec_capture sc;

    constexpr auto parse(fmt::format_parse_context& ctx) {
        return sc.parse_spec(ctx);
    }

    auto format(const censor::detail::scrubbed<T>& s, fmt::format_context& ctx) const {
        auto v = sc.apply(s.v);
        if (censor::has_marker(v))
            v = censor::neutralize(v);
        return fmt::format_to(ctx.out(), "{}", v);
    }
};

template <>
struct fmt::formatter<censor::detail::raw_marked> {
    constexpr auto parse(fmt::format_parse_context& ctx) {
        return ctx.begin();
    }

    auto format(const censor::detail::raw_marked& s, fmt::format_context& ctx) const {
        return fmt::format_to(ctx.out(), "{}", s.v.marked());
    }
};

#endif
