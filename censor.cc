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

#include "censor.h"

namespace censor {

void append_neutral(std::string& out, std::string_view in) {
    for (auto c : in) {
        if (is_marker(c)) {
            // The same escape munge_to_printable uses for control characters
            out += "\\u000";
            out += static_cast<char>('0' + c);
        } else {
            out += c;
        }
    }
}

std::string neutralize(std::string_view in) {
    if (!has_marker(in))
        return std::string{in};

    std::string out;
    out.reserve(in.size() + 16);
    append_neutral(out, in);
    return out;
}

std::string strip(std::string_view marked) {
    std::string out;
    out.reserve(marked.size());

    bool in_kind = false;

    for (auto c : marked) {
        if (c == span_open) {
            in_kind = true;
        } else if (c == span_value) {
            in_kind = false;
        } else if (c == span_close) {
            continue;
        } else if (!in_kind) {
            out += c;
        }
    }

    return out;
}

static bool known_kind(std::string_view t) {
    for (auto k : {kind::mac, kind::key, kind::ssid, kind::name, kind::ident, kind::ip, kind::location})
        if (token(k) == t)
            return true;
    return false;
}

bool valid(std::string_view marked) {
    size_t i = 0;

    while (i < marked.size()) {
        auto c = marked[i];

        if (c == span_value || c == span_close)
            return false;

        if (c != span_open) {
            i++;
            continue;
        }

        auto v = marked.find(span_value, i + 1);
        if (v == std::string_view::npos || !known_kind(marked.substr(i + 1, v - i - 1)))
            return false;

        auto e = marked.find(span_close, v + 1);
        if (e == std::string_view::npos)
            return false;

        for (auto j = v + 1; j < e; j++)
            if (marked[j] == span_open || marked[j] == span_value)
                return false;

        i = e + 1;
    }

    return true;
}

marked_string detail::builder::from_formatted(std::string&& marked) {
    marked_string r;
    r.marked_ = std::move(marked);
    r.spans_ = has_marker(r.marked_);
    if (r.spans_)
        r.plain_ = strip(r.marked_);
    return r;
}

}
