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

#include <stdlib.h>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <sstream>

#ifndef __BASE64_H__
#define __BASE64_H__

/* Unexciting base64 implementation 
 * Needed to handle b64 encoded post data for the webserver
 */

namespace base64_tables {
    inline constexpr std::array<char, 64> alphabet{
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    // Character to 6 bit value, -1 for characters outside the alphabet
    constexpr std::array<int8_t, 256> build_reverse() {
        std::array<int8_t, 256> r{};

        for (auto& v : r)
            v = -1;

        for (size_t i = 0; i < alphabet.size(); i++)
            r[static_cast<uint8_t>(alphabet[i])] = static_cast<int8_t>(i);

        return r;
    }

    inline constexpr std::array<int8_t, 256> reverse = build_reverse();

    static_assert(reverse['A'] == 0 && reverse['a'] == 26 && reverse['0'] == 52 &&
            reverse['+'] == 62 && reverse['/'] == 63, "base64 reverse table");
    static_assert(reverse['='] == -1 && reverse['-'] == -1 && reverse['_'] == -1 &&
            reverse[' '] == -1 && reverse[0x80] == -1, "base64 reverse table invalid chars");
}

class base64 {
public:
    // Decoding stops at the first '=' or character outside the alphabet
    static std::string decode(const std::string_view& in_str) {
        std::string ret;
        ret.resize((in_str.size() / 4) * 3 + 3);

        auto *out = reinterpret_cast<uint8_t *>(&ret[0]);
        uint32_t acc = 0;
        int n = 0;

        for (const auto c : in_str) {
            const auto v = base64_tables::reverse[static_cast<uint8_t>(c)];

            if (v < 0)
                break;

            acc = (acc << 6) | static_cast<uint32_t>(v);

            if (++n == 4) {
                *out++ = static_cast<uint8_t>(acc >> 16);
                *out++ = static_cast<uint8_t>(acc >> 8);
                *out++ = static_cast<uint8_t>(acc);
                acc = 0;
                n = 0;
            }
        }

        // A single trailing character carries no complete byte and is dropped
        if (n == 2) {
            *out++ = static_cast<uint8_t>(acc >> 4);
        } else if (n == 3) {
            *out++ = static_cast<uint8_t>(acc >> 10);
            *out++ = static_cast<uint8_t>(acc >> 2);
        }

        ret.resize(out - reinterpret_cast<uint8_t *>(&ret[0]));

        return ret;
    }

    static std::string decode(const std::string& in_str) {
        return decode(std::string_view{in_str});
    }

    static std::string encode(const std::string_view& in_str) {
        const auto& alphabet = base64_tables::alphabet;

        std::string ret;
        ret.resize(4 * ((in_str.size() + 2) / 3));

        auto *out = &ret[0];
        const auto *p = reinterpret_cast<const uint8_t *>(in_str.data());
        auto len = in_str.size();

        for (; len >= 3; len -= 3, p += 3) {
            *out++ = alphabet[p[0] >> 2];
            *out++ = alphabet[((p[0] & 0x03) << 4) | (p[1] >> 4)];
            *out++ = alphabet[((p[1] & 0x0f) << 2) | (p[2] >> 6)];
            *out++ = alphabet[p[2] & 0x3f];
        }

        if (len == 2) {
            *out++ = alphabet[p[0] >> 2];
            *out++ = alphabet[((p[0] & 0x03) << 4) | (p[1] >> 4)];
            *out++ = alphabet[(p[1] & 0x0f) << 2];
            *out++ = '=';
        } else if (len == 1) {
            *out++ = alphabet[p[0] >> 2];
            *out++ = alphabet[(p[0] & 0x03) << 4];
            *out++ = '=';
            *out++ = '=';
        }

        return ret;
    }

    static std::string encode(const std::string& in_str) {
        return encode(std::string_view{in_str});
    }
};

#endif
