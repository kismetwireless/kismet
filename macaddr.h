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

#ifndef __MACADDR_H__
#define __MACADDR_H__

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>

#include "fmt.h"
#include "multi_constexpr.h"

#include "regex_adapter.h"

#define MAC_LEN_MAX		8

struct mac_addr {
    // Shifting a 64 bit value by 64 is undefined; clamp to 64 and keep the shift in
    // 0..63, then zero the result for 0 bits.  Branchless since it's on the hash path.
    static constexpr uint64_t bits_to_mask(unsigned int bits) {
        const auto shifted = ~(uint64_t) 0 << ((64 - std::min(bits, 64U)) & 63);
        return shifted & (0 - (uint64_t) (bits != 0));
    }

    // Count of leading 1 bits; clz is undefined for 0, so all-ones is handled explicitly
    static constexpr uint8_t num_left_bits(uint64_t v) {
        if (v == ~(uint64_t) 0)
            return 64;
        return __builtin_clzll(~v);
    }

    uint64_t longmac;
    uint8_t maskbits;

    struct {
        unsigned int len : 3; // base 0
        unsigned int error : 1;
    } __attribute__((packed)) state;

#define LEN_MASK        0x7
#define ERROR_BIT       0x80

    void set_error(bool error) {
        state.error = error;
    }

    constexpr bool error() const {
        return state.error;
    }

    constexpr unsigned int length() const {
        return state.len + 1;
    }

    void set_len(unsigned int len) {
        if (len == 0 || len > 8)
            state.error = true;

        state.len = len - 1;
    }

    void string2long(const char *in) {
        state.len = 5;
        state.error = 0;

        longmac = 0;
        auto longmask = (uint64_t) -1;

        short unsigned int byte;

        int nbyte = 0;
        int mode = 0;
        int len = 0;

        while (*in) {
            if (in[0] == ':') {
                in++;
                continue;
            }

            if (in[0] == '/' || in[0] == '*') {
                longmask = 0L;
                mode = 1;
                nbyte = 0;
                in++;
                continue;
            }

            if (sscanf(in, "%2hX", &byte) != 1) {
                state.error = true;
                break;
            }

            if (strlen(in) >= 2)
                in += 2;
            else
                in++;

            if (nbyte >= MAC_LEN_MAX) {
                state.error = true;
                break;
            }

            if (mode == 0) {
                longmac |= (uint64_t) byte << ((MAC_LEN_MAX - nbyte - 1) * 8);
                len++;
            } else if (mode == 1) {
                longmask |= (uint64_t) byte << ((MAC_LEN_MAX - nbyte - 1) * 8);
            }

            nbyte++;
        }

        maskbits = num_left_bits(longmask);

        // A mask with no leading bits would match everything; reject it, and fall
        // back to an exact match for callers that don't check error()
        if (mode == 1 && maskbits == 0) {
            state.error = true;
            maskbits = 64;
        }

        state.len = len - 1;
    }

    constexpr mac_addr() :
        longmac(0),
        maskbits{64},
        state {
            .len = 5,
            .error = 0
        } { }

    // Defaulted so mac_addr stays trivially copyable and passes in registers
    constexpr mac_addr(const mac_addr& in) = default;
    constexpr mac_addr(mac_addr&& in) noexcept = default;
    mac_addr& operator=(const mac_addr& op) = default;
    mac_addr& operator=(mac_addr&& op) noexcept = default;

    mac_addr(const char *in) {
        string2long(in);
    }

    mac_addr(const std::string& in) {
        string2long(in.c_str());
    }

    constexpr mac_addr(int in __attribute__((unused)))  :
        longmac{0},
        maskbits{64},
        state {
            .len = 5,
            .error = 0
        } { }

    mac_addr(const uint8_t *in, unsigned int len) :
        longmac{0},
        maskbits{64},
        state {
            .len = len - 1,
            .error = 0
        } {
        for (unsigned int x = 0; x < len && x < MAC_LEN_MAX; x++) {
            uint64_t v = in[x];
            longmac |= v << ((MAC_LEN_MAX - x - 1) * 8);
        }
    }

    mac_addr(const char *in, unsigned int len) :
        longmac{0},
        maskbits{64},
        state {
            .len = len - 1,
            .error = 0
        } {

        for (unsigned int x = 0; x < len && x < MAC_LEN_MAX; x++) {
            uint64_t v = (in[x] & 0xFF);
            longmac |= v << ((MAC_LEN_MAX - x - 1) * 8);
        }
    }

    // slash-style byte count mask
    mac_addr(const uint8_t *in, unsigned int len, uint8_t mask) :
        longmac{0},
        maskbits{mask},
        state {
            .len = len - 1,
            .error = 0
        } {
        for (unsigned int x = 0; x < len && x < MAC_LEN_MAX; x++) {
            longmac |= (uint64_t) in[x] << ((MAC_LEN_MAX - x - 1) * 8);
        }
    }

    // Convert a string to a positional search fragment, places fragment
    // in ret_term and length of fragment in ret_len
    static bool prepare_search_term(const std::string& s, uint64_t &ret_term, unsigned int &ret_len) {
        short unsigned int byte;
        int nbyte = 0;
        const char *in = s.c_str();

        uint64_t temp_long = 0LL;

        ret_term = 0LL;

        // Parse the same way as we parse a string into a mac, count the number 
        // of bytes we found
        while (*in) {
            if (in[0] == ':') {
                in++;
                continue;
            }

            if (sscanf(in, "%2hX", &byte) != 1) {
                ret_len = 0;
                return false;
            }

            if (strlen(in) >= 2)
                in += 2;
            else
                break;

            if (nbyte >= MAC_LEN_MAX) {
                ret_len = 0;
                return false;
            }

            temp_long |= (uint64_t) byte << ((MAC_LEN_MAX - nbyte - 1) * 8);

            nbyte++;
        }

        ret_len = nbyte;

        if (nbyte == 0)
            ret_term = 0;
        else
            ret_term = temp_long >> ((MAC_LEN_MAX - nbyte) * 8);

        return true;
    }

    // Match against a partial MAC address, prepared with prepare_search_term; compares
    // each byte-aligned window of longmac by shifting, matching the previous little
    // endian memcmp behavior on any byte order
    constexpr17 bool partial_search(uint64_t in_term, unsigned int in_len) const {
        if (in_len == 0)
            return true;

        if (in_len > MAC_LEN_MAX)
            return false;

        const uint64_t window = in_len >= MAC_LEN_MAX ? ~(uint64_t) 0 :
            ((uint64_t) 1 << (in_len * 8)) - 1;

        for (unsigned int p = 0; p <= MAC_LEN_MAX - in_len; p++)
            if (((longmac >> (p * 8)) & window) == in_term)
                return true;

        return false;
    }

    constexpr17 bool bitwise_and(const mac_addr& op) const {
        return (longmac & op.longmac);
    }

    // Compared under the narrower of the two masks
    constexpr17 bool operator== (const mac_addr& op) const {
        return ((longmac ^ op.longmac) & bits_to_mask(std::min(maskbits, op.maskbits))) == 0;
    }

    constexpr17 bool operator== (const uint64_t op) const {
        return longmac == op;
	}

    constexpr17 bool operator!= (const mac_addr& op) const {
        return !(operator==(op));
    }

    constexpr17 bool operator<=(const mac_addr& op) const {
        const auto mask = bits_to_mask(maskbits);
        return (longmac & mask) <= (op.longmac & mask);
    }

    // MAC less-than for STL sorts...
    constexpr17 bool operator< (const mac_addr& op) const {
        const auto mask = bits_to_mask(maskbits);
        return (longmac & mask) < (op.longmac & mask);
    }

    mac_addr& operator= (const char *in) {
        string2long(in);
        return *this;
    }

    mac_addr& operator++() {
        longmac++;
        return *this;
    }

    mac_addr operator++(int) {
        mac_addr tmp = *this;
        ++*this;
        return tmp;
    }

    constexpr17 unsigned int index64(uint64_t val, int index) const {
        if (index >= MAC_LEN_MAX)
            return 0;

        return (uint8_t) (val >> ((MAC_LEN_MAX - index - 1) * 8));
    }

    constexpr17 unsigned int operator[] (int index) const {
        int mdex = index;
        if (index < 0 || index >= MAC_LEN_MAX)
            mdex = 0;
        return index64(longmac, mdex);
    }

    void set_byte(unsigned int index, uint8_t val) {
        if (index >= MAC_LEN_MAX)
            return;

        uint64_t clear_set = (uint64_t) 0xFF << ((MAC_LEN_MAX - index - 1) * 8);
        longmac &= ~clear_set;
        longmac |= (uint64_t) val << ((MAC_LEN_MAX - index - 1) * 8);
    }

	constexpr17 uint32_t OUI() const {
		return (longmac >> 40) & 0x00FFFFFF;
	}

    constexpr17 static uint32_t OUI(uint8_t *val) {
        return (val[0] << 16) | (val[1] << 8) | val[2];
    }

    constexpr17 static uint32_t OUI(unsigned int *val) {
        return (val[0] << 16) | (val[1] << 8) | val[2];
    }

    constexpr17 static uint32_t OUI(short *val) {
        return (val[0] << 16) | (val[1] << 8) | val[2];
    }

    // Bytes are stored left-aligned in longmac; the first byte is the top byte
    constexpr17 bool is_broadcast() const {
        const unsigned int bits = (state.len + 1) * 8;
        const uint64_t mask = bits >= 64 ? ~(uint64_t) 0 : ~(uint64_t) 0 << (64 - bits);
        return (longmac & mask) == mask;
    }

    // I/G bit of the first byte
    constexpr17 bool is_multicast() const {
        return (longmac >> ((MAC_LEN_MAX - 1) * 8)) & 0x01;
    }

    // Longest formatted mac or mask, 8 bytes as XX:XX:..., no terminator
    static constexpr size_t str_max_len = (MAC_LEN_MAX * 3) - 1;
    using str_buf_t = std::array<char, str_max_len>;

    // Format into a caller buffer without allocating; the view is only valid
    // while buf is
    std::string_view to_chars(str_buf_t& buf) const {
        return std::string_view(buf.data(), format_hex(longmac, buf));
    }

    std::string_view mask_to_chars(str_buf_t& buf) const {
        return std::string_view(buf.data(), format_hex(bits_to_mask(maskbits), buf));
    }

    std::string as_string() const {
        return mac_to_string();
    }

    std::string mac_to_string() const {
        str_buf_t buf;
        return std::string(to_chars(buf));
    }

    std::string mac_mask_to_string() const {
        str_buf_t buf;
        return std::string(mask_to_chars(buf));
    }

    constexpr17 uint64_t get_as_long() const {
        return longmac;
    }

    std::string mac_full_to_string() const {
        str_buf_t buf;
        std::string s;
        s.reserve((str_max_len * 2) + 1);
        s.append(to_chars(buf));
        s.push_back('/');
        s.append(mask_to_chars(buf));
        return s;
    }

    friend std::ostream& operator<<(std::ostream& os, const mac_addr& m);
    friend std::istream& operator>>(std::istream& is, mac_addr& m);

private:
    // Writes the first length() bytes of v as XX:XX:..., returns chars written
    size_t format_hex(uint64_t v, str_buf_t& buf) const {
        constexpr char hex[] = "0123456789ABCDEF";
        const auto len = length();
        size_t p = 0;

        for (unsigned int i = 0; i < len; i++) {
            if (i > 0)
                buf[p++] = ':';

            const auto b = index64(v, i);
            buf[p++] = hex[(b >> 4) & 0xF];
            buf[p++] = hex[b & 0xF];
        }

        return p;
    }
};

static_assert(std::is_trivially_copyable_v<mac_addr>, "mac_addr must stay trivially copyable");
static_assert(mac_addr::bits_to_mask(0) == 0);
static_assert(mac_addr::bits_to_mask(1) == 0x8000000000000000ULL);
static_assert(mac_addr::bits_to_mask(48) == 0xFFFFFFFFFFFF0000ULL);
static_assert(mac_addr::bits_to_mask(64) == ~(uint64_t) 0);
static_assert(mac_addr::bits_to_mask(200) == ~(uint64_t) 0);
static_assert(mac_addr::num_left_bits(0) == 0);
static_assert(mac_addr::num_left_bits(0xFFFFFF0000000000ULL) == 24);
static_assert(mac_addr::num_left_bits(0x7FFFFFFFFFFFFFFFULL) == 0);
static_assert(mac_addr::num_left_bits(~(uint64_t) 0) == 64);

std::ostream& operator<<(std::ostream& os, const mac_addr& m);
std::istream& operator>>(std::istream& is, mac_addr& m);

// Formats straight from a stack buffer; inherits string_view specs like width and alignment
template <> struct fmt::formatter<mac_addr> : fmt::formatter<std::string_view> {
    auto format(const mac_addr& m, fmt::format_context& ctx) const {
        mac_addr::str_buf_t buf;
        return fmt::formatter<std::string_view>::format(m.to_chars(buf), ctx);
    }
};

// A hash algorithm which is unique by mask.
//
// This does NOT make a std::unordered_map suitable for masked comparisons!  For a data
// structure which supports masking, you MUST use a std::map; the operator< function applies
// the mask to both sides of the comparison.
namespace std {
    template<> struct hash<mac_addr> {
        std::size_t operator()(mac_addr const& m) const noexcept {
            auto h = std::hash<uint64_t>{}(m.longmac & m.bits_to_mask(m.maskbits));
            h = h ^ (std::hash<uint64_t>{}(m.state.len));
            return h;
        }
    };
}

namespace kis_regex {
    // both the regex and string comparators are ugly right now & would benefit from
    // figuring out some smarter way of doing in so that there isn't a repeated forced
    // conversion to string
    //
    // conversely, it would take 3x the ram per mac to have a saved string conversion
    template<> struct regex_match<mac_addr> {
        bool operator()(const regex& re, const mac_addr& m) {
            mac_addr::str_buf_t buf;
            return re.match(m.to_chars(buf));
        }
    };

    template<> struct string_match<mac_addr> {
        bool operator()(const std::string& match, const mac_addr& m,
                bool match_icase, bool match_full) {
            return string_match<std::string>{}(match, m.as_string(), match_icase, match_full);
        }
    };
}


#endif

