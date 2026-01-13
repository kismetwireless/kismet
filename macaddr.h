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
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>

#include "fmt.h"
#include "multi_constexpr.h"

#define MAC_LEN_MAX		8

struct mac_addr {
    constexpr uint64_t bits_to_mask(unsigned int bits) const {
        return ((uint64_t) -1) << (64 - bits);
    }

    uint8_t num_left_bits(uint64_t v) const {
        uint8_t r = 0;
        for (int b = 0; b < 64; b++) {
            if ((v >> (63 - b)) & 0x1) {
                r++;
                continue;
            }

            break;
        }

        return r;
    }

    mac_addr(mac_addr&& o) noexcept :
        longmac{o.longmac},
        maskbits{o.maskbits},
        state {
            .len = o.state.len,
            .error = o.state.error 
        } { }
    
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
        state.len = len - 1;
    }

    constexpr mac_addr() :
        longmac(0),
        maskbits{64},
        state {
            .len = 5,
            .error = 0
        } { }

    constexpr mac_addr(const mac_addr& in) :
        longmac{in.longmac},
        maskbits{in.maskbits},
        state {
            .len = in.state.len,
            .error = in.state.error
        } { }

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
        ret_term = temp_long >> ((MAC_LEN_MAX - nbyte) * 8);

        return true;
    }

    // Match against a partial MAC address, prepared with prepare_search_term
    bool partial_search(uint64_t in_term, unsigned int in_len) const {
        unsigned char *rt = (uint8_t *) &in_term;
        unsigned char *rlm = (uint8_t *) &longmac;

        for (unsigned int p = 0; p <= MAC_LEN_MAX - in_len; p++) 
            if (memcmp(rt, rlm + p, in_len) == 0)
                return true;

        return false;
    }

    constexpr17 bool bitwise_and(const mac_addr& op) const {
        return (longmac & op.longmac);
    }

    constexpr17 bool operator== (const mac_addr& op) const {
        if (maskbits < op.maskbits)
            return ((longmac & bits_to_mask(maskbits)) == (op.longmac & bits_to_mask(maskbits)));
        return ((longmac & op.bits_to_mask(op.maskbits)) == (op.longmac & bits_to_mask(op.maskbits)));
    }

    constexpr17 bool operator== (const uint64_t op) const {
        return longmac == op;
	}

    constexpr17 bool operator!= (const mac_addr& op) const {
        return !(operator==(op));
    }

    constexpr17 bool operator<=(const mac_addr& op) const {
        return (longmac & bits_to_mask(maskbits)) <= (op.longmac & bits_to_mask(maskbits));
    }

    // MAC less-than for STL sorts...
    constexpr17 bool operator< (const mac_addr& op) const {
        return (longmac & bits_to_mask(maskbits)) < (op.longmac & bits_to_mask(maskbits));
    }

    mac_addr& operator= (const mac_addr& op) {
        longmac = op.longmac;
        maskbits = op.maskbits;
        state = op.state;
        return *this;
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

    constexpr17 bool is_broadcast() const {
        const uint64_t fill = -1;
        return (longmac << (8 - (state.len + 1) * 8) == (fill << (8 - (state.len + 1) * 8)));
    }

    constexpr17 bool is_multicast() const {
        return (longmac >> (8 - (state.len + 1) * 8) & 0x01);
    }

    std::string as_string() const {
        return mac_to_string();
    }

    std::string mac_to_string() const {
        switch (state.len) {
            case 0:
                return fmt::format("{:02X}", 
                        index64(longmac, 0));
            case 1:
                return fmt::format("{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1));
            case 2:
                return fmt::format("{:02X}:{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1), index64(longmac, 2));
            case 3:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
                        index64(longmac, 3));
            case 4:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
                        index64(longmac, 3), index64(longmac, 4));
            case 5:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
                        index64(longmac, 3), index64(longmac, 4), index64(longmac, 5));
            case 6:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
                        index64(longmac, 3), index64(longmac, 4), index64(longmac, 5),
                        index64(longmac, 6));
            case 7:
            default:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
                        index64(longmac, 3), index64(longmac, 4), index64(longmac, 5),
                        index64(longmac, 6), index64(longmac, 7));


        }
    }

    std::string mac_mask_to_string() const {
        auto longmask = bits_to_mask(maskbits);
        switch (state.len) {
            case 0:
                return fmt::format("{:02X}", 
                        index64(longmask, 0));
            case 1:
                return fmt::format("{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1));
            case 2:
                return fmt::format("{:02X}:{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1), index64(longmask, 2));
            case 3:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                        index64(longmask, 3));
            case 4:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                        index64(longmask, 3), index64(longmask, 4));
            case 5:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                        index64(longmask, 3), index64(longmask, 4), index64(longmask, 5));
            case 6:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                        index64(longmask, 3), index64(longmask, 4), index64(longmask, 5),
                        index64(longmask, 6));
            case 7:
            default:
                return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                        index64(longmask, 3), index64(longmask, 4), index64(longmask, 5),
                        index64(longmask, 6), index64(longmask, 7));


        }
    }

    constexpr17 uint64_t get_as_long() const {
        return longmac;
    }

    std::string mac_full_to_string() const {
        const auto s = fmt::format("{}/{}", mac_to_string(), mac_mask_to_string());
        return s;
    }

    friend std::ostream& operator<<(std::ostream& os, const mac_addr& m);
    friend std::istream& operator>>(std::istream& is, mac_addr& m);
};

std::ostream& operator<<(std::ostream& os, const mac_addr& m);
std::istream& operator>>(std::istream& is, mac_addr& m);

template <>struct fmt::formatter<mac_addr> : fmt::ostream_formatter {};

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

#endif

