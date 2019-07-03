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

// Maximum of 6 octets in a "mac" we handle
#define MAC_LEN_MAX		6

// Mac address transformed into 64bit int for fast sorting
//
// Supports mac addresses up to 7 octets, with optional
// masking, IP-subnet style.
//
struct mac_addr {
    uint64_t longmac;
    uint64_t longmask;
    int error;

    // Convert a string mac address to the long-int storage format, with 
    // mask conversion if present.
    void string2long(const char *in) {
        error = 0;
        longmac = 0;
        longmask = (uint64_t) -1;

        short unsigned int byte;

        int nbyte = 0;
        int mode = 0;

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
                // printf("couldn't read byte in pos %d '%s' %x\n", nbyte, in, in[0]);
                error = 1;
                break;
            }

            if (strlen(in) >= 2)
                in += 2;
            else
                in++;

            if (nbyte >= MAC_LEN_MAX) {
                // printf("pos > max len\n");
                error = 1;
                break;
            }

            if (mode == 0) {
                longmac |= (uint64_t) byte << ((MAC_LEN_MAX - nbyte - 1) * 8);
            } else if (mode == 1) {
                longmask |= (uint64_t) byte << ((MAC_LEN_MAX - nbyte - 1) * 8);
            }

            nbyte++;
        }
    }

    constexpr mac_addr() :
        longmac(0),
        longmask((uint64_t) -1),
        error(0) { }

    constexpr mac_addr(const mac_addr& in) :
        longmac {in.longmac},
        longmask {in.longmask},
        error {in.error} { }

    mac_addr(const char *in) {
        string2long(in);
    }

    mac_addr(const std::string& in) {
        string2long(in.c_str());
    }

    constexpr mac_addr(int in __attribute__((unused)))  :
        longmac{0},
        longmask{(uint64_t) -1},
        error{0} { }

    mac_addr(const uint8_t *in, unsigned int len) {
        error = 0;
        longmac = 0;
        longmask = (uint64_t) -1;

        for (unsigned int x = 0; x < len && x < MAC_LEN_MAX; x++) {
            uint64_t v = in[x];
            longmac |= v << ((MAC_LEN_MAX - x - 1) * 8);
        }
    }

    mac_addr(const char *in, unsigned int len) {
        error = 0;
        longmac = 0;
        longmask = (uint64_t) -1;

        for (unsigned int x = 0; x < len && x < MAC_LEN_MAX; x++) {
            uint64_t v = (in[x] & 0xFF);
            longmac |= v << ((MAC_LEN_MAX - x - 1) * 8);
        }
    }

    // slash-style byte count mask
    mac_addr(const uint8_t *in, unsigned int len, unsigned int mask) {
        error = 0;
        longmac = 0;
        longmask = (uint64_t) -1;

        for (unsigned int x = 0; x < len && x < MAC_LEN_MAX; x++) {
            longmac |= (uint64_t) in[x] << ((MAC_LEN_MAX - x - 1) * 8);
        }

        longmask = (longmask >> (64 - mask)) << mask;
    }

    // Convert a string to a positional search fragment, places fragent
    // in ret_term and length of fragment in ret_len
    inline static bool PrepareSearchTerm(const std::string& s, uint64_t &ret_term, unsigned int &ret_len) {
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

    // Match against a partial MAC address, prepared with PrepareSearchTerm
    bool PartialSearch(uint64_t in_term, unsigned int in_len) const {
        unsigned char *rt = (uint8_t *) &in_term;
        unsigned char *rlm = (uint8_t *) &longmac;

        for (unsigned int p = 0; p <= MAC_LEN_MAX - in_len; p++) 
            if (memcmp(rt, rlm + p, in_len) == 0)
                return true;
        return false;
    }

    // bitwise-and
    constexpr17 bool bitwise_and(const mac_addr& op) const {
        return (longmac & op.longmac);
    }

    // Masked MAC compare
    constexpr17 bool operator== (const mac_addr& op) const {
        if (longmask < op.longmask)
            return ((longmac & longmask) == (op.longmac & longmask));
        return ((longmac & op.longmask) == (op.longmac & op.longmask));
    }

    constexpr17 bool operator== (const uint64_t op) const {
        return longmac == op;
	}

    // MAC compare
    constexpr17 bool operator!= (const mac_addr& op) const {
        if (longmask < op.longmask)
            return ((longmac & longmask) != (op.longmac & longmask));
        return ((longmac & op.longmask) != (op.longmac & op.longmask));
    }

    // mac less-than-eq
    constexpr17 bool operator<=(const mac_addr& op) const {
        return (longmac & longmask) == (op.longmac & longmask);
    }

    // MAC less-than for STL sorts...
    constexpr17 bool operator< (const mac_addr& op) const {
        return ((longmac & longmask) < (op.longmac & longmask));
    }

    mac_addr& operator= (const mac_addr& op) {
        longmac = op.longmac;
        longmask = op.longmask;
        error = op.error;
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
        // Bitshift kung-foo
        return (uint8_t) (val >> ((MAC_LEN_MAX - index - 1) * 8));
    }

    constexpr17 unsigned int operator[] (int index) const {
        int mdex = index;
        if (index < 0 || index >= MAC_LEN_MAX)
            mdex = 0;
        return index64(longmac, mdex);
    }

	// Return the top 3 of the mac. 
	constexpr17 uint32_t OUI() const {
		return (longmac >> (3 * 8)) & 0x00FFFFFF;
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

    inline std::string asString() const {
        return Mac2String();
    }

    inline std::string Mac2String() const {
        return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
                index64(longmac, 3), index64(longmac, 4), index64(longmac, 5));
    }

    inline std::string MacMask2String() const {
        return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                index64(longmask, 3), index64(longmask, 4), index64(longmask, 5));
    }

    constexpr17 uint64_t GetAsLong() const {
        return longmac;
    }

    inline std::string MacFull2String() const {
        return fmt::format("{}/{}", Mac2String(), MacMask2String());
    }

    friend std::ostream& operator<<(std::ostream& os, const mac_addr& m);
    friend std::istream& operator>>(std::istream& is, mac_addr& m);
};

std::ostream& operator<<(std::ostream& os, const mac_addr& m);
std::istream& operator>>(std::istream& is, mac_addr& m);

#endif

