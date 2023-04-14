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

#ifndef __UUID_H__
#define __UUID_H__

#include "config.h"

#include <string>
#include <sstream>
#include <sys/time.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "util.h"
#include "fmt.h"

// UUID Generation
// From e2fstools, Theodore Ts'o

/* Assume that the gettimeofday() has microsecond granularity */
#define MAX_ADJUSTMENT 10

class uuid {
public:
    uuid() {
        time_low = 0;
        time_mid = 0;
        time_hi = 0;
        clock_seq = 0;
        node = 0;
        hash = 0;

        error = 1;
    }

    uuid(const uuid& u) {
        time_low = u.time_low;
        time_mid = u.time_mid;
        time_hi = u.time_hi;
        clock_seq = u.clock_seq;
        node = u.node;
        error = u.error;
        hash = u.hash;
    }

    uuid(uuid&& o) noexcept :
        time_low{o.time_low},
        time_mid{o.time_mid},
        time_hi{o.time_hi},
        clock_seq{o.clock_seq},
        node{o.node},
        hash{o.hash},
        error{o.error} { }

    uuid(const std::string& in) {
        from_string(in);
    }

    uuid(uint8_t *in_node) {
        generate_time_uuid(in_node);
    }

    void from_string(const std::string& in) {
        error = 0;
        time_low = 0;
        time_mid = 0;
        time_hi = 0;
        clock_seq = 0;
        node = 0;
        hash = 0;

        uint8_t node_f[6];

        if (sscanf(in.c_str(), "%08x-%04hx-%04hx-%04hx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                    &time_low, &time_mid, &time_hi, &clock_seq,
                    &node_f[0], &node_f[1], &node_f[2], &node_f[3], &node_f[4], &node_f[5]) != 10)
            error = 1;

        node =
            ((uint64_t) node_f[5] << 40) |
            ((uint64_t) node_f[4] << 32) |
            ((uint64_t) node_f[3] << 24) |
            ((uint64_t) node_f[2] << 16) |
            ((uint64_t) node_f[1] << 8) |
            ((uint64_t) node_f[0]);
        hash = gen_hash();
    }

    void generate_random_time_uuid() {
        uint32_t clock_mid;

        time_low = 0;
        time_mid = 0;
        time_hi = 0;
        clock_seq = 0;
        node = 0;

        get_clock(&clock_mid, &time_low, &clock_seq);

        clock_seq |= 0x8000;
        time_mid = (uint16_t) clock_mid;
        time_hi = ((clock_mid >> 16) & 0x0FFF) | 0x1000;
#ifdef LITTLE_ENDIAN
        get_random_bytes(reinterpret_cast<uint8_t *>(&node), 6);
#else
        get_random_bytes(reinterpret_cast<uint8_t *>(&node) + 2, 6);
#endif
        error = 0;
        hash = gen_hash();
    }

    void generate_time_uuid(uint8_t *in_node) {
        uint32_t clock_mid;

        time_low = 0;
        time_mid = 0;
        time_hi = 0;
        clock_seq = 0;
        node = 0;

        get_clock(&clock_mid, &time_low, &clock_seq);

        clock_seq |= 0x8000;
        time_mid = (uint16_t) clock_mid;
        time_hi = ((clock_mid >> 16) & 0x0FFF) | 0x1000;
#ifdef LITTLE_ENDIAN
        memcpy(reinterpret_cast<uint8_t *>(&node), in_node, 6);
#else
        memcpy(reinterpret_cast<uint8_t *>(&node) + 2, in_node, 6);
#endif
        error = 0;
        hash = gen_hash();
    }

    std::string as_string() const {
        return uuid_to_string();
    }

    std::string uuid_to_string() const {
        return fmt::format("{:08X}-{:04X}-{:04X}-{:04X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                time_low, time_mid, time_hi, clock_seq, 
                (uint8_t) (node), (uint8_t) (node >> 8), (uint8_t) (node >> 16),
                (uint8_t) (node >> 24), (uint8_t) (node >> 32),
                (uint8_t) (node >> 40));
    }

    // Stub compares - this cannot hold the full hash and should only be used to compare to 0
    inline bool operator== (const unsigned int op) const {
        if (op != 0)
            throw std::runtime_error("attempt to compare uuid to non-zero unsigned int");

        return (unsigned int) hash == op;
    }

    inline bool operator== (const int op) const {
        if (op != 0)
            throw std::runtime_error("attempt to compare uuid to non-zero int");

        return (int) hash == op;
    }

    inline bool operator== (const void *op) const {
        if (op == nullptr && hash == 0)
            return true;

        return false;
    }

    inline bool operator== (const uuid& op) const {
        return (hash == op.hash);
        /*
        return (time_low == op.time_low && time_mid == op.time_mid &&
                time_hi == op.time_hi && clock_seq == op.clock_seq &&
                node == op.node);
                */
    }

    inline bool operator!= (const uuid& op) const {
        return (hash != op.hash);
        /*
        return (time_low != op.time_low || time_mid != op.time_mid ||
                time_hi != op.time_hi || clock_seq != op.clock_seq ||
                node != op.node);
                */
    }

    inline bool operator<= (const uuid& op) const {
        return hash <= op.hash;
    }

    inline bool operator< (const uuid& op) const {
        return hash < op.hash;
    }

    uuid& operator= (const uuid& op) {
        time_low = op.time_low;
        time_mid = op.time_mid;
        time_hi = op.time_hi;
        clock_seq = op.clock_seq;
        node = op.node;
        hash = op.hash;

        error = op.error;
        return *this;
    }

    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi;
    uint16_t clock_seq;
    uint64_t node;

    std::size_t hash;

    uint8_t error;

protected:
    std::size_t gen_hash() {
        return std::hash<std::string>{}(as_string());
    }

    void get_random_bytes(void *buf, int nbytes) {
        int i, r;
        unsigned char *cp = (unsigned char *) buf;

        FILE *random;

        if ((random = fopen("/dev/urandom", "rb")) != NULL) {
            r = fread(buf, nbytes, 1, random);
            fclose(random);

            if (r >= 1)
                return;
        }

        if ((random = fopen("/dev/random", "rb")) != NULL) {
            r = fread(buf, nbytes, 1, random);
            fclose(random);

            if (r >= 1)
                return;
        }

        // If we didn't get enough random data or couldn't open our random files
        // use a crappy rand(); this is NOT crypto sensitive

        for (cp = (unsigned char *) buf, i = 0; i < nbytes; i++)
            *cp++ ^= (rand() >> 7) & 0xFF;

        return;
    }

    int get_clock(uint32_t *in_clock_high, uint32_t *in_clock_low,
            uint16_t *in_clock_seq) {
        static int adjustment = 0;
        static struct timeval last = {0, 0};
        static uint16_t	clock_seq;
        struct timeval tv;
        unsigned long long clock_reg;

try_again:
        gettimeofday(&tv, 0);
        if ((last.tv_sec == 0) && (last.tv_usec == 0)) {
            get_random_bytes(&clock_seq, sizeof(clock_seq));
            clock_seq &= 0x3FFF;
            last = tv;
            last.tv_sec--;
        }
        if ((tv.tv_sec < last.tv_sec) ||
                ((tv.tv_sec == last.tv_sec) &&
                 (tv.tv_usec < last.tv_usec))) {
            clock_seq = (clock_seq+1) & 0x3FFF;
            adjustment = 0;
            last = tv;
        } else if ((tv.tv_sec == last.tv_sec) &&
                (tv.tv_usec == last.tv_usec)) {
            if (adjustment >= MAX_ADJUSTMENT)
                goto try_again;
            adjustment++;
        } else {
            adjustment = 0;
            last = tv;
        }

        clock_reg = tv.tv_usec * 10 + adjustment;
        clock_reg += ((unsigned long long) tv.tv_sec) * 10000000;
        clock_reg += (((unsigned long long) 0x01B21DD2) << 32) + 0x13814000;

        *in_clock_high = clock_reg >> 32;
        *in_clock_low = (uint32_t) clock_reg;
        *in_clock_seq = clock_seq;
        return 0;
    }

    friend std::ostream& operator<<(std::ostream& os, const uuid& u);
    friend std::istream& operator>>(std::istream &is, uuid& u);
};

std::ostream& operator<<(std::ostream& os, const uuid& u);
std::istream& operator>>(std::istream &is, uuid& u);

template <>struct fmt::formatter<uuid> : fmt::ostream_formatter {};

namespace std {
    template<> struct hash<uuid> {
        std::size_t operator()(uuid const& u) const noexcept {
            return u.hash;
        }
    };
}

#endif

