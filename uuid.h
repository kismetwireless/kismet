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

// UUID Generation
// From e2fstools, Theodore Ts'o

/* Assume that the gettimeofday() has microsecond granularity */
#define MAX_ADJUSTMENT 10

class uuid {
public:
	uuid() {
		memset(uuid_block, 0, 16);
		time_low = (uint32_t *) &(uuid_block[0]);
		time_mid = (uint16_t *) &(uuid_block[4]);
		time_hi = (uint16_t *) &(uuid_block[6]);
		clock_seq = (uint16_t *) &(uuid_block[8]);
		node = &(uuid_block[10]);
		error = 1;
	}

	uuid(const string in) {
		memset(uuid_block, 0, 16);
		time_low = (uint32_t *) &(uuid_block[0]);
		time_mid = (uint16_t *) &(uuid_block[4]);
		time_hi = (uint16_t *) &(uuid_block[6]);
		clock_seq = (uint16_t *) &(uuid_block[8]);
		node = &(uuid_block[10]);

		unsigned int ln[6];
		unsigned int ltl, ltm, lth, lcs;
		if (sscanf(in.c_str(), "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
				 &ltl, &ltm, &lth, &lcs,
				 &ln[0], &ln[1], &ln[2], &ln[3], &ln[4], &ln[5]) != 10) {
			error = 1;
			return;
		}

		error = 0;

		*time_low = ltl;
		*time_mid = ltm;
		*time_hi = lth;
		*clock_seq = lcs;
		for (unsigned int x = 0; x < 6; x++) {
			node[x] = ln[x];
		}
	}

	uuid(uint8_t *in_node) {
		GenerateTimeUUID(in_node);
	}
	
	void GenerateTimeUUID(uint8_t *in_node) {
		uint32_t clock_mid;

		get_clock(&clock_mid, time_low, clock_seq);

		*clock_seq |= 0x8000;
		*time_mid = (uint16_t) clock_mid;
		*time_hi = ((clock_mid >> 16) & 0x0FFF) | 0x1000;
		memcpy(node, in_node, 6);
		error = 0;
	}

	void GenerateStoredUUID(uint32_t in_low, uint16_t in_mid, uint16_t in_hi,
							uint16_t in_seq, uint8_t *in_node) {
		*time_low = in_low;
		*time_mid = in_mid;
		*time_hi = in_hi;
		*clock_seq = in_seq;
		memcpy(node, in_node, 6);
		error = 0;
	}

	string UUID2String() const {
		char ids[38];
		snprintf(ids, 38, "%08x-%04hx-%04hx-%04hx-%02hx%02hx%02hx%02hx%02hx%02hx",
				 (unsigned int) *time_low, *time_mid, *time_hi, *clock_seq,
				 node[0], node[1], node[2], node[3], node[4], node[5]);
		return string(ids);
	}

	inline bool operator== (const uuid& op) const {
		if (memcmp(uuid_block, op.uuid_block, 16) == 0)
			return 1; 
		return 0;
	}

	inline bool operator!= (const uuid& op) const {
		if (memcmp(uuid_block, op.uuid_block, 16) != 0)
			return 1;

		return 0;
	}

	inline bool operator<= (const uuid& op) const {
		int ret = memcmp(uuid_block, op.uuid_block, 16);
		if (ret <= 0)
			return 1;
		return 0;
	}

	inline bool operator< (const uuid& op) const {
		int ret = memcmp(uuid_block, op.uuid_block, 16);
		if (ret < 0)
			return 1;
		return 0;
	}

	uuid& operator= (const uuid& op) {
		memcpy(uuid_block, op.uuid_block, 16);
		error = op.error;
		return *this;
	}

	uint8_t uuid_block[16];
	uint32_t *time_low;
	uint16_t *time_mid;
	uint16_t *time_hi;
	uint16_t *clock_seq;
	uint8_t *node;
	int error;

protected:
	int get_random_fd() {
		struct timeval tv;
		static int fd = -2;
		int	i;

		if (fd == -2) {
			gettimeofday(&tv, 0);
			fd = open("/dev/urandom", O_RDONLY);
			if (fd == -1)
				fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
			srand((getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec);
		}
		/* Crank the random number generator a few times */
		gettimeofday(&tv, 0);
		for (i = (tv.tv_sec ^ tv.tv_usec) & 0x1F; i > 0; i--)
			rand();
		return fd;
	}

	void get_random_bytes(void *buf, int nbytes) {
		int i, n = nbytes, fd = get_random_fd();
		int lose_counter = 0;
		unsigned char *cp = (unsigned char *) buf;

		if (fd >= 0) {
			while (n > 0) {
				i = read(fd, cp, n);
				if (i <= 0) {
					if (lose_counter++ > 16)
						break;
					continue;
				}
				n -= i;
				cp += i;
				lose_counter = 0;
			}
		}

		for (cp = (unsigned char *) buf, i = 0; i < nbytes; i++)
			*cp++ ^= (rand() >> 7) & 0xFF;

		close(fd);
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
};

#endif

