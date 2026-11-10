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

#ifndef __MM_UTIL_H__
#define __MM_UTIL_H__

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Explicit little-endian access; chip data is never assumed to be aligned */

static inline uint16_t mm_get_le16(const uint8_t *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

static inline uint32_t mm_get_le32(const uint8_t *p) {
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
        ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline uint64_t mm_get_le64(const uint8_t *p) {
    return (uint64_t) mm_get_le32(p) | ((uint64_t) mm_get_le32(p + 4) << 32);
}

static inline void mm_put_le16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
}

static inline void mm_put_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

static inline void mm_put_le64(uint8_t *p, uint64_t v) {
    mm_put_le32(p, (uint32_t) v);
    mm_put_le32(p + 4, (uint32_t) (v >> 32));
}

#define MM_ROUND_UP4(x) (((x) + 3) & ~((size_t) 3))
#define MM_PAD4(x) (((x) & 3) ? (4 - ((x) & 3)) : 0)

uint64_t mm_monotonic_ms(void);
void mm_sleep_us(unsigned int us);

#endif
