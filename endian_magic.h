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

#ifndef __ENDIAN_MAGIC_H__
#define __ENDIAN_MAGIC_H__

#include "config.h"

// Byteswap magic
#ifdef WORDS_BIGENDIAN

#define kis_hton16(x) (x)
#define kis_ntoh16(x) (x)

#define kis_hton32(x) (x)
#define kis_ntoh32(x) (x)

#define kis_hton64(x) (x)
#define kis_ntoh64(x) (x)

#define kis_extract16(x) kis_extractBE16(x)
#define kis_extract32(x) kis_extractBE32(x)
#define kis_extract64(x) kis_extractBE64(x)

#define kis_letoh16(x) kis_swap16((x))
#define kis_betoh16(x) (x)

#define kis_letoh32(x) kis_swap32((x))
#define kis_betoh32(x) (x)

#define kis_htole16(x) kis_swap16((x))
#define kis_htobe16(x) (x)

#define kis_htobe32(x) (x)
#define kis_htole32(x) kis_swap32((x))

#define kis_htobe64(x) (x)
#define kis_htole64(x) kis_swap64((x))

#else

#define kis_hton16(x) kis_swap16((x))
#define kis_ntoh16(x) kis_swap16((x))

#define kis_hton32(x) kis_swap32((x))
#define kis_ntoh32(x) kis_swap32((x))

#define kis_hton64(x) kis_swap64((x))
#define kis_ntoh64(x) kis_swap64((x))

#define kis_extract16(x) kis_extractLE16(x)
#define kis_extract32(x) kis_extractLE32(x)
#define kis_extract64(x) kis_extractLE64(x)

#define kis_betoh16(x) kis_swap16((x))
#define kis_letoh16(x) (x)

#define kis_betoh32(x) kis_swap32((x))
#define kis_letoh32(x) (x)

#define kis_htole16(x) (x)
#define kis_htobe16(x) kis_swap16((x))

#define kis_htole32(x) (x)
#define kis_htobe32(x) kis_swap32((x))

#define kis_htole64(x) (x)
#define kis_htobe64(x) kis_swap64((x))

#endif

// Swap magic
#define kis_swap16(x) \
({ \
    uint16_t __x = (x); \
    ((uint16_t)( \
        (uint16_t)(((uint16_t)(__x) & (uint16_t)0x00ff) << 8) | \
        (uint16_t)(((uint16_t)(__x) & (uint16_t)0xff00) >> 8) )); \
})

#define kis_swap32(x) \
({ \
    uint32_t __x = (x); \
    ((uint32_t)( \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x000000ff) << 24) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x0000ff00) << 8) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0x00ff0000) >> 8) | \
        (uint32_t)(((uint32_t)(__x) & (uint32_t)0xff000000) >> 24) )); \
})

#define kis_swap64(x) \
({ \
    uint64_t __x = (x); \
    ((uint64_t)( \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
        (uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

// Extract magic, also cribbed from tcpdump/ethereal
#define kis_extractLE16(x) \
	((uint16_t)((uint16_t)*((const uint8_t *)(x) + 1) << 8 | \
 	(uint16_t)*((const uint8_t *)(x) + 0))) 

#define kis_extractLE32(x) \
	((uint32_t)((uint32_t)*((const uint8_t *)(x) + 1) << 24 | \
	((uint32_t)((uint32_t)*((const uint8_t *)(x) + 0) << 16 | \
	((uint32_t)((uint32_t)*((const uint8_t *)(x) + 3) << 8 | \
 	(uint32_t)*((const uint8_t *)(x) + 2))) 

#define kis_extractLE64(x) \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 1) << 56 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 0) << 48 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 3) << 40 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 2) << 32 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 5) << 24 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 4) << 16 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 7) << 8 | \
 	(uint64_t)*((const uint8_t *)(x) + 6))) 

#define kis_extractBE16(x) \
	((uint16_t)((uint16_t)*((const uint8_t *)(x) + 0) << 8 | \
 	(uint16_t)*((const uint8_t *)(x) + 1))) 

#define kis_extractBE32(x) \
	((uint32_t)((uint32_t)*((const uint8_t *)(x) + 0) << 24 | \
	((uint32_t)((uint32_t)*((const uint8_t *)(x) + 1) << 16 | \
	((uint32_t)((uint32_t)*((const uint8_t *)(x) + 2) << 8 | \
 	(uint32_t)*((const uint8_t *)(x) + 3))) 

#define kis_extractBE64(x) \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 0) << 56 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 1) << 48 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 2) << 40 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 3) << 32 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 4) << 24 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 5) << 16 | \
	((uint64_t)((uint64_t)*((const uint8_t *)(x) + 6) << 8 | \
 	(uint64_t)*((const uint8_t *)(x) + 7))) 

#endif

