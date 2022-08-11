/* SPDX-License-Identifier: GPL-2.0 */

/* 
 * Userspace port (c) 2019 Hak5
 */

#ifndef __USERSPACE_CCIT_H__
#define __USERSPACE_CCIT_H__ 

#include <stdlib.h>

#include "kernel/types.h"

extern u16 const crc_ccitt_table[256];
extern u16 const crc_ccitt_false_table[256];

extern u16 crc_ccitt(u16 crc, const u8 *buffer, size_t len);
extern u16 crc_ccitt_false(u16 crc, const u8 *buffer, size_t len);

static inline u16 crc_ccitt_byte(u16 crc, const u8 c)
{
	return (crc >> 8) ^ crc_ccitt_table[(crc ^ c) & 0xff];
}

static inline u16 crc_ccitt_false_byte(u16 crc, const u8 c)
{
    return (crc << 8) ^ crc_ccitt_false_table[(crc >> 8) ^ c];
}

#endif /* ifndef USERSPACE_CCIT_H */

