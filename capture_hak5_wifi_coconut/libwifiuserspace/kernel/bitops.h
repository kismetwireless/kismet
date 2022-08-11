/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Userspace port (c) 2019 Hak5
 */

#ifndef __USERSPACE_BITOPS_H__
#define __USERSPACE_BITOPS_H__ 

#include "kernel/bits.h"
#include "kernel/types.h"

#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_TYPE(long))

/**
 * __test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is non-atomic and can be reordered.
 * If two examples of this operation race, one can appear to succeed
 * but actually fail.  You must protect multiple accesses with a lock.
 */
static inline int __test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old = *p;

	*p = old & ~mask;
	return (old & mask) != 0;
}
#define test_and_clear_bit(nr, addr)    __test_and_clear_bit((nr), (addr))


/*
 * Kluge swab16
 */
static inline __u16 ___swab16(__u16 x)
{
        return x<<8 | x>>8;
}
#define swab16(x)  ___swab16(x)

/*
 * Kluge FLS from generic
 */
/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */

static int __fls(unsigned int x)
{
    int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static int __fls64(__u64 x)
{
    __u32 h = x >> 32;
    if (h)
        return __fls(h) + 32;
    return __fls(x);
}

#define __fls_long(x) __fls64(x)


#endif /* ifndef USERSPACE_BITOPS_H */

