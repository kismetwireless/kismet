/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#ifndef __BITS_H__
#define __BITS_H__ 

#include <stdbool.h>

#define BIT(nr)			(1UL << (nr))
#define BIT_ULL(nr)		(1ULL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE		8
#define BITS_PER_LONG       (8 * BITS_PER_BYTE)

static inline void set_bit(int bit, unsigned long *x) {
    *x |= (1UL << bit);
}

static inline void clear_bit(int bit, unsigned long *x) {
    *x &= ~(1UL << bit);
}

static inline bool test_bit(int bit, unsigned long *x) {
    return (*x & (1UL << bit));
}

#define __clear_bit(n, r)   clear_bit((n), (r))
#define __get_bit(n, r)     get_bit((n), (r))
#define __set_bit(n, r)     set_bit((n), (r))

#endif /* ifndef BITS_H */

