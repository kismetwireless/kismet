/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#ifndef __USERSPACE_TYPES_H__
#define __USERSPACE_TYPES_H__ 

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#ifndef LIBWIFIUSERSPACE_EXCLUDE_TYPES
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* 
 * We lose the atomic stuff
 */
typedef int64_t atomic64_t;
typedef int64_t atomic_t;

/*
 * We lose the automagic endian checking and have to make sure
 * we do it ourselves properly.
 */
typedef uint16_t __le16;
typedef uint32_t __le32;

typedef uint16_t __be16;
typedef uint32_t __be32;


/*
 * Not going to make a whole netdev defs file for one def
 */
typedef u64 netdev_features_t;

#endif /* ifndef TYPES_H */
