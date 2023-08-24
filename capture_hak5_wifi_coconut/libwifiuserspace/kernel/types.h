/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#ifndef __USERSPACE_TYPES_H__
#define __USERSPACE_TYPES_H__ 

#include <stdint.h>

typedef uint8_t uint8_t;
typedef uint16_t uint16_t;
typedef uint32_t uint32_t;
typedef uint64_t u64;

typedef int8_t int8_t;
typedef int16_t int16_t;
typedef int32_t int32_t;
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
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;


/*
 * Not going to make a whole netdev defs file for one def
 */
typedef u64 netdev_features_t;

#endif /* ifndef TYPES_H */
