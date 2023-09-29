/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#ifndef __USERSPACE_TYPES_H__
#define __USERSPACE_TYPES_H__ 

#include <stdint.h>

/* 
 * We lose the atomic stuff
 */
typedef int64_t atomic64_t;
typedef int64_t atomic_t;

/*
 * We lose the automagic endian checking and have to make sure
 * we do it ourselves properly.
 */
typedef uint16_t ___le16;
typedef uint32_t ___le32;
typedef uint64_t ___le64;

typedef uint16_t ___be16;
typedef uint32_t ___be32;
typedef uint64_t ___be64;


/*
 * Not going to make a whole netdev defs file for one def
 */
typedef uint64_t netdev_features_t;

#endif /* ifndef TYPES_H */
