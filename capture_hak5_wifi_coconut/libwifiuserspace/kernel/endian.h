/*
 *
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#ifndef __USERSPACE_ENDIAN_H__
#define __USERSPACE_ENDIAN_H__ 

/** compatibility header for endian.h
 * This is a simple compatibility shim to convert
 * BSD/Linux endian macros to the Mac OS X equivalents.
 * It is public domain.
 * */

/* Derived from
 *
 * https://gist.githubusercontent.com/yinyin/2027912/raw/6b3e394dc6a37817410d66d6ba4d7cd6b8d5d03d/endian.h
 *
 */

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64) || defined(__WIN32__)) && !defined(__WINDOWS__)
#define __WINDOWS__
#endif

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#elif defined(__WINDOWS__)

#include <winsock.h>

#define htobe16(x) htons(x)
#define htole16(x) (x)
#define be16toh(x) ntohs(x)
#define le16toh(x) (x)

#define htobe32(x) htonl(x)
#define htole32(x) (x)
#define be32toh(x) ntohl(x)
#define le32toh(x) (x)

#define htobe64(x) htonll(x)
#define htole64(x) (x)
#define be64toh(x) ntohll(x)
#define le64toh(x) (x)

#else

#include <endian.h>

#endif 

#define cpu_to_le16(x)      \
    htole16(x)
#define le16_to_cpu(x)      \
    le16toh(x)

#define cpu_to_le32(x)      \
    htole32(x)
#define le32_to_cpu(x)      \
    le32toh(x)

#define cpu_to_be16(x)      \
    htobe16(x)
#define be16_to_cpu(x)      \
    be16toh(x)

#define cpu_to_be32(x)      \
    htobe32(x)
#define be32_to_cpu(x)      \
    be32toh(x)

#endif /* ifndef ENDIAN_H */

