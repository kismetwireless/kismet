#ifndef MSGPUCK_H_INCLUDED
#define MSGPUCK_H_INCLUDED
/*
 * Copyright (c) 2013-2017 MsgPuck Authors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file msgpuck.h
 * MsgPuck
 * \brief MsgPuck is a simple and efficient MsgPack encoder/decoder
 * library in a single self-contained file.
 *
 * Usage example:
 * \code
 * // Encode
 * char buf[1024];
 * char *w = buf;
 * w = mp_encode_array(w, 4)
 * w = mp_encode_uint(w, 10);
 * w = mp_encode_str(w, "hello world", strlen("hello world"));
 * w = mp_encode_bool(w, true);
 * w = mp_encode_double(w, 3.1415);
 *
 * // Validate
 * const char *b = buf;
 * int r = mp_check(&b, w);
 * assert(!r)
 * assert(b == w);
 *
 * // Decode
 * uint32_t size;
 * uint64_t ival;
 * const char *sval;
 * uint32_t sval_len;
 * bool bval;
 * double dval;
 *
 * const char *r = buf;
 *
 * size = mp_decode_array(&r);
 * // size is 4
 *
 * ival = mp_decode_uint(&r);
 * // ival is 10;
 *
 * sval = mp_decode_str(&r, &sval_len);
 * // sval is "hello world", sval_len is strlen("hello world")
 *
 * bval = mp_decode_bool(&r);
 * // bval is true
 *
 * dval = mp_decode_double(&r);
 * // dval is 3.1415
 *
 * assert(r == w);
 * \endcode
 *
 * \note Supported compilers.
 * The implementation requires a C99+ or C++03+ compatible compiler.
 *
 * \note Inline functions.
 * The implementation is compatible with both C99 and GNU inline functions.
 * Please link libmsgpuck.a static library for non-inlined versions of
 * functions and global tables.
 */

#if defined(__cplusplus) && !defined(__STDC_CONSTANT_MACROS)
#define __STDC_CONSTANT_MACROS 1 /* make С++ to be happy */
#endif
#if defined(__cplusplus) && !defined(__STDC_LIMIT_MACROS)
#define __STDC_LIMIT_MACROS 1    /* make С++ to be happy */
#endif
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/*
 * {{{ Platform-specific definitions
 */

/** \cond false **/

#if defined(__CC_ARM)         /* set the alignment to 1 for armcc compiler */
#define MP_PACKED    __packed
#else
#define MP_PACKED  __attribute__((packed))
#endif

#if defined(MP_SOURCE)
#error MP_SOURCE is not supported anymore, please link libmsgpuck.a
#endif

#if defined(__GNUC__) && !defined(__GNUC_STDC_INLINE__)
#if !defined(MP_LIBRARY)
#define MP_PROTO extern inline
#define MP_IMPL extern inline
#else /* defined(MP_LIBRARY) */
#define MP_PROTO
#define MP_IMPL
#endif
#define MP_ALWAYSINLINE
#else /* C99 inline */
#if !defined(MP_LIBRARY)
#define MP_PROTO inline
#define MP_IMPL inline
#else /* defined(MP_LIBRARY) */
#define MP_PROTO extern inline
#define MP_IMPL inline
#endif
#define MP_ALWAYSINLINE __attribute__((always_inline))
#endif /* GNU inline or C99 inline */

#if !defined __GNUC_MINOR__ || defined __INTEL_COMPILER || \
	defined __SUNPRO_C || defined __SUNPRO_CC
#define MP_GCC_VERSION(major, minor) 0
#else
#define MP_GCC_VERSION(major, minor) (__GNUC__ > (major) || \
	(__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#endif

#if !defined(__has_builtin)
#define __has_builtin(x) 0 /* clang */
#endif

#if MP_GCC_VERSION(2, 9) || __has_builtin(__builtin_expect)
#define mp_likely(x) __builtin_expect((x), 1)
#define mp_unlikely(x) __builtin_expect((x), 0)
#else
#define mp_likely(x) (x)
#define mp_unlikely(x) (x)
#endif

#if MP_GCC_VERSION(4, 5) || __has_builtin(__builtin_unreachable)
#define mp_unreachable() (assert(0), __builtin_unreachable())
#else
MP_PROTO void
mp_unreachable(void) __attribute__((noreturn));
MP_PROTO void
mp_unreachable(void) { assert(0); abort(); }
#define mp_unreachable() (assert(0))
#endif

#define mp_identity(x) (x) /* just to simplify mp_load/mp_store macroses */

#if MP_GCC_VERSION(4, 8) || __has_builtin(__builtin_bswap16)
#define mp_bswap_u16(x) __builtin_bswap16(x)
#else /* !MP_GCC_VERSION(4, 8) */
#define mp_bswap_u16(x) ( \
	(((x) <<  8) & 0xff00) | \
	(((x) >>  8) & 0x00ff) )
#endif

#if MP_GCC_VERSION(4, 3) || __has_builtin(__builtin_bswap32)
#define mp_bswap_u32(x) __builtin_bswap32(x)
#else /* !MP_GCC_VERSION(4, 3) */
#define mp_bswap_u32(x) ( \
	(((x) << 24) & UINT32_C(0xff000000)) | \
	(((x) <<  8) & UINT32_C(0x00ff0000)) | \
	(((x) >>  8) & UINT32_C(0x0000ff00)) | \
	(((x) >> 24) & UINT32_C(0x000000ff)) )
#endif

#if MP_GCC_VERSION(4, 3) || __has_builtin(__builtin_bswap64)
#define mp_bswap_u64(x) __builtin_bswap64(x)
#else /* !MP_GCC_VERSION(4, 3) */
#define mp_bswap_u64(x) (\
	(((x) << 56) & UINT64_C(0xff00000000000000)) | \
	(((x) << 40) & UINT64_C(0x00ff000000000000)) | \
	(((x) << 24) & UINT64_C(0x0000ff0000000000)) | \
	(((x) <<  8) & UINT64_C(0x000000ff00000000)) | \
	(((x) >>  8) & UINT64_C(0x00000000ff000000)) | \
	(((x) >> 24) & UINT64_C(0x0000000000ff0000)) | \
	(((x) >> 40) & UINT64_C(0x000000000000ff00)) | \
	(((x) >> 56) & UINT64_C(0x00000000000000ff)) )
#endif

#define MP_LOAD_STORE(name, type, bswap)					\
MP_PROTO type									\
mp_load_##name(const char **data);						\
MP_IMPL type									\
mp_load_##name(const char **data)						\
{										\
	struct MP_PACKED cast { type val; };					\
	type val = bswap(((struct cast *) *data)->val);				\
	*data += sizeof(type);							\
	return val;								\
}										\
MP_PROTO char *									\
mp_store_##name(char *data, type val);						\
MP_IMPL char *									\
mp_store_##name(char *data, type val)						\
{										\
	struct MP_PACKED cast { type val; };					\
	((struct cast *) (data))->val = bswap(val);				\
	return data + sizeof(type);						\
}

MP_LOAD_STORE(u8, uint8_t, mp_identity);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

MP_LOAD_STORE(u16, uint16_t, mp_bswap_u16);
MP_LOAD_STORE(u32, uint32_t, mp_bswap_u32);
MP_LOAD_STORE(u64, uint64_t, mp_bswap_u64);

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

MP_LOAD_STORE(u16, uint16_t, mp_identity);
MP_LOAD_STORE(u32, uint32_t, mp_identity);
MP_LOAD_STORE(u64, uint64_t, mp_identity);

#else
#error Unsupported __BYTE_ORDER__
#endif

#if !defined(__FLOAT_WORD_ORDER__)
#define __FLOAT_WORD_ORDER__ __BYTE_ORDER__
#endif /* defined(__FLOAT_WORD_ORDER__) */

#if __FLOAT_WORD_ORDER__ == __ORDER_LITTLE_ENDIAN__

/*
 * Idiots from msgpack.org byte-swaps even IEEE754 float/double types.
 * Some platforms (e.g. arm) cause SIGBUS on attempt to store
 * invalid float in registers, so code like flt = mp_bswap_float(flt)
 * can't be used here.
 */

union MP_PACKED mp_float_cast {
	uint32_t u32;
	float f;
};

union MP_PACKED mp_double_cast {
	uint64_t u64;
	double d;
};

MP_PROTO float
mp_load_float(const char **data);
MP_PROTO double
mp_load_double(const char **data);
MP_PROTO char *
mp_store_float(char *data, float val);
MP_PROTO char *
mp_store_double(char *data, double val);

MP_IMPL float
mp_load_float(const char **data)
{
	union mp_float_cast cast = *(union mp_float_cast *) *data;
	*data += sizeof(cast);
	cast.u32 = mp_bswap_u32(cast.u32);
	return cast.f;
}

MP_IMPL double
mp_load_double(const char **data)
{
	union mp_double_cast cast = *(union mp_double_cast *) *data;
	*data += sizeof(cast);
	cast.u64 = mp_bswap_u64(cast.u64);
	return cast.d;
}

MP_IMPL char *
mp_store_float(char *data, float val)
{
	union mp_float_cast cast;
	cast.f = val;
	cast.u32 = mp_bswap_u32(cast.u32);
	*(union mp_float_cast *) (data) = cast;
	return data + sizeof(cast);
}

MP_IMPL char *
mp_store_double(char *data, double val)
{
	union mp_double_cast cast;
	cast.d = val;
	cast.u64 = mp_bswap_u64(cast.u64);
	*(union mp_double_cast *) (data) = cast;
	return data + sizeof(cast);
}

#elif __FLOAT_WORD_ORDER__ == __ORDER_BIG_ENDIAN__

MP_LOAD_STORE(float, float, mp_identity);
MP_LOAD_STORE(double, double, mp_identity);

#else
#error Unsupported __FLOAT_WORD_ORDER__
#endif

#undef mp_identity
#undef MP_LOAD_STORE

/** \endcond */

/*
 * }}}
 */

/*
 * {{{ API definition
 */

/**
 * \brief MsgPack data types
 */
enum mp_type {
	MP_NIL = 0,
	MP_UINT,
	MP_INT,
	MP_STR,
	MP_BIN,
	MP_ARRAY,
	MP_MAP,
	MP_BOOL,
	MP_FLOAT,
	MP_DOUBLE,
	MP_EXT
};

/**
 * \brief Determine MsgPack type by a first byte \a c of encoded data.
 *
 * Example usage:
 * \code
 * assert(MP_ARRAY == mp_typeof(0x90));
 * \endcode
 *
 * \param c - a first byte of encoded data
 * \return MsgPack type
 */
MP_PROTO __attribute__((pure)) enum mp_type
mp_typeof(const char c);

/**
 * \brief Calculate exact buffer size needed to store an array header of
 * \a size elements. Maximum return value is 5. For performance reasons you
 * can preallocate buffer for maximum size without calling the function.
 * \param size - a number of elements
 * \return buffer size in bytes (max is 5)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_array(uint32_t size);

/**
 * \brief Encode an array header of \a size elements.
 *
 * All array members must be encoded after the header.
 *
 * Example usage:
 * \code
 * // Encode
 * char buf[1024];
 * char *w = buf;
 * w = mp_encode_array(w, 2)
 * w = mp_encode_uint(w, 10);
 * w = mp_encode_uint(w, 15);
 *
 * // Decode
 * const char *r = buf;
 * uint32_t size = mp_decode_array(&r);
 * for (uint32_t i = 0; i < size; i++) {
 *     uint64_t val = mp_decode_uint(&r);
 * }
 * assert (r == w);
 * \endcode
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param size - a number of elements
 * \return \a data + \link mp_sizeof_array() mp_sizeof_array(size) \endlink
 * \sa mp_sizeof_array
 */
MP_PROTO char *
mp_encode_array(char *data, uint32_t size);

/**
 * \brief Check that \a cur buffer has enough bytes to decode an array header
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_ARRAY
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_array(const char *cur, const char *end);

/**
 * \brief Decode an array header from MsgPack \a data.
 *
 * All array members must be decoded after the header.
 * \param data - the pointer to a buffer
 * \return the number of elements in an array
 * \post *data = *data + mp_sizeof_array(retval)
 * \sa \link mp_encode_array() An usage example \endlink
 */
MP_PROTO uint32_t
mp_decode_array(const char **data);

/**
 * \brief Calculate exact buffer size needed to store a map header of
 * \a size elements. Maximum return value is 5. For performance reasons you
 * can preallocate buffer for maximum size without calling the function.
 * \param size - a number of elements
 * \return buffer size in bytes (max is 5)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_map(uint32_t size);

/**
 * \brief Encode a map header of \a size elements.
 *
 * All map key-value pairs must be encoded after the header.
 *
 * Example usage:
 * \code
 * char buf[1024];
 *
 * // Encode
 * char *w = buf;
 * w = mp_encode_map(b, 2);
 * w = mp_encode_str(b, "key1", 4);
 * w = mp_encode_str(b, "value1", 6);
 * w = mp_encode_str(b, "key2", 4);
 * w = mp_encode_str(b, "value2", 6);
 *
 * // Decode
 * const char *r = buf;
 * uint32_t size = mp_decode_map(&r);
 * for (uint32_t i = 0; i < size; i++) {
 *      // Use switch(mp_typeof(**r)) to support more types
 *     uint32_t key_len, val_len;
 *     const char *key = mp_decode_str(&r, key_len);
 *     const char *val = mp_decode_str(&r, val_len);
 * }
 * assert (r == w);
 * \endcode
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param size - a number of key/value pairs
 * \return \a data + \link mp_sizeof_map() mp_sizeof_map(size)\endlink
 * \sa mp_sizeof_map
 */
MP_PROTO char *
mp_encode_map(char *data, uint32_t size);

/**
 * \brief Check that \a cur buffer has enough bytes to decode a map header
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_MAP
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_map(const char *cur, const char *end);

/**
 * \brief Decode a map header from MsgPack \a data.
 *
 * All map key-value pairs must be decoded after the header.
 * \param data - the pointer to a buffer
 * \return the number of key/value pairs in a map
 * \post *data = *data + mp_sizeof_array(retval)
 * \sa \link mp_encode_map() An usage example \endlink
 */
MP_PROTO uint32_t
mp_decode_map(const char **data);

/**
 * \brief Calculate exact buffer size needed to store an integer \a num.
 * Maximum return value is 9. For performance reasons you can preallocate
 * buffer for maximum size without calling the function.
 * Example usage:
 * \code
 * char **data = ...;
 * char *end = *data;
 * my_buffer_ensure(mp_sizeof_uint(x), &end);
 * // my_buffer_ensure(9, &end);
 * mp_encode_uint(buffer, x);
 * \endcode
 * \param num - a number
 * \return buffer size in bytes (max is 9)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_uint(uint64_t num);

/**
 * \brief Calculate exact buffer size needed to store an integer \a num.
 * Maximum return value is 9. For performance reasons you can preallocate
 * buffer for maximum size without calling the function.
 * \param num - a number
 * \return buffer size in bytes (max is 9)
 * \pre \a num < 0
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_int(int64_t num);

/**
 * \brief Encode an unsigned integer \a num.
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param num - a number
 * \return \a data + mp_sizeof_uint(\a num)
 * \sa \link mp_encode_array() An usage example \endlink
 * \sa mp_sizeof_uint()
 */
MP_PROTO char *
mp_encode_uint(char *data, uint64_t num);

/**
 * \brief Encode a signed integer \a num.
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param num - a number
 * \return \a data + mp_sizeof_int(\a num)
 * \sa \link mp_encode_array() An usage example \endlink
 * \sa mp_sizeof_int()
 * \pre \a num < 0
 */
MP_PROTO char *
mp_encode_int(char *data, int64_t num);

/**
 * \brief Check that \a cur buffer has enough bytes to decode an uint
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_UINT
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_uint(const char *cur, const char *end);

/**
 * \brief Check that \a cur buffer has enough bytes to decode an int
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_INT
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_int(const char *cur, const char *end);

/**
 * \brief Decode an unsigned integer from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return an unsigned number
 * \post *data = *data + mp_sizeof_uint(retval)
 */
MP_PROTO uint64_t
mp_decode_uint(const char **data);

/**
 * \brief Decode a signed integer from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return an unsigned number
 * \post *data = *data + mp_sizeof_int(retval)
 */
MP_PROTO int64_t
mp_decode_int(const char **data);

/**
 * \brief Compare two packed unsigned integers.
 *
 * The function is faster than two mp_decode_uint() calls.
 * \param data_a unsigned int a
 * \param data_b unsigned int b
 * \retval < 0 when \a a < \a b
 * \retval   0 when \a a == \a b
 * \retval > 0 when \a a > \a b
 */
MP_PROTO __attribute__((pure)) int
mp_compare_uint(const char *data_a, const char *data_b);

/**
 * \brief Calculate exact buffer size needed to store a float \a num.
 * The return value is always 5. The function was added to provide integrity of
 * the library.
 * \param num - a float
 * \return buffer size in bytes (always 5)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_float(float num);

/**
 * \brief Calculate exact buffer size needed to store a double \a num.
 * The return value is either 5 or 9. The function was added to provide
 * integrity of the library. For performance reasons you can preallocate buffer
 * for maximum size without calling the function.
 * \param num - a double
 * \return buffer size in bytes (5 or 9)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_double(double num);

/**
 * \brief Encode a float \a num.
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param num - a float
 * \return \a data + mp_sizeof_float(\a num)
 * \sa mp_sizeof_float()
 * \sa \link mp_encode_array() An usage example \endlink
 */
MP_PROTO char *
mp_encode_float(char *data, float num);

/**
 * \brief Encode a double \a num.
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param num - a float
 * \return \a data + mp_sizeof_double(\a num)
 * \sa \link mp_encode_array() An usage example \endlink
 * \sa mp_sizeof_double()
 */
MP_PROTO char *
mp_encode_double(char *data, double num);

/**
 * \brief Check that \a cur buffer has enough bytes to decode a float
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_FLOAT
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_float(const char *cur, const char *end);

/**
 * \brief Check that \a cur buffer has enough bytes to decode a double
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_DOUBLE
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_double(const char *cur, const char *end);

/**
 * \brief Decode a float from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return a float
 * \post *data = *data + mp_sizeof_float(retval)
 */
MP_PROTO float
mp_decode_float(const char **data);

/**
 * \brief Decode a double from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return a double
 * \post *data = *data + mp_sizeof_double(retval)
 */
MP_PROTO double
mp_decode_double(const char **data);

/**
 * \brief Calculate exact buffer size needed to store a string header of
 * length \a num. Maximum return value is 5. For performance reasons you can
 * preallocate buffer for maximum size without calling the function.
 * \param len - a string length
 * \return size in chars (max is 5)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_strl(uint32_t len);

/**
 * \brief Equivalent to mp_sizeof_strl(\a len) + \a len.
 * \param len - a string length
 * \return size in chars (max is 5 + \a len)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_str(uint32_t len);

/**
 * \brief Calculate exact buffer size needed to store a binstring header of
 * length \a num. Maximum return value is 5. For performance reasons you can
 * preallocate buffer for maximum size without calling the function.
 * \param len - a string length
 * \return size in chars (max is 5)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_binl(uint32_t len);

/**
 * \brief Equivalent to mp_sizeof_binl(\a len) + \a len.
 * \param len - a string length
 * \return size in chars (max is 5 + \a len)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_bin(uint32_t len);

/**
 * \brief Encode a string header of length \a len.
 *
 * The function encodes MsgPack header (\em only header) for a string of
 * length \a len. You should append actual string data to the buffer manually
 * after encoding the header (exactly \a len bytes without trailing '\0').
 *
 * This approach is very useful for cases when the total length of the string
 * is known in advance, but the string data is not stored in a single
 * continuous buffer (e.g. network packets).
 *
 * It is your responsibility to ensure that \a data has enough space.
 * Usage example:
 * \code
 * char buffer[1024];
 * char *b = buffer;
 * b = mp_encode_strl(b, hdr.total_len);
 * char *s = b;
 * memcpy(b, pkt1.data, pkt1.len)
 * b += pkt1.len;
 * // get next packet
 * memcpy(b, pkt2.data, pkt2.len)
 * b += pkt2.len;
 * // get next packet
 * memcpy(b, pkt1.data, pkt3.len)
 * b += pkt3.len;
 *
 * // Check that all data was received
 * assert(hdr.total_len == (uint32_t) (b - s))
 * \endcode
 * Hint: you can dynamically reallocate the buffer during the process.
 * \param data - a buffer
 * \param len - a string length
 * \return \a data + mp_sizeof_strl(len)
 * \sa mp_sizeof_strl()
 */
MP_PROTO char *
mp_encode_strl(char *data, uint32_t len);

/**
 * \brief Encode a string of length \a len.
 * The function is equivalent to mp_encode_strl() + memcpy.
 * \param data - a buffer
 * \param str - a pointer to string data
 * \param len - a string length
 * \return \a data + mp_sizeof_str(len) ==
 * data + mp_sizeof_strl(len) + len
 * \sa mp_encode_strl
 */
MP_PROTO char *
mp_encode_str(char *data, const char *str, uint32_t len);

/**
 * \brief Encode a binstring header of length \a len.
 * See mp_encode_strl() for more details.
 * \param data - a bufer
 * \param len - a string length
 * \return data + mp_sizeof_binl(\a len)
 * \sa mp_encode_strl
 */
MP_PROTO char *
mp_encode_binl(char *data, uint32_t len);

/**
 * \brief Encode a binstring of length \a len.
 * The function is equivalent to mp_encode_binl() + memcpy.
 * \param data - a buffer
 * \param str - a pointer to binstring data
 * \param len - a binstring length
 * \return \a data + mp_sizeof_bin(\a len) ==
 * data + mp_sizeof_binl(\a len) + \a len
 * \sa mp_encode_strl
 */
MP_PROTO char *
mp_encode_bin(char *data, const char *str, uint32_t len);

/**
 * \brief Encode a sequence of values according to format string.
 * Example: mp_format(buf, sz, "[%d {%d%s%d%s}]", 42, 0, "false", 1, "true");
 * to get a msgpack array of two items: number 42 and map (0->"false, 2->"true")
 * Does not write items that don't fit to data_size argument.
 *
 * \param data - a buffer
 * \param data_size - a buffer size
 * \param format - zero-end string, containing structure of resulting
 * msgpack and types of next arguments.
 * Format can contain '[' and ']' pairs, defining arrays,
 * '{' and '}' pairs, defining maps, and format specifiers, described below:
 * %d, %i - int
 * %u - unsigned int
 * %ld, %li - long
 * %lu - unsigned long
 * %lld, %lli - long long
 * %llu - unsigned long long
 * %hd, %hi - short
 * %hu - unsigned short
 * %hhd, %hhi - char (as number)
 * %hhu - unsigned char (as number)
 * %f - float
 * %lf - double
 * %b - bool
 * %s - zero-end string
 * %.*s - string with specified length
 * %p - MsgPack data
 * %.*p - MsgPack data with specified length
 * %% is ignored
 * %smthelse assert and undefined behaviour
 * NIL - a nil value
 * all other symbols are ignored.
 *
 * \return the number of requred bytes.
 * \retval > data_size means that is not enough space
 * and whole msgpack was not encoded.
 */
size_t
mp_format(char *data, size_t data_size, const char *format, ...);

/**
 * \brief mp_format variation, taking variable argument list
 * Example:
 *  va_list args;
 *  va_start(args, fmt);
 *  mp_vformat(data, data_size, fmt, args);
 *  va_end(args);
 * \sa \link mp_format() mp_format() \endlink
 */
size_t
mp_vformat(char *data, size_t data_size, const char *format, va_list args);

/**
 * \brief print MsgPack data \a file using JSON-like format.
 * MP_EXT is printed as "undefined"
 * \param file - pointer to file (or NULL for stdout)
 * \param data - pointer to buffer containing msgpack object
 * \retval >=0 - the number of bytes printed
 * \retval -1 - error
 * \sa fprintf()
 */
int
mp_fprint(FILE *file, const char *data);

/**
 * \brief format MsgPack data to \a buf using JSON-like format.
 * \sa mp_fprint()
 * \param buf - buffer to use
 * \param size - buffer size. This function write at most size bytes
 * (including the terminating null byte ('\0').
 * \param data - pointer to buffer containing msgpack object
 * \retval <size - the number of characters printed (excluding the null byte)
 * \retval >=size - the number of characters (excluding the null byte),
 *                  which would have been written to the final string if
 *                  enough space had been available.
 * \retval -1 - error
 * \sa snprintf()
 */
int
mp_snprint(char *buf, int size, const char *data);

/**
 * \brief Check that \a cur buffer has enough bytes to decode a string header
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_STR
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_strl(const char *cur, const char *end);

/**
 * \brief Check that \a cur buffer has enough bytes to decode a binstring header
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_BIN
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_binl(const char *cur, const char *end);

/**
 * \brief Decode a length of a string from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return a length of astring
 * \post *data = *data + mp_sizeof_strl(retval)
 * \sa mp_encode_strl
 */
MP_PROTO uint32_t
mp_decode_strl(const char **data);

/**
 * \brief Decode a string from MsgPack \a data
 * \param data - the pointer to a buffer
 * \param len - the pointer to save a string length
 * \return a pointer to a decoded string
 * \post *data = *data + mp_sizeof_str(*len)
 * \sa mp_encode_binl
 */
MP_PROTO const char *
mp_decode_str(const char **data, uint32_t *len);

/**
 * \brief Decode a length of a binstring from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return a length of a binstring
 * \post *data = *data + mp_sizeof_binl(retval)
 * \sa mp_encode_binl
 */
MP_PROTO uint32_t
mp_decode_binl(const char **data);

/**
 * \brief Decode a binstring from MsgPack \a data
 * \param data - the pointer to a buffer
 * \param len - the pointer to save a binstring length
 * \return a pointer to a decoded binstring
 * \post *data = *data + mp_sizeof_str(*len)
 * \sa mp_encode_binl
 */
MP_PROTO const char *
mp_decode_bin(const char **data, uint32_t *len);

/**
 * \brief Decode a length of a string or binstring from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return a length of a string
 * \post *data = *data + mp_sizeof_strbinl(retval)
 * \sa mp_encode_binl
 */
MP_PROTO uint32_t
mp_decode_strbinl(const char **data);

/**
 * \brief Decode a string or binstring from MsgPack \a data
 * \param data - the pointer to a buffer
 * \param len - the pointer to save a binstring length
 * \return a pointer to a decoded binstring
 * \post *data = *data + mp_sizeof_strbinl(*len)
 * \sa mp_encode_binl
 */
MP_PROTO const char *
mp_decode_strbin(const char **data, uint32_t *len);

/**
 * \brief Calculate exact buffer size needed to store the nil value.
 * The return value is always 1. The function was added to provide integrity of
 * the library.
 * \return buffer size in bytes (always 1)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_nil(void);

/**
 * \brief Encode the nil value.
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \return \a data + mp_sizeof_nil()
 * \sa \link mp_encode_array() An usage example \endlink
 * \sa mp_sizeof_nil()
 */
MP_PROTO char *
mp_encode_nil(char *data);

/**
 * \brief Check that \a cur buffer has enough bytes to decode nil
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_NIL
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_nil(const char *cur, const char *end);

/**
 * \brief Decode the nil value from MsgPack \a data
 * \param data - the pointer to a buffer
 * \post *data = *data + mp_sizeof_nil()
 */
MP_PROTO void
mp_decode_nil(const char **data);

/**
 * \brief Calculate exact buffer size needed to store a boolean value.
 * The return value is always 1. The function was added to provide integrity of
 * the library.
 * \return buffer size in bytes (always 1)
 */
MP_PROTO __attribute__((const)) uint32_t
mp_sizeof_bool(bool val);

/**
 * \brief Encode a bool value \a val.
 * It is your responsibility to ensure that \a data has enough space.
 * \param data - a buffer
 * \param val - a bool
 * \return \a data + mp_sizeof_bool(val)
 * \sa \link mp_encode_array() An usage example \endlink
 * \sa mp_sizeof_bool()
 */
MP_PROTO char *
mp_encode_bool(char *data, bool val);

/**
 * \brief Check that \a cur buffer has enough bytes to decode a bool value
 * \param cur buffer
 * \param end end of the buffer
 * \retval 0 - buffer has enough bytes
 * \retval > 0 - the number of remaining bytes to read
 * \pre cur < end
 * \pre mp_typeof(*cur) == MP_BOOL
 */
MP_PROTO __attribute__((pure)) ptrdiff_t
mp_check_bool(const char *cur, const char *end);

/**
 * \brief Decode a bool value from MsgPack \a data
 * \param data - the pointer to a buffer
 * \return a decoded bool value
 * \post *data = *data + mp_sizeof_bool(retval)
 */
MP_PROTO bool
mp_decode_bool(const char **data);

/**
 * \brief Decode an integer value as int32_t from MsgPack \a data.
 * \param data - the pointer to a buffer
 * \param[out] ret - the pointer to save a result
 * \retval  0 on success
 * \retval -1 if underlying mp type is not MP_INT or MP_UINT
 * \retval -1 if the result can't be stored in int32_t
 */
MP_PROTO int
mp_read_int32(const char **data, int32_t *ret);

/**
 * \brief Decode an integer value as int64_t from MsgPack \a data.
 * \param data - the pointer to a buffer
 * \param[out] ret - the pointer to save a result
 * \retval  0 on success
 * \retval -1 if underlying mp type is not MP_INT or MP_UINT
 * \retval -1 if the result can't be stored in int64_t
 */
MP_PROTO int
mp_read_int64(const char **data, int64_t *ret);

/**
 * \brief Decode a floating point value as double from MsgPack \a data.
 * \param data - the pointer to a buffer
 * \param[out] ret - the pointer to save a result
 * \retval  0 on success
 * \retval -1 if underlying mp type is not MP_INT, MP_UINT,
 *            MP_FLOAT, or MP_DOUBLE
 * \retval -1 if the result can't be stored in double
 */
MP_PROTO int
mp_read_double(const char **data, double *ret);

/**
 * \brief Skip one element in a packed \a data.
 *
 * The function is faster than mp_typeof + mp_decode_XXX() combination.
 * For arrays and maps the function also skips all members.
 * For strings and binstrings the function also skips the string data.
 *
 * Usage example:
 * \code
 * char buf[1024];
 *
 * char *w = buf;
 * // First MsgPack object
 * w = mp_encode_uint(w, 10);
 *
 * // Second MsgPack object
 * w = mp_encode_array(w, 4);
 *    w = mp_encode_array(w, 2);
 *         // Begin of an inner array
 *         w = mp_encode_str(w, "second inner 1", 14);
 *         w = mp_encode_str(w, "second inner 2", 14);
 *         // End of an inner array
 *    w = mp_encode_str(w, "second", 6);
 *    w = mp_encode_uint(w, 20);
 *    w = mp_encode_bool(w, true);
 *
 * // Third MsgPack object
 * w = mp_encode_str(w, "third", 5);
 * // EOF
 *
 * const char *r = buf;
 *
 * // First MsgPack object
 * assert(mp_typeof(**r) == MP_UINT);
 * mp_next(&r); // skip the first object
 *
 * // Second MsgPack object
 * assert(mp_typeof(**r) == MP_ARRAY);
 * mp_decode_array(&r);
 *     assert(mp_typeof(**r) == MP_ARRAY); // inner array
 *     mp_next(&r); // -->> skip the entire inner array (with all members)
 *     assert(mp_typeof(**r) == MP_STR); // second
 *     mp_next(&r);
 *     assert(mp_typeof(**r) == MP_UINT); // 20
 *     mp_next(&r);
 *     assert(mp_typeof(**r) == MP_BOOL); // true
 *     mp_next(&r);
 *
 * // Third MsgPack object
 * assert(mp_typeof(**r) == MP_STR); // third
 * mp_next(&r);
 *
 * assert(r == w); // EOF
 *
 * \endcode
 * \param data - the pointer to a buffer
 * \post *data = *data + mp_sizeof_TYPE() where TYPE is mp_typeof(**data)
 */
MP_PROTO void
mp_next(const char **data);

/**
 * \brief Equivalent to mp_next() but also validates MsgPack in \a data.
 * \param data - the pointer to a buffer
 * \param end - the end of a buffer
 * \retval 0 when MsgPack in \a data is valid.
 * \retval != 0 when MsgPack in \a data is not valid.
 * \post *data = *data + mp_sizeof_TYPE() where TYPE is mp_typeof(**data)
 * \post *data is not defined if MsgPack is not valid
 * \sa mp_next()
 */
MP_PROTO int
mp_check(const char **data, const char *end);

/*
 * }}}
 */

/*
 * {{{ Implementation
 */

/** \cond false */
extern const enum mp_type mp_type_hint[];
extern const int8_t mp_parser_hint[];
extern const char *mp_char2escape[];

MP_IMPL MP_ALWAYSINLINE enum mp_type
mp_typeof(const char c)
{
	return mp_type_hint[(uint8_t) c];
}

MP_IMPL uint32_t
mp_sizeof_array(uint32_t size)
{
	if (size <= 15) {
		return 1;
	} else if (size <= UINT16_MAX) {
		return 1 + sizeof(uint16_t);
	} else {
		return 1 + sizeof(uint32_t);
	}
}

MP_IMPL char *
mp_encode_array(char *data, uint32_t size)
{
	if (size <= 15) {
		return mp_store_u8(data, 0x90 | size);
	} else if (size <= UINT16_MAX) {
		data = mp_store_u8(data, 0xdc);
		data = mp_store_u16(data, size);
		return data;
	} else {
		data = mp_store_u8(data, 0xdd);
		return mp_store_u32(data, size);
	}
}

MP_IMPL ptrdiff_t
mp_check_array(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_ARRAY);
	uint8_t c = mp_load_u8(&cur);
	if (mp_likely(!(c & 0x40)))
		return cur - end;

	assert(c >= 0xdc && c <= 0xdd); /* must be checked above by mp_typeof */
	uint32_t hsize = 2U << (c & 0x1); /* 0xdc->2, 0xdd->4 */
	return hsize - (end - cur);
}

MP_PROTO uint32_t
mp_decode_array_slowpath(uint8_t c, const char **data);

MP_IMPL uint32_t
mp_decode_array_slowpath(uint8_t c, const char **data)
{
	uint32_t size;
	switch (c & 0x1) {
	case 0xdc & 0x1:
		size = mp_load_u16(data);
		return size;
	case 0xdd & 0x1:
		size = mp_load_u32(data);
		return size;
	default:
		mp_unreachable();
	}
}

MP_IMPL MP_ALWAYSINLINE uint32_t
mp_decode_array(const char **data)
{
	uint8_t c = mp_load_u8(data);

	if (mp_likely(!(c & 0x40)))
		return (c & 0xf);

	return mp_decode_array_slowpath(c, data);
}

MP_IMPL uint32_t
mp_sizeof_map(uint32_t size)
{
	if (size <= 15) {
		return 1;
	} else if (size <= UINT16_MAX) {
		return 1 + sizeof(uint16_t);
	} else {
		return 1 + sizeof(uint32_t);
	}
}

MP_IMPL char *
mp_encode_map(char *data, uint32_t size)
{
	if (size <= 15) {
		return mp_store_u8(data, 0x80 | size);
	} else if (size <= UINT16_MAX) {
		data = mp_store_u8(data, 0xde);
		data = mp_store_u16(data, size);
		return data;
	} else {
		data = mp_store_u8(data, 0xdf);
		data = mp_store_u32(data, size);
		return data;
	}
}

MP_IMPL ptrdiff_t
mp_check_map(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_MAP);
	uint8_t c = mp_load_u8(&cur);
	if (mp_likely((c & ~0xfU) == 0x80))
		return cur - end;

	assert(c >= 0xde && c <= 0xdf); /* must be checked above by mp_typeof */
	uint32_t hsize = 2U << (c & 0x1); /* 0xde->2, 0xdf->4 */
	return hsize - (end - cur);
}

MP_IMPL uint32_t
mp_decode_map(const char **data)
{
	uint8_t c = mp_load_u8(data);
	switch (c) {
	case 0xde:
		return mp_load_u16(data);
	case 0xdf:
		return mp_load_u32(data);
	default:
		if (mp_unlikely(c < 0x80 || c > 0x8f))
			mp_unreachable();
		return c & 0xf;
	}
}

MP_IMPL uint32_t
mp_sizeof_uint(uint64_t num)
{
	if (num <= 0x7f) {
		return 1;
	} else if (num <= UINT8_MAX) {
		return 1 + sizeof(uint8_t);
	} else if (num <= UINT16_MAX) {
		return 1 + sizeof(uint16_t);
	} else if (num <= UINT32_MAX) {
		return 1 + sizeof(uint32_t);
	} else {
		return 1 + sizeof(uint64_t);
	}
}

MP_IMPL uint32_t
mp_sizeof_int(int64_t num)
{
	assert(num < 0);
	if (num >= -0x20) {
		return 1;
	} else if (num >= INT8_MIN && num <= INT8_MAX) {
		return 1 + sizeof(int8_t);
	} else if (num >= INT16_MIN && num <= UINT16_MAX) {
		return 1 + sizeof(int16_t);
	} else if (num >= INT32_MIN && num <= UINT32_MAX) {
		return 1 + sizeof(int32_t);
	} else {
		return 1 + sizeof(int64_t);
	}
}

MP_IMPL ptrdiff_t
mp_check_uint(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_UINT);
	uint8_t c = mp_load_u8(&cur);
	return mp_parser_hint[c] - (end - cur);
}

MP_IMPL ptrdiff_t
mp_check_int(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_INT);
	uint8_t c = mp_load_u8(&cur);
	return mp_parser_hint[c] - (end - cur);
}

MP_IMPL char *
mp_encode_uint(char *data, uint64_t num)
{
	if (num <= 0x7f) {
		return mp_store_u8(data, num);
	} else if (num <= UINT8_MAX) {
		data = mp_store_u8(data, 0xcc);
		return mp_store_u8(data, num);
	} else if (num <= UINT16_MAX) {
		data = mp_store_u8(data, 0xcd);
		return mp_store_u16(data, num);
	} else if (num <= UINT32_MAX) {
		data = mp_store_u8(data, 0xce);
		return mp_store_u32(data, num);
	} else {
		data = mp_store_u8(data, 0xcf);
		return mp_store_u64(data, num);
	}
}

MP_IMPL char *
mp_encode_int(char *data, int64_t num)
{
	assert(num < 0);
	if (num >= -0x20) {
		return mp_store_u8(data, 0xe0 | num);
	} else if (num >= INT8_MIN) {
		data = mp_store_u8(data, 0xd0);
		return mp_store_u8(data, num);
	} else if (num >= INT16_MIN) {
		data = mp_store_u8(data, 0xd1);
		return mp_store_u16(data, num);
	} else if (num >= INT32_MIN) {
		data = mp_store_u8(data, 0xd2);
		return mp_store_u32(data, num);
	} else {
		data = mp_store_u8(data, 0xd3);
		return mp_store_u64(data, num);
	}
}

MP_IMPL uint64_t
mp_decode_uint(const char **data)
{
	uint8_t c = mp_load_u8(data);
	switch (c) {
	case 0xcc:
		return mp_load_u8(data);
	case 0xcd:
		return mp_load_u16(data);
	case 0xce:
		return mp_load_u32(data);
	case 0xcf:
		return mp_load_u64(data);
	default:
		if (mp_unlikely(c > 0x7f))
			mp_unreachable();
		return c;
	}
}

MP_IMPL int
mp_compare_uint(const char *data_a, const char *data_b)
{
	uint8_t ca = mp_load_u8(&data_a);
	uint8_t cb = mp_load_u8(&data_b);

	int r = ca - cb;
	if (r != 0)
		return r;

	if (ca <= 0x7f)
		return 0;

	uint64_t a, b;
	switch (ca & 0x3) {
	case 0xcc & 0x3:
		a = mp_load_u8(&data_a);
		b = mp_load_u8(&data_b);
		break;
	case 0xcd & 0x3:
		a = mp_load_u16(&data_a);
		b = mp_load_u16(&data_b);
		break;
	case 0xce & 0x3:
		a = mp_load_u32(&data_a);
		b = mp_load_u32(&data_b);
		break;
	case 0xcf & 0x3:
		a = mp_load_u64(&data_a);
		b = mp_load_u64(&data_b);
		return a < b ? -1 : a > b;
		break;
	default:
		mp_unreachable();
	}

	int64_t v = (a - b);
	return (v > 0) - (v < 0);
}

MP_IMPL int64_t
mp_decode_int(const char **data)
{
	uint8_t c = mp_load_u8(data);
	switch (c) {
	case 0xd0:
		return (int8_t) mp_load_u8(data);
	case 0xd1:
		return (int16_t) mp_load_u16(data);
	case 0xd2:
		return (int32_t) mp_load_u32(data);
	case 0xd3:
		return (int64_t) mp_load_u64(data);
	default:
		if (mp_unlikely(c < 0xe0))
			mp_unreachable();
		return (int8_t) (c);
	}
}

MP_IMPL uint32_t
mp_sizeof_float(float num)
{
	(void) num;
	return 1 + sizeof(float);
}

MP_IMPL uint32_t
mp_sizeof_double(double num)
{
	(void) num;
	return 1 + sizeof(double);
}

MP_IMPL ptrdiff_t
mp_check_float(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_FLOAT);
	return 1 + sizeof(float) - (end - cur);
}

MP_IMPL ptrdiff_t
mp_check_double(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_DOUBLE);
	return 1 + sizeof(double) - (end - cur);
}

MP_IMPL char *
mp_encode_float(char *data, float num)
{
	data = mp_store_u8(data, 0xca);
	return mp_store_float(data, num);
}

MP_IMPL char *
mp_encode_double(char *data, double num)
{
	data = mp_store_u8(data, 0xcb);
	return mp_store_double(data, num);
}

MP_IMPL float
mp_decode_float(const char **data)
{
	uint8_t c = mp_load_u8(data);
	assert(c == 0xca);
	(void) c;
	return mp_load_float(data);
}

MP_IMPL double
mp_decode_double(const char **data)
{
	uint8_t c = mp_load_u8(data);
	assert(c == 0xcb);
	(void) c;
	return mp_load_double(data);
}

MP_IMPL uint32_t
mp_sizeof_strl(uint32_t len)
{
	if (len <= 31) {
		return 1;
	} else if (len <= UINT8_MAX) {
		return 1 + sizeof(uint8_t);
	} else if (len <= UINT16_MAX) {
		return 1 + sizeof(uint16_t);
	} else {
		return 1 + sizeof(uint32_t);
	}
}

MP_IMPL uint32_t
mp_sizeof_str(uint32_t len)
{
	return mp_sizeof_strl(len) + len;
}

MP_IMPL uint32_t
mp_sizeof_binl(uint32_t len)
{
	if (len <= UINT8_MAX) {
		return 1 + sizeof(uint8_t);
	} else if (len <= UINT16_MAX) {
		return 1 + sizeof(uint16_t);
	} else {
		return 1 + sizeof(uint32_t);
	}
}

MP_IMPL uint32_t
mp_sizeof_bin(uint32_t len)
{
	return mp_sizeof_binl(len) + len;
}

MP_IMPL char *
mp_encode_strl(char *data, uint32_t len)
{
	if (len <= 31) {
		return mp_store_u8(data, 0xa0 | (uint8_t) len);
	} else if (len <= UINT8_MAX) {
		data = mp_store_u8(data, 0xd9);
		return mp_store_u8(data, len);
	} else if (len <= UINT16_MAX) {
		data = mp_store_u8(data, 0xda);
		return mp_store_u16(data, len);
	} else {
		data = mp_store_u8(data, 0xdb);
		return mp_store_u32(data, len);
	}
}

MP_IMPL char *
mp_encode_str(char *data, const char *str, uint32_t len)
{
	data = mp_encode_strl(data, len);
	memcpy(data, str, len);
	return data + len;
}

MP_IMPL char *
mp_encode_binl(char *data, uint32_t len)
{
	if (len <= UINT8_MAX) {
		data = mp_store_u8(data, 0xc4);
		return mp_store_u8(data, len);
	} else if (len <= UINT16_MAX) {
		data = mp_store_u8(data, 0xc5);
		return mp_store_u16(data, len);
	} else {
		data = mp_store_u8(data, 0xc6);
		return mp_store_u32(data, len);
	}
}

MP_IMPL char *
mp_encode_bin(char *data, const char *str, uint32_t len)
{
	data = mp_encode_binl(data, len);
	memcpy(data, str, len);
	return data + len;
}

MP_IMPL ptrdiff_t
mp_check_strl(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_STR);

	uint8_t c = mp_load_u8(&cur);
	if (mp_likely(c & ~0x1f) == 0xa0)
		return cur - end;

	assert(c >= 0xd9 && c <= 0xdb); /* must be checked above by mp_typeof */
	uint32_t hsize = 1U << (c & 0x3) >> 1; /* 0xd9->1, 0xda->2, 0xdb->4 */
	return hsize - (end - cur);
}

MP_IMPL ptrdiff_t
mp_check_binl(const char *cur, const char *end)
{
	uint8_t c = mp_load_u8(&cur);
	assert(cur < end);
	assert(mp_typeof(c) == MP_BIN);

	assert(c >= 0xc4 && c <= 0xc6); /* must be checked above by mp_typeof */
	uint32_t hsize = 1U << (c & 0x3); /* 0xc4->1, 0xc5->2, 0xc6->4 */
	return hsize - (end - cur);
}

MP_IMPL uint32_t
mp_decode_strl(const char **data)
{
	uint8_t c = mp_load_u8(data);
	switch (c) {
	case 0xd9:
		return mp_load_u8(data);
	case 0xda:
		return mp_load_u16(data);
	case 0xdb:
		return mp_load_u32(data);
	default:
		if (mp_unlikely(c < 0xa0 || c > 0xbf))
			mp_unreachable();
		return c & 0x1f;
	}
}

MP_IMPL const char *
mp_decode_str(const char **data, uint32_t *len)
{
	assert(len != NULL);

	*len = mp_decode_strl(data);
	const char *str = *data;
	*data += *len;
	return str;
}

MP_IMPL uint32_t
mp_decode_binl(const char **data)
{
	uint8_t c = mp_load_u8(data);

	switch (c) {
	case 0xc4:
		return mp_load_u8(data);
	case 0xc5:
		return mp_load_u16(data);
	case 0xc6:
		return mp_load_u32(data);
	default:
		mp_unreachable();
	}
}

MP_IMPL const char *
mp_decode_bin(const char **data, uint32_t *len)
{
	assert(len != NULL);

	*len = mp_decode_binl(data);
	const char *str = *data;
	*data += *len;
	return str;
}

MP_IMPL uint32_t
mp_decode_strbinl(const char **data)
{
	uint8_t c = mp_load_u8(data);

	switch (c) {
	case 0xd9:
		return mp_load_u8(data);
	case 0xda:
		return mp_load_u16(data);
	case 0xdb:
		return mp_load_u32(data);
	case 0xc4:
		return mp_load_u8(data);
	case 0xc5:
		return mp_load_u16(data);
	case 0xc6:
		return mp_load_u32(data);
	default:
		if (mp_unlikely(c < 0xa0 || c > 0xbf))
			mp_unreachable();
		return c & 0x1f;
	}
}

MP_IMPL const char *
mp_decode_strbin(const char **data, uint32_t *len)
{
	assert(len != NULL);

	*len = mp_decode_strbinl(data);
	const char *str = *data;
	*data += *len;
	return str;
}

MP_IMPL uint32_t
mp_sizeof_nil()
{
	return 1;
}

MP_IMPL char *
mp_encode_nil(char *data)
{
	return mp_store_u8(data, 0xc0);
}

MP_IMPL ptrdiff_t
mp_check_nil(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_NIL);
	return 1 - (end - cur);
}

MP_IMPL void
mp_decode_nil(const char **data)
{
	uint8_t c = mp_load_u8(data);
	assert(c == 0xc0);
	(void) c;
}

MP_IMPL uint32_t
mp_sizeof_bool(bool val)
{
	(void) val;
	return 1;
}

MP_IMPL char *
mp_encode_bool(char *data, bool val)
{
	return mp_store_u8(data, 0xc2 | (val & 1));
}

MP_IMPL ptrdiff_t
mp_check_bool(const char *cur, const char *end)
{
	assert(cur < end);
	assert(mp_typeof(*cur) == MP_BOOL);
	return 1 - (end - cur);
}

MP_IMPL bool
mp_decode_bool(const char **data)
{
	uint8_t c = mp_load_u8(data);
	switch (c) {
	case 0xc3:
		return true;
	case 0xc2:
		return false;
	default:
		mp_unreachable();
	}
}

MP_IMPL int
mp_read_int32(const char **data, int32_t *ret)
{
	uint32_t uval;
	const char *p = *data;
	uint8_t c = mp_load_u8(&p);
	switch (c) {
	case 0xd0:
		*ret = (int8_t) mp_load_u8(&p);
		break;
	case 0xd1:
		*ret = (int16_t) mp_load_u16(&p);
		break;
	case 0xd2:
		*ret = (int32_t) mp_load_u32(&p);
		break;
	case 0xcc:
		*ret = mp_load_u8(&p);
		break;
	case 0xcd:
		*ret = mp_load_u16(&p);
		break;
	case 0xce:
		uval = mp_load_u32(&p);
		if (mp_unlikely(uval > INT32_MAX))
			return -1;
		*ret = uval;
		break;
	default:
		if (mp_unlikely(c < 0xe0 && c > 0x7f))
			return -1;
		*ret = (int8_t) c;
		break;
	}
	*data = p;
	return 0;
}

MP_IMPL int
mp_read_int64(const char **data, int64_t *ret)
{
	uint64_t uval;
	const char *p = *data;
	uint8_t c = mp_load_u8(&p);
	switch (c) {
	case 0xd0:
		*ret = (int8_t) mp_load_u8(&p);
		break;
	case 0xd1:
		*ret = (int16_t) mp_load_u16(&p);
		break;
	case 0xd2:
		*ret = (int32_t) mp_load_u32(&p);
		break;
	case 0xd3:
		*ret = (int64_t) mp_load_u64(&p);
		break;
	case 0xcc:
		*ret = mp_load_u8(&p);
		break;
	case 0xcd:
		*ret = mp_load_u16(&p);
		break;
	case 0xce:
		*ret = mp_load_u32(&p);
		break;
	case 0xcf:
		uval = mp_load_u64(&p);
		if (uval > INT64_MAX)
			return -1;
		*ret = uval;
		break;
	default:
		if (mp_unlikely(c < 0xe0 && c > 0x7f))
			return -1;
		*ret = (int8_t) c;
		break;
	}
	*data = p;
	return 0;
}

MP_IMPL int
mp_read_double(const char **data, double *ret)
{
	int64_t ival;
	uint64_t uval;
	double val;
	const char *p = *data;
	uint8_t c = mp_load_u8(&p);
	switch (c) {
	case 0xd0:
		*ret = (int8_t) mp_load_u8(&p);
		break;
	case 0xd1:
		*ret = (int16_t) mp_load_u16(&p);
		break;
	case 0xd2:
		*ret = (int32_t) mp_load_u32(&p);
		break;
	case 0xd3:
		val = ival = (int64_t) mp_load_u64(&p);
		if ((int64_t)val != ival)
			return -1;
		*ret = val;
		break;
	case 0xcc:
		*ret = mp_load_u8(&p);
		break;
	case 0xcd:
		*ret = mp_load_u16(&p);
		break;
	case 0xce:
		*ret = mp_load_u32(&p);
		break;
	case 0xcf:
		val = uval = mp_load_u64(&p);
		if ((uint64_t)val != uval)
			return -1;
		*ret = val;
		break;
	case 0xca:
		*ret = mp_load_float(&p);
		break;
	case 0xcb:
		*ret = mp_load_double(&p);
		break;
	default:
		if (mp_unlikely(c < 0xe0 && c > 0x7f))
			return -1;
		*ret = (int8_t) c;
		break;
	}
	*data = p;
	return 0;
}

/** See mp_parser_hint */
enum {
	MP_HINT = -32,
	MP_HINT_STR_8 = MP_HINT,
	MP_HINT_STR_16 = MP_HINT - 1,
	MP_HINT_STR_32 = MP_HINT - 2,
	MP_HINT_ARRAY_16 = MP_HINT - 3,
	MP_HINT_ARRAY_32 = MP_HINT - 4,
	MP_HINT_MAP_16 = MP_HINT - 5,
	MP_HINT_MAP_32 = MP_HINT - 6,
	MP_HINT_EXT_8 = MP_HINT - 7,
	MP_HINT_EXT_16 = MP_HINT - 8,
	MP_HINT_EXT_32 = MP_HINT - 9
};

MP_PROTO void
mp_next_slowpath(const char **data, int64_t k);

MP_IMPL void
mp_next_slowpath(const char **data, int64_t k)
{
	for (; k > 0; k--) {
		uint8_t c = mp_load_u8(data);
		int l = mp_parser_hint[c];
		if (mp_likely(l >= 0)) {
			*data += l;
			continue;
		} else if (mp_likely(l > MP_HINT)) {
			k -= l;
			continue;
		}

		uint32_t len;
		switch (l) {
		case MP_HINT_STR_8:
			/* MP_STR (8) */
			len = mp_load_u8(data);
			*data += len;
			break;
		case MP_HINT_STR_16:
			/* MP_STR (16) */
			len = mp_load_u16(data);
			*data += len;
			break;
		case MP_HINT_STR_32:
			/* MP_STR (32) */
			len = mp_load_u32(data);
			*data += len;
			break;
		case MP_HINT_ARRAY_16:
			/* MP_ARRAY (16) */
			k += mp_load_u16(data);
			break;
		case MP_HINT_ARRAY_32:
			/* MP_ARRAY (32) */
			k += mp_load_u32(data);
			break;
		case MP_HINT_MAP_16:
			/* MP_MAP (16) */
			k += 2 * mp_load_u16(data);
			break;
		case MP_HINT_MAP_32:
			/* MP_MAP (32) */
			k += 2 * mp_load_u32(data);
			break;
		case MP_HINT_EXT_8:
			/* MP_EXT (8) */
			len = mp_load_u8(data);
			mp_load_u8(data);
			*data += len;
			break;
		case MP_HINT_EXT_16:
			/* MP_EXT (16) */
			len = mp_load_u16(data);
			mp_load_u8(data);
			*data += len;
			break;
		case MP_HINT_EXT_32:
			/* MP_EXT (32) */
			len = mp_load_u32(data);
			mp_load_u8(data);
			*data += len;
			break;
		default:
			mp_unreachable();
		}
	}
}

MP_IMPL void
mp_next(const char **data)
{
	int64_t k = 1;
	for (; k > 0; k--) {
		uint8_t c = mp_load_u8(data);
		int l = mp_parser_hint[c];
		if (mp_likely(l >= 0)) {
			*data += l;
			continue;
		} else if (mp_likely(c == 0xd9)){
			/* MP_STR (8) */
			uint8_t len = mp_load_u8(data);
			*data += len;
			continue;
		} else if (l > MP_HINT) {
			k -= l;
			continue;
		} else {
			*data -= sizeof(uint8_t);
			return mp_next_slowpath(data, k);
		}
	}
}

MP_IMPL int
mp_check(const char **data, const char *end)
{
#define MP_CHECK_LEN(_l) \
	if (mp_unlikely((size_t)(end - *data) < (size_t)(_l))) \
		return 1;

	int64_t k;
	for (k = 1; k > 0; k--) {
		MP_CHECK_LEN(1);
		uint8_t c = mp_load_u8(data);
		int l = mp_parser_hint[c];
		if (mp_likely(l >= 0)) {
			MP_CHECK_LEN(l);
			*data += l;
			continue;
		} else if (mp_likely(l > MP_HINT)) {
			k -= l;
			continue;
		}

		uint32_t len;
		switch (l) {
		case MP_HINT_STR_8:
			/* MP_STR (8) */
			MP_CHECK_LEN(sizeof(uint8_t));
			len = mp_load_u8(data);
			MP_CHECK_LEN(len);
			*data += len;
			break;
		case MP_HINT_STR_16:
			/* MP_STR (16) */
			MP_CHECK_LEN(sizeof(uint16_t));
			len = mp_load_u16(data);
			MP_CHECK_LEN(len);
			*data += len;
			break;
		case MP_HINT_STR_32:
			/* MP_STR (32) */
			MP_CHECK_LEN(sizeof(uint32_t))
			len = mp_load_u32(data);
			MP_CHECK_LEN(len);
			*data += len;
			break;
		case MP_HINT_ARRAY_16:
			/* MP_ARRAY (16) */
			MP_CHECK_LEN(sizeof(uint16_t));
			k += mp_load_u16(data);
			break;
		case MP_HINT_ARRAY_32:
			/* MP_ARRAY (32) */
			MP_CHECK_LEN(sizeof(uint32_t));
			k += mp_load_u32(data);
			break;
		case MP_HINT_MAP_16:
			/* MP_MAP (16) */
			MP_CHECK_LEN(sizeof(uint16_t));
			k += 2 * mp_load_u16(data);
			break;
		case MP_HINT_MAP_32:
			/* MP_MAP (32) */
			MP_CHECK_LEN(sizeof(uint32_t));
			k += 2 * mp_load_u32(data);
			break;
		case MP_HINT_EXT_8:
			/* MP_EXT (8) */
			MP_CHECK_LEN(sizeof(uint8_t) + sizeof(uint8_t));
			len = mp_load_u8(data);
			mp_load_u8(data);
			MP_CHECK_LEN(len);
			*data += len;
			break;
		case MP_HINT_EXT_16:
			/* MP_EXT (16) */
			MP_CHECK_LEN(sizeof(uint16_t) + sizeof(uint8_t));
			len = mp_load_u16(data);
			mp_load_u8(data);
			MP_CHECK_LEN(len);
			*data += len;
			break;
		case MP_HINT_EXT_32:
			/* MP_EXT (32) */
			MP_CHECK_LEN(sizeof(uint32_t) + sizeof(uint8_t));
			len = mp_load_u32(data);
			mp_load_u8(data);
			MP_CHECK_LEN(len);
			*data += len;
			break;
		default:
			mp_unreachable();
		}
	}

	assert(*data <= end);
#undef MP_CHECK_LEN
	return 0;
}

/** \endcond */

/*
 * }}}
 */

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#undef MP_LIBRARY
#undef MP_PROTO
#undef MP_IMPL
#undef MP_ALWAYSINLINE
#undef MP_GCC_VERSION

#endif /* MSGPUCK_H_INCLUDED */
