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

#define MP_LIBRARY 1
#include "msgpuck.h"

size_t
mp_vformat(char *data, size_t data_size, const char *format, va_list vl)
{
	size_t result = 0;
	const char *f = NULL;

	for (f = format; *f; f++) {
		if (f[0] == '[') {
			uint32_t size = 0;
			int level = 1;
			const char *e = NULL;

			for (e = f + 1; level && *e; e++) {
				if (*e == '[' || *e == '{') {
					if (level == 1)
						size++;
					level++;
				} else if (*e == ']' || *e == '}') {
					level--;
					/* opened '[' must be closed by ']' */
					assert(level || *e == ']');
				} else if (*e == '%') {
					if (e[1] == '%')
						e++;
					else if (level == 1)
						size++;
				} else if (*e == 'N' && e[1] == 'I'
					   && e[2] == 'L' && level == 1) {
					size++;
				}
			}
			/* opened '[' must be closed */
			assert(level == 0);
			result += mp_sizeof_array(size);
			if (result <= data_size)
				data = mp_encode_array(data, size);
		} else if (f[0] == '{') {
			uint32_t count = 0;
			int level = 1;
			const char *e = NULL;

			for (e = f + 1; level && *e; e++) {
				if (*e == '[' || *e == '{') {
					if (level == 1)
						count++;
					level++;
				} else if (*e == ']' || *e == '}') {
					level--;
					/* opened '{' must be closed by '}' */
					assert(level || *e == '}');
				} else if (*e == '%') {
					if (e[1] == '%')
						e++;
					else if (level == 1)
						count++;
				} else if (*e == 'N' && e[1] == 'I'
					   && e[2] == 'L' && level == 1) {
					count++;
				}
			}
			/* opened '{' must be closed */
			assert(level == 0);
			/* since map is a pair list, count must be even */
			assert(count % 2 == 0);
			uint32_t size = count / 2;
			result += mp_sizeof_map(size);
			if (result <= data_size)
				data = mp_encode_map(data, size);
		} else if (f[0] == '%') {
			f++;
			assert(f[0]);
			int64_t int_value = 0;
			int int_status = 0; /* 1 - signed, 2 - unsigned */

			if (f[0] == 'd' || f[0] == 'i') {
				int_value = va_arg(vl, int);
				int_status = 1;
			} else if (f[0] == 'u') {
				int_value = va_arg(vl, unsigned int);
				int_status = 2;
			} else if (f[0] == 's') {
				const char *str = va_arg(vl, const char *);
				uint32_t len = (uint32_t)strlen(str);
				result += mp_sizeof_str(len);
				if (result <= data_size)
					data = mp_encode_str(data, str, len);
			} else if (f[0] == '.' && f[1] == '*' && f[2] == 's') {
				uint32_t len = va_arg(vl, uint32_t);
				const char *str = va_arg(vl, const char *);
				result += mp_sizeof_str(len);
				if (result <= data_size)
					data = mp_encode_str(data, str, len);
				f += 2;
			} else if (f[0] == 'p') {
				const char *p = va_arg(vl, const char *);
				const char *end = p;
				mp_next(&end);
				uint32_t len = end - p;
				result += len;
				if (result <= data_size) {
					memcpy(data, p, len);
					data += len;
				}
			} else if (f[0] == '.' && f[1] == '*' && f[2] == 'p') {
				uint32_t len = va_arg(vl, uint32_t);
				const char *p = va_arg(vl, const char *);
				assert(len > 0);
				result += len;
				if (result <= data_size) {
					memcpy(data, p, len);
					data += len;
				}
				f += 2;
			} else if(f[0] == 'f') {
				float v = (float)va_arg(vl, double);
				result += mp_sizeof_float(v);
				if (result <= data_size)
					data = mp_encode_float(data, v);
			} else if(f[0] == 'l' && f[1] == 'f') {
				double v = va_arg(vl, double);
				result += mp_sizeof_double(v);
				if (result <= data_size)
					data = mp_encode_double(data, v);
				f++;
			} else if(f[0] == 'b') {
				bool v = (bool)va_arg(vl, int);
				result += mp_sizeof_bool(v);
				if (result <= data_size)
					data = mp_encode_bool(data, v);
			} else if (f[0] == 'l'
				   && (f[1] == 'd' || f[1] == 'i')) {
				int_value = va_arg(vl, long);
				int_status = 1;
				f++;
			} else if (f[0] == 'l' && f[1] == 'u') {
				int_value = va_arg(vl, unsigned long);
				int_status = 2;
				f++;
			} else if (f[0] == 'l' && f[1] == 'l'
				   && (f[2] == 'd' || f[2] == 'i')) {
				int_value = va_arg(vl, long long);
				int_status = 1;
				f += 2;
			} else if (f[0] == 'l' && f[1] == 'l' && f[2] == 'u') {
				int_value = va_arg(vl, unsigned long long);
				int_status = 2;
				f += 2;
			} else if (f[0] == 'h'
				   && (f[1] == 'd' || f[1] == 'i')) {
				int_value = va_arg(vl, int);
				int_status = 1;
				f++;
			} else if (f[0] == 'h' && f[1] == 'u') {
				int_value = va_arg(vl, unsigned int);
				int_status = 2;
				f++;
			} else if (f[0] == 'h' && f[1] == 'h'
				   && (f[2] == 'd' || f[2] == 'i')) {
				int_value = va_arg(vl, int);
				int_status = 1;
				f += 2;
			} else if (f[0] == 'h' && f[1] == 'h' && f[2] == 'u') {
				int_value = va_arg(vl, unsigned int);
				int_status = 2;
				f += 2;
			} else if (f[0] != '%') {
				/* unexpected format specifier */
				assert(false);
			}

			if (int_status == 1 && int_value < 0) {
				result += mp_sizeof_int(int_value);
				if (result <= data_size)
					data = mp_encode_int(data, int_value);
			} else if(int_status) {
				result += mp_sizeof_uint(int_value);
				if (result <= data_size)
					data = mp_encode_uint(data, int_value);
			}
		} else if (f[0] == 'N' && f[1] == 'I' && f[2] == 'L') {
			result += mp_sizeof_nil();
			if (result <= data_size)
				data = mp_encode_nil(data);
			f += 2;
		}
	}
	return result;
}

size_t
mp_format(char *data, size_t data_size, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	size_t res = mp_vformat(data, data_size, format, args);
	va_end(args);
	return res;
}

#define MP_PRINT(SELF, PRINTF) \
{										\
	switch (mp_typeof(**data)) {						\
	case MP_NIL:								\
		mp_decode_nil(data);						\
		PRINTF("null");							\
		break;								\
	case MP_UINT:								\
		PRINTF("%llu", (unsigned long long) mp_decode_uint(data));	\
		break;								\
	case MP_INT:								\
		PRINTF("%lld", (long long) mp_decode_int(data));		\
		break;								\
	case MP_STR:								\
	case MP_BIN:								\
	{									\
		uint32_t len = mp_typeof(**data) == MP_STR ?			\
			mp_decode_strl(data) : mp_decode_binl(data);		\
		PRINTF("\"");							\
		const char *s;							\
		for (s = *data; s < *data + len; s++) {				\
			unsigned char c = (unsigned char ) *s;			\
			if (c < 128 && mp_char2escape[c] != NULL) {		\
				/* Escape character */				\
				PRINTF("%s", mp_char2escape[c]);		\
			} else {						\
				PRINTF("%c", c);				\
			}							\
		}								\
		PRINTF("\"");							\
		*data += len;							\
		break;								\
	}									\
	case MP_ARRAY:								\
	{									\
		uint32_t count = mp_decode_array(data);				\
		PRINTF("[");							\
		uint32_t i;							\
		for (i = 0; i < count; i++) {					\
			if (i)							\
				PRINTF(", ");					\
			SELF(data);						\
		}								\
		PRINTF("]");							\
		break;								\
	}									\
	case MP_MAP:								\
	{									\
		uint32_t count = mp_decode_map(data);				\
		PRINTF("{");							\
		uint32_t i;							\
		for (i = 0; i < count; i++) {					\
			if (i)							\
				PRINTF(", ");					\
			SELF(data);						\
			PRINTF(": ");						\
			SELF(data);						\
		}								\
		PRINTF("}");							\
		break;								\
	}									\
	case MP_BOOL:								\
		PRINTF(mp_decode_bool(data) ? "true" : "false");		\
		break;								\
	case MP_FLOAT:								\
		PRINTF("%g", mp_decode_float(data));				\
		break;								\
	case MP_DOUBLE:								\
		PRINTF("%lg", mp_decode_double(data));				\
		break;								\
	case MP_EXT:								\
		mp_next(data);							\
		PRINTF("undefined");						\
		break;								\
	default:								\
		mp_unreachable();						\
		return -1;							\
	}									\
}

static inline int
mp_fprint_internal(FILE *file, const char **data)
{
	int total_bytes = 0;
#define HANDLE(FUN, ...) do {							\
	int bytes = FUN(file, __VA_ARGS__);					\
	if (mp_unlikely(bytes < 0))						\
		return -1;							\
	total_bytes += bytes;							\
} while (0)
#define PRINT(...) HANDLE(fprintf, __VA_ARGS__)
#define SELF(...) HANDLE(mp_fprint_internal, __VA_ARGS__)
MP_PRINT(SELF, PRINT)
#undef HANDLE
#undef SELF
#undef PRINT
	return total_bytes;
}

int
mp_fprint(FILE *file, const char *data)
{
	if (!file)
		file = stdout;
	int res = mp_fprint_internal(file, &data);
	return res;
}

static inline int
mp_snprint_internal(char *buf, int size, const char **data)
{
	int total_bytes = 0;
#define HANDLE(FUN, ...) do {							\
	int bytes = FUN(buf, size, __VA_ARGS__);				\
	if (mp_unlikely(bytes < 0))						\
		return -1;							\
	total_bytes += bytes;							\
	if (bytes < size) {							\
		buf += bytes;							\
		size -= bytes;							\
	} else {								\
		/* Calculate the number of bytes needed */			\
		buf = NULL;							\
		size = 0;							\
	}									\
} while (0)
#define PRINT(...) HANDLE(snprintf, __VA_ARGS__)
#define SELF(...) HANDLE(mp_snprint_internal, __VA_ARGS__)
MP_PRINT(SELF, PRINT)
#undef HANDLE
#undef SELF
#undef PRINT
	return total_bytes;
}
#undef MP_PRINT

int
mp_snprint(char *buf, int size, const char *data)
{
	return mp_snprint_internal(buf, size, &data);
}
