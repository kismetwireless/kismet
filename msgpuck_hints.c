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

#include "msgpuck.h"

/**
 * This lookup table used by mp_sizeof() to determine enum mp_type by the first
 * byte of MsgPack element.
 */
const enum mp_type mp_type_hint[256]= {
	/* {{{ MP_UINT (fixed) */
	/* 0x00 */ MP_UINT,
	/* 0x01 */ MP_UINT,
	/* 0x02 */ MP_UINT,
	/* 0x03 */ MP_UINT,
	/* 0x04 */ MP_UINT,
	/* 0x05 */ MP_UINT,
	/* 0x06 */ MP_UINT,
	/* 0x07 */ MP_UINT,
	/* 0x08 */ MP_UINT,
	/* 0x09 */ MP_UINT,
	/* 0x0a */ MP_UINT,
	/* 0x0b */ MP_UINT,
	/* 0x0c */ MP_UINT,
	/* 0x0d */ MP_UINT,
	/* 0x0e */ MP_UINT,
	/* 0x0f */ MP_UINT,
	/* 0x10 */ MP_UINT,
	/* 0x11 */ MP_UINT,
	/* 0x12 */ MP_UINT,
	/* 0x13 */ MP_UINT,
	/* 0x14 */ MP_UINT,
	/* 0x15 */ MP_UINT,
	/* 0x16 */ MP_UINT,
	/* 0x17 */ MP_UINT,
	/* 0x18 */ MP_UINT,
	/* 0x19 */ MP_UINT,
	/* 0x1a */ MP_UINT,
	/* 0x1b */ MP_UINT,
	/* 0x1c */ MP_UINT,
	/* 0x1d */ MP_UINT,
	/* 0x1e */ MP_UINT,
	/* 0x1f */ MP_UINT,
	/* 0x20 */ MP_UINT,
	/* 0x21 */ MP_UINT,
	/* 0x22 */ MP_UINT,
	/* 0x23 */ MP_UINT,
	/* 0x24 */ MP_UINT,
	/* 0x25 */ MP_UINT,
	/* 0x26 */ MP_UINT,
	/* 0x27 */ MP_UINT,
	/* 0x28 */ MP_UINT,
	/* 0x29 */ MP_UINT,
	/* 0x2a */ MP_UINT,
	/* 0x2b */ MP_UINT,
	/* 0x2c */ MP_UINT,
	/* 0x2d */ MP_UINT,
	/* 0x2e */ MP_UINT,
	/* 0x2f */ MP_UINT,
	/* 0x30 */ MP_UINT,
	/* 0x31 */ MP_UINT,
	/* 0x32 */ MP_UINT,
	/* 0x33 */ MP_UINT,
	/* 0x34 */ MP_UINT,
	/* 0x35 */ MP_UINT,
	/* 0x36 */ MP_UINT,
	/* 0x37 */ MP_UINT,
	/* 0x38 */ MP_UINT,
	/* 0x39 */ MP_UINT,
	/* 0x3a */ MP_UINT,
	/* 0x3b */ MP_UINT,
	/* 0x3c */ MP_UINT,
	/* 0x3d */ MP_UINT,
	/* 0x3e */ MP_UINT,
	/* 0x3f */ MP_UINT,
	/* 0x40 */ MP_UINT,
	/* 0x41 */ MP_UINT,
	/* 0x42 */ MP_UINT,
	/* 0x43 */ MP_UINT,
	/* 0x44 */ MP_UINT,
	/* 0x45 */ MP_UINT,
	/* 0x46 */ MP_UINT,
	/* 0x47 */ MP_UINT,
	/* 0x48 */ MP_UINT,
	/* 0x49 */ MP_UINT,
	/* 0x4a */ MP_UINT,
	/* 0x4b */ MP_UINT,
	/* 0x4c */ MP_UINT,
	/* 0x4d */ MP_UINT,
	/* 0x4e */ MP_UINT,
	/* 0x4f */ MP_UINT,
	/* 0x50 */ MP_UINT,
	/* 0x51 */ MP_UINT,
	/* 0x52 */ MP_UINT,
	/* 0x53 */ MP_UINT,
	/* 0x54 */ MP_UINT,
	/* 0x55 */ MP_UINT,
	/* 0x56 */ MP_UINT,
	/* 0x57 */ MP_UINT,
	/* 0x58 */ MP_UINT,
	/* 0x59 */ MP_UINT,
	/* 0x5a */ MP_UINT,
	/* 0x5b */ MP_UINT,
	/* 0x5c */ MP_UINT,
	/* 0x5d */ MP_UINT,
	/* 0x5e */ MP_UINT,
	/* 0x5f */ MP_UINT,
	/* 0x60 */ MP_UINT,
	/* 0x61 */ MP_UINT,
	/* 0x62 */ MP_UINT,
	/* 0x63 */ MP_UINT,
	/* 0x64 */ MP_UINT,
	/* 0x65 */ MP_UINT,
	/* 0x66 */ MP_UINT,
	/* 0x67 */ MP_UINT,
	/* 0x68 */ MP_UINT,
	/* 0x69 */ MP_UINT,
	/* 0x6a */ MP_UINT,
	/* 0x6b */ MP_UINT,
	/* 0x6c */ MP_UINT,
	/* 0x6d */ MP_UINT,
	/* 0x6e */ MP_UINT,
	/* 0x6f */ MP_UINT,
	/* 0x70 */ MP_UINT,
	/* 0x71 */ MP_UINT,
	/* 0x72 */ MP_UINT,
	/* 0x73 */ MP_UINT,
	/* 0x74 */ MP_UINT,
	/* 0x75 */ MP_UINT,
	/* 0x76 */ MP_UINT,
	/* 0x77 */ MP_UINT,
	/* 0x78 */ MP_UINT,
	/* 0x79 */ MP_UINT,
	/* 0x7a */ MP_UINT,
	/* 0x7b */ MP_UINT,
	/* 0x7c */ MP_UINT,
	/* 0x7d */ MP_UINT,
	/* 0x7e */ MP_UINT,
	/* 0x7f */ MP_UINT,
	/* }}} */

	/* {{{ MP_MAP (fixed) */
	/* 0x80 */ MP_MAP,
	/* 0x81 */ MP_MAP,
	/* 0x82 */ MP_MAP,
	/* 0x83 */ MP_MAP,
	/* 0x84 */ MP_MAP,
	/* 0x85 */ MP_MAP,
	/* 0x86 */ MP_MAP,
	/* 0x87 */ MP_MAP,
	/* 0x88 */ MP_MAP,
	/* 0x89 */ MP_MAP,
	/* 0x8a */ MP_MAP,
	/* 0x8b */ MP_MAP,
	/* 0x8c */ MP_MAP,
	/* 0x8d */ MP_MAP,
	/* 0x8e */ MP_MAP,
	/* 0x8f */ MP_MAP,
	/* }}} */

	/* {{{ MP_ARRAY (fixed) */
	/* 0x90 */ MP_ARRAY,
	/* 0x91 */ MP_ARRAY,
	/* 0x92 */ MP_ARRAY,
	/* 0x93 */ MP_ARRAY,
	/* 0x94 */ MP_ARRAY,
	/* 0x95 */ MP_ARRAY,
	/* 0x96 */ MP_ARRAY,
	/* 0x97 */ MP_ARRAY,
	/* 0x98 */ MP_ARRAY,
	/* 0x99 */ MP_ARRAY,
	/* 0x9a */ MP_ARRAY,
	/* 0x9b */ MP_ARRAY,
	/* 0x9c */ MP_ARRAY,
	/* 0x9d */ MP_ARRAY,
	/* 0x9e */ MP_ARRAY,
	/* 0x9f */ MP_ARRAY,
	/* }}} */

	/* {{{ MP_STR (fixed) */
	/* 0xa0 */ MP_STR,
	/* 0xa1 */ MP_STR,
	/* 0xa2 */ MP_STR,
	/* 0xa3 */ MP_STR,
	/* 0xa4 */ MP_STR,
	/* 0xa5 */ MP_STR,
	/* 0xa6 */ MP_STR,
	/* 0xa7 */ MP_STR,
	/* 0xa8 */ MP_STR,
	/* 0xa9 */ MP_STR,
	/* 0xaa */ MP_STR,
	/* 0xab */ MP_STR,
	/* 0xac */ MP_STR,
	/* 0xad */ MP_STR,
	/* 0xae */ MP_STR,
	/* 0xaf */ MP_STR,
	/* 0xb0 */ MP_STR,
	/* 0xb1 */ MP_STR,
	/* 0xb2 */ MP_STR,
	/* 0xb3 */ MP_STR,
	/* 0xb4 */ MP_STR,
	/* 0xb5 */ MP_STR,
	/* 0xb6 */ MP_STR,
	/* 0xb7 */ MP_STR,
	/* 0xb8 */ MP_STR,
	/* 0xb9 */ MP_STR,
	/* 0xba */ MP_STR,
	/* 0xbb */ MP_STR,
	/* 0xbc */ MP_STR,
	/* 0xbd */ MP_STR,
	/* 0xbe */ MP_STR,
	/* 0xbf */ MP_STR,
	/* }}} */

	/* {{{ MP_NIL, MP_BOOL */
	/* 0xc0 */ MP_NIL,
	/* 0xc1 */ MP_EXT, /* never used */
	/* 0xc2 */ MP_BOOL,
	/* 0xc3 */ MP_BOOL,
	/* }}} */

	/* {{{ MP_BIN */
	/* 0xc4 */ MP_BIN,   /* MP_BIN(8)  */
	/* 0xc5 */ MP_BIN,   /* MP_BIN(16) */
	/* 0xc6 */ MP_BIN,   /* MP_BIN(32) */
	/* }}} */

	/* {{{ MP_EXT */
	/* 0xc7 */ MP_EXT,
	/* 0xc8 */ MP_EXT,
	/* 0xc9 */ MP_EXT,
	/* }}} */

	/* {{{ MP_FLOAT, MP_DOUBLE */
	/* 0xca */ MP_FLOAT,
	/* 0xcb */ MP_DOUBLE,
	/* }}} */

	/* {{{ MP_UINT */
	/* 0xcc */ MP_UINT,
	/* 0xcd */ MP_UINT,
	/* 0xce */ MP_UINT,
	/* 0xcf */ MP_UINT,
	/* }}} */

	/* {{{ MP_INT */
	/* 0xd0 */ MP_INT,   /* MP_INT (8)  */
	/* 0xd1 */ MP_INT,   /* MP_INT (16) */
	/* 0xd2 */ MP_INT,   /* MP_INT (32) */
	/* 0xd3 */ MP_INT,   /* MP_INT (64) */
	/* }}} */

	/* {{{ MP_EXT */
	/* 0xd4 */ MP_EXT,   /* MP_INT (8)    */
	/* 0xd5 */ MP_EXT,   /* MP_INT (16)   */
	/* 0xd6 */ MP_EXT,   /* MP_INT (32)   */
	/* 0xd7 */ MP_EXT,   /* MP_INT (64)   */
	/* 0xd8 */ MP_EXT,   /* MP_INT (127)  */
	/* }}} */

	/* {{{ MP_STR */
	/* 0xd9 */ MP_STR,   /* MP_STR(8)  */
	/* 0xda */ MP_STR,   /* MP_STR(16) */
	/* 0xdb */ MP_STR,   /* MP_STR(32) */
	/* }}} */

	/* {{{ MP_ARRAY */
	/* 0xdc */ MP_ARRAY, /* MP_ARRAY(16)  */
	/* 0xdd */ MP_ARRAY, /* MP_ARRAY(32)  */
	/* }}} */

	/* {{{ MP_MAP */
	/* 0xde */ MP_MAP,   /* MP_MAP (16) */
	/* 0xdf */ MP_MAP,   /* MP_MAP (32) */
	/* }}} */

	/* {{{ MP_INT */
	/* 0xe0 */ MP_INT,
	/* 0xe1 */ MP_INT,
	/* 0xe2 */ MP_INT,
	/* 0xe3 */ MP_INT,
	/* 0xe4 */ MP_INT,
	/* 0xe5 */ MP_INT,
	/* 0xe6 */ MP_INT,
	/* 0xe7 */ MP_INT,
	/* 0xe8 */ MP_INT,
	/* 0xe9 */ MP_INT,
	/* 0xea */ MP_INT,
	/* 0xeb */ MP_INT,
	/* 0xec */ MP_INT,
	/* 0xed */ MP_INT,
	/* 0xee */ MP_INT,
	/* 0xef */ MP_INT,
	/* 0xf0 */ MP_INT,
	/* 0xf1 */ MP_INT,
	/* 0xf2 */ MP_INT,
	/* 0xf3 */ MP_INT,
	/* 0xf4 */ MP_INT,
	/* 0xf5 */ MP_INT,
	/* 0xf6 */ MP_INT,
	/* 0xf7 */ MP_INT,
	/* 0xf8 */ MP_INT,
	/* 0xf9 */ MP_INT,
	/* 0xfa */ MP_INT,
	/* 0xfb */ MP_INT,
	/* 0xfc */ MP_INT,
	/* 0xfd */ MP_INT,
	/* 0xfe */ MP_INT,
	/* 0xff */ MP_INT
	/* }}} */
};

/**
 * This lookup table used by mp_next() and mp_check() to determine
 * size of MsgPack element by its first byte.
 * A positive value contains size of the element (excluding the first byte).
 * A negative value means the element is compound (e.g. array or map)
 * of size (-n).
 * MP_HINT_* values used for special cases handled by switch() statement.
 */
const int8_t mp_parser_hint[256] = {
	/* {{{ MP_UINT(fixed) **/
	/* 0x00 */ 0,
	/* 0x01 */ 0,
	/* 0x02 */ 0,
	/* 0x03 */ 0,
	/* 0x04 */ 0,
	/* 0x05 */ 0,
	/* 0x06 */ 0,
	/* 0x07 */ 0,
	/* 0x08 */ 0,
	/* 0x09 */ 0,
	/* 0x0a */ 0,
	/* 0x0b */ 0,
	/* 0x0c */ 0,
	/* 0x0d */ 0,
	/* 0x0e */ 0,
	/* 0x0f */ 0,
	/* 0x10 */ 0,
	/* 0x11 */ 0,
	/* 0x12 */ 0,
	/* 0x13 */ 0,
	/* 0x14 */ 0,
	/* 0x15 */ 0,
	/* 0x16 */ 0,
	/* 0x17 */ 0,
	/* 0x18 */ 0,
	/* 0x19 */ 0,
	/* 0x1a */ 0,
	/* 0x1b */ 0,
	/* 0x1c */ 0,
	/* 0x1d */ 0,
	/* 0x1e */ 0,
	/* 0x1f */ 0,
	/* 0x20 */ 0,
	/* 0x21 */ 0,
	/* 0x22 */ 0,
	/* 0x23 */ 0,
	/* 0x24 */ 0,
	/* 0x25 */ 0,
	/* 0x26 */ 0,
	/* 0x27 */ 0,
	/* 0x28 */ 0,
	/* 0x29 */ 0,
	/* 0x2a */ 0,
	/* 0x2b */ 0,
	/* 0x2c */ 0,
	/* 0x2d */ 0,
	/* 0x2e */ 0,
	/* 0x2f */ 0,
	/* 0x30 */ 0,
	/* 0x31 */ 0,
	/* 0x32 */ 0,
	/* 0x33 */ 0,
	/* 0x34 */ 0,
	/* 0x35 */ 0,
	/* 0x36 */ 0,
	/* 0x37 */ 0,
	/* 0x38 */ 0,
	/* 0x39 */ 0,
	/* 0x3a */ 0,
	/* 0x3b */ 0,
	/* 0x3c */ 0,
	/* 0x3d */ 0,
	/* 0x3e */ 0,
	/* 0x3f */ 0,
	/* 0x40 */ 0,
	/* 0x41 */ 0,
	/* 0x42 */ 0,
	/* 0x43 */ 0,
	/* 0x44 */ 0,
	/* 0x45 */ 0,
	/* 0x46 */ 0,
	/* 0x47 */ 0,
	/* 0x48 */ 0,
	/* 0x49 */ 0,
	/* 0x4a */ 0,
	/* 0x4b */ 0,
	/* 0x4c */ 0,
	/* 0x4d */ 0,
	/* 0x4e */ 0,
	/* 0x4f */ 0,
	/* 0x50 */ 0,
	/* 0x51 */ 0,
	/* 0x52 */ 0,
	/* 0x53 */ 0,
	/* 0x54 */ 0,
	/* 0x55 */ 0,
	/* 0x56 */ 0,
	/* 0x57 */ 0,
	/* 0x58 */ 0,
	/* 0x59 */ 0,
	/* 0x5a */ 0,
	/* 0x5b */ 0,
	/* 0x5c */ 0,
	/* 0x5d */ 0,
	/* 0x5e */ 0,
	/* 0x5f */ 0,
	/* 0x60 */ 0,
	/* 0x61 */ 0,
	/* 0x62 */ 0,
	/* 0x63 */ 0,
	/* 0x64 */ 0,
	/* 0x65 */ 0,
	/* 0x66 */ 0,
	/* 0x67 */ 0,
	/* 0x68 */ 0,
	/* 0x69 */ 0,
	/* 0x6a */ 0,
	/* 0x6b */ 0,
	/* 0x6c */ 0,
	/* 0x6d */ 0,
	/* 0x6e */ 0,
	/* 0x6f */ 0,
	/* 0x70 */ 0,
	/* 0x71 */ 0,
	/* 0x72 */ 0,
	/* 0x73 */ 0,
	/* 0x74 */ 0,
	/* 0x75 */ 0,
	/* 0x76 */ 0,
	/* 0x77 */ 0,
	/* 0x78 */ 0,
	/* 0x79 */ 0,
	/* 0x7a */ 0,
	/* 0x7b */ 0,
	/* 0x7c */ 0,
	/* 0x7d */ 0,
	/* 0x7e */ 0,
	/* 0x7f */ 0,
	/* }}} */

	/* {{{ MP_MAP (fixed) */
	/* 0x80 */  0, /* empty map - just skip one byte */
	/* 0x81 */ -2, /* 2 elements follow */
	/* 0x82 */ -4,
	/* 0x83 */ -6,
	/* 0x84 */ -8,
	/* 0x85 */ -10,
	/* 0x86 */ -12,
	/* 0x87 */ -14,
	/* 0x88 */ -16,
	/* 0x89 */ -18,
	/* 0x8a */ -20,
	/* 0x8b */ -22,
	/* 0x8c */ -24,
	/* 0x8d */ -26,
	/* 0x8e */ -28,
	/* 0x8f */ -30,
	/* }}} */

	/* {{{ MP_ARRAY (fixed) */
	/* 0x90 */  0,  /* empty array - just skip one byte */
	/* 0x91 */ -1,  /* 1 element follows */
	/* 0x92 */ -2,
	/* 0x93 */ -3,
	/* 0x94 */ -4,
	/* 0x95 */ -5,
	/* 0x96 */ -6,
	/* 0x97 */ -7,
	/* 0x98 */ -8,
	/* 0x99 */ -9,
	/* 0x9a */ -10,
	/* 0x9b */ -11,
	/* 0x9c */ -12,
	/* 0x9d */ -13,
	/* 0x9e */ -14,
	/* 0x9f */ -15,
	/* }}} */

	/* {{{ MP_STR (fixed) */
	/* 0xa0 */ 0,
	/* 0xa1 */ 1,
	/* 0xa2 */ 2,
	/* 0xa3 */ 3,
	/* 0xa4 */ 4,
	/* 0xa5 */ 5,
	/* 0xa6 */ 6,
	/* 0xa7 */ 7,
	/* 0xa8 */ 8,
	/* 0xa9 */ 9,
	/* 0xaa */ 10,
	/* 0xab */ 11,
	/* 0xac */ 12,
	/* 0xad */ 13,
	/* 0xae */ 14,
	/* 0xaf */ 15,
	/* 0xb0 */ 16,
	/* 0xb1 */ 17,
	/* 0xb2 */ 18,
	/* 0xb3 */ 19,
	/* 0xb4 */ 20,
	/* 0xb5 */ 21,
	/* 0xb6 */ 22,
	/* 0xb7 */ 23,
	/* 0xb8 */ 24,
	/* 0xb9 */ 25,
	/* 0xba */ 26,
	/* 0xbb */ 27,
	/* 0xbc */ 28,
	/* 0xbd */ 29,
	/* 0xbe */ 30,
	/* 0xbf */ 31,
	/* }}} */

	/* {{{ MP_NIL, MP_BOOL */
	/* 0xc0 */ 0, /* MP_NIL */
	/* 0xc1 */ 0, /* never used */
	/* 0xc2 */ 0, /* MP_BOOL*/
	/* 0xc3 */ 0, /* MP_BOOL*/
	/* }}} */

	/* {{{ MP_BIN */
	/* 0xc4 */ MP_HINT_STR_8,  /* MP_BIN (8)  */
	/* 0xc5 */ MP_HINT_STR_16, /* MP_BIN (16) */
	/* 0xc6 */ MP_HINT_STR_32, /* MP_BIN (32) */
	/* }}} */

	/* {{{ MP_EXT */
	/* 0xc7 */ MP_HINT_EXT_8,    /* MP_EXT (8)  */
	/* 0xc8 */ MP_HINT_EXT_16,   /* MP_EXT (16) */
	/* 0xc9 */ MP_HINT_EXT_32,   /* MP_EXT (32) */
	/* }}} */

	/* {{{ MP_FLOAT, MP_DOUBLE */
	/* 0xca */ sizeof(float),    /* MP_FLOAT */
	/* 0xcb */ sizeof(double),   /* MP_DOUBLE */
	/* }}} */

	/* {{{ MP_UINT */
	/* 0xcc */ sizeof(uint8_t),  /* MP_UINT (8)  */
	/* 0xcd */ sizeof(uint16_t), /* MP_UINT (16) */
	/* 0xce */ sizeof(uint32_t), /* MP_UINT (32) */
	/* 0xcf */ sizeof(uint64_t), /* MP_UINT (64) */
	/* }}} */

	/* {{{ MP_INT */
	/* 0xd0 */ sizeof(uint8_t),  /* MP_INT (8)  */
	/* 0xd1 */ sizeof(uint16_t), /* MP_INT (8)  */
	/* 0xd2 */ sizeof(uint32_t), /* MP_INT (8)  */
	/* 0xd3 */ sizeof(uint64_t), /* MP_INT (8)  */
	/* }}} */

	/* {{{ MP_EXT (fixext) */
	/* 0xd4 */ 2,  /* MP_EXT (fixext 8)   */
	/* 0xd5 */ 3,  /* MP_EXT (fixext 16)  */
	/* 0xd6 */ 5,  /* MP_EXT (fixext 32)  */
	/* 0xd7 */ 9,  /* MP_EXT (fixext 64)  */
	/* 0xd8 */ 17, /* MP_EXT (fixext 128) */
	/* }}} */

	/* {{{ MP_STR */
	/* 0xd9 */ MP_HINT_STR_8,      /* MP_STR (8) */
	/* 0xda */ MP_HINT_STR_16,     /* MP_STR (16) */
	/* 0xdb */ MP_HINT_STR_32,     /* MP_STR (32) */
	/* }}} */

	/* {{{ MP_ARRAY */
	/* 0xdc */ MP_HINT_ARRAY_16,   /* MP_ARRAY (16) */
	/* 0xdd */ MP_HINT_ARRAY_32,   /* MP_ARRAY (32) */
	/* }}} */

	/* {{{ MP_MAP */
	/* 0xde */ MP_HINT_MAP_16,     /* MP_MAP (16) */
	/* 0xdf */ MP_HINT_MAP_32,     /* MP_MAP (32) */
	/* }}} */

	/* {{{ MP_INT (fixed) */
	/* 0xe0 */ 0,
	/* 0xe1 */ 0,
	/* 0xe2 */ 0,
	/* 0xe3 */ 0,
	/* 0xe4 */ 0,
	/* 0xe5 */ 0,
	/* 0xe6 */ 0,
	/* 0xe7 */ 0,
	/* 0xe8 */ 0,
	/* 0xe9 */ 0,
	/* 0xea */ 0,
	/* 0xeb */ 0,
	/* 0xec */ 0,
	/* 0xed */ 0,
	/* 0xee */ 0,
	/* 0xef */ 0,
	/* 0xf0 */ 0,
	/* 0xf1 */ 0,
	/* 0xf2 */ 0,
	/* 0xf3 */ 0,
	/* 0xf4 */ 0,
	/* 0xf5 */ 0,
	/* 0xf6 */ 0,
	/* 0xf7 */ 0,
	/* 0xf8 */ 0,
	/* 0xf9 */ 0,
	/* 0xfa */ 0,
	/* 0xfb */ 0,
	/* 0xfc */ 0,
	/* 0xfd */ 0,
	/* 0xfe */ 0,
	/* 0xff */ 0
	/* }}} */
};

const char *mp_char2escape[128] = {
	"\\u0000", "\\u0001", "\\u0002", "\\u0003",
	"\\u0004", "\\u0005", "\\u0006", "\\u0007",
	"\\b", "\\t", "\\n", "\\u000b",
	"\\f", "\\r", "\\u000e", "\\u000f",
	"\\u0010", "\\u0011", "\\u0012", "\\u0013",
	"\\u0014", "\\u0015", "\\u0016", "\\u0017",
	"\\u0018", "\\u0019", "\\u001a", "\\u001b",
	"\\u001c", "\\u001d", "\\u001e", "\\u001f",
	NULL, NULL, "\\\"", NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, "\\/",
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, "\\\\", NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, "\\u007f"
};
