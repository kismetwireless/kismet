/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __MSGPUCK_BUFFER_H__
#define __MSGPUCK_BUFFER_H__

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "msgpuck.h"

/* C-based buffer for encoding msgpack data via msgpuck; automatically grows the
 * buffer as the msgpuck data grows.  Each growth doubles the size of the buffer
 * to prevent constant resizing.  Buffer growth causes a memcpy; it will be most
 * efficient to allocate as close to a properly sized buffer as possible.
 */

struct msgpuck_buffer {
    char *buffer;
    char *buffer_write;

    size_t buffer_len;
};
typedef struct msgpuck_buffer msgpuck_buffer_t;

/* Create a buffer; return NULL if unable to allocate */
msgpuck_buffer_t *mp_b_create_buffer(size_t initial_sz);

/* Allocated size */
size_t mp_b_sizeof_buffer(msgpuck_buffer_t *buf);

/* Used */
size_t mp_b_used_buffer(msgpuck_buffer_t *buf);

/* Available size */
size_t mp_b_available_buffer(msgpuck_buffer_t *buf);

/* Reference to the internal buffer */
char *mp_b_get_buffer(msgpuck_buffer_t *buf);

/* Free a buffer *and contents* */
void mp_b_free_buffer(msgpuck_buffer_t *buf);

/* Free a buffer *returning contents which are not freed* */
char *mp_b_extract_buffer(msgpuck_buffer_t *buf);

/* Double the size of a buffer and copy the contents to the new array */
int mp_b_zoom_buffer(msgpuck_buffer_t *buf);

/* Duplicates of the msgpuck encode functions, but with length checking */
int mp_b_encode_array(msgpuck_buffer_t *buf, uint32_t size);
int mp_b_encode_map(msgpuck_buffer_t *buf, uint32_t size);
int mp_b_encode_uint(msgpuck_buffer_t *buf, uint32_t size);
int mp_b_encode_int(msgpuck_buffer_t *buf, int32_t in);
int mp_b_encode_float(msgpuck_buffer_t *buf, float in);
int mp_b_encode_double(msgpuck_buffer_t *buf, double in);
int mp_b_encode_str(msgpuck_buffer_t *buf, const char *str, uint32_t size);
int mp_b_encode_bin(msgpuck_buffer_t *buf, const char *str, uint32_t size);

#endif

