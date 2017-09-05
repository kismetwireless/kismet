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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "msgpuck_buffer.h"

/* Create a buffer; return NULL if unable to allocate */
msgpuck_buffer_t *mp_b_create_buffer(size_t initial_sz) {
    msgpuck_buffer_t *ret = (msgpuck_buffer_t *) malloc(sizeof(msgpuck_buffer_t));

    if (ret == NULL)
        return NULL;

    ret->buffer = (char *) malloc(initial_sz);

    if (ret->buffer == NULL) {
        free(ret);
        return NULL;
    }

    ret->buffer_write = ret->buffer;
    ret->buffer_len = initial_sz;

    return ret;
}

/* Allocated size */
size_t mp_b_sizeof_buffer(msgpuck_buffer_t *buf) {
    return buf->buffer_len;
}

/* Reference to buffer */
char *mp_b_get_buffer(msgpuck_buffer_t *buf) {
    return buf->buffer;
}

/* Used */
size_t mp_b_used_buffer(msgpuck_buffer_t *buf) {
    return (buf->buffer_write - buf->buffer);
}

/* Available size */
size_t mp_b_available_buffer(msgpuck_buffer_t *buf) {
    return buf->buffer_len - (buf->buffer_write - buf->buffer);
}

/* Free a buffer *and contents* */
void mp_b_free_buffer(msgpuck_buffer_t *buf) {
    free(buf->buffer);
    free(buf);
}

/* Free a buffer *returning contents which are not freed* */
char *mp_b_extract_buffer(msgpuck_buffer_t *buf) {
    char *ret = buf->buffer;
    free(buf);
    return ret;
}

/* Double the size of a buffer and copy the contents to the new array */
int mp_b_zoom_buffer(msgpuck_buffer_t *buf) {
    /* Double the size of the buffer so we don't keep doing micro-allocs and copies
     * If our buffer is somehow 0, make it a semi-arbitrary 32 bytes (and then 
     * double it) because otherwise we'll never grow */
    size_t bufsz = buf->buffer_len;

    if (bufsz == 0)
        bufsz = 32;

    char *newbuf = (char *) malloc(bufsz * 2);

    if (newbuf == NULL) {
        return -1;
    }

    size_t sz = mp_b_sizeof_buffer(buf);

    // Copy
    memcpy(newbuf, buf->buffer, sz);

    // Swap
    free(buf->buffer);
    buf->buffer = newbuf;

    // Advance the write pointer
    buf->buffer_write = &(buf->buffer[sz]);

    // Set the new len
    buf->buffer_len = (bufsz * 2);

    return 1;
}

/* Duplicates of the msgpuck encode functions, but with length checking */

int mp_b_encode_array(msgpuck_buffer_t *buf, unsigned int size) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_array(size)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_array(buf->buffer_write, size);
    return 1;
}

int mp_b_encode_map(msgpuck_buffer_t *buf, unsigned int size) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_map(size)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_map(buf->buffer_write, size);
    return 1;
}

int mp_b_encode_uint(msgpuck_buffer_t *buf, unsigned int in) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_uint(in)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_uint(buf->buffer_write, in);
    return 1;
}

int mp_b_encode_int(msgpuck_buffer_t *buf, int in ) {
    /* Msgpuck INSISTS that positive ints be encoded as unsigned.  I don't
     * know why. */
    if (in < 0) {
        if (mp_b_available_buffer(buf) <= mp_sizeof_int(in)) 
            if (mp_b_zoom_buffer(buf) < 0)
                return -1;
        buf->buffer_write = mp_encode_int(buf->buffer_write, in);
    } else {
        if (mp_b_available_buffer(buf) <= mp_sizeof_uint(in)) 
            if (mp_b_zoom_buffer(buf) < 0)
                return -1;
        buf->buffer_write = mp_encode_uint(buf->buffer_write, in);
    }
    return 1;
}

int mp_b_encode_float(msgpuck_buffer_t *buf, float in) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_float(in)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_float(buf->buffer_write, in);
    return 1;
}

int mp_b_encode_double(msgpuck_buffer_t *buf, double in) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_double(in)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_double(buf->buffer_write, in);
    return 1;
}

int mp_b_encode_str(msgpuck_buffer_t *buf, const char *str, uint32_t size) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_str(size)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_str(buf->buffer_write, str, size);
    return 1;
}

int mp_b_encode_bin(msgpuck_buffer_t *buf, const char *str, uint32_t size) {
    if (mp_b_available_buffer(buf) <= mp_sizeof_bin(size)) 
        if (mp_b_zoom_buffer(buf) < 0)
            return -1;
    buf->buffer_write = mp_encode_bin(buf->buffer_write, str, size);
    return 1;
}

