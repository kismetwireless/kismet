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

/* An extremely basic ring buffer implemented in pure C; for use with datasource 
 * implementations in C */

#ifndef __RINGBUF_C_H__
#define __RINGBUF_C_H__

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

struct kis_simple_ringbuf {
    uint8_t *buffer;
    size_t buffer_sz;
    size_t start_pos; /* Where reading starts from */
    size_t length; /* Amount of data in the buffer */
};
typedef struct kis_simple_ringbuf kis_simple_ringbuf_t;

/* Allocate a ring buffer
 *
 * Returns NULL if allocation failed
 */
kis_simple_ringbuf_t *kis_simple_ringbuf_create(size_t size);

/* Destroy a ring buffer
 */
void kis_simple_ringbuf_free(kis_simple_ringbuf_t *ringbuf);

/* Clear ring buffer
 */
void kis_simple_ringbuf_clear(kis_simple_ringbuf_t *ringbuf);

/* Get available space
 */
size_t kis_simple_ringbuf_available(kis_simple_ringbuf_t *ringbuf);

/* Get used space
 */
size_t kis_simple_ringbuf_used(kis_simple_ringbuf_t *ringbuf);

/* Append data
 *
 * Returns amount written
 */
size_t kis_simple_ringbuf_write(kis_simple_ringbuf_t *ringbuf, 
        void *data, size_t length);

/* Copies data into provided buffer.  Advances ringbuf, clearing consumed data.
 *
 * If requested amount is not available, reads amount available and returns.
 *
 * Returns amount copied
 */
size_t kis_simple_ringbuf_read(kis_simple_ringbuf_t *ringbuf, void *ptr, size_t size);

/* Peeks at data by copying into provided buffer.  Does NOT advance ringbuf
 * or consume data.
 *
 * If requested amount of data is not available, peeks amount available and 
 * returns;
 *
 * Returns amount copied
 */
size_t kis_simple_ringbuf_peek(kis_simple_ringbuf_t *ringbuf, void *ptr, size_t size);

#endif

