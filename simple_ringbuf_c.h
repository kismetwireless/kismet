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

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

struct kis_simple_ringbuf {
    uint8_t *buffer;
    size_t buffer_sz;
    size_t start_pos; /* Where reading starts from */
    size_t length; /* Amount of data in the buffer */

    int mid_peek, mid_commit; /* Are we in a peek or reserve? */
    int free_peek, free_commit; /* Do we need to free the peek or reserved buffers */

#ifdef USE_MMAP_RBUF
    void *mmap_region0;
    void *mmap_region1;

    int mmap_fd;
#endif
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

/* Get total size
 */
size_t kis_simple_ringbuf_size(kis_simple_ringbuf_t *ringbuf);

/* Append data
 *
 * Returns amount written
 */
size_t kis_simple_ringbuf_write(kis_simple_ringbuf_t *ringbuf, 
        void *data, size_t length);

/* Reserve a writeable chunk, striving to make it a zero-copy operation.  Only
 * one chunk may be reserved at a time.  A reserved chunk must be written 
 * with kis_simple_ringbuf_commit or discard with kis_simple_ringbuf_reserve_free
 *
 * Returns amount available.  Returns 0 if that amount cannot be reserved because
 * the buffer is full.
 */
size_t kis_simple_ringbuf_reserve(kis_simple_ringbuf_t *ringbuf, void **data, size_t size);

/* Reserve a writeable chunk, ensuring it is a zero-copy operation.  Only
 * one chunk may be reserved at a time.  A reserved chunk must be written 
 * with kis_simple_ringbuf_commit or discard with kis_simple_ringbuf_reserve_free
 *
 * Returns the contiguous zero-copy size available.
 */
size_t kis_simple_ringbuf_reserve_zcopy(kis_simple_ringbuf_t *ringbuf, void **data, size_t size);

/* Commit a previously reserved chunk.  Commits the specified number of bytes.
 *
 * Returns the amount committed.
 */
size_t kis_simple_ringbuf_commit(kis_simple_ringbuf_t *ringbuf, void *data, size_t size);

/* Free a previously reserved chunk without committing it.
 */
void kis_simple_ringbuf_reserve_free(kis_simple_ringbuf_t *ringbuf, void *data);


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

/* Peeks at data, using a zero-copy method if possible.  Does NOT advance ringbuf
 * or consume data.
 *
 * Peeked data MUST BE 'returned' via kis_simple_ringbuf_peek_free.
 *
 * Returns amount peeked.
 */
size_t kis_simple_ringbuf_peek_zc(kis_simple_ringbuf_t *ringbuf, void **ptr, size_t size);

/* Frees peeked zc data.  Must be called after peeking.
 *
 */
void kis_simple_ringbuf_peek_free(kis_simple_ringbuf_t *ringbuf, void *ptr);

/* Search for a byte in the buffer, return the offset; most useful for finding newlines 
 * in a buffer*/
ssize_t kis_simple_ringbuf_search_byte(kis_simple_ringbuf_t *ringbuf, unsigned char b);

#endif

