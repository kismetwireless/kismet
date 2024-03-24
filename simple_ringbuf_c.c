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

/* An extremely basic ring buffer implemented as a complete header in pure C; 
 * for use with datasource implementations in C */

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>

#ifdef USE_MMAP_RBUF
#include <sys/mman.h>
#include <sys/types.h>
#endif

#include "simple_ringbuf_c.h"

#ifdef USE_MMAP_RBUF
#define __NR_memfd_create 319
int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}
#endif

/* Allocate a ring buffer
 *
 * Returns NULL if allocation failed
 */
kis_simple_ringbuf_t *kis_simple_ringbuf_create(size_t size) {
    kis_simple_ringbuf_t *rb;
#ifdef USE_MMAP_RBUF
    char tmpfname[256];
#endif

    rb = (kis_simple_ringbuf_t *) malloc(sizeof(kis_simple_ringbuf_t));

    if (rb == NULL)
        return NULL;

#ifdef USE_MMAP_RBUF
    /* Initialize the buffer as an anonymous FD and dual-map it into RAM; we may
     * need to massage the buffer size to match the system page size */

    long page_sz = sysconf(_SC_PAGESIZE);

    /* We need to mmap a multiple of the page size */
    if (size % page_sz) {
        if (size < (size_t) page_sz) {
            /* Zoom desired size to page size if less */
            size = page_sz;
        } else {
            /* Map a multiple which is larger than the current page sz */
            size = page_sz * ceil((double) size / (double) page_sz);
        }
    }

    snprintf(tmpfname, 256, "ringbuf%p", (void *) rb);
    rb->mmap_fd = memfd_create(tmpfname, 0);

    ftruncate(rb->mmap_fd, size);

    /* Make the mmap buffer */
    rb->buffer = (unsigned char *) mmap(NULL, size * 2, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    /* Double-map the buffer into the memory space */
    rb->mmap_region0 = mmap(rb->buffer, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, rb->mmap_fd, 0);

    if (rb->mmap_region0 == MAP_FAILED) {
        fprintf(stderr, "FATAL:  Failed to mmap ringbuf region0: %s\n", strerror(errno));
        free(rb);
        return NULL;
    }

    rb->mmap_region1 = mmap(rb->buffer + size, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, rb->mmap_fd, 0);

    if (rb->mmap_region1 == MAP_FAILED) {
        fprintf(stderr, "FATAL:  Failed to mmap ringbuf region1: %s\n", strerror(errno));
        free(rb);
        return NULL;
    }

#else
    rb->buffer = (uint8_t *) malloc(size);

    if (rb->buffer == NULL) {
        free(rb);
        return NULL;
    }
#endif

    rb->buffer_sz = size;
    rb->start_pos = 0;
    rb->length = 0;
    rb->mid_peek = 0;
    rb->mid_commit = 0;
    rb->free_peek = 0;
    rb->free_commit = 0;

    return rb;
}

/* Destroy a ring buffer
 */
void kis_simple_ringbuf_free(kis_simple_ringbuf_t *ringbuf) {
#ifdef USE_MMAP_RBUF
    munmap(ringbuf->mmap_region1, ringbuf->buffer_sz);
    munmap(ringbuf->mmap_region0, ringbuf->buffer_sz);
    munmap(ringbuf->buffer, ringbuf->buffer_sz * 2);
    close(ringbuf->mmap_fd);
#else
    free(ringbuf->buffer);
#endif
    free(ringbuf);
}

/* Clear ring buffer
 */
void kis_simple_ringbuf_clear(kis_simple_ringbuf_t *ringbuf) {
    ringbuf->start_pos = 0;
    ringbuf->length = 0;
}

/* Get available space
 */
size_t kis_simple_ringbuf_available(kis_simple_ringbuf_t *ringbuf) {
    return ringbuf->buffer_sz - ringbuf->length;
}

/* Get used space
 */
size_t kis_simple_ringbuf_used(kis_simple_ringbuf_t *ringbuf) {
    return ringbuf->length;
}

/* Get total space
 * */
size_t kis_simple_ringbuf_size(kis_simple_ringbuf_t *ringbuf) {
    return ringbuf->buffer_sz;
}

/* Append data
 *
 * Returns amount written
 */
size_t kis_simple_ringbuf_write(kis_simple_ringbuf_t *ringbuf, 
        void *data, size_t length) {
    size_t copy_start;

    if (kis_simple_ringbuf_available(ringbuf) < length)
        return 0;

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

#ifdef USE_MMAP_RBUF
    memcpy(ringbuf->buffer + copy_start, data, length);
    ringbuf->length += length;

    return length;
#else
    /* Does the write op fit w/out looping? */
    if (copy_start + length < ringbuf->buffer_sz) {
        memcpy(ringbuf->buffer + copy_start, data, length);
        ringbuf->length += length;

        return length;
    } else {
        /* We have to split up, figure out the length of the two chunks */
        size_t chunk_a = ringbuf->buffer_sz - copy_start;
        size_t chunk_b = length - chunk_a;

        memcpy(ringbuf->buffer + ringbuf->start_pos + ringbuf->length, data, chunk_a);
        memcpy(ringbuf->buffer, (uint8_t *) data + chunk_a, chunk_b);

        /* Increase the length of the buffer */
        ringbuf->length += length;

        return length;
    }
#endif

    return 0;
}

size_t kis_simple_ringbuf_reserve(kis_simple_ringbuf_t *ringbuf, void **data, size_t size) {
    size_t copy_start;

    if (ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t mid-commit when reserve called\n");
        return 0;
    }

    if (kis_simple_ringbuf_available(ringbuf) < size) {
        return 0;
    }

    ringbuf->mid_commit = 1;

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

#ifdef USE_MMAP_RBUF
    ringbuf->mid_commit = 1;
    ringbuf->free_commit = 0;
    *data = ringbuf->buffer + copy_start;
    return size;
#else
    /* Does the write op fit w/out looping? */
    if (copy_start + size <= ringbuf->buffer_sz) {
        ringbuf->free_commit = 0;
        *data = ringbuf->buffer + copy_start;
        return size;
    } else {
        *data = malloc(size);

        if (*data == NULL) {
            fprintf(stderr, "ERROR:  Could not allocate split-op sz write buffer\n");
            return 0;
        }

        ringbuf->free_commit = 1;

        return size;
    }
#endif

    return 0;
}

size_t kis_simple_ringbuf_reserve_zcopy(kis_simple_ringbuf_t *ringbuf, void **data, size_t size) {
    size_t copy_start;

    if (ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t mid-commit when reserve called\n");
        return 0;
    }

    if (kis_simple_ringbuf_available(ringbuf) < size) {
        return 0;
    }

    ringbuf->mid_commit = 1;

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

#ifdef USE_MMAP_RBUF
    ringbuf->mid_commit = 1;
    ringbuf->free_commit = 0;
    *data = ringbuf->buffer + copy_start;
    return size;
#else
    ringbuf->free_commit = 0;
    *data = ringbuf->buffer + copy_start;

    /* Does the write op fit w/out looping? */
    if (copy_start + size <= ringbuf->buffer_sz) {
        return size;
    } else {
        return (ringbuf->buffer_sz - copy_start);
    }
#endif

    return 0;
}

size_t kis_simple_ringbuf_commit(kis_simple_ringbuf_t *ringbuf, void *data, size_t size) {
    if (!ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t not in a commit when commit called\n");
        return 0;
    }

#ifdef USE_MMAP_RBUF
    ringbuf->mid_commit = 0;
    ringbuf->length += size;
    return size;
#else
    size_t copy_start;

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

    ringbuf->mid_commit = 0;

    if (!ringbuf->free_commit) {
        ringbuf->length += size;
        return size;
    } else {
        /* Does the write op fit w/out looping? */
        if (copy_start + size <= ringbuf->buffer_sz) {
            memcpy(ringbuf->buffer + copy_start, data, size);
            ringbuf->length += size;

            return size;
        } else {
            /* We have to split up, figure out the length of the two chunks */
            size_t chunk_a = ringbuf->buffer_sz - copy_start;
            size_t chunk_b = size - chunk_a;

            memcpy(ringbuf->buffer + ringbuf->start_pos + ringbuf->length, data, chunk_a);
            memcpy(ringbuf->buffer, (uint8_t *) data + chunk_a, chunk_b);

            /* Increase the length of the buffer */
            ringbuf->length += size;

            return size;
        }
    }
#endif

    return 0;
}

/* Free a previously reserved chunk without committing it.
 */
void kis_simple_ringbuf_reserve_free(kis_simple_ringbuf_t *ringbuf, void *data) {
    if (!ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t not in a commit when commit_reserve_free called\n");
    }

    if (ringbuf->free_commit)
        free(data);

    ringbuf->mid_commit = 0;
}

/* Copies data into provided buffer.  Advances ringbuf, clearing consumed data.
 *
 * If requested amount is not available, reads amount available and returns.
 *
 * Returns amount copied
 */
size_t kis_simple_ringbuf_read(kis_simple_ringbuf_t *ringbuf, void *ptr, 
        size_t size) {
    /* Start with how much we have available - no matter what was
     * requested, we can't read more than this */
    size_t opsize = kis_simple_ringbuf_used(ringbuf);

    if (opsize == 0)
        return 0;

    /* Only read the amount we requested, if more is available */
    if (opsize > size)
        opsize = size;

#ifdef USE_MMAP_RBUF
    if (ptr != NULL)
        memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, opsize);

    ringbuf->start_pos = (ringbuf->start_pos + opsize) % ringbuf->buffer_sz;
    ringbuf->length -= opsize;

    return opsize;
#else
    /* Simple contiguous read */
    if (ringbuf->start_pos + opsize <= ringbuf->buffer_sz) {
        if (ptr != NULL)
            memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, opsize);
        ringbuf->start_pos += opsize;
        ringbuf->length -= opsize;
        return opsize;
    } else {
        /* First chunk, start to end of buffer */
        size_t chunk_a = ringbuf->buffer_sz - ringbuf->start_pos;
        /* Second chunk, 0 to remaining data */
        size_t chunk_b = opsize - chunk_a;

        if (ptr != NULL) {
            memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, chunk_a);
            memcpy((uint8_t *) ptr + chunk_a, ringbuf->buffer, chunk_b);
        }

        /* Fastforward around the ring to where we finished reading */
        ringbuf->start_pos = chunk_b;
        ringbuf->length -= opsize;

        return opsize;
    }
#endif

    return 0;
}

/* Peeks at data by copying into provided buffer.  Does NOT advance ringbuf
 * or consume data.
 *
 * If requested amount of data is not available, peeks amount available and 
 * returns;
 *
 * Returns amount copied
 */
size_t kis_simple_ringbuf_peek(kis_simple_ringbuf_t *ringbuf, void *ptr, 
        size_t size) {
    /* Start with how much we have available - no matter what was
     * requested, we can't read more than this */
    size_t opsize = kis_simple_ringbuf_used(ringbuf);

    if (opsize == 0)
        return 0;

    /* Only read the amount we requested, if more is available */
    if (opsize > size)
        opsize = size;

#ifdef USE_MMAP_RBUF
    memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, opsize);
    return opsize;
#else
    /* Simple contiguous read */
    if (ringbuf->start_pos + opsize <= ringbuf->buffer_sz) {
        memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, opsize);
        return opsize;
    } else {
        /* First chunk, start to end of buffer */
        size_t chunk_a = ringbuf->buffer_sz - ringbuf->start_pos;
        /* Second chunk, 0 to remaining data */
        size_t chunk_b = opsize - chunk_a;

        memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, chunk_a);
        memcpy((uint8_t *) ptr + chunk_a, ringbuf->buffer, chunk_b);

        return opsize;
    }
#endif

    return 0;
}

size_t kis_simple_ringbuf_peek_zc(kis_simple_ringbuf_t *ringbuf, void **ptr, size_t size) {
    /* Start with how much we have available - no matter what was
     * requested, we can't read more than this */
    size_t opsize = kis_simple_ringbuf_used(ringbuf);

    if (ringbuf->mid_peek) {
        fprintf(stderr, "ERROR: simple_ringbuf_peek_zc mid-peek already\n");
        return 0;
    }
    
    ringbuf->mid_peek = 1;

    if (opsize == 0)
        return 0;

    if (size == 0)
        size = kis_simple_ringbuf_size(ringbuf);

    /* Only read the amount we requested, if more is available */
    if (opsize > size)
        opsize = size;

#ifdef USE_MMAP_RBUF
    ringbuf->mid_peek = 1;
    ringbuf->free_peek = 0;
    *ptr = ringbuf->buffer + ringbuf->start_pos;
    return opsize;
#else
    /* Simple contiguous read */
    if (ringbuf->start_pos + opsize <= ringbuf->buffer_sz) {
        ringbuf->free_peek = 0;
        *ptr = ringbuf->buffer + ringbuf->start_pos;
        return opsize;
    } else {
        /* First chunk, start to end of buffer */
        size_t chunk_a = ringbuf->buffer_sz - ringbuf->start_pos;
        /* Second chunk, 0 to remaining data */
        size_t chunk_b = opsize - chunk_a;

        *ptr = malloc(opsize);

        if (*ptr == NULL) {
            fprintf(stderr, "ERROR: simple_ringbuf_peek_zc could not allocate buffer for split peek\n");
            return 0;
        }

        ringbuf->free_peek = 1;

        memcpy(*ptr, ringbuf->buffer + ringbuf->start_pos, chunk_a);
        memcpy((uint8_t *) *ptr + chunk_a, ringbuf->buffer, chunk_b);

        return opsize;
    }
#endif

    return 0;
}

void kis_simple_ringbuf_peek_free(kis_simple_ringbuf_t *ringbuf, void *ptr) {
    if (!ringbuf->mid_peek) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_peek_free called with no peeked data\n");
        return;
    }

    if (ringbuf->free_peek)
        free(ptr);

    ringbuf->mid_peek = 0;
}

ssize_t kis_simple_ringbuf_search_byte(kis_simple_ringbuf_t *ringbuf, unsigned char b) {
    size_t pos = 0;

    for (pos = 0; pos < ringbuf->length; pos++) {
        if (ringbuf->buffer[((ringbuf->start_pos + pos) % ringbuf->buffer_sz)] == b) {
            return pos;
        }
    }

    return -1;
}
