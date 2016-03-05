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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "util.h"
#include "ringbuf2.h"

RingbufV2::RingbufV2(size_t in_sz) {
    buffer = new uint8_t[in_sz];

    buffer_sz = in_sz;
    start_pos = 0;
    length = 0;

    pthread_mutex_init(&buffer_locker, NULL);
}

RingbufV2::~RingbufV2() {
    {
        local_locker lock(&buffer_locker);
        delete[] buffer;
    }

    pthread_mutex_destroy(&buffer_locker);
}

void RingbufV2::clear() {
    local_locker lock(&buffer_locker);
    start_pos = 0;
    length = 0;
}

size_t RingbufV2::size() {
    local_locker lock(&buffer_locker);
    return size_nl();
}

size_t RingbufV2::used() {
    local_locker lock(&buffer_locker);
    return used_nl();
}

size_t RingbufV2::available() {
    local_locker lock(&buffer_locker);
    return available_nl();
}

size_t RingbufV2::size_nl() {
    return buffer_sz;
}

size_t RingbufV2::used_nl() {
    return length;
}

size_t RingbufV2::available_nl() {
    return buffer_sz - length;
}

size_t RingbufV2::write(void *data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    size_t copy_start;

    if (available_nl() < in_sz)
        return 0;

    // Figure out if we can write a contiguous block
    copy_start = 
        (start_pos + length) % buffer_sz;

    if (copy_start + in_sz < buffer_sz) {
        memcpy(buffer + copy_start, data, in_sz);
        length += in_sz;

        return in_sz;
    } else {
        // Compute the two chunks
        size_t chunk_a = buffer_sz - copy_start;
        size_t chunk_b = in_sz - chunk_a;

        memcpy(buffer + start_pos + length, data, chunk_a);
        memcpy(buffer, (uint8_t *) data + chunk_a, chunk_b);

        /* Increase the length of the buffer */
        length += in_sz;

        return in_sz;
    }

    return 0;
}

size_t RingbufV2::read(void *ptr, size_t in_sz) {
    local_locker lock(&buffer_locker);

    // No matter what is requested we can't read more than we have
    size_t opsize = used_nl();

    if (opsize == 0)
        return 0;

    if (opsize > in_sz)
        opsize = in_sz;

    // Can we read contiguously?
    if (start_pos + opsize < buffer_sz) {
        if (ptr != NULL)
            memcpy(ptr, buffer + start_pos, opsize);

        start_pos += opsize;
        length -= opsize;

        return opsize;
    } else {
        // Split into chunks
        size_t chunk_a = buffer_sz - start_pos;
        size_t chunk_b = opsize - chunk_a;

        if (ptr != NULL) {
            memcpy(ptr, buffer + start_pos, chunk_a);
            memcpy((uint8_t *) ptr + chunk_a, buffer, chunk_b);
        }

        // Loop the ring buffer and mark read
        start_pos = chunk_b;
        length -= opsize;

        return opsize;
    }

    return 0;
}

size_t RingbufV2::peek(void *ptr, size_t in_sz) {
    local_locker lock(&buffer_locker);

    // No matter what is requested we can't read more than we have
    size_t opsize = used_nl();

    if (opsize == 0)
        return 0;

    if (opsize > in_sz)
        opsize = in_sz;

    // Can we read contiguously?
    if (start_pos + opsize < buffer_sz) {
        memcpy(ptr, buffer + start_pos, opsize);

        return opsize;
    } else {
        // Split into chunks
        size_t chunk_a = buffer_sz - start_pos;
        size_t chunk_b = opsize - chunk_a;

        memcpy(ptr, buffer + start_pos, chunk_a);
        memcpy((uint8_t *) ptr + chunk_a, buffer, chunk_b);

        return opsize;
    }

    return 0;
}

