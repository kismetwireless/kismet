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
    buffer = new unsigned char[in_sz];

    buffer_sz = in_sz;
    start_pos = 0;
    length = 0;
}

RingbufV2::~RingbufV2() {
    local_locker lock(&buffer_locker);
    
    delete[] buffer;
}

void RingbufV2::clear() {
    local_locker lock(&buffer_locker);
    start_pos = 0;
    length = 0;
}

ssize_t RingbufV2::size() {
    local_locker lock(&buffer_locker);
    return buffer_sz;
}

size_t RingbufV2::used() {
    local_locker lock(&buffer_locker);
    return length;
}

ssize_t RingbufV2::available() {
    local_locker lock(&buffer_locker);
    return buffer_sz - length;
}

ssize_t RingbufV2::peek(unsigned char **ptr, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (peek_reserved) {
        throw std::runtime_error("ringbuf v2 peek already locked");
    }

    // No matter what is requested we can't read more than we have
    size_t opsize = used();

    if (opsize == 0)
        return 0;

    if (opsize > in_sz)
        opsize = in_sz;

    // For now we always copy the buffer for peek
    peek_reserved = true;

    if (start_pos + opsize < buffer_sz) {
        // Can we read contiguously? if so we can do a zero-copy peek
        free_peek = false;
        *ptr = buffer + start_pos;
        return opsize;
    } else {
        // We have to allocate
        free_peek = true;
        *ptr = new unsigned char[opsize];

        // Split into chunks
        size_t chunk_a = buffer_sz - start_pos;
        size_t chunk_b = opsize - chunk_a;

        memcpy(*ptr, buffer + start_pos, chunk_a);
        memcpy((unsigned char *) *ptr + chunk_a, buffer, chunk_b);

        return opsize;
    }
}

ssize_t RingbufV2::zero_copy_peek(unsigned char **ptr, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (peek_reserved) {
        throw std::runtime_error("ringbuf v2 peek already locked");
    }

    // No matter what is requested we can't read more than we have
    size_t opsize = used();

    if (opsize == 0)
        return 0;

    if (opsize > in_sz)
        opsize = in_sz;

    // Trim to only the part of the buffer we can point to directly
    if (start_pos + opsize > buffer_sz) {
        opsize = buffer_sz - start_pos;
    }

    peek_reserved = true;
    free_peek = false;

    *ptr = (buffer + start_pos);
    return opsize;
}

void RingbufV2::peek_free(unsigned char *in_data) {
    local_locker lock(&buffer_locker);

    if (!peek_reserved) {
        throw std::runtime_error("ringbuf v2 peek_free on unlocked buffer");
    }

    if (free_peek) {
        delete[] in_data;
    }

    peek_reserved = false;
    free_peek = false;
}

size_t RingbufV2::consume(size_t in_sz) {
    local_locker lock(&buffer_locker);

    // No matter what is requested we can't read more than we have
    size_t opsize = used();

    if (opsize == 0)
        return 0;

    if (opsize > in_sz)
        opsize = in_sz;

    // Can we read contiguously?
    if (start_pos + opsize < buffer_sz) {
        start_pos += opsize;
        length -= opsize;

        return opsize;
    } else {
        // Split into chunks
        size_t chunk_a = buffer_sz - start_pos;
        size_t chunk_b = opsize - chunk_a;

        // Loop the ring buffer and mark read
        start_pos = chunk_b;
        length -= opsize;

        return opsize;
    }

    return 0;
}

ssize_t RingbufV2::write(unsigned char *data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    size_t copy_start;

    if (available() >= 0 && (size_t) available() < in_sz)
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
        memcpy(buffer, (unsigned char *) data + chunk_a, chunk_b);

        /* Increase the length of the buffer */
        length += in_sz;

        return in_sz;
    }

    return 0;
}

ssize_t RingbufV2::reserve(unsigned char **data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    size_t copy_start;

    if (available() >= 0 && (size_t) available() < in_sz)
        return 0;

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;

    // For now we always copy the buffer for peek
    write_reserved = true;

    if (copy_start + in_sz < buffer_sz) {
        // If we're entirely w/in one loop of the buffer we can return a zero-copy
        // pointer
        free_commit = false;
        *data = buffer + copy_start;

        return in_sz;
    } else {
        // We have to allocate a buffer because we span the end of the ringbuf
        free_commit = true;
        *data = new unsigned char[in_sz];
        return in_sz;
    }
}

bool RingbufV2::commit(unsigned char *data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (!write_reserved) {
        throw std::runtime_error("ringbuf v2 no pending commit");
    }

    // Unlock the write state
    write_reserved = false;

    // If we have allocated an interstitial buffer, we need copy the data over and delete
    // the temp buffer
    if (free_commit) {
        free_commit = false;

        ssize_t written = write(data, in_sz);

        delete[] data;

        if (written < 0)
            return false;

        return (size_t) written == in_sz;
    }

    // If we don't need to free our commit buffer, the data is already written 
    // in and we're done

    return true;
}


