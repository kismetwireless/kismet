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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "util.h"
#include "ringbuf2.h"

ringbuf_v2::ringbuf_v2(size_t in_sz) :
    buffer_sz {in_sz},
    start_pos {0},
    length {0},
    free_peek {false} {

    // Initialize the buffer as a fixed object
    buffer = new unsigned char[in_sz];
    memset(buffer, 0xAA, in_sz);
}

ringbuf_v2::~ringbuf_v2() {
    delete[] buffer;
}

void ringbuf_v2::clear_impl() {
    start_pos = 0;
    length = 0;
}

ssize_t ringbuf_v2::size_impl() {
    return buffer_sz;
}

size_t ringbuf_v2::used_impl() {
    return length;
}

ssize_t ringbuf_v2::available_impl() {
    return buffer_sz - length;
}

ssize_t ringbuf_v2::peek_impl(unsigned char **ptr, size_t in_sz) {
    // Always reserve first since we may blindly peek_free later
    peek_reserved = true;
    // Set free manually later if necessary
    free_peek = false;

    // If we can't peek this many bytes, just error out
    if (used() < in_sz) {
        return -1;
    }

    if (start_pos + in_sz < buffer_sz) {
        // Can we read contiguously? if so we can do a zero-copy peek
        free_peek = false;
        *ptr = buffer + start_pos;
    } else {
        // We have to allocate
        free_peek = true;
        *ptr = new unsigned char[in_sz];

        // Split into chunks
        size_t chunk_a = buffer_sz - start_pos;
        size_t chunk_b = in_sz - chunk_a;

        memcpy(*ptr, buffer + start_pos, chunk_a);
        memcpy(*ptr + chunk_a, buffer, chunk_b);
    }

    return in_sz;
}

ssize_t ringbuf_v2::zero_copy_peek_impl(unsigned char **ptr, size_t in_sz) {
    // Always reserve first since we might blindly peek_free later
    peek_reserved = true;
    free_peek = false;

    // No matter what is requested we can't read more than we have
    size_t opsize = std::min(in_sz, used());

    if (opsize == 0)
        return 0;

    // Trim to only the part of the buffer we can point to directly
    if (start_pos + opsize > buffer_sz) {
        opsize = buffer_sz - start_pos;
    }

    *ptr = (buffer + start_pos);
    return opsize;
}

void ringbuf_v2::peek_free_impl(unsigned char *in_data) {
    if (free_peek) {
        delete[] in_data;
    }
}

size_t ringbuf_v2::consume_impl(size_t in_sz) {
    // No matter what is requested we can't read more than we have
    size_t opsize = std::min(in_sz, used());

    if (opsize > length) {
        throw std::runtime_error("ringbuf v2 consuming more than we have?");
    }

    // Can we read contiguously?
    if (start_pos + opsize < buffer_sz) {
        start_pos += opsize;
        length -= opsize;

        return opsize;
    } else {
        // Loop the ring buffer and mark read
        start_pos = (start_pos + opsize) % buffer_sz;
        length -= opsize;

        return opsize;
    }

    return 0;
}

ssize_t ringbuf_v2::write_impl(unsigned char *data, size_t in_sz) {
    size_t copy_start;

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;

    if (copy_start + in_sz < buffer_sz) {
        if (data != NULL)
            memcpy(buffer + copy_start, data, in_sz);
        length += in_sz;

        return in_sz;
    } else {
        // Compute the two chunks
        size_t chunk_a = buffer_sz - copy_start;
        size_t chunk_b = in_sz - chunk_a;

        if (data != NULL) {
            memcpy(buffer + start_pos + length, data, chunk_a);
            memcpy(buffer, (unsigned char *) data + chunk_a, chunk_b);
        }

        /* Increase the length of the buffer */
        length += in_sz;

        return in_sz;
    }

    return 0;
}

ssize_t ringbuf_v2::reserve_impl(unsigned char **data, size_t in_sz) {
    size_t copy_start;

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;

    if (copy_start + in_sz < buffer_sz) {
        free_commit = false;
        *data = buffer + copy_start;

        return in_sz;
    } else {
        free_commit = true;
        *data = new unsigned char[in_sz];

        return in_sz;
    }

}

ssize_t ringbuf_v2::zero_copy_reserve_impl(unsigned char **data, size_t in_sz) {
    write_reserved = true;
    free_commit = false;

    size_t copy_start;
    copy_start = (start_pos + length) % buffer_sz;

    // Always return at the start of the buffer
    *data = buffer + copy_start;

    // If we're requesting a block contiguous with the buffer, return the
    // requested size, otherwise return the size of the remaining contiguous
    // space
    if (copy_start + in_sz < buffer_sz) {
        return in_sz;
    } else {
        return (buffer_sz - copy_start);
    }

}

