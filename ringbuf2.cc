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

void ringbuf_v2::clear() {
    local_locker lock(&write_mutex);
    start_pos = 0;
    length = 0;
}

ssize_t ringbuf_v2::size() {
    return buffer_sz;
}

size_t ringbuf_v2::used() {
    return length;
}

ssize_t ringbuf_v2::available() {
    return buffer_sz - length;
}

ssize_t ringbuf_v2::peek(unsigned char **ptr, size_t in_sz) {
    local_eol_locker peeklock(&write_mutex);

    if (peek_reserved) {
        peeklock.unlock();
        throw std::runtime_error("ringbuf v2 peek already locked");
    }

    // No matter what is requested we can't read more than we have
    size_t opsize = std::min(in_sz, used());

    // Always reserve first since we may blindly peek_free later
    peek_reserved = true;
    // Set free manually later if necessary
    free_peek = false;

    if (opsize == 0) {
        free_peek = false;
        return 0;
    }

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
        memcpy(*ptr + chunk_a, buffer, chunk_b);

        // fprintf(stderr, "debug - ringbuf2 peek from %lu sz %lu\n", start_pos, opsize);

        return opsize;
    }

}

ssize_t ringbuf_v2::zero_copy_peek(unsigned char **ptr, size_t in_sz) {
    local_eol_locker peeklock(&write_mutex);

    if (peek_reserved) {
        peeklock.unlock();
        throw std::runtime_error("ringbuf v2 peek already locked");
    }

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

void ringbuf_v2::peek_free(unsigned char *in_data) {
    local_unlocker unpeeklock(&write_mutex);

    if (!peek_reserved) {
        throw std::runtime_error("ringbuf v2 peek_free on unlocked buffer");
    }

    if (free_peek) {
        delete[] in_data;
    }

    peek_reserved = false;
    free_peek = false;
}

size_t ringbuf_v2::consume(size_t in_sz) {
    // Protect cross-thread
    local_locker peeklock(&write_mutex);

    if (peek_reserved) {
        throw std::runtime_error("ringbuf v2 consume while peeked data pending");
    }

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 consume while reserved data pending");
    }

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

ssize_t ringbuf_v2::write(unsigned char *data, size_t in_sz) {
    local_locker writelock(&write_mutex);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    if (in_sz == 0)
        return 0;

    if (available() < (ssize_t) in_sz) {
        // fprintf(stderr, "debug - ringbuf2 - insufficient space in buffer for %lu available %lu length %lu\n", in_sz, available(), length);
        return 0;
    }

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

ssize_t ringbuf_v2::reserve(unsigned char **data, size_t in_sz) {
    local_eol_locker writelock(&write_mutex);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    if (in_sz == 0) {
        writelock.unlock();
        return 0;
    }

    size_t copy_start;

    if (available() < (ssize_t) in_sz) {
        writelock.unlock();
        return 0;
    }

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;
    write_reserved = true;

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

ssize_t ringbuf_v2::zero_copy_reserve(unsigned char **data, size_t in_sz) {
    local_eol_locker writelock(&write_mutex);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    if (available() < (ssize_t) in_sz) {
        writelock.unlock();
        return 0;
    }

    if (in_sz == 0) {
        writelock.unlock();
        return 0;
    }

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

bool ringbuf_v2::commit(unsigned char *data, size_t in_sz) {
    local_unlocker unwritelock(&write_mutex);

    if (!write_reserved) {
        throw std::runtime_error("ringbuf v2 no pending commit");
    }

    // Unlock the write state
    write_reserved = false;

    // If we have allocated an interstitial buffer, we need copy the data over and delete
    // the temp buffer
    if (free_commit) {
        free_commit = false;

        if (in_sz == 0)
            return true;

        ssize_t written = write(data, in_sz);

        delete[] data;

        if (written < 0)
            return false;

        return (size_t) written == in_sz;
    } else {
        if (in_sz == 0)
            return true;

        ssize_t written = write(NULL, in_sz);
        if (written < 0)
            return false;

        return (size_t) written == in_sz;
    }
}


