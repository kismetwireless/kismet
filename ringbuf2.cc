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

    memset(buffer, 0xAA, in_sz);

    buffer_sz = in_sz;
    start_pos = 0;
    length = 0;

#ifdef PROFILE_RINGBUFV2 
    zero_copy_w_bytes = 0;
    zero_copy_r_bytes = 0;
    copy_w_bytes = 0;
    copy_r_bytes = 0;
    last_profile_bytes = 0;
#endif
}

RingbufV2::~RingbufV2() {
    local_locker lock(&buffer_locker);

#ifdef PROFILE_RINGBUFV2
    profile();
#endif
    
    delete[] buffer;
}

#ifdef PROFILE_RINGBUFV2
void RingbufV2::profile() {
    fprintf(stderr, "profile - ringbufv2 - %p stats - \n"
            "    len %lu\n"
            "    write zero copy %lu\n"
            "    write forced copy %lu\n"
            "    write efficiency %2.2f\n"
            "    read zero copy %lu\n"
            "    read forced copy %lu\n"
            "    read efficiency %2.2f\n",
            this,
            buffer_sz, 
            zero_copy_w_bytes, copy_w_bytes, 
            (double) ((double) zero_copy_w_bytes / (double) (copy_w_bytes + zero_copy_w_bytes)),
            zero_copy_r_bytes, copy_r_bytes, 
            (double) ((double) zero_copy_r_bytes / (double) (copy_r_bytes + zero_copy_r_bytes)));

    double total = zero_copy_w_bytes + zero_copy_r_bytes;
    char u = 'B';

    if (total < 1024) {
        ;
    } else if (total < 1024 * 1024) {
        total /= 1024;
        u = 'K';
    } else if (total < 1024 * 1024 * 1024) {
        total /= (1024 * 1024);
        u = 'M';
    } else if (total < (double) (1024.0 * 1024.0 * 1024.0 * 1024.0)) {
        total /= (1024 * 1024 * 1024);
        u = 'G';
    }

    fprintf(stderr, "     total saved: %2.2f %c\n", total, u);
    last_profile_bytes = 0;
}
#endif

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
    size_t opsize = min(in_sz, used());

    if (opsize == 0)
        return 0;

    peek_reserved = true;

    if (start_pos + opsize < buffer_sz) {
        // Can we read contiguously? if so we can do a zero-copy peek
        free_peek = false;
        *ptr = buffer + start_pos;

#ifdef PROFILE_RINGBUFV2
        zero_copy_r_bytes += opsize;
        last_profile_bytes += opsize;
        if (last_profile_bytes > (1024*1024))
            profile();
#endif

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

#ifdef PROFILE_RINGBUFV2
        copy_r_bytes += opsize;
        last_profile_bytes += opsize;
        if (last_profile_bytes > (1024*1024))
            profile();
#endif
        return opsize;
    }
}

ssize_t RingbufV2::zero_copy_peek(unsigned char **ptr, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (peek_reserved) {
        throw std::runtime_error("ringbuf v2 peek already locked");
    }

    // No matter what is requested we can't read more than we have
    size_t opsize = min(in_sz, used());

    if (opsize == 0)
        return 0;

    // Trim to only the part of the buffer we can point to directly
    if (start_pos + opsize > buffer_sz) {
        opsize = buffer_sz - start_pos;
    }

    peek_reserved = true;
    free_peek = false;

#ifdef PROFILE_RINGBUFV2
    zero_copy_r_bytes += opsize;
    last_profile_bytes += opsize;
    if (last_profile_bytes > (1024*1024))
        profile();
#endif

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

    if (peek_reserved) {
        throw std::runtime_error("ringbuf v2 consume while peeked data pending");
    }

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 consume while write block is reserved");
    }

    // No matter what is requested we can't read more than we have
    size_t opsize = min(in_sz, used());

    // Can we read contiguously?
    if (start_pos + opsize < buffer_sz) {

        start_pos += opsize;
        length -= opsize;

        // fprintf(stderr, "debug - ringbuf2 consuming %lu new start %lu new len %lu\n", in_sz, start_pos, length);

        return opsize;
    } else {
        // Split into chunks
        size_t chunk_a = buffer_sz - start_pos;
        size_t chunk_b = opsize - chunk_a;

        // Loop the ring buffer and mark read
        start_pos = chunk_b;
        length -= opsize;

        // fprintf(stderr, "debug - ringbuf2 loop consuming %lu new start pos %lu new len %lu\n", in_sz, start_pos, length);


        return opsize;
    }

    return 0;
}

ssize_t RingbufV2::write(unsigned char *data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    if (in_sz == 0)
        return 0;

    if (available() < (ssize_t) in_sz) {
        // fprintf(stderr, "debug - ringbuf2 - insufficient space in buffer for %lu\n", in_sz);
        return 0;
    }

#ifdef PROFILE_RINGBUFV2
    if (data != NULL)
        copy_w_bytes += in_sz;
    else
        zero_copy_w_bytes += in_sz;
    last_profile_bytes += in_sz;
    if (last_profile_bytes > (1024*1024))
        profile();
#endif

    size_t copy_start;

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;

    if (copy_start + in_sz < buffer_sz) {
        // fprintf(stderr, "debug - ringbuf2 write len %lu copy_start %lu start pos %lu length %lu buffer %lu\n", in_sz, copy_start, start_pos, length, buffer_sz);

        if (data != NULL)
            memcpy(buffer + copy_start, data, in_sz);
        length += in_sz;

        return in_sz;
    } else {
        // fprintf(stderr, "debug - ringbuf2 split write len %lu copy_start %lu start pos %lu length %lu buffer %lu\n", in_sz, copy_start, start_pos, length, buffer_sz);

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

ssize_t RingbufV2::reserve(unsigned char **data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    if (in_sz == 0)
        return 0;

    size_t copy_start;

    if (available() < (ssize_t) in_sz) {
        // fprintf(stderr, "debug - ringbuf2 - insufficient space in buffer for %lu\n", in_sz);
        return 0;
    }

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;

    write_reserved = true;

    if (copy_start + in_sz < buffer_sz) {
        free_commit = false;
        *data = buffer + copy_start;

        // fprintf(stderr, "debug - ringbuf2 - zerocopy reserve at %lu len  %lu\n", copy_start, in_sz);

        return in_sz;
    } else {
        free_commit = true;
        *data = new unsigned char[in_sz];

        // fprintf(stderr, "debug - ringbuf2 - copy reserve at %lu len  %lu\n", copy_start, in_sz);

        return in_sz;
    }
}

ssize_t RingbufV2::zero_copy_reserve(unsigned char **data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (write_reserved) {
        throw std::runtime_error("ringbuf v2 write already locked");
    }

    if (in_sz == 0) {
        fprintf(stderr, "debug - ringbuf2 - zcr got req for 0\n");
        return 0;
    }

    size_t copy_start;

    // Figure out if we can write a contiguous block
    copy_start = (start_pos + length) % buffer_sz;

    write_reserved = true;
    free_commit = false;

    *data = buffer + copy_start;

    // If we're looking for less than our total available, then return either what
    // we were looking for, or the contiguous remainder of the buffer
    if (in_sz < (size_t) available()) {
        // fprintf(stderr, "debug - %lu less than %lu\n", in_sz, available());
        return min(in_sz, buffer_sz - copy_start);
    }

    // Otherwise return the contiguous buffer left
    // fprintf(stderr, "debug - contiguous\n");
    return (buffer_sz - copy_start);
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

        if (in_sz == 0)
            return true;

        // fprintf(stderr, "debug - writing copied buffer %lu\n", in_sz);

        ssize_t written = write(data, in_sz);

        delete[] data;

        if (written < 0)
            return false;

        return (size_t) written == in_sz;
    } else {
        if (in_sz == 0)
            return true;

        // fprintf(stderr, "debug - finalizing zerocopy buffer %lu\n", in_sz);

        ssize_t written = write(NULL, in_sz);
        if (written < 0)
            return false;

        return (size_t) written == in_sz;
    }
}


