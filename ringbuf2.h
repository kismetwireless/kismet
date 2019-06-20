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

#ifndef __RINGBUF2_H__
#define __RINGBUF2_H__

#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <mutex>
#include "buffer_handler.h"

// #define PROFILE_RINGBUFV2   1

// A better ringbuffer implementation that will replace the old ringbuffer in 
// Kismet as the rewrite continues
//
// Automatically thread locks locally to prevent multiple operations overlapping
class RingbufV2 : public CommonBuffer {
public:
    RingbufV2(size_t in_sz);
    virtual ~RingbufV2();

    // Reset a buffer
    virtual void clear();

    virtual ssize_t size();
    virtual ssize_t available();
    virtual size_t used();

    // Write data into a buffer
    // Return amount of data actually written
    virtual ssize_t write(unsigned char *in_data, size_t in_sz);

    // Peek at data
    virtual ssize_t peek(unsigned char **in_data, size_t in_sz);
    virtual ssize_t zero_copy_peek(unsigned char **in_data, size_t in_sz);
    virtual void peek_free(unsigned char *in_data);

    virtual size_t consume(size_t in_sz);

    virtual ssize_t reserve(unsigned char **data, size_t in_sz);
    virtual ssize_t zero_copy_reserve(unsigned char **data, size_t in_sz);
    virtual bool commit(unsigned char *data, size_t in_sz);

#ifdef PROFILE_RINGBUFV2
    virtual void profile();
#endif

protected:
    unsigned char *buffer;
    // Total size
    std::atomic<size_t> buffer_sz;
    // Where reads start
    std::atomic<size_t> start_pos;
    // Length of data currently in buffer
    std::atomic<size_t> length;

    // Do we need to free our peeked or committed data?
    std::atomic<bool> free_peek, free_commit;

#ifdef PROFILE_RINGBUFV2 
    size_t zero_copy_w_bytes, zero_copy_r_bytes, copy_w_bytes, copy_r_bytes, last_profile_bytes;
#endif
};


#endif

