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
#include "buffer_handler.h"

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

    virtual size_t size();
    virtual size_t available();
    virtual size_t used();

    // Write data into a buffer
    // Return amount of data actually written
    virtual size_t write(unsigned char *in_data, size_t in_sz);

    // Peek data from a buffer, up to sz
    // Peeked data is not consumed
    // Return the amount of data actually peeked
    virtual size_t peek(unsigned char *in_data, size_t in_sz);

    virtual size_t consume(size_t in_sz);

protected:
    // Mutex for all operations on the buffer
    pthread_mutex_t buffer_locker;

    // Non-locking internal versions
    size_t size_nl();
    size_t available_nl();
    size_t used_nl();

    uint8_t *buffer;
    // Total size
    size_t buffer_sz;
    // Where reads start
    size_t start_pos;
    // Length of data currently in buffer
    size_t length;
};


#endif

