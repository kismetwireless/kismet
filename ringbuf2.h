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

// A better ringbuffer implementation that will replace the old ringbuffer in 
// Kismet as the rewrite continues
//
// Automatically thread locks locally to prevent multiple operations overlapping
class RingbufV2 {
public:
    RingbufV2(size_t in_sz);
    ~RingbufV2();

    // Reset a buffer
    void clear();

    size_t size();
    size_t available();
    size_t used();

    // Write data into a buffer
    // Return amount of data actually written
    size_t write(void *in_data, size_t in_sz);

    // Read data from a buffer up to sz
    // Read data is consumed
    // If the in_data pointer is NULL, data is consumed but no copy is performed.
    // Return the amount of data actually read
    size_t read(void *in_data, size_t in_sz);

    // Peek data from a buffer, up to sz
    // Peeked data is not consumed
    // Return the amount of data actually peeked
    size_t peek(void *in_data, size_t in_sz);

protected:
    // Mutex for all operations on the buffer
    pthread_mutex_t buffer_locker;

    uint8_t *buffer;
    // Total size
    size_t buffer_sz;
    // Where reads start
    size_t start_pos;
    // Length of data currently in buffer
    size_t length;
};


#endif

