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

#include "ringbuf.h"
#include <string.h>

RingBuffer::RingBuffer(int in_size) {
    ring_len = in_size;
    ring_data = new uint8_t[in_size];
    ring_rptr = ring_data;
    ring_wptr = ring_data;
}

RingBuffer::~RingBuffer() {
    delete[] ring_data;
}

int RingBuffer::InsertDummy(int in_len) {
    if (ring_wptr == ring_rptr && ring_wptr == ring_data)
        return 1;

    if (ring_wptr + in_len >= ring_data + ring_len) {
        int tail = (ring_data + ring_len) - ring_wptr;
        if (ring_data + (in_len - tail) >= ring_rptr)
            return 0;
    } else {
        if ((ring_rptr > ring_wptr) && (ring_wptr + in_len >= ring_rptr))
            return 0;
    }

    return 1;
}

int RingBuffer::InsertData(uint8_t *in_data, int in_len) {
    // Will this hit the end of the ring and go back to the beginning?
    if ((ring_wptr + in_len) >= (ring_data + ring_len)) {
        // How much data gets written to the tail of the ring before we
        // wrap?
        int tail = (ring_data + ring_len) - ring_wptr;

        // If we're going to wrap, will we overrun the read position?
        if (ring_data + (in_len - tail) >= ring_rptr)
            return 0;

        // Copy the data to the end of the loop, move to the beginning
        memcpy(ring_wptr, in_data, tail);
        memcpy(ring_data, in_data + tail, in_len - tail);
        ring_wptr = ring_data + (in_len - tail);
    } else {
        // Will we surpass the read pointer?
        if ((ring_rptr > ring_wptr) && (ring_wptr + in_len >= ring_rptr))
            return 0;

        // Copy the data to the write pointer
        memcpy(ring_wptr, in_data, in_len);
        ring_wptr = ring_wptr + in_len;
    }

    // printf("debug - inserted %d into ring buffer.\n", in_len);

    return 1;
}

int RingBuffer::FetchLen() {
    int ret = 0;

    if (ring_wptr < ring_rptr) {
        // If the write pointer is wrapped before the read, add the
        // length from read to the end plus the beginning to the write
        ret = (ring_data + ring_len) - ring_rptr + (ring_wptr - ring_data);
    } else {
        ret = (ring_wptr - ring_rptr);
    }

    //printf("ring begin %p wptr %p rptr %p lt %d len %d\n",
           //ring_data, ring_wptr, ring_rptr, ring_wptr < ring_rptr, ret);

    return ret;
}

void RingBuffer::FetchPtr(uint8_t *in_dataptr, int in_max, int *in_len) {
    // Has the write pointer looped back?
    if (ring_wptr < ring_rptr) {
        // Copy the read to the end, as much as we can
        *in_len = (ring_data + ring_len) - ring_rptr;

        // If we have more room than we need
        if (*in_len > in_max) {
            // printf("debug - ring %d avail, %d requested\n", *in_len, in_max);
            *in_len = in_max;
            memcpy(in_dataptr, ring_rptr, in_max);
            return;
        }

        // Copy all we can to the end of the array
        memcpy(in_dataptr, ring_rptr, *in_len);
       
        // How many bytes can we copy?  Whichever is smaller - the head of the
        // ring, or the max we can hold after we stocked it before
        int copybytes = kismin((ring_wptr - ring_data), (in_max - *in_len));

        // Copy it off the header
        memcpy(in_dataptr + *in_len, ring_data, copybytes);

        *in_len = *in_len + copybytes;

        return;
        
    } else {
        // Copy out the requested size or as much as we can
        *in_len = kismin((ring_wptr - ring_rptr), in_max);
        memcpy(in_dataptr, ring_rptr, *in_len);
        return;
    }
}

void RingBuffer::MarkRead(int in_len) {
    // Will we loop the array?
    if ((ring_rptr + in_len) >= (ring_data + ring_len)) {
        // How much comes off the length before we wrap?
        int tail = (ring_data + ring_len) - ring_rptr;

        // Catch surpassing the write pointer after the loop
        if (ring_data + (in_len - tail) > ring_wptr)
            ring_rptr = ring_wptr;
        else
            ring_rptr = ring_data + (in_len - tail);
    } else {
        ring_rptr += in_len;
    }

    //printf("debug - marked %d read in ring\n", in_len);
    
    return;
}

int RingBuffer::FetchSize() {
	return ring_len;
}

int RingBuffer::Resize(int in_newlen) {
	if (in_newlen < ring_len)
		return 0;

	// New buffer
	uint8_t *newdata = new uint8_t[in_newlen];
	// Copy old data
	memcpy(ring_data, newdata, ring_len);

	// Offset the pointers into the ring buf by the same # of bytes that they
	// were into the old buf
	ring_wptr = newdata + (ring_wptr - ring_data);
	ring_rptr = newdata + (ring_rptr - ring_data);

	// Remove the old, copy the new
	delete[] ring_data;
	ring_data = newdata;
	ring_len = in_newlen;

	return 1;
}

