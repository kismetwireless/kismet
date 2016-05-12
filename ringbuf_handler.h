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

#ifndef __RINGBUFFER_HANDLER__
#define __RINGBUFFER_HANDLER__

#include "config.h"

#include <stdlib.h>
#include <string>
#include "ringbuf2.h"

class RingbufferInterface;

// Common handler for a ringbuffer, which allows a simple standardized interface
// to the buffer when data is added.
//
// Network servers and consumers should communicate by defining ringbuffer
// interfaces
//
// Anything that handles async / nonblocking data can use this interface.
//
// RingbufferHandler automatically protects itself against 
class RingbufferHandler {
public:
    // For one-way buffers, define a buffer as having a size of zero
    RingbufferHandler(size_t r_buffer_sz, size_t w_buffer_sz);
    ~RingbufferHandler();

    // Basic size ops
    size_t GetReadBufferSize();
    size_t GetWriteBufferSize();

    size_t GetReadBufferUsed();
    size_t GetWriteBufferUsed();

    size_t GetReadBufferFree();
    size_t GetWriteBufferFree();

    // Fetch read and write buffer data, up to sz.  Consumes data from buffer.
    // Returns amount read
    size_t GetReadBufferData(void *in_ptr, size_t in_sz);
    size_t GetWriteBufferData(void *in_ptr, size_t in_sz);

    // Fetch read and write buffer data, up to in_amt.  Does not consume data.
    // Returns amount peeked
    size_t PeekReadBufferData(void *in_ptr, size_t in_sz);
    size_t PeekWriteBufferData(void *in_ptr, size_t in_sz);

    // Consume data w/out copying it (used to flag data we previously peeked)
    size_t ConsumeReadBufferData(size_t in_sz);
    size_t ConsumeWriteBufferData(size_t in_sz);

    // Place data in read or write buffer
    // Automatically triggers callbacks
    // Returns amount of data actually written
    size_t PutReadBufferData(void *in_ptr, size_t in_sz, bool in_atomic);
    size_t PutWriteBufferData(void *in_ptr, size_t in_sz, bool in_atomic);

    // Set interface callbacks to be called when we have data in the buffers
    void SetReadBufferInterface(RingbufferInterface *in_interface);
    void SetWriteBufferInterface(RingbufferInterface *in_interface);

    void RemoveReadBufferInterface();
    void RemoveWriteBufferInterface();

    // Propagate a buffer error to any listeners
    void BufferError(string in_error);
    // Propagate an error to a specific listener
    void ReadBufferError(string in_error);
    void WriteBufferError(string in_error);

protected:
    RingbufV2 *read_buffer;
    RingbufV2 *write_buffer;

    // Interfaces we notify when there has been activity on a buffer
    RingbufferInterface *wbuf_notify;
    RingbufferInterface *rbuf_notify;

    pthread_mutex_t handler_locker;
    pthread_mutex_t r_callback_locker;
    pthread_mutex_t w_callback_locker;
};

// Ringbuffer interface, interacts with a ringbuffer handler 
class RingbufferInterface {
public:
    RingbufferInterface();
    virtual ~RingbufferInterface();

    // Define which buffer we handle (register it with the interface automatically)
    virtual void HandleReadBuffer(RingbufferHandler *in_handler);
    virtual void HandleWriteBuffer(RingbufferHandler *in_handler);

    // Called when a buffer grows
    virtual void BufferAvailable(size_t in_amt) = 0;

    // Called when a buffer encounters an error
    virtual void BufferError(string in_error __attribute__((unused))) { }

protected:
    RingbufferHandler *handler;
    bool read_handler;
    bool write_handler;
};


#endif


