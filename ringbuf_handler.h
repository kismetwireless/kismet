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
#include <functional>
#include <streambuf>
#include <iostream>
#include <memory>

#include "ringbuf2.h"
#include "util.h"

class RingbufferInterface;

// Common handler for a ringbuffer, which allows a simple standardized interface
// to the buffer when data is added.
//
// Anything that handles async / nonblocking data can use this interface.
// 
// Network servers and consumers should communicate by defining ringbuffer
// interfaces
//
// Typically a ringbuffer handler is created for each async communication task
// (ie client connection, server socket, serial port, etc) and connected to 
// the low-level IO driver (often a Pollable) which reads and writes directly
// to the ring buffers.  The Ringbuffer Handler then automatically calls bound 
// handlers for read/write events.
//
class RingbufferHandler {
public:
    // For one-way buffers, define a buffer as having a size of zero
    RingbufferHandler(size_t r_buffer_sz, size_t w_buffer_sz);
    virtual ~RingbufferHandler();

    // Basic size ops
    size_t GetReadBufferSize();
    size_t GetWriteBufferSize();

    size_t GetReadBufferUsed();
    size_t GetWriteBufferUsed();

    size_t GetReadBufferFree();
    size_t GetWriteBufferFree();

    // Fetch read and write buffer data, up to sz.  Consumes data from buffer.
    // Automatically triggers buffer drain callbacks
    // Returns amount read
    size_t GetReadBufferData(void *in_ptr, size_t in_sz);
    size_t GetWriteBufferData(void *in_ptr, size_t in_sz);

    // Fetch read and write buffer data, up to in_amt.  Does not consume data.
    // Returns amount peeked
    size_t PeekReadBufferData(void *in_ptr, size_t in_sz);
    size_t PeekWriteBufferData(void *in_ptr, size_t in_sz);

    // Consume data w/out copying it (used to flag data we previously peeked)
    // Automatically triggers buffer drain callbacks
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

    // Set simple functional callbacks to be called when we drain an interface; used to
    // allow quick unlocking of blocked writers
    void SetReadBufferDrainCb(function<void (size_t)> in_cb);
    void SetWriteBufferDrainCb(function<void (size_t)> in_cb);

    void RemoveReadBufferDrainCb();
    void RemoveWriteBufferDrainCb();

    // Propagate a line-layer buffer error to any listeners (line IO system to interfaces)
    void BufferError(string in_error);
    // Propagate an error to a specific listener
    void ReadBufferError(string in_error);
    void WriteBufferError(string in_error);

    // Propagate a protocol-layer error to any line-drivers (protocol parser
    // to line drivers).  We don't pass a string to the line drivers because
    // the protocol driver should present the error usefully
    void ProtocolError();
    // Set a protocol error callback; line level drivers should set this and initiate
    // a shutdown of the line connections
    void SetProtocolErrorCb(function<void (void)> in_cb);

protected:

    RingbufV2 *read_buffer;
    RingbufV2 *write_buffer;

    // Interfaces we notify when there has been activity on a buffer
    RingbufferInterface *wbuf_notify;
    RingbufferInterface *rbuf_notify;

    pthread_mutex_t handler_locker;
    pthread_mutex_t r_callback_locker;
    pthread_mutex_t w_callback_locker;

    function<void (void)> protoerror_cb;

    function<void (size_t)> readbuf_drain_cb;
    function<void (size_t)> writebuf_drain_cb;
};

// A C++ streambuf-compatible wrapper around a ringbuf handler
struct RingbufferHandlerOStreambuf : public std::streambuf {
    RingbufferHandlerOStreambuf(shared_ptr<RingbufferHandler> in_rbhandler) :
        rb_handler(in_rbhandler), blocking(false) { }
    RingbufferHandlerOStreambuf(shared_ptr<RingbufferHandler> in_rbhandler, bool in_blocking) :
        rb_handler(in_rbhandler), blocking(in_blocking) { }

    virtual ~RingbufferHandlerOStreambuf();

protected:
    std::streamsize xsputn(const char_type *s, std::streamsize n) override;
    int_type overflow(int_type ch) override;

private:
    // Ringbuf handler we bind to
    shared_ptr<RingbufferHandler> rb_handler;

    // Do we block when buffer is full?
    bool blocking;

    // Locker variable if we block
    shared_ptr<conditional_locker<size_t> > blocking_cl;
};


// Ringbuffer interface, interacts with a ringbuffer handler 
class RingbufferInterface {
public:
    RingbufferInterface();
    virtual ~RingbufferInterface();

    // Called when the linked buffer grows
    virtual void BufferAvailable(size_t in_amt) = 0;

    // Called when a buffer encounters an error
    virtual void BufferError(string in_error __attribute__((unused))) { }

protected:
    RingbufferHandler *ringbuffer_handler;
    bool read_handler;
    bool write_handler;
};


#endif


