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

#include "util.h"

class BufferInterface;

// Common minimal API for a buffer
class CommonBuffer {
public:
    virtual ~CommonBuffer() { };

    // Clear all data (and free memory used, for dynamic buffers)
    virtual void clear() = 0;

    // Fetch total size of buffer
    virtual size_t size() = 0;

    // Fetch available space in buffer, -1 indicates unbounded dynamic buffer
    virtual ssize_t available() = 0;

    // Fetch amount used in current buffer
    virtual size_t used() = 0;

    // Reserve space in the write buffer; for fixed-size buffers such as a ringbuf this
    // will reserve the space and provide a direct pointer to the space.  For continual
    // dynamic buffers (like chainbuf) this may induce copy or may provide direct access.
    // Callers should not make any assumptions about the underlying nature of the buffer.
    //
    // Only one reservation may be made at a time.  Additional reservations without a
    // commit will fail.
    //
    // The caller must call 'commit' when the data has been copied.
    virtual ssize_t reserve(unsigned char **data, size_t in_sz) = 0;

    // Commit changes to the reserved block
    virtual bool commit(size_t in_sz) = 0;

    // Write an existing block of data to the buffer; this performs a memcpy to copy 
    // the data into the buffer
    virtual size_t write(unsigned char *data, size_t in_sz) = 0;

    // Copy data from the buffer into an existing memory allocation; this performs a
    // memcpy to extract data from the buffer
    virtual size_t peek(unsigned char *data, size_t in_sz) = 0;

    // Remove data from a buffer
    virtual size_t consume(size_t in_sz) = 0;
};

// Common handler for a buffer, which allows a simple standardized interface
// to the buffer when data is added.  Typically used with a Ringbuffer or a 
// Chainbuffer (When using a chainbuffer, be aware of the chainbuf limitations)
//
// Anything that handles async / nonblocking data can use this interface.
// 
// Network servers and consumers should communicate by defining buffer
// interfaces
//
// Typically a buffer handler is created for each async communication task
// (ie client connection, server socket, serial port, etc) and connected to 
// the low-level IO driver (often a Pollable) which reads and writes directly
// to the ring buffers.  The buffer handler then automatically calls bound 
// handlers for read/write events.
//
class BufferHandlerGeneric {
public:
    BufferHandlerGeneric();

    virtual ~BufferHandlerGeneric();

    // Basic size ops
    virtual size_t GetReadBufferSize();
    virtual size_t GetWriteBufferSize();

    virtual size_t GetReadBufferUsed();
    virtual size_t GetWriteBufferUsed();

    virtual size_t GetReadBufferFree();
    virtual size_t GetWriteBufferFree();

    // Fetch read and write buffer data, up to sz.  Consumes data from buffer.
    // Automatically triggers buffer drain callbacks
    // Returns amount read
    virtual size_t GetReadBufferData(void *in_ptr, size_t in_sz);
    virtual size_t GetWriteBufferData(void *in_ptr, size_t in_sz);

    // Fetch read and write buffer data, up to in_amt.  Does not consume data.
    // Returns amount peeked
    virtual size_t PeekReadBufferData(void *in_ptr, size_t in_sz);
    virtual size_t PeekWriteBufferData(void *in_ptr, size_t in_sz);

    // Consume data w/out copying it (used to flag data we previously peeked)
    // Automatically triggers buffer drain callbacks
    virtual size_t ConsumeReadBufferData(size_t in_sz);
    virtual size_t ConsumeWriteBufferData(size_t in_sz);

    // Place data in read or write buffer
    // Automatically triggers callbacks
    // Returns amount of data actually written
    virtual size_t PutReadBufferData(void *in_ptr, size_t in_sz, bool in_atomic);
    virtual size_t PutWriteBufferData(void *in_ptr, size_t in_sz, bool in_atomic);

    // Set interface callbacks to be called when we have data in the buffers
    virtual void SetReadBufferInterface(BufferInterface *in_interface);
    virtual void SetWriteBufferInterface(BufferInterface *in_interface);

    virtual void RemoveReadBufferInterface();
    virtual void RemoveWriteBufferInterface();

    // Set simple functional callbacks to be called when we drain an interface; used to
    // allow quick unlocking of blocked writers
    virtual void SetReadBufferDrainCb(function<void (size_t)> in_cb);
    virtual void SetWriteBufferDrainCb(function<void (size_t)> in_cb);

    virtual void RemoveReadBufferDrainCb();
    virtual void RemoveWriteBufferDrainCb();

    // Propagate a line-layer buffer error to any listeners (line IO system to interfaces)
    virtual void BufferError(string in_error);
    // Propagate an error to a specific listener
    virtual void ReadBufferError(string in_error);
    virtual void WriteBufferError(string in_error);

    // Propagate a protocol-layer error to any line-drivers (protocol parser
    // to line drivers).  We don't pass a string to the line drivers because
    // the protocol driver should present the error usefully
    virtual void ProtocolError();
    // Set a protocol error callback; line level drivers should set this and initiate
    // a shutdown of the line connections
    virtual void SetProtocolErrorCb(function<void (void)> in_cb);

protected:
    // Generic buffers
    CommonBuffer *read_buffer;
    CommonBuffer *write_buffer;

    // Interfaces we notify when there has been activity on a buffer
    BufferInterface *wbuf_notify;
    BufferInterface *rbuf_notify;

    pthread_mutex_t handler_locker;
    pthread_mutex_t r_callback_locker;
    pthread_mutex_t w_callback_locker;

    function<void (void)> protoerror_cb;

    function<void (size_t)> readbuf_drain_cb;
    function<void (size_t)> writebuf_drain_cb;
};

template<class B> 
class BufferHandler : public BufferHandlerGeneric {
public:
    // For one-way buffers, define a buffer as having a size of zero
    BufferHandler(size_t r_buffer_sz, size_t w_buffer_sz) {
        if (r_buffer_sz != 0)
            read_buffer = new B(r_buffer_sz);
        else
            read_buffer = NULL;

        if (w_buffer_sz != 0)
            write_buffer = new B(w_buffer_sz);
        else
            write_buffer = NULL;
    }
};

// A C++ streambuf-compatible wrapper around a buf handler
struct BufferHandlerOStreambuf : public std::streambuf {
    BufferHandlerOStreambuf(shared_ptr<BufferHandlerGeneric > in_rbhandler) :
        rb_handler(in_rbhandler), blocking(false) { }
    BufferHandlerOStreambuf(shared_ptr<BufferHandlerGeneric > in_rbhandler, bool in_blocking) :
        rb_handler(in_rbhandler), blocking(in_blocking) { }

    virtual ~BufferHandlerOStreambuf();

protected:
    std::streamsize xsputn(const char_type *s, std::streamsize n) override;
    int_type overflow(int_type ch) override;

private:
    // buf handler we bind to
    shared_ptr<BufferHandlerGeneric > rb_handler;

    // Do we block when buffer is full?
    bool blocking;

    // Locker variable if we block
    shared_ptr<conditional_locker<size_t> > blocking_cl;
};


// buffer interface, interacts with a buffer handler 
class BufferInterface {
public:
    BufferInterface();
    virtual ~BufferInterface();

    // Called when the linked buffer grows
    virtual void BufferAvailable(size_t in_amt) = 0;

    // Called when a buffer encounters an error
    virtual void BufferError(string in_error __attribute__((unused))) { }

protected:
    BufferHandlerGeneric *buffer_handler;
    bool read_handler;
    bool write_handler;
};


#endif


