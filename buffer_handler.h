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
#include "kis_mutex.h"

class BufferInterface;

// Common minimal API for a buffer
class CommonBuffer {
public:
    CommonBuffer() :
        write_reserved {false},
        peek_reserved {false} { }

    virtual ~CommonBuffer() { };

    // Clear all data (and free memory used, for dynamic buffers)
    virtual void clear() = 0;

    // Fetch total size of buffer; -1 indicates unbounded dynamic buffer
    virtual ssize_t size() = 0;

    // Fetch available space in buffer, -1 indicates unbounded dynamic buffer
    virtual ssize_t available() = 0;

    // Fetch amount used in current buffer
    virtual size_t used() = 0;

    // Reserve space in the write buffer; for fixed-size buffers such as a ringbuf this
    // will reserve the space and provide a direct pointer to the space.  For continual
    // dynamic buffers (like chainbuf) this may induce copy or may provide direct access.
    // Callers should not make any assumptions about the underlying nature of the buffer.
    //
    // The reserved space is provided in a data pointer; this object must be
    // returned to the buffer via commit()
    //
    // This data pointer may be a direct link (zero-copy) to the buffer, or may 
    // require an additional memory copy.
    //
    // Only one reservation may be made at a time.  Additional reservations without a
    // commit should fail.
    //
    // Implementations must track internally if the reserved data must be free'd upon commit
    //
    // Implementations should protect cross-thread reservations via write_mutex
    virtual ssize_t reserve(unsigned char **data, size_t in_sz) = 0;

    // Reserve as much space as possible, up to in_sz, and do as much as possible to 
    // ensure it is a zero-copy buffer.
    //
    // A zero-copy reservation may be smaller than the requested reservation size.
    //
    // Only one reservation may be made at a time.
    //
    // The caller must commit the reserved data.
    //
    // Implementations should protect cross-thread reservations via write_mutex
    virtual ssize_t zero_copy_reserve(unsigned char **data, size_t in_sz) = 0;

    // Commit changes to the reserved block
    //
    // Implementations should release the write_mutex lock 
    virtual bool commit(unsigned char *data, size_t in_sz) = 0;

    // Write an existing block of data to the buffer; this always performs a memcpy to copy 
    // the data into the buffer.  When possible, it is more efficient to use the 
    // reservation system.
    //
    // Implementations should protect cross-thread reservations via write_mutex
    virtual ssize_t write(unsigned char *data, size_t in_sz) = 0;

    // Peek data.  If possible, this will be a zero-copy operation, if not, it will 
    // allocate a buffer.  Content is returned in the **data pointer, which will be
    // a buffer of at least the returned size;  Peeking may return less data
    // than requested.
    //
    // Callers MUST free the data with 'peek_free(...)'.  Buffer implementations MUST
    // track if the peeked data must be deleted or if it is a zero-copy reference.
    //
    // Only one piece of data should be peek'd at a time, additional attempts prior
    // to a peek_free may fail.  This includes peek() and zero_copy_peek()
    //
    // peek will perform a copy to fulfill the total data size if the underlying
    // buffer implementation cannot return a zero-copy reference; as such it is most 
    // appropriate for performing read operations of structured data where the entire
    // object must be available.
    //
    // implementations should protect peek data cross-thread using the peek_mutex 
    virtual ssize_t peek(unsigned char **data, size_t in_sz) = 0;

    // Attempt a zero-copy peek; if the underlying buffer supports zero-copy references
    // this will return a direct pointer to the buffer contents; if the underlying buffer
    // does not, it may allocate memory and perform a copy.
    //
    // Callers MUST free the data with 'peek_free(...)'.  Buffer implementations MUST
    // track if the peeked data must be deleted or if it is a zero-copy reference.
    //
    // zero_copy_peek will NEVER allocate and copy a buffer when a no-copy shorter
    // buffer is available; This is most suited for draining buffers to an IO system
    // where the exact record length is not relevant; in general it is not as useful
    // when a fixed record size must be available.
    //
    // Only one piece of data should be peek'd at a time, additional attempts prior
    // to a peek_free may fail; this includes peek() and zero_copy_peek()
    //
    // implementations should protect peek data cross-thread using the peek_mutex 
    virtual ssize_t zero_copy_peek(unsigned char **data, size_t in_sz) = 0;

    // Deallocate peeked data; implementations should also use this time to release
    // the peek_mutex lock on peek data
    virtual void peek_free(unsigned char *data) = 0;

    // Remove data from a buffer
    virtual size_t consume(size_t in_sz) = 0;

protected:
    std::atomic<bool> write_reserved;
    std::atomic<bool> peek_reserved;

    // Additional mutex for protecting peek and write reservations across threads
    kis_recursive_timed_mutex peek_mutex, write_mutex;
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
class BufferHandlerGenericLocker;

class BufferHandlerGeneric {
public:
    BufferHandlerGeneric();
    virtual ~BufferHandlerGeneric();

    virtual void SetMutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent);

    // Basic size ops
    virtual ssize_t GetReadBufferSize();
    virtual ssize_t GetWriteBufferSize();

    virtual size_t GetReadBufferUsed();
    virtual size_t GetWriteBufferUsed();

    virtual ssize_t GetReadBufferAvailable();
    virtual ssize_t GetWriteBufferAvailable();

    // Fetch read and write buffer data, up to in_amt.  Does not consume data.
    // When possible, minimizes copies; actual copy and memory use depends on the
    // lower-level buffer, and consumers should not rely on specific behaviors.
    //
    // Consumers MUST conclude a peek operation with PeekFreeReadBufferData(...) or
    // PeekFreeWriteBufferData(...), and may not perform multiple peeks simultaneously;
    // refer to the comments for CommonBuffer
    //
    // Returns amount peeked
    virtual ssize_t PeekReadBufferData(void **in_ptr, size_t in_sz);
    virtual ssize_t PeekWriteBufferData(void **in_ptr, size_t in_sz);

    // Perform a zero-copy (when possible) peek of the buffer.  Does not consume
    // data.  When possible, minimizes copying of data (or performs no copy of data),
    // and is suitable for draining a buffer to the IO system.
    virtual ssize_t ZeroCopyPeekReadBufferData(void **in_ptr, size_t in_sz);
    virtual ssize_t ZeroCopyPeekWriteBufferData(void **in_ptr, size_t in_sz);

    virtual void PeekFreeReadBufferData(void *in_ptr);
    virtual void PeekFreeWriteBufferData(void *in_ptr);

    // Consume data from the buffer.  Must not be called while there is pending 'peek'd 
    // data.
    //
    // Automatically triggers buffer drain callbacks
    virtual size_t ConsumeReadBufferData(size_t in_sz);
    virtual size_t ConsumeWriteBufferData(size_t in_sz);

    // Place data in read or write buffer.  Performs a copy of the existing data and
    // writes it into the buffer.
    //
    // Automatically triggers callbacks
    //
    // Returns amount of data actually written
    virtual size_t PutReadBufferData(void *in_ptr, size_t in_sz, bool in_atomic);
    virtual size_t PutWriteBufferData(void *in_ptr, size_t in_sz, bool in_atomic);

    // Place data, as a string, into the buffer as an atomic op; returns success 
    // or failure on placing the entire record.
    virtual bool PutReadBufferData(std::string in_data);
    virtual bool PutWriteBufferData(std::string in_data);

    // Reserve space in the buffers; the returned pointer is suitable for direct
    // writing.  Whenever possible, this will be a zero-copy operation, however on
    // some buffer structures this may require copying of the data content to the
    // buffer.
    //
    // Callers must not make assumptions about the underlying structure of the buffer
    // or of the pointer they are given.
    //
    // Callers must conclude the write operation with CommitReadBufferData(..) or
    // CommitWriteBufferData(..).
    //
    // Only one block of data may be reserved at a time.
    //
    // Returns the amount of data allocated in the reserved block
    virtual ssize_t ReserveReadBufferData(void **in_ptr, size_t len);
    virtual ssize_t ReserveWriteBufferData(void **in_ptr, size_t len);

    // Reserve space in one of the buffers; Take excessive measures to make this a
    // zero-copy buffer, including reserving less size than requested.  This is most 
    // appropriate for incoming data streams being written to a buffer.
    //
    // Callers must conclude the write operation with CommitReadBufferData(..) or
    // CommitWriteBufferData(..)
    //
    // Only one block of data may be reserved at a time.
    //
    // Returns the amount of data available in the reserved block
    virtual ssize_t ZeroCopyReserveReadBufferData(void **in_ptr, size_t len);
    virtual ssize_t ZeroCopyReserveWriteBufferData(void **in_ptr, size_t len);
    

    // Commit a pending reserved data block to the buffer
    //
    // Automatically triggers callbacks.
    virtual bool CommitReadBufferData(void *in_ptr, size_t in_sz);
    virtual bool CommitWriteBufferData(void *in_ptr, size_t in_sz);


    // Clear a buffer
    //
    // Completely empties a buffer, possibly freeing any memory associated with it 
    // if it's a dynamic buffer
    virtual void ClearReadBuffer();
    virtual void ClearWriteBuffer();

    // Trigger callbacks directly
    virtual void TriggerWriteCallback(size_t in_sz);
    virtual void TriggerReadCallback(size_t in_sz);

    // Set interface callbacks to be called when we have data in the buffers
    virtual void SetReadBufferInterface(BufferInterface *in_interface);
    virtual void SetWriteBufferInterface(BufferInterface *in_interface);

    virtual void RemoveReadBufferInterface();
    virtual void RemoveWriteBufferInterface();

    // Set simple functional callbacks to be called when we drain an interface; used to
    // allow quick unlocking of blocked writers
    virtual void SetReadBufferDrainCb(std::function<void (size_t)> in_cb);
    virtual void SetWriteBufferDrainCb(std::function<void (size_t)> in_cb);

    virtual void RemoveReadBufferDrainCb();
    virtual void RemoveWriteBufferDrainCb();

    // Propagate a line-layer buffer error to any listeners (line IO system to interfaces)
    virtual void BufferError(std::string in_error);
    // Propagate an error to a specific listener
    virtual void ReadBufferError(std::string in_error);
    virtual void WriteBufferError(std::string in_error);

    // Propagate a protocol-layer error to any line-drivers (protocol parser
    // to line drivers).  We don't pass a string to the line drivers because
    // the protocol driver should present the error usefully
    virtual void ProtocolError();
    // Set a protocol error callback; line level drivers should set this and initiate
    // a shutdown of the line connections
    virtual void SetProtocolErrorCb(std::function<void (void)> in_cb);

    friend class BufferHandlerGenericLocker;

protected:
    // Generic buffers
    CommonBuffer *read_buffer;
    CommonBuffer *write_buffer;

    // Interfaces we notify when there has been activity on a buffer; use atomic booleans
    // to indicate if the function is available
    std::atomic<bool> wbuf_notify_avail, rbuf_notify_avail;
    BufferInterface *wbuf_notify;
    BufferInterface *rbuf_notify;

    std::shared_ptr<kis_recursive_timed_mutex> handler_mutex;

    std::function<void (void)> protoerror_cb;

    std::atomic<bool> wbuf_drain_avail, rbuf_drain_avail;
    std::function<void (size_t)> writebuf_drain_cb;
    std::function<void (size_t)> readbuf_drain_cb;
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

    BufferHandler(B *r_buf, B *w_buf) {
        read_buffer = r_buf;
        write_buffer = w_buf;
    }
};

// A C++ streambuf-compatible wrapper around a buf handler
struct BufferHandlerOStreambuf : public std::streambuf {
    BufferHandlerOStreambuf(std::shared_ptr<BufferHandlerGeneric > in_rbhandler) :
        rb_handler(in_rbhandler), blocking(false) { }
    BufferHandlerOStreambuf(std::shared_ptr<BufferHandlerGeneric > in_rbhandler, bool in_blocking) :
        rb_handler(in_rbhandler), blocking(in_blocking) { }

    virtual ~BufferHandlerOStreambuf();

protected:
    std::streamsize xsputn(const char_type *s, std::streamsize n) override;
    int_type overflow(int_type ch) override;

private:
    // buf handler we bind to
    std::shared_ptr<BufferHandlerGeneric > rb_handler;

    // Do we block when buffer is full?
    bool blocking;

    // Locker variable if we block
    std::shared_ptr<conditional_locker<size_t> > blocking_cl;
};

// A C++ streambuf-compatible wrapper around a buf handler with an interstitial string
// cache
struct BufferHandlerOStringStreambuf : public std::stringbuf {
    BufferHandlerOStringStreambuf(std::shared_ptr<BufferHandlerGeneric > in_rbhandler) :
        rb_handler(in_rbhandler) { }

    virtual ~BufferHandlerOStringStreambuf();

protected:
    // Wrap the stringbuf functions 
    std::streamsize xsputn(const char_type *s, std::streamsize n) override;
    int_type overflow(int_type ch) override;

    int sync() override;

private:
    kis_recursive_timed_mutex mutex;

    // buf handler we bind to
    std::shared_ptr<BufferHandlerGeneric > rb_handler;
    
};


// buffer interface, interacts with a buffer handler 
class BufferInterface {
public:
    BufferInterface();
    virtual ~BufferInterface();

    // Called when the linked buffer has new data available
    virtual void BufferAvailable(size_t in_amt) = 0;

    // Called when a buffer encounters an error
    virtual void BufferError(std::string in_error __attribute__((unused))) { }

protected:
    BufferHandlerGeneric *buffer_handler;
    bool read_handler;
    bool write_handler;
};

class BufferInterfaceFunc : public BufferInterface {
public:
    BufferInterfaceFunc(std::function<void (size_t)> in_available_cb,
            std::function<void (std::string)> in_error_cb) : 
        BufferInterface(),
        available_fn {in_available_cb},
        error_fn {in_error_cb} { }

    virtual ~BufferInterfaceFunc() { }

    virtual void BufferAvailable(size_t in_amt) {
        if (available_fn != nullptr)
            available_fn(in_amt);
    }

    virtual void BufferError(std::string in_error) {
        if (error_fn != nullptr)
            error_fn(in_error);
    }

protected:
    std::function<void (size_t)> available_fn;
    std::function<void (std::string)> error_fn;
};

#endif


