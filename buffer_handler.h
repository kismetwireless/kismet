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

#include <exception>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <stdlib.h>
#include <string>
#include <streambuf>

#include "kis_mutex.h"
#include "util.h"

class buffer_interface;

// Common minimal API for a buffer
class common_buffer {
public:
    common_buffer() :
        write_reserved {false},
        peek_reserved {false} { }

    virtual ~common_buffer() { };

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
// the low-level IO driver (often a kis_pollable) which reads and writes directly
// to the ring buffers.  The buffer handler then automatically calls bound 
// handlers for read/write events.
//
class buffer_handler_generic_locker;

class buffer_handler_generic {
public:
    buffer_handler_generic();
    buffer_handler_generic(std::shared_ptr<kis_recursive_timed_mutex> m);
    virtual ~buffer_handler_generic();

    virtual void set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent);
    virtual std::shared_ptr<kis_recursive_timed_mutex> get_mutex();

    // Basic size ops
    virtual ssize_t get_read_buffer_size();
    virtual ssize_t get_write_buffer_size();

    virtual size_t get_read_buffer_used();
    virtual size_t get_write_buffer_used();

    virtual ssize_t get_read_buffer_available();
    virtual ssize_t get_write_buffer_available();

    // Fetch read and write buffer data, up to in_amt.  Does not consume data.
    // When possible, minimizes copies; actual copy and memory use depends on the
    // lower-level buffer, and consumers should not rely on specific behaviors.
    //
    // Consumers MUST conclude a peek operation with peek_free_read_buffer_data(...) or
    // peek_free_write_buffer_data(...), and may not perform multiple peeks simultaneously;
    // refer to the comments for common_buffer
    //
    // Returns amount peeked
    virtual ssize_t peek_read_buffer_data(void **in_ptr, size_t in_sz);
    virtual ssize_t peek_write_buffer_data(void **in_ptr, size_t in_sz);

    // Perform a zero-copy (when possible) peek of the buffer.  Does not consume
    // data.  When possible, minimizes copying of data (or performs no copy of data),
    // and is suitable for draining a buffer to the IO system.
    virtual ssize_t zero_copy_peek_read_buffer_data(void **in_ptr, size_t in_sz);
    virtual ssize_t zero_copy_peek_write_buffer_data(void **in_ptr, size_t in_sz);

    virtual void peek_free_read_buffer_data(void *in_ptr);
    virtual void peek_free_write_buffer_data(void *in_ptr);

    // Consume data from the buffer.  Must not be called while there is pending 'peek'd 
    // data.
    //
    // Automatically triggers buffer drain callbacks
    virtual size_t consume_read_buffer_data(size_t in_sz);
    virtual size_t consume_write_buffer_data(size_t in_sz);

    // Place data in read or write buffer.  Performs a copy of the existing data and
    // writes it into the buffer.
    //
    // Automatically triggers callbacks
    //
    // Returns amount of data actually written
    virtual size_t put_read_buffer_data(void *in_ptr, size_t in_sz, bool in_atomic);
    virtual size_t put_write_buffer_data(void *in_ptr, size_t in_sz, bool in_atomic);

    // Place data, as a string, into the buffer as an atomic op; returns success 
    // or failure on placing the entire record.
    virtual bool put_read_buffer_data(std::string in_data);
    virtual bool put_write_buffer_data(std::string in_data);

    // Reserve space in the buffers; the returned pointer is suitable for direct
    // writing.  Whenever possible, this will be a zero-copy operation, however on
    // some buffer structures this may require copying of the data content to the
    // buffer.
    //
    // Callers must not make assumptions about the underlying structure of the buffer
    // or of the pointer they are given.
    //
    // Callers must conclude the write operation with commit_read_buffer_data(..) or
    // commit_write_buffer_data(..).
    //
    // Only one block of data may be reserved at a time.
    //
    // Returns the amount of data allocated in the reserved block
    virtual ssize_t reserve_read_buffer_data(void **in_ptr, size_t len);
    virtual ssize_t reserve_write_buffer_data(void **in_ptr, size_t len);

    // Reserve space in one of the buffers; Take excessive measures to make this a
    // zero-copy buffer, including reserving less size than requested.  This is most 
    // appropriate for incoming data streams being written to a buffer.
    //
    // Callers must conclude the write operation with commit_read_buffer_data(..) or
    // commit_write_buffer_data(..)
    //
    // Only one block of data may be reserved at a time.
    //
    // Returns the amount of data available in the reserved block
    virtual ssize_t zero_copy_reserve_read_buffer_data(void **in_ptr, size_t len);
    virtual ssize_t zero_copy_reserve_write_buffer_data(void **in_ptr, size_t len);
    

    // Commit a pending reserved data block to the buffer
    virtual bool commit_read_buffer_data(void *in_ptr, size_t in_sz);
    virtual bool commit_write_buffer_data(void *in_ptr, size_t in_sz);

    // Clear a buffer
    //
    // Completely empties a buffer, possibly freeing any memory associated with it 
    // if it's a dynamic buffer
    virtual void clear_read_buffer();
    virtual void clear_write_buffer();

    // Trigger callbacks directly
    virtual void trigger_write_callback(size_t in_sz);
    virtual void trigger_read_callback(size_t in_sz);

    // Set interface callbacks to be called when we have data in the buffers
    virtual void set_read_buffer_interface(buffer_interface *in_interface);
    virtual void set_write_buffer_interface(buffer_interface *in_interface);

    virtual void remove_read_buffer_interface();
    virtual void remove_write_buffer_interface();

    // Set simple functional callbacks to be called when we drain an interface; used to
    // allow quick unlocking of blocked writers
    virtual void set_read_buffer_drain_cb(std::function<void (size_t)> in_cb);
    virtual void set_write_buffer_drain_cb(std::function<void (size_t)> in_cb);

    virtual void remove_read_buffer_drain_cb();
    virtual void remove_write_buffer_drain_cb();

    // Propagate a line-layer buffer error to any listeners (line IO system to interfaces)
    virtual void buffer_error(std::string in_error);
    // Propagate an error to a specific listener
    virtual void read_buffer_error(std::string in_error);
    virtual void write_buffer_error(std::string in_error);

    // Propagate a protocol-layer error to any line-drivers (protocol parser
    // to line drivers).  We don't pass a string to the line drivers because
    // the protocol driver should present the error usefully
    virtual void protocol_error();
    // Set a protocol error callback; line level drivers should set this and initiate
    // a shutdown of the line connections
    virtual void set_protocol_error_cb(std::function<void (void)> in_cb);

    friend class buffer_handler_generic_locker;

protected:
    // Generic buffers
    common_buffer *read_buffer;
    common_buffer *write_buffer;

    // Interfaces we notify when there has been activity on a buffer; use atomic booleans
    // to indicate if the function is available
    std::atomic<bool> wbuf_notify_avail, rbuf_notify_avail;
    buffer_interface *wbuf_notify;
    buffer_interface *rbuf_notify;

    std::shared_ptr<kis_recursive_timed_mutex> handler_mutex;

    std::function<void (void)> protoerror_cb;

    std::atomic<bool> wbuf_drain_avail, rbuf_drain_avail;
    std::function<void (size_t)> writebuf_drain_cb;
    std::function<void (size_t)> readbuf_drain_cb;
};

template<class B> 
class buffer_handler : public buffer_handler_generic {
public:
    // For one-way buffers, define a buffer as having a size of zero
    buffer_handler(size_t r_buffer_sz, size_t w_buffer_sz) :
        buffer_handler_generic() {
        if (r_buffer_sz != 0)
            read_buffer = new B(r_buffer_sz);
        else
            read_buffer = NULL;

        if (w_buffer_sz != 0)
            write_buffer = new B(w_buffer_sz);
        else
            write_buffer = NULL;
    }

    buffer_handler(size_t r_buffer_sz, size_t w_buffer_sz, std::shared_ptr<kis_recursive_timed_mutex> m) :
        buffer_handler_generic(m) {
        if (r_buffer_sz != 0)
            read_buffer = new B(r_buffer_sz);
        else
            read_buffer = NULL;

        if (w_buffer_sz != 0)
            write_buffer = new B(w_buffer_sz);
        else
            write_buffer = NULL;
    }

    buffer_handler(B *r_buf, B *w_buf) {
        read_buffer = r_buf;
        write_buffer = w_buf;
    }
};

// A C++ streambuf-compatible wrapper around a buf handler
struct buffer_handler_ostream_buf : public std::streambuf {
    buffer_handler_ostream_buf(std::shared_ptr<buffer_handler_generic > in_rbhandler) :
        rb_handler(in_rbhandler), blocking(false) { }
    buffer_handler_ostream_buf(std::shared_ptr<buffer_handler_generic > in_rbhandler, bool in_blocking) :
        rb_handler(in_rbhandler), blocking(in_blocking) { }

    virtual ~buffer_handler_ostream_buf();

protected:
    std::streamsize xsputn(const char_type *s, std::streamsize n) override;
    int_type overflow(int_type ch) override;

private:
    // buf handler we bind to
    std::shared_ptr<buffer_handler_generic > rb_handler;

    // Do we block when buffer is full?
    bool blocking;

    // Locker variable if we block
    std::shared_ptr<conditional_locker<size_t> > blocking_cl;
};

// A C++ streambuf-compatible wrapper around a buf handler with an interstitial string
// cache
struct buffer_handler_ostringstream_buf : public std::stringbuf {
    buffer_handler_ostringstream_buf(std::shared_ptr<buffer_handler_generic > in_rbhandler) :
        rb_handler(in_rbhandler) { }

    virtual ~buffer_handler_ostringstream_buf();

protected:
    // Wrap the stringbuf functions 
    std::streamsize xsputn(const char_type *s, std::streamsize n) override;
    int_type overflow(int_type ch) override;

    int sync() override;

private:
    kis_recursive_timed_mutex mutex;

    // buf handler we bind to
    std::shared_ptr<buffer_handler_generic > rb_handler;
    
};


// buffer interface, interacts with a buffer handler 
class buffer_interface {
public:
    buffer_interface();
    virtual ~buffer_interface();

    // Called when the linked buffer has new data available
    virtual void buffer_available(size_t in_amt) = 0;

    // Called when a buffer encounters an error
    virtual void buffer_error(std::string in_error __attribute__((unused))) { }

protected:
    buffer_handler_generic *bufferhandler;
    bool read_handler;
    bool write_handler;
};

class buffer_interface_func : public buffer_interface {
public:
    buffer_interface_func(std::function<void (size_t)> in_available_cb,
            std::function<void (std::string)> in_error_cb) : 
        buffer_interface(),
        available_fn {in_available_cb},
        error_fn {in_error_cb} { }

    virtual ~buffer_interface_func() { }

    virtual void buffer_available(size_t in_amt) {
        if (available_fn != nullptr)
            available_fn(in_amt);
    }

    virtual void buffer_error(std::string in_error) {
        if (error_fn != nullptr)
            error_fn(in_error);
    }

protected:
    std::function<void (size_t)> available_fn;
    std::function<void (std::string)> error_fn;
};

// Common buffer v2 API
//
// Abstracted buffer IO with most logic in the abstraction layer.
//
// Designed around using futures and promises to provide blocking IO to dedicated protocol threads.
//
// Each buffer can be filled and drained; a typical communications channel will need 
// to use two buffers, one for rx and one for tx.
//
// The common buffer layer attempts to implement all needed thread protection around
// the buffer internals.
//
// Blocking variants are offered using the promise/future mechanism, whereby
// consumers can allocate threads which await new data.
//
struct common_buffer_v2_cancel : public std::exception {
    const char *what () const throw () {
        return "operation cancelled";
    }
};

struct common_buffer_v2_timeout : public std::exception {
    const char *what() const throw () {
        return "timeout";
    }
};

struct common_buffer_v2_close : public std::exception {
    common_buffer_v2_close(const std::string& w) :
        err{w} { }

    const char *what() const throw () {
        return err.c_str();
    }

    std::string err;
};

class common_buffer_v2 {
public:
    common_buffer_v2() :
        write_reserved {false},
        peek_reserved {false},
        free_peek {false},
        free_commit {false} { }

    virtual ~common_buffer_v2() { };

    // Clear all data (and free memory used, for dynamic buffers)
    void clear() {
        local_locker l(&write_mutex);
        clear_impl();
    }

    // Fetch total size of buffer; -1 indicates unbounded dynamic buffer
    ssize_t size() {
        return size_impl();
    }

    // Fetch available space in buffer, -1 indicates unbounded dynamic buffer
    ssize_t available() {
        return available_impl();
    }

    // Block until any new amount of data is available; useful for non-packet streamers
    template< class Rep, class Period>
    ssize_t new_available_block(const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (wanted_read_sz > 0)
            throw std::runtime_error("attempt to block for available while blocking for read");

        wanted_read_sz = 1;
        read_size_avail_pm = std::promise<bool>();
        auto ft = read_size_avail_pm.get_future();

        // Wait for it
        if (timeout_duration == std::chrono::duration<Rep,Period>(0)) {
            ft.wait();
        } else {
            auto r = ft.wait_for(timeout_duration);
            if (r == std::future_status::timeout)
                throw common_buffer_v2_timeout();
            else if (r == std::future_status::deferred)
                throw std::runtime_error("attempt to block for available with no future");
        }

        return available();
    }

    ssize_t new_available_block() {
        return new_available_block(std::chrono::seconds(0));
    }

    // Fetch amount used in current buffer
    size_t used() {
        return used_impl();
    }

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
    // commit will fail.
    //
    // Even if the reserve fails, a commit must be called to complete the transaction.
    //
    // A reserved block must be committed.  At the time of reservation, a reserved
    // block is guaranteed to fit in the buffer.
    ssize_t reserve(char **data, size_t in_sz)  {
        local_eol_locker wl(&write_mutex);

        if (write_reserved) {
            throw std::runtime_error("buffer reserve already locked");
        }

        write_reserved = true;
        free_commit = false;

        if (in_sz == 0) {
            return 0;
        }

        return reserve_impl(data, in_sz);
    }

    // Perform a blocking version of a reserve
    template< class Rep, class Period>
    ssize_t reserve_block(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        // Perform a normal reserve
        auto r = reserve(data, in_sz);

        if (r == static_cast<ssize_t>(in_sz))
            return r;

        commit(*data, 0);

        if (wanted_write_sz > 0)
            throw std::runtime_error("attempt to reserve while blocking for write");

        wanted_write_sz = in_sz;
        write_size_avail_pm = std::promise<bool>();
        auto ft = write_size_avail_pm.get_future();

        // Wait for it
        if (timeout_duration == 0) {
            ft.wait();
        } else {
            auto r = ft.wait_for(timeout_duration);
            if (r == std::future_status::timeout)
                throw common_buffer_v2_timeout();
            else if (r == std::future_status::deferred)
                throw std::runtime_error("attempt to block for reserve write with no future");
        }

        reserve(data, in_sz);
    }

    // Reserve as much space as possible, up to in_sz, and do as much as possible to 
    // ensure it is a zero-copy buffer.
    //
    // A zero-copy reservation may be smaller than the requested reservation size.
    //
    // Only one reservation may be made at a time.
    //
    // The caller must commit the reserved data.
    size_t zero_copy_reserve(char **data, size_t in_sz) {
        local_eol_locker wl(&write_mutex);

        if (write_reserved) {
            throw std::runtime_error("buffer zero_copy_reserve already locked");
        }

        write_reserved = true;
        free_commit = false;

        if (in_sz == 0) {
            return 0;
        }

        if (available() < static_cast<ssize_t>(in_sz)) {
            return 0;
        }

        return zero_copy_reserve_impl(data, in_sz);

    }

    // Commit changes to the reserved block
    //
    // Implementations should release the write_mutex lock 
    bool commit(char *data, size_t in_sz) {
        if (!write_reserved)
            throw std::runtime_error("buffer commit, but no reserved data");

        local_unlocker uwl(&write_mutex);

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

            if ((size_t) written != in_sz)
                return false;
        } else {
            if (in_sz == 0)
                return true;

            ssize_t written = write(NULL, in_sz);

            if (written < 0)
                return false;

            if ((size_t) written != in_sz)
                return false;
        }

        // Wake up any pending future
        if (wanted_read_sz > 0) {
            wanted_read_sz -= in_sz;

            if (wanted_read_sz <= 0) {
                try {
                    read_size_avail_pm.set_value(true);
                } catch (const std::future_error& e) {
                    ;
                }
            }
        }

        return true;
    }

    // Write an existing block of data to the buffer; this always performs a memcpy to copy 
    // the data into the buffer.  When possible, it is more efficient to use the 
    // reservation system.
    //
    // This may awaken pending reads awaiting data
    size_t write(const char *data, size_t in_sz) {
        local_locker writelock(&write_mutex);

        if (write_reserved) {
            throw std::runtime_error("buffer write already locked");
        }

        auto r = write_impl(data, in_sz);

        // Wake up any pending future
        if (wanted_read_sz > 0) {
            wanted_read_sz -= r;

            if (wanted_read_sz <= 0) {
                try {
                    read_size_avail_pm.set_value(true);
                } catch (const std::future_error& e) {
                    ;
                }
            }
        }

        return r;
    }

    // Perform a blocking version of write
    template< class Rep, class Period>
    ssize_t write_block(char *data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        // Write doesn't leave us locked, so set up an external lock here
        local_demand_locker l(&write_mutex);
        l.lock();

        // Perform a normal write
        auto r = write(data, in_sz);

        // If write succeeded, no reason to block for future
        if (r == (size_t) in_sz)
            return r;

        if (wanted_write_sz > 0)
            throw std::runtime_error("attempt to write while blocking for reserve");

        wanted_write_sz = in_sz;
        write_size_avail_pm = std::promise<bool>();
        auto ft = write_size_avail_pm.get_future();

        l.unlock();

        // Wait for it
        if (timeout_duration == std::chrono::duration<Rep, Period>(0)) {
            ft.wait();
        } else {
            auto r = ft.wait_for(timeout_duration);
            if (r == std::future_status::timeout)
                throw common_buffer_v2_timeout();
            else if (r == std::future_status::deferred)
                throw std::runtime_error("attempt to block for write with no future");
        }

        // Perform another write
        return write(data, in_sz);
    }

    // Peek data.  If possible, this will be a zero-copy operation, if not, it will 
    // allocate a buffer.  Content is returned in the **data pointer, which will be
    // a buffer of at least the returned size.
    //
    // Insufficient data available in the buffer will return a -1, but peek_free
    // MUST STILL BE CALLED.
    //
    // Callers MUST free the data with 'peek_free(...)'.  Buffer implementations MUST
    // track if the peeked data must be deleted or if it is a zero-copy reference.
    //
    // Only one piece of data may be peek'd at a time, additional attempts prior
    // to a peek_free will fail.  This includes peek() and zero_copy_peek()
    //
    // peek will perform a copy to fulfill the total data size if the underlying
    // buffer implementation cannot return a zero-copy reference; as such it is most 
    // appropriate for performing read operations of structured data where the entire
    // object must be available.
    size_t peek(char **data, size_t in_sz) {
        local_eol_locker peeklock(&write_mutex);

        if (peek_reserved) {
            peeklock.unlock();
            throw std::runtime_error("peek already locked");
        }

        return peek_impl(data, in_sz);
    }

    // Attempt a peek while blocking until at least the requested amount of
    // data is available.  Optimized to perform zero-copy peeks whenever possible.
    //
    // If timeout is 0, do not set a timeout (possibly dangerous).
    //
    // Failure to receive sufficient data within a timeout will throw an exception.
    template< class Rep, class Period>
    ssize_t peek_block(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {

        // Perform a normal peek
        auto r = peek(data, in_sz);

        // If peek succeeded, no reason to block for future
        if (r == (size_t) in_sz)
            return r;

        // Note how much we want
        wanted_read_sz = in_sz;

        // Initialize the promise
        read_size_avail_pm = std::promise<bool>();

        // Get a future to pend on
        auto ft = read_size_avail_pm.get_future();

        // Free the peek (and release the write lock) so that additional data can be 
        // written to the buffer to meet our requirements
        peek_free(*data);

        // Wait for it
        if (timeout_duration == std::chrono::duration<Rep, Period>(0)) {
            ft.wait();
        } else {
            auto r = ft.wait_for(timeout_duration);
            if (r == std::future_status::timeout)
                throw common_buffer_v2_timeout();
            else if (r == std::future_status::deferred)
                throw std::runtime_error("attempt to block for peek with no future");
        }

        // Perform another peek
        return peek(data, in_sz);
    }


    // Attempt a zero-copy peek; if the underlying buffer supports zero-copy references
    // this will return a direct pointer to the buffer contents; if the underlying buffer
    // does not, it may allocate memory and perform a copy.
    //
    // Callers MUST free the data with 'peek_free(...)'.  Buffer implementations MUST
    // track if the peeked data must be deleted or if it is a zero-copy reference.
    //
    // zero_copy_peek will NEVER allocate and copy a buffer when a no-copy shorter
    // buffer is available; This is most suited for draining buffers to an IO system
    // where the exact record length is not relevant; any common io for filling a structure
    // should use normal peek.
    //
    // Only one piece of data may be peek'd at a time, additional attempts prior
    // to a peek_free will fail; this includes peek() and zero_copy_peek()
    ssize_t zero_copy_peek(char **data, size_t in_sz) {
        local_eol_locker peeklock(&write_mutex);

        if (peek_reserved) {
            peeklock.unlock();
            throw std::runtime_error("buffer peek while peek already locked");
        }

        return zero_copy_peek_impl(data, in_sz);
    }

    // Deallocate peeked data; implementations should also use this time to release
    // the peek_mutex lock on peek data
    void peek_free(char *data) {
        local_unlocker unpeeklock(&write_mutex);

        if (!peek_reserved) {
            throw std::runtime_error("peek_free on unpeeked buffer");
        }

        peek_free_impl(data);

        peek_reserved = false;
        free_peek = false;
    }

    // Remove data from a buffer (which may awaken a pending write)
    size_t consume(size_t in_sz)  {
        // Protect cross-thread
        local_locker peeklock(&write_mutex);

        if (peek_reserved) {
            throw std::runtime_error("buffer consume while peeked data pending");
        }

        if (write_reserved) {
            throw std::runtime_error("buffer consume while reserved data pending");
        }

        auto r = consume_impl(in_sz);

        if (wanted_write_sz > 0) {
            wanted_write_sz -= r;

            if (wanted_write_sz <= 0) {
                try {
                    write_size_avail_pm.set_value(true);
                } catch (const std::future_error& e) {
                    ;
                }
            }
        }

        return r;
    }

    // Cancel pending operations
    void cancel() {
        cancel_blocked_reserve();
        cancel_blocked_write();
    }

    void cancel_blocked_reserve() {
        try {
            try {
                throw common_buffer_v2_cancel();
            } catch (const std::exception& e) {
                read_size_avail_pm.set_exception(std::current_exception());
            }
        } catch (const std::future_error& e) {
            // Silently ignore if the future is invalid
            ;
        }
    }

    void cancel_blocked_write() {
        try {
            try {
                throw common_buffer_v2_cancel();
            } catch (const std::exception& e) {
                write_size_avail_pm.set_exception(std::current_exception());
            }
        } catch (const std::future_error& e) {
            // Silently ignore if the future is invalid
            ;
        }
    }

    // Close down - throw an error that a listener should interpret as a terminal, but not actionable, signal
    void close(const std::string& e) {
        try {
            try {
                throw common_buffer_v2_close(e);
            } catch (const std::runtime_error& e) {
                read_size_avail_pm.set_exception(std::current_exception());
            }
        } catch (const std::future_error& e) {
            ;
        }

        try {
            try {
                throw common_buffer_v2_close(e);
            } catch (const std::runtime_error& e) {
                write_size_avail_pm.set_exception(std::current_exception());
            }
        } catch (const std::future_error& e) {
            ;
        }
    }

    // Error pending operations, with an exception; this will send the exception to
    // any blocking/pending operations.
    void set_exception(std::exception_ptr e) {
        try {
            write_size_avail_pm.set_exception(e);
        } catch (const std::future_error& e) {
            ;
        }

        try {
            read_size_avail_pm.set_exception(e);
        } catch (const std::future_error& e) {
            ;
        }
    }

protected:
    virtual void clear_impl() = 0;
    virtual ssize_t size_impl() = 0;
    virtual ssize_t available_impl() = 0;
    virtual size_t used_impl() = 0;
    virtual ssize_t reserve_impl(char **data, size_t in_sz) = 0;
    virtual ssize_t zero_copy_reserve_impl(char **data, size_t in_sz) = 0;
    virtual ssize_t write_impl(const char *data, size_t in_sz) = 0;
    virtual ssize_t peek_impl(char **data, size_t in_sz) = 0;
    virtual ssize_t zero_copy_peek_impl(char **data, size_t in_sz) = 0;
    virtual void peek_free_impl(char *data) = 0;
    virtual size_t consume_impl(size_t in_sz) = 0;

    std::atomic<bool> write_reserved;
    std::atomic<bool> peek_reserved;
    std::atomic<bool> free_peek, free_commit;

    // Pending unfulfillable write and read counts, if we're blocking
    std::atomic<ssize_t> wanted_write_sz;
    std::atomic<ssize_t> wanted_read_sz;

    // Promise fulfilled when pending write space is available
    std::promise<bool> write_size_avail_pm;
    std::future<bool> write_size_avail_ft;

    // Promise fulfilled when pending read data is available
    std::promise<bool> read_size_avail_pm;
    std::future<bool> read_size_avail_ft;

    // Additional mutex for protecting peek and write reservations across threads
    kis_recursive_timed_mutex peek_mutex, write_mutex;
};


#endif


