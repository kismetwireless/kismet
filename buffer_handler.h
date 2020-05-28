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

struct common_buffer_cancel : public std::exception {
    const char *what () const throw () {
        return "operation cancelled";
    }
};

// Common buffer API
// Each buffer can be filled and drained; a typical communications channel will need 
// to use two buffers, one for rx and one for tx.
//
// The common buffer layer attempts to implement all needed thread protection around
// the buffer internals.
//
// Blocking variants are offered using the promise/future mechanism, whereby
// consumers can allocate threads which await new data.
class common_buffer {
public:
    common_buffer() :
        write_reserved {false},
        peek_reserved {false},
        free_peek {false},
        free_commit {false} { }

    virtual ~common_buffer() { };

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
    // Even reserve fails, a commit must be called to complete the transaction.
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
        if (timeout_duration == 0)
            ft.wait();
        else
            ft.wait_for(timeout_duration);

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
        if (timeout_duration == 0)
            ft.wait();
        else
            ft.wait_for(timeout_duration);

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
        if (timeout_duration == 0)
            ft.wait();
        else
            ft.wait_for(timeout_duration);

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
    void cancel_blocked_reserve() {
        try {
            try {
                throw common_buffer_cancel();
            } catch (const std::runtime_error& e) {
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
                throw common_buffer_cancel();
            } catch (const std::runtime_error& e) {
                write_size_avail_pm.set_exception(std::current_exception());
            }
        } catch (const std::future_error& e) {
            // Silently ignore if the future is invalid
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

// Pair interface for a buffer, to link the back-end drain/populate IO systems with the front-end
// parsers and protocol handlers.
//
// IO should primarily be done via blocking and a dedicated producer or consumer thread.
class buffer_pair {
public:
    buffer_pair(std::shared_ptr<common_buffer> in_rbuf,
            std::shared_ptr<common_buffer> in_wbuf) :
        read_buffer {in_rbuf},
        write_buffer {in_rbuf} { }

    virtual ~buffer_pair() {
        if (read_buffer != nullptr) {
            read_buffer->cancel_blocked_write();
            read_buffer->cancel_blocked_reserve();
        }

        if (write_buffer != nullptr) {
            write_buffer->cancel_blocked_write();
            write_buffer->cancel_blocked_reserve();
        }
    }

    virtual ssize_t size_rbuf() {
        if (read_buffer != nullptr) 
            return read_buffer->size();

        return -1;
    }

    virtual ssize_t size_wbuf() {
        if (write_buffer != nullptr)
            return write_buffer->size();

        return -1;
    }

    virtual ssize_t used_rbuf() {
        if (read_buffer != nullptr)
            return read_buffer->used();

        return -1;
    }

    virtual ssize_t used_wbuf() {
        if (write_buffer != nullptr)
            return write_buffer->used();

        return -1;
    }


    virtual ssize_t available_rbuf() {
        if (read_buffer != nullptr)
            return read_buffer->available();

        return -1;
    }

    virtual ssize_t available_wbuf() {
        if (write_buffer != nullptr)
            return write_buffer->available();

        return -1;
    }


    virtual void clear_rbuf() {
        if (read_buffer != nullptr) {
            read_buffer->cancel_blocked_reserve();
            read_buffer->clear();
        }
    }

    virtual void clear_wbuf() {
        if (write_buffer != nullptr) {
            write_buffer->cancel_blocked_reserve();
            write_buffer->clear();
        }
    }


    template< class Rep, class Period>
    ssize_t peek_block_rbuf(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (read_buffer != nullptr)
            return read_buffer->peek_block(data, in_sz, timeout_duration);

        return -1;
    }

    template< class Rep, class Period>
    ssize_t peek_block_wbuf(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (write_buffer != nullptr)
            return write_buffer->peek_block(data, in_sz, timeout_duration);

        return -1;
    }

    ssize_t zero_copy_peek_rbuf(char **data, size_t in_sz) {
        if (read_buffer != nullptr)
            return read_buffer->zero_copy_peek(data, in_sz);

        return -1;
    }

    ssize_t zero_copy_peek_wbuf(char **data, size_t in_sz) {
        if (write_buffer != nullptr)
            return write_buffer->zero_copy_peek(data, in_sz);

        return -1;
    }

    void peek_free_rbuf(char *data) {
        if (read_buffer != nullptr)
            return read_buffer->peek_free(data);

        return;
    }

    void peek_free_wbuf(char *data) {
        if (write_buffer != nullptr)
            return write_buffer->peek_free(data);

        return;
    }

    size_t consume_rbuf(size_t in_sz) {
        if (read_buffer != nullptr) 
            return read_buffer->consume(in_sz);

        return 0;
    }

    size_t consume_wbuf(size_t in_sz) {
        if (write_buffer != nullptr)
            return write_buffer->consume(in_sz);

        return 0;
    }


    template< class Rep, class Period>
    ssize_t reserve_block_rbuf(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (read_buffer != nullptr)
            return read_buffer->reserve_block(data, in_sz,timeout_duration);

        return -1;
    }

    template< class Rep, class Period>
    ssize_t reserve_block_wbuf(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (write_buffer != nullptr)
            return write_buffer->reserve_block(data, in_sz,timeout_duration);

        return -1;
    }

    size_t zero_copy_reserve_rbuf(char **data, size_t in_sz) {
        if (read_buffer != nullptr)
            return read_buffer->zero_copy_reserve(data, in_sz);

        return 0;
    }

    size_t zero_copy_reserve_wbuf(char **data, size_t in_sz) {
        if (write_buffer != nullptr)
            return write_buffer->zero_copy_reserve(data, in_sz);

        return 0;
    }

    bool commit_rbuf(char *data, size_t in_sz) {
        if (read_buffer != nullptr)
            return read_buffer->commit(data, in_sz);

        return false;
    }

    bool commit_wbuf(char *data, size_t in_sz) {
        if (write_buffer != nullptr)
            return write_buffer->commit(data, in_sz);

        return false;
    }



    template< class Rep, class Period>
    ssize_t write_block_rbuf(char *data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (read_buffer != nullptr)
            return read_buffer->write_block(data, in_sz, timeout_duration);

        return -1;
    }

    template< class Rep, class Period>
    ssize_t write_block_wbuf(const char *data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (write_buffer != nullptr)
            return write_buffer->write_block(data, in_sz, timeout_duration);

        return -1;
    }


    void throw_error(std::exception_ptr e) {
        if (read_buffer != nullptr)
            read_buffer->set_exception(e);
        if (write_buffer != nullptr)
            write_buffer->set_exception(e);
    }

protected:
    std::shared_ptr<common_buffer> read_buffer;
    std::shared_ptr<common_buffer> write_buffer;
};

// A C++ streambuf-compatible interface to a buffer pair
template<class Rep, class Period>
struct buffer_pair_ostream : public std::streambuf {
    buffer_pair_ostream(std::shared_ptr<buffer_pair> in_pair) :
        handler {in_pair},
        timeout_duration {std::chrono::seconds(0)} { }
    buffer_pair_ostream(std::shared_ptr<buffer_pair> in_pair,
            const std::chrono::duration<Rep,Period> timeout_duration) :
        handler {in_pair},
        timeout_duration {timeout_duration} { }

    virtual ~buffer_pair_ostream() { }

protected:
    std::streamsize xsputn(const char_type *s, std::streamsize n) override {
        // In the rewrite to a blocking model this now requires the buffer to be able to hold the 
        // incoming data; detect and throw if this will never be the case for now, if we hit this,
        // we'll have to figure out how to rewrite to handle this cleanly in the future.
        if (static_cast<ssize_t>(n) > handler->size_wbuf())
            throw std::runtime_error(fmt::format("backing buffer behind buffer_pair_ostream size {}, "
                        "can never hold {}", handler->size_wbuf(), n));

        ssize_t written = handler->write_block_wbuf(static_cast<const char *>(s), 
                static_cast<size_t>(n), timeout_duration);

        if (written == n)
            return n;

        return -1;
    }

    int_type overflow(int_type ch) override { 
        if (handler->write_block_wbuf(reinterpret_cast<const char *>(&ch), 1, timeout_duration) == 1)
            return 1;

        return -1;
    }

private:
    std::shared_ptr<buffer_pair> handler;
    std::chrono::duration<Rep,Period> timeout_duration;
};

// A C++ streambuf-compatible interface to a buffer pair, with an interstitial stringbuf buffer
template<class Rep, class Period>
struct buffer_pair_ostringstream : public std::stringbuf {
    buffer_pair_ostringstream(std::shared_ptr<buffer_pair> in_pair) :
        handler {in_pair} { }
    virtual ~buffer_pair_ostringstream() { }

protected:
    // Wrap the stringbuf functions 
    std::streamsize xsputn(const char_type *s, std::streamsize n) override {
        auto sz = std::stringbuf::xsputn(s, n);

        if (str().length() >= 1024) {
            sync();
        }

        return sz;
    }

    int_type overflow(int_type ch) override {
        auto it = std::stringbuf::overflow(ch);

        if (str().length() >= 1024) {
            sync();
        }

        return it;
    }

    int sync() override {
        auto sz = str().length();

        auto written =
            handler->write_block_wbuf(static_cast<const char *>(str().data()), sz, timeout_duration);

        if (written != sz)
            return -1;

        str("");

        return 0;
    }

private:
    std::shared_ptr<buffer_pair> handler;
    std::chrono::duration<Rep,Period> timeout_duration;
};

#endif


