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

#ifndef __BUFFER_PAIR__
#define __BUFFER_PAIR__ 

#include "config.h"

#include "buffer_handler.h"

// Pair interface for a buffer, to link the back-end drain/populate IO systems with the front-end
// parsers and protocol handlers.
//
// IO should primarily be done via blocking and a dedicated producer or consumer thread.
class buffer_pair {
public:
    buffer_pair(std::shared_ptr<common_buffer_v2> in_rbuf,
            std::shared_ptr<common_buffer_v2> in_wbuf) :
        read_buffer {in_rbuf},
        write_buffer {in_rbuf},
		aux {nullptr} { }

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

    template< class Rep, class Period>
    ssize_t new_available_block_rbuf(const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (read_buffer != nullptr)
            return read_buffer->new_available_block(timeout_duration);

        return -1;
    }

    ssize_t new_available_block_rbuf() {
        return new_available_block_rbuf(std::chrono::seconds(0));
    }

    template< class Rep, class Period>
    ssize_t new_available_block_wbuf(const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (write_buffer != nullptr)
            return read_buffer->new_available_block(timeout_duration);

        return -1;
    }

    ssize_t new_available_block_wbuf() {
        return new_available_block_wbuf(std::chrono::seconds(0));
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
            return read_buffer->reserve_block(data, in_sz, timeout_duration);

        return -1;
    }

    template< class Rep, class Period>
    ssize_t reserve_block_wbuf(char **data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (write_buffer != nullptr)
            return write_buffer->reserve_block(data, in_sz, timeout_duration);

        return -1;
    }

    ssize_t reserve_rbuf(char **data, size_t in_sz) {
        if (read_buffer != nullptr)
            return read_buffer->reserve(data, in_sz);

        return -1;
    }

    ssize_t reserve_wbuf(char **data, size_t in_sz) {
        if (write_buffer != nullptr)
            return write_buffer->reserve(data, in_sz);

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
    ssize_t write_block_rbuf(void *data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (read_buffer != nullptr)
            return read_buffer->write_block((char *) data, in_sz, timeout_duration);

        return -1;
    }

    ssize_t write_rbuf(const void *data, size_t in_sz) {
        if (read_buffer != nullptr)
            return read_buffer->write((const char *) data, in_sz);
        return -1;
    }

    ssize_t write_rbuf(const std::string& data) {
        return write_rbuf(data.data(), data.size());
    }

    template< class Rep, class Period>
    ssize_t write_block_wbuf(void *data, size_t in_sz,
            const std::chrono::duration<Rep,Period>& timeout_duration) {
        if (write_buffer != nullptr)
            return write_buffer->write_block((char *) data, in_sz, timeout_duration);

        return -1;
    }

    ssize_t write_wbuf(const void *data, size_t in_sz) {
        if (write_buffer != nullptr)
            return write_buffer->write((const char *) data, in_sz);
        return -1;
    }

    ssize_t write_wbuf(const std::string& data) {
        return write_wbuf(data.data(), data.size());
    }

    // Cancel pending IO on the buffers with a 'gentle' exception, and call any existing cancel callback
    void close(const std::string& e) {
        local_locker l(&mutex, "buffer_pair::close");

        if (read_buffer != nullptr)
            read_buffer->close(e);
        if (write_buffer != nullptr)
            write_buffer->close(e);

        if (close_cb)
            close_cb();
    }

    // Propagate an error as an exception to both buffers, call an error cb if one exists
    void error(const std::string& e) {
        local_locker l(&mutex, "buffer_pair::error");

        try {
            throw std::runtime_error(e);
        } catch (std::exception& e) {
            if (read_buffer != nullptr)
                read_buffer->set_exception(std::current_exception());
            if (write_buffer != nullptr)
                write_buffer->set_exception(std::current_exception());
        }

        if (error_cb)
            error_cb();
    }

	template<typename... Args> 
	void error(const char *f, Args... args) {
		error(fmt::format(f, args...));
	}

    // Throw a specific exception to both buffers, call error cb if one exists
    void throw_error(std::exception_ptr e) {
        local_locker l(&mutex, "buffer_pair::throw_error");

        if (read_buffer != nullptr)
            read_buffer->set_exception(e);
        if (write_buffer != nullptr)
            write_buffer->set_exception(e);

        if (error_cb)
            error_cb();
    }

    void set_close_cb(std::function<void (void)> cb) {
        local_locker l(&mutex, "buffer_pair::set_close_cb");
        close_cb = cb;
    }

    void set_error_cb(std::function<void (void)> cb) {
        local_locker l(&mutex, "buffer_pair::set_error_cb");
        error_cb = cb;
    }

	void set_aux(void *in_aux) {
		aux = in_aux;
	}

	void *get_aux() {
		return aux;
	}

protected:
    kis_recursive_timed_mutex mutex;

    std::function<void (void)> close_cb;
    std::function<void (void)> error_cb;

    std::shared_ptr<common_buffer_v2> read_buffer;
    std::shared_ptr<common_buffer_v2> write_buffer;

	void *aux;
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


#endif /* ifndef BUFFER_PAIR */
