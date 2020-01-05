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

#include "config.h"

#include <stdlib.h>

#include "util.h"
#include "buffer_handler.h"

buffer_handler_generic::buffer_handler_generic() :
    read_buffer {nullptr},
    write_buffer {nullptr},
    wbuf_notify_avail {false},
    rbuf_notify_avail {false},
    handler_mutex {std::make_shared<kis_recursive_timed_mutex>()},
    wbuf_drain_avail {false},
    rbuf_drain_avail {false},
    writebuf_drain_cb {nullptr},
    readbuf_drain_cb {nullptr} { }

buffer_handler_generic::buffer_handler_generic(std::shared_ptr<kis_recursive_timed_mutex> m) :
    read_buffer {nullptr},
    write_buffer {nullptr},
    wbuf_notify_avail {false},
    rbuf_notify_avail {false},
    handler_mutex {m},
    wbuf_drain_avail {false},
    rbuf_drain_avail {false},
    writebuf_drain_cb {nullptr},
    readbuf_drain_cb {nullptr} { }

buffer_handler_generic::~buffer_handler_generic() {
    if (read_buffer)
        delete read_buffer;

    if (write_buffer)
        delete write_buffer;
}

void buffer_handler_generic::set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    if (in_parent != nullptr && in_parent == handler_mutex)
        return;

    if (in_parent == nullptr)
        in_parent = std::make_shared<kis_recursive_timed_mutex>();

    // Lock as we acquire parent
    local_locker l(in_parent);

    // Any lock holding the handler mutex should already have it
    handler_mutex = in_parent;
}

std::shared_ptr<kis_recursive_timed_mutex> buffer_handler_generic::get_mutex() {
    local_locker l(handler_mutex);

    return handler_mutex;
}

ssize_t buffer_handler_generic::get_read_buffer_size() {
    if (read_buffer)
        return read_buffer->size();

    return 0;
}

ssize_t buffer_handler_generic::get_write_buffer_size() {
    if (write_buffer)
        return write_buffer->size();

    return 0;
}

size_t buffer_handler_generic::get_read_buffer_used() {
    if (read_buffer)
        return read_buffer->used();

    return 0;
}

size_t buffer_handler_generic::get_write_buffer_used() {
    if (write_buffer)
        return write_buffer->used();

    return 0;
}

ssize_t buffer_handler_generic::get_read_buffer_available() {
    if (read_buffer)
        return read_buffer->available();

    return 0;
}

ssize_t buffer_handler_generic::get_write_buffer_available() {
    if (write_buffer)
        return write_buffer->available();

    return 0;
}

ssize_t buffer_handler_generic::peek_read_buffer_data(void **in_ptr, size_t in_sz) {
    if (in_ptr == NULL)
        return 0;

    if (read_buffer)
        return read_buffer->peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

ssize_t buffer_handler_generic::peek_write_buffer_data(void **in_ptr, size_t in_sz) {
    if (write_buffer)
        return write_buffer->peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

ssize_t buffer_handler_generic::zero_copy_peek_read_buffer_data(void **in_ptr, size_t in_sz) {
    if (in_ptr == NULL)
        return 0;

    if (read_buffer)
        return read_buffer->zero_copy_peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

ssize_t buffer_handler_generic::zero_copy_peek_write_buffer_data(void **in_ptr, size_t in_sz) {
    if (write_buffer)
        return write_buffer->zero_copy_peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

void buffer_handler_generic::peek_free_read_buffer_data(void *in_ptr) {
    if (read_buffer)
        return read_buffer->peek_free((unsigned char *) in_ptr);

    return;
}

void buffer_handler_generic::peek_free_write_buffer_data(void *in_ptr) {
    if (write_buffer)
        return write_buffer->peek_free((unsigned char *) in_ptr);

    return;
}

size_t buffer_handler_generic::consume_read_buffer_data(size_t in_sz) {
    size_t sz;

    if (read_buffer) {
        sz = read_buffer->consume(in_sz);

        if (rbuf_drain_avail && readbuf_drain_cb) {
            readbuf_drain_cb(sz);
        }
    }

    return 0;
}

size_t buffer_handler_generic::consume_write_buffer_data(size_t in_sz) {
    size_t sz;

    if (write_buffer) {
        sz = write_buffer->consume(in_sz);

        if (wbuf_drain_avail && writebuf_drain_cb) {
            writebuf_drain_cb(sz);
        }
    }

    return 0;
}


size_t buffer_handler_generic::put_read_buffer_data(void *in_ptr, size_t in_sz, 
        bool in_atomic) {
    size_t ret;

    {
        local_locker hlock(handler_mutex);

        if (!read_buffer)
            return 0;

        // Don't write any if we're an atomic complete write; buffers which report
        // -1 for available size are infinite
        if (in_atomic && read_buffer->available() >= 0 && 
                (size_t) read_buffer->available() < in_sz)
            return 0;

        ret = read_buffer->write((unsigned char *) in_ptr, in_sz);

    }

    if (rbuf_notify_avail && rbuf_notify) {
        if (ret != in_sz)
            rbuf_notify->buffer_error("insufficient space in buffer");
        rbuf_notify->buffer_available(ret);
    }

    return ret;
}

bool buffer_handler_generic::put_read_buffer_data(std::string in_data) {
    size_t r =
        put_read_buffer_data((void *) in_data.data(), in_data.length(), true);
    return (r == in_data.length());
}

bool buffer_handler_generic::put_write_buffer_data(std::string in_data) {
    size_t r =
        put_write_buffer_data((void *) in_data.data(), in_data.length(), true);
    return (r == in_data.length());
}

    
size_t buffer_handler_generic::put_write_buffer_data(void *in_ptr, size_t in_sz, bool in_atomic) {
    size_t ret;

    {
        local_locker hlock(handler_mutex);

        if (!write_buffer) {
            if (wbuf_notify)
                wbuf_notify->buffer_error("No write buffer connected");

            return 0;
        }

        // Don't write any if we're an atomic complete write; buffers which report
        // -1 for available size are infinite
        if (in_atomic && write_buffer->available() >= 0 &&
                (size_t) write_buffer->available() < in_sz)
            return 0;

        ret = write_buffer->write((unsigned char *) in_ptr, in_sz);
    }

    if (wbuf_notify_avail && wbuf_notify) {
        if (ret != in_sz)
            wbuf_notify->buffer_error("insufficient space in buffer");

        wbuf_notify->buffer_available(ret);
    }

    return ret;
}

ssize_t buffer_handler_generic::reserve_read_buffer_data(void **in_ptr, size_t in_sz) {
    local_locker hlock(handler_mutex);

    if (read_buffer != NULL) {
        return read_buffer->reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

ssize_t buffer_handler_generic::reserve_write_buffer_data(void **in_ptr, size_t in_sz) {
    local_locker hlock(handler_mutex);

    if (write_buffer != NULL) {
        return write_buffer->reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

ssize_t buffer_handler_generic::zero_copy_reserve_read_buffer_data(void **in_ptr, size_t in_sz) {
    local_locker hlock(handler_mutex);

    if (read_buffer != NULL) {
        return read_buffer->zero_copy_reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

ssize_t buffer_handler_generic::zero_copy_reserve_write_buffer_data(void **in_ptr, size_t in_sz) {
    local_locker hlock(handler_mutex);

    if (write_buffer != NULL) {
        return write_buffer->zero_copy_reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

void buffer_handler_generic::trigger_write_callback(size_t in_sz) {
    if (wbuf_notify_avail && wbuf_notify) {
        wbuf_notify->buffer_available(in_sz);
    }
}

void buffer_handler_generic::trigger_read_callback(size_t in_sz) {
    if (rbuf_notify_avail && rbuf_notify) {
        rbuf_notify->buffer_available(in_sz);
    }
}

bool buffer_handler_generic::commit_read_buffer_data(void *in_ptr, size_t in_sz) {
    bool s = false;

    {
        local_locker hlock(handler_mutex);

        if (read_buffer != NULL) {
            s = read_buffer->commit((unsigned char *) in_ptr, in_sz);
        }
    }

    if (rbuf_notify_avail && rbuf_notify) {
        if (!s)
            rbuf_notify->buffer_error("error committing to read buffer");
        else
            rbuf_notify->buffer_available(in_sz);
    }

    return s;
}

bool buffer_handler_generic::commit_write_buffer_data(void *in_ptr, size_t in_sz) {
    bool s = false;

    {
        local_locker hlock(handler_mutex);
        if (write_buffer != NULL) {
            s = write_buffer->commit((unsigned char *) in_ptr, in_sz);
        }
    }

    if (wbuf_notify_avail && wbuf_notify) {
        if (!s)
            wbuf_notify->buffer_error("error committing to write buffer");
        else
            wbuf_notify->buffer_available(in_sz);
    }

    return s;
}

void buffer_handler_generic::clear_read_buffer() {
    if (read_buffer)
        read_buffer->clear();
}

void buffer_handler_generic::clear_write_buffer() {
    if (write_buffer)
        write_buffer->clear();
}

void buffer_handler_generic::set_read_buffer_interface(buffer_interface *in_interface) {
    rbuf_notify_avail = false;
    rbuf_notify = in_interface;
    rbuf_notify_avail = true;

    size_t pending = get_read_buffer_used();
    if (pending)
        rbuf_notify->buffer_available(pending);
}

void buffer_handler_generic::set_write_buffer_interface(buffer_interface *in_interface) {
    wbuf_notify_avail = false;
    wbuf_notify = in_interface;
    wbuf_notify_avail = true;

    size_t pending = get_write_buffer_used();

    if (pending)
        wbuf_notify->buffer_available(pending);
}

void buffer_handler_generic::remove_read_buffer_interface() {
    rbuf_notify_avail = false;
    rbuf_notify = nullptr;
}

void buffer_handler_generic::remove_write_buffer_interface() {
    wbuf_notify_avail = false;
    wbuf_notify = nullptr;
}

void buffer_handler_generic::set_read_buffer_drain_cb(std::function<void (size_t)> in_cb) {
    rbuf_drain_avail = false;
    readbuf_drain_cb = in_cb;
    rbuf_drain_avail = true;
}

void buffer_handler_generic::set_write_buffer_drain_cb(std::function<void (size_t)> in_cb) {
    wbuf_drain_avail = false;
    writebuf_drain_cb = in_cb;
    wbuf_drain_avail = true;
}

void buffer_handler_generic::remove_read_buffer_drain_cb() {
    rbuf_drain_avail = false;
    readbuf_drain_cb = nullptr;
}

void buffer_handler_generic::remove_write_buffer_drain_cb() {
    wbuf_drain_avail = false;
    writebuf_drain_cb = nullptr; 
}

void buffer_handler_generic::buffer_error(std::string in_error) {
    read_buffer_error(in_error);
    write_buffer_error(in_error);
}

void buffer_handler_generic::read_buffer_error(std::string in_error) {
    if (rbuf_notify_avail && rbuf_notify)
        rbuf_notify->buffer_error(in_error);
}

void buffer_handler_generic::write_buffer_error(std::string in_error) {
    if (wbuf_notify_avail && wbuf_notify)
        wbuf_notify->buffer_error(in_error);
}

void buffer_handler_generic::set_protocol_error_cb(std::function<void (void)> in_cb) {
    local_locker lock(handler_mutex);

    protoerror_cb = in_cb;
}

void buffer_handler_generic::protocol_error() {
    // Use a write locker because future things may need RW access, too
    local_locker lock(handler_mutex);

    if (protoerror_cb != NULL)
        protoerror_cb();

}

buffer_interface::buffer_interface() :
    bufferhandler {nullptr},
    read_handler {false},
    write_handler {false} {}

buffer_interface::~buffer_interface() {
    if (bufferhandler != nullptr) {
        if (read_handler)
            bufferhandler->remove_read_buffer_interface();
        if (write_handler)
            bufferhandler->remove_write_buffer_interface();
    }
}

buffer_handler_ostream_buf::~buffer_handler_ostream_buf() {
    if (rb_handler != NULL) {
        rb_handler->remove_write_buffer_drain_cb();
        rb_handler = NULL;
    }
}

std::streamsize buffer_handler_ostream_buf::xsputn(const char_type *s, std::streamsize n) {
    if (rb_handler == NULL) {
        // fprintf(stderr, "debug - no rb handler\n");
        return -1;
    }

    // fprintf(stderr, "debug - ostreambuf putting %lu\n", n);
    ssize_t written = rb_handler->put_write_buffer_data((void *) s, (size_t) n, true);

    if (written == n)
        return n;

    // fprintf(stderr, "debug - ostreambuf couldn't put all, blocking?\n");

    // If we couldn't write it all into the buffer, flag a full error
    if (written != n && !blocking) {
        rb_handler->buffer_error("write buffer full, streambuf unable to write data");
        return -1;
    }

    // Otherwise go into a loop, blocking, until we've written the entire buffer...
    
    // Initialize the locking variable
    blocking_cl.reset(new conditional_locker<size_t>());

    // Set a write completion callback
    rb_handler->set_write_buffer_drain_cb([this](size_t amt __attribute__((unused))) {
        blocking_cl->unlock(amt);
    });

    // Jump as far as we managed to write
    ssize_t wpos = written;
    while (1) {
        written = rb_handler->put_write_buffer_data((void *) (s + wpos), n - wpos, true);

        if (wpos + written == n) {
            rb_handler->remove_write_buffer_drain_cb();
            return n;
        }

        // Keep track of where we are
        wpos += written;

        // Block until the buffer flushes
        blocking_cl->block_until();
    }

    rb_handler->remove_write_buffer_drain_cb();

    return n;
}

buffer_handler_ostream_buf::int_type buffer_handler_ostream_buf::overflow(int_type ch) {
    if (rb_handler == NULL)
        return -1;

    if (rb_handler->put_write_buffer_data((void *) &ch, 1, true) == 1) 
        return 1;

    // Not blocking, nothing we can do
    if (!blocking) {
        rb_handler->buffer_error("write buffer full, streambuf unable to write data");
        return -1;
    }

    // Initialize the locking variable
    blocking_cl.reset(new conditional_locker<size_t>());

    // Set a write completion callback
    rb_handler->set_write_buffer_drain_cb([this](size_t amt __attribute__((unused))) {
        blocking_cl->unlock(amt);
    });

    while (1) {
        if (rb_handler->put_write_buffer_data((void *) &ch, 1, true) == 1) {
            rb_handler->remove_write_buffer_drain_cb();
            return 1;
        }

        blocking_cl->block_until();
    }

    rb_handler->remove_write_buffer_drain_cb();

    return 1;
}

buffer_handler_ostringstream_buf::~buffer_handler_ostringstream_buf() {
    rb_handler = NULL;
}

std::streamsize buffer_handler_ostringstream_buf::xsputn(const char_type *s, std::streamsize n) {
    local_locker l(&mutex);

    std::streamsize sz = std::stringbuf::xsputn(s, n);

    // fmt::print(stderr, "DEBUG - ostringstreambuf put {}\n", n);

    if (str().length() >= 1024) {
        sync();
    }

    return sz;
}

buffer_handler_ostringstream_buf::int_type buffer_handler_ostringstream_buf::overflow(int_type ch) {
    local_locker l(&mutex);

    buffer_handler_ostringstream_buf::int_type it = std::stringbuf::overflow(ch);

    if (str().length() >= 1024) {
        sync();
    }

    return it;
}

int buffer_handler_ostringstream_buf::sync() {
    if (rb_handler == NULL) {
        return -1;
    }

    local_locker l(&mutex);

    size_t sz = str().length();

    // fmt::print(stderr, "debug - ostringstreambuf sync {}\n", sz);

    ssize_t written = 
        rb_handler->put_write_buffer_data((void *) str().data(), sz, true);

    if (written != (ssize_t) sz) {
        // fprintf(stderr, "debug - ostringstreambuf couldn't write temp string, wrote %lu of %lu\n", written, sz);
        return -1;
    }

    str("");

    return 0;
}

