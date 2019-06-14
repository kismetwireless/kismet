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

BufferHandlerGeneric::BufferHandlerGeneric() {
    read_buffer = NULL;
    write_buffer = NULL;

    rbuf_notify = NULL;
    wbuf_notify = NULL;
}

BufferHandlerGeneric::~BufferHandlerGeneric() {
    if (read_buffer)
        delete read_buffer;

    if (write_buffer)
        delete write_buffer;
}

ssize_t BufferHandlerGeneric::GetReadBufferSize() {
    if (read_buffer)
        return read_buffer->size();

    return 0;
}

ssize_t BufferHandlerGeneric::GetWriteBufferSize() {
    if (write_buffer)
        return write_buffer->size();

    return 0;
}

size_t BufferHandlerGeneric::GetReadBufferUsed() {
    if (read_buffer)
        return read_buffer->used();

    return 0;
}

size_t BufferHandlerGeneric::GetWriteBufferUsed() {
    if (write_buffer)
        return write_buffer->used();

    return 0;
}

ssize_t BufferHandlerGeneric::GetReadBufferAvailable() {
    if (read_buffer)
        return read_buffer->available();

    return 0;
}

ssize_t BufferHandlerGeneric::GetWriteBufferAvailable() {
    if (write_buffer)
        return write_buffer->available();

    return 0;
}

ssize_t BufferHandlerGeneric::PeekReadBufferData(void **in_ptr, size_t in_sz) {
    if (in_ptr == NULL)
        return 0;

    if (read_buffer)
        return read_buffer->peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

ssize_t BufferHandlerGeneric::PeekWriteBufferData(void **in_ptr, size_t in_sz) {
    if (write_buffer)
        return write_buffer->peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

ssize_t BufferHandlerGeneric::ZeroCopyPeekReadBufferData(void **in_ptr, size_t in_sz) {
    if (in_ptr == NULL)
        return 0;

    if (read_buffer)
        return read_buffer->zero_copy_peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

ssize_t BufferHandlerGeneric::ZeroCopyPeekWriteBufferData(void **in_ptr, size_t in_sz) {
    if (write_buffer)
        return write_buffer->zero_copy_peek((unsigned char **) in_ptr, in_sz);

    return 0;
}

void BufferHandlerGeneric::PeekFreeReadBufferData(void *in_ptr) {
    if (read_buffer)
        return read_buffer->peek_free((unsigned char *) in_ptr);

    return;
}

void BufferHandlerGeneric::PeekFreeWriteBufferData(void *in_ptr) {
    if (write_buffer)
        return write_buffer->peek_free((unsigned char *) in_ptr);

    return;
}

size_t BufferHandlerGeneric::ConsumeReadBufferData(size_t in_sz) {
    size_t sz;

    if (read_buffer) {
        sz = read_buffer->consume(in_sz);

        if (readbuf_drain_cb != NULL) {
            readbuf_drain_cb(sz);
        }
    }

    return 0;
}

size_t BufferHandlerGeneric::ConsumeWriteBufferData(size_t in_sz) {
    size_t sz;

    if (write_buffer) {
        sz = write_buffer->consume(in_sz);

        if (writebuf_drain_cb != NULL) {
            writebuf_drain_cb(sz);
        }
    }

    return 0;
}


size_t BufferHandlerGeneric::PutReadBufferData(void *in_ptr, size_t in_sz, 
        bool in_atomic) {
    size_t ret;

    {
        local_locker hlock(&handler_locker);

        if (!read_buffer)
            return 0;

        // Don't write any if we're an atomic complete write; buffers which report
        // -1 for available size are infinite
        if (in_atomic && read_buffer->available() >= 0 && 
                (size_t) read_buffer->available() < in_sz)
            return 0;

        ret = read_buffer->write((unsigned char *) in_ptr, in_sz);

    }

    {
        // Lock just the callback handler because the callback
        // needs to interact with us
        local_locker lock(&r_callback_locker);

        if (ret != in_sz)
            rbuf_notify->BufferError("insufficient space in buffer");

        if (rbuf_notify)
            rbuf_notify->BufferAvailable(ret);
    }

    return ret;
}

bool BufferHandlerGeneric::PutReadBufferData(std::string in_data) {
    size_t r =
        PutReadBufferData((void *) in_data.data(), in_data.length(), true);
    return (r == in_data.length());
}

bool BufferHandlerGeneric::PutWriteBufferData(std::string in_data) {
    size_t r =
        PutWriteBufferData((void *) in_data.data(), in_data.length(), true);
    return (r == in_data.length());
}

    
size_t BufferHandlerGeneric::PutWriteBufferData(void *in_ptr, size_t in_sz, bool in_atomic) {
    size_t ret;

    {
        local_locker hlock(&handler_locker);

        if (!write_buffer) {
            if (wbuf_notify)
                wbuf_notify->BufferError("No write buffer connected");

            return 0;
        }

        // Don't write any if we're an atomic complete write; buffers which report
        // -1 for available size are infinite
        if (in_atomic && write_buffer->available() >= 0 &&
                (size_t) write_buffer->available() < in_sz)
            return 0;

        ret = write_buffer->write((unsigned char *) in_ptr, in_sz);
    }

    {
        // Lock just the callback handler because the callback
        // needs to interact with us
        local_locker lock(&w_callback_locker);

        if (ret != in_sz && wbuf_notify)
            wbuf_notify->BufferError("insufficient space in buffer");

        if (wbuf_notify)
            wbuf_notify->BufferAvailable(ret);
    }

    return ret;
}

ssize_t BufferHandlerGeneric::ReserveReadBufferData(void **in_ptr, size_t in_sz) {
    local_locker hlock(&handler_locker);

    if (read_buffer != NULL) {
        return read_buffer->reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

ssize_t BufferHandlerGeneric::ReserveWriteBufferData(void **in_ptr, size_t in_sz) {
    local_locker hlock(&handler_locker);

    if (write_buffer != NULL) {
        return write_buffer->reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

ssize_t BufferHandlerGeneric::ZeroCopyReserveReadBufferData(void **in_ptr, size_t in_sz) {
    local_locker hlock(&handler_locker);

    if (read_buffer != NULL) {
        return read_buffer->zero_copy_reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

ssize_t BufferHandlerGeneric::ZeroCopyReserveWriteBufferData(void **in_ptr, size_t in_sz) {
    local_locker hlock(&handler_locker);

    if (write_buffer != NULL) {
        return write_buffer->zero_copy_reserve((unsigned char **) in_ptr, in_sz);
    }

    return -1;
}

void BufferHandlerGeneric::TriggerWriteCallback(size_t in_sz) {
    local_locker lock(&r_callback_locker);

    if (wbuf_notify) {
        wbuf_notify->BufferAvailable(in_sz);
    }
}

void BufferHandlerGeneric::TriggerReadCallback(size_t in_sz) {
    local_locker lock(&r_callback_locker);

    if (rbuf_notify) {
        rbuf_notify->BufferAvailable(in_sz);
    }
}

bool BufferHandlerGeneric::CommitReadBufferData(void *in_ptr, size_t in_sz) {
    bool s = false;

    {
        local_locker hlock(&handler_locker);

        if (read_buffer != NULL) {
            s = read_buffer->commit((unsigned char *) in_ptr, in_sz);
        }
    }

    {
        local_locker lock(&r_callback_locker);

        if (rbuf_notify) {
            if (!s)
                rbuf_notify->BufferError("error committing to read buffer");
            else
                rbuf_notify->BufferAvailable(in_sz);
        }
    }

    return s;
}

bool BufferHandlerGeneric::CommitWriteBufferData(void *in_ptr, size_t in_sz) {
    bool s = false;

    {
        local_locker hlock(&handler_locker);
        if (write_buffer != NULL) {
            s = write_buffer->commit((unsigned char *) in_ptr, in_sz);
        }
    }

    {
        local_locker lock(&w_callback_locker);

        if (wbuf_notify) {
            if (!s)
                wbuf_notify->BufferError("error committing to write buffer");
            else
                wbuf_notify->BufferAvailable(in_sz);
        }
    }

    return s;
}

void BufferHandlerGeneric::ClearReadBuffer() {
    if (read_buffer)
        read_buffer->clear();
}

void BufferHandlerGeneric::ClearWriteBuffer() {
    if (write_buffer)
        write_buffer->clear();
}

void BufferHandlerGeneric::SetReadBufferInterface(BufferInterface *in_interface) {
    local_locker lock(&r_callback_locker);

    rbuf_notify = in_interface;

    size_t pending = GetReadBufferUsed();

    if (pending)
        rbuf_notify->BufferAvailable(pending);

}

void BufferHandlerGeneric::SetWriteBufferInterface(BufferInterface *in_interface) {
    local_locker lock(&w_callback_locker);

    wbuf_notify = in_interface;

    size_t pending = GetWriteBufferUsed();

    if (pending)
        wbuf_notify->BufferAvailable(pending);
}

void BufferHandlerGeneric::RemoveReadBufferInterface() {
    local_locker lock(&r_callback_locker);

    rbuf_notify = NULL;
}

void BufferHandlerGeneric::RemoveWriteBufferInterface() {
    local_locker lock(&w_callback_locker);

    wbuf_notify = NULL;
}

void BufferHandlerGeneric::SetReadBufferDrainCb(std::function<void (size_t)> in_cb) {
    local_locker lock(&r_callback_locker);

    readbuf_drain_cb = in_cb;
}

void BufferHandlerGeneric::SetWriteBufferDrainCb(std::function<void (size_t)> in_cb) {
    local_locker lock(&w_callback_locker);

    writebuf_drain_cb = in_cb;
}

void BufferHandlerGeneric::RemoveReadBufferDrainCb() {
    local_locker lock(&r_callback_locker);
    readbuf_drain_cb = NULL;
}

void BufferHandlerGeneric::RemoveWriteBufferDrainCb() {
    local_locker lock(&w_callback_locker);
    writebuf_drain_cb = NULL;
}

void BufferHandlerGeneric::BufferError(std::string in_error) {
    ReadBufferError(in_error);
    WriteBufferError(in_error);
}

void BufferHandlerGeneric::ReadBufferError(std::string in_error) {
    local_locker lock(&r_callback_locker);

    if (rbuf_notify)
        rbuf_notify->BufferError(in_error);
}

void BufferHandlerGeneric::WriteBufferError(std::string in_error) {
    local_locker lock(&w_callback_locker);

    if (wbuf_notify)
        wbuf_notify->BufferError(in_error);
}

void BufferHandlerGeneric::SetProtocolErrorCb(std::function<void (void)> in_cb) {
    local_locker lock(&handler_locker);

    protoerror_cb = in_cb;
}

void BufferHandlerGeneric::ProtocolError() {
    // local_locker lock(&handler_locker);

    if (protoerror_cb != NULL)
        protoerror_cb();

}

BufferInterface::BufferInterface() {
    buffer_handler = NULL;
    read_handler = false;
    write_handler = false;
}

BufferInterface::~BufferInterface() {
    if (buffer_handler != NULL) {
        if (read_handler)
            buffer_handler->RemoveReadBufferInterface();
        if (write_handler)
            buffer_handler->RemoveWriteBufferInterface();
    }
}

BufferHandlerOStreambuf::~BufferHandlerOStreambuf() {
    if (rb_handler != NULL) {
        rb_handler->RemoveWriteBufferDrainCb();
        rb_handler = NULL;
    }
}

std::streamsize BufferHandlerOStreambuf::xsputn(const char_type *s, std::streamsize n) {
    if (rb_handler == NULL) {
        // fprintf(stderr, "debug - no rb handler\n");
        return -1;
    }

    // fprintf(stderr, "debug - ostreambuf putting %lu\n", n);
    ssize_t written = rb_handler->PutWriteBufferData((void *) s, (size_t) n, true);

    if (written == n)
        return n;

    // fprintf(stderr, "debug - ostreambuf couldn't put all, blocking?\n");

    // If we couldn't write it all into the buffer, flag a full error
    if (written != n && !blocking) {
        rb_handler->BufferError("write buffer full, streambuf unable to write data");
        return -1;
    }

    // Otherwise go into a loop, blocking, until we've written the entire buffer...
    
    // Initialize the locking variable
    blocking_cl.reset(new conditional_locker<size_t>());

    // Set a write completion callback
    rb_handler->SetWriteBufferDrainCb([this](size_t amt __attribute__((unused))) {
        blocking_cl->unlock(amt);
    });

    // Jump as far as we managed to write
    ssize_t wpos = written;
    while (1) {
        written = rb_handler->PutWriteBufferData((void *) (s + wpos), n - wpos, true);

        if (wpos + written == n) {
            rb_handler->RemoveWriteBufferDrainCb();
            return n;
        }

        // Keep track of where we are
        wpos += written;

        // Block until the buffer flushes
        blocking_cl->block_until();
    }

    rb_handler->RemoveWriteBufferDrainCb();

    return n;
}

BufferHandlerOStreambuf::int_type BufferHandlerOStreambuf::overflow(int_type ch) {
    if (rb_handler == NULL)
        return -1;

    if (rb_handler->PutWriteBufferData((void *) &ch, 1, true) == 1) 
        return 1;

    // Not blocking, nothing we can do
    if (!blocking) {
        rb_handler->BufferError("write buffer full, streambuf unable to write data");
        return -1;
    }

    // Initialize the locking variable
    blocking_cl.reset(new conditional_locker<size_t>());

    // Set a write completion callback
    rb_handler->SetWriteBufferDrainCb([this](size_t amt __attribute__((unused))) {
        blocking_cl->unlock(amt);
    });

    while (1) {
        if (rb_handler->PutWriteBufferData((void *) &ch, 1, true) == 1) {
            rb_handler->RemoveWriteBufferDrainCb();
            return 1;
        }

        blocking_cl->block_until();
    }

    rb_handler->RemoveWriteBufferDrainCb();

    return 1;
}

BufferHandlerOStringStreambuf::~BufferHandlerOStringStreambuf() {
    rb_handler = NULL;
}

std::streamsize BufferHandlerOStringStreambuf::xsputn(const char_type *s, std::streamsize n) {
    local_locker l(&mutex);

    std::streamsize sz = std::stringbuf::xsputn(s, n);

    // fmt::print(stderr, "DEBUG - ostringstreambuf put {}\n", n);

    if (str().length() >= 1024) {
        sync();
    }

    return sz;
}

BufferHandlerOStringStreambuf::int_type BufferHandlerOStringStreambuf::overflow(int_type ch) {
    local_locker l(&mutex);

    BufferHandlerOStringStreambuf::int_type it = std::stringbuf::overflow(ch);

    if (str().length() >= 1024) {
        sync();
    }

    return it;
}

int BufferHandlerOStringStreambuf::sync() {
    if (rb_handler == NULL) {
        return -1;
    }

    local_locker l(&mutex);

    size_t sz = str().length();

    // fmt::print(stderr, "debug - ostringstreambuf sync {}\n", sz);

    ssize_t written = 
        rb_handler->PutWriteBufferData((void *) str().data(), sz, true);

    if (written != (ssize_t) sz) {
        // fprintf(stderr, "debug - ostringstreambuf couldn't write temp string, wrote %lu of %lu\n", written, sz);
        return -1;
    }

    str("");

    return 0;
}

