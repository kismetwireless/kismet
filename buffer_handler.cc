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

    // Initialize as recursive to allow multiple locks in a single thread
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&handler_locker, &mutexattr);
    pthread_mutex_init(&r_callback_locker, &mutexattr);
    pthread_mutex_init(&w_callback_locker, &mutexattr);
}

BufferHandlerGeneric::~BufferHandlerGeneric() {
    local_eol_locker lock(&handler_locker);
    local_eol_locker rlock(&r_callback_locker);
    local_eol_locker wlock(&w_callback_locker);

    // fprintf(stderr, "debug - ~rbh inside locks\n");

    if (read_buffer)
        delete read_buffer;

    if (write_buffer)
        delete write_buffer;

    pthread_mutex_destroy(&handler_locker);
    pthread_mutex_destroy(&r_callback_locker);
    pthread_mutex_destroy(&w_callback_locker);
}

size_t BufferHandlerGeneric::GetReadBufferSize() {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->size();

    return 0;
}

size_t BufferHandlerGeneric::GetWriteBufferSize() {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->size();

    return 0;
}

size_t BufferHandlerGeneric::GetReadBufferUsed() {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->used();

    return 0;
}

size_t BufferHandlerGeneric::GetWriteBufferUsed() {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->used();

    return 0;
}

size_t BufferHandlerGeneric::GetReadBufferFree() {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->available();

    return 0;
}

size_t BufferHandlerGeneric::GetWriteBufferFree() {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->available();

    return 0;
}

size_t BufferHandlerGeneric::GetReadBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (read_buffer) {
        local_locker rlock(&r_callback_locker);
        size_t s;

        s = read_buffer->read(in_ptr, in_sz);

        if (readbuf_drain_cb != NULL) {
            readbuf_drain_cb(s);
        }

        return s;
    }

    return 0;
}

size_t BufferHandlerGeneric::GetWriteBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (write_buffer) {
        local_locker wlock(&w_callback_locker);
        size_t s;

        s = write_buffer->read(in_ptr, in_sz);

        if (writebuf_drain_cb != NULL) {
            writebuf_drain_cb(s);
        }

        return s;
    }

    return 0;
}

size_t BufferHandlerGeneric::PeekReadBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->peek(in_ptr, in_sz);

    return 0;
}

size_t BufferHandlerGeneric::PeekWriteBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->peek(in_ptr, in_sz);

    return 0;
}

size_t BufferHandlerGeneric::ConsumeReadBufferData(size_t in_sz) {
    return GetReadBufferData(NULL, in_sz);
}

size_t BufferHandlerGeneric::ConsumeWriteBufferData(size_t in_sz) {
    return GetWriteBufferData(NULL, in_sz);
}

size_t BufferHandlerGeneric::PutReadBufferData(void *in_ptr, size_t in_sz, 
        bool in_atomic) {
    size_t ret;

    {
        // Sub-context for locking so we don't lock read-op out
        local_locker lock(&handler_locker);

        if (!read_buffer)
            return 0;

        // Don't write any if we're an atomic complete write
        if (in_atomic && read_buffer->available() < in_sz)
            return 0;

        ret = read_buffer->write(in_ptr, in_sz);
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
    
size_t BufferHandlerGeneric::PutWriteBufferData(void *in_ptr, size_t in_sz,
        bool in_atomic) {
    size_t ret;

    {
        // Sub-context for locking so we don't lock read-op out
        local_locker lock(&handler_locker);

        if (!write_buffer) {
            if (wbuf_notify)
                wbuf_notify->BufferError("No write buffer connected");

            return 0;
        }

        // Don't write any if we're an atomic complete write
        if (in_atomic && write_buffer->available() < in_sz)
            return 0;

        ret = write_buffer->write(in_ptr, in_sz);
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

void BufferHandlerGeneric::SetReadBufferInterface(RingbufferInterface *in_interface) {
    local_locker lock(&r_callback_locker);

    rbuf_notify = in_interface;

    size_t pending = GetReadBufferUsed();

    if (pending)
        rbuf_notify->BufferAvailable(pending);

}

void BufferHandlerGeneric::SetWriteBufferInterface(RingbufferInterface *in_interface) {
    local_locker lock(&w_callback_locker);

    wbuf_notify = in_interface;

    size_t pending = GetWriteBufferUsed();

    if (pending)
        wbuf_notify->BufferAvailable(pending);
}

void BufferHandlerGeneric::RemoveReadBufferInterface() {
    local_locker lock(&r_callback_locker);
    // fprintf(stderr, "debug - RBH removing read buffer interface\n");

    rbuf_notify = NULL;
}

void BufferHandlerGeneric::RemoveWriteBufferInterface() {
    local_locker lock(&w_callback_locker);

    wbuf_notify = NULL;
}

void BufferHandlerGeneric::SetReadBufferDrainCb(function<void (size_t)> in_cb) {
    local_locker lock(&r_callback_locker);

    readbuf_drain_cb = in_cb;
}

void BufferHandlerGeneric::SetWriteBufferDrainCb(function<void (size_t)> in_cb) {
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

void BufferHandlerGeneric::BufferError(string in_error) {
    ReadBufferError(in_error);
    WriteBufferError(in_error);
}

void BufferHandlerGeneric::ReadBufferError(string in_error) {
    local_locker lock(&r_callback_locker);

    if (rbuf_notify)
        rbuf_notify->BufferError(in_error);
}

void BufferHandlerGeneric::WriteBufferError(string in_error) {
    local_locker lock(&w_callback_locker);

    if (wbuf_notify)
        wbuf_notify->BufferError(in_error);
}

void BufferHandlerGeneric::SetProtocolErrorCb(function<void (void)> in_cb) {
    local_locker lock(&handler_locker);

    protoerror_cb = in_cb;
}

void BufferHandlerGeneric::ProtocolError() {
    local_locker lock(&handler_locker);

    // fprintf(stderr, "debug - RBH calling protocol error\n");

    if (protoerror_cb != NULL)
        protoerror_cb();

}

template<class B>
BufferHandler<B>::BufferHandler(size_t r_buffer_sz, size_t w_buffer_sz) {
    if (r_buffer_sz != 0)
        read_buffer = new B(r_buffer_sz);
    else
        read_buffer = NULL;

    if (w_buffer_sz != 0)
        write_buffer = new B(w_buffer_sz);
    else
        write_buffer = NULL;
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
        return -1;
    }

    ssize_t written = rb_handler->PutWriteBufferData((void *) s, (size_t) n, true);

    if (written == n)
        return n;

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

