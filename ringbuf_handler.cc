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

#include "config.hpp"

#include <stdlib.h>

#include "util.h"
#include "ringbuf2.h"
#include "ringbuf_handler.h"

RingbufferHandler::RingbufferHandler(size_t r_buffer_sz, size_t w_buffer_sz) {
    if (r_buffer_sz != 0)
        read_buffer = new RingbufV2(r_buffer_sz);
    else
        read_buffer = NULL;

    if (w_buffer_sz != 0)
        write_buffer = new RingbufV2(w_buffer_sz);
    else
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

RingbufferHandler::~RingbufferHandler() {
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

size_t RingbufferHandler::GetReadBufferSize() {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->size();

    return 0;
}

size_t RingbufferHandler::GetWriteBufferSize() {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->size();

    return 0;
}

size_t RingbufferHandler::GetReadBufferUsed() {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->used();

    return 0;
}

size_t RingbufferHandler::GetWriteBufferUsed() {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->used();

    return 0;
}

size_t RingbufferHandler::GetReadBufferFree() {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->available();

    return 0;
}

size_t RingbufferHandler::GetWriteBufferFree() {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->available();

    return 0;
}

size_t RingbufferHandler::GetReadBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (read_buffer) 
        return read_buffer->read(in_ptr, in_sz);

    return 0;
}

size_t RingbufferHandler::GetWriteBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->read(in_ptr, in_sz);

    return 0;
}

size_t RingbufferHandler::PeekReadBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (read_buffer)
        return read_buffer->peek(in_ptr, in_sz);

    return 0;
}

size_t RingbufferHandler::PeekWriteBufferData(void *in_ptr, size_t in_sz) {
    local_locker lock(&handler_locker);

    if (write_buffer)
        return write_buffer->peek(in_ptr, in_sz);

    return 0;
}

size_t RingbufferHandler::PutReadBufferData(void *in_ptr, size_t in_sz, 
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
    
size_t RingbufferHandler::PutWriteBufferData(void *in_ptr, size_t in_sz,
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

void RingbufferHandler::SetReadBufferInterface(RingbufferInterface *in_interface) {
    local_locker lock(&r_callback_locker);

    rbuf_notify = in_interface;

    size_t pending = GetReadBufferUsed();

    if (pending)
        rbuf_notify->BufferAvailable(pending);

}

void RingbufferHandler::SetWriteBufferInterface(RingbufferInterface *in_interface) {
    local_locker lock(&w_callback_locker);

    wbuf_notify = in_interface;

    size_t pending = GetWriteBufferUsed();

    if (pending)
        wbuf_notify->BufferAvailable(pending);
}

void RingbufferHandler::RemoveReadBufferInterface() {
    local_locker lock(&r_callback_locker);
    // fprintf(stderr, "debug - RBH removing read buffer interface\n");

    rbuf_notify = NULL;
}

void RingbufferHandler::RemoveWriteBufferInterface() {
    local_locker lock(&w_callback_locker);

    wbuf_notify = NULL;
}

void RingbufferHandler::BufferError(string in_error) {
    ReadBufferError(in_error);
    WriteBufferError(in_error);
}

void RingbufferHandler::ReadBufferError(string in_error) {
    local_locker lock(&r_callback_locker);

    if (rbuf_notify)
        rbuf_notify->BufferError(in_error);
}

void RingbufferHandler::WriteBufferError(string in_error) {
    local_locker lock(&w_callback_locker);

    if (wbuf_notify)
        wbuf_notify->BufferError(in_error);
}

void RingbufferHandler::SetProtocolErrorCb(function<void (void)> in_cb) {
    local_locker lock(&handler_locker);

    protoerror_cb = in_cb;
}

void RingbufferHandler::ProtocolError() {
    local_locker lock(&handler_locker);

    // fprintf(stderr, "debug - RBH calling protocol error\n");

    if (protoerror_cb != NULL)
        protoerror_cb();

}

RingbufferInterface::RingbufferInterface() {
    ringbuffer_handler = NULL;
    read_handler = false;
    write_handler = false;
}

RingbufferInterface::~RingbufferInterface() {
    if (ringbuffer_handler != NULL) {
        if (read_handler)
            ringbuffer_handler->RemoveReadBufferInterface();
        if (write_handler)
            ringbuffer_handler->RemoveWriteBufferInterface();
    }
}

