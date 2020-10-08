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

#ifndef __FUTURE_CHAINBUF_H__
#define __FUTURE_CHAINBUF_H__ 

#include "config.h"

#include <sstream>
#include <string>
#include <mutex>
#include <future>
#include <list>

#include <stdlib.h>
#include <string.h>

// Future chainbuf, based on stringbuf
// Provides an inter-thread feeder/consumer model with locking based on futures
//
// Can be operated in stream (default) mode where it can be fed from a 
// std::ostream or similar, or in packet mode (set_packet()) where it operates
// in a packetized mode where each chunk is either allocated or reserved directly.
//
// Once in packet mode it can not be set to stream mode
//
// Offers two blocking interfaces:
// wait() - waits until data is *present in the buffer*, should be called by the consumer
// wait_write() - waits until the buffer *has flushed data*, should be called by a producer
//  looking to throttle size buffer size.
class future_chainbuf : public std::stringbuf {
protected:
    class data_chunk {
    public:
        data_chunk(size_t sz):
            sz_{sz},
            start_{0},
            end_{0} {
            chunk_ = new char[sz];
        }

        data_chunk(const char *data, size_t sz) :
            sz_{sz},
            start_{0},
            end_{sz} {
            chunk_ = new char[sz];
            memcpy(chunk_, data, sz);
        }

        ~data_chunk() {
            delete[] chunk_;
        }

        size_t write(const char *data, size_t len) {
            // Can't write more than is left in the chunk
            size_t write_sz = std::min(sz_ - end_, len);

            if (write_sz == 0)
                return len;

            memcpy(chunk_ + end_, data, write_sz);
            end_ += write_sz;

            return write_sz;
        }

        size_t consume(size_t len) {
            // Can't consume more than we've populated
            size_t consume_sz = std::min(end_ - start_, len);

            start_ += consume_sz;

            return consume_sz;
        }

        char *content() {
            return chunk_ + start_;
        }

        bool exhausted() const {
            return sz_ == end_ && end_ == start_;
        }

        size_t available() const {
            return sz_ - end_;
        }

        size_t used() const {
            return end_ - start_;
        }

        void recycle() {
            start_ = end_ = 0;
        }

        char *chunk_;
        size_t sz_;
        size_t start_, end_;
    };

public:
    future_chainbuf() :
        chunk_sz_{4096},
        sync_sz_{4096},
        total_sz_{0},
        waiting_{false},
        complete_{false},
        cancel_{false},
        packet_{false} {
        chunk_list_.push_front(new data_chunk(chunk_sz_));
    }
        
    future_chainbuf(size_t chunk_sz, size_t sync_sz = 1024) :
        chunk_sz_{chunk_sz},
        sync_sz_{sync_sz},
        total_sz_{0},
        waiting_{false},
        complete_{false},
        cancel_{false},
        packet_{false} {
        chunk_list_.push_front(new data_chunk(chunk_sz_));
    }

    ~future_chainbuf() {
        cancel();

        for (auto c : chunk_list_) {
            delete c;
        }
    }

    size_t get(char **data) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (total_sz_ == 0) {
            *data = nullptr;
            return 0;
        }

        data_chunk *target = chunk_list_.front();
        *data = target->content();
        return target->used();
    }

    void consume(size_t sz) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (chunk_list_.size() == 0)
            return;

        data_chunk *target = chunk_list_.front();

        size_t consumed_sz = 0;

        while (consumed_sz < sz && total_sz_ > 0) {
            size_t consumed_chunk_sz;

            consumed_chunk_sz = target->consume(sz);
            consumed_sz += consumed_chunk_sz;

            if (target->exhausted()) {
                if (chunk_list_.size() == 1) {
                    if (packet_) {
                        chunk_list_.pop_front();
                        delete target;
                        target = nullptr;
                    } else {
                        target->recycle();
                    }
                    break;
                } else {
                    chunk_list_.pop_front();
                    delete target;
                    target = chunk_list_.front();
                }
            }

            total_sz_ -= consumed_chunk_sz;
        }

        try {
            if (write_waiting_)
                write_wait_promise_.set_value();
        } catch (const std::future_error& e) {
            ;
        }
    }

    void put_data(const char *data, size_t sz) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (packet_) {
            data_chunk *target = new data_chunk(data, sz);
            chunk_list_.push_back(target);
            total_sz_ += sz;
            sync();
            return;
        }

        data_chunk *target = chunk_list_.back();
        size_t written_sz = 0;

        while (written_sz < sz) {
            size_t written_chunk_sz;

            written_chunk_sz = target->write(data + written_sz, sz - written_sz);
            written_sz += written_chunk_sz;

            if (target->available() == 0) {
                target = new data_chunk(chunk_sz_);
                chunk_list_.push_back(target);
            }
        }

        total_sz_ += sz;
    }

    char *reserve(size_t sz) {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (!packet_)
            throw std::runtime_error("cannot reserve in stream mode");

        // Trim the current chunk, and make a new chunk big enough to hold the entire record,
        // returning a pointer to the data; committed with a call to sync()
        
        auto current = chunk_list_.back();

        if (sz < current->available())
            return current->chunk_ + current->start_;

        auto sized = new data_chunk(std::max(sz, chunk_sz_));
        chunk_list_.push_back(sized);

        total_sz_ += sz;

        return sized->chunk_;
    }

    virtual std::streamsize xsputn(const char_type *s, std::streamsize n) override {
        if (packet_)
            throw std::runtime_error("cannot use stream methods in packet mode");

        put_data(s, n);

        if (size() > sync_sz_)
            sync();

        return n;
    }

    virtual int_type overflow(int_type ch) override {
        if (packet_)
            throw std::runtime_error("cannot use stream methods in packet mode");

        put_data((char *) &ch, 1);

        if (size() > sync_sz_)
            sync();

        return ch;
    }

    int sync() override {
        const std::lock_guard<std::mutex> lock(mutex_);
        try {
            if (waiting_)
                wait_promise_.set_value();
        } catch (const std::future_error& e) {
            ;
        }

        waiting_ = false;

        return 1;
    }

    bool running() const {
        return (!complete_ && !cancel_);
    }

    size_t size() {
        const std::lock_guard<std::mutex> lock(mutex_);
        return total_sz_;
    }

    void reset() {
        const std::lock_guard<std::mutex> lock(mutex_);

        if (waiting_)
            throw std::runtime_error("reset futurechainbuf while waiting");

        for (auto c : chunk_list_)
            delete c;
        chunk_list_.clear();
        chunk_list_.push_front(new data_chunk(chunk_sz_));

        total_sz_ = 0;
        complete_ = false;
        cancel_ = false;
        waiting_ = false;
    }

    void cancel() {
        cancel_ = true;
        sync();
    }

    void complete() {
        complete_ = true;
        sync();
    }

    void set_packetmode() {
        packet_ = true;
    }

    size_t wait() {
        if (waiting_)
            throw std::runtime_error("future_stream already blocking");

        if (total_sz_ > 0 || !running()) {
            return total_sz_;
        }

        mutex_.lock();
        waiting_ = true;
        wait_promise_ = std::promise<void>();
        auto ft = wait_promise_.get_future();
        mutex_.unlock();

        ft.wait();

        return total_sz_;
    }

    size_t wait_write() {
        if (write_waiting_)
            throw std::runtime_error("future_stream already blocking for write");

        mutex_.lock();
        write_waiting_ = true;
        write_wait_promise_ = std::promise<void>();
        auto ft = write_wait_promise_.get_future();
        mutex_.unlock();

        ft.wait();

        return total_sz_;
    }

protected:
    std::mutex mutex_;

    std::list<data_chunk *> chunk_list_;

    size_t chunk_sz_;
    size_t sync_sz_;
    size_t total_sz_;

    std::promise<void> wait_promise_;
    std::atomic<bool> waiting_;

    std::promise<void> write_wait_promise_;
    std::atomic<bool> write_waiting_;

    std::atomic<bool> complete_;
    std::atomic<bool> cancel_;

    std::atomic<bool> packet_;

};


#endif /* ifndef FUTURE_CHAINBUF_H */
