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

#ifndef __RINGBUF2_H__
#define __RINGBUF2_H__

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include <mutex>

#include "buffer_handler.h"

// Another iteration of the ringbuffer structure, this time based on the common_buffer_v2 
// blocking protocol thread model
class ringbuf_v3 : public common_buffer_v2 {
public:
    ringbuf_v3(size_t in_sz);
    virtual ~ringbuf_v3();

protected:
    // Reset a buffer
    virtual void clear_impl() override;

    virtual ssize_t size_impl() override;
    virtual ssize_t available_impl() override;
    virtual size_t used_impl() override;

    virtual ssize_t write_impl(const char *in_data, size_t in_sz) override;

    virtual ssize_t peek_impl(char **in_data, size_t in_sz) override;
    virtual ssize_t zero_copy_peek_impl(char **in_data, size_t in_sz) override;
    virtual void peek_free_impl(char *in_data) override;

    virtual size_t consume_impl(size_t in_sz) override;

    virtual ssize_t reserve_impl(char **data, size_t in_sz) override;
    virtual ssize_t zero_copy_reserve_impl(char **data, size_t in_sz) override;

    char *buffer;

    // Total size
    std::atomic<size_t> buffer_sz;
    // Where reads start
    std::atomic<size_t> start_pos;
    // Length of data currently in buffer
    std::atomic<size_t> length;
};


#endif

