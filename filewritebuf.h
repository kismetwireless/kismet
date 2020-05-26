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

#ifndef __FILEBUF_H__
#define __FILEBUF_H__

#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <mutex>
#include "buffer_handler.h"

// Direct file IO buffer for writing logs via the buffer API
//
// MAY THROW EXCEPTIONS on construction if the file cannot be opened

class file_write_buffer : public common_buffer {
public:
    // Specify a file and a block size
    file_write_buffer(std::string in_path, size_t chunk_sz);
    virtual ~file_write_buffer();

protected:
    size_t chunk_sz;
    uint8_t *reserve_chunk;

    bool free_commit;

    std::string filename;

    FILE *backfile;

    virtual void clear_impl() override;

    virtual ssize_t size_impl() override {
        return chunk_sz;
    }

    virtual ssize_t available_impl() override {
        return chunk_sz;
    }

    virtual size_t used_impl() override;

    // Write-only buffer, we don't allow peeking 
    virtual ssize_t peek_impl(unsigned char **ret_data, size_t in_sz) override {
        return -1;
    }

    virtual ssize_t zero_copy_peek_impl(unsigned char **ret_data, size_t in_sz) override {
        return -1;
    }

    virtual void peek_free_impl(unsigned char *in_data) override {
        return;
    }

    // Write amount to buffer, arbitrarily allocating new chunks
    virtual ssize_t write_impl(unsigned char *in_data, size_t in_sz) override;
  
    virtual ssize_t reserve_impl(unsigned char **data, size_t in_sz) override;
    virtual ssize_t zero_copy_reserve_impl(unsigned char **data, size_t in_sz) override;

    // Consume from buffer
    size_t consume_impl(size_t in_sz) override {
        return 0;
    }

};

#endif

