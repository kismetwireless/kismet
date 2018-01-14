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

class FileWritebuf : public CommonBuffer {
public:
    // Specify a file and a block size
    FileWritebuf(std::string in_path, size_t chunk_sz);
    virtual ~FileWritebuf();

    virtual void clear();

    virtual ssize_t size() {
        return chunk_sz;
    }

    virtual ssize_t available() {
        return chunk_sz;
    }

    virtual size_t used();

    virtual size_t total();

    // Write-only buffer, we don't allow peeking 
    virtual ssize_t peek(unsigned char **ret_data, size_t in_sz) {
        return -1;
    }

    virtual ssize_t zero_copy_peek(unsigned char **ret_data, size_t in_sz) {
        return -1;
    }

    virtual void peek_free(unsigned char *in_data) {
        return;
    }

    // Write amount to buffer, arbitrarily allocating new chunks
    virtual ssize_t write(unsigned char *in_data, size_t in_sz);
  
    virtual ssize_t reserve(unsigned char **data, size_t in_sz);
    virtual ssize_t zero_copy_reserve(unsigned char **data, size_t in_sz);
    virtual bool commit(unsigned char *data, size_t in_sz);

    // Consume from buffer
    size_t consume(size_t in_sz) {
        return 0;
    }

protected:
    size_t chunk_sz;
    uint8_t *reserve_chunk;

    bool free_commit;

    std::string filename;

    FILE *backfile;
};

#endif

