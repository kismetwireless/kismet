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

#ifndef __CHAINBUF_H__
#define __CHAINBUF_H__

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include <vector>
#include <mutex>

#include "buffer_handler.h"

/* Fairly basic linked buffer system which allows linear writing and linear reading.
 * Random access is not supported; use a string buffer for that.
 *
 * The linked buffer is best used for buffering serialized output before sending it
 * to the webserver as a stream - minimal copying is needed.
 *
 * Due to some implementation limitations this should probably only be used to stream
 * to a write sink - such as writing to a http endpoint.  Read and peek operations will
 * only return the remaining portion of the current slot as they operate purely on
 * the chunk and prevent memory copying.
 *
 */

class Chainbuf : public CommonBuffer {
public:
    // Size per chunk and number of slots to pre-allocate in the buffer
    Chainbuf(size_t in_chunk = 1024, size_t pre_allocate = 128);
    virtual ~Chainbuf();

    // Erase buffer
    virtual void clear();

    // Return amount used in buffer
    virtual size_t used();

    // Return about available (effectively "infinite"), use a crappy hack for now
    virtual size_t available() { return 1024 * 1024 * 2014; }

    // Return total size ever used by buffer, not current used
    virtual size_t total();

    // Write amount to buffer, arbitrarily allocating new chunks
    virtual size_t write(unsigned char *in_data, size_t in_sz);
   
    // Peek from buffer; will only return up to chunk size per peek
    virtual size_t peek(uint8_t *ret_data, size_t in_sz);

    // Consume from buffer
    size_t consume(size_t in_sz);

protected:
    std::recursive_timed_mutex cblock;

    size_t chunk_sz;
    bool free_after_read;

    unsigned int write_block;
    size_t write_offt;
    unsigned int read_block;
    size_t read_offt;

    std::vector<uint8_t *> buff_vec;

    size_t used_sz;
    size_t total_sz;

};

#endif
