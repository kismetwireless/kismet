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

#include "chainbuf.h"
#include "util.h"

Chainbuf::Chainbuf(size_t in_chunk, size_t pre_allocate) {
    chunk_sz = in_chunk;

    // Allocate slots in the vector, but not bytes
    buff_vec = std::vector<uint8_t *>(pre_allocate);

    buff_vec.push_back(new uint8_t[chunk_sz]);

    used_sz = 0;
    total_sz = 0;

    write_block = 0;
    read_block = 0;
    write_offt = 0;
    read_offt = 0;
}

Chainbuf::~Chainbuf() {
    local_locker lock(&cblock);

    fprintf(stderr, "debug - freeing chainbuf, total size %lu chunks %lu\n", total_sz, (total_sz / chunk_sz) + 1);

    clear();
}

void Chainbuf::clear() {
    local_locker lock(&cblock);

    for (auto x : buff_vec) 
        delete[](x);

    buff_vec.clear();
}

size_t Chainbuf::used() {
    local_locker lock(&cblock);

    return used_sz;
}

size_t Chainbuf::total() {
    local_locker lock(&cblock);

    return total_sz;
}

size_t Chainbuf::write(uint8_t *in_data, size_t in_sz) {
    local_locker lock(&cblock);

    size_t total_written = 0;

    while (total_written < in_sz) {
        // Available in this chunk
        size_t free_chunk_sz = chunk_sz - write_offt;

        // Whole buffer or whole chunk
        size_t w_sz = min(in_sz - total_written, free_chunk_sz);

        memcpy(buff_vec[write_block] + write_offt, in_data + total_written, w_sz);

        total_written += w_sz;

        used_sz += w_sz;
        total_sz += w_sz;

        // If we got here and we have more data, then we must need another chunk
        if (total_written < in_sz) {
            uint8_t *newchunk = new uint8_t[chunk_sz];
            buff_vec.push_back(newchunk);
            write_block++;
            write_offt = 0;
        }
    }

    return total_written;
}

size_t Chainbuf::peek(uint8_t **ret_data) {
    local_locker lock(&cblock);

    // Our return data is always at our read point
    *ret_data = buff_vec[read_block] + read_offt;

    // If our read position isn't in the same block as we're writing, we have
    // a full chunk; return the offset into it and the remaining length of the 
    // chunk.
    if (read_block != write_block) 
        return chunk_sz - read_offt;

    // Otherwise figure out the difference between our read and write and that's our length
    return write_offt - read_offt;
}

size_t Chainbuf::consume(size_t in_sz) {
    local_locker lock(&cblock);

    size_t consumed_sz = 0;

    while (consumed_sz < in_sz) {
        size_t rd_sz = 0;

        if (write_block != read_block) {
            rd_sz = min(in_sz, chunk_sz - read_offt);

            // We don't have to move the read block because we destroy
            // the current one and drop the array down, but we do need to move
            // the write block backwards one; we know write_block can't be 0 because
            // we're not the same block
            write_block -= 1;

            delete[](buff_vec[read_block]);
            buff_vec.erase(buff_vec.begin() + read_block);

            // We're at the head of the next chunk
            read_offt = 0;
        } else {
            rd_sz = min(in_sz, write_offt - read_offt);
            read_offt += rd_sz;
        }

        consumed_sz += rd_sz;
    }

    used_sz -= consumed_sz;
    return consumed_sz;
}

