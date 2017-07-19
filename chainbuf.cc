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

    free_read = false;
    free_commit = false;
}

Chainbuf::~Chainbuf() {
    local_locker lock(&buffer_locker);

    fprintf(stderr, "debug - freeing chainbuf, total size %lu chunks %lu\n", total_sz, (total_sz / chunk_sz) + 1);

    clear();
}

void Chainbuf::clear() {
    local_locker lock(&buffer_locker);

    for (auto x : buff_vec) 
        delete[](x);

    buff_vec.clear();
}

size_t Chainbuf::used() {
    local_locker lock(&buffer_locker);

    return used_sz;
}

size_t Chainbuf::total() {
    local_locker lock(&buffer_locker);

    return total_sz;
}

ssize_t Chainbuf::write(uint8_t *in_data, size_t in_sz) {
    local_locker lock(&buffer_locker);

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

ssize_t Chainbuf::peek(uint8_t **ret_data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (peek_reserved) {
        throw std::runtime_error("chainbuf peek already locked");
    }

    size_t goal_sz = min(used(), in_sz);

    // If we're contiguous 
    if (read_offt + goal_sz <= chunk_sz) {
        free_read = false;
        *ret_data = buff_vec[read_block] + read_offt;
        return goal_sz;
    }

    // Otherwise we have to copy it out; copy through every block until we
    // hit the max length
    free_read = true;
    *ret_data = new uint8_t[goal_sz];

    size_t left = goal_sz;
    size_t offt = read_offt;
    size_t block_offt = 0;
    size_t copy_offt = 0;

    while (left) {
        if (read_block + block_offt >= buff_vec.size())
            throw std::runtime_error("chainbuf ran out of room in buffer vector during peek");

        size_t copy_sz = chunk_sz - offt;
        if (left < copy_sz)
            copy_sz = left;

        // Copy whatever space we have in the buffer remaining
        memcpy(*ret_data + copy_offt, buff_vec[read_block + block_offt] + offt, copy_sz);
        // Subtract what we just copied
        left -= copy_sz;
        // Start at the beginning of the next buffer
        offt = 0;
        // Jump to the next buffer
        block_offt++;
        // Jump our buffer ahead by the same amount
        copy_offt += copy_sz;
    }

    return goal_sz;
}

ssize_t Chainbuf::zero_copy_peek(uint8_t **ret_data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (peek_reserved) {
        throw std::runtime_error("chainbuf peek already locked");
    }

    // Pick the least size: a zero-copy of our buffer, the requested size,
    // or the amount actually used
    size_t goal_sz = min(chunk_sz - read_offt, in_sz);
    goal_sz = min(goal_sz, used());

    *ret_data = buff_vec[read_block] + read_offt;
    free_read = false;
    return goal_sz;
}

void Chainbuf::peek_free(unsigned char *in_data) {
    local_locker lock(&buffer_locker);

    if (!peek_reserved) {
        throw std::runtime_error("chainbuf peek_free on unlocked buffer");
    }

    if (free_read) {
        delete[] in_data;
    }

    peek_reserved = false;
    free_read = false;
}

size_t Chainbuf::consume(size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (peek_reserved) {
        throw std::runtime_error("chainbuf consume while peeked data pending");
    }

    if (write_reserved) {
        throw std::runtime_error("chainbuf consume while write block is reserved");
    }

    ssize_t consumed_sz = 0;
    int block_offt = 0;

    while (consumed_sz < (ssize_t) in_sz) {
        ssize_t rd_sz = 0;

        if (read_block + block_offt >= buff_vec.size())
            throw std::runtime_error("chainbuf ran out of room in buffer vector "
                    "during consume");

        // Get either the remaining data, or the remaining chunk
        rd_sz = min(in_sz - consumed_sz, chunk_sz - read_offt);

        // Jump ahead
        consumed_sz += rd_sz;

        // Jump the read offset
        read_offt += rd_sz;

        // We've jumped to the next block...
        if (read_offt >= chunk_sz) {
            // Universal read offt jumps
            read_offt = 0;

            // Data consuming block offt jumps
            block_offt++;

            // Remove the old read block and set the slot to null
            delete[](buff_vec[read_block]);
            buff_vec[read_block] = NULL;

            // Move the global read pointer
            read_block++;
        }

    }

    used_sz -= consumed_sz;
    return consumed_sz;
}

ssize_t Chainbuf::reserve(unsigned char **data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (write_reserved) {
        throw std::runtime_error("chainbuf already locked");
    }

    // If we can fit inside the chunk we're in now...
    if (in_sz < chunk_sz - write_offt) {
        *data = buff_vec[write_block] + write_offt;
        free_commit = false;
        return in_sz;
    }

    // Otherwise we're going to have to malloc a chunk
    *data = new unsigned char[in_sz];
    free_commit = true;
    return in_sz;
}

bool Chainbuf::commit(unsigned char *data, size_t in_sz) {
    local_locker lock(&buffer_locker);

    if (!write_reserved) {
        throw std::runtime_error("chainbuf no pending commit");
    }

    // Unlock the write state
    write_reserved = false;

    // If we have allocated an interstitial buffer, we need copy the data over and delete
    // the temp buffer
    if (free_commit) {
        free_commit = false;

        ssize_t written = write(data, in_sz);

        delete[] data;

        if (written < 0)
            return false;

        return (size_t) written == in_sz;
    }

    // If we don't need to free our commit buffer, the data is already written 
    // in and we're done

    return true;
}
