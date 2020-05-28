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

chainbuf::chainbuf(size_t in_chunk, size_t pre_allocate) {
    chunk_sz = in_chunk;

    // Allocate slots in the vector, but not bytes
    buff_vec = std::vector<char *>();
    buff_vec.reserve(pre_allocate);

    buff_vec.push_back(new char[chunk_sz]);

    used_sz = 0;
    total_sz = 0;

    write_block = 0;
    write_buf = buff_vec[0];
    read_block = 0;
    read_buf = buff_vec[0];
    write_offt = 0;
    read_offt = 0;

    free_read = false;
    free_commit = false;

    alloc_delta = 0;
}

chainbuf::~chainbuf() {
    local_locker lock(&write_mutex);

    clear();
}

void chainbuf::clear_impl() {
    for (auto x : buff_vec) 
        delete[](x);

    buff_vec.clear();
}

size_t chainbuf::used_impl() {
    local_locker lock(&write_mutex);

    return used_sz;
}

ssize_t chainbuf::write_impl(const char *in_data, size_t in_sz) {
    size_t total_written = 0;

    while (total_written < in_sz) {
        // Available in this chunk
        size_t free_chunk_sz = chunk_sz - write_offt;

        // Whole buffer or whole chunk
        size_t w_sz = std::min(in_sz - total_written, free_chunk_sz);

        if (in_data != NULL) {
            if (w_sz == 1)
                write_buf[write_offt] = in_data[total_written];
            else {
                memcpy(write_buf + write_offt, in_data + total_written, w_sz);
            }
        }

        write_offt += w_sz;

        total_written += w_sz;

        used_sz += w_sz;
        total_sz += w_sz;

        // If we got here and we have more data, then we must need another chunk
        if (total_written < in_sz) {
            char *newchunk = new char[chunk_sz];
            buff_vec.push_back(newchunk);
            write_block++;
            write_buf = buff_vec[write_block];

            // fprintf(stderr, "debug - allocated new chunk %u\n", write_block);

            if (read_buf == NULL) {
                read_buf = buff_vec[read_block];
            }

            // Track the max simultaneously allocated
            if (write_block - read_block > alloc_delta)
                alloc_delta = write_block - read_block;

            write_offt = 0;
        }
    }

    return total_written;
}

ssize_t chainbuf::peek_impl(char **ret_data, size_t in_sz) {
    if (used() == 0) {
        free_read = false;
        peek_reserved = true;

        *ret_data = NULL;
        return 0;
    }

    size_t goal_sz = std::min(used(), in_sz);

    // If we're contiguous 
    if (read_offt + goal_sz < chunk_sz) {
        free_read = false;
        peek_reserved = true;

        *ret_data = read_buf + read_offt;
        return goal_sz;
    }

    // Otherwise we have to copy it out; copy through every block until we
    // hit the max length
    free_read = true;
    peek_reserved = true;
    *ret_data = new char[goal_sz];

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
        memcpy(*ret_data + copy_offt, read_buf + block_offt + offt, copy_sz);
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

ssize_t chainbuf::zero_copy_peek_impl(char **ret_data, size_t in_sz) {
    if (used() == 0) {
        free_read = false;
        peek_reserved = true;

        *ret_data = NULL;

        return 0;
    }

    if (read_buf == NULL) {
        throw std::runtime_error("chainbuf advanced into null readbuf");
    }

    // Pick the least size: a zero-copy of our buffer, the requested size,
    // or the amount actually used
    size_t goal_sz = std::min(chunk_sz - read_offt, in_sz);
    goal_sz = std::min(goal_sz, used());

    *ret_data = read_buf + read_offt;

    peek_reserved = true;
    free_read = false;

    return goal_sz;
}

void chainbuf::peek_free_impl(char *in_data) {
    if (free_read && in_data != NULL) {
        delete[] in_data;
    }

    peek_reserved = false;
    free_read = false;
}

size_t chainbuf::consume_impl(size_t in_sz) {
    ssize_t consumed_sz = 0;
    int block_offt = 0;

    while (consumed_sz < (ssize_t) in_sz) {
        ssize_t rd_sz = 0;

        // If we've wandered out of our block...
        if (read_block + block_offt >= buff_vec.size())
            throw std::runtime_error("chainbuf ran out of room in buffer vector "
                    "during consume");

        // Get either the remaining data, or the remaining chunk
        rd_sz = std::min(in_sz - consumed_sz, chunk_sz - read_offt);

        // Jump ahead
        consumed_sz += rd_sz;

        // Jump the read offset
        read_offt += rd_sz;

        // We've jumped to the next block...
        if (read_offt >= chunk_sz) {
            // fprintf(stderr, "debug - read consumed %u, deleting\n", read_block);

            // Universal read offt jumps
            read_offt = 0;

            // Data consuming block offt jumps
            block_offt++;

            // Remove the old read block and set the slot to null
            delete[](buff_vec[read_block]);
            buff_vec[read_block] = NULL;

            // Move the global read pointer
            read_block++;

            if (read_block < buff_vec.size()) 
                read_buf = buff_vec[read_block];
            else
                read_buf = NULL;
        }

    }

    used_sz -= consumed_sz;
    return consumed_sz;
}

ssize_t chainbuf::reserve_impl(char **data, size_t in_sz) {
    // If we can fit inside the chunk we're in now...
    if (in_sz < chunk_sz - write_offt) {
        *data = write_buf + write_offt;
        free_commit = false;
        return in_sz;
    }

    // Otherwise we're going to have to malloc a chunk
    *data = new char[in_sz];
    free_commit = true;
    return in_sz;
}

ssize_t chainbuf::zero_copy_reserve_impl(char **data, size_t in_sz) {
    // We can't do better than our zero copy attempt
    return reserve(data, in_sz);
}

