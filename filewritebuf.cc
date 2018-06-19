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

#include <stdio.h>

#include "util.h"
#include "filewritebuf.h"

FileWritebuf::FileWritebuf(std::string in_filename, size_t in_chunk) {
    filename = in_filename;
    chunk_sz = in_chunk;

    reserve_chunk = NULL;
    free_commit = false;

    if ((backfile = fopen(in_filename.c_str(), "wb")) == NULL) {
        throw std::runtime_error("Unable to open file " + in_filename + ":" + 
                kis_strerror_r(errno));
        return;
    }

    reserve_chunk = new uint8_t[chunk_sz];
}

FileWritebuf::~FileWritebuf() {
    local_locker lock(&write_mutex);

    if (backfile != NULL) {
        fflush(backfile);
        fclose(backfile);
        backfile = NULL;
    }

    if (reserve_chunk != NULL)
        delete[] reserve_chunk;
       
}

void FileWritebuf::clear() {
    local_locker lock(&write_mutex);
   
    if (backfile != NULL) {
        if (ftruncate(fileno(backfile), 0) < 0) {
            fflush(backfile);
            fclose(backfile);
            backfile = NULL;
        }
    }
}

size_t FileWritebuf::used() {
    local_locker lock(&write_mutex);

    if (backfile != NULL) 
        return (size_t) ftell(backfile);

    return 0;
}

size_t FileWritebuf::total() {
    local_locker lock(&write_mutex);

    if (backfile != NULL)
        return (size_t) ftell(backfile);

    return 0;
}

ssize_t FileWritebuf::write(uint8_t *in_data, size_t in_sz) {
    local_locker lock(&write_mutex);

    if (backfile == NULL)
        return -1;

    size_t written = fwrite(in_data, in_sz, 1, backfile);

    if (written == 1)
        return in_sz;

    return 0;
}

ssize_t FileWritebuf::reserve(unsigned char **data, size_t in_sz) {
    local_eol_locker lock(&write_mutex);

    if (write_reserved) {
        throw std::runtime_error("filebuf already reserved");
    }

    write_reserved = true;

    if (in_sz < chunk_sz) {
        *data = reserve_chunk;
        free_commit = false;
        return in_sz;
    }

    *data = new unsigned char[in_sz];
    free_commit = true;
    return in_sz;

}

ssize_t FileWritebuf::zero_copy_reserve(unsigned char **data, size_t in_sz) {
    return reserve(data, in_sz);
}

bool FileWritebuf::commit(unsigned char *data, size_t in_sz) {
    local_unlocker unwritelock(&write_mutex);

    if (!write_reserved) 
        throw std::runtime_error("filebuf no pending commit");

    if (backfile == NULL)
        throw std::runtime_error("filebuf could not open " + filename);

    write_reserved = false;

    size_t written = fwrite(data, in_sz, 1, backfile);

    if (free_commit) {
        free_commit = false;
        delete[] data;
    }

    return written == 1;
}

