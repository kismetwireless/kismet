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

#ifndef __MPACK_CPP_H__
#define __MPACK_CPP_H__

#include "mpack.h"

class mpack_tree_raii {
public:
    mpack_tree_raii() { }
    ~mpack_tree_raii() {
        mpack_tree_destroy(&tree);
    }

    mpack_tree_t *operator&() {
        return &tree;
    }

protected:
    mpack_tree_t tree;
};

// Owns the buffer a growable writer allocates, so no return or throw can leak it
class mpack_growable_buf {
public:
    mpack_growable_buf() { }
    ~mpack_growable_buf() {
        MPACK_FREE(data);
    }

    mpack_growable_buf(const mpack_growable_buf&) = delete;
    mpack_growable_buf& operator=(const mpack_growable_buf&) = delete;

    char *data = nullptr;
    size_t size = 0;
};

#endif
