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

#ifndef __XXHASH_CPP_H__
#define __XXHASH_CPP_H__

#include "config.h"

#include <stdint.h>
#include <stdexcept>
#include <sstream>

#include "kis_endian.h"
#include "xxhash.h"

class xx_hash_cpp {
public:
    xx_hash_cpp() :
        state { XXH32_createState() } {

        XXH_errorcode const result = XXH32_reset(state, 0);

        if (result == XXH_ERROR)
            throw std::runtime_error("could not initialize xxhash32 state");
    }

    xx_hash_cpp(uint32_t init_seed) :
        state { XXH32_createState() } { 

        XXH_errorcode const result = XXH32_reset(state, init_seed);

        if (result == XXH_ERROR)
            throw std::runtime_error("could not initialize xxhash32 state");
    }

    ~xx_hash_cpp() {
        XXH32_freeState(state);
    }

    void update(const void *data, size_t len) {
        XXH_errorcode const result = XXH32_update(state, data, len);

        if (result == XXH_ERROR)
            throw std::runtime_error("could not update xxhash32");
    }

    uint32_t hash() {
        return htole32(XXH32_digest(state));
    }

    std::string canonical() {
        XXH32_canonical_t digest;
        XXH32_canonicalFromHash(&digest, hash());

        std::stringstream ss;
        ss << std::hex << std::uppercase << 
            (unsigned int) digest.digest[0] << (unsigned int) digest.digest[1] << 
            (unsigned int) digest.digest[2] << (unsigned int) digest.digest[3];

        return ss.str();
    }

protected:
    XXH32_state_t * const state;
};

#endif

