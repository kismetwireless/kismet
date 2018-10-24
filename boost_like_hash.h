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

// Boost-like functionality without bringing in all of boost; we emulate the boost
// hash_combine function for instance but plumb it into a consistent xxhash32 engine

#ifndef __BOOST_LIKE_H__
#define __BOOST_LIKE_H__

#include "config.h"

#include <string>
#include <stdint.h>

#include "xxhash32.h"

namespace boost_like {

    template<typename T> void hash_combine(XXHash32& hash, const T& val);

    template<> void hash_combine(XXHash32& hash, const std::string& val);
    template<> void hash_combine(XXHash32& hash, const uint8_t& val);
    template<> void hash_combine(XXHash32& hash, const int8_t& val);
    template<> void hash_combine(XXHash32& hash, const uint16_t& val);
    template<> void hash_combine(XXHash32& hash, const int16_t& val);
    template<> void hash_combine(XXHash32& hash, const uint32_t& val);
    template<> void hash_combine(XXHash32& hash, const int32_t& val);
    template<> void hash_combine(XXHash32& hash, const uint64_t& val);
    template<> void hash_combine(XXHash32& hash, const int64_t& val);
    template<> void hash_combine(XXHash32& hash, const float& val);
    template<> void hash_combine(XXHash32& hash, const double& val);

    template<typename T, typename... Ts>
        XXHash32 hash_combine(XXHash32& hash, const T& arg1, const Ts&... args) {
            hash_combine(hash, arg1);
            hash_combine(hash, args...);
            return hash;
        } 

}

#endif

