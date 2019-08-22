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

#include "boost_like_hash.h"


#include <algorithm>
#include <functional>

#include <kis_endian.h>

#include "xxhash_cpp.h"

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const std::string& val) {
    hash.update(val.data(), val.length());
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const uint8_t& val) {
    hash.update(&val, sizeof(uint8_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const int8_t& val) {
    hash.update(&val, sizeof(int8_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const uint16_t& val) {
    auto le = htole16(val);
    hash.update(&le, sizeof(uint16_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const int16_t& val) {
    auto le = htole16(val);
    hash.update(&le, sizeof(int16_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const uint32_t& val) {
    auto le = htole32(val);
    hash.update(&le, sizeof(uint32_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const int32_t& val) {
    auto le = htole32(val);
    hash.update(&le, sizeof(int32_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const uint64_t& val) {
    auto le = htole64(val);
    hash.update(&le, sizeof(uint64_t));
}

template<> void boost_like::hash_combine(xx_hash_cpp& hash, const int64_t& val) {
    auto le = htole64(val);
    hash.update(&le, sizeof(int64_t));
}

