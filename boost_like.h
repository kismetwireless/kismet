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

// Boost-like functionality without bringing in all of boost; we use the boost
// hash_combine function for instance


#include <functional>

#ifndef __BOOST_LIKE_H__
#define __BOOST_LIKE_H__

namespace boost_like {

template<typename T>
void hash_combine(size_t& seed, const T& val) {
    seed ^= std::hash<T>()(val) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}

template<typename T, typename... Ts>
size_t hash_combine(size_t& seed, const T& arg1, const Ts&... args) {
    hash_combine(seed, arg1);
    hash_combine(seed, args...);
    return seed;
} 

}

#endif

