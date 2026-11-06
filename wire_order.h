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

#ifndef __WIRE_ORDER_H__
#define __WIRE_ORDER_H__

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

// Wire-order loads and stores built from byte shifts, so they give the same answer on
// any host byte order and never read through a misaligned or aliased pointer; gcc
// folds them into a single load (plus bswap where needed).
namespace kismet {

template<std::unsigned_integral T>
constexpr T load_le(std::span<const uint8_t, sizeof(T)> b) {
    T r = 0;
    for (std::size_t i = 0; i < sizeof(T); i++)
        r |= static_cast<T>(b[i]) << (8 * i);
    return r;
}

template<std::unsigned_integral T>
constexpr T load_be(std::span<const uint8_t, sizeof(T)> b) {
    T r = 0;
    for (std::size_t i = 0; i < sizeof(T); i++)
        r = static_cast<T>(r << 8) | b[i];
    return r;
}

template<std::unsigned_integral T>
constexpr void store_le(std::span<uint8_t, sizeof(T)> b, T v) {
    for (std::size_t i = 0; i < sizeof(T); i++)
        b[i] = static_cast<uint8_t>(v >> (8 * i));
}

template<std::unsigned_integral T>
constexpr void store_be(std::span<uint8_t, sizeof(T)> b, T v) {
    for (std::size_t i = 0; i < sizeof(T); i++)
        b[sizeof(T) - 1 - i] = static_cast<uint8_t>(v >> (8 * i));
}

// Pointer forms for callers that have already checked the length
template<std::unsigned_integral T>
constexpr T load_le(const uint8_t *p) {
    return load_le<T>(std::span<const uint8_t, sizeof(T)>{p, sizeof(T)});
}

template<std::unsigned_integral T>
constexpr T load_be(const uint8_t *p) {
    return load_be<T>(std::span<const uint8_t, sizeof(T)>{p, sizeof(T)});
}

template<std::unsigned_integral T>
constexpr void store_le(uint8_t *p, T v) {
    store_le<T>(std::span<uint8_t, sizeof(T)>{p, sizeof(T)}, v);
}

template<std::unsigned_integral T>
constexpr void store_be(uint8_t *p, T v) {
    store_be<T>(std::span<uint8_t, sizeof(T)>{p, sizeof(T)}, v);
}

namespace endian_test {
    constexpr std::array<uint8_t, 8> b{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    static_assert(load_le<uint16_t>(b.data()) == 0x0201);
    static_assert(load_be<uint16_t>(b.data()) == 0x0102);
    static_assert(load_le<uint32_t>(b.data()) == 0x04030201);
    static_assert(load_be<uint32_t>(b.data()) == 0x01020304);
    static_assert(load_le<uint64_t>(b.data()) == 0x0807060504030201ULL);
    static_assert(load_be<uint64_t>(b.data()) == 0x0102030405060708ULL);
    static_assert(load_le<uint8_t>(b.data() + 7) == 0x08);

    constexpr bool round_trip() {
        std::array<uint8_t, 8> o{};
        store_le<uint32_t>(o.data(), 0xa1b2c3d4);
        store_be<uint32_t>(o.data() + 4, 0xa1b2c3d4);
        return o[0] == 0xd4 && o[3] == 0xa1 && o[4] == 0xa1 && o[7] == 0xd4 &&
            load_le<uint32_t>(o.data()) == load_be<uint32_t>(o.data() + 4);
    }
    static_assert(round_trip());
}

}

#endif
