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

#ifndef __JSON_NUMBER_H__
#define __JSON_NUMBER_H__

#include <cmath>
#include <cstdint>
#include <optional>

#include "nlohmann/json.hpp"

// Range-checked numbers from JSON that came from a helper, a remote, a log or a file.
// get<T>() of an out of range float is undefined, and of a negative integer into an
// unsigned type wraps.
namespace json_number {
    // Doubles hold every integer up to here exactly, so the bound checks below are exact
    constexpr double max_exact_double = 9007199254740992.0;

    // A number as an integer in [lo, hi]: integers as they are, floats truncated toward
    // zero as a cast does.  Bounds must be within +/- 2^53.  NaN, infinities, out of
    // range values and non-numbers give nullopt.
    inline std::optional<int64_t> integral(const nlohmann::json& j, int64_t lo, int64_t hi) {
        if (j.is_number_unsigned()) {
            const uint64_t v = j.get<uint64_t>();

            if (hi < 0 || v > static_cast<uint64_t>(hi) || static_cast<int64_t>(v) < lo)
                return std::nullopt;

            return static_cast<int64_t>(v);
        }

        if (j.is_number_integer()) {
            const int64_t v = j.get<int64_t>();

            if (v < lo || v > hi)
                return std::nullopt;

            return v;
        }

        if (j.is_number_float()) {
            const double t = std::trunc(j.get<double>());

            if (!(t >= -max_exact_double && t <= max_exact_double))
                return std::nullopt;
            if (t < static_cast<double>(lo) || t > static_cast<double>(hi))
                return std::nullopt;

            return static_cast<int64_t>(t);
        }

        return std::nullopt;
    }

    // A JSON integer (never a float) in [0, hi]
    inline std::optional<uint64_t> unsigned_integer(const nlohmann::json& j, uint64_t hi) {
        uint64_t v = 0;

        if (j.is_number_unsigned()) {
            v = j.get<uint64_t>();
        } else if (j.is_number_integer()) {
            const int64_t s = j.get<int64_t>();

            if (s < 0)
                return std::nullopt;

            v = static_cast<uint64_t>(s);
        } else {
            return std::nullopt;
        }

        if (v > hi)
            return std::nullopt;

        return v;
    }
}

#endif
