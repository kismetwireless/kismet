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

#include "config.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>

#include "dr_core.h"

// Sorts: keys are computed once per device by the same backends as rules, then
// ordered natively.  Comparing devices directly would evaluate every key on both
// devices for every comparison.

namespace devicerules {

void ruleset::eval_sort_vm(eval_ctx& ctx, size_t s, value *out) const {
    const auto& sd = *sorts[s];

    for (size_t k = 0; k < sd.keys.size(); k++) {
        if (sd.keys[k].expr != nullptr) {
            out[k] = run_vm(ctx, sd.keys[k].cr);
            continue;
        }

        value v{};
        v.i = first_match(ctx, nullptr);
        v.valid = 1;
        out[k] = v;
    }
}

void ruleset::eval_sort(eval_ctx& ctx, size_t s, value *out) const {
    if (s < jit_sorts.size()) {
        jit_sorts[s](&ctx, out);
        return;
    }

    eval_sort_vm(ctx, s, out);
}

sort_table::sort_table(const ruleset& in_rs, size_t sort) :
    rs{in_rs},
    sd{in_rs.sort(sort)},
    si{sort},
    nk{sd.keys.size()},
    rows{0} { }

void sort_table::reserve(size_t n) {
    keys.reserve(n * nk);
}

void sort_table::add(eval_ctx& ctx) {
    if (rows >= UINT32_MAX)
        throw std::runtime_error("too many devices to sort");

    keys.resize((rows + 1) * nk);
    value *k = &keys[rows * nk];
    rs.eval_sort(ctx, si, k);

    for (size_t i = 0; i < nk; i++) {
        if (!k[i].valid)
            continue;

        switch (sd.keys[i].type) {
            case vtype::string:
                strs.emplace_back(k[i].s, k[i].len);
                k[i].s = strs.back().data();
                break;
            case vtype::real:
                // NaN has no order; it sorts as missing
                if (std::isnan(k[i].f))
                    k[i].valid = 0;
                break;
            default:
                break;
        }
    }

    rows++;
}

int sort_table::compare(uint32_t a, uint32_t b) const {
    const value *ka = &keys[a * nk];
    const value *kb = &keys[b * nk];

    for (size_t i = 0; i < nk; i++) {
        const auto& x = ka[i];
        const auto& y = kb[i];

        if (x.valid != y.valid)
            return x.valid ? -1 : 1;
        if (!x.valid)
            continue;

        int c = 0;
        switch (sd.keys[i].type) {
            case vtype::real:
                c = x.f < y.f ? -1 : (x.f > y.f ? 1 : 0);
                break;
            case vtype::mac:
                c = x.m < y.m ? -1 : (x.m > y.m ? 1 : 0);
                break;
            case vtype::string: {
                int m = memcmp(x.s, y.s, std::min(x.len, y.len));
                if (m == 0)
                    c = x.len < y.len ? -1 : (x.len > y.len ? 1 : 0);
                else
                    c = m < 0 ? -1 : 1;
                break;
            }
            default:
                c = x.i < y.i ? -1 : (x.i > y.i ? 1 : 0);
                break;
        }

        if (c != 0)
            return sd.keys[i].desc ? -c : c;
    }

    return 0;
}

std::vector<uint32_t> sort_table::order() const {
    std::vector<uint32_t> o(rows);
    std::iota(o.begin(), o.end(), 0);

    std::sort(o.begin(), o.end(), [this](uint32_t a, uint32_t b) {
            int c = compare(a, b);
            return c != 0 ? c < 0 : a < b;
        });

    return o;
}

}
