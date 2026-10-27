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

#include "dr_core.h"

namespace devicerules {

namespace {

// Each op is written once and shared by the VM and the JIT's slow path.  Operands
// are copied out first: the destination is often an operand, and gcc's overflow
// builtins misreport when the result aliases an input.

template<typename F>
inline void bin(value *R, const insn *pc, F f) {
    const value x = R[pc->b];
    const value y = R[pc->c];
    value d{};
    d.valid = x.valid & y.valid;
    if (d.valid)
        d.valid = f(x, y, d);
    R[pc->a] = d;
}

template<typename F>
inline void cmp(value *R, const insn *pc, F f) {
    const value x = R[pc->b];
    const value y = R[pc->c];
    value d{};
    d.i = (x.valid & y.valid) && f(x, y);
    d.valid = 1;
    R[pc->a] = d;
}

inline void boolean(value *R, uint16_t r, bool b) {
    value d{};
    d.i = b;
    d.valid = 1;
    R[r] = d;
}

}

// One body for both the VM loop, where it's inlined, and the out-of-line step()
static __attribute__((always_inline)) inline void exec_op(const ruleset& rs, eval_ctx& ctx,
        value *R, const insn *pc) {
    const auto& consts = rs.consts;

    switch (pc->o) {
        case bc::ldi:
        case bc::ldf:
        case bc::lds:
        case bc::ldm:
            rs.load_cached(ctx, pc->b, R[pc->a]);
            break;

        case bc::ki:
        case bc::kf:
            R[pc->a] = consts[pc->b];
            R[pc->a].valid = 1;
            break;

        case bc::ks:
        case bc::km:
            // Constants are folded into the string, set and mac ops
            R[pc->a] = value{};
            break;

        case bc::now:
            boolean(R, pc->a, false);
            R[pc->a].i = ctx.now;
            break;

        case bc::i2f: {
            value d = R[pc->b];
            d.f = (double) R[pc->b].i;
            R[pc->a] = d;
            break;
        }

        case bc::addi:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    return !__builtin_add_overflow(x.i, y.i, &d.i); });
            break;
        case bc::subi:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    return !__builtin_sub_overflow(x.i, y.i, &d.i); });
            break;
        case bc::muli:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    return !__builtin_mul_overflow(x.i, y.i, &d.i); });
            break;
        case bc::divi:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    if (y.i == 0 || (x.i == INT64_MIN && y.i == -1))
                        return false;
                    d.i = x.i / y.i;
                    return true; });
            break;
        case bc::modi:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    if (y.i == 0 || (x.i == INT64_MIN && y.i == -1))
                        return false;
                    d.i = x.i % y.i;
                    return true; });
            break;
        case bc::negi: {
            const value x = R[pc->b];
            value d{};
            d.valid = x.valid && x.i != INT64_MIN;
            if (d.valid)
                d.i = -x.i;
            R[pc->a] = d;
            break;
        }

        case bc::addf:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    d.f = x.f + y.f; return true; });
            break;
        case bc::subf:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    d.f = x.f - y.f; return true; });
            break;
        case bc::mulf:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    d.f = x.f * y.f; return true; });
            break;
        case bc::divf:
            bin(R, pc, [](const value& x, const value& y, value& d) {
                    if (y.f == 0)
                        return false;
                    d.f = x.f / y.f;
                    return true; });
            break;
        case bc::negf: {
            value d = R[pc->b];
            d.f = -d.f;
            R[pc->a] = d;
            break;
        }

        case bc::eqi: cmp(R, pc, [](const value& x, const value& y) { return x.i == y.i; }); break;
        case bc::nei: cmp(R, pc, [](const value& x, const value& y) { return x.i != y.i; }); break;
        case bc::lti: cmp(R, pc, [](const value& x, const value& y) { return x.i < y.i; }); break;
        case bc::lei: cmp(R, pc, [](const value& x, const value& y) { return x.i <= y.i; }); break;
        case bc::gti: cmp(R, pc, [](const value& x, const value& y) { return x.i > y.i; }); break;
        case bc::gei: cmp(R, pc, [](const value& x, const value& y) { return x.i >= y.i; }); break;
        case bc::eqf: cmp(R, pc, [](const value& x, const value& y) { return x.f == y.f; }); break;
        case bc::nef: cmp(R, pc, [](const value& x, const value& y) { return x.f != y.f; }); break;
        case bc::ltf: cmp(R, pc, [](const value& x, const value& y) { return x.f < y.f; }); break;
        case bc::lef: cmp(R, pc, [](const value& x, const value& y) { return x.f <= y.f; }); break;
        case bc::gtf: cmp(R, pc, [](const value& x, const value& y) { return x.f > y.f; }); break;
        case bc::gef: cmp(R, pc, [](const value& x, const value& y) { return x.f >= y.f; }); break;

        case bc::seq:
        case bc::sne:
        case bc::scont:
        case bc::sicont:
        case bc::spre:
        case bc::ssuf:
        case bc::sre:
        case bc::ini:
        case bc::inf:
        case bc::ins:
        case bc::inm:
        case bc::meq:
        case bc::mne:
            boolean(R, pc->a, rs.leaf_test(ctx, pc->o, R[pc->b], pc->c));
            break;

        case bc::mpred:
            boolean(R, pc->a, rs.run_mpred(ctx, pc->b));
            break;

        case bc::exists:
            boolean(R, pc->a, rs.run_exists(ctx, pc->b));
            break;

        case bc::count:
            boolean(R, pc->a, false);
            R[pc->a].i = rs.run_count(ctx, pc->b);
            break;

        case bc::lnot:
            boolean(R, pc->a, !R[pc->b].i);
            break;

        case bc::jf:
        case bc::jt:
        case bc::jmp:
        case bc::ret:
            // Control flow belongs to the caller
            break;
    }
}

void ruleset::step(eval_ctx& ctx, const insn *pc) const {
    exec_op(*this, ctx, ctx.regs.data(), pc);
}

bool ruleset::eval_vm(eval_ctx& ctx, size_t r) const {
    return run_vm(ctx, compiled[r]).i != 0;
}

const value& ruleset::run_vm(eval_ctx& ctx, const compiled_rule& cr) const {
    const insn *base = code.data();
    const insn *pc = base + cr.entry;
    value *R = ctx.regs.data();

    while (true) {
        switch (pc->o) {
            case bc::jf:
                if (!R[pc->a].i) {
                    pc = base + pc->b;
                    continue;
                }
                break;
            case bc::jt:
                if (R[pc->a].i) {
                    pc = base + pc->b;
                    continue;
                }
                break;
            case bc::jmp:
                pc = base + pc->b;
                continue;
            case bc::ret:
                return R[pc->a];
            default:
                exec_op(*this, ctx, R, pc);
                break;
        }

        pc++;
    }
}

void ruleset::eval_all(eval_ctx& ctx, const uint8_t *want, uint8_t *out) const {
    if (jit_all != nullptr) {
        jit_all(&ctx, want, out);
        return;
    }

    for (size_t r = 0; r < compiled.size(); r++)
        out[r] = (want == nullptr || want[r]) ? eval_vm(ctx, r) : 0;
}

size_t ruleset::first_match(eval_ctx& ctx, const uint8_t *want) const {
    if (jit_first != nullptr)
        return (size_t) jit_first(&ctx, want);

    for (size_t r = 0; r < compiled.size(); r++)
        if ((want == nullptr || want[r]) && eval_vm(ctx, r))
            return r;

    return compiled.size();
}

}
