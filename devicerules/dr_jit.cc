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

#include <cstddef>
#include <cstring>
#include <map>

#include "dr_core.h"

#include "dr_sljit_config.h"
#include "sljit/sljitLir.h"

// The JIT turns the bytecode of every rule into one native function.  Constants,
// integer arithmetic and compares, mac tests, logic, jumps and cached field loads
// are inlined; anything else calls ruleset::step, the same code the VM runs.

namespace devicerules {

namespace {

#if (defined SLJIT_64BIT_ARCHITECTURE && SLJIT_64BIT_ARCHITECTURE) && \
    !(defined SLJIT_CONFIG_UNSUPPORTED && SLJIT_CONFIG_UNSUPPORTED)
#define DR_JIT_SUPPORTED 1
#endif

#ifdef DR_JIT_SUPPORTED

void h_step(eval_ctx *ctx, const insn *pc) {
    ctx->rs->step(*ctx, pc);
}

void h_load(eval_ctx *ctx, sljit_sw slot, value *dst) {
    ctx->rs->load_cached(*ctx, (uint32_t) slot, *dst);
}

constexpr sljit_s32 CTX = SLJIT_S0;
constexpr sljit_s32 WANT = SLJIT_S1;
constexpr sljit_s32 OUT = SLJIT_S2;
constexpr sljit_s32 REGS = SLJIT_S3;

constexpr sljit_sw val_off(uint32_t r) {
    return (sljit_sw) r * (sljit_sw) sizeof(value);
}

constexpr sljit_sw valid_off(uint32_t r) {
    return val_off(r) + (sljit_sw) offsetof(value, valid);
}

#endif

}

#ifdef DR_JIT_SUPPORTED

class jit_builder {
public:
    jit_builder(ruleset& rs) :
        rs{rs}, c{nullptr} { }

    ~jit_builder() {
        if (c != nullptr)
            sljit_free_compiler(c);
    }

    // The all-rules function, or with first set, the first-match function
    void *build(bool in_first, std::string& err) {
        first = in_first;
        c = sljit_create_compiler(nullptr);
        if (c == nullptr) {
            err = "could not create the jit compiler";
            return nullptr;
        }

        // Field offsets are taken from a live instance rather than offsetof, since
        // eval_ctx holds vectors
        eval_ctx probe;
        auto base = reinterpret_cast<const char *>(&probe);
        off_now = reinterpret_cast<const char *>(&probe.now) - base;
        off_rp = reinterpret_cast<const char *>(&probe.rp) - base;
        off_cp = reinterpret_cast<const char *>(&probe.cp) - base;
        off_gen = reinterpret_cast<const char *>(&probe.gen) - base;

        eval_ctx::cache_ent ce;
        auto cbase = reinterpret_cast<const char *>(&ce);
        cache_sz = sizeof(eval_ctx::cache_ent);
        cache_gen = reinterpret_cast<const char *>(&ce.gen) - cbase;
        cache_v = reinterpret_cast<const char *>(&ce.v) - cbase;

        if (first)
            sljit_emit_enter(c, 0, SLJIT_ARGS2(W, P, P), 3, 4, 0);
        else
            sljit_emit_enter(c, 0, SLJIT_ARGS3V(P, P, P), 3, 4, 0);
        sljit_emit_op1(c, SLJIT_MOV_P, REGS, 0, SLJIT_MEM1(CTX), off_rp);

        for (size_t r = 0; r < rs.compiled.size(); r++)
            rule(r);

        if (first)
            sljit_emit_return(c, SLJIT_MOV, SLJIT_IMM, (sljit_sw) rs.compiled.size());
        else
            sljit_emit_return_void(c);

        if (sljit_get_compiler_error(c) != SLJIT_SUCCESS) {
            err = "jit code generation failed";
            return nullptr;
        }

        auto code = sljit_generate_code(c, 0, nullptr);
        if (code == nullptr)
            err = "could not map executable memory for the jit";

        return code;
    }

private:
    ruleset& rs;
    struct sljit_compiler *c;
    bool first;
    sljit_sw off_now, off_rp, off_cp, off_gen;
    sljit_sw cache_sz, cache_gen, cache_v;

    void set_valid(uint16_t r, sljit_sw v) {
        sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_MEM1(REGS), valid_off(r), SLJIT_IMM, v);
    }

    // R2 = valid(b) & valid(c)
    void both_valid(uint32_t b, uint32_t cr) {
        sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_R2, 0, SLJIT_MEM1(REGS), valid_off(b));
        sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_R1, 0, SLJIT_MEM1(REGS), valid_off(cr));
        sljit_emit_op2(c, SLJIT_AND, SLJIT_R2, 0, SLJIT_R2, 0, SLJIT_R1, 0);
    }

    // Store R0 & R2 as a boolean result
    void store_bool_and_valid(uint16_t a) {
        sljit_emit_op2(c, SLJIT_AND, SLJIT_R0, 0, SLJIT_R0, 0, SLJIT_R2, 0);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(a), SLJIT_R0, 0);
        set_valid(a, 1);
    }

    void call_step(const insn *pc) {
        sljit_emit_op1(c, SLJIT_MOV_P, SLJIT_R0, 0, CTX, 0);
        sljit_emit_op1(c, SLJIT_MOV_P, SLJIT_R1, 0, SLJIT_IMM, (sljit_sw) pc);
        sljit_emit_icall(c, SLJIT_CALL, SLJIT_ARGS2V(P, P), SLJIT_IMM, SLJIT_FUNC_ADDR(h_step));
    }

    void load(const insn& in) {
        // Cache hit: copy the cached value; miss: load through the env
        sljit_emit_op1(c, SLJIT_MOV_P, SLJIT_R1, 0, SLJIT_MEM1(CTX), off_cp);
        sljit_emit_op1(c, SLJIT_MOV_U32, SLJIT_R0, 0, SLJIT_MEM1(SLJIT_R1),
                (sljit_sw) in.b * cache_sz + cache_gen);
        sljit_emit_op1(c, SLJIT_MOV_U32, SLJIT_R2, 0, SLJIT_MEM1(CTX), off_gen);
        auto miss = sljit_emit_cmp(c, SLJIT_NOT_EQUAL, SLJIT_R0, 0, SLJIT_R2, 0);

        sljit_sw src = (sljit_sw) in.b * cache_sz + cache_v;
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(SLJIT_R1), src);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R2, 0, SLJIT_MEM1(SLJIT_R1), src + 8);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a), SLJIT_R0, 0);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a) + 8, SLJIT_R2, 0);
        auto done = sljit_emit_jump(c, SLJIT_JUMP);

        sljit_set_label(miss, sljit_emit_label(c));
        sljit_emit_op1(c, SLJIT_MOV_P, SLJIT_R0, 0, CTX, 0);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R1, 0, SLJIT_IMM, (sljit_sw) in.b);
        sljit_emit_op2(c, SLJIT_ADD, SLJIT_R2, 0, REGS, 0, SLJIT_IMM, val_off(in.a));
        sljit_emit_icall(c, SLJIT_CALL, SLJIT_ARGS3V(P, W, P), SLJIT_IMM, SLJIT_FUNC_ADDR(h_load));

        sljit_set_label(done, sljit_emit_label(c));
    }

    void konst(const insn& in) {
        sljit_sw bits;
        static_assert(sizeof(bits) == sizeof(rs.consts[0].i), "word size");
        memcpy(&bits, &rs.consts[in.b].i, sizeof(bits));
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a), SLJIT_IMM, bits);
        set_valid(in.a, 1);
    }

    void arith(const insn& in, sljit_s32 op) {
        both_valid(in.b, in.c);
        auto bad = sljit_emit_cmp(c, SLJIT_EQUAL, SLJIT_R2, 0, SLJIT_IMM, 0);

        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(REGS), val_off(in.b));
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R1, 0, SLJIT_MEM1(REGS), val_off(in.c));
        sljit_emit_op2(c, op | SLJIT_SET_OVERFLOW, SLJIT_R0, 0, SLJIT_R0, 0, SLJIT_R1, 0);
        auto ovf = sljit_emit_jump(c, SLJIT_OVERFLOW);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a), SLJIT_R0, 0);
        set_valid(in.a, 1);
        auto done = sljit_emit_jump(c, SLJIT_JUMP);

        auto lbad = sljit_emit_label(c);
        sljit_set_label(bad, lbad);
        sljit_set_label(ovf, lbad);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a), SLJIT_IMM, 0);
        set_valid(in.a, 0);

        sljit_set_label(done, sljit_emit_label(c));
    }

    void icmp(const insn& in, sljit_s32 setf, sljit_s32 cond) {
        both_valid(in.b, in.c);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(REGS), val_off(in.b));
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R1, 0, SLJIT_MEM1(REGS), val_off(in.c));
        sljit_emit_op2u(c, SLJIT_SUB | setf, SLJIT_R0, 0, SLJIT_R1, 0);
        sljit_emit_op_flags(c, SLJIT_MOV, SLJIT_R0, 0, cond);
        store_bool_and_valid(in.a);
    }

    void mac(const insn& in, bool eq) {
        const auto& km = rs.const_macs[in.c];
        sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_R2, 0, SLJIT_MEM1(REGS), valid_off(in.b));
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(REGS), val_off(in.b));
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R1, 0, SLJIT_IMM, (sljit_sw) km.second);
        sljit_emit_op2(c, SLJIT_AND, SLJIT_R0, 0, SLJIT_R0, 0, SLJIT_R1, 0);
        sljit_emit_op1(c, SLJIT_MOV, SLJIT_R1, 0, SLJIT_IMM, (sljit_sw) km.first);
        sljit_emit_op2u(c, SLJIT_SUB | SLJIT_SET_Z, SLJIT_R0, 0, SLJIT_R1, 0);
        sljit_emit_op_flags(c, SLJIT_MOV, SLJIT_R0, 0, eq ? SLJIT_EQUAL : SLJIT_NOT_EQUAL);
        store_bool_and_valid(in.a);
    }

    void rule(size_t r) {
        const auto& cr = rs.compiled[r];

        // Skip rules the caller didn't ask for
        auto all = sljit_emit_cmp(c, SLJIT_EQUAL, WANT, 0, SLJIT_IMM, 0);
        sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_R0, 0, SLJIT_MEM1(WANT), (sljit_sw) r);
        auto wanted = sljit_emit_cmp(c, SLJIT_NOT_EQUAL, SLJIT_R0, 0, SLJIT_IMM, 0);
        if (!first)
            sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_MEM1(OUT), (sljit_sw) r, SLJIT_IMM, 0);
        auto skip = sljit_emit_jump(c, SLJIT_JUMP);

        auto run = sljit_emit_label(c);
        sljit_set_label(all, run);
        sljit_set_label(wanted, run);

        // Jumps are forward only; patch each when its target is reached
        std::multimap<size_t, struct sljit_jump *> pending;
        std::vector<struct sljit_jump *> to_end;

        for (size_t i = 0; i < cr.len; i++) {
            size_t pos = cr.entry + i;
            const auto& in = rs.code[pos];

            auto pr = pending.equal_range(pos);
            if (pr.first != pr.second) {
                auto l = sljit_emit_label(c);
                for (auto pi = pr.first; pi != pr.second; ++pi)
                    sljit_set_label(pi->second, l);
                pending.erase(pr.first, pr.second);
            }

            switch (in.o) {
                case bc::ldi:
                case bc::ldf:
                case bc::lds:
                case bc::ldm:
                    load(in);
                    break;

                case bc::ki:
                case bc::kf:
                    konst(in);
                    break;

                case bc::now:
                    sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(CTX), off_now);
                    sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a), SLJIT_R0, 0);
                    set_valid(in.a, 1);
                    break;

                case bc::addi: arith(in, SLJIT_ADD); break;
                case bc::subi: arith(in, SLJIT_SUB); break;
                case bc::muli: arith(in, SLJIT_MUL); break;

                case bc::eqi: icmp(in, SLJIT_SET_Z, SLJIT_EQUAL); break;
                case bc::nei: icmp(in, SLJIT_SET_Z, SLJIT_NOT_EQUAL); break;
                case bc::lti: icmp(in, SLJIT_SET_SIG_LESS, SLJIT_SIG_LESS); break;
                case bc::lei: icmp(in, SLJIT_SET_SIG_LESS_EQUAL, SLJIT_SIG_LESS_EQUAL); break;
                case bc::gti: icmp(in, SLJIT_SET_SIG_GREATER, SLJIT_SIG_GREATER); break;
                case bc::gei: icmp(in, SLJIT_SET_SIG_GREATER_EQUAL, SLJIT_SIG_GREATER_EQUAL); break;

                case bc::meq: mac(in, true); break;
                case bc::mne: mac(in, false); break;

                case bc::lnot:
                    sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(REGS), val_off(in.b));
                    sljit_emit_op2u(c, SLJIT_SUB | SLJIT_SET_Z, SLJIT_R0, 0, SLJIT_IMM, 0);
                    sljit_emit_op_flags(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_EQUAL);
                    sljit_emit_op1(c, SLJIT_MOV, SLJIT_MEM1(REGS), val_off(in.a), SLJIT_R0, 0);
                    set_valid(in.a, 1);
                    break;

                case bc::jf:
                case bc::jt: {
                    sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(REGS), val_off(in.a));
                    auto j = sljit_emit_cmp(c, in.o == bc::jf ? SLJIT_EQUAL : SLJIT_NOT_EQUAL,
                            SLJIT_R0, 0, SLJIT_IMM, 0);
                    pending.emplace(in.b, j);
                    break;
                }

                case bc::jmp:
                    pending.emplace(in.b, sljit_emit_jump(c, SLJIT_JUMP));
                    break;

                case bc::ret:
                    sljit_emit_op1(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_MEM1(REGS), val_off(in.a));
                    if (first) {
                        // No match falls through to the next rule
                        to_end.push_back(sljit_emit_cmp(c, SLJIT_EQUAL, SLJIT_R0, 0, SLJIT_IMM, 0));
                        sljit_emit_return(c, SLJIT_MOV, SLJIT_IMM, (sljit_sw) r);
                        break;
                    }
                    sljit_emit_op2u(c, SLJIT_SUB | SLJIT_SET_Z, SLJIT_R0, 0, SLJIT_IMM, 0);
                    sljit_emit_op_flags(c, SLJIT_MOV, SLJIT_R0, 0, SLJIT_NOT_EQUAL);
                    sljit_emit_op1(c, SLJIT_MOV_U8, SLJIT_MEM1(OUT), (sljit_sw) r, SLJIT_R0, 0);
                    to_end.push_back(sljit_emit_jump(c, SLJIT_JUMP));
                    break;

                default:
                    call_step(&in);
                    break;
            }
        }

        // Jumps past the end of a rule can't happen, but don't leave any dangling
        auto end = sljit_emit_label(c);
        for (auto& p : pending)
            sljit_set_label(p.second, end);
        for (auto j : to_end)
            sljit_set_label(j, end);
        sljit_set_label(skip, end);
    }
};

#endif

ruleset::~ruleset() {
#ifdef DR_JIT_SUPPORTED
    if (jit_code != nullptr)
        sljit_free_code(jit_code, nullptr);
    if (jit_first_code != nullptr)
        sljit_free_code(jit_first_code, nullptr);
#endif

#ifdef HAVE_LIBPCRE2
    for (auto& r : regexes)
        pcre2_code_free(r.re);
    if (mctx != nullptr)
        pcre2_match_context_free(mctx);
#endif
}

bool ruleset::jit(std::string& err) {
    if (!compiled_ok) {
        err = "rules are not compiled";
        return false;
    }

    if (jit_code != nullptr)
        return true;

#ifdef DR_JIT_SUPPORTED
    auto code = jit_builder(*this).build(false, err);
    if (code == nullptr)
        return false;

    // Both functions or neither, so the two entry points never mix backends
    auto first_code = jit_builder(*this).build(true, err);
    if (first_code == nullptr) {
        sljit_free_code(code, nullptr);
        return false;
    }

    jit_code = code;
    jit_all = reinterpret_cast<jit_all_fn>(code);
    jit_first_code = first_code;
    jit_first = reinterpret_cast<jit_first_fn>(first_code);
    return true;
#else
    err = "the rules jit needs a 64-bit platform sljit supports";
    return false;
#endif
}

}
