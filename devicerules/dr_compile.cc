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

#include <cmath>
#include <cstring>
#include <sstream>

#include "dr_core.h"

namespace devicerules {

namespace {

struct alias {
    const char *name;
    const char *path;
};

constexpr alias aliases[] = {
    { "mac", "kismet.device.base.macaddr" },
    { "name", "kismet.device.base.commonname" },
    { "phy", "kismet.device.base.phyname" },
    { "type", "kismet.device.base.type" },
    { "manuf", "kismet.device.base.manuf" },
    { "crypt", "kismet.device.base.crypt" },
    { "channel", "kismet.device.base.channel" },
    { "frequency", "kismet.device.base.frequency" },
    { "packets", "kismet.device.base.packets.total" },
    { "datasize", "kismet.device.base.datasize" },
    { "first_time", "kismet.device.base.first_time" },
    { "last_time", "kismet.device.base.last_time" },
    { "mod_time", "kismet.device.base.mod_time" },
    { "num_alerts", "kismet.device.base.num_alerts" },
    { "signal", "kismet.device.base.signal/kismet.common.signal.last_signal" },
    { "min_signal", "kismet.device.base.signal/kismet.common.signal.min_signal" },
    { "max_signal", "kismet.device.base.signal/kismet.common.signal.max_signal" },
    { "seenby", "kismet.device.base.seenby" },
};

bool is_numeric(vtype t) {
    return t == vtype::integer || t == vtype::real;
}

std::vector<std::string> split_path(const std::string& in) {
    std::vector<std::string> ret;
    size_t s = 0;

    while (true) {
        auto e = in.find('/', s);
        ret.push_back(in.substr(s, e == std::string::npos ? std::string::npos : e - s));
        if (e == std::string::npos)
            break;
        s = e + 1;
    }

    return ret;
}

op mirror(op o) {
    switch (o) {
        case op::lt: return op::gt;
        case op::le: return op::ge;
        case op::gt: return op::lt;
        case op::ge: return op::le;
        default: return o;
    }
}

bc int_cmp(op o) {
    switch (o) {
        case op::eq: return bc::eqi;
        case op::ne: return bc::nei;
        case op::lt: return bc::lti;
        case op::le: return bc::lei;
        case op::gt: return bc::gti;
        default: return bc::gei;
    }
}

bc real_cmp(op o) {
    switch (o) {
        case op::eq: return bc::eqf;
        case op::ne: return bc::nef;
        case op::lt: return bc::ltf;
        case op::le: return bc::lef;
        case op::gt: return bc::gtf;
        default: return bc::gef;
    }
}

bc str_op(op o) {
    switch (o) {
        case op::eq: return bc::seq;
        case op::ne: return bc::sne;
        case op::contains: return bc::scont;
        case op::icontains: return bc::sicont;
        case op::startswith: return bc::spre;
        case op::endswith: return bc::ssuf;
        default: return bc::sre;
    }
}

}

class compiler {
public:
    compiler(ruleset& rs, resolver& r) :
        rs{rs}, res{r}, cur_now{nullptr} { }

    void compile_all() {
        for (auto& r : rs.rules) {
            cur_what = "rule '" + r->name + "'";
            cur_now = &r->uses_now;
            r->uses_now = false;
            check(r->expr, true);

            compiled_rule cr;
            cr.entry = rs.code.size();
            nregs = 1;
            gen(r->expr.get(), 0);
            emit(bc::ret, 0, 0, 0);
            cr.len = rs.code.size() - cr.entry;
            cr.nregs = nregs;
            rs.compiled.push_back(cr);

            if (nregs > rs.nregs_max)
                rs.nregs_max = nregs;
            if (r->uses_now)
                rs.any_now = true;
        }

        for (auto& s : rs.sorts) {
            cur_what = "sort '" + s->name + "'";
            cur_now = &s->uses_now;
            s->uses_now = false;

            for (auto& k : s->keys) {
                if (k.expr == nullptr) {
                    k.type = vtype::integer;
                    continue;
                }

                check(k.expr, false);

                if (is_multi(k.expr))
                    error(k.expr.get(), "fields with several values can't be sort keys");
                if (k.expr->kind == nkind::literal)
                    error(k.expr.get(), "a sort key can't be a constant");

                switch (k.expr->type) {
                    case vtype::boolean:
                    case vtype::integer:
                    case vtype::real:
                    case vtype::string:
                    case vtype::mac:
                        break;
                    default:
                        error(k.expr.get(), "can't sort by this");
                }

                k.type = k.expr->type;
                k.cr.entry = rs.code.size();
                nregs = 1;
                gen(k.expr.get(), 0);
                emit(bc::ret, 0, 0, 0);
                k.cr.len = rs.code.size() - k.cr.entry;
                k.cr.nregs = nregs;

                if (nregs > rs.nregs_max)
                    rs.nregs_max = nregs;
            }

            if (s->uses_now)
                rs.any_now = true;
        }
    }

private:
    ruleset& rs;
    resolver& res;
    std::string cur_what;
    bool *cur_now;
    uint16_t nregs;
    ankerl::unordered_dense::map<std::string, int> slot_map;

    [[noreturn]] void error(const node *n, const std::string& msg) {
        throw parse_error(cur_what + ": " + msg, n->line, n->col);
    }

    int resolve_field(const node *n, const std::string& text) {
        std::string full = text;

        if (text.find('.') == std::string::npos && text.find('/') == std::string::npos) {
            bool found = false;
            for (const auto& a : aliases) {
                if (text == a.name) {
                    full = a.path;
                    found = true;
                    break;
                }
            }
            if (!found)
                error(n, "unknown field '" + text + "'");
        }

        auto sm = slot_map.find(full);
        if (sm != slot_map.end())
            return sm->second;

        field_slot fs;
        fs.text = full;
        fs.multi = false;
        fs.type = vtype::none;
        fs.leaf = ftype::unsupported;

        auto parts = split_path(full);

        for (size_t i = 0; i < parts.size(); i++) {
            ftype t;
            int id = res.resolve(parts[i], t);

            if (id < 0)
                error(n, "unknown field '" + parts[i] + "'");

            bool last = i + 1 == parts.size();

            if (!last && t != ftype::map && t != ftype::container)
                error(n, "'" + parts[i] + "' has no fields under it");

            fs.path.push_back(id);
            fs.fanout.push_back(!last && t == ftype::container);
            if (!last && t == ftype::container)
                fs.multi = true;

            if (last)
                fs.leaf = t;
        }

        switch (fs.leaf) {
            case ftype::integer:
            case ftype::uinteger:
                fs.type = vtype::integer;
                break;
            case ftype::real:
                fs.type = vtype::real;
                break;
            case ftype::string:
                fs.type = vtype::string;
                break;
            case ftype::mac:
                fs.type = vtype::mac;
                break;
            case ftype::string_list:
                fs.type = vtype::string;
                fs.multi = true;
                break;
            case ftype::real_list:
                fs.type = vtype::real;
                fs.multi = true;
                break;
            default:
                fs.type = vtype::none;
                break;
        }

        if (rs.fields.size() >= 65535)
            error(n, "too many fields");

        int slot = rs.fields.size();
        rs.fields.push_back(std::move(fs));
        slot_map[full] = slot;
        return slot;
    }

    static bool is_lit(const std::unique_ptr<node>& n) {
        return n->kind == nkind::literal && n->set.empty();
    }

    bool is_multi(const std::unique_ptr<node>& n) {
        return n->kind == nkind::field && rs.fields[n->slot].multi;
    }

    // Literal int to real, for mixed comparisons
    static void lit_to_real(std::unique_ptr<node>& n) {
        if (n->type == vtype::integer) {
            n->lit.f = (double) n->lit.i;
            n->type = vtype::real;
        }
    }

    void to_bool(std::unique_ptr<node>& n) {
        if (n->type == vtype::boolean)
            return;

        if (n->type != vtype::integer)
            error(n.get(), std::string("expected a true/false value, not a ") + vtype_name(n->type));

        auto zero = std::make_unique<node>();
        zero->kind = nkind::literal;
        zero->type = vtype::integer;
        zero->line = n->line;
        zero->col = n->col;
        zero->lit = value{};
        zero->lit.valid = 1;
        zero->mask = 0;
        zero->slot = -1;
        zero->aux = -1;

        auto ne = std::make_unique<node>();
        ne->kind = nkind::binary;
        ne->o = op::ne;
        ne->type = vtype::boolean;
        ne->line = n->line;
        ne->col = n->col;
        ne->lit = value{};
        ne->mask = 0;
        ne->slot = -1;
        ne->aux = 0;
        ne->a = std::move(n);
        ne->b = std::move(zero);
        n = std::move(ne);
    }

    void fold(std::unique_ptr<node>& n) {
        auto& a = n->a;
        auto& b = n->b;

        if (n->type == vtype::integer) {
            int64_t r;
            bool ovf = false;
            switch (n->o) {
                case op::add: ovf = __builtin_add_overflow(a->lit.i, b->lit.i, &r); break;
                case op::sub: ovf = __builtin_sub_overflow(a->lit.i, b->lit.i, &r); break;
                case op::mul: ovf = __builtin_mul_overflow(a->lit.i, b->lit.i, &r); break;
                case op::div:
                case op::mod:
                    if (b->lit.i == 0)
                        error(n.get(), "division by zero");
                    if (a->lit.i == INT64_MIN && b->lit.i == -1)
                        error(n.get(), "integer overflow");
                    r = n->o == op::div ? a->lit.i / b->lit.i : a->lit.i % b->lit.i;
                    break;
                default:
                    return;
            }
            if (ovf)
                error(n.get(), "integer overflow");
            a->lit.i = r;
        } else {
            double x = a->type == vtype::integer ? (double) a->lit.i : a->lit.f;
            double y = b->type == vtype::integer ? (double) b->lit.i : b->lit.f;
            double r;
            switch (n->o) {
                case op::add: r = x + y; break;
                case op::sub: r = x - y; break;
                case op::mul: r = x * y; break;
                case op::div:
                    if (y == 0)
                        error(n.get(), "division by zero");
                    r = x / y;
                    break;
                default:
                    return;
            }
            if (!std::isfinite(r))
                error(n.get(), "number out of range");
            a->lit.f = r;
            a->type = vtype::real;
        }

        auto keep = std::move(n->a);
        n = std::move(keep);
    }

    void check(std::unique_ptr<node>& n, bool want_bool) {
        switch (n->kind) {
            case nkind::literal:
                if (!n->set.empty())
                    error(n.get(), "a set must follow 'in'");
                break;

            case nkind::now:
                *cur_now = true;
                n->type = vtype::integer;
                break;

            case nkind::field: {
                n->slot = resolve_field(n.get(), n->str);
                const auto& f = rs.fields[n->slot];
                if (f.type == vtype::none) {
                    if (f.leaf == ftype::map || f.leaf == ftype::container)
                        error(n.get(), "'" + n->str + "' is a group of fields; use exists() or count()");
                    error(n.get(), "'" + n->str + "' has a type rules can't use");
                }
                n->type = f.type;
                break;
            }

            case nkind::exists:
            case nkind::count: {
                n->slot = resolve_field(n.get(), n->str);
                const auto& f = rs.fields[n->slot];
                if (n->kind == nkind::count && !f.multi && f.leaf != ftype::container)
                    error(n.get(), "count() needs a field that holds several values");
                n->type = n->kind == nkind::exists ? vtype::boolean : vtype::integer;
                break;
            }

            case nkind::unary:
                if (n->o == op::lnot) {
                    check(n->a, true);
                    to_bool(n->a);
                    n->type = vtype::boolean;
                } else {
                    check(n->a, false);
                    if (is_multi(n->a))
                        error(n.get(), "fields with several values can only be compared to a value");
                    if (!is_numeric(n->a->type))
                        error(n.get(), "'-' needs a number");
                    n->type = n->a->type;
                }
                break;

            case nkind::binary:
                check_binary(n);
                break;
        }

        if (want_bool && n->type == vtype::integer)
            to_bool(n);
    }

    void check_binary(std::unique_ptr<node>& n) {
        auto o = n->o;

        if (o == op::land || o == op::lor) {
            check(n->a, true);
            check(n->b, true);
            to_bool(n->a);
            to_bool(n->b);
            n->type = vtype::boolean;
            return;
        }

        check(n->a, false);

        if (o == op::in) {
            check_in(n);
            return;
        }

        check(n->b, false);

        if (o == op::add || o == op::sub || o == op::mul || o == op::div || o == op::mod) {
            if (is_multi(n->a) || is_multi(n->b))
                error(n.get(), "fields with several values can only be compared to a value");
            if (!is_numeric(n->a->type) || !is_numeric(n->b->type))
                error(n.get(), std::string("'") + op_name(o) + "' needs numbers");
            if (o == op::mod && (n->a->type != vtype::integer || n->b->type != vtype::integer))
                error(n.get(), "'%' needs integers");

            n->type = (n->a->type == vtype::real || n->b->type == vtype::real) ?
                vtype::real : vtype::integer;

            if (is_lit(n->a) && is_lit(n->b))
                fold(n);
            return;
        }

        if (is_lit(n->a) && is_lit(n->b))
            error(n.get(), "comparing two values");

        // Comparisons and string predicates put the literal on the right
        if (is_lit(n->a)) {
            if (o != op::eq && o != op::ne && o != op::lt && o != op::le && o != op::gt && o != op::ge)
                error(n.get(), std::string("'") + op_name(o) + "' needs a field on the left");
            std::swap(n->a, n->b);
            n->o = o = mirror(o);
        }

        auto at = n->a->type;
        auto bt = n->b->type;

        if (is_multi(n->b))
            error(n.get(), "fields with several values can only be compared to a value");

        if (is_multi(n->a) && !is_lit(n->b))
            error(n.get(), "fields with several values can only be compared to a value");

        n->type = vtype::boolean;

        if (o == op::contains || o == op::icontains || o == op::startswith ||
                o == op::endswith || o == op::matches) {
            if (at != vtype::string)
                error(n.get(), std::string("'") + op_name(o) + "' needs a string on the left");
            if (bt != vtype::string || !is_lit(n->b))
                error(n.get(), std::string("'") + op_name(o) + "' needs a string value on the right");

            if (o == op::matches)
                n->aux = add_regex(n.get(), n->b->str);
            else
                n->aux = add_string(n->b->str);
            return;
        }

        // eq ne lt le gt ge
        if (is_numeric(at) && is_numeric(bt)) {
            if (at == vtype::real || bt == vtype::real) {
                if (is_lit(n->b))
                    lit_to_real(n->b);
                n->aux = 1;
            } else {
                n->aux = 0;
            }
            return;
        }

        // true/false compare as 1/0 against integer flags
        if ((at == vtype::boolean || at == vtype::integer) && (bt == vtype::boolean || bt == vtype::integer)) {
            if (o != op::eq && o != op::ne)
                error(n.get(), "true/false values can only be tested with == or !=");
            n->aux = 0;
            return;
        }

        if (at == vtype::string && bt == vtype::string) {
            if (o != op::eq && o != op::ne)
                error(n.get(), "strings can't be ordered; use ==, !=, contains, startswith, endswith or matches");
            if (!is_lit(n->b))
                error(n.get(), "strings can only be compared to a string value");
            n->aux = add_string(n->b->str);
            return;
        }

        if (at == vtype::mac && bt == vtype::mac) {
            if (o != op::eq && o != op::ne)
                error(n.get(), "macs can only be tested with == or !=");
            if (!is_lit(n->b))
                error(n.get(), "macs can only be compared to a mac value");
            n->aux = add_mac(n->b->lit.m, n->b->mask);
            return;
        }

        error(n.get(), std::string("can't compare ") + vtype_name(at) + " to " + vtype_name(bt));
    }

    void check_in(std::unique_ptr<node>& n) {
        auto at = n->a->type;
        auto& sn = n->b;

        if (sn->kind != nkind::literal || sn->set.empty())
            error(n.get(), "'in' needs a [list] of values");

        if (is_lit(n->a))
            error(n.get(), "testing a value against a set");

        if (at != vtype::integer && at != vtype::real && at != vtype::string && at != vtype::mac)
            error(n.get(), std::string("can't test a ") + vtype_name(at) + " against a set");

        if (rs.sets.size() >= 65535)
            error(n.get(), "too many sets");

        bool any_real = false;
        for (auto& e : sn->set) {
            auto et = e->type;
            bool ok = is_numeric(at) ? is_numeric(et) : et == at;
            if (!ok)
                error(e.get(), std::string("a ") + vtype_name(et) + " in a set tested against a " +
                        vtype_name(at));
            if (et == vtype::real)
                any_real = true;
        }

        value_set vs;
        vs.type = (at == vtype::integer && any_real) ? vtype::real : at;

        for (auto& e : sn->set) {
            switch (vs.type) {
                case vtype::integer:
                    vs.ints.insert(e->lit.i);
                    break;
                case vtype::real:
                    vs.reals.push_back(e->type == vtype::integer ? (double) e->lit.i : e->lit.f);
                    break;
                case vtype::string:
                    vs.strings.insert(e->str);
                    break;
                default:
                    if (e->mask == ~(uint64_t) 0)
                        vs.macs.insert(e->lit.m);
                    else
                        vs.masked.push_back(std::make_pair(e->lit.m & e->mask, e->mask));
                    break;
            }
        }

        // An integer field tested against a real set
        n->slot = (vs.type == vtype::real && at == vtype::integer) ? 1 : 0;
        n->aux = rs.sets.size();
        rs.sets.push_back(std::move(vs));
        n->type = vtype::boolean;
    }

    int add_string(const std::string& s) {
        for (size_t i = 0; i < rs.const_strings.size(); i++)
            if (rs.const_strings[i] == s)
                return i;
        rs.const_strings.push_back(s);
        return rs.const_strings.size() - 1;
    }

    int add_mac(uint64_t m, uint64_t mask) {
        rs.const_macs.push_back(std::make_pair(m & mask, mask));
        return rs.const_macs.size() - 1;
    }

    int add_const(const value& v) {
        rs.consts.push_back(v);
        return rs.consts.size() - 1;
    }

    int add_regex(const node *n, const std::string& pattern) {
#ifdef HAVE_LIBPCRE2
        int errnum;
        PCRE2_SIZE erroff;

        auto re = pcre2_compile((PCRE2_SPTR8) pattern.data(), pattern.size(), 0,
                &errnum, &erroff, nullptr);

        if (re == nullptr) {
            PCRE2_UCHAR buf[256];
            pcre2_get_error_message(errnum, buf, sizeof(buf));
            error(n, std::string("bad regex at ") + std::to_string(erroff) + ": " + (char *) buf);
        }

        // Interpreted matching still works if the regex jit isn't available
        pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);

        regex_ent e;
        e.pattern = pattern;
        e.re = re;
        rs.regexes.push_back(e);
        return rs.regexes.size() - 1;
#else
        (void) pattern;
        error(n, "'matches' needs Kismet built with pcre2");
#endif
    }

    uint16_t reg(const node *n, size_t r) {
        if (r >= max_regs)
            error(n, "expression is too complex");
        if (r + 1 > nregs)
            nregs = r + 1;
        return r;
    }

    size_t emit(bc o, uint16_t a, uint32_t b, uint32_t c) {
        insn i{};
        i.o = o;
        i.a = a;
        i.b = b;
        i.c = c;
        rs.code.push_back(i);
        return rs.code.size() - 1;
    }

    void gen_lit(const node *n, uint16_t r) {
        switch (n->type) {
            case vtype::boolean:
            case vtype::integer:
                emit(bc::ki, r, add_const(n->lit), 0);
                break;
            case vtype::real:
                emit(bc::kf, r, add_const(n->lit), 0);
                break;
            default:
                error(n, "unexpected value");
        }
    }

    // Leaf test against a literal, as a multi-path predicate
    void gen_mpred(const node *n, uint16_t r, bc o, uint32_t k, bool i2f) {
        mpred_ent m;
        m.slot = n->a->slot;
        m.o = o;
        m.i2f = i2f;
        m.k = k;
        rs.mpreds.push_back(m);
        emit(bc::mpred, r, rs.mpreds.size() - 1, 0);
    }

    void gen(const node *n, size_t ri) {
        auto r = reg(n, ri);

        switch (n->kind) {
            case nkind::literal:
                gen_lit(n, r);
                return;

            case nkind::now:
                emit(bc::now, r, 0, 0);
                return;

            case nkind::field: {
                const auto& f = rs.fields[n->slot];
                switch (f.type) {
                    case vtype::integer: emit(bc::ldi, r, n->slot, 0); break;
                    case vtype::real: emit(bc::ldf, r, n->slot, 0); break;
                    case vtype::string: emit(bc::lds, r, n->slot, 0); break;
                    case vtype::mac: emit(bc::ldm, r, n->slot, 0); break;
                    default: error(n, "unexpected field");
                }
                return;
            }

            case nkind::exists:
                emit(bc::exists, r, n->slot, 0);
                return;

            case nkind::count:
                emit(bc::count, r, n->slot, 0);
                return;

            case nkind::unary:
                gen(n->a.get(), r);
                if (n->o == op::lnot)
                    emit(bc::lnot, r, r, 0);
                else
                    emit(n->type == vtype::real ? bc::negf : bc::negi, r, r, 0);
                return;

            case nkind::binary:
                break;
        }

        auto o = n->o;

        if (o == op::land || o == op::lor) {
            gen(n->a.get(), r);
            auto j = emit(o == op::land ? bc::jf : bc::jt, r, 0, 0);
            gen(n->b.get(), r);
            rs.code[j].b = rs.code.size();
            return;
        }

        bool multi = n->a->kind == nkind::field && rs.fields[n->a->slot].multi;

        if (o == op::in) {
            const auto& vs = rs.sets[n->aux];
            bc t;
            switch (vs.type) {
                case vtype::integer: t = bc::ini; break;
                case vtype::real: t = bc::inf; break;
                case vtype::string: t = bc::ins; break;
                default: t = bc::inm; break;
            }

            bool i2f = n->slot == 1;

            if (multi) {
                gen_mpred(n, r, t, n->aux, i2f);
                return;
            }

            gen(n->a.get(), r);
            if (i2f)
                emit(bc::i2f, r, r, 0);
            emit(t, r, r, n->aux);
            return;
        }

        if (o == op::add || o == op::sub || o == op::mul || o == op::div || o == op::mod) {
            auto r2 = reg(n, ri + 1);
            bool real = n->type == vtype::real;

            gen(n->a.get(), r);
            if (real && n->a->type == vtype::integer)
                emit(bc::i2f, r, r, 0);
            gen(n->b.get(), r2);
            if (real && n->b->type == vtype::integer)
                emit(bc::i2f, r2, r2, 0);

            bc t;
            switch (o) {
                case op::add: t = real ? bc::addf : bc::addi; break;
                case op::sub: t = real ? bc::subf : bc::subi; break;
                case op::mul: t = real ? bc::mulf : bc::muli; break;
                case op::div: t = real ? bc::divf : bc::divi; break;
                default: t = bc::modi; break;
            }

            emit(t, r, r, r2);
            return;
        }

        auto at = n->a->type;

        if (at == vtype::string) {
            bc t = str_op(o);
            if (multi) {
                gen_mpred(n, r, t, n->aux, false);
                return;
            }
            gen(n->a.get(), r);
            emit(t, r, r, n->aux);
            return;
        }

        if (at == vtype::mac) {
            bc t = o == op::eq ? bc::meq : bc::mne;
            if (multi) {
                gen_mpred(n, r, t, n->aux, false);
                return;
            }
            gen(n->a.get(), r);
            emit(t, r, r, n->aux);
            return;
        }

        // Numeric and boolean comparisons
        bool real = n->aux == 1;
        bc t = real ? real_cmp(o) : int_cmp(o);

        if (multi) {
            gen_mpred(n, r, t, add_const(n->b->lit), real && n->a->type == vtype::integer);
            return;
        }

        auto r2 = reg(n, ri + 1);
        gen(n->a.get(), r);
        if (real && n->a->type == vtype::integer)
            emit(bc::i2f, r, r, 0);
        gen(n->b.get(), r2);
        if (real && n->b->type == vtype::integer)
            emit(bc::i2f, r2, r2, 0);
        emit(t, r, r, r2);
    }
};

ruleset::ruleset() :
    nregs_max{1},
    any_now{false},
    compiled_ok{false},
#ifdef HAVE_LIBPCRE2
    mctx{nullptr},
#endif
    jit_all{nullptr},
    jit_first{nullptr},
    jit_code{nullptr},
    jit_first_code{nullptr} { }

void ruleset::compile(resolver& r) {
    if (compiled_ok)
        throw std::runtime_error("ruleset already compiled");

#ifdef HAVE_LIBPCRE2
    mctx = pcre2_match_context_create(nullptr);
    if (mctx == nullptr)
        throw std::runtime_error("could not allocate regex context");
    pcre2_set_match_limit(mctx, regex_match_limit);
    pcre2_set_depth_limit(mctx, regex_match_limit);
#endif

    compiler c(*this, r);
    c.compile_all();
    compiled_ok = true;
}

eval_ctx::eval_ctx() :
    rs{nullptr},
    e{nullptr},
    now{0},
    rp{nullptr},
    cp{nullptr},
    gen{1} {
#ifdef HAVE_LIBPCRE2
    md = nullptr;
#endif
}

eval_ctx::~eval_ctx() {
#ifdef HAVE_LIBPCRE2
    if (md != nullptr)
        pcre2_match_data_free(md);
#endif
}

void eval_ctx::bind(const ruleset *in_rs, env *in_e) {
    rs = in_rs;
    e = in_e;
    regs.assign(rs->nregs_max, value{});
    cache.assign(rs->fields.size() + 1, cache_ent{});
    rp = regs.data();
    cp = cache.data();
    gen = 1;

#ifdef HAVE_LIBPCRE2
    if (md == nullptr && !rs->regexes.empty()) {
        md = pcre2_match_data_create(1, nullptr);
        if (md == nullptr)
            throw std::runtime_error("could not allocate regex match data");
    }
#endif
}

bool str_icontains(const char *h, size_t hl, const char *n, size_t nl) {
    if (nl == 0)
        return true;
    if (nl > hl)
        return false;

    auto lc = [](char c) -> char {
        return (c >= 'A' && c <= 'Z') ? c + 32 : c;
    };

    for (size_t i = 0; i + nl <= hl; i++) {
        size_t j = 0;
        while (j < nl && lc(h[i + j]) == lc(n[j]))
            j++;
        if (j == nl)
            return true;
    }

    return false;
}

bool ruleset::load_cached(eval_ctx& ctx, uint32_t slot, value& out) const {
    auto& c = ctx.cache[slot];

    if (c.gen != ctx.gen) {
        c.gen = ctx.gen;
        c.ok = ctx.e->load(fields[slot], c.v);
        if (!c.ok)
            c.v.valid = 0;
        else
            c.v.valid = 1;
    }

    out = c.v;
    return c.ok;
}

bool ruleset::leaf_test(eval_ctx& ctx, bc o, const value& v, uint32_t k) const {
    if (!v.valid)
        return false;

    switch (o) {
        case bc::eqi: return v.i == consts[k].i;
        case bc::nei: return v.i != consts[k].i;
        case bc::lti: return v.i < consts[k].i;
        case bc::lei: return v.i <= consts[k].i;
        case bc::gti: return v.i > consts[k].i;
        case bc::gei: return v.i >= consts[k].i;
        case bc::eqf: return v.f == consts[k].f;
        case bc::nef: return v.f != consts[k].f;
        case bc::ltf: return v.f < consts[k].f;
        case bc::lef: return v.f <= consts[k].f;
        case bc::gtf: return v.f > consts[k].f;
        case bc::gef: return v.f >= consts[k].f;

        case bc::seq:
        case bc::sne: {
            const auto& s = const_strings[k];
            bool eq = v.len == s.size() && memcmp(v.s, s.data(), s.size()) == 0;
            return o == bc::seq ? eq : !eq;
        }
        case bc::scont: {
            const auto& s = const_strings[k];
            return std::string_view(v.s, v.len).find(s) != std::string_view::npos;
        }
        case bc::sicont: {
            const auto& s = const_strings[k];
            return str_icontains(v.s, v.len, s.data(), s.size());
        }
        case bc::spre: {
            const auto& s = const_strings[k];
            return v.len >= s.size() && memcmp(v.s, s.data(), s.size()) == 0;
        }
        case bc::ssuf: {
            const auto& s = const_strings[k];
            return v.len >= s.size() && memcmp(v.s + v.len - s.size(), s.data(), s.size()) == 0;
        }
        case bc::sre:
#ifdef HAVE_LIBPCRE2
            return pcre2_match(regexes[k].re, (PCRE2_SPTR8) v.s, v.len, 0, 0, ctx.md, mctx) >= 0;
#else
            return false;
#endif

        case bc::ini:
            return sets[k].ints.find(v.i) != sets[k].ints.end();
        case bc::inf:
            for (auto f : sets[k].reals)
                if (f == v.f)
                    return true;
            return false;
        case bc::ins:
            return sets[k].strings.find(std::string(v.s, v.len)) != sets[k].strings.end();
        case bc::inm: {
            const auto& vs = sets[k];
            if (vs.macs.find(v.m) != vs.macs.end())
                return true;
            for (const auto& mm : vs.masked)
                if ((v.m & mm.second) == mm.first)
                    return true;
            return false;
        }

        case bc::meq:
            return (v.m & const_macs[k].second) == const_macs[k].first;
        case bc::mne:
            return (v.m & const_macs[k].second) != const_macs[k].first;

        default:
            return false;
    }
}

namespace {
    struct mpred_arg {
        const ruleset *rs;
        eval_ctx *ctx;
        const mpred_ent *m;
    };

    bool mpred_cb(const value& v, const void *a) {
        auto arg = static_cast<const mpred_arg *>(a);

        if (arg->m->i2f) {
            value fv = v;
            fv.f = (double) v.i;
            return arg->rs->leaf_test(*arg->ctx, arg->m->o, fv, arg->m->k);
        }

        return arg->rs->leaf_test(*arg->ctx, arg->m->o, v, arg->m->k);
    }
}

bool ruleset::run_mpred(eval_ctx& ctx, uint32_t idx) const {
    mpred_arg arg{this, &ctx, &mpreds[idx]};
    return ctx.e->any(fields[mpreds[idx].slot], mpred_cb, &arg);
}

int64_t ruleset::run_count(eval_ctx& ctx, uint32_t slot) const {
    return ctx.e->count(fields[slot]);
}

bool ruleset::run_exists(eval_ctx& ctx, uint32_t slot) const {
    const auto& f = fields[slot];

    if (f.multi || f.type == vtype::none)
        return ctx.e->exists(f);

    value v;
    return load_cached(ctx, slot, v);
}

const char *bc_name(bc b) {
    static const char *names[] = {
        "ldi", "ldf", "lds", "ldm",
        "ki", "kf", "ks", "km",
        "now",
        "i2f",
        "addi", "subi", "muli", "divi", "modi", "negi",
        "addf", "subf", "mulf", "divf", "negf",
        "eqi", "nei", "lti", "lei", "gti", "gei",
        "eqf", "nef", "ltf", "lef", "gtf", "gef",
        "seq", "sne", "scont", "sicont", "spre", "ssuf", "sre",
        "ini", "inf", "ins", "inm",
        "meq", "mne",
        "mpred",
        "exists", "count",
        "lnot",
        "jf", "jt", "jmp",
        "ret",
    };

    static_assert(sizeof(names) / sizeof(names[0]) == (size_t) bc::ret + 1, "bc names");

    return names[(size_t) b];
}

std::string ruleset::disassemble(size_t r) const {
    std::stringstream ss;
    const auto& cr = compiled[r];

    for (size_t i = 0; i < cr.len; i++) {
        const auto& in = code[cr.entry + i];
        ss << i << "\t" << bc_name(in.o) << "\tr" << in.a << ", " << in.b << ", " << in.c;

        switch (in.o) {
            case bc::ldi:
            case bc::ldf:
            case bc::lds:
            case bc::ldm:
            case bc::exists:
            case bc::count:
                ss << "\t; " << fields[in.b].text;
                break;
            case bc::jf:
            case bc::jt:
            case bc::jmp:
                ss << "\t; -> " << (in.b - cr.entry);
                break;
            default:
                break;
        }

        ss << "\n";
    }

    return ss.str();
}

}
