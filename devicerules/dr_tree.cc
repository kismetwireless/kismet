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

#include <cstring>

#include "dr_core.h"

// Reference evaluator over the checked tree.  It's slow and deliberately written
// apart from the bytecode helpers, so the VM and JIT can be tested against it.

namespace devicerules {

namespace {

struct tree_eval {
    const ruleset& rs;
    eval_ctx& ctx;

    static value invalid() {
        value v{};
        v.valid = 0;
        return v;
    }

    static value boolean(bool b) {
        value v{};
        v.i = b;
        v.valid = 1;
        return v;
    }

    static double as_real(const value& v, vtype t) {
        return t == vtype::integer || t == vtype::boolean ? (double) v.i : v.f;
    }

    bool str_test(op o, const std::string_view& s, const node *n) {
        const std::string& lit = n->b->str;

        switch (o) {
            case op::eq: return s == lit;
            case op::ne: return s != lit;
            case op::contains: return s.find(lit) != std::string_view::npos;
            case op::icontains: {
                std::string a(s), b(lit);
                for (auto& c : a)
                    c = tolower((unsigned char) c);
                for (auto& c : b)
                    c = tolower((unsigned char) c);
                return a.find(b) != std::string::npos;
            }
            case op::startswith: return s.substr(0, lit.size()) == lit;
            case op::endswith:
                return s.size() >= lit.size() && s.substr(s.size() - lit.size()) == lit;
            case op::matches:
#ifdef HAVE_LIBPCRE2
                return pcre2_match(rs.regexes[n->aux].re, (PCRE2_SPTR8) s.data(), s.size(),
                        0, 0, ctx.md, rs.mctx) >= 0;
#else
                return false;
#endif
            default:
                return false;
        }
    }

    bool num_test(op o, double x, double y) {
        switch (o) {
            case op::eq: return x == y;
            case op::ne: return x != y;
            case op::lt: return x < y;
            case op::le: return x <= y;
            case op::gt: return x > y;
            case op::ge: return x >= y;
            default: return false;
        }
    }

    bool int_test(op o, int64_t x, int64_t y) {
        switch (o) {
            case op::eq: return x == y;
            case op::ne: return x != y;
            case op::lt: return x < y;
            case op::le: return x <= y;
            case op::gt: return x > y;
            case op::ge: return x >= y;
            default: return false;
        }
    }

    bool set_test(const node *n, const value& v, vtype t) {
        // An integer tested against a set holding any real compares as reals
        bool reals = t == vtype::real;
        for (const auto& e : n->b->set)
            if (e->type == vtype::real)
                reals = true;

        for (const auto& e : n->b->set) {
            switch (t) {
                case vtype::integer:
                case vtype::real:
                    if (reals) {
                        if (as_real(v, t) == as_real(e->lit, e->type))
                            return true;
                    } else if (v.i == e->lit.i) {
                        return true;
                    }
                    break;
                case vtype::string:
                    if (std::string_view(v.s, v.len) == e->str)
                        return true;
                    break;
                case vtype::mac:
                    if ((v.m & e->mask) == (e->lit.m & e->mask))
                        return true;
                    break;
                default:
                    break;
            }
        }
        return false;
    }

    // Test one leaf value against the literal side of a comparison node
    bool leaf(const node *n, const value& v, vtype t) {
        if (!v.valid)
            return false;

        if (n->o == op::in)
            return set_test(n, v, t);

        if (t == vtype::string)
            return str_test(n->o, std::string_view(v.s, v.len), n);

        if (t == vtype::mac) {
            bool eq = (v.m & n->b->mask) == (n->b->lit.m & n->b->mask);
            return n->o == op::eq ? eq : !eq;
        }

        if (n->aux == 1)
            return num_test(n->o, as_real(v, t), as_real(n->b->lit, n->b->type));

        return int_test(n->o, v.i, n->b->lit.i);
    }

    value field(const node *n) {
        value v{};
        if (!ctx.e->load(rs.fields[n->slot], v))
            return invalid();
        v.valid = 1;
        return v;
    }

    value eval(const node *n) {
        switch (n->kind) {
            case nkind::literal: {
                value v = n->lit;
                v.valid = 1;
                return v;
            }

            case nkind::now: {
                value v{};
                v.i = ctx.now;
                v.valid = 1;
                return v;
            }

            case nkind::field:
                return field(n);

            case nkind::exists: {
                const auto& f = rs.fields[n->slot];
                if (f.multi || f.type == vtype::none)
                    return boolean(ctx.e->exists(f));
                value v{};
                return boolean(ctx.e->load(f, v));
            }

            case nkind::count: {
                value v{};
                v.i = ctx.e->count(rs.fields[n->slot]);
                v.valid = 1;
                return v;
            }

            case nkind::unary: {
                auto a = eval(n->a.get());
                if (n->o == op::lnot)
                    return boolean(!a.i);
                if (!a.valid)
                    return invalid();
                if (n->type == vtype::real) {
                    a.f = -a.f;
                    return a;
                }
                if (a.i == INT64_MIN)
                    return invalid();
                a.i = -a.i;
                return a;
            }

            case nkind::binary:
                return binary(n);
        }

        return invalid();
    }

    value binary(const node *n) {
        switch (n->o) {
            case op::land: {
                if (!eval(n->a.get()).i)
                    return boolean(false);
                return boolean(eval(n->b.get()).i);
            }
            case op::lor: {
                if (eval(n->a.get()).i)
                    return boolean(true);
                return boolean(eval(n->b.get()).i);
            }
            default:
                break;
        }

        const auto o = n->o;

        if (o == op::add || o == op::sub || o == op::mul || o == op::div || o == op::mod) {
            auto a = eval(n->a.get());
            auto b = eval(n->b.get());

            if (!a.valid || !b.valid)
                return invalid();

            value r{};
            r.valid = 1;

            if (n->type == vtype::real) {
                double x = as_real(a, n->a->type), y = as_real(b, n->b->type);
                switch (o) {
                    case op::add: r.f = x + y; break;
                    case op::sub: r.f = x - y; break;
                    case op::mul: r.f = x * y; break;
                    default:
                        if (y == 0)
                            return invalid();
                        r.f = x / y;
                        break;
                }
                return r;
            }

            bool bad = false;
            switch (o) {
                case op::add: bad = __builtin_add_overflow(a.i, b.i, &r.i); break;
                case op::sub: bad = __builtin_sub_overflow(a.i, b.i, &r.i); break;
                case op::mul: bad = __builtin_mul_overflow(a.i, b.i, &r.i); break;
                default:
                    if (b.i == 0 || (a.i == INT64_MIN && b.i == -1))
                        return invalid();
                    r.i = o == op::div ? a.i / b.i : a.i % b.i;
                    break;
            }
            if (bad)
                return invalid();
            return r;
        }

        // Several values: any of them passing passes
        if (n->a->kind == nkind::field && rs.fields[n->a->slot].multi) {
            struct arg_t {
                tree_eval *te;
                const node *n;
                vtype t;
            } arg{this, n, n->a->type};

            return boolean(ctx.e->any(rs.fields[n->a->slot],
                    [](const value& v, const void *p) -> bool {
                        auto a = static_cast<const arg_t *>(p);
                        value lv = v;
                        lv.valid = 1;
                        return a->te->leaf(a->n, lv, a->t);
                    }, &arg));
        }

        auto a = eval(n->a.get());

        if (o == op::in || n->b->kind == nkind::literal)
            return boolean(leaf(n, a, n->a->type));

        auto b = eval(n->b.get());
        if (!a.valid || !b.valid)
            return boolean(false);

        if (n->aux == 1)
            return boolean(num_test(o, as_real(a, n->a->type), as_real(b, n->b->type)));

        return boolean(int_test(o, a.i, b.i));
    }
};

}

bool ruleset::eval_tree(eval_ctx& ctx, size_t r) const {
    tree_eval te{*this, ctx};
    return te.eval(rules[r]->expr.get()).i != 0;
}

}
