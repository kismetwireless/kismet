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

#include <cerrno>
#include <cmath>
#include <cstring>

#include "dr_core.h"

namespace devicerules {

namespace {

enum class tok : uint8_t {
    end,
    ident,
    integer,
    real,
    string,
    mac,
    lparen, rparen, lbrace, rbrace, lbrack, rbrack, comma,
    plus, minus, star, slash, percent,
    eq, ne, lt, le, gt, ge,
};

struct token {
    tok t;
    std::string text;
    int64_t i;
    double f;
    uint64_t mac, mask;
    size_t line, col;
    // Offset of the token in the source, for recovering rule text
    size_t off;
};

constexpr size_t max_ident_len = 1024;
constexpr size_t max_string_len = 4096;
constexpr int max_depth = 64;

bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int hexval(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

bool is_ident_start(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool is_ident_char(char c) {
    return is_ident_start(c) || (c >= '0' && c <= '9') || c == '.';
}

class lexer {
public:
    lexer(const std::string& in) :
        src{in}, pos{0}, line{1}, col{1} { }

    token next() {
        skip_space();

        token t{};
        t.line = line;
        t.col = col;
        t.off = pos;

        if (pos >= src.size()) {
            t.t = tok::end;
            return t;
        }

        char c = src[pos];

        if (c == '"')
            return lex_string(t);

        if (is_hex(c)) {
            size_t groups = mac_groups();
            if (groups >= 2)
                return lex_mac(t, groups);
        }

        if (c >= '0' && c <= '9')
            return lex_number(t);

        if (is_ident_start(c))
            return lex_ident(t);

        advance();

        switch (c) {
            case '(': t.t = tok::lparen; return t;
            case ')': t.t = tok::rparen; return t;
            case '{': t.t = tok::lbrace; return t;
            case '}': t.t = tok::rbrace; return t;
            case '[': t.t = tok::lbrack; return t;
            case ']': t.t = tok::rbrack; return t;
            case ',': t.t = tok::comma; return t;
            case '+': t.t = tok::plus; return t;
            case '-': t.t = tok::minus; return t;
            case '*': t.t = tok::star; return t;
            case '/': t.t = tok::slash; return t;
            case '%': t.t = tok::percent; return t;
            case '=':
                if (peek() == '=') {
                    advance();
                    t.t = tok::eq;
                    return t;
                }
                break;
            case '!':
                if (peek() == '=') {
                    advance();
                    t.t = tok::ne;
                    return t;
                }
                break;
            case '<':
                if (peek() == '=') {
                    advance();
                    t.t = tok::le;
                    return t;
                }
                t.t = tok::lt;
                return t;
            case '>':
                if (peek() == '=') {
                    advance();
                    t.t = tok::ge;
                    return t;
                }
                t.t = tok::gt;
                return t;
        }

        throw parse_error(std::string("unexpected character '") + c + "'", t.line, t.col);
    }

    size_t offset() const { return pos; }

private:
    const std::string& src;
    size_t pos, line, col;

    char peek(size_t n = 0) const {
        if (pos + n >= src.size())
            return 0;
        return src[pos + n];
    }

    void advance() {
        if (src[pos] == '\n') {
            line++;
            col = 1;
        } else {
            col++;
        }
        pos++;
    }

    void skip_space() {
        while (pos < src.size()) {
            char c = src[pos];

            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                advance();
                continue;
            }

            if (c == '#') {
                while (pos < src.size() && src[pos] != '\n')
                    advance();
                continue;
            }

            break;
        }
    }

    // Count colon-separated hex byte groups at the cursor; 0 when it's not a mac
    size_t mac_groups() const {
        size_t p = pos;
        size_t groups = 0;

        while (p + 1 < src.size() && is_hex(src[p]) && is_hex(src[p + 1])) {
            groups++;
            p += 2;

            if (p < src.size() && src[p] == ':') {
                p++;
                continue;
            }

            break;
        }

        if (p < src.size() && is_ident_char(src[p]))
            return 0;

        return groups;
    }

    token& lex_mac(token& t, size_t groups) {
        if (groups > 8)
            throw parse_error("mac address has too many bytes", t.line, t.col);

        uint64_t m = 0;
        for (size_t g = 0; g < groups; g++) {
            int hi = hexval(src[pos]);
            advance();
            int lo = hexval(src[pos]);
            advance();
            m |= (uint64_t) ((hi << 4) | lo) << ((7 - g) * 8);
            if (g + 1 < groups)
                advance();
        }

        // A short mac is a prefix
        uint64_t mask = groups >= 8 ? ~(uint64_t) 0 :
            ~((~(uint64_t) 0) >> (groups * 8));

        if (groups == 6)
            mask = ~(uint64_t) 0;

        if (peek() == '/') {
            advance();

            if (peek() >= '0' && peek() <= '9' && mac_groups() < 2) {
                int bits = 0;
                while (peek() >= '0' && peek() <= '9') {
                    bits = bits * 10 + (peek() - '0');
                    advance();
                    if (bits > 64)
                        throw parse_error("mac mask is wider than 64 bits", t.line, t.col);
                }

                if (bits == 0)
                    throw parse_error("mac mask of 0 bits matches everything", t.line, t.col);

                mask = bits == 64 ? ~(uint64_t) 0 : ~((~(uint64_t) 0) >> bits);
            } else {
                size_t mg = mac_groups();
                if (mg < 2 || mg > 8)
                    throw parse_error("expected a mask after '/'", line, col);

                mask = 0;
                for (size_t g = 0; g < mg; g++) {
                    int hi = hexval(src[pos]);
                    advance();
                    int lo = hexval(src[pos]);
                    advance();
                    mask |= (uint64_t) ((hi << 4) | lo) << ((7 - g) * 8);
                    if (g + 1 < mg)
                        advance();
                }

                if (mask == 0)
                    throw parse_error("mac mask of 0 bits matches everything", t.line, t.col);
            }
        }

        t.t = tok::mac;
        t.mac = m & mask;
        t.mask = mask;
        return t;
    }

    token& lex_string(token& t) {
        advance();

        while (true) {
            if (pos >= src.size())
                throw parse_error("unterminated string", t.line, t.col);

            char c = src[pos];

            if (c == '"') {
                advance();
                break;
            }

            if (c == '\n')
                throw parse_error("newline in string", t.line, t.col);

            if (c == '\\') {
                advance();
                if (pos >= src.size())
                    throw parse_error("unterminated string", t.line, t.col);

                c = src[pos];
                switch (c) {
                    case 'n': c = '\n'; break;
                    case 't': c = '\t'; break;
                    case '\\': break;
                    case '"': break;
                    default:
                        // Pass other escapes through so regexes keep theirs
                        t.text += '\\';
                        break;
                }
            }

            t.text += c;
            advance();

            if (t.text.size() > max_string_len)
                throw parse_error("string is too long", t.line, t.col);
        }

        t.t = tok::string;
        return t;
    }

    token& lex_number(token& t) {
        size_t start = pos;

        if (peek() == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
            advance();
            advance();

            if (!is_hex(peek()))
                throw parse_error("expected hex digits", t.line, t.col);

            uint64_t v = 0;
            int digits = 0;
            while (is_hex(peek())) {
                v = (v << 4) | hexval(peek());
                advance();
                if (++digits > 16)
                    throw parse_error("hex number is too large", t.line, t.col);
            }

            if (is_ident_char(peek()))
                throw parse_error("bad hex number", t.line, t.col);

            t.t = tok::integer;
            t.i = (int64_t) v;
            return t;
        }

        bool is_real = false;

        while (peek() >= '0' && peek() <= '9')
            advance();

        if (peek() == '.' && peek(1) >= '0' && peek(1) <= '9') {
            is_real = true;
            advance();
            while (peek() >= '0' && peek() <= '9')
                advance();
        }

        if ((peek() == 'e' || peek() == 'E') &&
                ((peek(1) >= '0' && peek(1) <= '9') ||
                 ((peek(1) == '-' || peek(1) == '+') && peek(2) >= '0' && peek(2) <= '9'))) {
            is_real = true;
            advance();
            if (peek() == '-' || peek() == '+')
                advance();
            while (peek() >= '0' && peek() <= '9')
                advance();
        }

        std::string num = src.substr(start, pos - start);

        // Durations become seconds
        int64_t mult = 0;
        if (!is_real) {
            char u = peek();
            if (!is_ident_char(peek(1))) {
                if (u == 's')
                    mult = 1;
                else if (u == 'm')
                    mult = 60;
                else if (u == 'h')
                    mult = 3600;
                else if (u == 'd')
                    mult = 86400;
            }
            if (mult != 0)
                advance();
        }

        if (is_ident_char(peek()))
            throw parse_error("bad number '" + num + "'", t.line, t.col);

        if (is_real) {
            errno = 0;
            t.f = strtod(num.c_str(), nullptr);
            if (errno != 0 || !std::isfinite(t.f))
                throw parse_error("number out of range", t.line, t.col);
            t.t = tok::real;
            return t;
        }

        errno = 0;
        auto v = strtoll(num.c_str(), nullptr, 10);
        if (errno != 0)
            throw parse_error("number out of range", t.line, t.col);

        if (mult != 0) {
            if (v > INT64_MAX / mult)
                throw parse_error("duration out of range", t.line, t.col);
            v *= mult;
        }

        t.t = tok::integer;
        t.i = v;
        return t;
    }

    // Identifiers and field paths; a '/' with no space around it joins path elements
    token& lex_ident(token& t) {
        while (true) {
            while (is_ident_char(peek()))
                advance();

            if (peek() == '/' && is_ident_start(peek(1))) {
                advance();
                continue;
            }

            break;
        }

        t.text = src.substr(t.off, pos - t.off);

        if (t.text.size() > max_ident_len)
            throw parse_error("name is too long", t.line, t.col);

        if (t.text.back() == '.')
            throw parse_error("name ends in '.'", t.line, t.col);

        t.t = tok::ident;
        return t;
    }
};

class parser {
public:
    parser(const std::string& in) :
        src{in}, lex{in}, depth{0} {
        cur = lex.next();
    }

    bool at_end() const {
        return cur.t == tok::end;
    }

    bool at_sort() const {
        return is_word("sort");
    }

    std::unique_ptr<rule_def> parse_rule() {
        if (cur.t == tok::end)
            return nullptr;

        size_t start = cur.off;

        if (!is_word("rule"))
            error("expected 'rule' or 'sort'");
        expect_word("rule");

        if (cur.t != tok::ident && cur.t != tok::integer)
            error("expected a rule name");

        auto r = std::make_unique<rule_def>();
        r->view = false;
        r->alert = false;
        r->live = false;
        r->uses_now = false;

        r->name = rule_name("rule");

        expect(tok::lbrace, "'{'");

        while (cur.t != tok::rbrace) {
            if (cur.t == tok::end)
                error("rule '" + r->name + "' is missing '}'");

            if (cur.t != tok::ident)
                error("expected when, tag, color, view, alert or live");

            auto w = cur.text;

            if (w == "when") {
                if (r->expr != nullptr)
                    error("rule has more than one 'when'");
                advance();
                r->expr = parse_expr();
            } else if (w == "tag") {
                advance();
                if (cur.t != tok::string || cur.text.empty())
                    error("expected a tag string");
                if (r->tags.size() >= 16)
                    error("too many tags on one rule");
                r->tags.push_back(cur.text);
                advance();
            } else if (w == "color") {
                advance();
                if (cur.t != tok::string || !valid_color(cur.text))
                    error("expected a color string like \"#ff0000\"");
                r->color = cur.text;
                advance();
            } else if (w == "view") {
                advance();
                r->view = true;
                if (cur.t == tok::string) {
                    r->view_desc = cur.text;
                    advance();
                }
            } else if (w == "alert") {
                advance();
                r->alert = true;
            } else if (w == "live") {
                advance();
                r->live = true;
            } else {
                error("unknown rule statement '" + w + "'");
            }
        }

        size_t end = lex.offset();
        advance();

        if (r->expr == nullptr)
            throw parse_error("rule '" + r->name + "' has no 'when'", line0, col0);

        r->source = src.substr(start, end - start);

        return r;
    }

    std::unique_ptr<sort_def> parse_sort() {
        size_t start = cur.off;

        expect_word("sort");

        if (cur.t != tok::ident && cur.t != tok::integer)
            error("expected a sort name");

        auto s = std::make_unique<sort_def>();
        s->uses_now = false;
        s->line = line0;
        s->col = col0;
        s->name = rule_name("sort");

        expect(tok::lbrace, "'{'");

        while (cur.t != tok::rbrace) {
            if (cur.t == tok::end)
                error("sort '" + s->name + "' is missing '}'");

            if (!is_word("by"))
                error("expected 'by'");
            advance();

            while (true) {
                if (s->keys.size() >= max_sort_keys)
                    error("too many sort keys");

                sort_key k;
                k.desc = false;
                k.type = vtype::none;
                k.cr = compiled_rule{};

                if (is_word("rule"))
                    advance();
                else
                    k.expr = parse_expr();

                if (is_word("asc")) {
                    advance();
                } else if (is_word("desc")) {
                    k.desc = true;
                    advance();
                }

                s->keys.push_back(std::move(k));

                if (cur.t != tok::comma)
                    break;
                advance();
            }
        }

        size_t end = lex.offset();
        advance();

        if (s->keys.empty())
            throw parse_error("sort '" + s->name + "' has no 'by'", s->line, s->col);

        s->source = src.substr(start, end - start);

        return s;
    }

private:
    const std::string& src;
    lexer lex;
    token cur;
    int depth;
    size_t line0, col0;

    [[noreturn]] void error(const std::string& msg) {
        throw parse_error(msg, cur.line, cur.col);
    }

    void advance() {
        cur = lex.next();
    }

    void expect(tok t, const char *what) {
        if (cur.t != t)
            error(std::string("expected ") + what);
        advance();
    }

    void expect_word(const char *w) {
        if (cur.t != tok::ident || cur.text != w)
            error(std::string("expected '") + w + "'");
        line0 = cur.line;
        col0 = cur.col;
        advance();
    }

    bool is_word(const char *w) const {
        return cur.t == tok::ident && cur.text == w;
    }

    static bool valid_color(const std::string& c) {
        if (c.size() != 7 && c.size() != 4)
            return false;
        if (c[0] != '#')
            return false;
        for (size_t i = 1; i < c.size(); i++)
            if (!is_hex(c[i]))
                return false;
        return true;
    }

    // Names are used in view ids and urls, so keep them plain
    std::string rule_name(const std::string& kind) {
        std::string n;

        if (cur.t == tok::integer)
            error(kind + " names must start with a letter");

        n = cur.text;
        advance();

        // Allow dashes by gluing ident - ident
        while (cur.t == tok::minus) {
            advance();
            if (cur.t != tok::ident && cur.t != tok::integer)
                error("bad " + kind + " name");
            n += "-";
            n += cur.t == tok::integer ? std::to_string(cur.i) : cur.text;
            advance();
        }

        if (n.size() > 64)
            error(kind + " name is too long");

        for (auto c : n)
            if (!(is_ident_start(c) || (c >= '0' && c <= '9') || c == '-'))
                error(kind + " names may only use letters, digits, '_' and '-'");

        return n;
    }

    std::unique_ptr<node> mk(nkind k) {
        auto n = std::make_unique<node>();
        n->kind = k;
        n->o = op::add;
        n->type = vtype::none;
        n->line = cur.line;
        n->col = cur.col;
        n->lit = value{};
        n->mask = 0;
        n->slot = -1;
        n->aux = -1;
        return n;
    }

    std::unique_ptr<node> binary(op o, std::unique_ptr<node> a, std::unique_ptr<node> b,
            size_t line, size_t col) {
        auto n = mk(nkind::binary);
        n->o = o;
        n->line = line;
        n->col = col;
        n->a = std::move(a);
        n->b = std::move(b);
        return n;
    }

    struct depth_guard {
        parser *p;
        depth_guard(parser *in) : p{in} {
            if (++p->depth > max_depth)
                p->error("expression is nested too deeply");
        }
        ~depth_guard() { p->depth--; }
    };

    std::unique_ptr<node> parse_expr() {
        depth_guard g(this);
        return parse_or();
    }

    std::unique_ptr<node> parse_or() {
        auto l = parse_and();
        while (is_word("or")) {
            auto ln = cur.line, cn = cur.col;
            advance();
            l = binary(op::lor, std::move(l), parse_and(), ln, cn);
        }
        return l;
    }

    std::unique_ptr<node> parse_and() {
        auto l = parse_not();
        while (is_word("and")) {
            auto ln = cur.line, cn = cur.col;
            advance();
            l = binary(op::land, std::move(l), parse_not(), ln, cn);
        }
        return l;
    }

    std::unique_ptr<node> parse_not() {
        if (is_word("not")) {
            depth_guard g(this);
            auto n = mk(nkind::unary);
            n->o = op::lnot;
            advance();
            n->a = parse_not();
            return n;
        }
        return parse_cmp();
    }

    std::unique_ptr<node> parse_cmp() {
        auto l = parse_sum();
        auto ln = cur.line, cn = cur.col;

        op o;
        switch (cur.t) {
            case tok::eq: o = op::eq; break;
            case tok::ne: o = op::ne; break;
            case tok::lt: o = op::lt; break;
            case tok::le: o = op::le; break;
            case tok::gt: o = op::gt; break;
            case tok::ge: o = op::ge; break;
            case tok::ident:
                if (cur.text == "contains")
                    o = op::contains;
                else if (cur.text == "icontains")
                    o = op::icontains;
                else if (cur.text == "startswith")
                    o = op::startswith;
                else if (cur.text == "endswith")
                    o = op::endswith;
                else if (cur.text == "matches")
                    o = op::matches;
                else if (cur.text == "in")
                    o = op::in;
                else if (cur.text == "not") {
                    // 'x not in [...]'
                    advance();
                    if (!is_word("in"))
                        error("expected 'in' after 'not'");
                    advance();
                    auto n = mk(nkind::unary);
                    n->o = op::lnot;
                    n->line = ln;
                    n->col = cn;
                    n->a = binary(op::in, std::move(l), parse_set(), ln, cn);
                    return n;
                } else
                    return l;
                break;
            default:
                return l;
        }

        advance();

        if (o == op::in)
            return binary(o, std::move(l), parse_set(), ln, cn);

        return binary(o, std::move(l), parse_sum(), ln, cn);
    }

    std::unique_ptr<node> parse_set() {
        auto n = mk(nkind::literal);
        n->str = "set";
        expect(tok::lbrack, "'['");

        while (cur.t != tok::rbrack) {
            if (n->set.size() >= 4096)
                error("set is too large");

            auto e = parse_unary();
            if (e->kind != nkind::literal)
                error("sets may only hold literal values");
            n->set.push_back(std::move(e));

            if (cur.t == tok::comma) {
                advance();
                continue;
            }

            if (cur.t != tok::rbrack)
                error("expected ',' or ']'");
        }

        advance();

        if (n->set.empty())
            error("empty set");

        return n;
    }

    std::unique_ptr<node> parse_sum() {
        auto l = parse_prod();
        while (cur.t == tok::plus || cur.t == tok::minus) {
            auto o = cur.t == tok::plus ? op::add : op::sub;
            auto ln = cur.line, cn = cur.col;
            advance();
            l = binary(o, std::move(l), parse_prod(), ln, cn);
        }
        return l;
    }

    std::unique_ptr<node> parse_prod() {
        auto l = parse_unary();
        while (cur.t == tok::star || cur.t == tok::slash || cur.t == tok::percent) {
            auto o = cur.t == tok::star ? op::mul : cur.t == tok::slash ? op::div : op::mod;
            auto ln = cur.line, cn = cur.col;
            advance();
            l = binary(o, std::move(l), parse_unary(), ln, cn);
        }
        return l;
    }

    std::unique_ptr<node> parse_unary() {
        if (cur.t == tok::minus) {
            depth_guard g(this);
            auto n = mk(nkind::unary);
            n->o = op::neg;
            advance();
            n->a = parse_unary();

            // Fold negative literals so sets and limits work
            if (n->a->kind == nkind::literal && n->a->set.empty()) {
                if (n->a->type == vtype::integer) {
                    if (n->a->lit.i == INT64_MIN)
                        error("number out of range");
                    n->a->lit.i = -n->a->lit.i;
                    return std::move(n->a);
                }
                if (n->a->type == vtype::real) {
                    n->a->lit.f = -n->a->lit.f;
                    return std::move(n->a);
                }
            }
            return n;
        }

        return parse_primary();
    }

    std::unique_ptr<node> parse_primary() {
        switch (cur.t) {
            case tok::integer: {
                auto n = mk(nkind::literal);
                n->type = vtype::integer;
                n->lit.i = cur.i;
                n->lit.valid = 1;
                advance();
                return n;
            }
            case tok::real: {
                auto n = mk(nkind::literal);
                n->type = vtype::real;
                n->lit.f = cur.f;
                n->lit.valid = 1;
                advance();
                return n;
            }
            case tok::string: {
                auto n = mk(nkind::literal);
                n->type = vtype::string;
                n->str = cur.text;
                n->lit.valid = 1;
                advance();
                return n;
            }
            case tok::mac: {
                auto n = mk(nkind::literal);
                n->type = vtype::mac;
                n->lit.m = cur.mac;
                n->lit.valid = 1;
                n->mask = cur.mask;
                advance();
                return n;
            }
            case tok::lparen: {
                advance();
                auto n = parse_expr();
                expect(tok::rparen, "')'");
                return n;
            }
            case tok::ident:
                break;
            default:
                error("expected a value or field");
        }

        auto w = cur.text;

        if (w == "true" || w == "false") {
            auto n = mk(nkind::literal);
            n->type = vtype::boolean;
            n->lit.i = w == "true";
            n->lit.valid = 1;
            advance();
            return n;
        }

        if (w == "now") {
            auto n = mk(nkind::now);
            n->type = vtype::integer;
            advance();
            return n;
        }

        if (w == "exists" || w == "count" || w == "age") {
            auto n = mk(w == "exists" ? nkind::exists : w == "count" ? nkind::count : nkind::binary);
            advance();
            expect(tok::lparen, "'('");
            if (cur.t != tok::ident || is_keyword(cur.text))
                error("expected a field name");
            auto f = field();
            expect(tok::rparen, "')'");

            if (w == "age") {
                // age(x) is now - x
                auto now = mk(nkind::now);
                now->type = vtype::integer;
                now->line = n->line;
                now->col = n->col;
                n->o = op::sub;
                n->a = std::move(now);
                n->b = std::move(f);
                return n;
            }

            n->str = f->str;
            return n;
        }

        if (is_keyword(w))
            error("unexpected '" + w + "'");

        return field();
    }

    std::unique_ptr<node> field() {
        auto n = mk(nkind::field);
        n->str = cur.text;
        advance();
        return n;
    }

    static bool is_keyword(const std::string& w) {
        static const char *kw[] = { "and", "or", "not", "in", "contains", "icontains",
            "startswith", "endswith", "matches", "true", "false", "now", "exists",
            "count", "age", "when", "tag", "color", "view", "alert", "live", "rule",
            "sort", "by", "asc", "desc" };

        for (auto k : kw)
            if (w == k)
                return true;
        return false;
    }

};

}

void ruleset::parse(const std::string& text) {
    parser p(text);

    while (!p.at_end()) {
        if (p.at_sort()) {
            auto s = p.parse_sort();

            for (const auto& e : sorts)
                if (e->name == s->name)
                    throw parse_error("duplicate sort '" + s->name + "'", s->line, s->col);

            if (sorts.size() >= max_sorts)
                throw parse_error("too many sorts", s->line, s->col);

            sorts.push_back(std::move(s));
            continue;
        }

        auto r = p.parse_rule();

        for (const auto& e : rules)
            if (e->name == r->name)
                throw parse_error("duplicate rule '" + r->name + "'", r->expr->line, r->expr->col);

        if (rules.size() >= 4096)
            throw parse_error("too many rules", r->expr->line, r->expr->col);

        rules.push_back(std::move(r));
    }
}

const char *vtype_name(vtype t) {
    switch (t) {
        case vtype::none: return "none";
        case vtype::boolean: return "boolean";
        case vtype::integer: return "integer";
        case vtype::real: return "number";
        case vtype::string: return "string";
        case vtype::mac: return "mac";
    }
    return "?";
}

const char *op_name(op o) {
    switch (o) {
        case op::add: return "+";
        case op::sub: return "-";
        case op::mul: return "*";
        case op::div: return "/";
        case op::mod: return "%";
        case op::neg: return "-";
        case op::eq: return "==";
        case op::ne: return "!=";
        case op::lt: return "<";
        case op::le: return "<=";
        case op::gt: return ">";
        case op::ge: return ">=";
        case op::contains: return "contains";
        case op::icontains: return "icontains";
        case op::startswith: return "startswith";
        case op::endswith: return "endswith";
        case op::matches: return "matches";
        case op::in: return "in";
        case op::land: return "and";
        case op::lor: return "or";
        case op::lnot: return "not";
    }
    return "?";
}

}
