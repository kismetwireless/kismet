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

#ifndef __DR_CORE_H__
#define __DR_CORE_H__

// Device rules: a small typed classification language compiled to a register
// bytecode, run by a VM or, where the platform allows it, native code from the JIT.
// The core knows nothing about tracked devices; field access goes through an env.

#include "config.h"

#include <stdint.h>

#include <deque>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "unordered_dense.h"

#ifdef HAVE_LIBPCRE2
#ifndef PCRE2_CODE_UNIT_WIDTH
#define PCRE2_CODE_UNIT_WIDTH 8
#endif
#include <pcre2.h>
#endif

namespace devicerules {

enum class vtype : uint8_t {
    none,
    boolean,
    integer,
    real,
    string,
    mac,
};

const char *vtype_name(vtype t);

// Field types the env reports for a resolved path element
enum class ftype : uint8_t {
    unsupported,
    integer,
    uinteger,
    real,
    string,
    mac,
    map,
    container,
    // Containers of plain values
    string_list,
    real_list,
};

struct value {
    union {
        int64_t i;
        double f;
        uint64_t m;
        const char *s;
    };
    uint32_t len;
    uint8_t valid;
};

static_assert(sizeof(value) == 16, "value must stay two words for the jit");

class parse_error : public std::runtime_error {
public:
    parse_error(const std::string& msg, size_t line, size_t col) :
        std::runtime_error(msg), line{line}, col{col} { }

    size_t line, col;
    // File the text came from, when known
    std::string origin;
};

// Where rule text comes from, and what it may hold
struct parse_source {
    enum class block : uint8_t {
        // Any number of rules, sorts and includes
        any,
        // One rule or sort without its leading keyword, as written on a config line
        rule,
        sort,
    };

    std::string origin;
    // Added to line numbers, and to columns on the first line, for text taken from
    // the middle of a file
    size_t line_base = 0;
    size_t col_base = 0;
    block only = block::any;

    // Called for each 'include "path"'; includes are refused without it
    std::function<void(const std::string& path, size_t line, size_t col)> include;
};

// A resolved field path; slot is its index in the ruleset
struct field_slot {
    std::string text;
    std::vector<int> path;
    // Path elements after which the path crosses a container
    std::vector<bool> fanout;
    vtype type;
    ftype leaf;
    bool multi;
};

// Resolves names to field ids and types; the kismet side uses the entry tracker
class resolver {
public:
    virtual ~resolver() { }

    // Return the field id and type for a name, or a negative id when unknown
    virtual int resolve(const std::string& name, ftype& type) = 0;
};

// Device field access for one evaluation
class env {
public:
    virtual ~env() { }

    // Load a scalar field; false when any part of the path is missing.  Strings
    // must stay valid until reset().
    virtual bool load(const field_slot& f, value& out) = 0;

    // Call fn for each leaf along a multi path until it returns true
    virtual bool any(const field_slot& f, bool (*fn)(const value&, const void *), const void *arg) = 0;

    // Number of leaves along the path, or the size of a container leaf
    virtual int64_t count(const field_slot& f) = 0;

    // Whether the path leads anywhere, through any branch of a multi path
    virtual bool exists(const field_slot& f) = 0;

    // Drop anything held for the last device
    virtual void reset() { }
};

enum class op : uint8_t {
    // integer and real arithmetic
    add, sub, mul, div, mod, neg,
    // comparisons
    eq, ne, lt, le, gt, ge,
    // string predicates
    contains, icontains, startswith, endswith, matches,
    // membership
    in,
    // logic
    land, lor, lnot,
};

const char *op_name(op o);

enum class nkind : uint8_t {
    literal,
    field,
    now,
    unary,
    binary,
    exists,
    count,
};

struct node {
    nkind kind;
    op o;
    vtype type;
    size_t line, col;

    value lit;
    uint64_t mask;
    std::string str;
    int slot;
    int aux;

    std::unique_ptr<node> a, b;
    std::vector<std::unique_ptr<node>> set;
};

struct rule_def {
    std::string name;
    std::string source;
    std::string origin;
    size_t line;
    std::unique_ptr<node> expr;

    std::vector<std::string> tags;
    std::string color;
    bool view;
    std::string view_desc;
    bool alert;
    bool live;
    bool uses_now;
};

struct compiled_rule {
    size_t entry;
    size_t len;
    uint16_t nregs;
};

// One 'by' of a sort; a null expr is 'by rule', the index of the first matching rule
struct sort_key {
    std::unique_ptr<node> expr;
    bool desc;
    vtype type;
    compiled_rule cr;
};

struct sort_def {
    std::string name;
    std::string source;
    std::string origin;
    std::vector<sort_key> keys;
    bool uses_now;
    size_t line, col;
};

constexpr size_t max_sorts = 256;
constexpr size_t max_sort_keys = 8;

// Constant sets for 'in'
struct value_set {
    vtype type;
    ankerl::unordered_dense::set<int64_t> ints;
    std::vector<double> reals;
    ankerl::unordered_dense::set<std::string> strings;
    ankerl::unordered_dense::set<uint64_t> macs;
    // Masked macs, mac then mask
    std::vector<std::pair<uint64_t, uint64_t>> masked;
};

struct regex_ent {
    std::string pattern;
#ifdef HAVE_LIBPCRE2
    pcre2_code *re;
#endif
};

// Backtracking cap for rule regexes
constexpr uint32_t regex_match_limit = 100000;
constexpr size_t max_regs = 4096;

// Bytecode
enum class bc : uint8_t {
    ldi, ldf, lds, ldm,
    ki, kf, ks, km,
    now,
    i2f,
    addi, subi, muli, divi, modi, negi,
    addf, subf, mulf, divf, negf,
    eqi, nei, lti, lei, gti, gei,
    eqf, nef, ltf, lef, gtf, gef,
    seq, sne, scont, sicont, spre, ssuf, sre,
    ini, inf, ins, inm,
    meq, mne,
    mpred,
    exists, count,
    lnot,
    jf, jt, jmp,
    ret,
};

const char *bc_name(bc b);

struct insn {
    bc o;
    uint8_t pad;
    uint16_t a;
    uint32_t b;
    uint32_t c;
    uint32_t pad2;
};

static_assert(sizeof(insn) == 16, "insn layout");

// Predicate on each leaf of a multi path: leaf <op> constant
struct mpred_ent {
    uint32_t slot;
    bc o;
    // Integer leaves tested against a real constant
    bool i2f;
    uint32_t k;
};

class ruleset;

// Per-thread evaluation state; one per evaluating thread
struct eval_ctx {
    const ruleset *rs;
    env *e;
    int64_t now;

    std::vector<value> regs;
    // Raw views of regs and cache for the jit
    value *rp;

    // Leaf loads cached for the device being evaluated
    struct cache_ent {
        uint32_t gen;
        uint8_t ok;
        value v;
    };
    std::vector<cache_ent> cache;
    cache_ent *cp;
    uint32_t gen;

#ifdef HAVE_LIBPCRE2
    pcre2_match_data *md;
#endif

    eval_ctx();
    ~eval_ctx();
    eval_ctx(const eval_ctx&) = delete;
    eval_ctx& operator=(const eval_ctx&) = delete;

    void bind(const ruleset *in_rs, env *in_e);

    // Start a new device; previous loads are dropped
    void next_device(int64_t in_now) {
        now = in_now;
        if (++gen == 0) {
            for (auto& c : cache)
                c.gen = 0;
            gen = 1;
        }
        if (e != nullptr)
            e->reset();
    }
};

// Evaluate every rule with a nonzero want (or all, when want is null) into out
using jit_all_fn = void (*)(eval_ctx *, const uint8_t *, uint8_t *);
// Index of the first wanted rule that matches, or the rule count
using jit_first_fn = intptr_t (*)(eval_ctx *, const uint8_t *);
// Every key of one sort into out
using jit_sort_fn = void (*)(eval_ctx *, value *);

class ruleset {
public:
    ruleset();
    ~ruleset();
    ruleset(const ruleset&) = delete;
    ruleset& operator=(const ruleset&) = delete;

    // Parse rule blocks, appending to the set; throws parse_error
    void parse(const std::string& text) {
        parse(text, parse_source{});
    }

    // Parse more rules into the set.  A rule or sort with the name of one from another
    // origin replaces it in place; the same name twice from one origin is an error.
    void parse(const std::string& text, const parse_source& src);

    // Drop a rule or sort by name before compiling; false when there's none
    bool remove_rule(const std::string& name);
    bool remove_sort(const std::string& name);

    // Rules and sorts replaced by later definitions while parsing
    std::vector<std::string> replaced;

    // Resolve fields, type check and generate bytecode; throws parse_error
    void compile(resolver& r);

    // Build native code for the set; false leaves the VM in use, with the reason
    bool jit(std::string& err);
    bool is_jit() const { return jit_all != nullptr; }

    size_t size() const { return rules.size(); }
    const rule_def& rule(size_t i) const { return *rules[i]; }

    const std::vector<field_slot>& slots() const { return fields; }
    bool uses_now() const { return any_now; }

    bool eval_tree(eval_ctx& ctx, size_t r) const;
    bool eval_vm(eval_ctx& ctx, size_t r) const;

    // Rules are evaluated a device at a time; call ctx.next_device() first
    void eval_all(eval_ctx& ctx, const uint8_t *want, uint8_t *out) const;

    // Stop at the first wanted rule that matches; returns its index, or size()
    size_t first_match(eval_ctx& ctx, const uint8_t *want) const;

    size_t sort_count() const { return sorts.size(); }
    const sort_def& sort(size_t i) const { return *sorts[i]; }

    // Keys of sort s for the current device into out, one per 'by'.  String keys
    // point into the env and are only good until it's reset.
    void eval_sort(eval_ctx& ctx, size_t s, value *out) const;
    void eval_sort_vm(eval_ctx& ctx, size_t s, value *out) const;
    void eval_sort_tree(eval_ctx& ctx, size_t s, value *out) const;

    // One non-control instruction, for the VM and the JIT slow path
    void step(eval_ctx& ctx, const insn *pc) const;

    std::string disassemble(size_t r) const;

    // Shared by every backend
    bool load_cached(eval_ctx& ctx, uint32_t slot, value& out) const;
    bool leaf_test(eval_ctx& ctx, bc o, const value& v, uint32_t k) const;
    bool run_mpred(eval_ctx& ctx, uint32_t idx) const;
    int64_t run_count(eval_ctx& ctx, uint32_t slot) const;
    bool run_exists(eval_ctx& ctx, uint32_t slot) const;

    std::vector<std::unique_ptr<rule_def>> rules;
    std::vector<std::unique_ptr<sort_def>> sorts;
    std::vector<field_slot> fields;
    std::vector<value> consts;
    std::vector<std::string> const_strings;
    // mac, mask
    std::vector<std::pair<uint64_t, uint64_t>> const_macs;
    std::vector<value_set> sets;
    std::vector<regex_ent> regexes;
    std::vector<mpred_ent> mpreds;
    std::vector<insn> code;
    std::vector<compiled_rule> compiled;
    uint16_t nregs_max;
    bool any_now;
    bool compiled_ok;

#ifdef HAVE_LIBPCRE2
    pcre2_match_context *mctx;
#endif

protected:
    jit_all_fn jit_all;
    jit_first_fn jit_first;
    void *jit_code;
    void *jit_first_code;
    std::vector<jit_sort_fn> jit_sorts;
    std::vector<void *> jit_sort_code;

    // Run compiled code to its ret and return the value it returns
    const value& run_vm(eval_ctx& ctx, const compiled_rule& cr) const;

    friend class compiler;
    friend class jit_builder;
};

// Lower-case ASCII compare helpers shared by the backends
bool str_icontains(const char *h, size_t hl, const char *n, size_t nl);

// Sort keys of many devices, captured one device at a time, then ordered.  Missing
// keys sort last in either direction; ties keep the order rows were added.
class sort_table {
public:
    sort_table(const ruleset& rs, size_t sort);

    void reserve(size_t rows);

    // Capture the keys of the device ctx is on; call after next_device, before the
    // env is reset.  Strings are copied.
    void add(eval_ctx& ctx);

    size_t size() const { return rows; }

    // Row numbers in sorted order
    std::vector<uint32_t> order() const;

    // -1, 0 or 1 as row a sorts before, with or after row b, ignoring the tie break
    int compare(uint32_t a, uint32_t b) const;

    const value& key(uint32_t row, size_t k) const { return keys[row * nk + k]; }

private:
    const ruleset& rs;
    const sort_def& sd;
    size_t si;
    size_t nk;
    size_t rows;
    std::vector<value> keys;
    // A deque never moves its strings, so keys can point at them
    std::deque<std::string> strs;
};

}

#endif
