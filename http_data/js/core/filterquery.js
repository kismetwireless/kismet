// The device list's search box: a plain word or phrase is the server's usual
// search, and anything with an operator, quotes, a MAC address, or a sort
// becomes a device rules filter (see conf/kismet_device_rules.txt) that the
// device view evaluates.
//
//   Huawei                        plain search, as before
//   Huawei || Dell                text("Huawei") or text("Dell")
//   ssid == ONE || ssid == TWO    <ssid path> in ["ONE", "TWO"]
//   packets > 1000 && signal > -60
//   manuf ~ apple                 icontains;  name =~ /^corp-/  matches
//   last_time < 5m                age(last_time) < 5m, for time fields
//   uptime > 1d                   1d in the field's own units, for duration fields
//   00:11:22 || aa:bb             MACs: 2-6 octets anywhere in the address, in
//                                 every MAC field; ^00:11 prefix, 22:33$ suffix
//   ssid* ~ guest                 name* is the wider set of fields, if there is one
//   sort: signal desc, packets    order the list
//
// Field names are full paths, the server's short names, column ids (without a
// group prefix like wifi_) and titles, or search field ids, which match if any
// of their fields do.  Columns and search fields may say what they hold with
// filterKind ('text', 'number', 'time', 'mac', 'duration') and their wider set
// with filterWide (paths).  A duration field takes 30s, 5m, 2h, 1d and turns
// them into its own units with filterConvert(seconds), such as durationIn.us;
// a plain number is used as it is.
//
// compileQuery(text, fieldContext(columns, searchFields)) returns
// { search } or { filter, sort }, and throws a QueryError with the position.

export class QueryError extends Error {
    constructor(message, pos) {
        super(message);
        this.pos = pos;
    }
}

// The server's short names; channel is a string in Kismet
const aliases = {
    mac: ['kismet.device.base.macaddr', 'mac'],
    name: ['kismet.device.base.commonname', 'text'],
    phy: ['kismet.device.base.phyname', 'text'],
    type: ['kismet.device.base.type', 'text'],
    manuf: ['kismet.device.base.manuf', 'text'],
    crypt: ['kismet.device.base.crypt', 'text'],
    channel: ['kismet.device.base.channel', 'text'],
    frequency: ['kismet.device.base.frequency', 'number'],
    packets: ['kismet.device.base.packets.total', 'number'],
    datasize: ['kismet.device.base.datasize', 'number'],
    first_time: ['kismet.device.base.first_time', 'time'],
    last_time: ['kismet.device.base.last_time', 'time'],
    mod_time: ['kismet.device.base.mod_time', 'time'],
    num_alerts: ['kismet.device.base.num_alerts', 'number'],
    signal: ['kismet.device.base.signal/kismet.common.signal.last_signal', 'number'],
    min_signal: ['kismet.device.base.signal/kismet.common.signal.min_signal', 'number'],
    max_signal: ['kismet.device.base.signal/kismet.common.signal.max_signal', 'number'],
};

// filterConvert functions for duration fields, from seconds to the field's units
export const durationIn = {
    s: (s) => s,
    ms: (s) => s * 1e3,
    us: (s) => s * 1e6,
    ns: (s) => s * 1e9,
};

const durSeconds = { s: 1, m: 60, h: 3600, d: 86400 };

const aliasByPath = new Map(Object.entries(aliases).map(([n, [p]]) => [p, n]));

const pathOf = (spec) => (Array.isArray(spec) ? spec[0] : spec);
// Short names read better in the generated filter
const out = (path) => aliasByPath.get(path) ?? path;

const aliasKind = (path) => aliases[aliasByPath.get(path)]?.[1] ?? null;

// Names the box knows, from the columns and search fields (registry lists).
// Each name has its paths and the kind of each; a search field's filterKind
// may be one kind or { path: kind }, and is text when not given.  Its
// filterConvert may likewise be one function or { path: function }.
export function fieldContext(columns = [], searchFields = []) {
    const names = new Map();
    const macFields = [];
    const addMac = (p) => macFields.includes(p) || macFields.push(p);

    for (const [n, [path, kind]] of Object.entries(aliases)) {
        names.set(n, { paths: [path], kinds: [kind], convs: [null] });
        if (kind === 'mac')
            addMac(path);
    }

    const add = (name, entry) => {
        const n = String(name ?? '').trim().toLowerCase().replace(/\s+/g, '_');
        if (n && /^[a-z0-9_]+$/.test(n) && !names.has(n))
            names.set(n, entry);
    };

    for (const c of columns) {
        const path = c.sortField ?? (c.fields?.length === 1 ? pathOf(c.fields[0]) : null);
        if (!path || path.startsWith('#'))
            continue;
        const kind = c.filterKind ?? aliasKind(path) ?? (/_time$/.test(path) ? 'time' : null);
        const entry = { paths: [path], kinds: [kind], convs: [c.filterConvert ?? null], wide: c.filterWide };
        if (kind === 'mac')
            addMac(path);
        // wifi_ssid in the Wi-Fi group is ssid
        const prefix = (c.group ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
        if (prefix && c.id.startsWith(`${prefix}_`))
            add(c.id.slice(prefix.length + 1), entry);
        add(c.id, entry);
        add(c.title, entry);
    }

    for (const s of searchFields) {
        const paths = (s.fields ?? []).map(pathOf).filter((p) => !p.startsWith('#'));
        const fk = s.filterKind;
        const kinds = paths.map((p) => (typeof fk === 'string' ? fk : fk?.[p]) ?? aliasKind(p) ?? 'text');
        const fc = s.filterConvert;
        const convs = paths.map((p) => (typeof fc === 'function' ? fc : fc?.[p]) ?? null);
        if (paths.length)
            add(s.id, { paths, kinds, convs });
    }

    return { names, macFields };
}

// Tokens

const macRe = /^(\^)?((?:[0-9a-f]{2}[:-]){1,5}[0-9a-f]{2}|[0-9a-f]{2}:)(\$)?$/i;
const numRe = /^-?(\d+\.?\d*|\.\d+)$/;
const durRe = /^\d+[smhd]$/;
const wordStop = /[\s()!,"=<>~&|]/;

function lex(text) {
    const toks = [];
    let i = 0;

    while (i < text.length) {
        const c = text[i];
        const two = text.slice(i, i + 2);
        const pos = i;

        if (/\s/.test(c)) {
            i++;
        } else if (two === '||' || two === '&&' || two === '==' || two === '!=' || two === '<=' ||
                two === '>=' || two === '=~') {
            toks.push({ t: two, pos });
            i += 2;
            // =~ takes a /regex/
            if (two === '=~') {
                while (/\s/.test(text[i] ?? ''))
                    i++;
                if (text[i] === '/') {
                    const start = i;
                    let re = '';
                    i++;
                    while (i < text.length && text[i] !== '/') {
                        if (text[i] === '\\' && text[i + 1] === '/') {
                            re += '/';
                            i += 2;
                        } else {
                            re += text[i++];
                        }
                    }
                    if (i >= text.length)
                        throw new QueryError('unfinished /regex/', start);
                    i++;
                    toks.push({ t: 'regex', v: re, pos: start });
                }
            }
        } else if ('()!,<>~='.includes(c)) {
            // A single '=' means '=='
            toks.push({ t: c === '=' ? '==' : c, pos });
            i++;
        } else if (c === '"') {
            let s = '';
            i++;
            while (i < text.length && text[i] !== '"') {
                if (text[i] === '\\' && i + 1 < text.length)
                    i++;
                s += text[i++];
            }
            if (i >= text.length)
                throw new QueryError('unfinished "quote"', pos);
            i++;
            toks.push({ t: 'string', v: s, pos });
        } else if (c === '&' || c === '|') {
            throw new QueryError(`use ${c}${c}`, pos);
        } else {
            let w = '';
            while (i < text.length && !wordStop.test(text[i]))
                w += text[i++];
            if (/^sort:/i.test(w)) {
                toks.push({ t: 'sort', pos });
                i = pos + 5;
                continue;
            }
            const low = w.toLowerCase();
            if (low === 'and' || low === 'or' || low === 'not')
                toks.push({ t: low === 'and' ? '&&' : low === 'or' ? '||' : '!', pos, word: w });
            else if (macRe.test(w))
                toks.push({ t: 'mac', v: w, pos });
            else if (numRe.test(w))
                toks.push({ t: 'number', v: w, pos });
            else if (durRe.test(w))
                toks.push({ t: 'duration', v: w, pos });
            else
                toks.push({ t: 'word', v: w, pos });
        }
    }

    return toks;
}

// A box with only words in it is the plain search; and/or/not as words don't
// count, so "Bed Bath and Beyond" still searches
function isPlain(toks) {
    return toks.every((k) => k.t === 'word' || k.t === 'number' || k.t === 'duration' || k.word);
}

// Parse

const cmpOps = new Set(['==', '!=', '<', '<=', '>', '>=', '~', '=~']);

function parse(toks) {
    let i = 0;
    const peek = () => toks[i];
    const at = (t) => toks[i]?.t === t;
    const endPos = () => (toks.length ? toks[toks.length - 1].pos + 1 : 0);
    const fail = (msg) => {
        throw new QueryError(msg, peek()?.pos ?? endPos());
    };

    // Primary values can start an implied 'and'
    const starts = () => ['word', 'string', 'mac', 'number', 'duration', '(', '!'].includes(peek()?.t);

    function or() {
        const a = [and()];
        while (at('||')) {
            i++;
            a.push(and());
        }
        return a.length === 1 ? a[0] : { t: 'or', a };
    }

    function and() {
        const a = [not()];
        while (at('&&') || starts()) {
            if (at('&&'))
                i++;
            a.push(not());
        }
        return a.length === 1 ? a[0] : { t: 'and', a };
    }

    function not() {
        if (at('!')) {
            i++;
            return { t: 'not', a: not() };
        }
        return primary();
    }

    function primary() {
        const k = peek();
        if (!k)
            fail('expected a value');

        if (k.t === '(') {
            i++;
            const e = or();
            if (!at(')'))
                fail("expected ')'");
            i++;
            return e;
        }

        if (!['word', 'string', 'mac', 'number', 'duration'].includes(k.t))
            fail(`unexpected '${k.word ?? k.t}'`);
        i++;

        if (k.t === 'word' && cmpOps.has(peek()?.t)) {
            const op = peek();
            i++;
            const v = peek();
            if (!v || !['word', 'string', 'mac', 'number', 'duration', 'regex'].includes(v.t))
                fail(`expected a value after '${op.t}'`);
            if ((v.t === 'regex') !== (op.t === '=~'))
                fail(op.t === '=~' ? 'expected a /regex/ after =~' : 'a /regex/ needs =~');
            i++;
            return { t: 'cmp', field: k, op: op.t, value: v, pos: k.pos };
        }

        if (cmpOps.has(peek()?.t))
            fail(`'${k.v}' isn't a field name`);

        return { t: 'bare', value: k, pos: k.pos };
    }

    function sortKeys() {
        const keys = [];
        do {
            if (keys.length)
                i++;
            const k = peek();
            if (k?.t !== 'word')
                fail('expected a field to sort by');
            i++;
            let dir = '';
            const d = peek();
            if (d?.t === 'word' && /^(asc|desc)$/i.test(d.v)) {
                dir = d.v.toLowerCase();
                i++;
            }
            keys.push({ field: k, dir });
        } while (at(','));
        return keys;
    }

    const expr = at('sort') || !toks.length ? null : or();
    let sort = null;
    if (at('sort')) {
        i++;
        sort = sortKeys();
    }
    if (i < toks.length)
        fail(`unexpected '${peek().word ?? peek().v ?? peek().t}'`);

    return { expr, sort };
}

// Generate

const quote = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function resolve(ctx, tok) {
    const name = tok.v;
    if (name.includes('.') || name.includes('/')) {
        const path = name.replace(/\*$/, '');
        return { name, paths: [path], kinds: [aliasKind(path)], convs: [null] };
    }

    const low = name.toLowerCase();
    const wide = low.endsWith('*');
    const base = wide ? low.slice(0, -1) : low;

    if (wide && base === 'mac')
        return { name, paths: ctx.macFields, kinds: ctx.macFields.map(() => 'mac'), convs: ctx.macFields.map(() => null) };

    const e = ctx.names.get(base);
    if (!e)
        throw new QueryError(`unknown field '${name.replace(/\*$/, '')}'`, tok.pos);

    if (wide && e.wide?.length)
        return { name: `${base}*`, paths: e.wide, kinds: e.wide.map(() => e.kinds[0]), convs: e.wide.map(() => e.convs[0]) };
    return { name: base, paths: e.paths, kinds: e.kinds, convs: e.convs };
}

function macParts(text) {
    const m = macRe.exec(text);
    const octets = m[2].split(/[:-]/).filter(Boolean).map((o) => o.toUpperCase());
    return { octets, prefix: !!m[1], suffix: !!m[3] };
}

const macStr = (o) => o.join(':');

// Every aligned place the octets can be, as masked MACs
function macEntries(text) {
    const { octets, prefix, suffix } = macParts(text);
    const n = octets.length;
    if (n === 6)
        return [macStr(octets)];
    const first = suffix ? 6 - n : 0;
    const last = prefix ? 0 : 6 - n;
    const list = [];
    for (let p = first; p <= last; p++) {
        const v = Array(6).fill('00');
        const m = Array(6).fill('00');
        octets.forEach((o, k) => {
            v[p + k] = o;
            m[p + k] = 'FF';
        });
        list.push(`${macStr(v)}/${macStr(m)}`);
    }
    return list;
}

// A duration such as 1d in a field's units
function durationValue(name, conv, v) {
    const n = Math.round((conv ?? durationIn.s)(Number(v.v.slice(0, -1)) * durSeconds[v.v.slice(-1)]));
    if (!Number.isSafeInteger(n))
        throw new QueryError(`${v.v} is too long for ${name}`, v.pos);
    return String(n);
}

// One value as the server's literal for a field of kind k
function literal(name, k, op, v, conv) {

    if (v.t === 'regex')
        return quote(v.v);

    if (k === 'mac') {
        if (v.t !== 'mac')
            throw new QueryError(`${name} is a MAC address`, v.pos);
        const { octets, suffix } = macParts(v.v);
        if (suffix && octets.length < 6)
            return macEntries(v.v)[0];
        return macStr(octets);
    }

    if (k === 'duration') {
        if (v.t === 'duration')
            return durationValue(name, conv, v);
        if (v.t !== 'number')
            throw new QueryError(`${name} is a length of time, like 30s, 5m, 2h or 1d`, v.pos);
        return v.v;
    }

    if (k === 'number' || (k === 'time' && v.t !== 'duration')) {
        if (v.t !== 'number')
            throw new QueryError(`${name} is a number`, v.pos);
        return v.v;
    }

    if (k === 'time')
        return v.v;

    if (k === 'text' || op === '~')
        return quote(v.v);

    // Unknown kinds: numbers and MACs as they are, the rest as text
    if (v.t === 'number' || v.t === 'duration' || v.t === 'mac')
        return v.v;
    return quote(v.v);
}

const serverOp = { '~': 'icontains', '=~': 'matches' };

// One comparison on one path of kind k
function term(name, p, k, conv, op, v, pos) {
    if (['<', '<=', '>', '>='].includes(op) && (k === 'text' || k === 'mac'))
        throw new QueryError(`${name} is ${k === 'mac' ? 'a MAC address' : 'text'}; use ~ or ==`, pos);
    if ((op === '~' || op === '=~') && (k === 'number' || k === 'time' || k === 'duration'))
        throw new QueryError(`${name} is a number; use == != < <= > >=`, pos);
    if (op === '=~' && k === 'mac')
        throw new QueryError(`${name} is a MAC address; use == or ~`, pos);

    // A part of a MAC, anywhere in it
    if (op === '~' && k === 'mac') {
        if (v.t !== 'mac')
            throw new QueryError(`${name} is a MAC address`, v.pos);
        return `${out(p)} in [${macEntries(v.v).join(', ')}]`;
    }

    const lit = literal(name, k, op, v, conv);
    const age = k === 'time' && v.t === 'duration';
    return `${age ? `age(${out(p)})` : out(p)} ${serverOp[op] ?? op} ${lit}`;
}

// The terms for each path that can take the comparison; a name with several
// fields of different kinds skips the ones that can't
function terms(f, fn) {
    const list = [];
    let err = null;
    f.paths.forEach((p, i) => {
        try {
            list.push(fn(p, f.kinds[i], f.convs?.[i]));
        } catch (e) {
            if (!(e instanceof QueryError))
                throw e;
            err = err ?? e;
        }
    });
    if (!list.length)
        throw err ?? new QueryError(`${f.name} has no fields`, 0);
    return list;
}

function cmp(ctx, n) {
    const f = resolve(ctx, n.field);
    const { op, value: v, pos } = n;

    // Not equal to any of them
    if (op === '!=' && f.paths.length > 1)
        return `not ${any(terms(f, (p, k, conv) => term(f.name, p, k, conv, '==', v, pos)))}`;
    return any(terms(f, (p, k, conv) => term(f.name, p, k, conv, op, v, pos)));
}

const any = (terms) => (terms.length === 1 ? terms[0] : `(${terms.join(' or ')})`);

function bare(ctx, v) {
    if (v.t === 'mac') {
        if (!ctx.macFields.length)
            throw new QueryError('no MAC fields to match', v.pos);
        const set = `[${macEntries(v.v).join(', ')}]`;
        return any(ctx.macFields.map((p) => `${out(p)} in ${set}`));
    }
    return `text(${quote(v.v)})`;
}

function gen(ctx, n) {
    switch (n.t) {
        case 'cmp':
            return cmp(ctx, n);
        case 'bare':
            return bare(ctx, n.value);
        case 'not':
            // 'not' takes a comparison, so only and/or need parentheses
            return n.a.t === 'and' || n.a.t === 'or' ? `not (${gen(ctx, n.a)})` : `not ${gen(ctx, n.a)}`;
        case 'and':
            return n.a.map((c) => (c.t === 'or' ? `(${gen(ctx, c)})` : gen(ctx, c))).join(' and ');
        case 'or':
            return orTerms(ctx, n.a).join(' or ');
    }
    return '';
}

// '==' on one field, or'd together, becomes 'in [...]'
function orTerms(ctx, list) {
    const groups = new Map();
    const order = [];

    for (const c of list) {
        const f = c.t === 'cmp' && c.op === '==' ? resolve(ctx, c.field) : null;
        // age() comparisons stay as they are
        if (f && !(c.value.t === 'duration' && f.kinds.includes('time'))) {
            const key = f.paths.join('\n');
            if (!groups.has(key)) {
                groups.set(key, { f, nodes: [] });
                order.push({ key });
            }
            groups.get(key).nodes.push(c);
        } else {
            order.push({ node: c });
        }
    }

    return order.map(({ key, node }) => {
        if (node)
            return gen(ctx, node);
        const { f, nodes } = groups.get(key);
        if (nodes.length === 1)
            return gen(ctx, nodes[0]);
        return any(terms(f, (p, k, conv) => {
            const vals = [];
            let err = null;
            for (const c of nodes) {
                try {
                    vals.push(literal(f.name, k, '==', c.value, conv));
                } catch (e) {
                    if (!(e instanceof QueryError))
                        throw e;
                    err = err ?? e;
                }
            }
            if (!vals.length)
                throw err;
            return `${out(p)} in [${[...new Set(vals)].join(', ')}]`;
        }));
    });
}

function sortText(ctx, keys) {
    return keys.map(({ field, dir }) => {
        const f = resolve(ctx, field);
        if (f.paths.length !== 1)
            throw new QueryError(`can't sort by ${f.name}, it's several fields`, field.pos);
        return dir ? `${out(f.paths[0])} ${dir}` : out(f.paths[0]);
    }).join(', ');
}

export function compileQuery(text, ctx) {
    const src = String(text ?? '').trim();
    if (!src)
        return { search: '' };

    const toks = lex(src);
    if (isPlain(toks))
        return { search: src };

    const { expr, sort } = parse(toks);
    return {
        filter: expr ? gen(ctx, expr) : '',
        sort: sort ? sortText(ctx, sort) : '',
    };
}
