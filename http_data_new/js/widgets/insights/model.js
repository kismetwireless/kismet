// The data behind the Insights tab: one read of the devices heard in the
// window, built into a graph (with the insightRelations entries), the
// findings, and the activity rhythm.  Kept free of the DOM so it can be
// tested on its own.

import * as rrd from '../../core/rrd.js';

const base = 'kismet.device.base';

export const baseFields = [
    `${base}.key`, `${base}.macaddr`, `${base}.commonname`, `${base}.name`, `${base}.username`, `${base}.phyname`,
    `${base}.type`, `${base}.manuf`, `${base}.first_time`, `${base}.last_time`, `${base}.channel`,
    `${base}.crypt`, `${base}.packets.total`, `${base}.packets.tx_total`, `${base}.packets.rx_total`,
    `${base}.signal/kismet.common.signal.last_signal`, `${base}.packets.rrd`,
    `${base}.signal/kismet.common.signal.signal_rrd`,
];

export const label = (rec) => rec[`${base}.commonname`] || rec[`${base}.name`] || rec[`${base}.macaddr`] || '?';

// The fields to read: the base ones and every relation's and finder's
export function fieldsFor(...registries) {
    const out = new Set(baseFields);
    for (const reg of registries)
        for (const e of reg)
            for (const f of e.fields ?? [])
                out.add(typeof f === 'string' ? f : JSON.stringify(f));
    return [...out].map((f) => (f.startsWith('[') ? JSON.parse(f) : f));
}

// Build the graph.  `prev` is the last graph: the packet counts give how
// much each device sent since.
export function buildGraph(records, relations, prev = null) {
    const nodes = new Map();
    const links = [];
    const linkIds = new Map();
    const byMac = new Map();
    const sameAs = new Map();
    const root = (n) => {
        let r = n;
        while (sameAs.get(r) && sameAs.get(r) !== r)
            r = sameAs.get(r);
        return r;
    };

    for (const rec of records) {
        const key = rec[`${base}.key`];
        if (!key)
            continue;
        const old = prev?.nodes.get(key);
        const tx = rec[`${base}.packets.tx_total`] ?? 0;
        const rx = rec[`${base}.packets.rx_total`] ?? 0;
        const n = {
            id: key, kind: 'device', key, rec, label: label(rec), role: 'other',
            mac: rec[`${base}.macaddr`], flags: [], degree: 0,
            tx, rx,
            sentSince: old?.rec ? Math.max(0, tx - (old.tx ?? tx)) : 0,
            gotSince: old?.rec ? Math.max(0, rx - (old.rx ?? rx)) : 0,
        };
        nodes.set(key, n);
        if (n.mac)
            byMac.set(n.mac.toUpperCase(), n);
    }

    const g = {
        device: (key) => nodes.get(key) ?? null,
        mac: (mac) => (mac ? byMac.get(String(mac).toUpperCase()) ?? null : null),
        thing(id, { label: text = id, kind = 'thing', title = '' } = {}) {
            const tid = `thing:${id}`;
            let n = nodes.get(tid);
            if (!n) {
                n = { id: tid, kind: 'thing', thingKind: kind, label: text, title, role: kind, flags: [], degree: 0 };
                nodes.set(tid, n);
            }
            return n;
        },
        link(a, b, { kind = 'other', weight = 1, title = '' } = {}) {
            if (!a || !b || a === b)
                return null;
            const id = `${a.id}|${b.id}|${kind}`;
            let l = linkIds.get(id);
            if (l) {
                l.weight = Math.max(l.weight, weight);
                return l;
            }
            l = { id, a, b, kind, weight, title };
            linkIds.set(id, l);
            links.push(l);
            a.degree++;
            b.degree++;
            return l;
        },
        flag(node, text) {
            if (node && !node.flags.includes(text))
                node.flags.push(text);
        },
        role(node, role) {
            if (node)
                node.role = role;
        },
        same(a, b) {
            if (!a || !b || a === b)
                return;
            const ra = root(a), rb = root(b);
            if (ra !== rb)
                sameAs.set(rb, ra);
        },
        drop(node) {
            if (!node || !nodes.delete(node.id))
                return;
            for (let i = links.length - 1; i >= 0; i--) {
                const l = links[i];
                if (l.a === node || l.b === node) {
                    l.a.degree--;
                    l.b.degree--;
                    linkIds.delete(l.id);
                    links.splice(i, 1);
                }
            }
        },
        nodes, links,
    };

    for (const r of relations) {
        for (const rec of records) {
            try {
                r.relate(rec, g);
            } catch (err) {
                console.error(`insight relation ${r.id} failed:`, err);
            }
        }
    }
    for (const r of relations) {
        try {
            r.after?.(g);
        } catch (err) {
            console.error(`insight relation ${r.id} failed:`, err);
        }
    }
    // Several addresses that are one device (g.same), as units: each device
    // node gets .unit, shared by the others in it
    const units = new Map();
    for (const n of nodes.values()) {
        if (n.kind !== 'device')
            continue;
        const r = root(n);
        if (!units.has(r))
            units.set(r, { id: r.id, members: [] });
        units.get(r).members.push(n);
        n.unit = units.get(r);
    }
    return { nodes, links, byMac, units: [...units.values()] };
}

export function findAll(model, finders) {
    const out = [];
    for (const f of finders) {
        try {
            for (const item of f.find(model) ?? [])
                out.push({ finder: f.id, ...item });
        } catch (err) {
            console.error(`insight finder ${f.id} failed:`, err);
        }
    }
    const rank = { high: 0, medium: 1, info: 2 };
    return out.sort((x, y) => (rank[x.severity] ?? 3) - (rank[y.severity] ?? 3));
}

// Correlation of a and b over the minutes where mask is set
function pearson(a, b, mask) {
    let n = 0, sa = 0, sb = 0;
    for (let i = 0; i < a.length; i++) {
        if (!mask[i])
            continue;
        n++;
        sa += a[i];
        sb += b[i];
    }
    if (n < 4)
        return 0;
    const ma = sa / n, mb = sb / n;
    let num = 0, da = 0, db = 0;
    for (let i = 0; i < a.length; i++) {
        if (!mask[i])
            continue;
        const x = a[i] - ma, y = b[i] - mb;
        num += x * y;
        da += x * x;
        db += y * y;
    }
    return da > 0 && db > 0 ? num / Math.sqrt(da * db) : 0;
}

// The minutes of the last hour when any of a device's data sources was
// delivering packets: a device can only be missed while something listens.
//   sources   data source records with uuid and packets_rrd
//   seenby    Map device key -> [source uuids]
export function listening(sources, seenby, now) {
    const active = new Map();
    for (const s of sources) {
        const h = rrd.history(s['kismet.datasource.packets_rrd'], now, 'hour').slice(0, -1);
        active.set(s['kismet.datasource.uuid'], h.map((v) => v > 0));
    }
    const out = new Map();
    for (const [key, uuids] of seenby) {
        const masks = uuids.map((u) => active.get(u)).filter(Boolean);
        if (masks.length)
            out.set(key, masks[0].map((_, k) => masks.some((m) => m[k])));
    }
    return out;
}

// Activity per device over the last hour, a minute per column, and which
// devices come and go together.
//   rows      [{ key, rec, label, values, present: fraction of minutes heard }]
//             ordered so that similar rhythms sit together
//   together  [[keys]]: groups whose comings and goings match
export function rhythm(records, now, { listen = new Map(), maxRows = 160 } = {}) {
    let rows = [];
    for (const rec of records) {
        const h = rrd.history(rec[`${base}.packets.rrd`], now, 'hour');
        if (!h.length)
            continue;
        // the current bin is still filling
        const values = h.slice(0, -1);
        const heard = values.filter((v) => v > 0).length;
        if (heard === 0)
            continue;
        const key = rec[`${base}.key`];
        const mask = listen.get(key) ?? values.map(() => true);
        const on = values.map((v) => v > 0);
        const usable = on.filter((_, k) => mask[k]);
        rows.push({ key, rec, label: label(rec), values, mask, on,
            present: heard / values.length,
            seen: usable.length ? usable.filter(Boolean).length / usable.length : 0,
            changes: usable.reduce((a, v, k) => a + (k > 0 && v !== usable[k - 1]), 0),
            shape: values.map((v) => Math.log1p(v)) });
    }
    rows.sort((x, y) => y.values.reduce((a, v) => a + v, 0) - x.values.reduce((a, v) => a + v, 0));
    rows = rows.slice(0, maxRows);
    const n = rows.length;
    if (n < 2)
        return { rows, together: [] };

    // Compare two devices only over minutes when both could have been heard;
    // a source that stopped is a gap, not both devices leaving
    const both = (a, b) => a.mask.map((m, k) => m && b.mask[k]);
    const r = Array.from({ length: n }, () => new Float32Array(n));
    for (let i = 0; i < n; i++) {
        r[i][i] = 1;
        for (let j = i + 1; j < n; j++)
            r[i][j] = r[j][i] = pearson(rows[i].shape, rows[j].shape, both(rows[i], rows[j]));
    }

    // Average-linkage clustering; the leaf order puts similar rows side by side
    let clusters = rows.map((_, i) => ({ members: [i] }));
    while (clusters.length > 1) {
        let best = -Infinity, bi = 0, bj = 1;
        for (let i = 0; i < clusters.length; i++) {
            for (let j = i + 1; j < clusters.length; j++) {
                let s = 0;
                for (const a of clusters[i].members)
                    for (const b of clusters[j].members)
                        s += r[a][b];
                s /= clusters[i].members.length * clusters[j].members.length;
                if (s > best) {
                    best = s;
                    bi = i;
                    bj = j;
                }
            }
        }
        const merged = { members: [...clusters[bi].members, ...clusters[bj].members] };
        clusters = clusters.filter((_, k) => k !== bi && k !== bj);
        clusters.push(merged);
    }
    const order = clusters[0].members;

    // Groups that come and go together: each arrives and leaves a few times,
    // strongly correlated, and heard in mostly the same minutes
    const parent = rows.map((_, i) => i);
    const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const intermittent = (row) => row.seen > 0.08 && row.seen < 0.92 && row.changes >= 3 && row.on.filter(Boolean).length >= 3;
    for (let i = 0; i < n; i++) {
        if (!intermittent(rows[i]))
            continue;
        for (let j = i + 1; j < n; j++) {
            if (!intermittent(rows[j]) || r[i][j] < 0.75)
                continue;
            const mask = both(rows[i], rows[j]);
            let together = 0, either = 0;
            for (let k = 0; k < mask.length; k++) {
                if (!mask[k])
                    continue;
                const a = rows[i].on[k], b = rows[j].on[k];
                together += a && b;
                either += a || b;
            }
            if (either && together / either >= 0.8)
                parent[find(i)] = find(j);
        }
    }
    const groups = new Map();
    for (let i = 0; i < n; i++) {
        const root = find(i);
        groups.set(root, [...(groups.get(root) ?? []), i]);
    }
    const together = [...groups.values()].filter((m) => m.length > 1).map((m) => m.map((i) => rows[i].key));

    return { rows: order.map((i) => rows[i]), together, corr: (a, b) => {
        const ia = rows.findIndex((x) => x.key === a), ib = rows.findIndex((x) => x.key === b);
        return ia < 0 || ib < 0 ? 0 : r[ia][ib];
    } };
}
