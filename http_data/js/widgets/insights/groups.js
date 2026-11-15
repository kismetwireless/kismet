// The device graph gathered for the Flow and Access points views: the names
// (networks), the hubs devices attach to (access points, with the addresses
// of one box as one hub), the devices attached to them, and the devices that
// only look for names.  Devices of one kind seen on several hubs (wired hosts
// on a shared wire) are one group instead of a group on each hub.
//
//   const r = gather(graph, findings);
//   r.names, r.hubs, r.attached, r.seekers   lists of items, each { id, label, members, ... }
//   r.edges        [{ from, to, kind, count }] between items of neighboring columns
//
//   condense(r, { seeds, all })   the same, trimmed for drawing a busy area

const shortManuf = (m) => (m ?? '').replace(/\(.*?\)|,|\b(Inc|Ltd|LLC|Co|Corp|Corporation|Limited|Technologies|Technology|Electronics)\b\.?/gi, '')
    .trim().split(/\s+/).slice(0, 2).join(' ');

// A hub's name: a name the user gave one of its addresses, or its maker and
// the end of its first address
export function unitName(unit) {
    const p = unitParts(unit);
    return p.named ? p.short : `${p.maker} ${p.short}`;
}

// The name in parts for tight spaces: { short, maker, named }
export function unitParts(unit) {
    const named = unit.members.find((n) => n.rec?.['kismet.device.base.username']);
    const first = [...unit.members].sort((a, b) => (a.mac ?? '').localeCompare(b.mac ?? ''))[0];
    const maker = shortManuf(first.rec?.['kismet.device.base.manuf']);
    return {
        short: named ? named.rec['kismet.device.base.username'] : (first.mac ?? '').slice(-5),
        maker: maker && maker !== 'Unknown' ? maker : 'Access point',
        named: !!named,
    };
}

export function gather(graph, findings = []) {
    // findings worth marking; 'info' ones (a shared wire) would mark most devices
    const flagged = new Map();
    for (const f of findings.filter((x) => x.severity !== 'info'))
        for (const k of f.devices ?? [])
            flagged.set(k, [...(flagged.get(k) ?? []), f]);

    const hubOf = (n) => (n.kind === 'device' && n.role === 'ap' ? n.unit : null);
    const names = new Map();
    const hubs = new Map();
    const seekers = new Map();
    const attachedBy = new Map();      // kind -> Map(device -> Set(hub unit))
    const edges = new Map();
    const edge = (from, to, kind, n = 1) => {
        const id = `${from.id}|${to.id}|${kind}`;
        const e = edges.get(id) ?? { from, to, kind, count: 0, members: new Set() };
        e.count += n;
        edges.set(id, e);
        return e;
    };
    const hubItem = (unit) => {
        if (!hubs.has(unit)) {
            hubs.set(unit, { id: `hub:${unit.id}`, unit, label: unitName(unit), parts: unitParts(unit), members: unit.members,
                channels: [...new Set(unit.members.map((m) => m.rec?.['kismet.device.base.channel']).filter(Boolean))],
                names: new Set(), flags: unit.members.flatMap((m) => flagged.get(m.key) ?? []) });
        }
        return hubs.get(unit);
    };
    const nameItem = (t) => {
        if (!names.has(t))
            names.set(t, { id: t.id, thing: t, label: t.label, sought: t.thingKind === 'ssid-sought', members: [] });
        return names.get(t);
    };

    for (const l of graph.links) {
        const thing = l.a.kind === 'thing' ? l.a : l.b.kind === 'thing' ? l.b : null;
        if (thing) {
            const dev = thing === l.a ? l.b : l.a;
            if (dev.kind !== 'device')
                continue;
            const hub = hubOf(dev);
            const name = nameItem(thing);
            if (hub) {
                const h = hubItem(hub);
                h.names.add(name.label);
                edge(name, h, l.kind).members.add(dev);
            } else {
                const id = `seek:${l.kind}`;
                if (!seekers.has(id))
                    seekers.set(id, { id, kind: l.kind, members: [], seen: new Set() });
                const s = seekers.get(id);
                if (!s.seen.has(dev)) {
                    s.seen.add(dev);
                    s.members.push(dev);
                }
                edge(s, name, l.kind).members.add(dev);
            }
            continue;
        }
        const ha = hubOf(l.a), hb = hubOf(l.b);
        if (!ha === !hb)
            continue;
        const dev = ha ? l.b : l.a;
        const hub = ha ?? hb;
        hubItem(hub);
        if (!attachedBy.has(l.kind))
            attachedBy.set(l.kind, new Map());
        const m = attachedBy.get(l.kind);
        if (!m.has(dev))
            m.set(dev, new Set());
        m.get(dev).add(hub);
    }

    // Devices attached to several hubs on average are one group for their kind
    const attached = new Map();
    for (const [kind, m] of attachedBy) {
        const spread = [...m.values()].reduce((s, hs) => s + hs.size, 0) / m.size;
        for (const [dev, hs] of m) {
            for (const hub of hs) {
                const id = spread > 1.5 ? `att:${kind}` : `att:${kind}:${hub.id}`;
                if (!attached.has(id))
                    attached.set(id, { id, kind, shared: spread > 1.5, members: [], seen: new Set() });
                const g = attached.get(id);
                if (!g.seen.has(dev)) {
                    g.seen.add(dev);
                    g.members.push(dev);
                }
                const e = edge(hubItem(hub), g, kind, 0);
                if (!e.members.has(dev)) {
                    e.members.add(dev);
                    e.count++;
                }
            }
        }
    }
    for (const n of names.values())
        n.members = [n.thing];
    for (const g of [...attached.values(), ...seekers.values()])
        g.flags = g.members.flatMap((d) => flagged.get(d.key) ?? []);

    return {
        names: [...names.values()].sort((a, b) => a.sought - b.sought || a.label.localeCompare(b.label)),
        hubs: [...hubs.values()],
        attached: [...attached.values()],
        seekers: [...seekers.values()],
        edges: [...edges.values()],
        flagged,
        quietHubs: (graph.units ?? []).filter((u) => u.members.some((m) => m.role === 'ap') && !hubs.has(u)),
    };
}

// How many of each column a busy area shows before the rest are merged
export const flowCaps = { hubs: 25, names: 30, sought: 10 };

// A gathered graph trimmed for drawing.  With seeds (item ids), only what
// links through them: everything reached from a seed going right, and going
// left.  Otherwise, unless all is set, a column over its cap keeps its
// busiest entries and every one with a finding, and the rest of it becomes
// one "more" entry carrying their links.  hidden counts what was merged.
export function condense(r, { seeds = null, all = false } = {}) {
    const hidden = { hubs: 0, names: 0, sought: 0, total: { hubs: r.hubs.length, names: r.names.length } };
    if (seeds) {
        const right = new Map(), left = new Map();
        for (const e of r.edges) {
            right.set(e.from.id, [...(right.get(e.from.id) ?? []), e.to]);
            left.set(e.to.id, [...(left.get(e.to.id) ?? []), e.from]);
        }
        const keep = new Set(seeds);
        for (const way of [right, left]) {
            const stack = [...seeds];
            const seen = new Set(seeds);
            while (stack.length) {
                for (const next of way.get(stack.pop()) ?? []) {
                    if (seen.has(next.id))
                        continue;
                    seen.add(next.id);
                    keep.add(next.id);
                    stack.push(next.id);
                }
            }
        }
        const has = (it) => keep.has(it.id);
        return { ...r, names: r.names.filter(has), hubs: r.hubs.filter(has), attached: r.attached.filter(has),
            seekers: r.seekers.filter(has), edges: r.edges.filter((e) => has(e.from) && has(e.to)), hidden, focused: true };
    }
    if (all)
        return { ...r, hidden };

    // How much flows through an item, with a finding first
    const weight = new Map();
    for (const e of r.edges)
        for (const it of [e.from, e.to])
            weight.set(it.id, (weight.get(it.id) ?? 0) + e.count);
    const rank = (list) => [...list].sort((a, b) => (b.flags?.length ? 1 : 0) - (a.flags?.length ? 1 : 0) ||
        (weight.get(b.id) ?? 0) - (weight.get(a.id) ?? 0));
    const top = (list, cap) => {
        if (list.length <= cap)
            return [list, []];
        const sorted = rank(list);
        const kept = new Set(sorted.filter((it, i) => i < cap || it.flags?.length));
        return [list.filter((it) => kept.has(it)), list.filter((it) => !kept.has(it))];
    };

    const into = new Map();
    const merge = (rest, item) => {
        if (!rest.length)
            return null;
        item.members = rest.flatMap((it) => it.members);
        for (const it of rest)
            into.set(it.id, item);
        return item;
    };
    const plural = (n, one, many) => `${n.toLocaleString()} more ${n === 1 ? one : many}`;

    const [hubs, hubRest] = top(r.hubs, flowCaps.hubs);
    hidden.hubs = hubRest.length;
    const moreHub = merge(hubRest, { id: 'more:hub', more: true, label: plural(hubRest.length, 'access point', 'access points'),
        parts: { short: `${hubRest.length.toLocaleString()} more`, maker: 'access points', named: true },
        channels: [], names: new Set(), flags: [] });

    const [sought, soughtRest] = top(r.names.filter((n) => n.sought), flowCaps.sought);
    const [named, namedRest] = top(r.names.filter((n) => !n.sought), Math.max(1, flowCaps.names - sought.length));
    hidden.names = namedRest.length;
    hidden.sought = soughtRest.length;
    const moreName = merge(namedRest, { id: 'more:name', more: true, sought: false,
        label: plural(namedRest.length, 'network', 'networks') });
    const moreSought = merge(soughtRest, { id: 'more:sought', more: true, sought: true,
        label: plural(soughtRest.length, 'name looked for', 'names looked for') });

    // A merged access point's own devices go with it, one group per kind
    const attached = [];
    const moreAtt = new Map();
    const hubOfGroup = new Map(r.edges.filter((e) => e.from.id.startsWith('hub:')).map((e) => [e.to, e.from]));
    for (const g of r.attached) {
        const hub = hubOfGroup.get(g);
        if (!g.shared && hub && into.has(hub.id)) {
            if (!moreAtt.has(g.kind))
                moreAtt.set(g.kind, { id: `more:att:${g.kind}`, kind: g.kind, more: true, shared: false, members: [], flags: [] });
            const m = moreAtt.get(g.kind);
            m.members.push(...g.members);
            into.set(g.id, m);
        } else {
            attached.push(g);
        }
    }

    // Links into merged entries become one link per pair and kind
    const edges = new Map();
    for (const e of r.edges) {
        const from = into.get(e.from.id) ?? e.from;
        const to = into.get(e.to.id) ?? e.to;
        const id = `${from.id}|${to.id}|${e.kind}`;
        const x = edges.get(id) ?? { from, to, kind: e.kind, count: 0 };
        x.count += e.count;
        edges.set(id, x);
    }
    return {
        ...r,
        names: [...named, ...(moreName ? [moreName] : []), ...sought, ...(moreSought ? [moreSought] : [])],
        hubs: [...hubs, ...(moreHub ? [moreHub] : [])],
        attached: [...attached, ...moreAtt.values()],
        edges: [...edges.values()],
        hidden,
    };
}
