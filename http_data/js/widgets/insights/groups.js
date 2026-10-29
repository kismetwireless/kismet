// The device graph gathered for the Flow and Access points views: the names
// (networks), the hubs devices attach to (access points, with the addresses
// of one box as one hub), the devices attached to them, and the devices that
// only look for names.  Devices of one kind seen on several hubs (wired hosts
// on a shared wire) are one group instead of a group on each hub.
//
//   const r = gather(graph, findings);
//   r.names, r.hubs, r.attached, r.seekers   lists of items, each { id, label, members, ... }
//   r.edges        [{ from, to, kind, count }] between items of neighboring columns

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
