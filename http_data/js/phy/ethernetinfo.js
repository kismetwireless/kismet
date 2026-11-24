// Text for the Ethernet (IEEE802.3) phy's fields: VLAN labels, protocol and
// role bits, flow endpoints, TCP flags, the status counters worth a warning,
// checks for the Ethernet flows window's filters, and the pollers that keep
// flow windows up to date.  No DOM, so it can be tested on its own;
// js/phy/ethernet.js draws with it.

const protocolBits = [
    [1 << 0, 'ARP'], [1 << 1, 'IPv4'], [1 << 2, 'IPv6'], [1 << 3, 'TCP'], [1 << 4, 'UDP'],
    [1 << 5, 'ICMP'], [1 << 6, 'ICMPv6'], [1 << 7, 'DHCP'], [1 << 8, 'DHCPv6'], [1 << 9, 'LLC'],
    [1 << 10, 'VLAN tagged'], [1 << 11, 'QinQ'], [1 << 12, 'Other'],
];

const roleBits = [
    [1 << 0, 'DHCP server'], [1 << 1, 'DHCPv6 server'], [1 << 2, 'Gateway'], [1 << 3, 'DNS server'],
];

const ipProtocols = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 132: 'SCTP' };

const tcpFlagBits = [
    [0x02, 'SYN'], [0x10, 'ACK'], [0x08, 'PSH'], [0x01, 'FIN'], [0x04, 'RST'], [0x20, 'URG'], [0x40, 'ECE'], [0x80, 'CWR'],
];

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

function bitNames(table, bits) {
    const b = num(bits);
    return table.filter(([bit]) => (b & bit) !== 0).map(([, name]) => name);
}

export const protocolNames = (bits) => bitNames(protocolBits, bits);
export const roleNames = (bits) => bitNames(roleBits, bits);
export const tcpFlagNames = (bits) => bitNames(tcpFlagBits, bits);

export function ipProtocolName(p) {
    const n = num(p);
    return ipProtocols[n] ?? `IP ${n}`;
}

// A VLAN as people write it: untagged, a VLAN ID, VLAN 0 (priority tagged
// only), or QinQ as outer/inner
export function vlanLabel(tags, vid, inner) {
    const t = num(tags);
    if (t === 0)
        return 'Untagged';
    if (t === 1)
        return num(vid) === 0 ? '0 (priority)' : String(num(vid));
    return `${num(vid)}/${num(inner)}`;
}

export function vlanTagText(tags) {
    const t = num(tags);
    if (t === 0)
        return 'None';
    if (t === 1)
        return '802.1Q';
    return t === 2 ? 'QinQ' : `QinQ, ${t} tags`;
}

// Sort key that puts untagged first, then by outer and inner VLAN ID
export const vlanSortKey = (tags, vid, inner) => (num(tags) === 0 ? -1 : num(vid) * 4096 + num(inner) + (num(tags) > 1 ? 0.5 : 0));

// One side of a flow: an address and, for protocols with ports, the port
export function endpoint(addr, port, proto) {
    const a = typeof addr === 'string' ? addr : '';
    const n = num(proto);
    if (n !== 6 && n !== 17 && n !== 132)
        return a;
    return a.includes(':') ? `[${a}]:${num(port)}` : `${a}:${num(port)}`;
}

// Device names, the DHCP hostname first, then the fully qualified names
export function hostNames(names) {
    if (!Array.isArray(names))
        return [];
    const rank = { dhcp_hostname: 0, dhcp_fqdn: 1, dhcpv6_fqdn: 2 };
    return names
        .filter((n) => n && typeof n['ethernet.device.name.name'] === 'string' && n['ethernet.device.name.name'] !== '')
        .slice()
        .sort((a, b) => (rank[a['ethernet.device.name.source']] ?? 9) - (rank[b['ethernet.device.name.source']] ?? 9))
        .map((n) => n['ethernet.device.name.name'])
        .filter((n, i, all) => all.indexOf(n) === i);
}

// IPv4 then IPv6 addresses of a device, as listed
export function addresses(ipv4, ipv6) {
    const list = (v) => (Array.isArray(v) ? v : [])
        .map((r) => r?.['ethernet.device.ip.address'])
        .filter((a) => typeof a === 'string' && a !== '');
    return [...list(ipv4), ...list(ipv6)];
}

// The status counters worth telling someone about: each nonzero one as
// { id, text, help }.  Nothing when all is well.
export function statusNotes(st) {
    if (!st || typeof st !== 'object')
        return [];
    const s = (k) => num(st[`ethernet.status.${k}`]);
    const n = (v) => v.toLocaleString('en-US');
    const notes = [];
    if (s('devices_capped'))
        notes.push({ id: 'capped', text: `${n(s('devices_capped'))} new MAC addresses not tracked: the limit of ` +
            `${n(s('max_devices'))} Ethernet devices was reached`,
        help: 'Raise wired_max_devices in kismet_wired.conf for a larger network.  A MAC flood looks like this too.' });
    if (s('devices_rate_limited'))
        notes.push({ id: 'rate', text: `${n(s('devices_rate_limited'))} new MAC addresses not tracked: more than ` +
            `${n(s('new_device_rate'))} new devices a second`,
        help: 'wired_new_device_rate in kismet_wired.conf limits new devices per second of capture time.  ' +
            'A MAC that keeps sending is let in later.' });
    if (s('devices_evicted'))
        notes.push({ id: 'evicted', text: `${n(s('devices_evicted'))} devices which sent only a frame or two were ` +
            'forgotten to make room for new ones',
        help: 'At the device limit, a new MAC that keeps sending replaces the oldest device that sent only a frame or two.' });
    if (s('future_timestamps'))
        notes.push({ id: 'future', text: `${n(s('future_timestamps'))} frames dated more than a minute past the server clock`,
            help: 'The capture\'s clock is ahead of the server\'s, or the capture is damaged.' });
    if (s('flows_dropped'))
        notes.push({ id: 'flows', text: `${n(s('flows_dropped'))} new flows not kept: the flow table of ` +
            `${n(s('max_flows'))} was full`,
        help: 'Raise wired_max_flows in kismet_wired.conf, or shorten the flow timeouts.' });
    if (s('ip_bindings_dropped'))
        notes.push({ id: 'ips', text: `${n(s('ip_bindings_dropped'))} IP address bindings not kept: the table was full`,
            help: 'Kismet keeps at most 65,536 IP to MAC bindings.' });
    if (s('vlans_dropped'))
        notes.push({ id: 'vlans', text: `${n(s('vlans_dropped'))} VLANs not added to the inventory: it was full`,
            help: 'Kismet keeps at most 4,096 VLANs in the inventory.' });
    return notes;
}

// Filters for the flows endpoint, checked here so a typo gets a plain message
// instead of a server error.  Returns { filter } or { error }.
const macPattern = /^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$/;
const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const ipv6Pattern = /^[0-9A-Fa-f:.]{2,45}$/;

export function flowFilter({ mac = '', ip = '', vlan = '' } = {}) {
    const filter = {};
    const m = String(mac).trim();
    const i = String(ip).trim();
    const v = String(vlan).trim();
    if (m) {
        if (!macPattern.test(m))
            return { error: 'MAC addresses are six pairs of hex digits, like 02:00:00:00:00:01.' };
        filter.mac = m.replace(/-/g, ':').toUpperCase();
    }
    if (i) {
        const v4 = ipv4Pattern.exec(i);
        if (v4 ? v4.slice(1).some((o) => Number(o) > 255) : !(i.includes(':') && ipv6Pattern.test(i)))
            return { error: 'IP addresses are IPv4 (192.0.2.1) or IPv6 (2001:db8::1).' };
        filter.ip = i;
    }
    if (v) {
        if (!/^\d{1,4}$/.test(v) || Number(v) > 4095)
            return { error: 'VLAN IDs are 0 to 4095.' };
        filter.vlan = Number(v);
    }
    return { filter };
}

// What identifies a flow: its protocol, both ends and its VLAN tags
const flowKeyFields = ['family', 'proto', 'addr_a', 'port_a', 'addr_b', 'port_b', 'vlan_tags', 'vid', 'inner_vid'];
export const flowKey = (r) => flowKeyFields.map((k) => r?.[`ethernet.flow.${k}`]).join('|');

// The flows endpoint filters by address and VLAN, not by flow, so a flow is
// read again by asking for the newest flows of one end's address on its VLAN.
// The query for one side, or null when that side has no usable address.
export function flowQuery(r, side, length) {
    const addr = r?.[`ethernet.flow.addr_${side}`];
    const f = flowFilter({ ip: typeof addr === 'string' ? addr : '' });
    if (f.error || !f.filter.ip)
        return null;
    const vlan = num(r?.['ethernet.flow.vlan_tags']) > 0 ? { vlan: num(r['ethernet.flow.vid']) } : {};
    return { ip: f.filter.ip, ...vlan, start: 0, length };
}

// A flow in a reply: { flow, total, complete }, complete when the reply holds
// every flow of the address, so a flow missing from it is gone
export function matchFlow(want, reply) {
    const rows = Array.isArray(reply?.['ethernet.flows.flows']) ? reply['ethernet.flows.flows'] : [];
    const total = num(reply?.['ethernet.flows.total']);
    return { flow: rows.find((x) => flowKey(x) === want) ?? null, total, complete: total <= rows.length };
}

// Read one flow again: a few of the newest flows of each end, then more of the
// end with fewer flows, one read only.  post(body) gives the endpoint's reply.
// known holds totals already read for a side ({ a: 250 }), so that side isn't
// asked again; isClosed() stops it between reads.  Resolves to
// { state, flow, prefer }, state being
//   found     flow is the fresh record
//   gone      a complete list for one of its addresses doesn't have it: the
//             server has forgotten it
//   unknown   every list read was cut short before it turned up
//   closed    isClosed() said to stop
// prefer is the end whose address has fewer flows, to ask about first next time.
export async function findFlow(r, post, { prefer = 'a', few = 100, more = 1000, known = {}, isClosed = () => false } = {}) {
    const want = flowKey(r);
    const totals = { ...known };
    const better = () => ('a' in totals && 'b' in totals && totals.b < totals.a ? 'b' : 'a' in totals ? 'a' :
        'b' in totals ? 'b' : prefer);
    const sides = (prefer === 'b' ? ['b', 'a'] : ['a', 'b']).filter((s) => flowQuery(r, s, few));
    const ask = async (side, length) => {
        if (isClosed())
            return { state: 'closed' };
        const reply = await post(flowQuery(r, side, length));
        if (isClosed())
            return { state: 'closed' };
        const m = matchFlow(want, reply);
        totals[side] = m.total;
        if (m.flow)
            return { state: 'found', flow: m.flow };
        return m.complete ? { state: 'gone', flow: null } : null;
    };
    const done = (got) => (got.state === 'closed' ? { state: 'closed', flow: null, prefer } : { ...got, prefer: better() });
    for (const side of sides) {
        if (side in known)
            continue;
        const got = await ask(side, few);
        if (got)
            return done(got);
    }
    const quieter = sides.filter((s) => num(totals[s]) > few).sort((x, y) => totals[x] - totals[y])[0];
    if (quieter && more > few) {
        const got = await ask(quieter, more);
        if (got)
            return done(got);
    }
    return { state: 'unknown', flow: null, prefer: better() };
}

// Keeps open flow windows up to date with as few reads as it can.  Every
// `seconds` while visible(): one read of `few` flows per address and VLAN,
// shared by every window that asks about it, at most maxReads of them (the
// longest waiting first).  A flow missing from a cut-short list gets a longer
// look (findFlow), one at a time and at most one started a tick.  A flow
// found gone or unknown is no longer read until check() asks again.
//
// watch(flow, onUpdate) gives { stop(), check() }; onUpdate(w) is called with
// { flow, state, was, error } as they change, state being found, checking,
// gone, unknown or error (an endpoint error; still read every tick), and
// was the state before a check.
export function flowPoller({ post, few = 100, more = 1000, maxReads = 4, seconds = 5, visible = () => true }) {
    const watchers = new Set();
    const lookups = [];
    let ticks = 0;
    let busy = false;
    let looking = false;
    let lookTick = -1;
    let timer = null;

    function sync() {
        if (!seconds)
            return;
        if (watchers.size && !timer) {
            timer = setInterval(tick, seconds * 1000);
        } else if (!watchers.size && timer) {
            clearInterval(timer);
            timer = null;
        }
    }

    function set(w, state, extra = {}) {
        if (w.stopped)
            return;
        if (state === 'checking' && w.state !== 'checking')
            w.was = w.state;
        Object.assign(w, { state }, extra);
        w.onUpdate(w);
    }

    function lookFurther(w, known) {
        w.known = known;
        set(w, 'checking');
        if (!lookups.includes(w))
            lookups.push(w);
        nextLookup();
    }

    async function nextLookup() {
        if (looking || lookTick === ticks)
            return;
        // stop() takes a window out of the queue
        const w = lookups.shift();
        if (!w)
            return;
        looking = true;
        lookTick = ticks;
        try {
            const got = await findFlow(w.flow, post, { prefer: w.prefer, few, more, known: w.known,
                isClosed: () => w.stopped });
            if (got.state !== 'closed') {
                w.prefer = got.prefer;
                set(w, got.state, got.flow ? { flow: got.flow, error: '' } : { error: '' });
            }
        } catch (err) {
            set(w, 'error', { error: err?.message ?? String(err) });
        } finally {
            looking = false;
        }
    }

    async function tick() {
        if (busy || !visible())
            return;
        busy = true;
        ticks++;
        try {
            const groups = new Map();
            for (const w of watchers) {
                if (w.state !== 'found' && w.state !== 'error')
                    continue;
                const side = [w.prefer, w.prefer === 'a' ? 'b' : 'a'].find((s) => flowQuery(w.flow, s, few));
                if (!side) {
                    set(w, 'unknown');
                    continue;
                }
                const query = flowQuery(w.flow, side, few);
                const k = JSON.stringify(query);
                if (!groups.has(k))
                    groups.set(k, { query, members: [], oldest: Infinity });
                const g = groups.get(k);
                g.members.push({ w, side });
                g.oldest = Math.min(g.oldest, w.lastTick);
            }
            const chosen = [...groups.values()].sort((x, y) => x.oldest - y.oldest).slice(0, maxReads);
            await Promise.all(chosen.map(async (g) => {
                for (const { w } of g.members)
                    w.lastTick = ticks;
                let reply;
                try {
                    reply = await post(g.query);
                } catch (err) {
                    for (const { w } of g.members)
                        set(w, 'error', { error: err?.message ?? String(err) });
                    return;
                }
                for (const { w, side } of g.members) {
                    if (w.stopped || (w.state !== 'found' && w.state !== 'error'))
                        continue;
                    const m = matchFlow(flowKey(w.flow), reply);
                    if (m.flow)
                        set(w, 'found', { flow: m.flow, error: '' });
                    else if (m.complete)
                        set(w, 'gone', { error: '' });
                    else
                        lookFurther(w, { [side]: m.total });
                }
            }));
        } finally {
            busy = false;
        }
        nextLookup();
    }

    function watch(flow, onUpdate) {
        const w = { flow, prefer: 'a', state: 'found', was: 'found', error: '', stopped: false, lastTick: ticks,
            known: {}, onUpdate };
        watchers.add(w);
        sync();
        return {
            stop() {
                w.stopped = true;
                watchers.delete(w);
                const i = lookups.indexOf(w);
                if (i >= 0)
                    lookups.splice(i, 1);
                sync();
            },
            // Look for it again, all the way, after it was found gone or unknown
            check() {
                if (!w.stopped && w.state !== 'checking')
                    lookFurther(w, {});
            },
        };
    }

    return { watch, tick, get size() { return watchers.size; } };
}

// A flow's server key (ethernet.flow.key: hex, '-', a hex serial), or null
// from an older server that has none.  It holds both addresses, so it goes
// into URLs only, never onto the page.
const serverKeyPattern = /^[0-9a-f]{8,128}-[0-9a-f]{1,32}$/;
export function serverFlowKey(r) {
    const k = r?.['ethernet.flow.key'];
    return typeof k === 'string' && serverKeyPattern.test(k) ? k : null;
}

// How a flow's traffic history changed between two history_time values:
// none (still none), same, started, restarted (began again: graphs start
// over) or stopped (given back)
export function historyChange(before, after) {
    const b = num(before);
    const a = num(after);
    if (a === b)
        return a ? 'same' : 'none';
    if (!a)
        return 'stopped';
    return b ? 'restarted' : 'started';
}

// Why a flow has no traffic history, from the flow and the status endpoint's
// reply (null before it's read)
export function historyNote(flow, st) {
    const has = (k) => !!st && typeof st === 'object' && typeof st[`ethernet.status.${k}`] === 'number';
    const s = (k) => (has(k) ? num(st[`ethernet.status.${k}`]) : 0);
    const n = (v) => v.toLocaleString('en-US');
    const min = s('flow_history_min_packets');
    const max = s('max_flow_histories');
    const packets = num(flow?.['ethernet.flow.packets_ab']) + num(flow?.['ethernet.flow.packets_ba']);
    if (has('max_flow_histories') && max === 0)
        return 'Traffic history is turned off on this server (wired_flow_history_max is 0).';
    if (min > 0 && packets < min)
        return `No traffic history yet: Kismet starts one once a flow has ${n(min)} packets ` +
            '(wired_flow_history_min_packets).';
    if (max > 0 && s('flow_histories') >= max)
        return `No traffic history: all ${n(max)} are in use (wired_flow_history_max).`;
    if (min > 0)
        return 'No traffic history: it was given back while the flow was idle, or every history was in use when ' +
            'the flow qualified.';
    return 'No traffic history yet: Kismet starts one once a flow has a few packets (wired_flow_history_min_packets).';
}

// Keeps open flow windows up to date by reading each flow by its server key
// (serverFlowKey), once when watch() starts and then every `seconds` while
// visible(): one read per window, at
// most maxReads of them however many are open (the longest waiting first),
// each given up after `timeout` seconds.  read(key, signal) gives the
// endpoint's reply or throws with err.status: 404 is a flow the server has
// forgotten, 400 a key it can't read.  A flow found gone or invalid is no
// longer read until check() asks again.
//
// watch(flow, onUpdate) gives { stop(), check() }; stop() also aborts a read
// under way.  onUpdate(w) is called with { flow, state, was, error } as they
// change, state being found, checking, gone, invalid or error (no reply or an
// endpoint error; still read every tick), and was the state before a check.
export function flowKeyPoller({ read, maxReads = 4, seconds = 5, timeout = 15, visible = () => true }) {
    const watchers = new Set();
    let ticks = 0;
    let busy = false;
    let timer = null;

    function sync() {
        if (!seconds)
            return;
        if (watchers.size && !timer) {
            timer = setInterval(tick, seconds * 1000);
        } else if (!watchers.size && timer) {
            clearInterval(timer);
            timer = null;
        }
    }

    function set(w, state, extra = {}) {
        if (w.stopped)
            return;
        if (state === 'checking' && w.state !== 'checking')
            w.was = w.state;
        Object.assign(w, { state }, extra);
        w.onUpdate(w);
    }

    // One read of a window's flow; never throws
    async function readOne(w) {
        const ctl = new AbortController();
        w.reading = ctl;
        const limit = setTimeout(() => ctl.abort(), timeout * 1000);
        try {
            const reply = await read(w.key, ctl.signal);
            if (serverFlowKey(reply) !== w.key)
                set(w, 'error', { error: 'the server sent a different flow' });
            else
                set(w, 'found', { flow: reply, error: '' });
        } catch (err) {
            if (err?.status === 404)
                set(w, 'gone', { error: '' });
            else if (err?.status === 400)
                set(w, 'invalid', { error: '' });
            else if (err?.name === 'AbortError' || ctl.signal.aborted)
                set(w, 'error', { error: 'no reply in time' });
            else
                set(w, 'error', { error: err?.message ?? String(err) });
        } finally {
            clearTimeout(limit);
            if (w.reading === ctl)
                w.reading = null;
        }
    }

    async function tick() {
        if (busy || !visible())
            return;
        busy = true;
        ticks++;
        try {
            const due = [...watchers].filter((w) => !w.reading && (w.state === 'found' || w.state === 'error'))
                .sort((x, y) => x.lastTick - y.lastTick).slice(0, maxReads);
            for (const w of due)
                w.lastTick = ticks;
            await Promise.all(due.map(readOne));
        } finally {
            busy = false;
        }
    }

    function watch(flow, onUpdate) {
        const w = { flow, key: serverFlowKey(flow), state: 'found', was: 'found', error: '', stopped: false,
            lastTick: ticks, reading: null, onUpdate };
        if (!w.key)
            w.state = 'invalid';
        watchers.add(w);
        sync();
        // A list row has no history, so a new window reads its flow at once
        if (w.key && visible())
            readOne(w);
        return {
            stop() {
                w.stopped = true;
                w.reading?.abort();
                watchers.delete(w);
                sync();
            },
            // Read it again now, after it was found gone
            check() {
                if (w.stopped || w.reading || w.state === 'checking' || w.state === 'invalid')
                    return;
                set(w, 'checking');
                readOne(w);
            },
        };
    }

    return { watch, tick, get size() { return watchers.size; } };
}
