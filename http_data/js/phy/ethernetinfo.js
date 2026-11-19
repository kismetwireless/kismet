// Text for the Ethernet (IEEE802.3) phy's fields: VLAN labels, protocol and
// role bits, flow endpoints, TCP flags, the status counters worth a warning,
// and checks for the Ethernet flows window's filters.  No DOM, so it can be tested on
// its own; js/phy/ethernet.js draws with it.

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
