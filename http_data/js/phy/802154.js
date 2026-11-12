// IEEE 802.15.4: Zigbee, Thread, and other 6LoWPAN networks.

const base = 'kismet.device.base';
const d = '802154.device';

const hex = (digits) => (v) => `0x${v.toString(16).padStart(digits, '0')}`;

const threadVersions = { 1: 'Thread 1.0', 2: 'Thread 1.1', 3: 'Thread 1.2', 4: 'Thread 1.3', 5: 'Thread 1.4' };
const threadJoining = { 1: 'No', 2: 'Devices its commissioner lists', 3: 'Any device' };
const threadDiscovery = { 1: 'Looking for Thread networks', 2: 'Looking for a network to join' };

export function register(kismet) {
    const { ui, format, icons } = kismet;
    // Search box names for the 802.15.4 details
    const filterHint = (id, names, path, more = {}) =>
        ui.filterHints.add({ id, phy: '802.15.4', names, fields: [`${d}/${d}.${path}`], ...more });
    filterHint('802154_pan_id', ['pan_id', 'pan'], 'pan_id', { filterKind: 'number', help: 'PAN ID of the 802.15.4 network' });
    filterHint('802154_short_addr', ['short_addr'], 'short_addr', { filterKind: 'number', help: '16-bit short address' });
    filterHint('802154_ext_pan_id', ['ext_pan_id'], 'ext_pan_id', { filterEmpty: '', help: 'Thread extended PAN ID' });
    filterHint('802154_network_name', ['network_name'], 'network_name', { filterEmpty: '', help: 'Thread network name' });
    filterHint('802154_role', ['role'], 'role', { filterEmpty: '', help: 'Thread role, such as router or end device' });
    filterHint('802154_thread_version', ['thread_version'], 'thread_version', { filterKind: 'number', filterEmpty: 0, help: 'Thread version' });
    // 1 no, 2 listed devices, 3 any: "joining > 1" finds the open networks
    filterHint('802154_thread_router_id', ['router_id', 'thread_router_id'], 'thread_router_id', { filterKind: 'number', help: 'Thread router ID' });
    filterHint('802154_thread_child_id', ['child_id', 'thread_child_id'], 'thread_child_id', { filterKind: 'number', help: 'Thread child ID' });
    filterHint('802154_thread_children', ['children', 'thread_children'], 'thread_children', { filterKind: 'number',
        help: 'Number of a Thread router\'s children' });
    filterHint('802154_thread_polls', ['polls', 'thread_polls'], 'thread_polls', { filterKind: 'number', filterEmpty: 0,
        help: 'Data polls sent by a sleepy end device' });
    // "poll_interval > 30s"
    filterHint('802154_thread_poll_interval', ['poll_interval'], 'thread_poll_interval',
        { filterKind: 'duration', filterConvert: ui.durationIn.ms, filterEmpty: 0, help: 'Time between a sleepy end device\'s polls' });
    filterHint('802154_thread_joining', ['joining', 'thread_joining'], 'thread_joining', { filterKind: 'number', filterEmpty: 0,
        help: 'Joining: 1 closed, 2 listed devices, 3 anyone; joining > 1 finds open networks' });

    const is802154 = (row) => row[`${base}.phyname`] === '802.15.4';

    ui.deviceIcons.add({
        id: '802154', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (is802154(row) ? icons.icon('zigbee', '802.15.4') : null),
    });

    ui.mapSources.add({
        id: '802154', title: '802.15.4 / Zigbee', priority: 73, icon: 'zigbee', view: 'phy-802.15.4', position: 'average',
        defaultVisible: false,
        color: () => 'hsl(50 85% 48%)',
    });

    ui.phyColors.add({ id: '802.15.4', title: '802.15.4/Zigbee', color: '#b2f2bb' });

    // The 802.15.4 channel plan: 0 at 868.3 MHz, 1-10 every 2 MHz from 906,
    // 11-26 every 5 MHz from 2405
    const channelFrequency = (channel) => {
        if (!/^\d{1,2}$/.test(String(channel ?? '').trim()))
            return null;
        const n = Number(channel);
        if (n > 26)
            return null;
        return n === 0 ? 868300 : n <= 10 ? 906000 + (n - 1) * 2000 : 2405000 + (n - 11) * 5000;
    };
    const channelName = (khz) => {
        if (khz === 868300)
            return '0';
        if (khz >= 906000 && khz <= 924000 && (khz - 906000) % 2000 === 0)
            return String((khz - 906000) / 2000 + 1);
        if (khz >= 2405000 && khz <= 2480000 && (khz - 2405000) % 5000 === 0)
            return String((khz - 2405000) / 5000 + 11);
        return null;
    };

    ui.channelNames.add({ id: '802.15.4', title: '802.15.4', priority: 20, name: channelName, frequency: channelFrequency });
    // Ahead of Bluetooth LE, which also claims 'nrf' sources; the KW41Z hops
    // the BLE advertising channels as well as 802.15.4's
    const bleAdvertising = { 37: 2402000, 38: 2426000, 39: 2480000 };
    ui.sourceChannels.add({
        id: '802154', priority: -10,
        title: (channel) => (bleAdvertising[Number(channel)] ? 'BLE' : '802.15.4'),
        match: (src) => /^(ticc2531|nrf52840|rzkillerbee|catsniffer_zigbee|freaklabszigbee|nxp_kw41z|zigbee900sdr)$/i
            .test(src['kismet.datasource.driver.type'] ?? ''),
        frequency: (channel) => channelFrequency(channel) ?? bleAdvertising[Number(channel)] ?? null,
    });

    ui.deviceColumns.add({
        id: '802154_network', title: '802.15.4 network', priority: 110, group: '802.15.4', width: '8em',
        description: 'Zigbee, Zigbee Green Power, Thread, or 6LoWPAN',
        fields: [[`${d}/${d}.network_type`, 'network_type']],
        sortField: `${d}/${d}.network_type`,
        filterKind: 'text',
        render: (row) => row.network_type || '',
    });

    // PAN IDs and short addresses of 0xffff mean "not known"
    const hexOrUnknown = (digits) => (v) => (v === 0xffff ? ui.muted('Unknown') : hex(digits)(v));

    ui.deviceDetails.add({
        id: '802154', title: '802.15.4', priority: 5,
        match: (device) => device[`${base}.phyname`] === '802.15.4' && d in device,
        fields: [
            { title: 'Network', field: `${d}/${d}.network_type`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'What the frames carry: a Zigbee network header or beacon, Zigbee Green Power, Thread (its beacon, MLE over 6LoWPAN, or a PAN that Thread traffic has shown to be a Thread network), or other 6LoWPAN traffic.' },
            { title: 'Role', field: `${d}/${d}.role`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'From its beacons: the PAN coordinator, or a router (Zigbee routers send beacons).  In a Thread network, from its short address: a router or an end device.  An end device that polls its router for traffic held for it is a sleepy end device, and one that wakes on a schedule it announces (CSL) is a synchronized sleepy end device.' },
            { title: 'PAN ID', field: `${d}/${d}.pan_id`, format: hexOrUnknown(4) },
            { title: 'Short address', field: `${d}/${d}.short_addr`, format: hexOrUnknown(4) },
            { title: 'IEEE address', field: `${d}/${d}.ieee_addr`, show: (v) => v !== '00:00:00:00:00:00',
                format: (v) => kismet.dom.el('span', { class: 'mono' }, v),
                help: 'The 64-bit address (EUI-64) a Zigbee network header gave for this short address.' },
            { title: 'GPD source ID', field: `${d}/${d}.gpd_srcid`, hideZero: true, format: hex(8),
                help: 'The Zigbee Green Power source ID that names this device.  It has no MAC address of its own, so Kismet tracks it under an address made from this ID.' },
            { title: 'Extended PAN ID', field: `${d}/${d}.ext_pan_id`, hideEmpty: true, empty: ui.muted('Unknown') },
            { title: 'Network name', field: `${d}/${d}.network_name`, hideEmpty: true },
            { title: 'Zigbee stack profile', field: `${d}/${d}.stack_profile`, hideZero: true,
                format: (v) => ({ 1: 'Zigbee', 2: 'Zigbee PRO' }[v] ?? `Profile ${v}`) },
            { title: 'Thread version', field: `${d}/${d}.thread_version`, hideZero: true,
                format: (v) => threadVersions[v] ?? `Version ${v}`,
                help: 'The Thread version its Discovery Response or beacon gives for its network, or its own in a discovery request.' },
            { title: 'Accepting new devices', field: `${d}/${d}.thread_joining`, hideZero: true,
                format: (v) => threadJoining[v] ?? String(v),
                help: 'Whether its Thread network lets new devices join, from a router\'s Discovery Response or beacon: any device with the network\'s joining credential, only the devices its commissioner lists, or none.  Matter devices usually join through Bluetooth instead, so a Matter network can show "No" while devices are being added.' },
            { title: 'Native commissioner', field: `${d}/${d}.thread_native`,
                format: (v) => (v ? 'Allowed' : 'Not allowed'),
                help: 'Whether its Thread network lets a commissioner on the Thread network itself (rather than through a border router) add devices.' },
            { title: 'Joiner port', field: `${d}/${d}.thread_joiner_port`, hideZero: true,
                help: 'The UDP port devices joining its Thread network use to reach this router.' },
            { title: 'Thread discovery', field: `${d}/${d}.thread_discovery`, hideZero: true,
                format: (v) => threadDiscovery[v] ?? String(v),
                help: 'From its Thread discovery requests: a device looking for a network to join, or one looking for networks (a commissioner, border router or phone app).' },
            { title: 'Thread router ID', field: `${d}/${d}.thread_router_id`,
                help: 'A Thread short address (RLOC16) holds a router ID (0-62) in its top six bits and, for an end device, the child ID its router gave it in the low bits.  For an end device this is the ID of its parent router.' },
            { title: 'Thread child ID', field: `${d}/${d}.thread_child_id`, hideZero: true },
            { title: 'Parent router', field: `${d}/${d}.thread_parent`, show: (v) => v && v !== '0' && v !== '00_0',
                format: (v, rec) => {
                    const router = rec[d]?.[`${d}.thread_router_id`] ?? 0;
                    return kismet.dom.el('a', { href: '#', onclick: (e) => { e.preventDefault(); ui.openDevice(v); } },
                        `Router ${router} (${hex(4)(router << 10)})`);
                },
                help: 'The router this end device is attached to, from its short address.' },
            { title: 'Children', field: `${d}/${d}.thread_children`, show: (v, rec) => rec[d]?.[`${d}.thread_child_id`] === 0,
                format: (v) => `${v} seen in the last hour`,
                help: 'End devices of this router (short addresses with its router ID) seen in the last hour.' },
            { title: 'Routers in its network', field: `${d}/${d}.thread_routers`, hideZero: true,
                help: 'Routers of its Thread network seen in the last hour.' },
            { title: 'Data polls', field: `${d}/${d}.thread_polls`, hideZero: true,
                format: (v, rec) => {
                    const ms = rec[d]?.[`${d}.thread_poll_interval`] ?? 0;
                    const sec = Math.round(ms / 1000);
                    return ms ? `${v}, about every ${sec < 60 ? `${sec}s` : format.duration(sec)}` : String(v);
                },
                help: 'MAC Data Requests: a sleepy end device asking its router for traffic held for it.  The interval averages the gaps between its recent polls.' },
            { title: 'CSL period', field: `${d}/${d}.thread_csl_period`, hideZero: true,
                format: (v) => `${Math.round(v * 0.16)} ms`,
                help: 'How often a synchronized sleepy end device (Thread 1.2 and later) wakes to listen, from the CSL header in its frames.' },
            { title: 'MAC key index', field: `${d}/${d}.thread_key_index`,
                help: 'The key index in its secured frames.  Thread derives a new MAC key each time the network key sequence advances, and the index follows it.' },
            { title: 'Key sequence', field: `${d}/${d}.thread_key_seq`,
                help: 'The network key sequence from its secured MLE messages.  It advances when the network rotates its keys.' },
        ],
    });
}
