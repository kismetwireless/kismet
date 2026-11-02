// IEEE 802.15.4: Zigbee, Thread, and other 6LoWPAN networks.

const base = 'kismet.device.base';
const d = '802154.device';

const hex = (digits) => (v) => `0x${v.toString(16).padStart(digits, '0')}`;

const threadVersions = { 1: 'Thread 1.0', 2: 'Thread 1.1', 3: 'Thread 1.2', 4: 'Thread 1.3', 5: 'Thread 1.4' };
const threadJoining = { 1: 'No', 2: 'Devices its commissioner lists', 3: 'Any device' };
const threadDiscovery = { 1: 'Looking for Thread networks', 2: 'Looking for a network to join' };

export function register(kismet) {
    const { ui, icons } = kismet;
    // Search box names for the 802.15.4 details
    const filterHint = (id, names, path, more = {}) =>
        ui.filterHints.add({ id, phy: '802.15.4', names, fields: [`${d}/${d}.${path}`], ...more });
    filterHint('802154_pan_id', ['pan_id', 'pan'], 'pan_id', { filterKind: 'number' });
    filterHint('802154_short_addr', ['short_addr'], 'short_addr', { filterKind: 'number' });
    filterHint('802154_ext_pan_id', ['ext_pan_id'], 'ext_pan_id', { filterEmpty: '' });
    filterHint('802154_network_name', ['network_name'], 'network_name', { filterEmpty: '' });
    filterHint('802154_role', ['role'], 'role', { filterEmpty: '' });
    filterHint('802154_thread_version', ['thread_version'], 'thread_version', { filterKind: 'number', filterEmpty: 0 });
    // 1 no, 2 listed devices, 3 any: "joining > 1" finds the open networks
    filterHint('802154_thread_joining', ['joining', 'thread_joining'], 'thread_joining', { filterKind: 'number', filterEmpty: 0 });

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
                help: 'From its beacons: the PAN coordinator, or a router (Zigbee routers send beacons).' },
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
        ],
    });
}
