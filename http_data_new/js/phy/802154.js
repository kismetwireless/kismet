// IEEE 802.15.4: Zigbee, Thread, and other 6LoWPAN networks.

const base = 'kismet.device.base';
const d = '802154.device';

const hex = (digits) => (v) => `0x${v.toString(16).padStart(digits, '0')}`;

export function register(kismet) {
    const { ui, icons } = kismet;
    const is802154 = (row) => row[`${base}.phyname`] === '802.15.4';

    ui.deviceIcons.add({
        id: '802154', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (is802154(row) ? icons.icon('zigbee', '802.15.4') : null),
    });

    ui.rowHighlights.add({
        id: '802154_all', name: '802.15.4/Zigbee device', priority: 100,
        description: 'Every 802.15.4 device',
        defaultColor: '#b2f2bb',
        fields: [`${base}.phyname`],
        match: is802154,
    });

    ui.deviceColumns.add({
        id: '802154_network', title: '802.15.4 network', priority: 110, group: '802.15.4', width: '8em',
        description: 'Zigbee, Zigbee Green Power, Thread, or 6LoWPAN',
        fields: [[`${d}/${d}.network_type`, 'network_type']],
        sortField: `${d}/${d}.network_type`,
        render: (row) => row.network_type || '',
    });

    // PAN IDs and short addresses of 0xffff mean "not known"
    const hexOrUnknown = (digits) => (v) => (v === 0xffff ? ui.muted('Unknown') : hex(digits)(v));

    ui.deviceDetails.add({
        id: '802154', title: '802.15.4', priority: 5,
        match: (device) => device[`${base}.phyname`] === '802.15.4' && d in device,
        fields: [
            { title: 'Network', field: `${d}/${d}.network_type`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'What the frames carry: a Zigbee network header or beacon, Zigbee Green Power, Thread (its beacon, or MLE over 6LoWPAN), or other 6LoWPAN traffic.' },
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
        ],
    });
}
