// Meshtastic LoRa mesh nodes.

const base = 'kismet.device.base';
const n = 'meshtastic.node';

// Config.DeviceConfig.Role values
const roles = {
    0: 'Client',
    1: 'Client (mute)',
    2: 'Router',
    3: 'Router/client',
    4: 'Repeater',
    5: 'Tracker',
    6: 'Sensor',
    7: 'TAK',
    8: 'Client (hidden)',
    9: 'Lost and found',
    10: 'TAK tracker',
    11: 'Router (late)',
    12: 'Client (base)',
};

const telemetryFields = ['battery', 'voltage', 'chan_util', 'chan_tx_util', 'uptime'];

export function register(kismet) {
    const { ui, icons, format, api } = kismet;
    const isMeshtastic = (row) => row[`${base}.phyname`] === 'Meshtastic';

    icons.define('mesh', '<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="17" r="2.2"/><circle cx="19" cy="17" r="2.2"/><path d="M10.9 6.9L6.1 15M13.1 6.9l4.8 8.1M7.2 17h9.6"/>');

    ui.deviceIcons.add({
        id: 'meshtastic', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isMeshtastic(row) ? icons.icon('mesh', 'Meshtastic node') : null),
    });

    // Nodes that share their position.  Meshtastic packets are relayed, so
    // there's no point to say where Kismet heard a node.
    ui.mapSources.add({
        id: 'meshtastic', title: 'Meshtastic nodes', priority: 30, icon: 'mesh', view: 'phy-Meshtastic', maxAge: 3600,
        fields: [[`${n}/${n}.longname`, 'longname'], [`${n}/${n}.shortname`, 'shortname']],
        label: (d) => String(d.longname ?? '').trim() || String(d.shortname ?? '').trim() || d.name,
        detail: (d) => (d.rep_alt ? format.height(d.rep_alt) : ''),
        color: () => 'var(--accent)',
    });

    ui.rowHighlights.add({
        id: 'meshtastic_all', name: 'Meshtastic node', priority: 100,
        description: 'Meshtastic LoRa mesh nodes',
        defaultColor: '#c8f7d2', defaultEnabled: true,
        fields: [`${base}.phyname`],
        match: isMeshtastic,
    });

    const percent = (v) => `${v.toFixed(1)}%`;

    ui.deviceDetails.add({
        id: 'meshtastic', title: 'Meshtastic', priority: 5,
        match: (device) => n in device,
        fields: [
            { title: 'Node ID', field: `${n}/${n}.nodeid`, empty: ui.muted('Unknown'),
                help: 'The Meshtastic node number, which comes from the radio\'s hardware ID.' },
            { title: 'Long name', field: `${n}/${n}.longname`, hideEmpty: true,
                help: 'The node\'s name, as its owner set it and as it advertises it.' },
            { title: 'Short name', field: `${n}/${n}.shortname`, hideEmpty: true,
                help: 'The short name shown on device screens and in the Meshtastic apps.' },
            { title: 'Role', field: `${n}/${n}.role`, format: (v) => roles[v] ?? `Unknown (${v})`,
                help: 'What the node is set up to do; routers and repeaters relay messages for other nodes.' },
            { title: 'Hardware model', field: `${n}/${n}.manuf`, hideZero: true,
                format: (v, _r, dev) => `${dev[`${base}.manuf`]} (${v})`,
                help: 'The hardware model the node advertises, and Meshtastic\'s number for it.' },
            { title: 'Licensed operator', field: `${n}/${n}.licensed`, format: (v) => (v ? 'Yes' : 'No'),
                help: 'Licensed amateur radio operators run without encryption, as many countries require.' },
            {
                group: 'Telemetry',
                // Shown once the node has reported any telemetry
                show: (dev) => telemetryFields.some((f) => api.field(dev, `${n}/${n}.telem.${f}`, 0) > 0),
                fields: [
                    { title: 'Battery', field: `${n}/${n}.telem.battery`, hideZero: true,
                        format: (v) => (v > 100 ? 'External power' : `${v}%`),
                        help: 'The battery level the node reports; over 100% means it\'s on external power.' },
                    { title: 'Voltage', field: `${n}/${n}.telem.voltage`, hideZero: true, format: (v) => `${v.toFixed(2)} V` },
                    { title: 'Channel use', field: `${n}/${n}.telem.chan_util`, hideZero: true, format: percent,
                        help: 'How much of the channel\'s airtime is in use, as the node hears it, including other nodes.' },
                    { title: 'Transmit use', field: `${n}/${n}.telem.chan_tx_util`, hideZero: true, format: percent,
                        help: 'How much airtime the node itself spent transmitting.' },
                    { title: 'Uptime', field: `${n}/${n}.telem.uptime`, hideZero: true, format: format.duration },
                    { title: 'Reported', field: `${n}/${n}.telem.timestamp`, hideZero: true, format: format.time,
                        help: 'The time the node put on its telemetry report, from its own clock.' },
                ],
            },
        ],
    });
}
