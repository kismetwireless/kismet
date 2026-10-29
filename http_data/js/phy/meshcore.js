// MeshCore LoRa mesh nodes.

const base = 'kismet.device.base';
const n = 'meshcore.node';

// Advert node types, from the MeshCore firmware's ADV_TYPE_* values
const nodeTypes = {
    0: 'None',
    1: 'Companion',
    2: 'Repeater',
    3: 'Room server',
    4: 'Sensor',
};

export function register(kismet) {
    const { ui, icons, format, dom } = kismet;
    const isMeshcore = (row) => row[`${base}.phyname`] === 'MeshCore';

    // The same picture as Meshtastic's; whichever module loads first defines it
    if (!icons.has('mesh'))
        icons.define('mesh', '<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="17" r="2.2"/><circle cx="19" cy="17" r="2.2"/><path d="M10.9 6.9L6.1 15M13.1 6.9l4.8 8.1M7.2 17h9.6"/>');

    ui.deviceIcons.add({
        id: 'meshcore', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isMeshcore(row) ? icons.icon('mesh', 'MeshCore node') : null),
    });

    // Nodes that put a location in their adverts
    ui.mapSources.add({
        id: 'meshcore', title: 'MeshCore nodes', priority: 31, icon: 'mesh', view: 'phy-MeshCore', maxAge: 3600,
        fields: [[`${n}/${n}.name`, 'mc_name'], [`${n}/${n}.type`, 'mc_type']],
        label: (d) => String(d.mc_name ?? '').trim() || d.name,
        detail: (d) => nodeTypes[d.mc_type] ?? '',
        color: () => 'var(--accent)',
    });

    ui.rowHighlights.add({
        id: 'meshcore_all', name: 'MeshCore node', priority: 100,
        description: 'MeshCore LoRa mesh nodes',
        defaultColor: '#d2e4f7', defaultEnabled: true,
        fields: [`${base}.phyname`],
        match: isMeshcore,
    });

    const count = (v) => v.toLocaleString();

    ui.deviceDetails.add({
        id: 'meshcore', title: 'MeshCore', priority: 5,
        match: (device) => n in device,
        fields: [
            { title: 'Name', field: `${n}/${n}.name`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'The node name from its most recent signed advert.' },
            { title: 'Node type', field: `${n}/${n}.type`, format: (v) => nodeTypes[v] ?? `Unknown (${v})`,
                help: 'What the node says it is: repeaters relay messages for other nodes, and room servers host shared message boards.' },
            { title: 'Public key', field: `${n}/${n}.pubkey`,
                format: (v, rec) => dom.el('span', {}, `${rec[`${n}.key_type`] ?? ''} `,
                    dom.el('span', { class: 'mono', style: { wordBreak: 'break-all' } }, v)),
                help: 'The public key that identifies the node, in base64.  Other packets refer to nodes by the first byte or bytes of this key.' },
            { title: 'Advertised location', field: `${n}/${n}.lat`, hideZero: true,
                format: (lat, rec) => `${lat.toFixed(6)}, ${(rec[`${n}.lon`] ?? 0).toFixed(6)}`,
                help: 'The location the node puts in its adverts, if any.' },
            { title: 'Adverts', field: `${n}/${n}.adverts`, format: count,
                help: 'Adverts with valid signatures seen from this node, including copies relayed by other nodes.' },
            { title: 'Last advert time', field: `${n}/${n}.advert_ts`, hideZero: true, format: format.time,
                help: 'The time from the node\'s own clock in its last advert, which may be wrong.' },
            { title: 'Advert hops', field: `${n}/${n}.advert_hops`,
                help: 'How many repeaters the most recent advert passed through on its way here.' },
            { title: 'Packets relayed', field: `${n}/${n}.relayed`, hideZero: true, format: count,
                help: 'Packets this node was seen repeating for other nodes.' },
            { title: 'Last relayed', field: `${n}/${n}.last_relayed`, hideZero: true, format: format.time },
            { title: 'Invalid adverts', field: `${n}/${n}.bad_signatures`, hideZero: true, format: count,
                help: 'Adverts using this node\'s key that failed signature checks; these may be forged.' },
        ],
    });
}
