// Z-Wave home automation devices, from KillerZee captures.

const base = 'kismet.device.base';
const z = 'zwave.device';

export function register(kismet) {
    const { ui } = kismet;
    const hex = (v) => v.toString(16);

    ui.mapSources.add({
        id: 'zwave', title: 'Z-Wave', priority: 72, icon: 'radio', view: 'phy-Z-Wave', position: 'average',
        defaultVisible: false,
        color: () => 'hsl(30 80% 55%)',
    });

    ui.phyColors.add({ id: 'Z-Wave', title: 'Z-Wave', color: '#ffe6b3', enabled: true });

    ui.deviceDetails.add({
        id: 'zwave', title: 'Z-Wave', priority: 5,
        match: (device) => device[`${base}.phyname`] === 'Z-Wave',
        fields: [
            { title: 'Home ID', field: `${z}/${z}.home_id`, format: hex, empty: ui.muted('Unknown'),
                help: 'The network the device belongs to; every device in one home shares it.' },
            { title: 'Device ID', field: `${z}/${z}.device_id`, format: hex, empty: ui.muted('Unknown'),
                help: 'The device\'s node number within its home network.' },
        ],
    });
}
