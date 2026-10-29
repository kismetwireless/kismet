// Bluetooth (classic and LE, as seen by HCI and Ubertooth-style sources).

const base = 'kismet.device.base';

export function register(kismet) {
    const { ui, icons } = kismet;
    const isBluetooth = (row) => row[`${base}.phyname`] === 'Bluetooth';

    ui.deviceIcons.add({
        id: 'bluetooth', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isBluetooth(row) ? icons.icon('bluetooth', 'Bluetooth') : null),
    });

    ui.mapSources.add({
        id: 'bluetooth', title: 'Bluetooth', priority: 60, icon: 'bluetooth', view: 'phy-Bluetooth', position: 'average',
        defaultVisible: false,
        detail: (d) => d.type,
        color: () => 'hsl(260 70% 65%)',
    });

    ui.rowHighlights.add({
        id: 'bluetooth_all', name: 'Bluetooth device', priority: 100,
        description: 'Every Bluetooth device',
        defaultColor: '#a5d8ff',
        fields: [`${base}.phyname`],
        match: isBluetooth,
    });

    ui.rowHighlights.add({
        id: 'bluetooth_bredr', name: 'Bluetooth BR/EDR device', priority: 101,
        description: 'Classic (BR/EDR) Bluetooth devices',
        defaultColor: '#d0bfff',
        fields: [`${base}.type`],
        match: (row) => row[`${base}.type`] === 'BR/EDR',
    });

    ui.rowHighlights.add({
        id: 'bluetooth_ble', name: 'Bluetooth BLE device', priority: 103,
        description: 'Bluetooth Low Energy devices',
        defaultColor: '#b3d9ff',
        fields: [`${base}.type`],
        match: (row) => row[`${base}.type`] === 'BTLE',
    });

    const b = 'bluetooth.device';
    ui.deviceDetails.add({
        id: 'bluetooth', title: 'Bluetooth', priority: 5,
        match: (device) => device[`${base}.phyname`] === 'Bluetooth' && b in device,
        fields: [
            { title: 'Type', field: `${b}/${b}.type` },
            { title: 'Connectable', field: `${b}/${b}.connectable`, format: (v) => (v ? 'Yes' : 'No') },
            { title: 'TX power', field: `${b}/${b}.txpower`, hideZero: true, format: (v) => `${v} dBm`,
                help: 'The transmit power the device advertises.' },
            { title: 'Path loss', field: `${b}/${b}.pathloss`, hideZero: true, format: (v) => `${v} dB`,
                help: 'How much signal is lost between the device and the radio: its advertised power minus the signal received.' },
            { title: 'Services', field: `${b}/${b}.service_uuid_strs`, show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => v.join(', ') },
        ],
    });
}
