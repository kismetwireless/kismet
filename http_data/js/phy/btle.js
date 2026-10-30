// Bluetooth LE advertisements captured by BTLE radios (nRF, TI, CatSniffer...).

import { registerTrackers } from './btle_trackers.js';

const base = 'kismet.device.base';
const b = 'btle.device';

// Advertising packet (PDU) types
const pduTypes = {
    0x0: 'ADV_IND (connectable)',
    0x1: 'ADV_DIRECT_IND',
    0x2: 'ADV_NONCONN_IND (not connectable)',
    0x3: 'SCAN_REQ',
    0x4: 'SCAN_RSP',
    0x5: 'CONNECT_REQ',
    0x6: 'ADV_SCAN_IND (scannable)',
    0x7: 'ADV_EXT_IND',
};

export function register(kismet) {
    const { ui, icons, format } = kismet;
    const isBtle = (row) => row[`${base}.phyname`] === 'BTLE';
    const supported = (v) => (v ? 'Supported' : 'Not supported');

    // BLE channels: 37, 38, and 39 advertise; 0-36 carry connections
    const bleFrequency = (channel) => {
        const n = Number(channel);
        if (!Number.isInteger(n) || n < 0 || n > 39)
            return null;
        const mhz = n === 37 ? 2402 : n === 38 ? 2426 : n === 39 ? 2480 : (n <= 10 ? 2404 + n * 2 : 2428 + (n - 11) * 2);
        return mhz * 1000;
    };
    const bleChannel = (khz) => {
        const mhz = khz / 1000;
        if (mhz === 2402)
            return '37';
        if (mhz === 2426)
            return '38';
        if (mhz === 2480)
            return '39';
        if (Number.isInteger(mhz) && mhz % 2 === 0 && mhz >= 2404 && mhz <= 2478)
            return String(mhz < 2426 ? (mhz - 2404) / 2 : (mhz - 2428) / 2 + 11);
        return null;
    };

    registerTrackers(kismet);

    ui.channelNames.add({ id: 'BTLE', title: 'BLE', priority: 10, name: bleChannel, frequency: bleFrequency });
    ui.sourceChannels.add({
        id: 'btle',
        match: (src) => /nrf|cc2540|sniffle|ble|wch/i.test(src['kismet.datasource.driver.type'] ?? ''),
        frequency: bleFrequency,
    });

    ui.deviceIcons.add({
        id: 'btle', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isBtle(row) ? icons.icon('bluetooth', 'Bluetooth LE') : null),
    });

    ui.mapSources.add({
        id: 'btle', title: 'Bluetooth LE', priority: 61, icon: 'bluetooth', view: 'phy-BTLE', position: 'average',
        defaultVisible: false,
        color: () => 'hsl(185 65% 50%)',
    });

    ui.phyColors.add({ id: 'BTLE', title: 'BTLE', color: '#99e9f2' });

    ui.deviceDetails.add({
        id: 'btle', title: 'Bluetooth LE', priority: 5,
        match: (device) => device[`${base}.phyname`] === 'BTLE' && b in device,
        fields: [
            {
                title: 'Discovery',
                value: (dev) => {
                    const modes = [];
                    if (kismet.api.field(dev, `${b}/${b}.le_limited_discoverable`))
                        modes.push('Limited');
                    if (kismet.api.field(dev, `${b}/${b}.le_general_discoverable`))
                        modes.push('General');
                    return modes.length ? modes.join(', ') : null;
                },
                empty: ui.muted('Unknown'),
                help: 'Devices in limited discovery can only be found for about 30 seconds at a time; devices in general discovery can be found any time.',
            },
            { title: 'BR/EDR mode', field: `${b}/${b}.br_edr_unsupported`, format: (v) => (v ? 'Not supported' : 'Supported'),
                help: 'Whether the device also supports classic Bluetooth (BR/EDR).' },
            { title: 'BR/EDR controller', field: `${b}/${b}.simultaneous_br_edr_controller`, format: supported,
                help: 'The device can use classic Bluetooth (BR/EDR) as a controller at the same time.' },
            { title: 'BR/EDR host', field: `${b}/${b}.simultaneous_br_edr_host`, format: supported,
                help: 'The device can use classic Bluetooth (BR/EDR) as a host at the same time.' },
            { title: 'PDU type', field: `${b}/${b}.pdu_type`, format: (v) => pduTypes[v] ?? `Unknown (${v})`,
                help: 'The kind of advertising packet, which says whether the device accepts connections.' },
            { title: 'Manufacturer ID', field: `${b}/${b}.manuf_company_id`, hideZero: true,
                format: (v) => `0x${v.toString(16).padStart(4, '0')}`,
                help: 'The Bluetooth SIG company ID in the device\'s manufacturer data.' },
            { title: 'Bluetooth version', field: `${b}/${b}.lmp_version`,
                help: 'The Bluetooth version the device\'s controller reported when a host connected to it.' },
            { title: 'Chip maker', field: `${b}/${b}.chip_manufacturer`,
                help: 'Maker of the device\'s controller chip, from its Bluetooth company ID.' },
            { title: 'Chip firmware', field: `${b}/${b}.lmp_subversion`, hideZero: true,
                help: 'The controller\'s firmware subversion, chosen by the chip maker.' },
            { title: 'LE features', field: `${b}/${b}.le_features`,
                help: 'LE feature mask read from the device by active probing.' },
            { title: 'Last probed', field: `${b}/${b}.last_probed`, hideZero: true, format: format.time,
                help: 'Last time a source\'s opt-in active probing connected to this device.' },
        ],
    });
}
