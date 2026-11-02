// Bluetooth (classic and LE, as seen by HCI and Ubertooth-style sources).

import { serviceLabeler } from './btadv.js';

const base = 'kismet.device.base';

export function register(kismet) {
    const { ui, icons, format } = kismet;
    const serviceLabel = serviceLabeler(kismet);
    const mono = (v) => kismet.dom.el('span', { class: 'mono', style: { wordBreak: 'break-all' } }, String(v));
    const addressTypes = {
        static: 'Static random',
        resolvable: 'Resolvable private (rotating)',
        'non-resolvable': 'Non-resolvable private (rotating)',
        reserved: 'Reserved',
    };
    // Search box names for the Bluetooth details
    ui.filterHints.add({ id: 'bluetooth_services', phy: 'Bluetooth', names: ['services'],
        fields: ['bluetooth.device/bluetooth.device.service_uuid_strs'] });

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

    ui.phyColors.add({ id: 'Bluetooth', title: 'Bluetooth', color: '#a5d8ff' });

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
                format: (v) => kismet.dom.el('div', {}, v.map((uuid) => kismet.dom.el('div', {}, serviceLabel(uuid)))),
                help: 'Service UUIDs the device has advertised, with the service or company each is assigned to when Kismet knows it.' },
            { title: 'Service data', field: `${b}/${b}.service_data_bytes`,
                show: (v) => v !== null && typeof v === 'object' && Object.keys(v).length > 0,
                format: (v) => kismet.dom.el('div', {}, Object.keys(v).sort().map((uuid) =>
                    kismet.dom.el('div', { style: { wordBreak: 'break-all' } }, serviceLabel(uuid), ': ',
                        mono(typeof v[uuid] === 'string' ? v[uuid] || '(empty)' : JSON.stringify(v[uuid]))))),
                help: 'The latest payload the device advertised for each service UUID, in hex.' },
            { title: 'Class of device', field: `${b}/${b}.major_class`, hideEmpty: true,
                format: (v, dev) => {
                    const minor = kismet.api.field(dev, `${b}/${b}.minor_class`);
                    return minor ? `${v}: ${minor}` : v;
                },
                help: 'The kind of device a classic Bluetooth device says it is.' },
            { title: 'Device services', field: `${b}/${b}.service_classes`, show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => v.join(', '),
                help: 'The service classes in its class of device: audio, telephony, networking and so on.' },
            { title: 'Appearance', field: `${b}/${b}.appearance_name`, hideEmpty: true,
                help: 'What the device advertises itself as (its Bluetooth appearance value).' },
            { title: 'Address type', field: `${b}/${b}.random_address_type`, hideEmpty: true,
                format: (v) => addressTypes[v] ?? v,
                help: 'For a random address: static addresses last until the device is reset; resolvable and non-resolvable private addresses change every few minutes.' },
            { title: 'Partial address', field: `${b}/${b}.partial_address`, hideEmpty: true, format: mono,
                help: 'The part of the address known from the piconet\'s access code; ?? marks the unknown parts.' },
            { title: 'Manufacturer data', field: `${b}/${b}.manuf_data`, hideEmpty: true, format: mono,
                help: 'The rest of the most recent manufacturer data, in hex.' },
            { title: 'Bluetooth version', field: `${b}/${b}.lmp_version`,
                help: 'The Bluetooth version the device\'s controller reported when a host connected to it.' },
            { title: 'Chip maker', field: `${b}/${b}.chip_manufacturer`,
                help: 'Maker of the device\'s controller chip, from its Bluetooth company ID.' },
            { title: 'Chip firmware', field: `${b}/${b}.lmp_subversion`, hideZero: true,
                help: 'The controller\'s firmware subversion, chosen by the chip maker.' },
            { title: 'LMP features', field: `${b}/${b}.lmp_features`, hideEmpty: true, format: mono,
                help: 'Classic feature mask read from the device by active probing.' },
            { title: 'LE features', field: `${b}/${b}.le_features`, hideEmpty: true, format: mono,
                help: 'LE feature mask read from the device by active probing.' },
            { title: 'Last probed', field: `${b}/${b}.last_probed`, hideZero: true, format: format.time,
                help: 'Last time a source\'s opt-in active probing connected to this device.' },
        ],
    });
}
