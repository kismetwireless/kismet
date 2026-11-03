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
        // "BTLE", "BTLE Tracker", and the like
        match: (row) => String(row[`${base}.type`] ?? '').startsWith('BTLE'),
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

    registerProbeSection(kismet);
}

// Scanning and active probing on Linux HCI sources: scan=, probe= and
// probe_interval= sent at runtime through set_channel, read back from what
// the helper reports
const ds = 'kismet.datasource';
const lbt = `${ds}.linuxbt`;
const probeModes = {
    off: 'Off',
    name: 'Names: ask classic devices for their names',
    info: 'Info: names, and connect to read version and features',
};
const probeNotes = {
    name: 'The source transmits name requests to classic (BR/EDR) devices it hears.',
    info: 'The source transmits: it asks classic devices for their names, and connects to devices to read their ' +
        'Bluetooth version, chip maker and features.  Devices may log or show the connection.',
};
const scanModes = {
    both: 'LE and classic (BR/EDR)',
    le: 'LE only',
    bredr: 'Classic (BR/EDR) only',
};
const intervalMin = 60;
const intervalMax = 86400;

function registerProbeSection(kismet) {
    const { ui, dom, format, datasources: sources } = kismet;
    const { el, replace } = dom;
    const { confirm } = kismet.widgets.dialog;
    const hint = (text) => el('div', { class: 'ds-hint' }, text);
    const reported = (s) => (s[`${lbt}.probe`] ?? '') !== '';

    async function setMode(ctx, s, want) {
        if (want !== 'off' && !await confirm({ title: `Turn on active probing (${want})?`,
            text: `${probeNotes[want]}\n\nThis lasts until the source re-opens or Kismet restarts; to keep it, add ` +
                `probe=${want} to the source= line.`, ok: 'Turn on' }))
            return;
        ctx.busy(sources.setting(s[`${ds}.uuid`], `probe=${want}`), 'Changing probing...');
    }

    // A select and Apply, built once; the select follows the reported value
    // unless the user has picked something they haven't applied
    function chooser(cell, state, { options, current, note, onApply }) {
        if (!state.select) {
            state.select = el('select', { onchange: () => { state.touched = true; } },
                ...Object.entries(options).map(([value, label]) => el('option', { value }, label)));
            state.button = el('button', { type: 'button', onclick: () => {
                state.touched = false;
                if (state.select.value !== state.current)
                    state.onApply(state.select.value);
            } }, 'Apply');
            replace(cell, el('span', { class: 'ds-buttons' }, state.select, state.button), note ? hint(note) : null);
        }
        state.current = current;
        state.onApply = onApply;
        if (!state.touched && document.activeElement !== state.select && current)
            state.select.value = current;
    }

    const scanReported = (s) => (s[`${lbt}.scan`] ?? '') !== '';

    ui.sourceSections.add({
        id: 'btscan', title: 'Scanning', priority: 4, drivers: ['linuxbluetooth'], running: true,
        when: (s) => scanReported(s),
        fields: [
            { id: 'scan', title: 'Scan for', draw: (cell, v, s, state, ctx) => chooser(cell, state, {
                options: scanModes, current: s[`${lbt}.scan`],
                onApply: (want) => ctx.busy(sources.setting(s[`${ds}.uuid`], `scan=${want}`), 'Changing the scan...'),
            }), help: 'Which advertisements the controller listens for.  Scanning is passive either way.  ' +
                'A change lasts until the source re-opens; scan= on the source line keeps it.' },
            { title: 'Scanning', field: `${lbt}.scan_active`,
                show: (v, s) => !!v && v !== s[`${lbt}.scan`],
                format: (v) => el('span', { class: 'warn-text' },
                    v === 'none' ? 'Nothing: the controller supports neither' : `${scanModes[v] ?? v}: the controller can't do the rest`),
                help: 'What the controller is scanning for, when it can\'t do everything asked.' },
        ],
    });

    ui.sourceSections.add({
        id: 'btprobe', title: 'Active probing', priority: 5, drivers: ['linuxbluetooth'], running: true,
        fields: [
            { id: 'mode', title: 'Probing', draw: (cell, v, s, state, ctx) => chooser(cell, state, {
                options: probeModes, current: s[`${lbt}.probe`] ?? '',
                note: 'Probing transmits; it is off unless turned on here or with probe= on the source line.',
                onApply: (want) => setMode(ctx, s, want),
            }), help: 'Off listens only.  Names asks classic devices for their names.  Info also connects to devices ' +
                'to read their controller\'s version and features.' },
            { id: 'interval', title: 'Probe interval', show: (v, s) => reported(s), draw: (cell, v, s, state, ctx) => {
                if (!state.input) {
                    state.text = el('span');
                    state.input = el('input', { type: 'number', min: intervalMin, max: intervalMax, step: 1,
                        placeholder: 'seconds', style: { width: '7em' } });
                    state.button = el('button', { type: 'button', onclick: () => {
                        const val = state.input.value.trim();
                        const n = Number(val);
                        if (!/^\d+$/.test(val) || n < intervalMin || n > intervalMax) {
                            state.ctx.message(`The interval is ${intervalMin} to ${intervalMax} seconds.`, 'error');
                            return;
                        }
                        state.input.value = '';
                        state.ctx.busy(sources.setting(state.uuid, `probe_interval=${n}`), 'Setting the interval...');
                    } }, 'Set');
                    replace(cell, el('span', { class: 'ds-buttons' }, state.text, state.input, state.button));
                }
                state.ctx = ctx;
                state.uuid = s[`${ds}.uuid`];
                const sec = s[`${lbt}.probe_interval`] ?? 0;
                replace(state.text, `${format.count(sec)} seconds`);
            }, help: `The least time between probes of the same device, ${intervalMin} to ${intervalMax} seconds.` },
            { title: 'Devices probed', field: `${lbt}.probes`, show: (v, s) => reported(s), format: format.count,
                help: 'Devices connected to and probed since the source opened.' },
            { title: 'Waiting', field: `${lbt}.probe_queue`, show: (v, s) => reported(s) && s[`${lbt}.probe`] !== 'off',
                format: format.count, help: 'Devices waiting to be probed.' },
            { title: 'Last probe', field: `${lbt}.probe_last`, hideZero: true, format: format.time },
        ],
    });
}
