// Bluetooth LE advertisements captured by BTLE radios (nRF, TI, CatSniffer...).

import { registerTrackers } from './btle_trackers.js';
import { registerBtAdv, serviceLabeler } from './btadv.js';

const base = 'kismet.device.base';
const b = 'btle.device';

const addressTypes = {
    static: 'Static random',
    resolvable: 'Resolvable private (rotating)',
    'non-resolvable': 'Non-resolvable private (rotating)',
    reserved: 'Reserved',
};

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
    // Search box names for the BTLE details
    const filterHint = (id, names, path, more = {}) =>
        ui.filterHints.add({ id, phy: 'BTLE', names, fields: [`${b}/${b}.${path}`], filterEmpty: '', ...more });
    filterHint('btle_company_id', ['company_id'], 'manuf_company_id', { help: 'Bluetooth SIG company ID in the manufacturer data' });
    filterHint('btle_version', ['bt_version'], 'lmp_version', { help: 'Bluetooth version the device\'s controller reported' });
    filterHint('btle_chip', ['chip', 'chip_maker'], 'chip_manufacturer', { help: 'Maker of the device\'s controller chip' });
    // Addresses in a device's related group, itself included: related > 1 lists the
    // devices with related devices
    filterHint('btle_related', ['related', 'related_count'], 'related_count', { filterKind: 'number', filterEmpty: 0,
        help: 'Addresses in the device\'s related group, itself included; related > 1 finds devices with related devices' });

    const isBtle = (row) => row[`${base}.phyname`] === 'BTLE';
    const supported = (v) => (v ? 'Supported' : 'Not supported');

    const serviceLabel = serviceLabeler(kismet);

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

    // When each address advertising the same payload as a device was heard, one bar
    // per address, and a link to the newest one
    const relatedFields = [`${base}.key`, `${base}.macaddr`, `${base}.first_time`, `${base}.last_time`,
        [`${b}/${b}.old_address`, 'old']];

    function relatedTimeline(selfKey) {
        const { el } = kismet.dom;
        const now = () => (kismet.clock.isKnown() ? kismet.clock.now() : Date.now() / 1000);
        const chart = kismet.widgets.charts.timeline({ onPick: (item) => ui.openDevice(item.id), empty: 'Kismet no longer tracks this address\'s group; it was forgotten to save memory.' });
        const newestLine = el('div', { class: 'related-newest' });
        const node = el('div', {}, newestLine, chart.node);
        let members = [];
        let newest = null;
        let timer = null;
        let everConnected = false;

        function draw() {
            const t = now();
            const items = members.slice().sort((x, y) => x.start - y.start);
            const from = Math.min(t - 60, ...items.map((m) => m.start));
            chart.update(items, from, t, [kismet.format.time(from), 'now']);

            const n = members.find((m) => m.id === newest);
            if (!newest || newest === '0' || !n) {
                newestLine.replaceChildren();
            } else if (newest === selfKey) {
                newestLine.replaceChildren(el('span', { class: 'muted' }, 'This is the newest address.'));
            } else {
                newestLine.replaceChildren('Newest: ', el('a', { href: '#', class: 'mono', title: 'Open in a new window',
                    onclick: (e) => {
                        e.preventDefault();
                        ui.openDevice(newest);
                    } }, n.mac, icons.icon('chain')));
            }
        }

        async function refresh() {
            clearTimeout(timer);
            if (node.isConnected)
                everConnected = true;
            else if (everConnected)
                return;
            const onScreen = node.checkVisibility ? node.checkVisibility() : node.offsetParent !== null;
            if (node.isConnected && onScreen && document.visibilityState !== 'hidden') {
                try {
                    const rows = await kismet.api.post(`phy/btle/related-of/${encodeURIComponent(selfKey)}/devices.json`,
                        { fields: relatedFields });
                    const t = now();
                    members = (rows ?? []).map((r) => {
                        const mac = r[`${base}.macaddr`];
                        const start = r[`${base}.first_time`];
                        const end = r[`${base}.last_time`];
                        const self = r[`${base}.key`] === selfKey;
                        return {
                            id: r[`${base}.key`], mac, start, end,
                            label: self ? `${mac} (this)` : mac,
                            color: r.old ? 'var(--muted)' : t - end < 60 ? 'var(--ok)' : 'var(--accent)',
                            title: `${mac}${r.old ? ', replaced' : ''}\n${kismet.format.time(start)} – ${kismet.format.time(end)}`,
                        };
                    });
                    draw();
                } catch {
                    // Keep what's drawn; the next refresh tries again
                }
            }
            timer = setTimeout(refresh, (everConnected ? 10 : 0.5) * 1000);
        }

        draw();
        refresh();
        return {
            node,
            setNewest(key) {
                if (key === newest)
                    return;
                newest = key;
                draw();
            },
        };
    }

    registerTrackers(kismet);
    registerBtAdv(kismet);

    ui.channelNames.add({ id: 'BTLE', title: 'BLE', priority: 10, name: bleChannel, frequency: bleFrequency });
    ui.sourceChannels.add({
        id: 'btle', title: 'BLE',
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
            { title: 'Appearance', field: `${b}/${b}.appearance_name`, hideEmpty: true,
                help: 'What the device advertises itself as (its Bluetooth appearance value).' },
            { title: 'Address type', field: `${b}/${b}.random_address_type`, hideEmpty: true,
                format: (v) => addressTypes[v] ?? v,
                help: 'For a random address: static addresses last until the device is reset; resolvable and non-resolvable private addresses change every few minutes.' },
            { title: 'Linked to', field: `${b}/${b}.alias_group`, hideEmpty: true,
                format: (v, dev) => {
                    const how = kismet.api.field(dev, `${b}/${b}.alias_method`);
                    return kismet.dom.el('span', {}, kismet.dom.el('span', { class: 'mono' }, v), how ? ` (by ${how})` : '');
                },
                help: 'Kismet linked this randomized address to others it believes are the same device; this is the first address in the chain.' },
            {
                group: 'BTLE Related Devices',
                show: (dev) => (kismet.api.field(dev, `${b}/${b}.related_count`) ?? 0) > 0,
                help: 'Rotating random addresses that advertised exactly the same payload as this one: most likely one device moving from address to address, or several identical devices.  An address is replaced once it has gone quiet and a newer one with the same payload has appeared.  The timeline shows when each address was heard: each bar runs from the first to the last time.  Green bars were heard in the last minute; replaced addresses are grey.  Kismet tracks a limited number of these groups and addresses per group to save memory: the least recently heard group is forgotten first, and a full group drops its longest quiet address.  Only set when btle_related is on.',
                fields: [
                    { title: 'Count', field: `${b}/${b}.related_count`,
                        format: (v, dev) => {
                            const n = v === 1 ? 'This address only' : `${v} addresses`;
                            return kismet.api.field(dev, `${b}/${b}.old_address`) ? `${n}, replaced by a newer one` : n;
                        } },
                    { title: 'Incomplete', field: `${b}/${b}.related_truncated`, show: (v) => !!v,
                        format: () => kismet.dom.el('span', { class: 'warn-text' }, 'Older addresses were left out of this group to save memory'),
                        help: 'The group reached btle_related_max_addresses, so its longest quiet addresses were dropped from it; the count and timeline only cover the addresses still tracked.' },
                    {
                        id: 'related_timeline', wide: true,
                        value: (dev) => dev[`${base}.key`],
                        draw: (cell, key, dev, state) => {
                            if (!state.timeline) {
                                state.timeline = relatedTimeline(key);
                                cell.replaceChildren(state.timeline.node);
                            }
                            state.timeline.setNewest(kismet.api.field(dev, `${b}/${b}.related_newest`));
                        },
                    },
                ],
            },
            { title: 'Advertising set', field: `${b}/${b}.adv_sid`,
                help: 'The extended advertising set ID the device uses.' },
            { title: 'PDU type', field: `${b}/${b}.pdu_type`, format: (v) => pduTypes[v] ?? `Unknown (${v})`,
                help: 'The kind of advertising packet, which says whether the device accepts connections.' },
            { title: 'Manufacturer ID', field: `${b}/${b}.manuf_company_id`, hideEmpty: true,
                format: (v) => `0x${v.toString(16).padStart(4, '0')}`,
                help: 'The Bluetooth SIG company ID in the device\'s manufacturer data.' },
            { title: 'Manufacturer data', field: `${b}/${b}.manuf_data`, hideEmpty: true,
                format: (v) => kismet.dom.el('span', { class: 'mono', style: { wordBreak: 'break-all' } }, v),
                help: 'The rest of the most recent manufacturer data, in hex.' },
            { title: 'Services', field: `${b}/${b}.service_uuid_vec`,
                show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => kismet.dom.el('div', {}, v.map((uuid) => kismet.dom.el('div', {}, serviceLabel(uuid)))),
                help: 'Service UUIDs the device has advertised, with the service or company each is assigned to when Kismet knows it.' },
            { title: 'Service data', field: `${b}/${b}.service_data`,
                show: (v) => v !== null && typeof v === 'object' && Object.keys(v).length > 0,
                format: (v) => kismet.dom.el('div', {}, Object.keys(v).sort().map((uuid) =>
                    kismet.dom.el('div', { style: { wordBreak: 'break-all' } }, serviceLabel(uuid), ': ',
                        kismet.dom.el('span', { class: 'mono' }, v[uuid] || '(empty)')))),
                help: 'The latest payload the device advertised for each service UUID, in hex.  Location trackers are left out; their decoded fields are under Location tracker.' },
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
