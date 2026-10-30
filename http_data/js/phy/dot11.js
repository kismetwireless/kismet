// Wi-Fi (IEEE 802.11) support: icons, highlights, columns, views, details.

import { registerChannelPicker } from './dot11_channels.js';
import { registerInsights } from './dot11_insights.js';
import { registerAirspace } from './dot11_airspace.js';

const phy = 'IEEE802.11';
const base = 'kismet.device.base';
const beacon = 'dot11.device/dot11.device.last_beaconed_ssid_record';

// The Wi-Fi channel number at a frequency in kHz, or null if it isn't the
// centre of a Wi-Fi channel
export function channelName(khz) {
    const mhz = khz / 1000;
    if (!Number.isInteger(mhz))
        return null;
    const grid = (start, lo, hi) => {
        const n = (mhz - start) / 5;
        return Number.isInteger(n) && n >= lo && n <= hi ? String(n) : null;
    };
    if (mhz === 2484)
        return '14';
    if (mhz < 2500)
        return grid(2407, 1, 13);
    if (mhz >= 4910 && mhz <= 4980)
        return grid(4000, 182, 196);
    if (mhz === 5935)
        return '2';
    if (mhz < 5950)
        return grid(5000, 32, 177);
    if (mhz <= 7125)
        return grid(5950, 1, 233);
    if (mhz >= 58320 && mhz <= 70200) {
        const n = (mhz - 56160) / 2160;
        return Number.isInteger(n) ? String(n) : null;
    }
    return null;
}

// The frequency (kHz) of a Wi-Fi source's channel: '6', '36HT40+', '100VHT80',
// '5W6e' (6 GHz), or a frequency in MHz like '2412'.  Wider channels count at
// their control channel.
export function channelFrequency(channel) {
    const m = /^(\d+)(-?W6e)?/.exec(String(channel));
    if (!m)
        return null;
    const n = Number(m[1]);
    let mhz;
    if (m[2])
        mhz = n === 2 ? 5935 : 5950 + n * 5;
    else if (n > 196)
        mhz = n;
    else if (n === 14)
        mhz = 2484;
    else if (n < 14)
        mhz = 2407 + n * 5;
    else if (n >= 182)
        mhz = 4000 + n * 5;
    else
        mhz = 5000 + n * 5;
    return n > 0 ? mhz * 1000 : null;
}

// The frequencies (kHz) a wide Wi-Fi channel takes in: '36HT40+', '100VHT80',
// '36VHT160'; null for a 20 MHz one
const vht80 = [42, 58, 106, 122, 138, 155, 171];
const vht160 = [50, 114, 163];
export function channelSpan(channel) {
    const m = /^(\d+)(HT40[+-]|VHT80|VHT160)$/.exec(String(channel));
    if (!m)
        return null;
    const n = Number(m[1]);
    const mhz = channelFrequency(m[1]) / 1000;
    if (!mhz)
        return null;
    let lo;
    let hi;
    if (m[2] === 'HT40+') {
        lo = mhz - 10;
        hi = mhz + 30;
    } else if (m[2] === 'HT40-') {
        lo = mhz - 30;
        hi = mhz + 10;
    } else {
        const wide = m[2] === 'VHT80';
        const c = (wide ? vht80 : vht160).find((cc) => Math.abs(n - cc) <= (wide ? 6 : 14));
        if (c === undefined)
            return null;
        const half = wide ? 40 : 80;
        lo = 5000 + c * 5 - half;
        hi = 5000 + c * 5 + half;
    }
    return { low: lo * 1000, high: hi * 1000 };
}

// A complete WPA handshake: EAPOL messages 1+2 or 2+3 from any client
function hasHandshake(list) {
    for (const packets of Object.values(list ?? {})) {
        let seen = 0;
        for (const p of packets ?? []) {
            seen |= 1 << p['dot11.eapol.message_num'];
            if ((seen & 0x06) === 0x06 || (seen & 0x0c) === 0x0c)
                return true;
        }
    }
    return false;
}

export function register(kismet) {
    const { ui, icons, format, dom, api } = kismet;
    const { el } = dom;
    const isWifi = (row) => row[`${base}.phyname`] === phy;

    // Drivers that capture other radios, whose channels never look like Wi-Fi ones
    registerInsights(kismet);
    registerAirspace(kismet);
    registerChannelPicker(kismet, (s) => !/^(cell|rtl|bt|hci|ubertooth|nrf|ticc|nxp|zwave|meshtastic|adsb|ais)/.test(ui.driverOf(s)));

    ui.deviceIcons.add({
        id: 'dot11', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isWifi(row) ? icons.icon('wifi', 'Wi-Fi') : null),
    });

    ui.deviceViews.add({ id: 'phydot11_accesspoints', title: 'Wi-Fi access points', group: 'Wi-Fi', priority: -100 });

    // Access points don't move, so the middle of where Kismet heard them is
    // the best guess of where they are; clients are off until asked for
    const wifiDetail = (d) => [d.crypt, d.channel ? `channel ${d.channel}` : null].filter(Boolean).join(', ');
    ui.mapSources.add({
        id: 'dot11_ap', title: 'Wi-Fi access points', priority: 50, icon: 'wifi', view: 'phydot11_accesspoints',
        position: 'average',
        fields: [[`${beacon}/dot11.advertisedssid.ssid`, 'ssid'], [`${base}.crypt`, 'crypt'], [`${base}.channel`, 'channel']],
        label: (d) => String(d.ssid ?? '').trim() || d.name,
        detail: wifiDetail,
        color: () => 'hsl(210 80% 55%)',
    });
    ui.mapSources.add({
        id: 'dot11_client', title: 'Wi-Fi clients', priority: 51, icon: 'wifi', view: `phy-${phy}`, position: 'average',
        defaultVisible: false, interval: 5000,
        regex: [[`${base}.type`, '^Wi-Fi (Client|Bridged|Device)$']],
        fields: [[`${base}.channel`, 'channel']],
        detail: (d) => [d.type, d.channel ? `channel ${d.channel}` : null].filter(Boolean).join(', '),
        color: () => 'hsl(195 45% 60%)',
    });
    ui.channelNames.add({ id: phy, title: 'Wi-Fi', priority: 0, name: channelName, frequency: channelFrequency });
    ui.sourceChannels.add({
        id: 'dot11',
        match: (src) => /wifi|wlan|coconut|shuriken|halow|bladerf/i.test(src['kismet.datasource.driver.type'] ?? ''),
        frequency: channelFrequency,
        span: channelSpan,
    });

    ui.rowHighlights.add({
        id: 'dot11_handshake', name: 'WPA handshake', priority: 10,
        description: 'Networks with a complete WPA handshake captured',
        defaultColor: '#e03131', defaultEnabled: true,
        fields: ['dot11.device/dot11.device.wpa_handshake_list'],
        match: (row) => hasHandshake(row['dot11.device.wpa_handshake_list']),
    });

    ui.rowHighlights.add({
        id: 'dot11_pmkid', name: 'RSN PMKID', priority: 11,
        description: 'Networks with a captured RSN PMKID',
        defaultColor: '#f06595', defaultEnabled: true,
        fields: [['dot11.device/dot11.device.pmkid_packet', 'pmkid']],
        match: (row) => !!row.pmkid,
    });

    ui.rowHighlights.add({
        id: 'dot11_all', name: 'Wi-Fi device', priority: 100,
        description: 'Every Wi-Fi device',
        defaultColor: '#8ce99a',
        fields: [`${base}.phyname`],
        match: isWifi,
    });

    ui.deviceColumns.add({
        id: 'wifi_ssid', title: 'SSID', priority: 5, group: 'Wi-Fi',
        description: 'Network name the access point advertises',
        fields: [[`${beacon}/dot11.advertisedssid.ssid`, 'ssid']],
        sortField: `${beacon}/dot11.advertisedssid.ssid`,
        render: (row) => row.ssid ?? '',
    });

    ui.deviceColumns.add({
        id: 'wifi_clients', title: 'Clients', priority: 100, group: 'Wi-Fi', width: '5.5em', align: 'right',
        description: 'Wi-Fi clients seen talking to this access point',
        fields: ['dot11.device/dot11.device.num_associated_clients'],
        sortField: 'dot11.device/dot11.device.num_associated_clients',
        render: (row) => row['dot11.device.num_associated_clients'] || '',
    });

    ui.deviceColumns.add({
        id: 'wifi_bssid', title: 'BSSID', priority: 101, group: 'Wi-Fi', width: '11em',
        description: 'The access point a client last used',
        fields: ['dot11.device/dot11.device.last_bssid'],
        sortField: 'dot11.device/dot11.device.last_bssid',
        render: (row) => {
            const b = row['dot11.device.last_bssid'];
            return b && b !== '00:00:00:00:00:00' ? el('span', { class: 'mono' }, b) : '';
        },
    });

    ui.deviceColumns.add({
        id: 'wifi_uptime', title: 'Uptime', priority: 102, group: 'Wi-Fi', width: '7em', align: 'right',
        description: 'Access point uptime, from its beacon timestamp',
        fields: ['dot11.device/dot11.device.bss_timestamp'],
        sortField: 'dot11.device/dot11.device.bss_timestamp',
        render: (row) => (row['dot11.device.bss_timestamp'] ? format.duration(row['dot11.device.bss_timestamp'] / 1e6) : ''),
    });

    ui.deviceColumns.add({
        id: 'wifi_qbss_usage', title: 'QBSS usage', priority: 42, group: 'Wi-Fi', width: '7em',
        defaultVisible: true,
        description: 'QBSS channel utilization: how busy the access point says its channel is (802.11e)',
        fields: [[`${beacon}/dot11.advertisedssid.dot11e_qbss`, 'qbss'],
            [`${beacon}/dot11.advertisedssid.dot11e_channel_utilization_perc`, 'qbss_usage']],
        sortField: `${beacon}/dot11.advertisedssid.dot11e_channel_utilization_perc`,
        render: (row) => (row.qbss ? kismet.widgets.cellgraphs.fillBar(row.qbss_usage) : ''),
    });

    ui.deviceColumns.add({
        id: 'wifi_qbss_clients', title: 'QBSS clients', priority: 104, group: 'Wi-Fi', width: '6em', align: 'right',
        description: 'Clients the access point says are associated (802.11e QBSS)',
        fields: [[`${beacon}/dot11.advertisedssid.dot11e_qbss`, 'qbss'],
            [`${beacon}/dot11.advertisedssid.dot11e_qbss_stations`, 'qbss_stations']],
        sortField: `${beacon}/dot11.advertisedssid.dot11e_qbss_stations`,
        render: (row) => (row.qbss ? row.qbss_stations : ''),
    });

    ui.deviceColumns.add({
        id: 'wifi_beacon_name', title: 'Beacon name', priority: 105, group: 'Wi-Fi', width: '10em',
        description: 'Extra name or hardware id some vendors put in beacons',
        fields: [[`${beacon}/dot11.advertisedssid.beacon_info`, 'beacon_info']],
        sortField: `${beacon}/dot11.advertisedssid.beacon_info`,
        render: (row) => (typeof row.beacon_info === 'string' ? row.beacon_info : ''),
    });

    registerDetails(kismet);
}

// Encryption bits from packet_ieee80211.h
const crypt = {
    none: 0, unknown: 1, wep: 1 << 1, layer3: 1 << 2, wep40: 1 << 3, wep104: 1 << 4, tkip: 1 << 5,
    wpa: 1 << 6, psk: 1 << 7, aes_ocb: 1 << 8, aes_ccm: 1 << 9, wpa_migmode: 1 << 10, eap: 1 << 11,
    leap: 1 << 12, ttls: 1 << 13, tls: 1 << 14, peap: 1 << 15, sae: 1 << 16, wpa_owe: 1 << 17,
    protectmask: 0xfffff, isakmp: 1 << 20, pptp: 1 << 21, fortress: 1 << 22, keyguard: 1 << 23,
    unknown_protected: 1 << 24, unknown_nonwep: 1 << 25, wps: 1 << 26,
    version_wpa2: 1 << 28, version_wpa3: 1 << 29,
};

// An encryption bit set (dot11.advertisedssid.crypt_set) as text, e.g. "WPA2 WPA2-PSK AES-CCM"
export function cryptToText(set) {
    if (set === crypt.none)
        return 'None / Open';
    if (set === crypt.unknown)
        return 'Unknown';

    const out = [];
    if (set & crypt.wps)
        out.push('WPS');
    if ((set & crypt.protectmask) === crypt.wep)
        return [...out, 'WEP'].join(' ');
    if (set === crypt.wpa_owe)
        return 'Open (OWE)';
    if (set & crypt.wpa_owe)
        return 'OWE';

    const wpa = (set & crypt.version_wpa3) ? 'WPA3' : ((set & crypt.version_wpa2) ? 'WPA2' : 'WPA');
    const names = [
        [crypt.wpa, wpa],
        [crypt.psk, `${wpa}-PSK`], [crypt.sae, `${wpa}-SAE`], [crypt.eap, `${wpa}-EAP`], [crypt.peap, `${wpa}-PEAP`],
        [crypt.leap, 'EAP-LEAP'], [crypt.ttls, 'EAP-TTLS'], [crypt.tls, 'EAP-TLS'], [crypt.wpa_migmode, 'WPA-MIGRATION'],
        [crypt.wep40, 'WEP40'], [crypt.wep104, 'WEP104'], [crypt.tkip, 'TKIP'], [crypt.aes_ocb, 'AES-OCB'],
        [crypt.aes_ccm, 'AES-CCM'], [crypt.layer3, 'Layer3'], [crypt.isakmp, 'Layer3-ISA-KMP'], [crypt.pptp, 'Layer3-PPTP'],
        [crypt.fortress, 'Fortress'], [crypt.keyguard, 'Keyguard'], [crypt.unknown_protected, 'Unknown'],
        [crypt.unknown_nonwep, 'Unknown-Non-WEP'],
    ];
    for (const [bit, name] of names) {
        if (set & bit)
            out.push(name);
        // WPA3 networks that also take WPA2 passwords
        if (bit === crypt.wpa && (set & crypt.version_wpa3) && (set & crypt.psk) && (set & crypt.sae))
            out.push('WPA3-TRANSITION');
    }
    return out.join(' ');
}

// A hex string as hex-and-ASCII dump lines, 16 bytes to a line
function hexdumpLines(hex) {
    const bytes = [];
    for (let i = 0; i + 1 < (hex ?? '').length; i += 2)
        bytes.push(parseInt(hex.substr(i, 2), 16));

    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i + 16);
        const hexPart = chunk.map((b) => b.toString(16).padStart(2, '0'))
            .map((h, j) => (j === 8 ? ` ${h}` : h)).join(' ');
        const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
        lines.push(`${hexPart.padEnd(48)}  ${ascii}`);
    }
    return lines;
}

// Which EAPOL handshake messages (1-4) were seen, as a bit set
function handshakeMessages(packets) {
    let seen = 0;
    for (const p of packets ?? [])
        seen |= 1 << p['dot11.eapol.message_num'];
    return seen;
}

// AP uptime from its beacon timestamp (microseconds), e.g. "3d 4h 12m 5s"
function uptime(usec) {
    const sec = Math.floor(usec / 1e6);
    const parts = [[Math.floor(sec / 86400), 'd'], [Math.floor(sec / 3600) % 24, 'h'], [Math.floor(sec / 60) % 60, 'm']];
    let out = '';
    let started = false;
    for (const [n, unit] of parts) {
        if (n > 0 || started) {
            out += `${n}${unit} `;
            started = true;
        }
    }
    return `${out}${sec % 60}s`;
}

// Other devices this one mentions (its access points, its clients), looked
// up together in one request and kept for a little while.
function createLookup(api) {
    const cache = new Map();        // key -> { dev, at }
    const waiting = new Map();      // key -> callbacks
    const keepMs = 15000;
    let timer = null;
    const fields = [
        'kismet.device.base.key', 'kismet.device.base.macaddr', 'kismet.device.base.type',
        'kismet.device.base.commonname', 'kismet.device.base.manuf',
        'dot11.device/dot11.device.client_map',
        ['dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid', 'last_ssid'],
    ];

    async function fetchWaiting() {
        timer = null;
        const batch = new Map(waiting);
        waiting.clear();
        let devs = {};
        try {
            devs = await api.post('devices/multikey/as-object/devices.json', { devices: [...batch.keys()], fields });
        } catch (err) {
            console.error('Wi-Fi: could not look up related devices:', err);
        }
        const at = Date.now();
        if (cache.size > 2000)
            cache.clear();
        for (const [key, callbacks] of batch) {
            const dev = devs?.[key] ?? null;
            cache.set(key, { dev, at });
            for (const fn of callbacks)
                fn(dev);
        }
    }

    // The device record (or undefined until it's known); fn(dev) is called
    // when a lookup finishes
    return function lookup(key, fn = null) {
        if (!key || key === '0')
            return null;
        const hit = cache.get(key);
        if (hit && Date.now() - hit.at < keepMs)
            return hit.dev;
        if (!waiting.has(key))
            waiting.set(key, new Set());
        if (fn)
            waiting.get(key).add(fn);
        timer ??= setTimeout(fetchWaiting, 0);
        return hit?.dev;
    };
}

function registerDetails(kismet) {
    const { ui, format, dom, api, icons, clock } = kismet;
    const { el } = dom;
    const muted = ui.muted;
    const lookup = createLookup(api);
    const macCache = new Map();     // MAC -> Wi-Fi device key (or null)

    icons.define('download', '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>');

    const d = 'dot11.device';
    const as = 'dot11.advertisedssid';
    const ps = 'dot11.probedssid';
    const cl = 'dot11.client';
    const loc = 'kismet.common.location';

    const deviceLink = (key, text) => el('a', { href: '#', onclick: (e) => {
        e.preventDefault();
        ui.openDevice(key);
    } }, text);
    const download = (path, text) => el('a', { href: api.linkUrl(path).href, download: '' }, icons.icon('download'), ` ${text}`);
    const copyable = (v) => el('span', {}, el('span', { class: 'mono' }, v),
        el('button', { class: 'copy-button', type: 'button', title: 'Copy', onclick: () => navigator.clipboard?.writeText(v) },
            icons.icon('copy')));
    const count = (v) => v.toLocaleString();
    const dbm = (v) => `${v} dBm`;
    const enabled = () => 'Enabled';
    const point = (v) => (Array.isArray(v) && v[0] && v[1] ? `${v[1].toFixed(6)}, ${v[0].toFixed(6)}` : muted('Unknown'));
    const notZeroMac = (v) => typeof v === 'string' && v.replace(/[0:]/g, '') !== '';
    const hasKeys = (v) => v && typeof v === 'object' && Object.keys(v).length > 0;

    // An access point's clients as a searchable, sortable table.  One request
    // fetches every client with just the columns' fields; the table draws
    // rows as they're scrolled to and reloads every few seconds while open.
    const clientFields = [
        `${base}.key`, `${base}.macaddr`, `${base}.commonname`, `${base}.type`, `${base}.manuf`,
        `${base}.packets.total`, `${base}.last_time`, `${base}.datasize`,
        [`${base}.signal/kismet.common.signal.last_signal`, 'signal'],
    ];

    function clientTable(apKey) {
        const v = (name) => (r) => r[`${base}.${name}`];
        return kismet.widgets.listTable({
            id: 'dot11-clients',
            load: () => api.post(`phy/phy80211/clients-of/${encodeURIComponent(apKey)}/clients.json`, { fields: clientFields }),
            search: 'Search MAC, name, type, or manufacturer',
            empty: 'No clients.',
            defaultSort: { column: 'last_time', dir: 'desc' },
            columns: [
                { id: 'mac', title: 'MAC', value: v('macaddr'),
                    render: (r) => el('a', { href: '#', class: 'mono', title: 'Open this device',
                        onclick: (e) => { e.preventDefault(); ui.openDevice(r[`${base}.key`]); } }, r[`${base}.macaddr`]) },
                { id: 'name', title: 'Name',
                    value: (r) => (r[`${base}.commonname`] !== r[`${base}.macaddr`] ? r[`${base}.commonname`] : '') },
                { id: 'type', title: 'Type', value: v('type') },
                { id: 'manuf', title: 'Manufacturer', value: v('manuf') },
                { id: 'packets', title: 'Packets', value: v('packets.total'), align: 'right', dir: 'desc',
                    render: (r) => (r[`${base}.packets.total`] ?? 0).toLocaleString() },
                { id: 'signal', title: 'Signal', value: (r) => r.signal || null, align: 'right', dir: 'desc',
                    render: (r) => (r.signal ? format.signal(r.signal) : '') },
                { id: 'last_time', title: 'Last seen', value: v('last_time'), dir: 'desc',
                    render: (r) => format.time(r[`${base}.last_time`]) },
                { id: 'data', title: 'Data', value: v('datasize'), align: 'right', dir: 'desc',
                    render: (r) => (r[`${base}.datasize`] ? format.size(r[`${base}.datasize`]) : '') },
            ],
        });
    }

    // When each client was seen with an access point: one bar per client, from
    // the first to the last time it was seen with it.  The most recently seen
    // clients are shown, at most timelineMax of them.
    const timelineMax = 40;
    const timelineSpans = [['all', 'All'], ['day', 'Past day'], ['hour', 'Past hour']];
    const timelineFields = [
        `${base}.key`, `${base}.macaddr`, `${base}.commonname`,
        [`${d}/${d}.client_map`, 'client_map'],
    ];

    function clientTimeline(apKey) {
        const chart = kismet.widgets.charts.timeline({ onPick: (item) => ui.openDevice(item.id), empty: 'No clients in this period.' });
        const note = el('div', { class: 'muted timeline-note' });
        let span = 'all';
        let clients = [];
        let timer = null;
        let everConnected = false;

        const buttons = timelineSpans.map(([id, label]) => el('button', { type: 'button',
            class: id === span ? 'active' : null,
            onclick: () => {
                span = id;
                buttons.forEach((b, i) => b.classList.toggle('active', timelineSpans[i][0] === id));
                draw();
            } }, label));
        const node = el('div', {}, el('div', { class: 'graph-tabs' }, buttons), chart.node, note);

        function draw() {
            const t = clock.isKnown() ? clock.now() : Date.now() / 1000;
            const from = span === 'hour' ? t - 3600 : span === 'day' ? t - 86400 :
                Math.min(t - 60, ...clients.map((c) => c.start));
            const shown = clients.filter((c) => c.end >= from)
                .sort((a, b) => b.end - a.end)
                .slice(0, timelineMax)
                .sort((a, b) => a.start - b.start);
            // The start of "All": a clock time if it's within the day, else the date too
            const start = t - from < 86400 ? format.clock(from) : format.time(from);
            chart.update(shown, from, t, [span === 'all' ? start : `-${span === 'hour' ? '60m' : '24h'}`, 'now']);
            const inSpan = clients.filter((c) => c.end >= from).length;
            note.textContent = inSpan > shown.length ? `The ${shown.length} most recently seen of ${inSpan.toLocaleString()} clients.` : '';
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
                    const rows = await api.post(`phy/phy80211/clients-of/${encodeURIComponent(apKey)}/clients.json`,
                        { fields: timelineFields });
                    const t = clock.isKnown() ? clock.now() : Date.now() / 1000;
                    clients = (rows ?? []).map((r) => {
                        // The client's record for this access point
                        const rec = Object.values(r.client_map ?? {}).find((c) => c['dot11.client.bssid_key'] === apKey);
                        if (!rec)
                            return null;
                        const mac = r[`${base}.macaddr`];
                        const name = r[`${base}.commonname`] !== mac ? r[`${base}.commonname`] : '';
                        const start = rec['dot11.client.first_time'];
                        const end = rec['dot11.client.last_time'];
                        const data = rec['dot11.client.datasize'];
                        return {
                            id: r[`${base}.key`], start, end,
                            label: name || mac,
                            // Seen in the last minute
                            color: t - end < 60 ? 'var(--ok)' : 'var(--accent)',
                            title: `${name ? `${name} (${mac})` : mac}\n${format.time(start)} – ${format.time(end)}` +
                                (data ? `\n${format.size(data)} of data` : ''),
                        };
                    }).filter(Boolean);
                    draw();
                } catch {
                    // Keep what's drawn; the next refresh tries again
                }
            }
            timer = setTimeout(refresh, (everConnected ? 10 : 0.5) * 1000);
        }

        draw();
        refresh();
        return { node };
    }

    // When things happened to a device: each client's handshake messages, the
    // PMKID, the last WPS M3 and disconnect (the server keeps their count and
    // last time), and the alerts that name it.  The alerts come from the
    // server's recent alerts, fetched while the section is on screen.
    const eventHandshakes = 8;
    const severityColor = (sev) => (sev >= 15 ? 'var(--error)' :
        sev >= 10 ? 'color-mix(in srgb, var(--error) 50%, var(--warn))' : sev >= 5 ? 'var(--warn)' : 'var(--muted)');
    // Handshake messages in blues and greens, apart from the PMKID (warn) and
    // WPS / disconnect (error) colours
    const handshakeColors = ['var(--accent)', 'var(--ok)', 'color-mix(in srgb, var(--accent) 50%, var(--text))',
        'color-mix(in srgb, var(--ok) 50%, var(--text))'];
    const handshakeColor = (n) => handshakeColors[Math.min(3, Math.max(0, n - 1))];

    function eventRows(dev, alerts) {
        const rows = [];
        const handshakes = Object.entries(api.field(dev, `${d}/${d}.wpa_handshake_list`) ?? {});
        for (const [mac, packets] of handshakes.slice(0, eventHandshakes)) {
            rows.push({ label: mac, title: `Handshake with ${mac}`, events: (packets ?? []).map((p) => {
                const t = p['dot11.eapol.timestamp'] ?? 0;
                const n = p['dot11.eapol.message_num'] ?? 0;
                return { t, color: handshakeColor(n), title: `Handshake message ${n} of 4 with ${mac}\n${format.time(t)}` };
            }) });
        }
        const pmkid = api.field(dev, `${d}/${d}.pmkid_packet`);
        if (pmkid?.['kismet.packet.ts_sec'])
            rows.push({ label: 'RSN PMKID', events: [{ t: pmkid['kismet.packet.ts_sec'], color: 'var(--warn)',
                title: `RSN PMKID captured\n${format.time(pmkid['kismet.packet.ts_sec'])}` }] });
        const counted = (label, count, last, what) => {
            const n = api.field(dev, `${d}/${d}.${count}`, 0);
            const t = api.field(dev, `${d}/${d}.${last}`, 0);
            if (n && t)
                rows.push({ label, events: [{ t, color: 'var(--error)',
                    title: `${n.toLocaleString()} ${what}${n === 1 ? '' : 's'}; the last at ${format.time(t)}` }] });
        };
        counted('WPS M3', 'wps_m3_count', 'wps_m3_last', 'WPS M3 message');
        counted('Disconnects', 'client_disconnects', 'client_disconnects_last', 'disconnect or deauthentication message');
        if (alerts.length)
            rows.push({ label: 'Alerts', events: alerts.map((a) => ({ t: a['kismet.alert.timestamp'] ?? 0,
                color: severityColor(a['kismet.alert.severity'] ?? 0),
                title: `${a['kismet.alert.header']}\n${format.time(a['kismet.alert.timestamp'])}\n${a['kismet.alert.text'] ?? ''}` })) });
        return rows;
    }

    function deviceEvents(dev) {
        const chart = kismet.widgets.charts.eventTimeline({ empty: 'Nothing in this period.' });
        const swatch = (color, label) => el('span', {}, el('span', { class: 'timeline-mark', style: { background: color } }), label);
        const legend = el('div', { class: 'timeline-legend' },
            el('span', {}, 'Handshakes, by client:'),
            [1, 2, 3, 4].map((n) => swatch(handshakeColor(n), `message ${n}`)),
            swatch('var(--warn)', 'PMKID'), swatch('var(--error)', 'WPS M3, disconnect, critical alert'));
        let span = 'all';
        let device = dev;
        let alerts = [];
        let timer = null;
        let everConnected = false;
        const mac = dev[`${base}.macaddr`];
        const key = dev[`${base}.key`];

        const buttons = timelineSpans.map(([id, label]) => el('button', { type: 'button',
            class: id === span ? 'active' : null,
            onclick: () => {
                span = id;
                buttons.forEach((b, i) => b.classList.toggle('active', timelineSpans[i][0] === id));
                draw();
            } }, label));
        const node = el('div', {}, el('div', { class: 'graph-tabs' }, buttons), chart.node, legend);

        function draw() {
            const t = clock.isKnown() ? clock.now() : Date.now() / 1000;
            const rows = eventRows(device, alerts);
            const times = rows.flatMap((r) => r.events.map((e) => e.t)).filter((v) => v > 0);
            const from = span === 'hour' ? t - 3600 : span === 'day' ? t - 86400 : Math.min(t - 60, ...times);
            const start = t - from < 86400 ? format.clock(from) : format.time(from);
            chart.update(rows, from, t, [span === 'all' ? start : `-${span === 'hour' ? '60m' : '24h'}`, 'now']);
        }

        // The alerts naming this device, by any of its addresses or its key
        const names = (a) => a['kismet.alert.device_key'] === key || ['source_mac', 'dest_mac', 'transmitter_mac', 'other_mac']
            .some((f) => a[`kismet.alert.${f}`] === mac);

        async function refresh() {
            clearTimeout(timer);
            if (node.isConnected)
                everConnected = true;
            else if (everConnected)
                return;
            const onScreen = node.checkVisibility ? node.checkVisibility() : node.offsetParent !== null;
            if (node.isConnected && onScreen && document.visibilityState !== 'hidden') {
                try {
                    alerts = ((await api.get('alerts/all_alerts.json')) ?? []).filter(names);
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
            update(dev2) {
                device = dev2;
                draw();
            },
        };
    }

    // An SSID: cloaked SSIDs are blanks or spaces
    function ssidText(v, rec) {
        if (typeof v !== 'string')
            return muted('None');
        if (v.replace(/\s/g, '').length === 0) {
            if (rec && rec[`${as}.owe_ssid`])
                return muted('Advertised as OWE');
            return muted(`Cloaked / empty (${v.length} spaces)`);
        }
        return v;
    }

    // The Wi-Fi device a MAC belongs to, as a link once it's been found
    function macLink(cell, mac) {
        const show = (key) => {
            dom.replace(cell, el('span', { class: 'mono' }, mac), key ? [' ', deviceLink(key, 'View')] : null);
        };
        // The server doesn't decode the path, so the MAC goes in as is; only
        // well-formed ones, so nothing else can end up in the URL
        if (macCache.has(mac) || !/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/.test(mac)) {
            show(macCache.get(mac));
            return undefined;
        }
        macCache.set(mac, null);
        show(null);
        api.post(`devices/by-mac/${mac}/devices.json`,
            { fields: ['kismet.device.base.key', 'kismet.device.base.phyname'] })
            .then((devs) => {
                const wifi = (devs ?? []).find((x) => x['kismet.device.base.phyname'] === phy);
                macCache.set(mac, wifi?.['kismet.device.base.key'] ?? null);
                if (cell.isConnected)
                    show(macCache.get(mac));
            })
            .catch(() => {});
        return undefined;
    }

    // Draw the name of a related device into a cell, filling it in once known
    function relatedText(cell, key, text) {
        const fill = (dev) => {
            if (cell.isConnected)
                dom.replace(cell, dev ? text(dev) : muted('Unknown'));
        };
        const dev = lookup(key, fill);
        // Known already: draw it now (the cell may not be on the page yet)
        if (dev !== undefined)
            dom.replace(cell, dev ? text(dev) : muted('Unknown'));
        else if (!cell.childNodes.length)
            cell.replaceChildren(muted('Looking up...'));
    }

    // Average location, for an SSID record
    const locationGroup = (path) => ({
        group: 'Average location',
        show: (rec) => api.field(rec, `${path}/${loc}.avg_loc/${loc}.fix`, 0) >= 2,
        fields: [
            { title: 'Location', field: `${path}/${loc}.avg_loc/${loc}.geopoint`, format: point },
            { title: 'Altitude', field: `${path}/${loc}.avg_loc/${loc}.alt`,
                show: (_v, rec) => api.field(rec, `${path}/${loc}.avg_loc/${loc}.fix`, 0) >= 3,
                format: (v) => format.height(v, 1) },
        ],
    });

    const wpsHelp = (what) => `Devices that support Wi-Fi Protected Setup (WPS) may include ${what} in their WPS messages.  WPS isn't recommended because of its security flaws.`;

    // Fields for an advertised or responded SSID.  Some only make sense in
    // beacons, so responded SSIDs leave them out.
    function ssidFields(beaconed) {
        const all = [
            { title: 'SSID', field: `${as}.ssid`, format: ssidText,
                help: 'A network name can be up to 32 characters of anything.  Some access points try to hide it by sending blanks or spaces; the real name shows up when a client joins.' },
            { title: 'OWE SSID', field: `${as}.owe_ssid`, hideEmpty: true,
                help: 'Opportunistic Wireless Encryption (OWE) networks advertise their real SSID on a second BSSID.' },
            { title: 'OWE BSSID', field: `${as}.owe_bssid`, show: notZeroMac,
                help: 'The BSSID linked to this OWE network.',
                draw: (cell, v) => (notZeroMac(v) ? macLink(cell, v) : undefined) },
            beaconed && { title: 'Mesh ID', field: `${as}.dot11s.meshid`, hideEmpty: true,
                help: 'The 802.11s mesh ID, only present on mesh networks.' },
            beaconed ?
                { title: 'Encryption', field: `${as}.crypt_string`, hideEmpty: true,
                    help: 'The encryption the network advertises in its beacons.  It\'s often a mix of WPA, WPA2, and WPA3 options.' } :
                { title: 'Encryption', field: `${as}.crypt_set`, format: cryptToText,
                    help: 'Wi-Fi encryption (open, WEP, or WPA) is set by the access point\'s announcements.  Encryption added later, such as a VPN, isn\'t part of the network itself.' },
            { title: 'MFP', field: `${as}.wpa_mfp_required`,
                help: 'Management Frame Protection (MFP) guards against denial of service attacks by authenticating management packets.  It\'s part of the 802.11w standard, or a Cisco extension.',
                format: (v, rec) => {
                    if (v)
                        return 'Required (802.11w)';
                    if (rec[`${as}.wpa_mfp_supported`])
                        return 'Supported (802.11w)';
                    if (rec[`${as}.cisco_client_mfp`])
                        return 'Supported (Cisco)';
                    return 'Unavailable';
                } },
            beaconed && { title: 'Channel', field: `${as}.channel`, hideEmpty: true,
                help: 'Networks on 2.4 GHz must say their channel, because neighbouring channels overlap and the exact one can\'t be told from the signal.  5 GHz networks usually don\'t need to.' },
            { title: 'HT mode', field: `${as}.ht_mode`, hideEmpty: true,
                help: '802.11n and 802.11ac networks can use wider channels: HT40, HT80, HT160, or HT80+80 (802.11ac wave 2 only).' },
            { title: 'HT center', field: `${as}.ht_center_1`, hideZero: true, format: (v) => `${v} MHz (channel ${(v - 5000) / 5})`,
                help: 'The center frequency of a wide 802.11ac channel.' },
            { title: 'HT center 2', field: `${as}.ht_center_2`, hideZero: true, format: (v) => `${v} MHz (channel ${(v - 5000) / 5})`,
                help: 'The center of the second part of an 80+80 channel, only on 802.11ac wave 2 gear.' },
            beaconed && { title: 'Beacon info', field: `${as}.beacon_info`, hideEmpty: true,
                help: 'Enterprise access points (Cisco, Aruba/HP, Mist, Ruckus, Arista, Aerohive, Extreme, Mojo, and others) can put a name in their beacons, usually so network admins can tell which access point is where.' },
            beaconed && { title: 'Mesh gateway', field: `${as}.dot11s.gateway`,
                show: (_v, rec) => !!rec[`${as}.dot11s.meshid`], format: (v) => (v === 1 ? 'Enabled' : 'Disabled (not a gateway)'),
                help: 'A mesh device in gateway mode connects the mesh to another network, such as wired Ethernet.' },
            beaconed && { title: 'Mesh forwarding', field: `${as}.dot11s.forwarding`,
                show: (_v, rec) => !!rec[`${as}.dot11s.meshid`], format: (v) => (v === 1 ? 'Forwarding' : 'No'),
                help: 'A mesh device may pass packets along to another mesh device.' },
            beaconed && { title: 'Mesh peers', field: `${as}.dot11s.num_peerings`,
                show: (_v, rec) => !!rec[`${as}.dot11s.meshid`],
                help: 'How many mesh peers this device has.' },
            beaconed && { title: 'Connected stations', field: `${as}.dot11e_qbss_stations`,
                show: (_v, rec) => rec[`${as}.dot11e_qbss`] === 1,
                help: 'Access points with 802.11e (QBSS) report how many stations they see on the channel.' },
            beaconed && { title: 'Channel utilization', field: `${as}.dot11e_channel_utilization_perc`,
                show: (_v, rec) => rec[`${as}.dot11e_qbss`] === 1,
                format: (v) => kismet.widgets.cellgraphs.fillBar(v),
                help: 'Access points with 802.11e (QBSS) estimate how busy the channel is.' },
            beaconed && { title: 'Advertised power', field: `${as}.advertised_txpower`, hideZero: true, format: dbm,
                help: 'Some access points advertise their transmit power in the IE 35 (TPC) element.' },
            { title: 'Cisco CCX power', field: `${as}.ccx_txpower`, hideZero: true, format: dbm,
                help: 'Cisco access points may advertise their transmit power in a Cisco CCX tag, usually on enterprise networks with many access points.' },
            { title: '802.11r mobility', field: `${as}.dot11r_mobility`, hideZero: true, format: enabled,
                help: '802.11r lets clients roam quickly between access points on the same network, usually on enterprise networks with many access points.' },
            { title: 'Mobility domain', field: `${as}.dot11r_mobility_domain_id`, hideZero: true,
                help: 'The 802.11r roaming group this access point belongs to.' },
            { title: 'First seen', field: `${as}.first_time`, format: format.time },
            { title: 'Last seen', field: `${as}.last_time`, format: format.time },
            locationGroup(`${as}.location`),
            beaconed && { title: 'Beacon rate', field: `${as}.beaconrate`, hideZero: true, format: (v) => `${v}/s`,
                help: 'Wi-Fi usually beacons 10 times a second.  An access point hosting many SSIDs may slow that down.' },
            { title: 'Max rate', field: `${as}.maxrate`, hideZero: true, format: (v) => `${v} Mbit/s`,
                help: 'The fastest basic rate the access point supports.' },
            { title: '802.11d country', field: `${as}.dot11d_country`, hideEmpty: true,
                help: '802.11d had access points announce their country and power limits so clients would follow the same rules.  It\'s been phased out but still shows up on older hardware.' },
            { title: 'WPS manufacturer', field: `${as}.wps_manuf`, hideEmpty: true, help: wpsHelp('the manufacturer') },
            { title: 'WPS device', field: `${as}.wps_device_name`, hideEmpty: true, help: wpsHelp('the device name') },
            { title: 'WPS model', field: `${as}.wps_model_name`, hideEmpty: true, help: wpsHelp('the model name') },
            { title: 'WPS model number', field: `${as}.wps_model_number`, hideEmpty: true, help: wpsHelp('the model number') },
            { title: 'WPS serial number', field: `${as}.wps_serial_number`, hideEmpty: true,
                help: `${wpsHelp('the serial number')}  It isn't always valid.` },
            { title: 'Broadcom WPS', field: `${as}.wps_broadcom`, hideZero: true,
                format: (v) => ({
                    1: 'Possible (Broadcom element)',
                    2: 'Likely (Broadcom SDK default WPS identity or UUID)',
                    3: 'Confirmed (answers like Broadcom\'s wps_monitor)',
                }[v] ?? `Unknown (${v})`),
                help: 'Access points running the WPS daemon from Broadcom\'s SDK (wps_monitor) may be open to WPS fragment reassembly attacks.  Possible: the access point advertises WPS and Broadcom\'s own element, which Broadcom\'s driver adds under other WPS daemons too.  Likely: it advertises the SDK\'s default WPS identity or UUID.  Confirmed: it rejected an empty WPS fragment the way wps_monitor does.  See https://github.com/qkaiser/broadcom-wps' },
            { title: 'AirMAX', field: `${as}.airmax_variant`, hideEmpty: true,
                format: (v, rec) => `AirMAX ${v} (version ${rec[`${as}.airmax_version`]})`,
                help: 'Ubiquiti AirMAX access points include a scrambled vendor tag describing the radio.  Kismet decodes it when it matches the sender\'s MAC.' },
            { title: 'AirMAX radio name', field: `${as}.airmax_radioname`, hideEmpty: true,
                help: 'The radio name set on a Ubiquiti AirMAX device.' },
            { title: 'AirMAX SSID', field: `${as}.airmax_ssid`, hideEmpty: true,
                help: 'The SSID in the AirMAX tag, which may be there even when the beaconed SSID is hidden.' },
            { title: 'AirMAX radio MAC', field: `${as}.airmax_radio_mac`, hideEmpty: true,
                help: 'The radio MAC address in the AirMAX tag.' },
            { title: 'AirMAX capabilities', field: `${as}.airmax_cap_flags`, hideEmpty: true,
                show: (_v, rec) => !!rec[`${as}.airmax_variant`],
                format: (v) => `0x${v.toString(16).padStart(8, '0')}`,
                help: 'The capability flags in the AirMAX tag.' },
            { title: 'MikroTik device', field: `${as}.mikrotik_device_name`, hideEmpty: true,
                help: 'MikroTik / RouterBoard access points may advertise their device name in a vendor tag.' },
            {
                id: 'ie_tags', wide: true, field: `${as}.ie_tag_content`,
                show: (v) => hasKeys(v),
                draw: (cell, tags, _rec, state) => {
                    const sig = JSON.stringify(tags);
                    if (state.sig === sig)
                        return undefined;
                    state.sig = sig;
                    return ieTags(tags);
                },
            },
        ];
        return all.filter(Boolean);
    }

    // The information elements (IE tags) in the beacon, as a table with a hex dump
    function ieTags(tags) {
        const rows = Object.values(tags).map((tag) => {
            const label = [el('b', {}, String(tag['dot11.ietag.number']))];
            if (tag['dot11.ietag.oui']) {
                const oui = tag['dot11.ietag.oui'].toString(16).padStart(6, '0').replace(/(..)(?!$)/g, '$1:');
                label.push(el('div', {}, tag['dot11.ietag.oui_manuf'] ? `${oui} (${tag['dot11.ietag.oui_manuf']})` : oui));
            }
            if (tag['dot11.ietag.subtag'] >= 0)
                label.push(el('div', {}, `Subtag ${tag['dot11.ietag.subtag']}`));
            return el('tr', {},
                el('td', { style: { verticalAlign: 'top', whiteSpace: 'nowrap' } }, label),
                el('td', {}, el('pre', { class: 'mono', style: { margin: 0 } }, hexdumpLines(tag['dot11.ietag.data']).join('\n'))));
        });
        return el('div', {},
            el('div', { class: 'df-group-title' }, 'IE tags'),
            el('table', { class: 'mini-table' }, el('tbody', {}, rows)));
    }

    const probedFields = [
        { title: 'Probed SSID', field: `${ps}.ssid`, empty: muted('Broadcast'),
            format: (v) => (v === '' ? muted('Broadcast') : ssidText(v)) },
        { title: 'MFP', field: `${ps}.wpa_mfp_required`,
            help: 'Management Frame Protection (MFP) guards against denial of service attacks by authenticating management packets.  It\'s part of the 802.11w standard, or a Cisco extension.',
            format: (v, rec) => (v ? 'Required (802.11w)' : (rec[`${ps}.wpa_mfp_supported`] ? 'Supported (802.11w)' : 'Unavailable')) },
        { title: 'First seen', field: `${ps}.first_time`, format: format.time },
        { title: 'Last seen', field: `${ps}.last_time`, format: format.time },
        locationGroup(`${ps}.location`),
        { title: '802.11r mobility', field: `${ps}.dot11r_mobility`, hideZero: true, format: enabled,
            help: '802.11r lets clients roam quickly between access points on the same network.' },
        { title: 'Mobility domain', field: `${ps}.dot11r_mobility_domain_id`, hideZero: true },
        { title: 'WPS manufacturer', field: `${ps}.wps_manuf`, hideEmpty: true, help: wpsHelp('the manufacturer') },
        { title: 'WPS device', field: `${ps}.wps_device_name`, hideEmpty: true, help: wpsHelp('the device name') },
        { title: 'WPS model', field: `${ps}.wps_model_name`, hideEmpty: true, help: wpsHelp('the model name') },
        { title: 'WPS model number', field: `${ps}.wps_model_number`, hideEmpty: true, help: wpsHelp('the model number') },
        { title: 'WPS serial number', field: `${ps}.wps_serial_number`, hideEmpty: true, help: wpsHelp('the serial number') },
        { title: 'AirMAX', field: `${ps}.airmax_variant`, hideEmpty: true,
            format: (v, rec) => `AirMAX ${v} (version ${rec[`${ps}.airmax_version`]})`,
            help: 'Ubiquiti AirMAX clients include a scrambled vendor tag describing the radio.' },
        { title: 'AirMAX radio name', field: `${ps}.airmax_radioname`, hideEmpty: true },
        { title: 'AirMAX SSID', field: `${ps}.airmax_ssid`, hideEmpty: true },
        { title: 'AirMAX firmware', field: `${ps}.airmax_fwname`, hideEmpty: true },
        { title: 'AirMAX TX power', field: `${ps}.airmax_txpower`, hideEmpty: true, hideZero: true,
            help: 'The transmit power in the AirMAX tag, in the device\'s own units.' },
        { title: 'AirMAX chains', field: `${ps}.airmax_tx_chainmask`, hideEmpty: true,
            show: (_v, rec) => !!rec[`${ps}.airmax_variant`],
            format: (v, rec) => `TX 0x${v.toString(16)}, RX 0x${(rec[`${ps}.airmax_rx_chainmask`] ?? 0).toString(16)}`,
            help: 'The transmit and receive antenna chains in the AirMAX tag.' },
        { title: 'MikroTik device', field: `${ps}.mikrotik_device_name`, hideEmpty: true },
    ];

    // A table row for a list kept in the device record: the table is made
    // once and handed the list's current entries on every update
    const lookupTables = new Set();
    // Tables with cells that need another device looked up redraw once it's known
    const redrawLookupTables = dom.debounce(50, () => {
        for (const t of lookupTables) {
            if (t.node.isConnected)
                t.redraw();
            else
                lookupTables.delete(t);
        }
    });
    const looked = (key) => lookup(key, redrawLookupTables);

    const mapTable = (id, path, options) => ({
        id: `${id}_table`, wide: true, field: path,
        draw: (cell, map, _rec, state) => {
            if (!state.table) {
                state.table = kismet.widgets.listTable({ id: `dot11-${id}`, ...options });
                if (options.lookups)
                    lookupTables.add(state.table);
                cell.replaceChildren(state.table.node);
            }
            state.table.setRows(Object.entries(map ?? {}).map(([key, value]) => ({ key, value })), map);
        },
    });

    // An SSID's name for a table cell and for sorting and searching
    const ssidSort = (v) => (typeof v === 'string' && v.replace(/\s/g, '') !== '' ? v : '');

    const advertisedTable = (id, path, beaconed) => mapTable(id, path, {
        search: 'Search SSID, encryption, or channel',
        empty: 'None.',
        defaultSort: { column: 'last', dir: 'desc' },
        rowKey: (r) => r.key,
        detail: (r, el) => ui.detailFields(el, r.value, ssidFields(beaconed)),
        columns: [
            { id: 'ssid', title: 'SSID', value: (r) => ssidSort(r.value[`${as}.ssid`]) || r.value[`${as}.owe_ssid`] || '',
                render: (r) => ssidText(r.value[`${as}.ssid`], r.value) },
            { id: 'crypt', title: 'Encryption', value: (r) => r.value[`${as}.crypt_string`] ?? cryptToText(r.value[`${as}.crypt_set`]) },
            { id: 'channel', title: 'Channel', value: (r) => r.value[`${as}.channel`] || '' },
            ...(beaconed ? [{ id: 'rate', title: 'Beacons', value: (r) => r.value[`${as}.beaconrate`] || null, align: 'right', dir: 'desc',
                render: (r) => (r.value[`${as}.beaconrate`] ? `${r.value[`${as}.beaconrate`]}/s` : '') }] : []),
            { id: 'first', title: 'First seen', value: (r) => r.value[`${as}.first_time`], dir: 'desc',
                render: (r) => format.time(r.value[`${as}.first_time`]) },
            { id: 'last', title: 'Last seen', value: (r) => r.value[`${as}.last_time`], dir: 'desc',
                render: (r) => format.time(r.value[`${as}.last_time`]) },
        ],
    });

    // Related devices (shared hardware) by key; one request looks them all up
    const relatedFields = [
        `${base}.key`, `${base}.macaddr`, `${base}.commonname`, `${base}.type`, `${base}.manuf`, `${base}.last_time`,
        [`${d}/${d}.last_beaconed_ssid_record/${as}.ssid`, 'last_ssid'],
    ];
    const relatedTable = (id, path) => ({
        id: `${id}_table`, wide: true, field: path,
        draw: (cell, map, _rec, state) => {
            state.keys = Object.values(map ?? {});
            if (state.table)
                return;
            state.table = kismet.widgets.listTable({
                id: `dot11-${id}`,
                load: async () => Object.values(await api.post('devices/multikey/as-object/devices.json',
                    { devices: state.keys, fields: relatedFields }) ?? {}),
                search: 'Search MAC, name, SSID, or manufacturer',
                empty: 'None.',
                defaultSort: { column: 'last', dir: 'desc' },
                columns: [
                    { id: 'mac', title: 'MAC', value: (r) => r[`${base}.macaddr`],
                        render: (r) => deviceLink(r[`${base}.key`], r[`${base}.macaddr`]) },
                    { id: 'name', title: 'Name', value: (r) => (r[`${base}.commonname`] !== r[`${base}.macaddr`] ? r[`${base}.commonname`] : '') },
                    { id: 'ssid', title: 'SSID', value: (r) => ssidSort(r.last_ssid) },
                    { id: 'type', title: 'Type', value: (r) => r[`${base}.type`] },
                    { id: 'manuf', title: 'Manufacturer', value: (r) => r[`${base}.manuf`] },
                    { id: 'last', title: 'Last seen', value: (r) => r[`${base}.last_time`], dir: 'desc',
                        render: (r) => format.time(r[`${base}.last_time`]) },
                ],
            });
            cell.replaceChildren(state.table.node);
        },
    });

    // One access point this device has been a client of
    const clientOfFields = [
        { id: 'ap', title: 'Access point', field: `${cl}.bssid_key`,
            format: (key) => (key && key !== '0' ? deviceLink(key, 'View access point') : muted('No record of this access point')) },
        { title: 'BSSID', field: `${cl}.bssid`, format: copyable },
        { id: 'ap_name', title: 'Name', field: `${cl}.bssid_key`,
            draw: (cell, key) => relatedText(cell, key, (dev) => dev['kismet.device.base.commonname'] || muted('None')) },
        { id: 'ap_ssid', title: 'Last SSID', field: `${cl}.bssid_key`,
            draw: (cell, key) => relatedText(cell, key, (dev) => ssidText(dev.last_ssid)) },
        { title: 'First connected', field: `${cl}.first_time`, format: format.time },
        { title: 'Last connected', field: `${cl}.last_time`, format: format.time },
        { title: 'Data', field: `${cl}.datasize`, format: format.size },
        { title: 'Retried data', field: `${cl}.datasize_retry`, format: format.size },
        {
            group: 'DHCP',
            show: (c) => !!c[`${cl}.dhcp_host`],
            fields: [
                { title: 'DHCP hostname', field: `${cl}.dhcp_host`, empty: muted('Unknown'),
                    help: 'From DHCP packets, Kismet can learn the hostname a client asks for and its operating system or vendor.' },
                { title: 'DHCP vendor', field: `${cl}.dhcp_vendor`, hideEmpty: true, empty: muted('Unknown') },
            ],
        },
        { title: 'EAP identity', field: `${cl}.eap_identity`, hideEmpty: true,
            help: 'When a client joins a WPA-Enterprise network, Kismet may see its EAP identity: possibly the user\'s login, or empty or "anonymous" for networks with a second login step, like WPA-PEAP.' },
        {
            group: 'CDP',
            show: (c) => !!c[`${cl}.cdp_device`],
            fields: [
                { title: 'CDP device', field: `${cl}.cdp_device`,
                    help: 'Clients bridged to a wired network may leak Cisco Discovery Protocol (CDP) packets, which can reveal details of the wired network.' },
                { title: 'CDP port', field: `${cl}.cdp_port`, hideEmpty: true, empty: muted('Unknown') },
            ],
        },
        {
            group: 'IP',
            show: (c) => !!api.field(c, `${cl}.ipdata/kismet.common.ipdata.address`),
            fields: [
                { title: 'IP address', field: `${cl}.ipdata/kismet.common.ipdata.address`,
                    help: 'Kismet works out the addresses in use on a network from the traffic it sees and from DHCP answers.' },
                { title: 'Netmask', field: `${cl}.ipdata/kismet.common.ipdata.netmask`,
                    format: (v) => v || muted('Unknown') },
                { title: 'Gateway', field: `${cl}.ipdata/kismet.common.ipdata.gateway`,
                    format: (v) => v || muted('Unknown') },
            ],
        },
    ];

    const beaconRec = `${d}/${d}.last_beaconed_ssid_record`;
    const probeRec = `${d}/${d}.last_probed_ssid_record`;

    ui.deviceDetails.add({
        id: 'dot11', title: 'Wi-Fi (802.11)', priority: 5,
        match: (dev) => dev[`${base}.phyname`] === phy,
        fields: [
            { title: 'Last beaconed SSID', field: `${beaconRec}/${as}.ssid`,
                format: (v, dev) => ssidText(v, api.field(dev, beaconRec)),
                help: 'The last network name this device advertised as an access point, in a beacon or a probe response.' },
            { title: 'Last probed SSID', field: `${probeRec}/${ps}.ssid`,
                format: (v) => (v === '' ? muted('Broadcast') : ssidText(v)),
                help: 'The last network name this device asked for as a client looking for a network.' },
            { title: 'Last BSSID', field: `${d}/${d}.last_bssid`, show: notZeroMac, format: copyable,
                help: 'The BSSID (MAC address) of the last network this device was part of.  Every access point has its own BSSID, even ones sharing an SSID.' },
            { title: 'Uptime', field: `${d}/${d}.bss_timestamp`, hideZero: true, format: uptime,
                help: 'Access points send a high-precision timestamp that shows roughly how long they\'ve been running.  It usually resets when the access point restarts.' },

            {
                group: 'Fingerprints',
                fields: [
                    { title: 'Beacon', field: `${d}/${d}.beacon_fingerprint`, empty: muted('None'),
                        format: (v) => (v ? String(v) : muted('None')),
                        help: 'Kismet builds a fingerprint from the attributes in a device\'s beacons.  It\'s used to spot spoofed devices and for allow lists.' },
                ],
            },

            {
                group: 'Packets',
                fields: [
                    {
                        id: 'packet_types', wide: true,
                        value: (dev) => [
                            dev[`${base}.packets.llc`] ?? 0, dev[`${base}.packets.data`] ?? 0,
                            api.field(dev, `${d}/${d}.num_retries`, 0), api.field(dev, `${d}/${d}.num_fragments`, 0),
                        ],
                        draw: (cell, values, _rec, state) => {
                            if (!state.graph) {
                                state.graph = kismet.widgets.historyGraph({ type: 'bar', title: 'Packets by kind', height: '7rem' });
                                cell.replaceChildren(state.graph.node);
                            }
                            state.graph.draw(values, ['Management', 'Data', 'Retried', 'Fragmented']);
                        },
                    },
                    { title: 'Total', field: `${base}.packets.total`, format: count,
                        help: 'Every packet seen from this device, of all kinds.' },
                    { title: 'Management', field: `${base}.packets.llc`, format: count,
                        help: 'Management packets (beacons, probes, and the like) set up and run Wi-Fi networks.  Access points send a lot of them.' },
                    { title: 'Data', field: `${base}.packets.data`, format: count,
                        help: 'Data packets carry what the device is actually sending.' },
                    { title: 'Errors', field: `${base}.packets.error`, format: count,
                        help: 'Packets damaged in the air or otherwise invalid.' },
                    { title: 'Fragmented', field: `${d}/${d}.num_fragments`, format: count,
                        help: 'Data split into smaller packets.  Usually unwanted, because it adds overhead and latency.' },
                    { title: 'Retried', field: `${d}/${d}.num_retries`, format: count,
                        help: 'Packets sent again because the first try was lost to weak signal, interference, or collisions.  Lots of retries means a poor connection.' },
                    { title: 'Data size', field: `${d}/${d}.datasize`, format: format.size,
                        help: 'How much data this device has sent.' },
                    { title: 'Retried data', field: `${d}/${d}.datasize_retry`, format: format.size,
                        help: 'How much data was sent again after being lost.' },
                ],
            },

            {
                group: 'Additional capabilities',
                show: (dev) => api.field(dev, `${d}/${d}.min_tx_power`, 0) !== 0 ||
                    api.field(dev, `${d}/${d}.max_tx_power`, 0) !== 0 ||
                    (api.field(dev, `${d}/${d}.supported_channels`) ?? []).length > 0,
                help: 'Some devices describe their abilities in extra tags when joining a network.',
                fields: [
                    { title: 'Minimum TX power', field: `${d}/${d}.min_tx_power`, hideZero: true, format: dbm,
                        help: 'The lowest transmit power the device claims, from IE 33 in its association request.  A hostile device could fake it.' },
                    { title: 'Maximum TX power', field: `${d}/${d}.max_tx_power`, hideZero: true, format: dbm,
                        help: 'The highest transmit power the device claims, from IE 33 in its association request.  A hostile device could fake it.' },
                    { title: 'Supported channels', field: `${d}/${d}.supported_channels`,
                        show: (v) => Array.isArray(v) && v.length > 0, format: (v) => v.join(', '),
                        help: 'The 5 GHz channels the device says it supports (IE 36) when joining a network.  2.4 GHz channels aren\'t listed.' },
                ],
            },

            {
                group: 'Ubiquiti AirMAX / MikroTik',
                show: (dev) => [`${beaconRec}/${as}.airmax_variant`, `${beaconRec}/${as}.mikrotik_device_name`,
                    `${probeRec}/${ps}.airmax_variant`, `${probeRec}/${ps}.mikrotik_device_name`]
                    .some((path) => !!api.field(dev, path)),
                help: 'Ubiquiti AirMAX devices include a scrambled vendor tag describing the radio, and MikroTik devices may include their device name.  Kismet decodes AirMAX tags only when they match the sender\'s MAC.',
                fields: [
                    { title: 'AirMAX (AP)', field: `${beaconRec}/${as}.airmax_variant`, hideEmpty: true,
                        format: (v, dev) => `AirMAX ${v} (version ${api.field(dev, `${beaconRec}/${as}.airmax_version`)})`,
                        help: 'The AirMAX variant and version this device advertises as an access point.' },
                    { title: 'Radio name', field: `${beaconRec}/${as}.airmax_radioname`, hideEmpty: true },
                    { title: 'AirMAX SSID', field: `${beaconRec}/${as}.airmax_ssid`, hideEmpty: true,
                        help: 'The SSID in the AirMAX tag, which may be there even when the beaconed SSID is hidden.' },
                    { title: 'Radio MAC', field: `${beaconRec}/${as}.airmax_radio_mac`, hideEmpty: true },
                    { title: 'Capabilities', field: `${beaconRec}/${as}.airmax_cap_flags`,
                        show: (_v, dev) => !!api.field(dev, `${beaconRec}/${as}.airmax_variant`),
                        format: (v) => `0x${v.toString(16).padStart(8, '0')}` },
                    { title: 'MikroTik device (AP)', field: `${beaconRec}/${as}.mikrotik_device_name`, hideEmpty: true },
                    { title: 'AirMAX (client)', field: `${probeRec}/${ps}.airmax_variant`, hideEmpty: true,
                        format: (v, dev) => `AirMAX ${v} (version ${api.field(dev, `${probeRec}/${ps}.airmax_version`)})`,
                        help: 'The AirMAX variant and version this device sends as a client.' },
                    { title: 'Client radio name', field: `${probeRec}/${ps}.airmax_radioname`, hideEmpty: true },
                    { title: 'Client AirMAX SSID', field: `${probeRec}/${ps}.airmax_ssid`, hideEmpty: true },
                    { title: 'Firmware', field: `${probeRec}/${ps}.airmax_fwname`, hideEmpty: true },
                    { title: 'TX power', field: `${probeRec}/${ps}.airmax_txpower`, hideEmpty: true, hideZero: true,
                        help: 'The transmit power in the AirMAX tag, in the device\'s own units.' },
                    { title: 'Chains', field: `${probeRec}/${ps}.airmax_tx_chainmask`,
                        show: (_v, dev) => !!api.field(dev, `${probeRec}/${ps}.airmax_variant`),
                        format: (v, dev) => `TX 0x${v.toString(16)}, RX 0x${api.field(dev, `${probeRec}/${ps}.airmax_rx_chainmask`, 0).toString(16)}`,
                        help: 'The transmit and receive antenna chains in the AirMAX tag.' },
                    { title: 'MikroTik device (client)', field: `${probeRec}/${ps}.mikrotik_device_name`, hideEmpty: true },
                ],
            },

            {
                group: 'Wi-Fi events',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.wpa_handshake_list`)) ||
                    !!api.field(dev, `${d}/${d}.pmkid_packet`) || api.field(dev, `${d}/${d}.wps_m3_count`, 0) > 0 ||
                    api.field(dev, `${d}/${d}.client_disconnects`, 0) > 0,
                help: 'When things happened to this device: handshake messages with each client, the RSN PMKID, WPS M3 messages and disconnects (Kismet keeps how many and the last one), and alerts that name the device.  A burst of disconnects or alerts usually means a deauthentication attack; a full set of handshake messages means the handshake was captured.  Hover over a mark for details.',
                fields: [
                    {
                        id: 'wifi_events', wide: true,
                        value: (dev) => dev,
                        draw: (cell, dev, _rec, state) => {
                            if (!state.events) {
                                state.events = deviceEvents(dev);
                                cell.replaceChildren(state.events.node);
                            } else {
                                state.events.update(dev);
                            }
                        },
                    },
                ],
            },

            {
                group: 'WPA handshakes',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.wpa_handshake_list`)),
                help: 'When a client joins a WPA network, it trades four packets with the access point (the handshake) to set up the session key.  Decrypting the traffic or recovering the password needs the handshake.  Kismet saves the handshake packets so they can be downloaded as a pcap file.',
                fields: [
                    {
                        list: `${d}/${d}.wpa_handshake_list`,
                        itemTitle: (_packets, mac) => `Client ${mac}`,
                        fields: [
                            { title: 'Messages seen', value: (packets) => handshakeMessages(packets),
                                format: (seen) => [1, 2, 3, 4].filter((n) => seen & (1 << n)).join(' '),
                                help: 'Which of the four handshake packets Kismet captured.' },
                            {
                                title: 'Handshake pcap',
                                value: (packets) => handshakeMessages(packets),
                                draw: (cell, seen, _packets, state, dev) => {
                                    // The client's MAC is the list key; find it from the device's list
                                    const list = api.field(dev, `${d}/${d}.wpa_handshake_list`) ?? {};
                                    const mac = Object.keys(list).find((m) => list[m] === _packets);
                                    const key = `${mac}:${seen}`;
                                    if (state.key === key)
                                        return undefined;
                                    state.key = key;
                                    // All four messages are bits 1-4: 0b11110
                                    return el('div', {},
                                        // The server doesn't decode the path, so the MAC goes in as is
                                        /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/.test(mac ?? '') ?
                                            download(`phy/phy80211/by-key/${encodeURIComponent(dev[`${base}.key`])}/device/${mac}/pcap/handshake.pcap`,
                                                'Download pcap file') : muted('Unknown client'),
                                        seen !== 30 ? el('div', { class: 'form-error' },
                                            'Not all four handshake packets have been seen.  A partial handshake may still be usable.') : null);
                                },
                            },
                        ],
                    },
                ],
            },

            {
                group: 'WPA RSN PMKID',
                show: (dev) => !!api.field(dev, `${d}/${d}.pmkid_packet`),
                help: 'Some access points reveal the RSN PMKID at the start of authentication.  Tools like Aircrack-NG or Hashcat can use it to attack the password.  When Kismet sees one, it can provide a pcap file.',
                fields: [
                    { title: 'PMKID pcap', value: (dev) => dev[`${base}.key`],
                        format: (key) => download(`phy/phy80211/by-key/${encodeURIComponent(key)}/pcap/handshake-pmkid.pcap`, 'Download pcap file') },
                ],
            },

            {
                group: 'Probed SSIDs',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.probed_ssid_map`)),
                help: 'Clients send probe requests for networks they want to join: either broadcast probes asking any network nearby to answer, or probes for one network the client has used before.  Modern clients usually only send broadcast probes.',
                fields: [
                    mapTable('probed', `${d}/${d}.probed_ssid_map`, {
                        search: 'Search SSID',
                        empty: 'None.',
                        defaultSort: { column: 'last', dir: 'desc' },
                        rowKey: (r) => r.key,
                        detail: (r, el) => ui.detailFields(el, r.value, probedFields),
                        columns: [
                            { id: 'ssid', title: 'SSID', value: (r) => r.value[`${ps}.ssid`] || '',
                                render: (r) => (r.value[`${ps}.ssid`] ? ssidText(r.value[`${ps}.ssid`]) : muted('Broadcast')) },
                            { id: 'mfp', title: 'MFP', value: (r) => (r.value[`${ps}.wpa_mfp_required`] ? 'Required' : (r.value[`${ps}.wpa_mfp_supported`] ? 'Supported' : '')) },
                            { id: 'wps', title: 'WPS device', value: (r) => r.value[`${ps}.wps_device_name`] || '' },
                            { id: 'first', title: 'First seen', value: (r) => r.value[`${ps}.first_time`], dir: 'desc',
                                render: (r) => format.time(r.value[`${ps}.first_time`]) },
                            { id: 'last', title: 'Last seen', value: (r) => r.value[`${ps}.last_time`], dir: 'desc',
                                render: (r) => format.time(r.value[`${ps}.last_time`]) },
                        ],
                    }),
                ],
            },

            {
                group: 'Advertised SSIDs',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.advertised_ssid_map`)),
                help: 'One BSSID can advertise several SSIDs, by changing its name over time or by hosting several networks on one radio address.  Most modern access points with several SSIDs use a separate MAC for each one.  These SSIDs were seen in the access point\'s beacons.',
                fields: [
                    advertisedTable('advertised', `${d}/${d}.advertised_ssid_map`, true),
                ],
            },

            {
                group: 'Responded SSIDs',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.responded_ssid_map`)),
                help: 'SSIDs the access point named when answering probe requests.  Normally an access point only answers for SSIDs it also advertises.',
                fields: [
                    advertisedTable('responded', `${d}/${d}.responded_ssid_map`, false),
                ],
            },

            {
                group: 'Shared hardware (uptime)',
                show: (dev) => hasKeys(api.field(dev, `${base}.related_devices/dot11_bssts_similar`)),
                help: 'Access points send a high-precision timestamp in their beacons.  Devices with nearly identical timestamps are usually one physical access point advertising several BSSIDs.',
                fields: [relatedTable('shared_uptime', `${base}.related_devices/dot11_bssts_similar`)],
            },

            {
                group: 'Shared hardware (WPS UUID)',
                show: (dev) => hasKeys(api.field(dev, `${base}.related_devices/dot11_uuid_e`)),
                help: 'Some devices change MAC address but keep the same WPS UUID.  These devices use the same unique ID, which is very unlikely to happen by chance.',
                fields: [relatedTable('shared_uuid', `${base}.related_devices/dot11_uuid_e`)],
            },

            {
                group: 'Wi-Fi client behavior',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.client_map`)),
                help: 'A Wi-Fi device can be a client of several networks over time, but only of one access point at a time.  Clients usually roam between access points with the same SSID.',
                fields: [
                    mapTable('client_of', `${d}/${d}.client_map`, {
                        search: 'Search BSSID, SSID, or name',
                        empty: 'None.',
                        lookups: true,
                        defaultSort: { column: 'last', dir: 'desc' },
                        rowKey: (r) => r.key,
                        detail: (r, el) => ui.detailFields(el, r.value, clientOfFields),
                        columns: [
                            { id: 'bssid', title: 'BSSID', value: (r) => r.key,
                                render: (r) => {
                                    const key = r.value[`${cl}.bssid_key`];
                                    return key && key !== '0' ? deviceLink(key, r.key) : el('span', { class: 'mono' }, r.key);
                                } },
                            { id: 'ssid', title: 'SSID', value: (r) => ssidSort(looked(r.value[`${cl}.bssid_key`])?.last_ssid) },
                            { id: 'name', title: 'Name', value: (r) => {
                                const ap = looked(r.value[`${cl}.bssid_key`]);
                                return ap && ap['kismet.device.base.commonname'] !== ap['kismet.device.base.macaddr'] ? ap['kismet.device.base.commonname'] : '';
                            } },
                            { id: 'first', title: 'First connected', value: (r) => r.value[`${cl}.first_time`], dir: 'desc',
                                render: (r) => format.time(r.value[`${cl}.first_time`]) },
                            { id: 'last', title: 'Last connected', value: (r) => r.value[`${cl}.last_time`], dir: 'desc',
                                render: (r) => format.time(r.value[`${cl}.last_time`]) },
                            { id: 'data', title: 'Data', value: (r) => r.value[`${cl}.datasize`], align: 'right', dir: 'desc',
                                render: (r) => (r.value[`${cl}.datasize`] ? format.size(r.value[`${cl}.datasize`]) : '') },
                        ],
                    }),
                ],
            },

            {
                group: 'Associated clients',
                show: (dev) => hasKeys(api.field(dev, `${d}/${d}.associated_client_map`)),
                help: 'Devices seen talking through this access point: wireless clients connected to it, or wired devices on the network behind it.  The timeline shows when each one was seen with it: each bar runs from the first to the last time, so a long bar doesn\'t mean it was there the whole time.  Green bars were seen in the last minute.',
                fields: [
                    {
                        id: 'client_timeline', wide: true,
                        value: (dev) => dev[`${base}.key`],
                        draw: (cell, apKey, _rec, state) => {
                            if (state.timeline)
                                return;
                            state.timeline = clientTimeline(apKey);
                            cell.replaceChildren(state.timeline.node);
                        },
                    },
                    {
                        // A table rather than a list: access points can have thousands of clients
                        id: 'client_table', wide: true,
                        value: (dev) => dev[`${base}.key`],
                        draw: (cell, apKey, _rec, state) => {
                            if (state.table)
                                return;
                            state.table = clientTable(apKey);
                            cell.replaceChildren(state.table.node);
                        },
                    },
                ],
            },
        ],
    });

    // Every SSID seen, as a tab next to the device list
    const sg = 'dot11.ssidgroup';
    ui.addTable({
        id: 'ssids', title: 'SSIDs', area: 'main', priority: 20,
        endpoint: 'phy/phy80211/ssids/views/ssids.json',
        noun: 'SSIDs',
        rowKey: (r) => r[`${sg}.hash`],
        onRowClick: (r) => openSsid(r[`${sg}.hash`]),
        alwaysFields: [`${sg}.hash`],
        defaultSort: { column: 'last_time', dir: 'desc' },
        columns: [
            { id: 'ssid', title: 'SSID', priority: 0, defaultVisible: true,
                fields: [`${sg}.ssid`, `${sg}.ssid_len`], sortField: `${sg}.ssid`,
                render: (r) => ssidText(r[`${sg}.ssid`]) },
            { id: 'crypt', title: 'Encryption', priority: 10, defaultVisible: true, width: '12em',
                fields: [`${sg}.crypt_string`], sortField: `${sg}.crypt_string`,
                render: (r) => r[`${sg}.crypt_string`] || muted('n/a') },
            { id: 'advertising', title: 'Access points', priority: 20, defaultVisible: true, width: '7em', align: 'right',
                description: 'Access points advertising this SSID',
                fields: [`${sg}.advertising_devices_len`], sortField: `${sg}.advertising_devices_len`,
                render: (r) => r[`${sg}.advertising_devices_len`] || '' },
            { id: 'responding', title: 'Responding', priority: 30, defaultVisible: true, width: '7em', align: 'right',
                description: 'Access points that answered probes for this SSID',
                fields: [`${sg}.responding_devices_len`], sortField: `${sg}.responding_devices_len`,
                render: (r) => r[`${sg}.responding_devices_len`] || '' },
            { id: 'probing', title: 'Probing', priority: 40, defaultVisible: true, width: '7em', align: 'right',
                description: 'Clients looking for this SSID',
                fields: [`${sg}.probing_devices_len`], sortField: `${sg}.probing_devices_len`,
                render: (r) => r[`${sg}.probing_devices_len`] || '' },
            { id: 'length', title: 'Length', priority: 50, width: '5em', align: 'right',
                description: 'SSID length in bytes',
                fields: [`${sg}.ssid_len`], sortField: `${sg}.ssid_len`,
                render: (r) => r[`${sg}.ssid_len`] },
            { id: 'first_time', title: 'First seen', priority: 60, defaultVisible: true, width: '11.5em',
                fields: [`${sg}.first_time`], sortField: `${sg}.first_time`,
                render: (r) => format.time(r[`${sg}.first_time`]) },
            { id: 'last_time', title: 'Last seen', priority: 70, defaultVisible: true, width: '11.5em',
                fields: [`${sg}.last_time`], sortField: `${sg}.last_time`,
                render: (r) => format.time(r[`${sg}.last_time`]) },
        ],
        highlights: [
            { id: 'open', name: 'Open networks', priority: 0, description: 'SSIDs with no encryption',
                fields: [`${sg}.crypt_set`, `${sg}.advertising_devices_len`], defaultColor: '#fab005', defaultEnabled: false,
                match: (r) => r[`${sg}.crypt_set`] === 0 && r[`${sg}.advertising_devices_len`] > 0 },
            { id: 'probed_only', name: 'Only probed for', priority: 10,
                description: 'SSIDs clients are looking for that no access point here advertises',
                fields: [`${sg}.advertising_devices_len`, `${sg}.probing_devices_len`], defaultColor: '#74c0fc', defaultEnabled: false,
                match: (r) => !r[`${sg}.advertising_devices_len`] && r[`${sg}.probing_devices_len`] > 0 },
        ],
    });

    // An SSID in its own panel: its details, and the devices advertising,
    // answering for, and probing for it, each as a searchable table
    function openSsid(hash) {
        const body = el('div', {}, el('p', { class: 'muted' }, 'Loading...'));
        const d = kismet.widgets.dialog.dialog({ title: 'SSID', body, modal: false, className: 'detail-panel' });
        api.get(`phy/phy80211/ssids/by-hash/${encodeURIComponent(hash)}/ssid.json`).then((rec) => {
            d.setTitle(rec[`${sg}.ssid`] ? `SSID ${rec[`${sg}.ssid`]}` : 'Hidden SSID');
            const devices = (title, field, help) => ({
                group: title, help,
                show: (r) => (r[field] ?? []).length > 0,
                fields: [{
                    id: `${field}_table`, wide: true, field,
                    draw: (cell, keys, _r, state) => {
                        if (state.table)
                            return;
                        state.table = kismet.widgets.listTable({
                            id: `dot11-ssid-devices`,
                            load: async () => Object.values(await api.post('devices/multikey/as-object/devices.json',
                                { devices: keys, fields: relatedFields }) ?? {}),
                            search: 'Search MAC, name, or manufacturer',
                            defaultSort: { column: 'last', dir: 'desc' },
                            columns: [
                                { id: 'mac', title: 'MAC', value: (x) => x[`${base}.macaddr`],
                                    render: (x) => deviceLink(x[`${base}.key`], x[`${base}.macaddr`]) },
                                { id: 'name', title: 'Name', value: (x) => (x[`${base}.commonname`] !== x[`${base}.macaddr`] ? x[`${base}.commonname`] : '') },
                                { id: 'type', title: 'Type', value: (x) => x[`${base}.type`] },
                                { id: 'manuf', title: 'Manufacturer', value: (x) => x[`${base}.manuf`] },
                                { id: 'last', title: 'Last seen', value: (x) => x[`${base}.last_time`], dir: 'desc',
                                    render: (x) => format.time(x[`${base}.last_time`]) },
                            ],
                        });
                        cell.replaceChildren(state.table.node);
                    },
                }],
            });
            ui.detailFields(body, rec, [
                { title: 'SSID', field: `${sg}.ssid`, format: (v) => ssidText(v) },
                { title: 'Length', field: `${sg}.ssid_len`, format: (v) => `${v} bytes` },
                { title: 'Encryption', field: `${sg}.crypt_string`, hideEmpty: true },
                { title: 'First seen', field: `${sg}.first_time`, format: format.time },
                { title: 'Last seen', field: `${sg}.last_time`, format: format.time },
                devices('Advertised by', `${sg}.advertising_devices`, 'Access points beaconing this SSID.'),
                devices('Answered by', `${sg}.responding_devices`, 'Access points that answered probe requests for this SSID.'),
                devices('Probed for by', `${sg}.probing_devices`, 'Clients that sent probe requests looking for this SSID.'),
            ]);
        }).catch((err) => body.replaceChildren(el('p', { class: 'form-error' }, `Could not load the SSID: ${err.message}`)));
    }
}
