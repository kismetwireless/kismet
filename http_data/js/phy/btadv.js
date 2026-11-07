// Battery, distance, beacon, connection, and decoded advertising data for BTLE and
// Bluetooth (HCI) devices.  The server keeps the same records under both phys.

const sources = ['btle.device', 'bluetooth.device'];

const batterySources = {
    apple_proximity: 'Apple Proximity Pairing',
    fast_pair: 'Google Fast Pair',
    bthome: 'BTHome',
    pvvx: 'pvvx firmware',
    eddystone_tlm: 'Eddystone TLM',
    battery_service: 'Battery Service',
    ruuvi: 'Ruuvi',
};

const rangingSources = {
    ibeacon: 'iBeacon power',
    altbeacon: 'AltBeacon power',
    eddystone: 'Eddystone power',
    ruuvi: 'Ruuvi power',
    tx_power_level: 'Advertised TX power',
};

const beaconTypes = {
    ibeacon: 'iBeacon',
    altbeacon: 'AltBeacon',
    eddystone_uid: 'Eddystone UID',
    eddystone_url: 'Eddystone URL',
};

const sensorSources = {
    ruuvi: 'Ruuvi',
    xiaomi: 'Xiaomi',
    govee: 'Govee',
    bthome: 'BTHome',
    pvvx: 'pvvx firmware',
    atc1441: 'ATC firmware',
    eddystone_tlm: 'Eddystone TLM',
};

// A labeler for service UUIDs: 'Nest Labs Inc (feaf)', or the UUID alone when it has no
// known name.  One shared name cache for every phy's details.
let labeler = null;
export function serviceLabeler(kismet) {
    if (labeler)
        return labeler;
    // Service UUID names from the server's Bluetooth ID list, looked up in batches as details
    // show them; null once a UUID has no known name.  Details redraw, so names fill in after.
    const uuidNames = new Map();
    let uuidQueue = new Set();
    let uuidTimer = null;
    const fetchUuidNames = async () => {
        const uuids = [...uuidQueue];
        uuidQueue = new Set();
        uuidTimer = null;
        let names = null;
        try {
            names = await kismet.api.post('phy/bluetooth/uuid_names.json', { uuids });
        } catch { /* an older server has no names to give */ }
        for (const u of uuids)
            uuidNames.set(u, typeof names?.[u] === 'string' ? names[u] : null);
    };
    const serviceName = (uuid) => {
        const u = String(uuid).toLowerCase();
        if (uuidNames.has(u))
            return uuidNames.get(u);
        if (uuidQueue.size < 64) {
            uuidQueue.add(u);
            uuidTimer ??= setTimeout(fetchUuidNames, 50);
        }
        return null;
    };
    const serviceLabel = (uuid) => {
        const name = serviceName(uuid);
        const hex = kismet.dom.el('span', { class: 'mono' }, uuid);
        return name ? [`${name} (`, hex, ')'] : [hex];
    };
    labeler = serviceLabel;
    return labeler;
}

export function registerBtAdv(kismet) {
    const { ui, format, icons } = kismet;
    const api = kismet.api;

    // A plain apple (the fruit) for devices sending Apple Continuity messages
    icons.define('apple', '<path d="M12 9c1.5-1.2 3-1.5 4.5-1.5 2.5 0 4 2.2 4 5.2 0 4.3-3.2 8.8-6 8.8-1 0-1.6-.5-2.5-.5s-1.5.5-2.5.5c-2.8 0-6-4.5-6-8.8 0-3 1.5-5.2 4-5.2 1.5 0 3 .3 4.5 1.5z"/>' +
        '<path d="M12 9c0-2.5.2-4.5.8-6.5"/><path d="M12.4 6.2C13.5 3.8 17 2.8 20 3.6c-1 2.6-4.5 3.6-7.6 2.6z"/>');
    const continuityFields = sources.map((s, i) =>
        [`${s}/${s}.adv/bluetooth.adv.continuity/bluetooth.adv.continuity.seen_types`, `continuity${i}`]);
    ui.deviceIcons.add({
        id: 'apple_continuity', priority: -5,
        fields: continuityFields,
        match: (row) => (continuityFields.some(([, name]) => row[name]) ?
            icons.icon('apple', 'Apple Continuity') : null),
    });

    const mono = (v) => kismet.dom.el('span', { class: 'mono' }, String(v));
    const yesno = (v) => (v ? 'Yes' : 'No');
    const words = (v) => {
        const s = String(v).replace(/_/g, ' ');
        return s.charAt(0).toUpperCase() + s.slice(1);
    };
    const named = (names) => (v) => names[v] ?? words(v);
    const hex = (digits) => (v) => mono(`0x${Number(v).toString(16).padStart(digits, '0')}`);
    const usec = (v) => `${(v / 1000).toFixed(2)} ms`;
    const percent = (v) => `${v}%`;

    // The first phy record on this device with the given child holding more than a timestamp
    const recordOf = (device, child) => {
        for (const s of sources) {
            const p = `${s}/${s}.${child}`;
            const v = api.field(device, p);
            if (v && typeof v === 'object' && Object.keys(v).some((k) => !k.endsWith('.last_time')))
                return p;
        }
        return null;
    };

    const section = (id, title, priority, child, fields) => ui.deviceDetails.add({
        id, title, priority,
        match: (device) => recordOf(device, child) !== null,
        render(device, el) {
            ui.detailFields(el, device, fields(recordOf(device, child)));
        },
    });

    section('bt_battery', 'Battery', 4, 'battery', (p) => {
        const f = (n) => `${p}/btle.device.battery.${n}`;
        const charging = { format: yesno };
        return [
            { title: 'Battery', field: f('percent'), show: (v) => v >= 0, format: percent,
                help: 'The battery level the device advertises.  It is not authenticated.' },
            { title: 'Charging', field: f('charging'), ...charging },
            { title: 'Voltage', field: f('millivolts'), format: (v) => `${(v / 1000).toFixed(3)} V` },
            { title: 'Left earbud', field: f('left_percent'), show: (v) => v >= 0, format: percent },
            { title: 'Left charging', field: f('left_charging'), ...charging },
            { title: 'Right earbud', field: f('right_percent'), show: (v) => v >= 0, format: percent },
            { title: 'Right charging', field: f('right_charging'), ...charging },
            { title: 'Case', field: f('case_percent'), show: (v) => v >= 0, format: percent },
            { title: 'Case charging', field: f('case_charging'), ...charging },
            { title: 'From', field: f('source'), hideEmpty: true, format: named(batterySources),
                help: 'The advertisement the battery level came from.' },
            { title: 'Last reported', field: f('last_time'), hideZero: true, format: format.time },
        ];
    });

    section('bt_ranging', 'Distance', 6, 'ranging', (p) => {
        const f = (n) => `${p}/btle.device.ranging.${n}`;
        return [
            { title: 'Estimated distance', field: f('distance'), show: (v) => v > 0, format: (v) => format.distance(v, 1),
                help: 'From the signal received and the power the device says it transmits.  A rough guide only: walls, bodies, and antennas easily change it by a factor of two or more.' },
            { title: 'Power at 1 m', field: f('ref_power'), format: format.signal },
            { title: 'Signal used', field: f('rssi'), format: (v) => format.signal(Math.round(v)),
                help: 'The smoothed signal the estimate is based on.' },
            { title: 'Power from', field: f('source'), hideEmpty: true, format: named(rangingSources) },
            { title: 'Last estimate', field: f('last_time'), hideZero: true, format: format.time },
        ];
    });

    section('bt_beacon', 'Beacon', 6, 'beacon', (p) => {
        const f = (n) => `${p}/btle.device.beacon.${n}`;
        return [
            { title: 'Format', field: f('type'), hideEmpty: true, format: named(beaconTypes),
                help: 'The identity a proximity beacon advertises.' },
            { title: 'UUID', field: f('uuid'), hideEmpty: true, format: mono },
            { title: 'Major', field: f('major') },
            { title: 'Minor', field: f('minor') },
            { title: 'Namespace', field: f('namespace'), hideEmpty: true, format: mono },
            { title: 'Instance', field: f('instance'), hideEmpty: true, format: mono },
            { title: 'URL', field: f('url'), hideEmpty: true },
            { title: 'Last seen', field: f('last_time'), hideZero: true, format: format.time },
        ];
    });

    section('btle_connection', 'Connection', 6, 'connection', (p) => {
        const f = (n) => `${p}/btle.device.connection.${n}`;
        return [
            { title: 'Central', field: f('central'), format: mono,
                help: 'The device that last connected to this one, from its connection request.' },
            { title: 'Access address', field: f('access_address'), format: hex(8) },
            { title: 'Interval', field: f('interval_us'), hideZero: true, format: usec },
            { title: 'Latency', field: f('latency'), format: (v) => `${v} events` },
            { title: 'Timeout', field: f('timeout_ms'), hideZero: true, format: (v) => `${v} ms` },
            { title: 'Hop increment', field: f('hop') },
            { title: 'Last connection', field: f('last_time'), hideZero: true, format: format.time },
        ];
    });

    section('bt_adv', 'Advertised data', 6, 'adv', (p) => {
        const f = (n) => `${p}/bluetooth.adv.${n}`;
        const sub = (rec, n) => `${f(rec)}/bluetooth.adv.${rec}.${n}`;
        const has = (rec) => (rec2, device) => api.field(device, f(rec)) !== undefined;
        return [
            { title: 'Company', field: `${p}/bluetooth.company_name`, hideEmpty: true,
                help: 'The company named by the manufacturer data\'s company ID.  Everything here is what the device advertises; none of it is authenticated.' },
            { title: 'Services', field: f('service_names'), show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => v.join(', ') },
            { title: 'Kind of device', field: f('service_class'), hideEmpty: true, format: words,
                help: 'The kind of device its advertised services suggest.' },
            { title: 'Vehicle', field: f('vehicle'), hideEmpty: true, format: words },
            { title: 'Device ID', field: f('device_id'), show: (v) => v && typeof v === 'object',
                format: (v) => {
                    const vendor = v['bluetooth.company_name'] ||
                        `0x${Number(v['bluetooth.adv.device_id.vendor']).toString(16).padStart(4, '0')}`;
                    return `${vendor} (${v['bluetooth.adv.device_id.vendor_source']}), product 0x` +
                        `${Number(v['bluetooth.adv.device_id.product']).toString(16).padStart(4, '0')}, ` +
                        `version ${v['bluetooth.adv.device_id.version']}`;
                },
                help: 'The vendor, product, and version from its Device ID record.' },
            { title: 'Microsoft', field: f('microsoft_device'), hideEmpty: true,
                help: 'From a Microsoft Connected Devices or Swift Pair advertisement.' },
            { title: 'Swift Pair name', field: f('swift_pair_name'), hideEmpty: true },
            { title: 'Fast Pair model', field: f('fast_pair_model'), hideEmpty: true, format: mono,
                help: 'Google Fast Pair model ID, sent while the device is pairable.' },
            { title: 'Matter', field: f('matter'), show: (v) => v && typeof v === 'object',
                format: (v) => {
                    const vendor = v['bluetooth.adv.matter.vendor_name'] ||
                        `vendor 0x${Number(v['bluetooth.adv.matter.vendor_id']).toString(16).padStart(4, '0')}`;
                    return `${vendor}, product 0x${Number(v['bluetooth.adv.matter.product_id']).toString(16).padStart(4, '0')}, ` +
                        `discriminator ${v['bluetooth.adv.matter.discriminator']}` +
                        (v['bluetooth.adv.matter.extended_announcement'] ? ', extended announcement' : '');
                },
                help: 'A Matter device waiting to be commissioned.' },
            { title: 'Sensor', field: f('sensor'), show: (v) => v && typeof v === 'object',
                format: (v) => {
                    const parts = [];
                    if ('bluetooth.adv.sensor.temperature' in v)
                        parts.push(`${v['bluetooth.adv.sensor.temperature'].toFixed(2)} °C`);
                    if ('bluetooth.adv.sensor.humidity' in v)
                        parts.push(`${v['bluetooth.adv.sensor.humidity'].toFixed(1)}% RH`);
                    if ('bluetooth.adv.sensor.pressure' in v)
                        parts.push(`${v['bluetooth.adv.sensor.pressure'].toFixed(1)} hPa`);
                    if ('bluetooth.adv.sensor.battery_mv' in v)
                        parts.push(`${(v['bluetooth.adv.sensor.battery_mv'] / 1000).toFixed(3)} V`);
                    const src = v['bluetooth.adv.sensor.source'];
                    return `${parts.join(', ')}${src ? ` (${sensorSources[src] ?? src})` : ''}`;
                },
                help: 'Environmental readings the device broadcasts.' },
            { title: 'Indoor position', field: f('indoor'), show: (v) => v && typeof v === 'object',
                format: (v) => {
                    const parts = [];
                    if ('bluetooth.adv.indoor.latitude' in v)
                        parts.push(kismet.censor.hidesMaps() ? 'location hidden' :
                            `${v['bluetooth.adv.indoor.latitude'].toFixed(6)}, ${v['bluetooth.adv.indoor.longitude'].toFixed(6)}`);
                    if ('bluetooth.adv.indoor.north_dm' in v)
                        parts.push(`${v['bluetooth.adv.indoor.north_dm'] / 10} m N, ${v['bluetooth.adv.indoor.east_dm'] / 10} m E`);
                    if ('bluetooth.adv.indoor.floor' in v)
                        parts.push(`floor ${v['bluetooth.adv.indoor.floor']}`);
                    if ('bluetooth.adv.indoor.altitude_dm' in v)
                        parts.push(format.height(v['bluetooth.adv.indoor.altitude_dm'] / 10, 1));
                    if (v['bluetooth.adv.indoor.mobile'])
                        parts.push('mobile');
                    return parts.join(', ');
                },
                help: 'The location an Indoor Positioning beacon advertises.' },
            { title: 'URI', field: f('uri'), hideEmpty: true },
            { title: 'Transports', field: f('transports'), hideEmpty: true },
            { title: 'LE role', field: f('le_role'), hideEmpty: true },
            { title: 'Advertising interval', field: f('adv_interval_us'), hideZero: true, format: usec },
            { title: 'Preferred interval',
                value: (dev) => {
                    const lo = api.field(dev, f('conn_interval_min_us'));
                    const hi = api.field(dev, f('conn_interval_max_us'));
                    return lo || hi ? [lo, hi] : undefined;
                },
                format: (v) => `${usec(v[0] ?? 0)} to ${usec(v[1] ?? 0)}`,
                help: 'The connection interval range the device asks for.' },
            { title: 'LE features', field: f('le_features'), hideEmpty: true, format: mono },
            {
                group: 'Apple Continuity', show: has('continuity'),
                help: 'Messages Apple devices broadcast for Handoff, AirDrop, Nearby, HomeKit, setup, AirPods pairing and Find My.',
                fields: [
                    { title: 'Messages', field: sub('continuity', 'messages'), hideEmpty: true },
                    { title: 'Activity', field: sub('continuity', 'activity'), hideEmpty: true, format: words },
                    { title: 'Wi-Fi on', field: sub('continuity', 'wifi_on'), format: yesno },
                    { title: 'AirDrop receiving', field: sub('continuity', 'airdrop_receiving'), format: yesno },
                    { title: 'Action', field: sub('continuity', 'nearby_action'), hideEmpty: true, format: words },
                    { title: 'Setting up', field: sub('continuity', 'setup_device'), hideEmpty: true, format: words },
                    { title: 'HomeKit accessory', field: sub('continuity', 'homekit.category'), hideEmpty: true, format: words },
                    { title: 'HomeKit ID', field: sub('continuity', 'homekit.device_id'), hideEmpty: true, format: mono },
                    { title: 'HomeKit paired', field: sub('continuity', 'homekit.paired'), format: yesno },
                    { title: 'AirPlay address', field: sub('continuity', 'airplay_ipv4'), hideEmpty: true, format: mono },
                    { title: 'AirPrint address', field: sub('continuity', 'airprint_address'), hideEmpty: true, format: mono },
                    { title: 'Hotspot network', field: sub('continuity', 'hotspot.network'), hideEmpty: true },
                    { title: 'Hotspot signal', field: sub('continuity', 'hotspot.signal_bars'), format: (v) => `${v} bars` },
                    { title: 'Hotspot battery', field: sub('continuity', 'hotspot.battery'), format: percent },
                    { title: 'Last message', field: sub('continuity', 'last_time'), hideZero: true, format: format.time },
                ],
            },
            {
                group: 'Bluetooth mesh', show: has('mesh'),
                fields: [
                    { title: 'Beacon', field: sub('mesh', 'beacon'), hideEmpty: true, format: words },
                    { title: 'Network ID', field: sub('mesh', 'network_id'), hideEmpty: true, format: mono },
                    { title: 'IV index', field: sub('mesh', 'iv_index') },
                    { title: 'Key refresh', field: sub('mesh', 'key_refresh'), format: yesno },
                    { title: 'IV update', field: sub('mesh', 'iv_update'), format: yesno },
                    { title: 'Proxy', field: sub('mesh', 'proxy'), hideEmpty: true, format: words },
                    { title: 'Unprovisioned UUID', field: sub('mesh', 'device_uuid'), hideEmpty: true, format: mono },
                    { title: 'OOB information', field: sub('mesh', 'oob_info'), hideEmpty: true },
                    { title: 'Sends messages', field: sub('mesh', 'message'), format: yesno },
                ],
            },
            {
                group: 'LE Audio', show: has('audio'),
                fields: [
                    { title: 'Broadcast', field: sub('audio', 'broadcast_name'), hideEmpty: true },
                    { title: 'Broadcast ID', field: sub('audio', 'broadcast_id'), hideEmpty: true, format: mono },
                    { title: 'Program', field: sub('audio', 'program_info'), hideEmpty: true },
                    { title: 'Language', field: sub('audio', 'language'), hideEmpty: true },
                    { title: 'Quality', field: sub('audio', 'quality'), hideEmpty: true, format: words },
                    { title: 'Encrypted', field: sub('audio', 'encrypted'), format: yesno },
                    { title: 'Unicast', field: sub('audio', 'unicast'), hideEmpty: true },
                    { title: 'Sink contexts', field: sub('audio', 'sink_contexts'), hideEmpty: true },
                    { title: 'Source contexts', field: sub('audio', 'source_contexts'), hideEmpty: true },
                    { title: 'Coordinated set', field: sub('audio', 'set_id'), hideEmpty: true, format: mono,
                        help: 'Earbuds, hearing aids and other devices that work as a set share this identifier.' },
                ],
            },
            { title: 'Last advertised data', field: f('last_time'), hideZero: true, format: format.time },
        ];
    });
}
