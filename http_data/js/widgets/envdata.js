// Environmental sensor records from the server (/system/environment and the
// ENVIRONMENT event), turned into plain objects, with no DOM, so the
// Environment window, the ribbon, the overview and the data sources window
// read them the same way.
//
//   sensors(json) -> [sensor], from /system/environment, environment_current
//       or thermal
//   readings(event) -> { id: { kind, value, last_time, source } } from an
//       ENVIRONMENT event
//   sourceStaleSeconds(json) -> how old a data source's reading may get, from
//       the server's report interval
//   servedAt(list) -> when the server produced the list (server seconds), or 0
//   stale(sensor, now, sources, sourceLimit) -> '' when current, else why it isn't
//   groups(list, sources) -> [{ source, name, state, sensors }], the
//       server's own sensors first, then each data source by name
//   hottest(list, now, sources, sourceLimit) -> the hottest current thermal
//       sensor, or null
//   batteryState(b) -> 'Charging', 'Discharging', ... or ''
//
// A sensor is { id, label, kind, units, value, last_time, origin, source,
// sourceName, rrd, battery }; battery is { state, power, voltage, remaining }
// or null.  `sources` is a Map of data source uuid -> { name, running }, or
// null when the data sources weren't read.

export const env = 'kismet.system.environment';
export const sn = `${env}.sensor`;
const bn = `${env}.battery`;

export const kinds = ['thermal', 'fan', 'battery'];
export const hostUuid = '00000000-0000-0000-0000-000000000000';

// The server reads its own sensors every second.  Data sources report every
// source_report_sec seconds, so a reading is old after three missed reports;
// servers that don't say how often get the fallback
export const hostStaleSeconds = 10;
export const fallbackSourceStale = 120;
const minSourceStale = 10;

export function sourceStaleSeconds(json) {
    const r = json?.[`${env}.source_report_sec`];
    if (typeof r !== 'number' || !Number.isFinite(r) || r <= 0)
        return fallbackSourceStale;
    return Math.max(minSourceStale, 3 * r);
}

const uuidRe = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
export const validUuid = (u) => typeof u === 'string' && uuidRe.test(u);

const str = (v) => (typeof v === 'string' ? v : '');
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : NaN);

function battery(b) {
    if (!b || typeof b !== 'object')
        return null;
    const power = b[`${bn}.external_power`];
    return {
        state: str(b[`${bn}.state`]) || 'unknown',
        // 1 on external power, 0 not, -1 unknown
        power: power === 1 || power === 0 ? power : -1,
        voltage: num(b[`${bn}.voltage`]) > 0 ? b[`${bn}.voltage`] : 0,
        remaining: num(b[`${bn}.remaining`]) > 0 ? b[`${bn}.remaining`] : 0,
    };
}

function sourceOf(uuid, origin) {
    return origin === 'datasource' && validUuid(uuid) && uuid !== hostUuid ? uuid.toUpperCase() : '';
}

export function sensors(json) {
    const map = json?.[`${env}.sensors`];
    if (!map || typeof map !== 'object')
        return [];
    const out = [];
    for (const [key, s] of Object.entries(map)) {
        if (!s || typeof s !== 'object')
            continue;
        const kind = str(s[`${sn}.kind`]);
        if (!kinds.includes(kind))
            continue;
        const id = str(s[`${sn}.id`]) || key;
        const origin = str(s[`${sn}.origin`]) === 'datasource' ? 'datasource' : 'host';
        out.push({
            id,
            label: str(s[`${sn}.label`]) || id,
            kind,
            units: str(s[`${sn}.units`]),
            value: num(s[`${sn}.value`]),
            last_time: num(s[`${sn}.last_time`]) || 0,
            origin,
            source: sourceOf(s[`${sn}.source_uuid`], origin),
            sourceName: str(s[`${sn}.source_name`]),
            rrd: s[`${sn}.rrd`] && typeof s[`${sn}.rrd`] === 'object' ? s[`${sn}.rrd`] : null,
            battery: kind === 'battery' ? battery(s[`${sn}.battery`]) : null,
        });
    }
    return out;
}

export function readings(event) {
    const map = event?.[`${env}.sensors`];
    const out = {};
    if (!map || typeof map !== 'object')
        return out;
    for (const [id, r] of Object.entries(map)) {
        const kind = str(r?.[`${sn}.kind`]);
        if (!kinds.includes(kind))
            continue;
        const uuid = r[`${sn}.source_uuid`];
        out[id] = { kind, value: num(r[`${sn}.value`]), last_time: num(r[`${sn}.last_time`]) || 0,
            source: validUuid(uuid) && uuid !== hostUuid ? uuid.toUpperCase() : '' };
    }
    return out;
}

// When the server produced a list of sensors: the newest RRD serialization or
// reading, so a slow reply doesn't make every reading look old; 0 if unknown
export function servedAt(list) {
    let t = 0;
    for (const s of list) {
        const st = s.rrd?.['kismet.common.rrd.serial_time'];
        t = Math.max(t, s.last_time || 0, typeof st === 'number' && Number.isFinite(st) ? st : 0);
    }
    return t;
}

// Why a reading is no longer current, or '' when it is
export function stale(s, now, sources = null, sourceLimit = fallbackSourceStale) {
    if (s.source && sources) {
        const src = sources.get(s.source);
        if (!src)
            return 'source removed';
        if (!src.running)
            return 'source closed';
    }
    if (!Number.isFinite(s.value))
        return 'no reading';
    if (!Number.isFinite(now) || !s.last_time)
        return '';
    const limit = s.source ? sourceLimit : hostStaleSeconds;
    return now - s.last_time > limit ? 'not updated' : '';
}

const byLabel = (a, b) => String(a.label).localeCompare(String(b.label), undefined, { numeric: true });

export function groups(list, sources = null) {
    const by = new Map();
    for (const s of list) {
        if (!by.has(s.source))
            by.set(s.source, []);
        by.get(s.source).push(s);
    }
    const out = [];
    for (const [source, members] of by) {
        const src = source ? sources?.get(source) : null;
        const name = source ? (src?.name || members.find((m) => m.sourceName)?.sourceName || source) : '';
        const state = !source || !sources ? '' : !src ? 'removed' : src.running ? '' : 'closed';
        out.push({ source, name, state, sensors: members.sort(byLabel) });
    }
    return out.sort((a, b) => (!a.source ? -1 : !b.source ? 1 :
        a.name.localeCompare(b.name, undefined, { numeric: true }) || a.source.localeCompare(b.source)));
}

export function hottest(list, now, sources = null, sourceLimit = fallbackSourceStale) {
    let best = null;
    for (const s of list)
        if (s.kind === 'thermal' && Number.isFinite(s.value) && !stale(s, now, sources, sourceLimit) &&
            (!best || s.value > best.value))
            best = s;
    return best;
}

const batteryStates = {
    charging: 'Charging',
    discharging: 'Discharging',
    full: 'Full',
    not_charging: 'Not charging',
};

export const batteryState = (b) => (Object.hasOwn(batteryStates, b?.state ?? '') ? batteryStates[b.state] : '');

// A sensor's name with its data source, for lists that mix sources
export const fullLabel = (s) => (s.source && s.sourceName ? `${s.label} (${s.sourceName})` : s.label);
