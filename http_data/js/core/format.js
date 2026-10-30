// Turning raw values from Kismet into readable text.

import * as settings from './settings.js';

// Display units, chosen in Settings.  Kismet keeps speeds in km/h and
// lengths in meters.
export const speedUnits = [
    { id: 'kmh', title: 'km/h', per: 1 },
    { id: 'mph', title: 'mph', per: 1 / 1.609344 },
    { id: 'knots', title: 'knots', per: 1 / 1.852 },
];
export const lengthUnits = [
    { id: 'metric', title: 'Meters and kilometers' },
    { id: 'imperial', title: 'Feet and miles' },
];

const unitOf = (list, key) => list.find((u) => u.id === settings.get(key)) ?? list[0];
let speedUnit = unitOf(speedUnits, 'units.speed');
let imperial = unitOf(lengthUnits, 'units.length').id === 'imperial';
settings.watch('units.speed', () => { speedUnit = unitOf(speedUnits, 'units.speed'); });
settings.watch('units.length', () => { imperial = unitOf(lengthUnits, 'units.length').id === 'imperial'; });

export const isImperial = () => imperial;

const fixed = (v, digits) => v.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits });
const upTo = (v, digits) => v.toLocaleString(undefined, { maximumFractionDigits: digits });
const finite = (v) => Number.isFinite(Number(v));

// A speed in km/h
export function speed(kmh, digits = 1) {
    if (!finite(kmh))
        return '-';
    return `${fixed(Number(kmh) * speedUnit.per, digits)} ${speedUnit.title}`;
}

// A height or altitude in meters, as meters or (whole) feet; altitudes read
// in one unit, so they aren't scaled to kilometers or miles
export function height(m, digits = 0) {
    if (!finite(m))
        return '-';
    return imperial ? `${fixed(Number(m) / 0.3048, 0)} ft` : `${fixed(Number(m), digits)} m`;
}

// A distance in meters: meters or feet up close, kilometers or miles further
export function distance(m, digits = 0) {
    if (!finite(m))
        return '-';
    m = Number(m);
    if (imperial) {
        const ft = m / 0.3048;
        if (Math.abs(ft) < 1000)
            return `${upTo(ft, digits)} ft`;
        const mi = m / 1609.344;
        return `${upTo(mi, Math.abs(mi) < 1 ? 2 : Math.abs(mi) < 100 ? 1 : 0)} mi`;
    }
    if (Math.abs(m) < 1000)
        return `${upTo(m, digits)} m`;
    return `${upTo(m / 1000, Math.abs(m) < 100000 ? 1 : 0)} km`;
}

// A climb or descent in m/s, per minute
export function verticalSpeed(ms) {
    if (!finite(ms))
        return '-';
    return imperial ? `${fixed(Number(ms) * 60 / 0.3048, 0)} ft/min` : `${fixed(Number(ms) * 60, 0)} m/min`;
}

export function size(bytes) {
    if (!Number.isFinite(bytes))
        return '-';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }
    return `${bytes.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function count(n) {
    if (!Number.isFinite(n))
        return '-';
    if (n >= 1e6)
        return `${(n / 1e6).toFixed(1)}M`;
    if (n >= 1e4)
        return `${(n / 1e3).toFixed(1)}k`;
    return n.toLocaleString();
}

// A frequency in kHz, as Kismet reports them, to four digits: 5.200 GHz,
// 2.412 GHz, 433.9 MHz
export function frequency(khz) {
    if (!khz)
        return '-';
    if (khz >= 1e6)
        return `${(khz / 1e6).toPrecision(4)} GHz`;
    if (khz >= 1e3)
        return `${(khz / 1e3).toPrecision(4)} MHz`;
    return `${Number(khz).toPrecision(4)} kHz`;
}

const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const two = (n) => String(n).padStart(2, '0');

// Unix seconds to local time, e.g. "Oct 21 2026 13:57:16"
export function time(sec) {
    if (!sec)
        return '-';
    const d = new Date(sec * 1000);
    return `${months[d.getMonth()]} ${two(d.getDate())} ${d.getFullYear()} ` +
        `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
}

// Unix seconds to a local clock time, e.g. "13:57"
export function clock(sec) {
    const d = new Date(sec * 1000);
    return `${two(d.getHours())}:${two(d.getMinutes())}`;
}

// How long ago, e.g. "4s", "12m", "3h", "2d"
export function ago(sec, now = Date.now() / 1000) {
    if (!sec)
        return '-';
    const s = Math.max(0, Math.round(now - sec));
    if (s < 60)
        return `${s}s`;
    if (s < 3600)
        return `${Math.floor(s / 60)}m`;
    if (s < 86400)
        return `${Math.floor(s / 3600)}h`;
    return `${Math.floor(s / 86400)}d`;
}

export function duration(sec) {
    sec = Math.max(0, Math.round(sec));
    const d = Math.floor(sec / 86400);
    const h = Math.floor(sec / 3600) % 24;
    const m = Math.floor(sec / 60) % 60;
    if (d)
        return `${d}d ${h}h`;
    if (h)
        return `${h}h ${m}m`;
    return `${m}m ${sec % 60}s`;
}

// Kismet uses 0 for "no signal recorded"
export function signal(dbm) {
    if (!dbm)
        return '-';
    return `${dbm} dBm`;
}
