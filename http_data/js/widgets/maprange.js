// Receiver range: for devices that report their own position (aircraft,
// vessels, mesh nodes), how far from Kismet each one was when it was heard,
// kept by direction.  The furthest distance in each 2° of bearing makes the
// outline of what the receiver covers, drawn around where Kismet is now.
//
// The browser keeps the outline for each server and kind of device, so it
// survives reloads; a mobile receiver's outline is its range around itself,
// wherever it has been.

import * as settings from '../core/settings.js';

const binDeg = 2;
export const bins = 360 / binDeg;
const fillGap = 3;                  // empty directions up to this many wide are filled from their neighbors
const groups = [1, 2, 3, 5, 9, 15];  // bins drawn as one direction, finest first
const minFilled = 0.6;              // share of directions with a distance before an outline is that fine
const saveMs = 30000;
const maxDevices = 20000;           // last samples kept for the glitch check
const earth = 6371000;
const rad = Math.PI / 180;

// Bearing (degrees from north) and distance (m) from a to b, both [lon, lat]
export function bearingDistance(a, b) {
    const [lon1, lat1] = [a[0] * rad, a[1] * rad];
    const [lon2, lat2] = [b[0] * rad, b[1] * rad];
    const dlon = lon2 - lon1;
    const h = Math.sin((lat2 - lat1) / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dlon / 2) ** 2;
    const distance = 2 * earth * Math.asin(Math.min(1, Math.sqrt(h)));
    const y = Math.sin(dlon) * Math.cos(lat2);
    const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dlon);
    return { bearing: (Math.atan2(y, x) / rad + 360) % 360, distance };
}

// The [lat, lng] at a bearing and distance from [lon, lat]
export function destination(from, bearing, distance) {
    const lat1 = from[1] * rad, lon1 = from[0] * rad, b = bearing * rad, d = distance / earth;
    const lat2 = Math.asin(Math.sin(lat1) * Math.cos(d) + Math.cos(lat1) * Math.sin(d) * Math.cos(b));
    const lon2 = lon1 + Math.atan2(Math.sin(b) * Math.sin(d) * Math.cos(lat1), Math.cos(d) - Math.sin(lat1) * Math.sin(lat2));
    return [lat2 / rad, ((lon2 / rad + 540) % 360) - 180];
}

function blank() {
    return { bins: new Array(bins).fill(0), samples: 0, center: null };
}

function valid(rec) {
    return rec && Array.isArray(rec.bins) && rec.bins.length === bins &&
        rec.bins.every((v) => Number.isFinite(v) && v >= 0);
}

// One store per server: key names it in the settings
export function createRangeStore(key) {
    const settingKey = `map.range.${key}`;
    const data = new Map();          // source id -> { bins, samples, center }
    const lastSample = new Map();    // device key -> { bin, distance }
    let dirty = false;
    let saveTimer = null;

    const saved = settings.get(settingKey, null);
    for (const [id, rec] of Object.entries(saved?.sources ?? {})) {
        if (!valid(rec))
            continue;
        const center = Array.isArray(rec.center) && rec.center.length === 2 && rec.center.every(Number.isFinite) ?
            rec.center : null;
        data.set(id, { bins: rec.bins.slice(), samples: Number(rec.samples) || 0, center });
    }

    function save() {
        saveTimer = null;
        if (!dirty)
            return;
        dirty = false;
        const sources = {};
        for (const [id, rec] of data)
            sources[id] = { bins: rec.bins.map(Math.round), samples: rec.samples, center: rec.center };
        settings.set(settingKey, { sources });
    }

    function changed() {
        dirty = true;
        if (!saveTimer)
            saveTimer = setTimeout(save, saveMs);
    }

    return {
        // A device at rep, heard by Kismet at heard (both [lon, lat]).  A
        // distance only counts when the device's previous sample agrees with
        // it, so one bad position decode can't stretch the outline.
        record(srcId, devKey, heard, rep, limit) {
            if (!heard || !rep || !devKey)
                return;
            const { bearing, distance } = bearingDistance(heard, rep);
            if (!Number.isFinite(distance) || distance < 1 || distance > limit)
                return;
            const bin = Math.floor(bearing / binDeg) % bins;
            const prev = lastSample.get(devKey);
            if (lastSample.size >= maxDevices && !prev)
                lastSample.clear();
            lastSample.set(devKey, { bin, distance });
            const near = prev && Math.min((bin - prev.bin + bins) % bins, (prev.bin - bin + bins) % bins) <= 1 &&
                Math.abs(distance - prev.distance) <= Math.max(2000, distance * 0.2);
            let rec = data.get(srcId);
            if (!rec) {
                rec = blank();
                data.set(srcId, rec);
            }
            const c = rec.center;
            if (!c || c[0] !== heard[0] || c[1] !== heard[1]) {
                rec.center = [heard[0], heard[1]];
                changed();
            }
            if (!near)
                return;
            rec.samples++;
            if (distance > rec.bins[bin]) {
                rec.bins[bin] = distance;
                changed();
            }
        },

        has(srcId) {
            return (data.get(srcId)?.samples ?? 0) > 0;
        },

        get(srcId) {
            return data.get(srcId) ?? null;
        },

        // The outline: { step, dist }, a distance every step degrees with
        // short gaps filled in.  Until enough directions have been heard
        // from, it's drawn in coarser steps, so it fills in as it sharpens.
        outline(srcId) {
            const rec = data.get(srcId);
            if (!rec)
                return null;
            let out = null, size = 1;
            for (const g of groups) {
                size = g;
                const n = Math.floor(bins / g);
                out = new Array(n).fill(0);
                rec.bins.forEach((v, i) => {
                    const k = Math.min(Math.floor(i / g), n - 1);
                    out[k] = Math.max(out[k], v);
                });
                if (out.filter((v) => v > 0).length >= n * minFilled)
                    break;
            }
            const n = out.length;
            const filled = out.map((v, i) => (v > 0 ? i : -1)).filter((i) => i >= 0);
            if (filled.length < 3)
                return null;
            for (let k = 0; k < filled.length; k++) {
                const a = filled[k], b = filled[(k + 1) % filled.length];
                const gap = (b - a + n) % n || n;
                if (gap <= 1 || gap - 1 > fillGap)
                    continue;
                for (let j = 1; j < gap; j++)
                    out[(a + j) % n] = out[a] + (out[b] - out[a]) * j / gap;
            }
            return { step: 360 / n, dist: out };
        },

        // The bearing at the middle of a bin
        bearing(bin) {
            return (bin + 0.5) * binDeg;
        },

        clear(srcId) {
            data.delete(srcId);
            lastSample.clear();
            dirty = true;
            save();
        },

        flush() {
            clearTimeout(saveTimer);
            save();
        },
    };
}

// Ring spacing giving about four rings out to a distance, in meters
export function ringStep(max) {
    const steps = [1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500].map((k) => k * 1000);
    return steps.find((s) => max / s <= 5) ?? 1000000;
}
