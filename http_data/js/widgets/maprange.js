// Receiver range: for devices that report their own position (aircraft,
// vessels, mesh nodes), how far from Kismet each one was when it was heard,
// kept by direction.  The furthest distance in each direction makes the
// outline of what the receiver covers.
//
// Servers since 2026-10 keep the range themselves (/range/); for older ones
// the browser collects it from the map's refreshes, in 2° of bearing, and
// keeps it for each server and kind of device so it survives reloads.  A
// mobile receiver's outline is its range around itself, wherever it has been.
//
// Without Kismet's own location there's no range; positions then go into a
// convex hull, the area the devices were heard over.

import * as settings from '../core/settings.js';

const binDeg = 2;
export const bins = 360 / binDeg;
const fillGap = 3;                  // empty directions up to this many wide are filled from their neighbors
const stepsDeg = [1, 2, 4, 6, 10, 18, 30];  // outline steps, finest first
const minFilled = 0.6;              // share of directions with a distance before an outline is that fine
const saveMs = 30000;
const maxDevices = 20000;           // last samples kept for the glitch check
const maxJump = 50000;              // m between a device's positions that still agree, without Kismet's location
const maxHull = 1024;
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
    return { bins: new Array(bins).fill(0), samples: 0, center: null, hull: [], hullSamples: 0 };
}

const lonlat = (p) => Array.isArray(p) && p.length === 2 && p.every(Number.isFinite) &&
    Math.abs(p[0]) <= 180 && Math.abs(p[1]) <= 90;

// Convex hull of [lon, lat] points, counterclockwise, flat at these sizes:
// longitude is scaled at the first point's latitude and taken relative to it
export function convexHull(points) {
    if (points.length < 3)
        return points.slice();
    const [lon0, lat0] = points[0];
    const k = Math.cos(lat0 * rad);
    const x = (p) => ((((p[0] - lon0) % 360) + 540) % 360 - 180) * k;
    const cross = (o, a, b) => (x(a) - x(o)) * (b[1] - o[1]) - (a[1] - o[1]) * (x(b) - x(o));
    const pts = points.slice().sort((a, b) => x(a) - x(b) || a[1] - b[1]);
    const lower = [], upper = [];
    for (const p of pts) {
        while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0)
            lower.pop();
        lower.push(p);
    }
    for (let i = pts.length - 1; i >= 0; i--) {
        const p = pts[i];
        while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0)
            upper.pop();
        upper.push(p);
    }
    return lower.slice(0, -1).concat(upper.slice(0, -1));
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
        const hull = Array.isArray(rec.hull) ? rec.hull.filter(lonlat).slice(0, maxHull) : [];
        data.set(id, { bins: rec.bins.slice(), samples: Number(rec.samples) || 0, center, hull,
            hullSamples: Number(rec.hullSamples) || 0 });
    }

    function save() {
        saveTimer = null;
        if (!dirty)
            return;
        dirty = false;
        const sources = {};
        for (const [id, rec] of data)
            sources[id] = { bins: rec.bins.map(Math.round), samples: rec.samples, center: rec.center,
                hull: rec.hull, hullSamples: rec.hullSamples };
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
            if (!rep || !devKey)
                return;
            if (!heard) {
                this.recordHull(srcId, devKey, rep);
                return;
            }
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

        // A position heard while Kismet's own location is unknown; it counts
        // when the device's previous one is near enough to agree with it
        recordHull(srcId, devKey, rep) {
            const prev = lastSample.get(devKey);
            if (lastSample.size >= maxDevices && !prev)
                lastSample.clear();
            lastSample.set(devKey, { pos: rep });
            if (!prev?.pos || bearingDistance(prev.pos, rep).distance > maxJump)
                return;
            let rec = data.get(srcId);
            if (!rec) {
                rec = blank();
                data.set(srcId, rec);
            }
            rec.hullSamples++;
            const hull = convexHull([...rec.hull, [rep[0], rep[1]]]);
            if (hull.length <= maxHull && (hull.length !== rec.hull.length ||
                    hull.some((p, i) => p !== rec.hull[i]))) {
                rec.hull = hull;
                changed();
            }
        },

        has(srcId) {
            const rec = data.get(srcId);
            return (rec?.samples ?? 0) + (rec?.hullSamples ?? 0) > 0;
        },

        get(srcId) {
            return data.get(srcId) ?? null;
        },

        outline(srcId) {
            const rec = data.get(srcId);
            return rec ? outlineOf(rec.bins) : null;
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

// The outline of distances in equal bins from north: { step, dist }, a
// distance every step degrees with short gaps filled in, or null.  Until
// enough directions have been heard from, it's drawn in coarser steps, so it
// fills in as it sharpens.
export function outlineOf(distances) {
    const len = distances?.length ?? 0;
    if (!len || 360 % len)
        return null;
    let out = null;
    for (const deg of stepsDeg) {
        const g = deg * len / 360;
        if (g < 1 || g !== Math.floor(g))
            continue;
        const n = len / g;
        out = new Array(n).fill(0);
        distances.forEach((v, i) => {
            const k = Math.floor(i / g);
            if (Number.isFinite(v) && v > out[k])
                out[k] = v;
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
}

// Ring spacing giving about four rings out to a distance, in meters; round
// kilometers (or meters), or round miles when imperial
export function ringStep(max, imperial = false) {
    const steps = imperial ? [0.25, 0.5, 1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500].map((k) => k * 1609.344) :
        [0.25, 0.5, 1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500].map((k) => k * 1000);
    return steps.find((s) => max / s <= 5) ?? steps[steps.length - 1] * 2;
}
