// Where map devices have been, collected by the browser from each map
// refresh, so their paths can be drawn even when the server keeps no
// location history.  Tracks live as long as the page and are shared by
// every map.

const maxPoints = 1000;             // per device
const maxTotal = 200000;            // across all devices
const maxSpeed = 1500;              // m/s; faster jumps are taken as bad decodes
const restartAfter = 3;             // consecutive bad jumps that agree start a new track
export const gapSeconds = 15 * 60;  // a longer silence breaks the line

// key -> { points: [{ t, end?, lon, lat }], rejected, seen }; `end` is the
// last time a device reported the same position again
const tracks = new Map();
let total = 0;

function meters(a, b) {
    const r = Math.PI / 180;
    const dlon = ((b.lon - a.lon + 540) % 360) - 180;
    const x = dlon * r * Math.cos(((a.lat + b.lat) / 2) * r);
    const y = (b.lat - a.lat) * r;
    return Math.hypot(x, y) * 6371000;
}

function plausible(a, b) {
    const d = meters(a, b);
    return d < 5000 || d / Math.max(b.t - a.t, 1) <= maxSpeed;
}

// Add a position; t is in seconds.  Repeats of the last position only
// refresh its time.
export function record(key, lon, lat, t) {
    if (!key || !Number.isFinite(lon) || !Number.isFinite(lat) || !Number.isFinite(t) ||
            Math.abs(lat) > 90 || Math.abs(lon) > 180 || (!lon && !lat))
        return;
    let tr = tracks.get(key);
    if (!tr) {
        tr = { points: [], rejected: [], seen: t };
        tracks.set(key, tr);
    }
    tr.seen = Math.max(tr.seen, t);
    const p = { t, lon, lat };
    const pts = tr.points;
    const prev = pts[pts.length - 1];

    if (prev) {
        if (t < (prev.end ?? prev.t))
            return;
        if (prev.lon === lon && prev.lat === lat) {
            prev.end = t;
            return;
        }
        if (!plausible({ ...prev, t: prev.end ?? prev.t }, p)) {
            const rej = tr.rejected;
            if (rej.length && !plausible(rej[rej.length - 1], p))
                rej.length = 0;
            rej.push(p);
            if (rej.length < restartAfter)
                return;
            // The jump keeps holding up, so the old track was the bad one
            total -= pts.length;
            pts.length = 0;
            pts.push(...rej);
            total += rej.length;
            rej.length = 0;
            trim();
            return;
        }
    }
    tr.rejected.length = 0;
    pts.push(p);
    total++;
    if (pts.length > maxPoints) {
        pts.shift();
        total--;
    }
    trim();
}

// Drop the least recently heard devices' tracks when over budget
function trim() {
    if (total <= maxTotal)
        return;
    const order = [...tracks.entries()].sort((a, b) => a[1].seen - b[1].seen);
    for (const [key, tr] of order) {
        if (total <= maxTotal * 0.9)
            break;
        total -= tr.points.length;
        tracks.delete(key);
    }
}

// Forget positions older than `before` (seconds)
export function prune(before) {
    for (const [key, tr] of tracks) {
        const pts = tr.points;
        let n = 0;
        while (n < pts.length && (pts[n].end ?? pts[n].t) < before)
            n++;
        if (n) {
            pts.splice(0, n);
            total -= n;
        }
        if (!pts.length)
            tracks.delete(key);
    }
}

// A copy of a device's positions, oldest first: [{ t, end, lon, lat }]
export function get(key) {
    return (tracks.get(key)?.points ?? []).map(({ t, end, lon, lat }) => ({ t, end: end ?? t, lon, lat }));
}

export function has(key) {
    return (tracks.get(key)?.points.length ?? 0) > 1;
}

export function clear() {
    tracks.clear();
    total = 0;
}

// Positions as Leaflet line segments: [[lat, lon], ...] runs, split at long
// silences, with longitudes unwrapped so a path over the date line stays short
export function segments(points) {
    const out = [];
    let run = null;
    let prev = null;
    let lonPrev = 0;
    for (const p of points) {
        let lon = p.lon;
        if (prev) {
            while (lon - lonPrev > 180)
                lon -= 360;
            while (lon - lonPrev < -180)
                lon += 360;
        }
        if (!run || p.t - (prev.end ?? prev.t) > gapSeconds) {
            run = [];
            out.push(run);
        }
        run.push([p.lat, lon]);
        prev = p;
        lonPrev = lon;
    }
    return out.filter((r) => r.length > 1);
}
