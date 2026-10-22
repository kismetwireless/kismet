// Kismet RRDs (round-robin databases): rolling history of a value, such as
// packets per second for the last minute.
//
// Each vector is a ring buffer: the value for time t lives in slot
// floor(t / binSeconds) % length.  Slots after the RRD's last update hold stale
// data and read as zero.

const vectors = {
    minute: ['kismet.common.rrd.minute_vec', 1],      // 60 one-second bins
    hour: ['kismet.common.rrd.hour_vec', 60],         // 60 one-minute bins
    day: ['kismet.common.rrd.day_vec', 3600],         // 24 one-hour bins
};

// History oldest-first as a plain array, ending at `now` (server seconds).
export function history(rrd, now, span = 'minute') {
    const [name, bin] = vectors[span];
    const data = rrd?.[name];
    if (!Array.isArray(data) || data.length === 0)
        return [];

    const last = Math.floor((rrd['kismet.common.rrd.last_time'] ?? 0) / bin);
    const end = Math.floor((now ?? rrd['kismet.common.rrd.last_time'] ?? 0) / bin);
    const len = data.length;
    const out = new Array(len);

    for (let i = 0; i < len; i++) {
        const t = end - (len - 1 - i);
        out[i] = (t > last || t <= last - len) ? 0 : data[((t % len) + len) % len];
    }

    return out;
}

// The most recent complete value (the last second, minute, or hour)
export function latest(rrd, now, span = 'minute') {
    const h = history(rrd, now, span);
    // The current bin is still filling; use the one before it
    return h.length > 1 ? h[h.length - 2] : (h[0] ?? 0);
}
