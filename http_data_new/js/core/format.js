// Turning raw values from Kismet into readable text.

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
