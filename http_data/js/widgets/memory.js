// The Memory window: the Kismet server's memory and device count over the
// last minute, hour or day, what the memory is made of, the settings which
// change how much devices use, and insights worked out from them (memory per
// device, growth, time until the system runs out).
//
//   openMemory()
//
// /system/memory holds the detail; servers without it still get the graphs
// from /system/status.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';
import { series } from './charts.js';
import { openPackets } from './packetgraphs.js';

const sys = 'kismet.system';
const mem = 'kismet.system.memory';

const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
const binSeconds = { minute: 1, hour: 60, day: 3600 };
const refresh = { minute: 2, hour: 15, day: 60 };
// The detail is read at most this often; the server limits heap reads too
const detailSeconds = 10;

const statusFields = [`${mem}.rss`, `${mem}.rrd`, `${sys}.devices.count`, `${sys}.devices.rrd`,
    `${sys}.timestamp.start_sec`];

// What each setting does, for the settings list; in kismet_memory.conf, kismet_80211.conf for dot11_,
// or kismet_logging.conf for pcapng_
const settingText = {
    tracker_device_timeout: ['Forget devices idle for this many seconds', (v) => v ? format.duration(v) : 'never'],
    tracker_device_packets: ['Only forget idle devices with fewer packets than this', (v) => v ? format.count(v) : 'any'],
    tracker_max_devices: ['Most devices kept; the oldest are forgotten past it', (v) => v ? format.count(v) : 'no limit'],
    track_device_rrds: ['Packet and data history graphs for each device', null],
    track_device_seenby_views: ['Device lists for each data source', null],
    track_device_phy_views: ['Device lists for each phy type', null],
    keep_per_datasource_stats: ['Signal and packet history per data source, for each device', null],
    keep_location_cloud_history: ['Location history cloud for each device', null],
    tracker_device_presize: ['Room reserved in the device list at startup', (v) => format.count(v)],
    manuf_lookup: ['Manufacturer names from the OUI list, loaded at startup', null],
    alertbacklog: ['Alerts kept in the alert history', (v) => format.count(v)],
    packet_backlog_warning: ['Warn when this many packets wait to be processed', (v) => v ? format.count(v) : 'off'],
    packet_backlog_limit: ['Drop packets past this many waiting, about 1.5 kB each', (v) => v ? format.count(v) : 'no limit'],
    ulimit_mbytes: ['Most memory Kismet may use before it exits', (v) => v ? format.size(v * 1024 * 1024) : 'no limit'],
    rtl433_track_last: ['Keep the last message from each rtl433 sensor', null],
    dot11_keep_eapol: ['Keep WPA handshake packets for each Wi-Fi device', null],
    dot11_keep_ietags: ['Keep a copy of the IE tags for each SSID', null],
    dot11_fingerprint_devices: ['Fingerprints of Wi-Fi devices, needed for allow lists', null],
    dot11_11d_country_full: ['Full 802.11d channel lists for each access point', null],
    dot11_view_accesspoints: ['Device list of Wi-Fi access points', null],
    dot11_view_ssids: ['SSID list, separate from the devices', null],
    dot11_max_ssid_groups: ['Most SSID groups the SSID list keeps', (v) => v ? format.count(v) : 'no limit'],
    dot11_ap_only_survey: ['Only track Wi-Fi access points, not clients', null],
    kismet_packet_threads: ['Packet threads; each keeps up to 1,024 packets from the last second to spot duplicates', (v) => format.count(v)],
    pcapng_log_buffer_mb: ['Most packets each pcapng log holds while its writer catches up', (v) => format.size(v * 1024 * 1024)],
    pcapng_ring_file_size_mb: ['Size of each pcapng ring file, on tmpfs when pcapng_ring logging is on', (v) => format.size(v * 1024 * 1024)],
    pcapng_ring_file_count: ['Files in the pcapng ring; the ring holds about size times count of system memory',
        (v, set) => `${format.count(v)}, ${format.size(v * (set.pcapng_ring_file_size_mb ?? 0) * 1024 * 1024)}`],
};

const kb = (v) => Number.isFinite(v) && v > 0 ? format.size(v * 1024) : '-';
const mbText = (v) => Number.isFinite(v) ? format.size(v * 1024 * 1024) : '-';
const pct = (a, b) => {
    if (!(b > 0))
        return '-';
    const p = 100 * a / b;
    return `${p < 10 ? +p.toFixed(1) : Math.round(p)}%`;
};

let openWindow = null;

function tabs(choices, current, onPick) {
    const buttons = Object.entries(choices).map(([id, title]) => {
        const b = el('button', { type: 'button', onclick: () => {
            current = id;
            show();
            onPick(id);
        } }, title);
        b.dataset.id = id;
        return b;
    });
    const show = () => buttons.forEach((b) => {
        b.classList.toggle('active', b.dataset.id === current);
        b.setAttribute('aria-pressed', String(b.dataset.id === current));
    });
    show();
    return el('div', { class: 'graph-tabs' }, buttons);
}

function pointTime(i, now, span, count) {
    const bin = binSeconds[span];
    const t = (Math.floor(now / bin) - count + i) * bin;
    if (span === 'minute')
        return format.time(t).slice(-8);
    if (span === 'hour')
        return format.clock(t);
    return `${format.clock(t)} to ${format.clock(t + bin)}`;
}

// Least-squares slope and intercept of y over x
function fit(points) {
    const n = points.length;
    if (n < 3)
        return null;
    let sx = 0, sy = 0, sxx = 0, sxy = 0;
    for (const [x, y] of points) {
        sx += x;
        sy += y;
        sxx += x * x;
        sxy += x * y;
    }
    const d = n * sxx - sx * sx;
    if (d === 0)
        return null;
    const slope = (n * sxy - sx * sy) / d;
    return { slope, intercept: (sy - slope * sx) / n };
}

// What the devices hold: the heap in use (or the resident memory, without heap stats), less
// what Kismet held once it had loaded, the estimate for its data sources, recent packets kept
// to recognize duplicates, and freed packets kept for reuse.  Sizes in kB; null on servers
// without the startup snapshot
function deviceMemory(detail, rss) {
    const x = (f) => detail?.[`${mem}.${f}`] ?? 0;
    const devices = detail?.[`${sys}.devices.count`] ?? 0;
    let basis, used, start;
    if (x('heap_known') && x('startup_heap_used') > 0) {
        basis = 'heap';
        used = x('heap_used') + x('heap_mmap');
        start = x('startup_heap_used') + x('startup_heap_mmap');
    } else if (x('startup_rss') > 0 && rss > 0) {
        basis = 'rss';
        used = rss;
        start = x('startup_rss');
    } else {
        return null;
    }
    const sources = x('datasources') * x('datasource_estimate');
    const pool = x('packet_pool_estimate');
    const dedupe = x('dedupe_estimate');
    const device = Math.max(0, used - start - sources - pool - dedupe);
    return { basis, used, start, sources, nsources: x('datasources'), pool, dedupe, device, devices,
        per: devices > 0 ? device / devices : 0 };
}

function deviceMemoryText(dm) {
    const parts = [`the ${kb(dm.start)} Kismet held once it had loaded`];
    if (dm.sources)
        parts.push(`about ${kb(dm.sources)} for ${format.count(dm.nsources)} data source${dm.nsources === 1 ? '' : 's'}`);
    if (dm.dedupe)
        parts.push(`${kb(dm.dedupe)} of recent packets kept to spot duplicates`);
    if (dm.pool)
        parts.push(`${kb(dm.pool)} of freed packets kept for reuse`);
    const last = parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : parts[0];
    return `${dm.basis === 'heap' ? 'Heap in use' : 'Kismet\'s memory'} (${kb(dm.used)}), less ${last}, divided by the devices.`;
}

const estimateCaveat = 'These are estimates and can be well off, especially soon after Kismet starts: packet buffers are ' +
    'still filling, and with few devices one-time costs are spread over too few of them.';

const finitePairs = (a, b) => a.map((v, i) => [v, b[i]]).filter(([x, y]) => Number.isFinite(x) && Number.isFinite(y));

// Memory per device: how memory moved with the device count, over the hour
// and then the day, once the count has changed enough to tell
function perDevice(hist) {
    for (const span of ['hour', 'day', 'minute']) {
        const pairs = finitePairs(hist[span].devices, hist[span].rss).filter(([d]) => d > 0);
        if (pairs.length < 3)
            continue;
        const counts = pairs.map(([d]) => d);
        const lo = Math.min(...counts), hi = Math.max(...counts);
        if (hi - lo < Math.max(20, hi * 0.05))
            continue;
        const f = fit(pairs);
        if (f && f.slope > 0)
            return { kb: f.slope, span };
    }
    return null;
}

// Growth in kB per hour, from the hour or (with three hours or more) the day
function growth(hist) {
    // Ten minutes, or three hours, before a trend means anything
    const fromSpan = (span, perHour, least) => {
        const pts = hist[span].rss.map((v, i) => [i, v]).filter(([, v]) => Number.isFinite(v) && v > 0);
        if (pts.length < least)
            return null;
        const f = fit(pts);
        return f ? { rate: f.slope * perHour, span, points: pts.length } : null;
    };
    return fromSpan('day', 1, 3) ?? fromSpan('hour', 60, 10);
}

function change(values) {
    const v = values.filter((x) => Number.isFinite(x) && x > 0);
    if (v.length < 2)
        return null;
    return { first: v[0], last: v[v.length - 1], min: Math.min(...v), max: Math.max(...v) };
}

// Insights as [{ level: ok|info|warn|error, title, text }]
function insights({ status, detail, hist, views }) {
    const out = [];
    const rss = status[`${mem}.rss`] ?? 0;
    const devices = status[`${sys}.devices.count`] ?? 0;

    if (!rss) {
        out.push({ id: 'unavailable', level: 'info', title: 'Memory use not available',
            text: 'This server can\'t read its own memory use; Kismet reads it from /proc on Linux.' });
        return out;
    }

    const set = detail?.[`${mem}.settings`] ?? null;
    const total = detail?.[`${mem}.system_total`] ?? 0;
    const avail = detail?.[`${mem}.system_available`] ?? 0;

    const per = perDevice(hist);
    const dm = deviceMemory(detail, rss);
    if (per)
        out.push({ id: 'per-device', level: 'info', title: `About ${format.size(per.kb * 1024)} per new device`,
            text: `How memory rose with the device count over the last ${per.span}.` +
                (dm?.devices ? ` ${format.count(dm.devices)} devices now hold about ${kb(dm.device)}, ${format.size(dm.per * 1024)} each.` :
                    devices ? ` ${format.count(devices)} devices now, about ${format.size(rss * 1024 / devices)} each counting everything else Kismet holds.` : '') +
                `  ${estimateCaveat}` });
    else if (dm?.devices)
        out.push({ id: 'per-device', level: 'info', title: `About ${format.size(dm.per * 1024)} per device`,
            text: `${deviceMemoryText(dm)}  The cost of a new device shows once the device count has changed enough over the hour.  ${estimateCaveat}` });
    else if (devices)
        out.push({ id: 'per-device', level: 'info', title: `${format.size(rss * 1024 / devices)} per device, overall`,
            text: `Kismet's memory divided by its devices.  The cost of a new device shows once the device count has changed enough over the hour.  ${estimateCaveat}` });

    const g = growth(hist);
    const forgets = set && (set.tracker_device_timeout > 0 || set.tracker_max_devices > 0);
    if (g && g.rate > 1024) {
        const text = [`Over the last ${g.span}, at ${format.size(g.rate * 1024)} an hour.`];
        let level = 'info';
        if (avail > 0) {
            const hours = avail / g.rate;
            text.push(`At this rate the system's free memory (${kb(avail)}) runs out in about ${format.duration(hours * 3600)}.`);
            if (hours < 24)
                level = 'warn';
        }
        if (set && !forgets)
            text.push('Devices are kept until Kismet restarts; tracker_device_timeout or tracker_max_devices in kismet_memory.conf caps them.');
        out.push({ id: 'growing', level, title: 'Memory is growing', text: text.join(' ') });
    } else if (g && Math.abs(g.rate) <= 1024) {
        out.push({ id: 'steady', level: 'ok', title: 'Memory is steady', text: `No real change over the last ${g.span}.` });
    }

    // Growth with no new devices points away from device data
    const hr = change(hist.hour.rss);
    const hd = change(hist.hour.devices);
    const hf = change(hist.hour.fields);
    if (hr && hd && hr.last - hr.first > Math.max(20 * 1024, hr.first * 0.05) &&
            Math.abs(hd.last - hd.first) <= Math.max(5, hd.first * 0.01)) {
        const fieldsGrew = hf && hf.last - hf.first > hf.first * 0.05;
        out.push({ id: 'grew-no-devices', level: 'warn', title: 'Memory grew without new devices',
            text: `${kb(hr.last - hr.first)} over the last hour while the device count held at ${format.count(hd.last)}. ` +
                (fieldsGrew ? 'Tracked fields grew too, so it is data kept in the devices (clients, probed SSIDs, history).' :
                    hf ? 'Tracked fields did not grow, so it is outside device data: packet queues, HTTP clients, or the allocator holding freed memory.' : '') });
    }

    if (total > 0 && avail > 0) {
        const left = avail / total;
        if (left < 0.05)
            out.push({ id: 'system-low', level: 'error', title: 'System memory nearly gone', text: `${kb(avail)} of ${kb(total)} left.` });
        else if (left < 0.1)
            out.push({ id: 'system-low', level: 'warn', title: 'System memory is low', text: `${kb(avail)} of ${kb(total)} left.` });
        out.push({ id: 'share', level: rss / total > 0.5 ? 'warn' : 'info', title: `Kismet uses ${pct(rss, total)} of system memory`,
            text: `${kb(rss)} of ${kb(total)}; ${kb(avail)} is free for other programs.` });
    }

    const swap = detail?.[`${mem}.swap`] ?? 0;
    if (swap > 0)
        out.push({ id: 'swap', level: 'warn', title: `${kb(swap)} swapped out`,
            text: 'Part of Kismet is on disk; looking up devices that were swapped out is slow.' });

    const peak = detail?.[`${mem}.peak_rss`] ?? 0;
    if (peak > rss * 1.5 && peak - rss > 50 * 1024)
        out.push({ id: 'peak', level: 'info', title: `Peaked at ${kb(peak)}`,
            text: 'Memory was once much higher than now: a burst of devices or packets, or a large download from the server.' });

    if (detail?.[`${mem}.heap_known`]) {
        const used = detail[`${mem}.heap_used`] ?? 0;
        const free = detail[`${mem}.heap_free`] ?? 0;
        if (free > 64 * 1024 && free > (used + free) * 0.3)
            out.push({ id: 'held-free', level: 'info', title: `${kb(free)} held free`,
                text: 'Freed memory the allocator keeps for reuse instead of returning it; usual after devices are forgotten or a burst passes.' });
    }

    if (set) {
        if (set.keep_location_cloud_history)
            out.push({ id: 'location-clouds', level: 'info', title: 'Location clouds are kept',
                text: 'keep_location_cloud_history keeps a location history for every device; turning it off saves memory.' });
        if (set.keep_per_datasource_stats)
            out.push({ id: 'per-source-stats', level: 'info', title: 'Per data source history is kept',
                text: 'keep_per_datasource_stats keeps signal and packet history for every device from each data source.' });
    }

    const phys = (views ?? []).filter((v) => String(v['kismet.devices.view.id'] ?? '').startsWith('phy-') &&
        (v['kismet.devices.view.size'] ?? 0) > 0);
    const phyTotal = phys.reduce((a, v) => a + v['kismet.devices.view.size'], 0);
    const top = [...phys].sort((a, b) => b['kismet.devices.view.size'] - a['kismet.devices.view.size'])[0];
    if (top && phys.length > 1 && phyTotal >= 100 && top['kismet.devices.view.size'] / phyTotal > 0.6)
        out.push({ id: 'phy-share', level: 'info', title: `Most devices are ${top['kismet.devices.view.description'] || top['kismet.devices.view.id'].slice(4)}`,
            text: `${pct(top['kismet.devices.view.size'], phyTotal)} of devices, so most of the device memory.` });

    const order = { error: 0, warn: 1, info: 2, ok: 3 };
    return out.sort((a, b) => order[a.level] - order[b.level]);
}

function readout(label, value, title = '') {
    return el('div', { class: 'mem-stat', title }, el('span', { class: 'mem-stat-label' }, label), el('span', { class: 'mem-stat-value' }, value));
}

function rows(list) {
    return list.filter(Boolean).map(([label, value, note]) =>
        el('div', { class: 'mem-row' }, el('span', {}, label), el('span', { class: 'mem-row-value' }, value),
            el('span', { class: 'muted mem-row-note' }, note ?? '')));
}

export function openMemory() {
    if (openWindow?.node.isConnected) {
        openWindow.raise();
        return openWindow;
    }

    let span = settings.get('memory.span', 'hour');
    if (!spans[span])
        span = 'hour';

    let shown = { now: Date.now() / 1000, count: 0 };
    const pointLabel = (i) => pointTime(i, shown.now, span, shown.count);

    // Memory against the left axis, devices against the right
    const memGraph = historyGraph({ type: 'line', unit: 'MB', height: '11rem', fill: true, pointLabel, fmt: mbText });
    const deviceText = (v) => Number.isFinite(v) ? format.count(Math.round(v)) : '-';
    const fieldGraph = historyGraph({ type: 'line', unit: 'k', height: '6rem', pointLabel,
        fmt: (v) => Number.isFinite(v) ? format.count(Math.round(v * 1000)) : '-' });
    const sysGraph = historyGraph({ type: 'line', unit: 'MB', height: '6rem', min: 0, fill: true, pointLabel, fmt: mbText });
    const graphs = [memGraph, fieldGraph, sysGraph];

    const status = el('span', { class: 'muted' });
    const stats = el('div', { class: 'mem-stats' });
    const insightList = el('ul', { class: 'mem-insights' });
    const reopenInsights = el('button', { type: 'button', class: 'link-button mem-reopen', hidden: true, onclick: () => {
        settings.set('memory.closedInsights', []);
        showInsights();
    } });
    const breakdown = el('div', { class: 'mem-rows' });
    const settingList = el('div', { class: ['mem-rows', 'mem-settings'] });
    const sysTitle = el('h3', {}, 'System memory used');
    const fieldSection = el('section', {}, el('h3', { title: 'Every value Kismet tracks, in devices and everything else' }, 'Tracked fields'), fieldGraph.node);
    const sysSection = el('section', { hidden: true }, sysTitle, sysGraph.node);
    const detailSections = el('div', { class: 'mem-detail', hidden: true },
        el('section', {}, el('h3', {}, 'What the memory is'), breakdown),
        el('section', {}, el('h3', {}, 'Settings that change memory use'), settingList,
            el('p', { class: 'muted mem-note' }, 'Set in kismet_memory.conf, kismet_80211.conf for the dot11_ settings, or kismet_logging.conf for the pcapng_ ones; kismet_site.conf overrides them.')));

    const body = el('div', { class: 'mem-window' },
        el('div', { class: 'pk-bar' },
            tabs(Object.fromEntries(Object.entries(spans).map(([k, v]) => [k, v[0]])), span, (s) => {
                span = s;
                settings.set('memory.span', s);
                read(true);
            }), status,
            el('button', { type: 'button', class: 'link-button pk-channels', title: 'Packet rates and queues',
                onclick: () => openPackets() }, 'Packet rates')),
        stats,
        el('section', {}, el('h3', {}, 'Insights'), insightList, reopenInsights),
        el('section', {}, el('h3', {}, 'Memory and devices'), memGraph.node),
        fieldSection, sysSection, detailSections);

    const w = Math.min(820, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 900);
    const d = dialog({
        title: 'Memory', body, modal: false, className: 'pk-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            clearTimeout(timer);
            graphs.forEach((g) => g.destroy());
            openWindow = null;
        },
    });

    let timer = null;
    let reading = false;
    let detail = null;
    let detailAt = 0;
    let hasDetail = true;
    let views = null;
    let insightKey = '';
    let found = [];

    // A closed insight stays closed until it turns more serious
    const closedKey = (f) => `${f.id}:${f.level}`;
    function closeInsight(f) {
        settings.set('memory.closedInsights', [...new Set([...settings.get('memory.closedInsights', []), closedKey(f)])]);
        showInsights();
    }

    // Only redraw the list when it changes, so it keeps its place
    function showInsights() {
        const closed = new Set(settings.get('memory.closedInsights', []));
        const open = found.filter((f) => !closed.has(closedKey(f)));
        const hidden = found.length - open.length;
        reopenInsights.hidden = hidden === 0;
        reopenInsights.textContent = `Show ${format.count(hidden)} closed insight${hidden === 1 ? '' : 's'}`;
        const key = JSON.stringify(open);
        if (key === insightKey)
            return;
        insightKey = key;
        insightList.replaceChildren(...open.map((f) =>
            el('li', { class: ['mem-insight', `mem-${f.level}`] },
                el('button', { type: 'button', class: 'icon-button mem-insight-close', title: 'Close',
                    'aria-label': `Close ${f.title}`, onclick: () => closeInsight(f) }, icon('close')),
                el('strong', {}, f.title), el('span', { class: 'muted' }, f.text))));
    }

    async function readDetail(force) {
        const t = Date.now() / 1000;
        if (!hasDetail || (!force && t - detailAt < detailSeconds))
            return;
        detailAt = t;
        const [m, v] = await Promise.all([
            api.get('system/memory.json').catch((err) => {
                // Older servers have no detail; keep to the graphs
                if (err.status === 404)
                    hasDetail = false;
                return detail;
            }),
            api.get('devices/views/all_views.json').catch(() => views),
        ]);
        detail = m;
        views = v;
    }

    function perDeviceReadout(rss, devices) {
        const dm = deviceMemory(detail, rss);
        if (dm?.devices)
            return readout('Per device', `~${format.size(dm.per * 1024)}`, `${deviceMemoryText(dm)}\n${estimateCaveat}`);
        return rss && devices ? readout('Per device', `~${format.size(rss * 1024 / devices)}`,
            `Kismet's memory divided by its devices.\n${estimateCaveat}`) : null;
    }

    function showStats(s, now) {
        const rss = s[`${mem}.rss`] ?? 0;
        const devices = s[`${sys}.devices.count`] ?? 0;
        const total = detail?.[`${mem}.system_total`] ?? 0;
        const avail = detail?.[`${mem}.system_available`] ?? 0;
        const start = s[`${sys}.timestamp.start_sec`];
        stats.replaceChildren(...[
            readout('Kismet', rss ? kb(rss) : 'n/a', 'Resident memory of the Kismet server'),
            detail?.[`${mem}.peak_rss`] ? readout('Peak', kb(detail[`${mem}.peak_rss`]), 'The most it has used since it started') : null,
            readout('Devices', format.count(devices)),
            perDeviceReadout(rss, devices),
            total ? readout('System free', `${kb(avail)} (${pct(avail, total)})`, `Of ${kb(total)}`) : null,
            start ? readout('Up', format.duration(now - start)) : null].filter(Boolean));
    }

    function showDetail() {
        detailSections.hidden = !detail;
        if (!detail)
            return;
        const x = (f) => detail[`${mem}.${f}`] ?? 0;
        const heap = x('heap_known');
        const dm = deviceMemory(detail, x('rss'));
        const used = dm?.basis === 'heap' ? 'of the heap in use' : 'of Kismet\'s memory';
        breakdown.replaceChildren(...rows([
            dm ? ['Once loaded', kb(dm.start), `${used}, before any data source opened`] : null,
            dm ? ['Data sources', dm.sources ? `~${kb(dm.sources)}` : 'none',
                dm.nsources ? `about ${kb(x('datasource_estimate'))} each; capture helpers are separate programs` : ''] : null,
            dm ? ['Recent packets', dm.dedupe ? `~${kb(dm.dedupe)}` : 'none',
                `${format.count(x('dedupe_packets'))} kept to spot duplicates, up to ${format.count(1024)} per packet thread`] : null,
            dm ? ['Packets kept for reuse', dm.pool ? `~${kb(dm.pool)}` : 'none', `${format.count(x('packet_pool'))} freed packets`] : null,
            dm ? ['Devices', kb(dm.device), `${used}, ${format.count(dm.devices)} device${dm.devices === 1 ? '' : 's'}`] : null,
            ['Heap and stacks', kb(x('rss_anon')), 'device records, packets, buffers'],
            ['Program and libraries', kb(x('rss_file')), 'shared with other programs using them'],
            x('rss_shmem') ? ['Shared memory', kb(x('rss_shmem'))] : null,
            ['Swapped out', x('swap') ? kb(x('swap')) : 'none'],
            ['Address space', kb(x('virtual')), 'reserved, mostly never used'],
            heap ? ['Heap in use', kb(x('heap_used'))] : null,
            heap ? ['Heap held free', kb(x('heap_free')), 'kept by the allocator for reuse'] : null,
            heap ? ['Large allocations', kb(x('heap_mmap')), 'mapped on their own'] : null,
            ['Threads', format.count(x('threads'))],
            ['Tracked fields', format.count(detail[`${sys}.num_fields`] ?? 0)],
            ['Tracked records', format.count(detail[`${sys}.num_components`] ?? 0)],
            ['Cached strings', format.count(detail[`${sys}.string_cache_size`] ?? 0)],
            ['Web connections', format.count(detail[`${sys}.num_http_connections`] ?? 0)],
        ]));
        const set = detail[`${mem}.settings`] ?? {};
        settingList.replaceChildren(...rows(Object.entries(settingText).filter(([k]) => k in set).map(([k, [text, fmt]]) =>
            [el('code', {}, k), fmt ? fmt(set[k], set) : set[k] ? 'on' : 'off', text])));
    }

    async function read(force = false) {
        clearTimeout(timer);
        if (!d.node.isConnected)
            return;
        if (!reading && document.visibilityState !== 'hidden') {
            reading = true;
            try {
                const [s] = await Promise.all([
                    api.post('system/status.json', { fields: statusFields }),
                    readDetail(force),
                ]);
                const now = clock.isKnown() ? clock.now() : undefined;
                const at = now ?? Date.now() / 1000;
                const hist = {};
                for (const sp of Object.keys(spans)) {
                    // The newest bin is still filling; bins before the server started have nothing
                    const h = (v) => rrd.history(v, now, sp, { blank: NaN }).slice(0, -1);
                    hist[sp] = {
                        rss: h(s[`${mem}.rrd`]),
                        devices: h(s[`${sys}.devices.rrd`]),
                        fields: h(detail?.[`${sys}.num_fields_rrd`]),
                        sysused: h(detail?.[`${mem}.system_used_rrd`]),
                    };
                }
                const cur = hist[span];
                shown = { now: at, count: cur.rss.length };
                const labels = [spans[span][1], 'now'];

                memGraph.draw([
                    { label: 'Kismet memory', color: series(0), values: cur.rss.map((v) => v / 1024) },
                    { label: 'Devices', color: series(1), values: cur.devices, axis: 'right', fill: false, fmt: deviceText },
                ], labels);
                fieldSection.hidden = !cur.fields.length;
                if (cur.fields.length)
                    fieldGraph.draw([{ label: 'Tracked fields', color: series(2), values: cur.fields.map((v) => v / 1000) }], labels);
                const total = detail?.[`${mem}.system_total`] ?? 0;
                sysSection.hidden = !cur.sysused.length || !total;
                if (!sysSection.hidden) {
                    sysTitle.textContent = `System memory used, of ${kb(total)}`;
                    sysGraph.draw([
                        { label: 'System', color: series(3), values: cur.sysused.map((v) => v / 1024) },
                        { label: 'Kismet', color: series(0), values: cur.rss.map((v) => v / 1024) },
                    ], labels);
                }

                showStats(s, at);
                showDetail();

                found = insights({ status: s, detail, hist, views });
                showInsights();
                status.textContent = `Updated ${format.time(at)}`;
            } catch (err) {
                status.textContent = err.message;
            } finally {
                reading = false;
            }
        }
        timer = setTimeout(read, refresh[span] * 1000);
    }

    read(true);
    openWindow = d;
    return d;
}
