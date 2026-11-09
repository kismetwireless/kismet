// The channel coverage window: what's on the air, frequency by frequency, and
// what the data sources are listening to.
//
//   Activity   a bar per frequency: devices active (or packets per second)
//              now, with a mark at the busiest second of the last minute
//   History    the last minute as a waterfall, newest at the top, scrolling
//              smoothly as time passes
//   Sources    a lane per data source: ticks for the channels it hops
//              through, and a marker that moves to the channel it's on;
//              a wide channel (an SDR's 2442/80, Wi-Fi's VHT80) is a bar
//              across the frequencies it takes in
//   Heat map   every frequency as a row and time across, over the last
//              minute, hour, or day, colored by how busy it was
//   Time       an estimate of how much of the time each frequency is
//              listened to, from the sources' channel lists and hop rates
//
// Bars sit at their real frequency, so channel spacing and overlap look the
// way they are on the air.  The server keeps a minute of per-second history
// for every frequency (/channels/channels.json); the sources come from
// /datasource/all_sources.json.  Both are polled only while the window is
// open and the page visible.

import { el, fitCanvas } from '../core/dom.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import { themeColor, onChange } from '../core/theme.js';
import { sourceChannels, channelNames } from '../registry/devices.js';
import { dialog } from './dialog.js';
import { barList, stat } from './charts.js';

const channelSeconds = 2;
const sourceSeconds = 1;

// What the bars, history, and heat map show.  Servers older than 2026-10
// averaged packet and data counts per frequency, so on those they read low.
const metrics = {
    devices: { title: 'Devices', unit: 'Devices', note: '', fmt: (v) => num(v) },
    packets: { title: 'Packets', unit: 'Packets/s', note: '', fmt: (v) => num(v) },
    data: { title: 'Data', unit: 'Data/s', note: '', fmt: (v) => format.size(v) },
};

// Heat map time spans: the RRD vector, its columns, and how often to reload
const spans = {
    minute: { title: 'Last minute', seconds: 1, columns: 60, reload: 2 },
    hour: { title: 'Last hour', seconds: 60, columns: 60, reload: 15 },
    day: { title: 'Last day', seconds: 3600, columns: 24, reload: 60 },
};

// Small numbers keep a decimal, the rest are rounded
const num = (v) => (v > 0 && v < 10 && v % 1 ? v.toFixed(1) : format.count(Math.round(v)));

// The channels at a frequency, by phy, from each phy's channel numbering:
// [{ phy: 'Wi-Fi', channel: '1' }, { phy: 'BLE', channel: '4' }]
export function channelsAt(khz) {
    const out = [];
    for (const c of channelNames.list()) {
        try {
            const name = c.name(khz);
            if (name)
                out.push({ phy: c.title ?? c.id, channel: name });
        } catch (err) {
            console.error(`channel names ${c.id} failed:`, err);
        }
    }
    return out;
}

// A frequency's short name: the server's channel name, else the phys'
// channel numbering (the first phy plainly, others with their name, like
// 'BLE 37'), else the frequency
export function frequencyLabel(khz, channel = null) {
    if (channel && channel !== 'unknown' && channel !== '0')
        return String(channel);
    const at = channelsAt(khz);
    if (at.length) {
        const first = channelNames.list()[0];
        return at[0].phy === (first?.title ?? first?.id) ? at[0].channel : `${at[0].phy} ${at[0].channel}`;
    }
    return format.frequency(khz).replace(' ', '');
}

// A channel name with no frequency: placed only if every phy that knows the
// name agrees where it is
function frequencyOfChannel(channel) {
    const found = new Set();
    for (const c of channelNames.list()) {
        try {
            const f = c.frequency?.(channel);
            if (f)
                found.add(f);
        } catch {
            // that phy can't read it
        }
    }
    return found.size === 1 ? [...found][0] : null;
}

export const bands = [
    { id: 'sub', title: 'Below 1 GHz', min: 0, max: 1e6 },
    { id: '2.4', title: '2.4 GHz', min: 2.3e6, max: 2.6e6 },
    { id: '5', title: '5 GHz', min: 4.9e6, max: 5.93e6 },
    { id: '6', title: '6 GHz', min: 5.93e6, max: 7.2e6 },
    { id: 'other', title: 'Other', min: 1e6, max: Infinity },
];

function bandOf(khz) {
    return bands.find((b) => b.id !== 'other' && khz >= b.min && khz < b.max) ?? bands.at(-1);
}

const sourceFields = [
    'kismet.datasource.uuid', 'kismet.datasource.name', 'kismet.datasource.running',
    'kismet.datasource.type_driver/kismet.datasource.driver.type',
    'kismet.datasource.channel', 'kismet.datasource.hop_channels', 'kismet.datasource.hopping',
    'kismet.datasource.hop_rate', 'kismet.datasource.hop_offset', 'kismet.datasource.channel_spans',
];

// A source's channel as a frequency: a phy that knows the source's channels,
// or a channel that's already a frequency ('2412', '433.92MHz', '915000')
export function sourceFrequency(source, channel) {
    return sourceChannel(source, channel)?.f ?? null;
}

// A source's channel as { f, title }: the frequency, and the short name of the
// phy whose numbering it's in, when its mapping gives one
function sourceChannel(source, channel) {
    if (channel === undefined || channel === null || channel === '')
        return null;
    for (const s of sourceChannels.list()) {
        try {
            if (s.match(source)) {
                const f = s.frequency(channel);
                if (f)
                    return { f, title: (typeof s.title === 'function' ? s.title(channel) : s.title) ?? null };
            }
        } catch (err) {
            console.error(`source channels ${s.id} failed:`, err);
        }
    }
    const m = /^([\d.]+)\s*(khz|mhz|ghz)?$/i.exec(String(channel).trim());
    if (!m)
        return null;
    const n = parseFloat(m[1]);
    const unit = (m[2] ?? '').toLowerCase();
    if (unit === 'ghz')
        return { f: n * 1e6, title: null };
    if (unit === 'mhz' || (!unit && n >= 1000 && n < 100000))
        return { f: n * 1000, title: null };
    if (unit === 'khz' || (!unit && n >= 100000))
        return { f: n, title: null };
    return null;
}

// The frequencies a source's channel takes in, { low, high } in kHz, for a
// wide channel: the server's ranges (SDRs, from 2026-10), a phy's (wide
// Wi-Fi channels), or a channel named as a center and width in MHz
// ('2442/80').  Null for a channel that's one frequency.
export function sourceSpan(source, channel) {
    if (channel === undefined || channel === null || channel === '')
        return null;
    const known = source['kismet.datasource.channel_spans']?.[channel];
    if (Array.isArray(known) && known.length === 2 && known[1] > known[0])
        return { low: known[0], high: known[1] };
    for (const s of sourceChannels.list()) {
        try {
            if (s.span && s.match(source)) {
                const sp = s.span(channel);
                if (sp)
                    return sp;
            }
        } catch (err) {
            console.error(`source channels ${s.id} failed:`, err);
        }
    }
    const m = /^([\d.]+)\/([\d.]+)$/.exec(String(channel).trim());
    if (m) {
        const center = parseFloat(m[1]) * 1000;
        const width = parseFloat(m[2]) * 1000;
        if (center > 0 && width > 0 && width < center)
            return { low: center - width / 2, high: center + width / 2 };
    }
    return null;
}

// One coverage window at a time; opening it again brings it to the front
let openWindow = null;

export function openCoverage({ view: startView = null } = {}) {
    if (openWindow?.dialog.node.isConnected) {
        if (startView)
            openWindow.setView(startView);
        openWindow.dialog.raise();
        return openWindow.dialog;
    }
    const canvas = el('canvas', { class: 'coverage-canvas' });
    // The heat map gets its own canvas, which scrolls when there are more
    // rows than fit
    const heatCanvas = el('canvas', { class: 'coverage-heat-canvas' });
    const heatScroll = el('div', { class: 'coverage-heat' }, heatCanvas);
    const tip = el('div', { class: 'coverage-tip', hidden: true });
    const tabs = el('div', { class: 'coverage-tabs', role: 'tablist' });
    const status = el('span', { class: 'muted coverage-status' });
    let metric = metrics[settings.get('coverage.metric', 'devices')] ? settings.get('coverage.metric', 'devices') : 'devices';
    const metricButtons = Object.entries(metrics).map(([id, m]) => el('button', { type: 'button', class: id === metric ? 'active' : null,
        onclick: () => {
            metric = id;
            settings.set('coverage.metric', id);
            metricButtons.forEach((b, i) => b.classList.toggle('active', Object.keys(metrics)[i] === id));
            note.textContent = metrics[id].note;
            shown.clear();
            tip.hidden = true;
            if (view !== 'live')
                draw();
        } }, m.title));
    const note = el('span', { class: 'muted coverage-note' }, metrics[metric].note);

    let view = startView ?? settings.get('coverage.view', 'live');
    if (!['live', 'heat', 'time'].includes(view))
        view = 'live';
    let span = spans[settings.get('coverage.span', 'hour')] ? settings.get('coverage.span', 'hour') : 'hour';
    const views = [['live', 'Live'], ['heat', 'Heat map'], ['time', 'Time']];
    const viewButtons = views.map(([id, title]) => el('button', { type: 'button',
        onclick: () => setView(id) }, title));
    const spanButtons = Object.entries(spans).map(([id, sp]) => el('button', { type: 'button',
        onclick: () => {
            span = id;
            settings.set('coverage.span', id);
            tip.hidden = true;
            showButtons();
            reloadSoon();
            draw();
        } }, sp.title));
    const spanBar = el('div', { class: 'graph-tabs coverage-span' }, spanButtons);

    // The time view: charts and a table of the listening estimate, scrolling
    const timeCanvas = el('canvas', { class: 'coverage-time-canvas' });
    const timeStats = [stat('frequencies listened to'), stat('busy frequencies heard under 25% of the time'),
        stat('sources with a channel plan')];
    const timeSources = el('div', { class: 'coverage-time-sources' });
    const timeMissed = barList({ empty: 'Nothing busy is going unheard', fmt: (v) => metrics[metric].fmt(v) });
    const timeTable = el('tbody');
    const timeMissedTitle = el('h4', {});
    const timeScroll = el('div', { class: 'coverage-time' },
        el('p', { class: 'muted coverage-time-note' }, 'Estimated from each source\'s channel list and hop rate: a hopping ',
            'source gives every channel in its list an equal share of its time.  Time spent changing channels, and a ',
            'source that falls behind, aren\'t counted.'),
        el('div', { class: 'coverage-time-stats' }, timeStats.map((t) => t.node)),
        el('h4', {}, 'Estimated time listened, by frequency'),
        el('div', { class: 'coverage-time-legend muted' },
            el('span', {}, el('span', { class: 'swatch' }), 'listened to'),
            el('span', {}, el('span', { class: 'swatch warn' }), 'busy, heard under 25% of the time')),
        timeCanvas,
        el('h4', {}, 'Where each source spends its time'),
        timeSources,
        timeMissedTitle,
        timeMissed.node,
        el('h4', {}, 'Every frequency'),
        el('div', { class: 'coverage-time-table' }, el('table', { class: 'data-table' },
            el('thead', {}, el('tr', {}, ['Channel', 'Frequency', 'Listened (est.)', 'Sources', 'Each visit', 'Heard every', 'Activity']
                .map((t) => el('th', {}, t)))),
            timeTable)));

    const stage = el('div', { class: 'coverage-stage' }, canvas, heatScroll, timeScroll, tip);
    // The sources get their own strip, which scrolls when there are many
    const srcCanvas = el('canvas', { class: 'coverage-sources-canvas' });
    const srcScroll = el('div', { class: 'coverage-sources' }, srcCanvas);
    const body = el('div', { class: 'coverage' },
        el('div', { class: 'coverage-bar' }, el('div', { class: 'graph-tabs coverage-view' }, viewButtons), tabs,
            el('div', { class: 'graph-tabs coverage-metric' }, metricButtons), spanBar, status),
        note, stage, srcScroll);

    const w = Math.round(window.innerWidth * 0.8);
    const h = Math.round(window.innerHeight * 0.8);
    const d = dialog({
        title: 'Channel coverage',
        body,
        modal: false,
        className: 'coverage-panel',
        fullSize: true,
        position: { left: Math.round((window.innerWidth - w) / 2), top: Math.round((window.innerHeight - h) / 2), width: w, height: h },
        onClose: () => {
            closed = true;
            openWindow = null;
            clearTimeout(channelTimer);
            clearTimeout(sourceTimer);
            cancelAnimationFrame(frame);
            clearTimeout(idle);
            stopTheme();
            resize.disconnect();
        },
    });

    let closed = false;
    let channelTimer = null;
    let sourceTimer = null;
    let frame = null;
    let idle = null;
    let band = settings.get('coverage.band', 'all');
    // A frequency picked in the heat map, highlighted in the live view
    let pinned = null;

    function showButtons() {
        viewButtons.forEach((b, i) => b.classList.toggle('active', views[i][0] === view));
        spanButtons.forEach((b, i) => b.classList.toggle('active', Object.keys(spans)[i] === span));
        spanBar.hidden = view !== 'heat';
        canvas.hidden = view !== 'live';
        heatScroll.hidden = view !== 'heat';
        timeScroll.hidden = view !== 'time';
        srcScroll.hidden = view !== 'live';
    }

    function setView(id) {
        view = id;
        settings.set('coverage.view', id);
        tip.hidden = true;
        showButtons();
        reloadSoon();
        draw();
    }

    // A span or view change can want fresher data than the next reload
    function reloadSoon() {
        clearTimeout(channelTimer);
        channelTimer = setTimeout(loadChannels, 50);
    }

    // Data from the server
    let freqs = new Map();      // kHz -> { channel, packets, devices (per second, oldest first), data, signal }
    let sources = [];
    let fetchedAt = 0;          // when the channel data arrived (performance.now)
    let serverNow;              // server time of the channel data

    // What's drawn, eased toward the data so changes slide instead of jump
    const shown = new Map();    // kHz -> bar height (packets/s)
    const markers = new Map();  // source uuid -> where its marker is drawn (canvas x)
    let hover = null;
    let hoverLane = null;       // source uuid under the pointer in the sources strip

    const stopTheme = onChange(() => draw());
    const resize = new ResizeObserver(() => draw());
    resize.observe(stage);

    async function loadChannels() {
        if (closed)
            return;
        if (document.visibilityState !== 'hidden') {
            try {
                const r = await api.get('channels/channels.json');
                const now = clock.isKnown() ? clock.now() : undefined;
                const next = new Map();
                // Per-channel records: those with a frequency name it; those
                // without are placed by the phys' channel numbering
                const byChannel = Object.values(r['kismet.channeltracker.channel_map'] ?? {});
                const named = new Map();
                const records = Object.values(r['kismet.channeltracker.frequency_map'] ?? {});
                for (const rec of byChannel) {
                    const ch = rec['kismet.channelrec.channel'];
                    let khz = rec['kismet.channelrec.frequency'];
                    if (!khz) {
                        khz = frequencyOfChannel(ch);
                        if (khz && !records.some((x) => x['kismet.channelrec.frequency'] === khz))
                            records.push({ ...rec, 'kismet.channelrec.frequency': khz });
                    }
                    if (khz && ch && ch !== 'unknown')
                        named.set(khz, ch);
                }
                for (const rec of records) {
                    const khz = rec['kismet.channelrec.frequency'];
                    if (!khz)
                        continue;
                    const rrds = {
                        packets: rec['kismet.channelrec.packets_rrd'],
                        devices: rec['kismet.channelrec.device_rrd'],
                        data: rec['kismet.channelrec.data_rrd'],
                    };
                    next.set(khz, {
                        channel: named.get(khz) ?? rec['kismet.channelrec.channel'],
                        packets: rrd.history(rrds.packets, now),
                        devices: rrd.history(rrds.devices, now),
                        data: rrd.history(rrds.data, now),
                        rrds,
                        signal: rec['kismet.channelrec.signal']?.['kismet.common.signal.last_signal'] ?? 0,
                    });
                }
                freqs = next;
                fetchedAt = performance.now();
                serverNow = now;
                if (view !== 'live')
                    draw();
                status.textContent = '';
                buildTabs();
            } catch (err) {
                status.textContent = `Could not load channels: ${err.message}`;
            }
        }
        const every = view === 'heat' ? spans[span].reload : channelSeconds;
        channelTimer = setTimeout(loadChannels, every * 1000);
    }

    async function loadSources() {
        if (closed)
            return;
        if (document.visibilityState !== 'hidden') {
            try {
                sources = (await api.post('datasource/all_sources.json', { fields: sourceFields }))
                    .filter((s) => s['kismet.datasource.running']);
                const named = new Map();
                for (const src of sources) {
                    for (const c of [src['kismet.datasource.channel'], ...(src['kismet.datasource.hop_channels'] ?? [])]) {
                        const at = sourceChannel(src, c);
                        if (at?.title && !named.has(at.f))
                            named.set(at.f, `${at.title} ${c}`);
                    }
                }
                sourceLabels = named;
                buildTabs();
                if (view === 'time')
                    draw();
            } catch (err) {
                console.error('coverage: could not load sources:', err);
            }
        }
        sourceTimer = setTimeout(loadSources, sourceSeconds * 1000);
    }

    // Each source's channels, as frequencies, with the range of the wide
    // ones.  A wide channel sits at its center, unless it names a
    // frequency inside its range.
    function sourceLanes() {
        return sources.map((src) => {
            const where = (c) => {
                const sp = sourceSpan(src, c);
                let f = sourceFrequency(src, c);
                if (sp && !(f >= sp.low && f <= sp.high))
                    f = (sp.low + sp.high) / 2;
                return f ? { f, span: sp } : null;
            };
            const hops = (src['kismet.datasource.hop_channels'] ?? []).map(where).filter(Boolean);
            const cur = where(src['kismet.datasource.channel']);
            const hopSpans = hops.map((h) => h.span).filter(Boolean);
            const currentSpan = cur?.span ?? null;
            return {
                src, hop: hops.map((h) => h.f), current: cur?.f ?? null, hopSpans, currentSpan,
                // Everything the lane reaches, for the band tabs and the layout
                reach: [...hops.map((h) => h.f), cur?.f, ...[...hopSpans, currentSpan].filter(Boolean).flatMap((sp) => [sp.low, sp.high])].filter(Boolean),
            };
        });
    }

    // How much of the time each frequency is listened to, estimated from the
    // sources' hop plans: a hopping source gives each entry in its channel
    // list an equal slice (a channel listed twice gets two), a source on one
    // channel is there all the time.  Sources hopping the same list at the
    // same rate from different offsets (hop_split) are on different entries
    // at once; other sources are taken as independent.  A wide Wi-Fi channel
    // counts at its primary frequency, an SDR's range across all of it.
    //
    // Returns { byFreq: f -> { coverage, listening, visitsPerSec, visit,
    // fixed, shares: [{ name, share }] }, plans: [per source] }
    function timeEstimate() {
        const covers = (src, c) => {
            const known = src['kismet.datasource.channel_spans']?.[c];
            const named = /^([\d.]+)\/([\d.]+)$/.test(String(c).trim());
            const sp = Array.isArray(known) || named ? sourceSpan(src, c) : null;
            if (sp) {
                const inside = [...freqs.keys()].filter((f) => f >= sp.low && f <= sp.high);
                return inside.length ? inside : [(sp.low + sp.high) / 2];
            }
            const sp2 = sourceSpan(src, c);
            let f = sourceFrequency(src, c);
            if (sp2 && !(f >= sp2.low && f <= sp2.high))
                f = (sp2.low + sp2.high) / 2;
            return f ? [f] : [];
        };

        const plans = sources.map((src) => {
            const rate = Number(src['kismet.datasource.hop_rate']) || 0;
            const list = src['kismet.datasource.hop_channels'] ?? [];
            const hopping = !!src['kismet.datasource.hopping'] && rate > 0 && list.length > 1;
            const channel = src['kismet.datasource.channel'];
            const entries = hopping ? list : (channel ? [channel] : (list.length === 1 ? list : []));
            const per = new Map();
            const bandsIn = new Map();
            for (const c of entries) {
                const fs = covers(src, c);
                for (const f of fs)
                    per.set(f, (per.get(f) ?? 0) + 1);
                if (fs.length) {
                    const b = bandOf(fs[0]);
                    bandsIn.set(b, (bandsIn.get(b) ?? 0) + 1);
                }
            }
            return {
                src, name: src['kismet.datasource.name'] ?? '?', hopping, rate, n: entries.length, per, bandsIn,
                offset: src['kismet.datasource.hop_offset'] ?? 0,
                key: hopping ? `${rate}|${list.join()}` : null,
            };
        });

        // Hop split groups: the members' distinct offsets are on distinct entries
        const groups = new Map();
        for (const p of plans) {
            if (!p.key)
                continue;
            if (!groups.has(p.key))
                groups.set(p.key, []);
            groups.get(p.key).push(p);
        }
        for (const members of groups.values())
            for (const p of members)
                p.splitWith = members.filter((o) => o !== p).map((o) => o.name);

        const all = new Set();
        for (const p of plans)
            for (const f of p.per.keys())
                all.add(f);

        const byFreq = new Map();
        for (const f of all) {
            let none = 1;
            let listening = 0;
            let visitsPerSec = 0;
            let visit = Infinity;
            let fixed = false;
            const shares = [];
            for (const p of plans) {
                const k = p.per.get(f) ?? 0;
                if (!k)
                    continue;
                const share = p.hopping ? k / p.n : 1;
                listening += share;
                shares.push({ name: p.name, share });
                if (p.hopping) {
                    visitsPerSec += (k * p.rate) / p.n;
                    visit = Math.min(visit, 1 / p.rate);
                } else {
                    fixed = true;
                }
            }
            for (const p of plans)
                if (!p.hopping && p.per.get(f))
                    none = 0;
            for (const members of groups.values()) {
                const k = members[0].per.get(f) ?? 0;
                if (!k)
                    continue;
                const L = members[0].n;
                // Chance none of d sources on d different entries is on one of the k
                const d = Math.min(L, new Set(members.map((m) => m.offset)).size);
                let miss = 1;
                for (let i = 0; i < d; i++)
                    miss *= Math.max(0, L - k - i) / (L - i);
                none *= miss;
            }
            byFreq.set(f, { coverage: 1 - none, listening, visitsPerSec, visit: fixed ? null : visit, fixed, shares });
        }
        return { byFreq, plans };
    }

    // The canvas extent of a frequency range, a piece per segment it shows in
    function spanPieces(sp, segments) {
        const out = [];
        for (const sg of segments) {
            const lo = Math.max(sp.low, sg.lo);
            const hi = Math.min(sp.high, sg.hi);
            if (lo >= hi || bandOf((lo + hi) / 2) !== sg.band)
                continue;
            const at = (f) => sg.x0 + ((f - sg.lo) / (sg.hi - sg.lo)) * sg.w;
            out.push([at(lo), at(hi)]);
        }
        return out;
    }

    // The sources taking in a frequency now, by channel
    function listeningAt(f, lanes = sourceLanes()) {
        return lanes.filter((l) => (l.currentSpan ? f >= l.currentSpan.low && f <= l.currentSpan.high : l.current === f));
    }

    // Tabs for the bands that have traffic or a source listening in them
    let tabKey = '';
    function buildTabs() {
        const seen = new Set([...freqs.keys()].map((f) => bandOf(f).id));
        for (const lane of sourceLanes())
            for (const f of lane.reach)
                seen.add(bandOf(f).id);
        const found = bands.filter((b) => seen.has(b.id));
        const list = found.length > 1 ? [{ id: 'all', title: 'All' }, ...found] : found;
        if (list.length && !list.some((b) => b.id === band))
            band = list[0].id;
        const key = list.map((b) => b.id).join() + band;
        if (key === tabKey)
            return;
        tabKey = key;
        tabs.replaceChildren(...list.map((b) => el('button', {
            class: ['tab', b.id === band && 'active'], role: 'tab', 'aria-selected': String(b.id === band),
            onclick: () => {
                band = b.id;
                settings.set('coverage.band', band);
                tabKey = '';
                buildTabs();
            },
        }, b.title)));
        if (!list.length)
            status.textContent = 'Nothing seen on any frequency yet.';
    }

    // Where everything goes across the width.  Each band with something in
    // it gets a segment, to scale inside itself and trimmed to what's there;
    // "All" puts the segments side by side, a single band fills the width.
    // x(f) is the canvas x of a frequency, or null if it isn't shown.
    function layout(W, ratio, leftCss = 110) {
        const left = leftCss * ratio;
        const right = 14 * ratio;
        const plotW = Math.max(1, W - left - right);
        const shownBands = band === 'all' ? bands : bands.filter((b) => b.id === band);

        const byBand = new Map();
        const note = (f) => {
            const b = bandOf(f);
            if (!shownBands.includes(b))
                return;
            if (!byBand.has(b))
                byBand.set(b, new Set());
            byBand.get(b).add(f);
        };
        for (const f of freqs.keys())
            note(f);
        for (const lane of sourceLanes())
            for (const f of lane.reach)
                note(f);

        const used = shownBands.filter((b) => byBand.has(b));
        const gap = used.length > 1 ? 28 * ratio : 0;
        // Busier bands get more room, but every band gets some
        const weights = used.map((b) => 3 + byBand.get(b).size);
        const total = weights.reduce((a, z) => a + z, 0) || 1;
        const room = plotW - gap * Math.max(0, used.length - 1);
        let at = left;
        const segments = used.map((b, i) => {
            const fs = [...byBand.get(b)];
            let lo = Math.min(...fs);
            let hi = Math.max(...fs);
            const pad = Math.max((hi - lo) * 0.06, 10000);
            lo -= pad;
            hi += pad;
            const w = (room * weights[i]) / total;
            const seg = { band: b, lo, hi, x0: at, w };
            at += w + gap;
            return seg;
        });

        const x = (f) => {
            const seg = segments.find((sg) => sg.band === bandOf(f));
            if (!seg || f < seg.lo || f > seg.hi)
                return null;
            return seg.x0 + ((f - seg.lo) / (seg.hi - seg.lo)) * seg.w;
        };
        const list = [...freqs.keys()].filter((f) => x(f) !== null).sort((a, z) => a - z);
        return { left, right, plotW, segments, x, list };
    }

    // A frequency's label: the server's channel name, else the channel a
    // source listens to there, by its phy ('802.15.4 12'), else the phys'
    // channel numbering (the first phy plainly, others with their name, like
    // 'BLE 37'), else the frequency
    let sourceLabels = new Map();
    const label = (khz) => {
        const channel = freqs.get(khz)?.channel;
        if (channel && channel !== 'unknown' && channel !== '0')
            return String(channel);
        return sourceLabels.get(khz) ?? frequencyLabel(khz);
    };

    // Frequency labels on their side under a graph: the channel nearest the
    // graph, then the frequency in MHz.  A label that's already a frequency
    // shows once.
    function freqLabelParts(f) {
        const name = label(f);
        const mhz = String(+(f / 1000).toFixed(3));
        return name === format.frequency(f).replace(' ', '') ? [mhz, null] : [name, mhz];
    }

    // Labels slant down to the left, so a long one takes less height
    const labelAngle = Math.PI / 4;

    function freqLabelsHeight(ctx, list, font, maxH) {
        const gap = font * 0.6;
        let longest = 0;
        for (const f of list) {
            const [a, b] = freqLabelParts(f);
            longest = Math.max(longest, ctx.measureText(a).width + (b ? gap + ctx.measureText(b).width : 0));
        }
        return Math.min(maxH, Math.max(font * 2.4, longest * Math.sin(labelAngle) + font * 1.5));
    }

    // Labels that would touch one already placed are left out.  They're
    // placed in order of interest: the hovered or picked frequency, then ones
    // with traffic in the last minute, then the rest, each left to right.
    function drawFreqLabels(ctx, list, x, top, font, colors, picked = null) {
        const gap = font * 0.6;
        const rank = (f) => (f === picked ? 0 : history(f, 'packets').some((v) => v > 0) ? 1 : freqs.has(f) ? 2 : 3);
        const order = list.filter((f) => x(f) !== null).map((f) => ({ f, r: rank(f), x: x(f) }))
            .sort((a, z) => a.r - z.r || a.x - z.x);
        // Slanted labels side by side need more room across than upright ones
        const apart = (font * 1.15) / Math.sin(labelAngle);
        const placed = [];
        for (const o of order)
            if (!placed.some((p) => Math.abs(p.x - o.x) < apart))
                placed.push(o);
        const keep = placed.map((o) => o.f);
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (const f of keep) {
            const [a, b] = freqLabelParts(f);
            ctx.save();
            ctx.translate(x(f) + font * 0.3, top + font * 0.6);
            ctx.rotate(-labelAngle);
            ctx.fillStyle = f === picked ? colors.accent : colors.text;
            ctx.fillText(a, 0, 0);
            if (b) {
                ctx.fillStyle = f === picked ? colors.accent : colors.muted;
                ctx.fillText(b, -(ctx.measureText(a).width + gap), 0);
            }
            ctx.restore();
        }
    }

    // The chosen measure's last minute for a frequency, oldest first
    const history = (f, which = metric) => freqs.get(f)?.[which] ?? [];

    // "Now": the last full second
    const nowValue = (f, which = metric) => {
        const hst = history(f, which);
        return hst.length > 1 ? hst[hst.length - 2] : 0;
    };

    function draw() {
        cancelAnimationFrame(frame);
        clearTimeout(idle);
        frame = null;
        if (closed)
            return;
        if (view === 'heat')
            return drawHeat();
        if (view === 'time')
            return drawTime();
        // Nothing to see in a hidden tab; look again in a second
        if (document.visibilityState === 'hidden') {
            idle = setTimeout(draw, 1000);
            return;
        }
        const { w: W, h: H, ratio } = fitCanvas(canvas, stage.clientWidth, stage.clientHeight);
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, W, H);

        const accent = themeColor('--accent') || '#4b9fe8';
        const text = themeColor('--text') || '#ddd';
        const muted = themeColor('--muted') || '#888';
        const grid = themeColor('--border') || '#444';
        const surface = themeColor('--surface') || '#111';
        const warn = themeColor('--warn') || '#fc3';
        const font = 11 * ratio;
        ctx.font = `${font}px system-ui, sans-serif`;

        const { left, right, plotW, segments, x, list } = layout(W, ratio);
        const lanes = sourceLanes();

        // Two areas, top to bottom; the sources are in their own strip below
        const laneH = 26 * ratio;
        const sourcesH = 0;
        const labelsH = freqLabelsHeight(ctx, list, font, H * 0.25);
        const gapH = font;
        const actH = (H - sourcesH - labelsH - gapH) * 0.55;
        const actTop = font;
        const actBottom = actH;
        const histTop = actH + gapH;
        const histBottom = H - sourcesH - labelsH;

        const barW = Math.max(3 * ratio, Math.min(28 * ratio, plotW / Math.max(1, list.length) * 0.5,
            // never wider than the gap to the nearest neighbour
            ...list.slice(1).map((f, i) => (x(f) - x(list[i])) * 0.8).filter((d) => d > 0)));

        // Section names down the left
        ctx.fillStyle = muted;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.fillText(metrics[metric].unit, 8 * ratio, actTop);
        ctx.fillText('Last minute', 8 * ratio, histTop);
        ctx.fillText('now', 8 * ratio, histTop + font * 1.4);
        ctx.textBaseline = 'bottom';
        ctx.fillText('-60s', 8 * ratio, histBottom);

        // With more than one band showing, name each segment and mark the breaks
        if (segments.length > 1) {
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = muted;
            segments.forEach((sg, i) => {
                ctx.fillText(sg.band.title, sg.x0 + sg.w / 2, 0);
                if (i > 0) {
                    const bx = Math.round(sg.x0 - 14 * ratio) + 0.5;
                    ctx.strokeStyle = grid;
                    ctx.setLineDash([3 * ratio, 4 * ratio]);
                    ctx.beginPath();
                    ctx.moveTo(bx, actTop);
                    ctx.lineTo(bx, H);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }
            });
        }

        if (!list.length && !lanes.length) {
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('Nothing seen in this band yet', W / 2, H / 2);
            idle = setTimeout(draw, 500);
            return;
        }

        // What each source with a wide channel takes in now, behind the bars;
        // the one under the pointer in the sources strip stands out
        for (const lane of lanes) {
            if (!lane.currentSpan)
                continue;
            const on = hoverLane === lane.src['kismet.datasource.uuid'];
            ctx.globalAlpha = on ? 0.2 : 0.07;
            ctx.fillStyle = accent;
            for (const [x0, x1] of spanPieces(lane.currentSpan, segments))
                ctx.fillRect(x0, actTop, Math.max(ratio, x1 - x0), actBottom - actTop);
        }
        ctx.globalAlpha = 1;

        // Activity bars, eased toward the latest second
        let animating = false;
        const peak = Math.max(1, ...list.map((f) => Math.max(0, ...history(f))));
        const yAct = (v) => actBottom - (v / peak) * (actBottom - actTop - font);
        ctx.strokeStyle = grid;
        ctx.lineWidth = ratio;
        for (const sg of segments) {
            ctx.beginPath();
            ctx.moveTo(sg.x0, Math.round(actBottom) + 0.5);
            ctx.lineTo(sg.x0 + sg.w, Math.round(actBottom) + 0.5);
            ctx.stroke();
        }
        ctx.fillStyle = muted;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(num(peak), left - 6 * ratio, yAct(peak));
        ctx.fillText('0', left - 6 * ratio, actBottom);

        for (const f of list) {
            const target = nowValue(f);
            const cur = shown.get(f) ?? 0;
            const next = Math.abs(target - cur) < 0.05 ? target : cur + (target - cur) * 0.18;
            if (next !== target)
                animating = true;
            shown.set(f, next);

            const cx = x(f);
            const top = Math.min(yAct(next), actBottom - 1.5 * ratio);
            ctx.globalAlpha = hover === f || pinned === f ? 1 : 0.85;
            ctx.fillStyle = accent;
            ctx.fillRect(cx - barW / 2, top, barW, actBottom - top);
            ctx.globalAlpha = 1;

            // The minute's busiest second
            const max = Math.max(0, ...history(f));
            if (max > 0) {
                ctx.fillStyle = warn;
                ctx.fillRect(cx - barW / 2, yAct(max) - ratio, barW, 2 * ratio);
            }
        }

        // Channel and frequency labels under both graphs
        drawFreqLabels(ctx, list, x, histBottom, font, { text, muted, accent }, hover ?? pinned);

        // History waterfall: one row per second, newest at the top.  Rows are
        // placed by how long ago they were, so they slide down smoothly as
        // time passes; new seconds fill in at the top as data arrives.
        const rows = 60;
        const rowH = (histBottom - histTop) / rows;
        const slide = Math.min(channelSeconds + 1, (performance.now() - fetchedAt) / 1000);
        const logPeak = Math.log1p(peak);
        ctx.save();
        ctx.beginPath();
        ctx.rect(left, histTop, plotW, histBottom - histTop);
        ctx.clip();
        ctx.fillStyle = surface;
        for (const sg of segments)
            ctx.fillRect(sg.x0, histTop, sg.w, histBottom - histTop);
        for (const f of list) {
            const hst = history(f);
            for (let i = 0; i < hst.length; i++) {
                const v = hst[hst.length - 1 - i];
                if (!v)
                    continue;
                const top = histTop + (i + slide) * rowH;
                ctx.globalAlpha = 0.15 + 0.85 * (Math.log1p(v) / logPeak);
                ctx.fillStyle = accent;
                ctx.fillRect(x(f) - barW / 2, top, barW, Math.ceil(rowH) + 0.5);
            }
        }
        ctx.restore();
        ctx.globalAlpha = 1;
        ctx.strokeStyle = grid;
        for (const sg of segments)
            ctx.strokeRect(Math.round(sg.x0) + 0.5, histTop + 0.5, Math.round(sg.w) - 1, histBottom - histTop - 1);

        if (drawSources(W, ratio, x, segments, lanes, { left, font, laneH, accent, text, muted, grid }))
            animating = true;

        // Full speed while bars or markers are moving; otherwise about 15
        // frames a second, enough for the waterfall's slow scroll
        if (animating)
            frame = requestAnimationFrame(draw);
        else
            idle = setTimeout(() => { frame = requestAnimationFrame(draw); }, 66);
    }

    // The heat map: a row per frequency, grouped by band, and a column per
    // second, minute, or hour.  Cells are shaded on a log scale up to the
    // busiest cell shown; the last column is still filling.
    let heatLayout = null;

    function heatRows() {
        const shownBands = band === 'all' ? bands : bands.filter((b) => b.id === band);
        const rows = [];
        for (const b of shownBands) {
            const fs = [...freqs.keys()].filter((f) => bandOf(f) === b).sort((a, z) => a - z);
            if (!fs.length)
                continue;
            if (shownBands.length > 1)
                rows.push({ band: b });
            for (const f of fs)
                rows.push({ f });
        }
        return rows;
    }

    function heatColumns(f) {
        const sp = spans[span];
        const r = freqs.get(f)?.rrds?.[metric];
        const h = rrd.history(r, serverNow, span);
        return h.length ? h : new Array(sp.columns).fill(0);
    }

    // Labels under the columns: seconds ago, or the clock time of the minute or hour
    function columnLabel(i, n) {
        const sp = spans[span];
        const ago = (n - 1 - i) * sp.seconds;
        if (span === 'minute')
            return ago ? `-${ago}s` : 'now';
        const t = new Date(((serverNow ?? Date.now() / 1000) - ago) * 1000);
        const hh = String(t.getHours()).padStart(2, '0');
        return span === 'day' ? `${hh}:00` : `${hh}:${String(t.getMinutes()).padStart(2, '0')}`;
    }

    function drawHeat() {
        const ratio = window.devicePixelRatio || 1;
        const rows = heatRows();
        const font = 11 * ratio;
        const rowMin = 9;
        const top = 34;
        const bottom = 26;
        const cssW = Math.max(1, heatScroll.clientWidth);
        const cssH = Math.max(heatScroll.clientHeight, top + bottom + rows.length * rowMin);
        if (heatCanvas.style.height !== `${cssH}px`)
            heatCanvas.style.height = `${cssH}px`;
        const { w: W, h: H } = fitCanvas(heatCanvas, cssW, cssH);
        const ctx = heatCanvas.getContext('2d');
        ctx.clearRect(0, 0, W, H);
        ctx.font = `${font}px system-ui, sans-serif`;

        const accent = themeColor('--accent') || '#4b9fe8';
        const text = themeColor('--text') || '#ddd';
        const muted = themeColor('--muted') || '#888';
        const grid = themeColor('--border') || '#444';
        const surface = themeColor('--surface-2') || themeColor('--surface') || '#111';

        const m = metrics[metric];
        const sp = spans[span];
        const left = 150 * ratio;
        const right = 14 * ratio;
        const plotW = Math.max(1, W - left - right);
        const y0 = top * ratio;
        const rowH = rows.length ? (H - y0 - bottom * ratio) / rows.length : 0;
        const colW = plotW / sp.columns;
        heatLayout = { rows, left, y0, rowH, colW, columns: sp.columns, ratio };

        if (!rows.length) {
            ctx.fillStyle = muted;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('Nothing seen in this band yet', W / 2, H / 2);
            return;
        }

        const data = rows.map((r) => (r.f ? heatColumns(r.f) : null));
        const heatLanes = sourceLanes();
        const peak = Math.max(0, ...data.filter(Boolean).flat());
        const logPeak = Math.log1p(peak) || 1;

        // Legend: the scale from nothing to the busiest cell
        ctx.textBaseline = 'middle';
        ctx.textAlign = 'left';
        ctx.fillStyle = muted;
        ctx.fillText(`${m.unit}, ${sp.title.toLowerCase()}`, 8 * ratio, 12 * ratio);
        const peakText = m.fmt(peak);
        const lw = 160 * ratio;
        const lx = W - right - ctx.measureText(peakText).width - 6 * ratio - lw;
        const grad = ctx.createLinearGradient(lx, 0, lx + lw, 0);
        grad.addColorStop(0, surface);
        grad.addColorStop(1, accent);
        ctx.fillStyle = grad;
        ctx.fillRect(lx, 7 * ratio, lw, 10 * ratio);
        ctx.fillStyle = muted;
        ctx.textAlign = 'right';
        ctx.fillText('0', lx - 6 * ratio, 12 * ratio);
        ctx.fillText(peakText, W - right, 12 * ratio);

        rows.forEach((r, i) => {
            const y = y0 + i * rowH;
            if (r.band) {
                ctx.fillStyle = muted;
                ctx.textAlign = 'left';
                ctx.fillText(r.band.title, 8 * ratio, y + rowH / 2);
                ctx.strokeStyle = grid;
                ctx.beginPath();
                ctx.moveTo(left, Math.round(y + rowH / 2) + 0.5);
                ctx.lineTo(W - right, Math.round(y + rowH / 2) + 0.5);
                ctx.stroke();
                return;
            }
            ctx.fillStyle = surface;
            ctx.fillRect(left, y, plotW, Math.max(1, rowH - ratio));
            const vals = data[i];
            for (let c = 0; c < vals.length; c++) {
                const v = vals[c];
                if (!(v > 0))
                    continue;
                ctx.globalAlpha = 0.15 + 0.85 * (Math.log1p(v) / logPeak);
                ctx.fillStyle = accent;
                ctx.fillRect(left + c * colW, y, Math.ceil(colW), Math.max(1, rowH - ratio));
            }
            ctx.globalAlpha = 1;
            // A mark by the rows a source is taking in now
            if (listeningAt(r.f, heatLanes).length) {
                ctx.fillStyle = accent;
                ctx.fillRect(left - 5 * ratio, y, 3 * ratio, Math.max(1, rowH - ratio));
            }
            // Row labels, when there's room for them
            if (rowH >= font * 0.9 || i % Math.ceil((font * 0.9) / rowH) === 0) {
                ctx.fillStyle = r.f === heatHover?.f ? accent : text;
                ctx.textAlign = 'right';
                ctx.fillText(label(r.f), left - 9 * ratio, y + rowH / 2);
            }
        });

        // The column still filling, and the hovered cell
        const nowX = left + (sp.columns - 1) * colW;
        ctx.strokeStyle = muted;
        ctx.setLineDash([3 * ratio, 3 * ratio]);
        ctx.strokeRect(Math.round(nowX) + 0.5, y0, Math.round(colW), rows.length * rowH);
        ctx.setLineDash([]);
        if (heatHover?.f !== undefined && heatHover.col !== undefined) {
            const ri = rows.findIndex((r) => r.f === heatHover.f);
            if (ri >= 0) {
                ctx.strokeStyle = text;
                ctx.strokeRect(left + heatHover.col * colW + 0.5, y0 + ri * rowH + 0.5, Math.max(1, colW - 1), Math.max(1, rowH - 1));
            }
        }

        // Time labels, spaced so they don't run together
        ctx.fillStyle = muted;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        const every = span === 'day' ? 4 : 10;
        const ly = y0 + rows.length * rowH + 6 * ratio;
        for (let c = sp.columns - 1; c >= 0; c -= every)
            ctx.fillText(columnLabel(c, sp.columns), left + (c + 0.5) * colW, ly);

        // The minute view moves every second; the others only when data arrives
        if (span === 'minute' && !closed)
            idle = setTimeout(draw, 1000);
    }

    let heatHover = null;

    function heatCell(e) {
        if (!heatLayout)
            return null;
        const { rows, left, y0, rowH, colW, columns, ratio } = heatLayout;
        const r = heatCanvas.getBoundingClientRect();
        const px = (e.clientX - r.left) * ratio;
        const py = (e.clientY - r.top) * ratio;
        const ri = Math.floor((py - y0) / rowH);
        if (ri < 0 || ri >= rows.length || !rows[ri].f)
            return null;
        const col = px >= left ? Math.min(columns - 1, Math.floor((px - left) / colW)) : undefined;
        return { f: rows[ri].f, col };
    }

    heatCanvas.addEventListener('pointermove', (e) => {
        const cell = heatCell(e);
        heatHover = cell;
        draw();
        if (!cell) {
            tip.hidden = true;
            return;
        }
        const named = channelsAt(cell.f).map((c) => `${c.phy} ${c.channel}`);
        const rec = freqs.get(cell.f);
        const server = rec?.channel && rec.channel !== 'unknown' && rec.channel !== '0' ? `Channel ${rec.channel}` : null;
        const title = [server, ...named, format.frequency(cell.f)].filter(Boolean)
            .filter((v, i, a) => a.indexOf(v) === i).join(' · ');
        const lines = [el('b', {}, title)];
        if (cell.col === undefined) {
            lines.push(el('div', { class: 'muted' }, 'Click to see it in the live view'));
        } else {
            const sp = spans[span];
            const v = heatColumns(cell.f)[cell.col] ?? 0;
            const when = span === 'minute' ? columnLabel(cell.col, sp.columns) :
                `${span === 'hour' ? 'the minute' : 'the hour'} from ${columnLabel(cell.col, sp.columns)}`;
            lines.push(el('div', {}, `${metrics[metric].fmt(v)} ${metrics[metric].unit.toLowerCase()}`,
                span === 'minute' ? '' : ' on average', `, ${when}`));
            if (cell.col === sp.columns - 1)
                lines.push(el('div', { class: 'muted' }, 'Still being counted'));
        }
        lines.push(...listening(cell.f));
        tip.replaceChildren(...lines);
        tip.hidden = false;
        const sr = stage.getBoundingClientRect();
        tip.style.left = `${Math.min(Math.max(0, e.clientX - sr.left + 14), sr.width - tip.offsetWidth - 4)}px`;
        tip.style.top = `${Math.max(0, e.clientY - sr.top - tip.offsetHeight - 10)}px`;
    });
    heatCanvas.addEventListener('pointerleave', () => {
        heatHover = null;
        tip.hidden = true;
        draw();
    });
    // A row's label opens that frequency in the live view
    heatCanvas.addEventListener('click', (e) => {
        const cell = heatCell(e);
        if (!cell || cell.col !== undefined)
            return;
        pinned = cell.f;
        setView('live');
    });

    // The time view: the estimate as a few numbers, a bar per frequency at its
    // place on the air, each source's time by band, the busy frequencies
    // heard least, and a table of every frequency
    let timeLayout = null;
    let timeHover = null;

    // The chosen measure's average over the last minute's full seconds
    function activity(f) {
        const h = history(f).slice(0, -1);
        return h.length ? h.reduce((a, z) => a + z, 0) / h.length : 0;
    }

    const pct = (v) => (v > 0 && v < 0.01 ? '<1%' : `${Math.round(v * 100)}%`);
    const secs = (s) => {
        if (s < 1)
            return `${Math.round(s * 1000)} ms`;
        if (s < 60)
            return `${s < 10 ? +s.toFixed(1) : Math.round(s)} s`;
        return format.duration(Math.round(s));
    };

    function drawTime() {
        const est = timeEstimate();
        timeLayout = null;
        if (!timeScroll.clientWidth)
            return;

        const peakAct = Math.max(0, ...[...freqs.keys()].map(activity));
        const busy = (f) => {
            const a = activity(f);
            return a > 0 && a >= peakAct * 0.05;
        };
        const coverage = (f) => est.byFreq.get(f)?.coverage ?? 0;
        const rarely = (f) => busy(f) && coverage(f) < 0.25;

        timeStats[0].update(format.count([...est.byFreq.values()].filter((e) => e.coverage > 0).length));
        timeStats[1].update(format.count([...freqs.keys()].filter(rarely).length));
        timeStats[2].update(`${est.plans.filter((p) => p.n).length} of ${est.plans.length}`);

        // The bars, on their own so hovering redraws only them
        const chart = () => {
            const accent = themeColor('--accent') || '#4b9fe8';
            const text = themeColor('--text') || '#ddd';
            const muted = themeColor('--muted') || '#888';
            const grid = themeColor('--border') || '#444';
            const warn = themeColor('--warn') || '#fc3';
            const ratio = window.devicePixelRatio || 1;
            const font = 11 * ratio;

            // Every frequency with traffic or a source planned on it
            const cssW = timeCanvas.clientWidth || timeScroll.clientWidth;
            const probe = timeCanvas.getContext('2d');
            probe.font = `${font}px system-ui, sans-serif`;
            const { segments, x, left } = layout(cssW * ratio, ratio, 44);
            const list = [...new Set([...freqs.keys(), ...est.byFreq.keys()])].filter((f) => x(f) !== null).sort((a, z) => a - z);
            const plotH = 170 * ratio;
            const top = font * 1.6;
            const labelsH = freqLabelsHeight(probe, list, font, 130 * ratio);
            const cssH = Math.round((top + plotH + labelsH) / ratio);
            if (timeCanvas.style.height !== `${cssH}px`)
                timeCanvas.style.height = `${cssH}px`;
            const { w: W, h: H } = fitCanvas(timeCanvas, cssW, cssH);
            const ctx = timeCanvas.getContext('2d');
            ctx.clearRect(0, 0, W, H);
            ctx.font = `${font}px system-ui, sans-serif`;
            const bottom = top + plotH;
            const y = (v) => bottom - v * plotH;

            // Recessive gridlines at quarters, labelled down the left
            ctx.strokeStyle = grid;
            ctx.lineWidth = ratio;
            ctx.fillStyle = muted;
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            for (const q of [0, 0.25, 0.5, 0.75, 1]) {
                ctx.globalAlpha = q === 0 ? 1 : 0.45;
                for (const sg of segments) {
                    ctx.beginPath();
                    ctx.moveTo(sg.x0, Math.round(y(q)) + 0.5);
                    ctx.lineTo(sg.x0 + sg.w, Math.round(y(q)) + 0.5);
                    ctx.stroke();
                }
                ctx.globalAlpha = 1;
                ctx.fillText(`${q * 100}%`, left - 6 * ratio, y(q));
            }
            if (segments.length > 1) {
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                for (const sg of segments)
                    ctx.fillText(sg.band.title, sg.x0 + sg.w / 2, 0);
            }

            if (!list.length) {
                ctx.textAlign = 'center';
                ctx.fillText('No source has a channel plan to estimate from', W / 2, top + plotH / 2);
            }

            const barW = Math.max(3 * ratio, Math.min(18 * ratio,
                ...list.slice(1).map((f, i) => (x(f) - x(list[i])) * 0.7).filter((d) => d > 0)));
            const radius = Math.min(4 * ratio, barW / 2);
            for (const f of list) {
                const v = coverage(f);
                if (!(v > 0))
                    continue;
                const h = Math.max(2 * ratio, v * plotH);
                ctx.fillStyle = rarely(f) ? warn : accent;
                ctx.globalAlpha = timeHover === null || timeHover === f ? 1 : 0.7;
                ctx.beginPath();
                ctx.roundRect(x(f) - barW / 2, bottom - h, barW, h, [radius, radius, 0, 0]);
                ctx.fill();
            }
            ctx.globalAlpha = 1;
            // Busy frequencies nobody listens to, as a mark on the baseline
            for (const f of list) {
                if (coverage(f) === 0 && rarely(f)) {
                    ctx.fillStyle = warn;
                    ctx.fillRect(x(f) - barW / 2, bottom - 2 * ratio, barW, 2 * ratio);
                }
            }
            drawFreqLabels(ctx, list, x, bottom, font, { text, muted, accent }, timeHover);
            timeLayout = { x, list, ratio, est, rarely, redraw: chart };
            return list;
        };
        const list = chart();

        // Each source's time by band, labelled in place
        timeSources.replaceChildren(...est.plans.map((p) => {
            let how;
            if (!p.n)
                how = 'No channel to estimate from';
            else if (!p.hopping)
                how = `On ${p.src['kismet.datasource.channel'] || p.src['kismet.datasource.hop_channels']?.[0]} all the time`;
            else if (!p.per.size)
                how = `${p.n} channels at ${num(p.rate)} hops/s, on frequencies the web UI doesn't know`;
            else
                how = `${p.n} channels at ${num(p.rate)} hops/s: ${secs(1 / p.rate)} on each, back every ${secs(p.n / p.rate)}` +
                    (p.splitWith.length ? `, split with ${p.splitWith.join(', ')}` : '');
            const parts = [...p.bandsIn].sort((a, z) => bands.indexOf(a[0]) - bands.indexOf(z[0]));
            const counted = parts.reduce((a, [, c]) => a + c, 0) || 1;
            return el('div', { class: 'coverage-time-source' },
                el('span', { class: 'coverage-time-name', title: p.name }, p.name),
                parts.length ? el('span', { class: 'coverage-time-split' }, parts.map(([b, c], i) =>
                    el('span', { class: ['seg', i % 2 && 'alt'], style: { flexGrow: c }, title: `${b.title}: ${pct(c / counted)}` },
                        `${b.title} ${pct(c / counted)}`))) : null,
                el('span', { class: 'muted coverage-time-how' }, how));
        }));

        // Busy but rarely heard: activity times the share of time nobody's listening
        const unit = metrics[metric].unit.toLowerCase();
        timeMissedTitle.textContent = `Busy but rarely heard: ${unit} on average while no source listens`;
        timeMissed.update([...freqs.keys()].filter(rarely).map((f) => ({
            id: f, label: `${label(f)} · ${format.frequency(f)}`, value: activity(f) * (1 - coverage(f)),
            title: `${metrics[metric].fmt(activity(f))} ${unit} on average, listened to about ${pct(coverage(f))} of the time`,
        })).sort((a, z) => z.value - a.value).slice(0, 10));

        timeTable.replaceChildren(...list.map((f) => {
            const e = est.byFreq.get(f);
            const v = e?.coverage ?? 0;
            return el('tr', { class: rarely(f) ? 'coverage-time-rare' : null },
                el('td', {}, label(f)),
                el('td', {}, format.frequency(f)),
                el('td', {}, el('span', { class: 'coverage-time-meter' }, el('span', { style: { width: `${v * 100}%` } })), ` ${pct(v)}`),
                el('td', { title: e?.shares.map((s) => `${s.name} ${pct(s.share)}`).join(', ') ?? '' },
                    e?.shares.map((s) => `${s.name} ${pct(s.share)}`).join(', ') || '–'),
                el('td', {}, e ? (e.fixed ? 'all the time' : secs(e.visit)) : '–'),
                el('td', {}, e ? (e.fixed ? '–' : secs(1 / e.visitsPerSec)) : 'never'),
                el('td', {}, metrics[metric].fmt(activity(f))));
        }));
    }

    timeCanvas.addEventListener('pointermove', (e) => {
        if (!timeLayout)
            return;
        const { x, list, ratio, est, rarely } = timeLayout;
        const r = timeCanvas.getBoundingClientRect();
        const px = (e.clientX - r.left) * ratio;
        let best = null;
        let bestD = 12 * ratio;
        for (const f of list) {
            const d = Math.abs(x(f) - px);
            if (d < bestD) {
                best = f;
                bestD = d;
            }
        }
        if (best !== timeHover) {
            timeHover = best;
            timeLayout.redraw();
        }
        if (best === null) {
            tip.hidden = true;
            return;
        }
        const est1 = est.byFreq.get(best);
        const named = channelsAt(best).map((c) => `${c.phy} ${c.channel}`);
        const lines = [el('b', {}, [...named, format.frequency(best)].filter((v, i, a) => a.indexOf(v) === i).join(' · '))];
        if (!est1) {
            lines.push(el('div', {}, 'No source listens here'));
        } else {
            lines.push(el('div', {}, `Listened to about ${pct(est1.coverage)} of the time (estimated)`));
            lines.push(el('div', {}, est1.fixed ? 'A source stays on it' :
                `${secs(est1.visit)} at a time, about every ${secs(1 / est1.visitsPerSec)}`));
            lines.push(el('div', { class: 'muted' }, est1.shares.map((s) => `${s.name} ${pct(s.share)}`).join(', ')));
        }
        lines.push(el('div', {}, `${metrics[metric].fmt(activity(best))} ${metrics[metric].unit.toLowerCase()} on average`));
        if (rarely(best))
            lines.push(el('div', { class: 'muted' }, 'Busy, but heard under a quarter of the time'));
        tip.replaceChildren(...lines);
        tip.hidden = false;
        const sr = stage.getBoundingClientRect();
        tip.style.left = `${Math.min(Math.max(0, e.clientX - sr.left + 14), sr.width - tip.offsetWidth - 4)}px`;
        tip.style.top = `${Math.max(0, e.clientY - sr.top - tip.offsetHeight - 10)}px`;
    });
    timeCanvas.addEventListener('pointerleave', () => {
        timeHover = null;
        tip.hidden = true;
        timeLayout?.redraw();
    });

    // The source lanes, in their own canvas under the graphs, using the same
    // layout so ticks and markers line up with the bars.  Returns true while a
    // marker is still moving.
    function drawSources(W, ratio, x, segments, lanes, { left, font, laneH, accent, text, muted, grid }) {
        const cssH = Math.round((font * 2.6 + Math.max(1, lanes.length) * laneH) / ratio);
        if (srcCanvas.style.height !== `${cssH}px`)
            srcCanvas.style.height = `${cssH}px`;
        // Exactly as wide as the graphs above, scrollbar or not
        if (srcCanvas.style.width !== `${W / ratio}px`)
            srcCanvas.style.width = `${W / ratio}px`;
        const H = Math.round(cssH * ratio);
        if (srcCanvas.width !== W || srcCanvas.height !== H) {
            srcCanvas.width = W;
            srcCanvas.height = H;
        }
        const ctx = srcCanvas.getContext('2d');
        ctx.clearRect(0, 0, W, H);
        ctx.font = `${font}px system-ui, sans-serif`;
        ctx.fillStyle = muted;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.fillText('Sources', 8 * ratio, 4 * ratio);
        if (!lanes.length) {
            ctx.fillText('No data sources running', left, 4 * ratio);
            return false;
        }
        const srcTop = 0;
        let animating = false;

        // The same breaks between bands as above
        ctx.strokeStyle = grid;
        segments.forEach((sg, i) => {
            if (i === 0)
                return;
            const bx = Math.round(sg.x0 - 14 * ratio) + 0.5;
            ctx.setLineDash([3 * ratio, 4 * ratio]);
            ctx.beginPath();
            ctx.moveTo(bx, 0);
            ctx.lineTo(bx, H);
            ctx.stroke();
            ctx.setLineDash([]);
        });
        // Hop channels as ticks; the current one as a marker that glides from
        // channel to channel as the source hops
        ctx.textBaseline = 'middle';
        lanes.forEach((lane, i) => {
            const cy = srcTop + font * 3 + i * laneH;
            const name = lane.src['kismet.datasource.name'] ?? '?';
            ctx.fillStyle = text;
            ctx.textAlign = 'right';
            ctx.fillText(name.length > 16 ? `${name.slice(0, 15)}…` : name, left - 8 * ratio, cy);

            ctx.strokeStyle = grid;
            for (const sg of segments) {
                ctx.beginPath();
                ctx.moveTo(sg.x0, cy);
                ctx.lineTo(sg.x0 + sg.w, cy);
                ctx.stroke();
            }

            // Wide channels as bars across what they take in: the ones hopped
            // through faintly, the current one in the accent color
            const uuid = lane.src['kismet.datasource.uuid'];
            const on = hoverLane === uuid;
            ctx.fillStyle = muted;
            ctx.globalAlpha = 0.3;
            for (const sp of lane.hopSpans)
                for (const [x0, x1] of spanPieces(sp, segments))
                    ctx.fillRect(x0, cy - 4 * ratio, Math.max(ratio, x1 - x0), 8 * ratio);
            if (lane.currentSpan) {
                ctx.fillStyle = accent;
                ctx.globalAlpha = on ? 0.7 : 0.45;
                for (const [x0, x1] of spanPieces(lane.currentSpan, segments))
                    ctx.fillRect(x0, cy - 6 * ratio, Math.max(ratio, x1 - x0), 12 * ratio);
            }
            ctx.globalAlpha = 1;

            ctx.fillStyle = muted;
            for (const f of lane.hop) {
                const fx = x(f);
                if (fx !== null)
                    ctx.fillRect(fx - ratio, cy - 5 * ratio, 2 * ratio, 10 * ratio);
            }

            // The marker glides in screen space, so a hop between bands
            // slides across the break instead of jumping
            const targetX = lane.current ? x(lane.current) : null;
            if (targetX !== null) {
                const from = markers.get(uuid) ?? targetX;
                const atX = Math.abs(targetX - from) < 0.5 ? targetX : from + (targetX - from) * 0.25;
                if (atX !== targetX)
                    animating = true;
                markers.set(uuid, atX);
                ctx.fillStyle = accent;
                ctx.beginPath();
                ctx.arc(atX, cy, 5 * ratio, 0, Math.PI * 2);
                ctx.fill();
            } else {
                markers.delete(uuid);
                ctx.fillStyle = muted;
                ctx.textAlign = 'left';
                const hopping = lane.src['kismet.datasource.hopping'];
                const why = lane.current ? 'listening in another band' :
                    (hopping ? 'hopping' : (lane.src['kismet.datasource.channel'] ? `on ${lane.src['kismet.datasource.channel']}` : 'no channel'));
                ctx.fillText(why, left + 8 * ratio, cy - 11 * ratio);
            }
        });

        return animating;
    }

    // The sources taking in a frequency now, for the tooltips
    function listening(f) {
        const on = listeningAt(f);
        if (!on.length)
            return [];
        return [el('div', { class: 'muted' }, `Listening: ${on.map((l) =>
            `${l.src['kismet.datasource.name'] ?? '?'} (${l.src['kismet.datasource.channel']})`).join(', ')}`)];
    }

    // Hovering over a source lane picks out what it takes in
    srcCanvas.addEventListener('pointermove', (e) => {
        const ratio = window.devicePixelRatio || 1;
        const r = srcCanvas.getBoundingClientRect();
        const py = (e.clientY - r.top) * ratio;
        const font = 11 * ratio;
        const i = Math.round((py - font * 3) / (26 * ratio));
        const lanes = sourceLanes();
        const id = i >= 0 && i < lanes.length ? lanes[i].src['kismet.datasource.uuid'] : null;
        if (id !== hoverLane) {
            hoverLane = id;
            draw();
        }
    });
    srcCanvas.addEventListener('pointerleave', () => {
        if (hoverLane !== null) {
            hoverLane = null;
            draw();
        }
    });

    // Hovering over a frequency shows what's on it
    stage.addEventListener('pointermove', (e) => {
        if (view !== 'live')
            return;
        const ratio = window.devicePixelRatio || 1;
        const r = stage.getBoundingClientRect();
        const { x, list } = layout(stage.clientWidth * ratio, ratio);
        const px = (e.clientX - r.left) * ratio;
        let best = null;
        let bestD = 12 * ratio;
        for (const f of list) {
            const dist = Math.abs(x(f) - px);
            if (dist < bestD) {
                best = f;
                bestD = dist;
            }
        }
        hover = best;
        if (best === null) {
            tip.hidden = true;
            return;
        }
        const rec = freqs.get(best);
        const busiest = Math.max(0, ...history(best, 'devices'));
        // Every phy's channel here: Wi-Fi 1 and BLE 4 share 2412 MHz
        const named = channelsAt(best).map((c) => `${c.phy} ${c.channel}`);
        const server = rec.channel && rec.channel !== 'unknown' && rec.channel !== '0' ? `Channel ${rec.channel}` : null;
        tip.replaceChildren(
            el('b', {}, [server, ...named, format.frequency(best)].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(' · ')),
            el('div', {}, `${num(nowValue(best, 'devices'))} devices now, up to ${num(busiest)} in the last minute`),
            el('div', {}, `${num(nowValue(best, 'packets'))} packets/s now`),
            rec.signal ? el('div', {}, `Last signal ${format.signal(rec.signal)}`) : null,
            ...listening(best));
        tip.hidden = false;
        const tx = Math.min(Math.max(0, e.clientX - r.left + 14), r.width - tip.offsetWidth - 4);
        tip.style.left = `${tx}px`;
        tip.style.top = `${Math.max(0, e.clientY - r.top - tip.offsetHeight - 10)}px`;
    });
    stage.addEventListener('pointerleave', () => {
        if (view !== 'live')
            return;
        hover = null;
        tip.hidden = true;
    });

    showButtons();
    loadChannels();
    loadSources();
    draw();
    openWindow = { dialog: d, setView };
    return d;
}
