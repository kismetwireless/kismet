// The Packet rates window: the server's packet processing (packets in,
// processed, the queue, and what was dropped or duplicated) and a graph for
// each data source, over the last minute, hour or day.  Alerts, and data
// sources opening, closing or failing, are marked on the graphs, and times
// when packets were dropped are shaded.
//
//   recordEvents()   once at startup: keep data source events for the marks
//   openPackets()

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import * as eventbus from '../core/eventbus.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';
import { series } from './charts.js';
import { openSources } from './datasources.js';

const pc = 'kismet.packetchain';
const ds = 'kismet.datasource';

const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
const binSeconds = { minute: 1, hour: 60, day: 3600 };
const spanSeconds = { minute: 60, hour: 3600, day: 86400 };
// Seconds between reads for each span; an hour bin only changes once a minute
const refresh = { minute: 2, hour: 15, day: 60 };

const rates = [
    { id: 'in', label: 'Incoming', field: `${pc}.packets_rrd`, color: series(0) },
    { id: 'peak', label: 'Incoming (peak)', field: `${pc}.peak_packets_rrd`, color: series(4) },
    { id: 'done', label: 'Processed', field: `${pc}.processed_packets_rrd`, color: series(1) },
];
const losses = [
    { id: 'queue', label: 'Queued', field: `${pc}.queued_packets_rrd`, color: series(2) },
    { id: 'drop', label: 'Dropped', field: `${pc}.dropped_packets_rrd`, color: series(3) },
    { id: 'dupe', label: 'Duplicates', field: `${pc}.dupe_packets_rrd`, color: series(5) },
    { id: 'error', label: 'Errors', field: `${pc}.error_packets_rrd`, color: series(7) },
];

// The server doesn't keep a history of data source events, so they're kept
// from when the page loads
const sourceEvents = [];
const sourceEventMax = 500;
const sourceTopics = {
    DATASOURCE_OPENED: ['opened', 'var(--ok)'],
    DATASOURCE_CLOSED: ['closed', 'var(--muted)'],
    DATASOURCE_ERROR: ['failed', 'var(--error)'],
};
const markMax = 200;

let openWindow = null;

export function recordEvents() {
    for (const [topic, [what, color]] of Object.entries(sourceTopics))
        // The event is the source's uuid
        eventbus.subscribe(topic, null, (e) => {
            const uuid = typeof e === 'string' ? e : e?.[topic];
            sourceEvents.push({ t: clock.isKnown() ? clock.now() : Date.now() / 1000, uuid, what, color });
            if (sourceEvents.length > sourceEventMax)
                sourceEvents.shift();
        });
}

// Where a time falls among the values of a graph ending at the last full bin
// before now; see annotate in historygraph.js
function markPos(t, now, span, count) {
    const bin = binSeconds[span];
    return Math.min(count, t / bin - (Math.floor(now / bin) - count));
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

// Runs of values where test(i) holds, as bands
function runs(count, test, color, label) {
    const out = [];
    let from = null;
    for (let i = 0; i <= count; i++) {
        if (i < count && test(i)) {
            from ??= i;
        } else if (from !== null) {
            out.push({ from, to: i, color, label });
            from = null;
        }
    }
    return out;
}

const rateText = (v) => `${v >= 10 ? format.count(Math.round(v)) : v.toFixed(1)}/s`;

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

export function openPackets() {
    if (openWindow?.node.isConnected) {
        openWindow.node.dispatchEvent(new Event('pointerdown'));
        return openWindow;
    }

    let span = settings.get('packets.span', 'minute');
    if (!spans[span])
        span = 'minute';
    let sourceKind = settings.get('packets.sourceKind', 'packets') === 'data' ? 'data' : 'packets';

    // What the readouts label each value with, from the last read
    let shown = { now: Date.now() / 1000, count: 0 };
    const pointLabel = (i) => pointTime(i, shown.now, span, shown.count);

    const rateGraph = historyGraph({ type: 'line', unit: '/s', height: '10rem', min: 0, pointLabel });
    // The queue is a count of packets waiting, the others per second
    const lossGraph = historyGraph({ type: 'line', height: '8rem', min: 0, pointLabel });
    const status = el('span', { class: 'muted' });
    const sourceList = el('ol', { class: 'pk-sources' });
    const sourceNote = el('p', { class: 'muted pk-note' });
    const rows = new Map();

    const body = el('div', { class: 'pk-window' },
        el('div', { class: 'pk-bar' },
            tabs(Object.fromEntries(Object.entries(spans).map(([k, v]) => [k, v[0]])), span, (s) => {
                span = s;
                settings.set('packets.span', s);
                read();
            }), status),
        el('section', {}, el('h3', {}, 'Packets per second'), rateGraph.node),
        el('section', {}, el('h3', {}, 'Queue and losses'), lossGraph.node),
        el('section', {},
            el('div', { class: 'pk-head' }, el('h3', {}, 'Data sources'),
                tabs({ packets: 'Packets', data: 'Data' }, sourceKind, (k) => {
                    sourceKind = k;
                    settings.set('packets.sourceKind', k);
                    read();
                })),
            sourceList, sourceNote));

    const w = Math.min(820, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 860);
    const d = dialog({
        title: 'Packet rates', body, modal: false, className: 'pk-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            clearTimeout(timer);
            for (const g of [rateGraph, lossGraph, ...[...rows.values()].map((r) => r.graph)])
                g.destroy();
            openWindow = null;
        },
    });

    // A row for each data source: its name, driver, graph and rate
    function sourceRow(uuid) {
        let r = rows.get(uuid);
        if (!r) {
            r = {
                name: el('button', { type: 'button', class: 'link-button pk-src-name', title: 'Show the data sources', onclick: () => openSources() }),
                driver: el('span', { class: 'muted pk-src-driver' }),
                state: el('span', { class: 'pk-src-state' }),
                rate: el('span', { class: 'pk-src-rate' }),
                graph: historyGraph({ type: 'line', unit: '/s', height: '2.6rem', min: 0, fill: true, pointLabel }),
            };
            r.node = el('li', { class: 'pk-src' }, r.name, r.driver, r.graph.node, el('span', { class: 'pk-src-end' }, r.state, r.rate));
            rows.set(uuid, r);
        }
        return r;
    }

    let timer = null;
    let reading = false;
    const history = (v, now) => {
        const out = rrd.history(v, now, span);
        // The newest bin is still filling
        return out.slice(0, -1);
    };

    async function read() {
        clearTimeout(timer);
        if (!d.node.isConnected)
            return;
        if (!reading && document.visibilityState !== 'hidden') {
            reading = true;
            try {
                const rrdField = sourceKind === 'data' ? `${ds}.packets_datasize_rrd` : `${ds}.packets_rrd`;
                const since = Math.floor((clock.isKnown() ? clock.now() : Date.now() / 1000) - spanSeconds[span]);
                const [stats, sources, alerts] = await Promise.all([
                    api.get('packetchain/packet_stats.json'),
                    api.post('datasource/all_sources.json', { fields: [`${ds}.uuid`, `${ds}.name`, `${ds}.running`, `${ds}.error`,
                        `${ds}.error_reason`, `${ds}.type_driver/${ds}.driver.description`, rrdField] }),
                    api.get(`alerts/wrapped/last-time/${since}/alerts.json`).catch(() => null),
                ]);
                const now = clock.isKnown() ? clock.now() : undefined;
                const at = now ?? Date.now() / 1000;
                const labels = [spans[span][1], 'now'];
                const v = {};
                for (const r of [...rates, ...losses])
                    v[r.id] = history(stats[r.field], now);
                const count = v.in.length;
                shown = { now: at, count };
                const inSpan = (t) => t >= at - binSeconds[span] * count;
                const pos = (t) => markPos(t, at, span, count);

                const names = new Map(sources.map((s) => [s[`${ds}.uuid`], s[`${ds}.name`] || s[`${ds}.uuid`]]));
                const alertMarks = (alerts?.['kismet.alert.list'] ?? []).map((a) => ({
                    t: a['kismet.alert.timestamp'], color: 'var(--warn)',
                    label: `${a['kismet.alert.header']}: ${(a['kismet.alert.text'] ?? '').slice(0, 80)}`,
                }));
                const sourceMarks = sourceEvents.map((e) => ({ t: e.t, uuid: e.uuid, what: e.what, color: e.color,
                    label: `${names.get(e.uuid) ?? 'Data source'} ${e.what}` }));
                const marks = [...sourceMarks, ...alertMarks].filter((m) => inSpan(m.t))
                    .sort((a, b) => a.t - b.t)
                    .slice(-markMax)
                    .map((m) => ({ ...m, pos: pos(m.t) }));

                const dropped = runs(count, (i) => v.drop[i] > 0, 'var(--error)', 'Packets dropped');

                rateGraph.annotate({ marks, bands: dropped });
                rateGraph.draw(rates.map((r) => ({ ...r, values: v[r.id] })), labels);
                lossGraph.annotate({ marks, bands: dropped });
                lossGraph.draw(losses.map((r) => ({ ...r, values: v[r.id] })), labels);

                const order = [...sources].sort((a, b) => (a[`${ds}.name`] ?? '').localeCompare(b[`${ds}.name`] ?? ''));
                const keep = new Set();
                const nodes = order.map((s, i) => {
                    const uuid = s[`${ds}.uuid`];
                    keep.add(uuid);
                    const r = sourceRow(uuid);
                    // Data sizes are in bytes; graph them in kB
                    const values = history(s[rrdField], now).map((x) => sourceKind === 'data' ? x / 1024 : x);
                    r.graph.annotate({ marks: marks.filter((m) => m.uuid === uuid) });
                    // The graphs above label the span; the rows keep their height for the line
                    r.graph.draw([{ label: names.get(uuid), color: series(i), values }], []);
                    r.name.textContent = names.get(uuid);
                    r.driver.textContent = s[`${ds}.driver.description`] ?? '';
                    const last = values.length ? values[values.length - 1] : 0;
                    r.rate.textContent = sourceKind === 'data' ? `${last >= 10 ? Math.round(last) : last.toFixed(1)} kB/s` : rateText(last);
                    const failed = s[`${ds}.error`];
                    r.state.textContent = failed ? 'failed' : s[`${ds}.running`] ? '' : 'closed';
                    r.state.className = ['pk-src-state', failed ? 'badge error' : s[`${ds}.running`] ? '' : 'badge'].join(' ');
                    r.state.title = failed ? s[`${ds}.error_reason`] ?? '' : '';
                    return r.node;
                });
                for (const [uuid, r] of rows)
                    if (!keep.has(uuid)) {
                        r.graph.destroy();
                        rows.delete(uuid);
                    }
                sourceList.replaceChildren(...nodes);
                sourceNote.textContent = !nodes.length ? 'No data sources.' :
                    sourceKind === 'data' ? 'kB per second from each data source.' : 'Packets per second from each data source.';
                status.textContent = `Updated ${format.time(at)}`;
            } catch (err) {
                status.textContent = err.message;
            } finally {
                reading = false;
            }
        }
        timer = setTimeout(read, refresh[span] * 1000);
    }

    read();
    openWindow = d;
    return d;
}
