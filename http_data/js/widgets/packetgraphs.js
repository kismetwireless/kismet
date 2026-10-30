// The Packet rates window: the server's packet processing (packets in,
// processed, the queue, and what was dropped or duplicated) and the packets or
// data from each data source, over the last minute, hour or day.
//
//   openPackets()

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';
import { series } from './charts.js';

const pc = 'kismet.packetchain';
const ds = 'kismet.datasource';

const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
// Seconds between reads for each span; an hour bin only changes once a minute
const refresh = { minute: 2, hour: 15, day: 60 };

const rates = [
    { label: 'Incoming', field: `${pc}.packets_rrd`, color: series(0) },
    { label: 'Incoming (peak)', field: `${pc}.peak_packets_rrd`, color: series(4) },
    { label: 'Processed', field: `${pc}.processed_packets_rrd`, color: series(1) },
];
const losses = [
    { label: 'Queued', field: `${pc}.queued_packets_rrd`, color: series(2) },
    { label: 'Dropped', field: `${pc}.dropped_packets_rrd`, color: series(3) },
    { label: 'Duplicates', field: `${pc}.dupe_packets_rrd`, color: series(5) },
    { label: 'Errors', field: `${pc}.error_packets_rrd`, color: series(7) },
];

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

export function openPackets() {
    if (openWindow?.node.isConnected) {
        openWindow.node.dispatchEvent(new Event('pointerdown'));
        return openWindow;
    }

    let span = settings.get('packets.span', 'minute');
    if (!spans[span])
        span = 'minute';
    let sourceKind = settings.get('packets.sourceKind', 'packets') === 'data' ? 'data' : 'packets';

    const rateGraph = historyGraph({ type: 'line', unit: '/s', height: '10rem', min: 0 });
    // The queue is a count of packets waiting, the others per second
    const lossGraph = historyGraph({ type: 'line', height: '8rem', min: 0 });
    const sourceGraph = historyGraph({ type: 'line', unit: '/s', height: '10rem', min: 0, fill: true });
    const status = el('span', { class: 'muted' });
    const sourceNote = el('p', { class: 'muted pk-note' });

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
            el('div', { class: 'pk-head' }, el('h3', {}, 'Per data source'),
                tabs({ packets: 'Packets', data: 'Data' }, sourceKind, (k) => {
                    sourceKind = k;
                    settings.set('packets.sourceKind', k);
                    read();
                })),
            sourceGraph.node, sourceNote));

    const w = Math.min(820, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 860);
    const d = dialog({
        title: 'Packet rates', body, modal: false, className: 'pk-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            clearTimeout(timer);
            for (const g of [rateGraph, lossGraph, sourceGraph])
                g.destroy();
            openWindow = null;
        },
    });

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
                const [stats, sources] = await Promise.all([
                    api.get('packetchain/packet_stats.json'),
                    api.post('datasource/all_sources.json', { fields: [`${ds}.uuid`, `${ds}.name`, rrdField] }),
                ]);
                const now = clock.isKnown() ? clock.now() : undefined;
                const labels = [spans[span][1], 'now'];
                rateGraph.draw(rates.map((r) => ({ ...r, values: history(stats[r.field], now) })), labels);
                lossGraph.draw(losses.map((r) => ({ ...r, values: history(stats[r.field], now) })), labels);

                const lines = [...sources]
                    .sort((a, b) => (a[`${ds}.name`] ?? '').localeCompare(b[`${ds}.name`] ?? ''))
                    .map((s, i) => ({
                        label: s[`${ds}.name`] || s[`${ds}.uuid`],
                        color: series(i),
                        // Data sizes are in bytes; graph them in kB
                        values: history(s[rrdField], now).map((v) => sourceKind === 'data' ? v / 1024 : v),
                    }));
                sourceGraph.draw(lines, labels);
                sourceNote.textContent = !lines.length ? 'No data sources.' :
                    sourceKind === 'data' ? 'kB per second from each data source.' : 'Packets per second from each data source.';
                status.textContent = `Updated ${format.time(now ?? Date.now() / 1000)}`;
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
