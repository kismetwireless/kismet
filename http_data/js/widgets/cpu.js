// The CPU window: the CPU load of the system the Kismet server runs on, and of
// Kismet itself, over the last minute, hour or day.
//
//   openCpu()
//
// The load is from /system/cpu, as a percent of all the CPUs; servers without
// it, or which can't read the load, say so instead.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';
import { series } from './charts.js';
import { openThermal } from './thermal.js';

const cpu = 'kismet.system.cpu';

const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
const binSeconds = { minute: 1, hour: 60, day: 3600 };
const refresh = { minute: 2, hour: 15, day: 60 };

let openWindow = null;

const pctText = (v) => Number.isFinite(v) ? `${v < 10 ? v.toFixed(1) : Math.round(v)}%` : '-';

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

function range(values) {
    const v = values.filter(Number.isFinite);
    if (!v.length)
        return null;
    return { max: Math.max(...v), avg: v.reduce((a, x) => a + x, 0) / v.length };
}

export function openCpu() {
    if (openWindow?.node.isConnected) {
        openWindow.raise();
        return openWindow;
    }

    let span = settings.get('cpu.span', 'hour');
    if (!spans[span])
        span = 'hour';

    let shown = { now: Date.now() / 1000, count: 0 };
    const pointLabel = (i) => pointTime(i, shown.now, span, shown.count);
    const graph = historyGraph({ type: 'line', unit: '%', height: '13rem', min: 0, joinGaps: true, pointLabel, fmt: pctText });

    const status = el('span', { class: 'muted' });
    const stats = el('div', { class: 'mem-stats' });
    const empty = el('p', { class: 'muted', hidden: true });
    const graphSection = el('section', {}, el('h3', {}, 'CPU load, percent of all CPUs'), graph.node);

    const body = el('div', { class: 'mem-window' },
        el('div', { class: 'pk-bar' },
            tabs(Object.fromEntries(Object.entries(spans).map(([k, v]) => [k, v[0]])), span, (s) => {
                span = s;
                settings.set('cpu.span', s);
                read();
            }), status,
            el('button', { type: 'button', class: 'link-button pk-channels', title: 'Temperatures and CPU load',
                onclick: () => openThermal() }, 'Thermal')),
        stats,
        empty,
        graphSection);

    // Fitted to the content once the first reading is drawn
    const w = Math.min(820, window.innerWidth - 32);
    const d = dialog({
        title: 'CPU', body, modal: false, className: 'pk-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: 300 },
        onClose: () => {
            clearTimeout(timer);
            graph.destroy();
            openWindow = null;
        },
    });

    let timer = null;
    let reading = false;
    let fitted = false;

    async function read() {
        clearTimeout(timer);
        if (!d.node.isConnected)
            return;
        if (!reading && document.visibilityState !== 'hidden') {
            reading = true;
            try {
                const c = await api.get('system/cpu.json');
                const now = clock.isKnown() ? clock.now() : undefined;
                const at = now ?? Date.now() / 1000;
                const available = !!c[`${cpu}.available`];

                empty.hidden = available;
                empty.textContent = 'The server can\'t read its CPU load; Kismet reads it from /proc on Linux.';
                graphSection.hidden = !available;

                if (available) {
                    const hist = (f) => rrd.history(c[`${cpu}.${f}`], now, span, { blank: NaN }).slice(0, -1);
                    const system = hist('total_rrd');
                    const kismet = hist('kismet_rrd');
                    shown = { now: at, count: system.length };
                    graph.draw([
                        { label: 'System', color: series(0), values: system },
                        { label: 'Kismet', color: series(1), values: kismet },
                    ], [spans[span][1], 'now']);

                    const n = c[`${cpu}.count`] ?? 0;
                    const sr = range(system);
                    const kr = range(kismet);
                    const kis = c[`${cpu}.kismet`] ?? 0;
                    // Percent of all CPUs, so a busy single thread shows as 100% / CPUs
                    const oneCpu = n > 1 ? `${pctText(kis * n)} of one CPU` : '';
                    stats.replaceChildren(...[
                        readout('System', pctText(c[`${cpu}.total`]), 'Load of the whole system, of all its CPUs'),
                        readout('Kismet', pctText(kis), oneCpu ? `Load of the Kismet server, of all CPUs; ${oneCpu}` :
                            'Load of the Kismet server'),
                        n ? readout('CPUs', format.count(n), 'CPUs online') : null,
                        sr ? readout(`System peak, ${spans[span][0].toLowerCase()}`, pctText(sr.max),
                            `Average ${pctText(sr.avg)}`) : null,
                        kr ? readout(`Kismet peak, ${spans[span][0].toLowerCase()}`, pctText(kr.max),
                            `Average ${pctText(kr.avg)}`) : null,
                    ].filter(Boolean));
                } else {
                    stats.replaceChildren();
                }
                status.textContent = `Updated ${format.time(at)}`;
            } catch (err) {
                status.textContent = err.status === 404 ? 'This server doesn\'t report its CPU load' : err.message;
            } finally {
                reading = false;
            }
            // Once, so a size the user dragged it to stays
            if (!fitted) {
                fitted = true;
                d.fitContent();
            }
        }
        timer = setTimeout(read, refresh[span] * 1000);
    }

    read();
    openWindow = d;
    return d;
}

function readout(label, value, title = '') {
    return el('div', { class: 'mem-stat', title }, el('span', { class: 'mem-stat-label' }, label),
        el('span', { class: 'mem-stat-value' }, value));
}
