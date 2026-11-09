// The Thermal window: the temperature sensors of the system the Kismet server
// runs on, over the last minute, hour or day, with each sensor's range, and the
// CPU load of the system and of Kismet against the right axis.
//
//   openThermal()
//   hottest(temps) -> [name, degrees C] of the hottest of a THERMAL event's
//       kismet.system.sensors.temp, or null
//   sensorList() -> promise of [{ name, label }], every sensor the server has
//       read, by label
//
// /system/thermal holds the sensors and their history; servers without it,
// or with no sensors, say so instead.  The CPU load is from /system/cpu, when
// the server has it.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';
import { series } from './charts.js';

const th = 'kismet.system.thermal';
const sn = 'kismet.system.thermal.sensor';
const cpu = 'kismet.system.cpu';

const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
const binSeconds = { minute: 1, hour: 60, day: 3600 };
const refresh = { minute: 2, hour: 15, day: 60 };
// Sensors graphed when none are picked
const defaultGraphed = 4;
// A sensor not read for this long is shown as gone
const staleSeconds = 10;

let openWindow = null;

export function hottest(temps) {
    let best = null;
    for (const [name, c] of Object.entries(temps ?? {}))
        if (Number.isFinite(c) && (!best || c > best[1]))
            best = [name, c];
    return best;
}

const byLabel = (a, b) => String(a.label).localeCompare(String(b.label), undefined, { numeric: true });

export async function sensorList() {
    const t = await api.get('system/thermal.json');
    return Object.values(t[`${th}.sensors`] ?? {}).map((s) => ({
        name: s[`${sn}.name`], label: s[`${sn}.label`] || s[`${sn}.name`],
    })).sort(byLabel);
}

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
    return { min: Math.min(...v), max: Math.max(...v), avg: v.reduce((a, x) => a + x, 0) / v.length };
}

export function openThermal() {
    if (openWindow?.node.isConnected) {
        openWindow.raise();
        return openWindow;
    }

    let span = settings.get('thermal.span', 'hour');
    if (!spans[span])
        span = 'hour';

    let shown = { now: Date.now() / 1000, count: 0 };
    const pointLabel = (i) => pointTime(i, shown.now, span, shown.count);
    const tempText = (v) => Number.isFinite(v) ? `${v.toFixed(1)}${format.tempUnit()}` : '-';
    // The unit is in the heading, since it can change while the window is open
    const graph = historyGraph({ type: 'line', height: '13rem', joinGaps: true, pointLabel, fmt: tempText });
    const graphTitle = el('h3', {}, 'Temperatures');
    const cpuText = (v) => Number.isFinite(v) ? `${v < 10 ? v.toFixed(1) : Math.round(v)}%` : '-';

    const status = el('span', { class: 'muted' });
    const stats = el('div', { class: 'mem-stats' });
    const list = el('div', { class: 'thermal-rows' });
    const empty = el('p', { class: 'muted', hidden: true });
    const historyNote = el('p', { class: 'muted mem-note', hidden: true },
        'The server keeps only the current temperatures; set system_thermal_history=true in kismet_site.conf for history.');

    const body = el('div', { class: 'mem-window' },
        el('div', { class: 'pk-bar' },
            tabs(Object.fromEntries(Object.entries(spans).map(([k, v]) => [k, v[0]])), span, (s) => {
                span = s;
                settings.set('thermal.span', s);
                read();
            }), status),
        stats,
        empty,
        el('section', {}, graphTitle, graph.node, historyNote),
        el('section', {}, el('h3', { title: 'Check a sensor to graph it' }, 'Sensors'), list));

    const w = Math.min(820, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 900);
    const d = dialog({
        title: 'Thermal', body, modal: false, className: 'pk-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            clearTimeout(timer);
            stopUnits();
            graph.destroy();
            openWindow = null;
        },
    });

    let timer = null;
    let reading = false;
    let fitted = false;
    let listKey = '';
    const stopUnits = settings.watch('units.temperature', () => read());
    const rowsByName = new Map();

    // The sensors picked to graph; none picked graphs the hottest few
    const picked = () => new Set(settings.get('thermal.graphed', []));
    function toggle(name, on) {
        const p = picked();
        if (on)
            p.add(name);
        else
            p.delete(name);
        settings.set('thermal.graphed', [...p]);
        read();
    }

    function row(name) {
        let r = rowsByName.get(name);
        if (r)
            return r;
        const check = el('input', { type: 'checkbox', onchange: (e) => toggle(name, e.target.checked) });
        const label = el('span', { class: 'thermal-label' });
        const now = el('span', { class: 'thermal-value' });
        const spread = el('span', { class: 'thermal-value muted' });
        r = { node: el('label', { class: 'thermal-row', title: name }, check, label, now, spread), check, label, now, spread };
        rowsByName.set(name, r);
        return r;
    }

    async function read() {
        clearTimeout(timer);
        if (!d.node.isConnected)
            return;
        if (!reading && document.visibilityState !== 'hidden') {
            reading = true;
            try {
                const [t, c] = await Promise.all([api.get('system/thermal.json'),
                    api.get('system/cpu.json').catch(() => null)]);
                const now = clock.isKnown() ? clock.now() : undefined;
                const at = now ?? Date.now() / 1000;
                const history = !!t[`${th}.history`];
                const sensors = Object.values(t[`${th}.sensors`] ?? {})
                    .sort((a, b) => String(a[`${sn}.label`]).localeCompare(String(b[`${sn}.label`]), undefined, { numeric: true }));

                empty.hidden = sensors.length > 0;
                empty.textContent = 'The server has no temperature sensors it can read.';
                historyNote.hidden = history || !sensors.length;

                const readings = sensors.map((s) => {
                    const hist = rrd.history(s[`${sn}.rrd`], now, span, { blank: NaN }).slice(0, -1)
                        .map((v) => Number.isFinite(v) ? format.tempValue(v) : NaN);
                    const live = at - (s[`${sn}.last_time`] ?? 0) <= staleSeconds;
                    return { name: s[`${sn}.name`], label: s[`${sn}.label`] || s[`${sn}.name`],
                        temp: s[`${sn}.temp`], live, hist, range: range(hist) };
                });

                const chosen = picked();
                const known = readings.filter((s) => chosen.has(s.name));
                const graphed = known.length ? known :
                    [...readings].filter((s) => s.live).sort((a, b) => b.temp - a.temp).slice(0, defaultGraphed);
                const graphedNames = new Set(graphed.map((s) => s.name));

                const cpuHist = (f) => rrd.history(c[`${cpu}.${f}`], now, span, { blank: NaN }).slice(0, -1);
                const cpuLines = c?.[`${cpu}.available`] ? [
                    { label: 'System CPU', values: cpuHist('total_rrd') },
                    { label: 'Kismet CPU', values: cpuHist('kismet_rrd') },
                ] : [];
                const tempLines = history ? graphed.map((s) => ({ label: s.label, values: s.hist })) : [];
                const lines = [...tempLines, ...cpuLines.map((l) => ({ ...l, axis: 'right', unit: '%', fill: false, fmt: cpuText }))]
                    .map((l, i) => ({ ...l, color: series(i) }));

                shown = { now: at, count: lines[0]?.values.length ?? 0 };
                graphTitle.textContent = [tempLines.length && `Temperatures, ${format.tempUnit()}`,
                    cpuLines.length && 'CPU load'].filter(Boolean).join(', and ') || 'Temperatures';
                if (lines.length)
                    graph.draw(lines, [spans[span][1], 'now']);
                graph.node.hidden = !lines.length;

                const live = readings.filter((s) => s.live);
                const hot = [...live].sort((a, b) => b.temp - a.temp)[0];
                const avg = live.length ? live.reduce((a, s) => a + s.temp, 0) / live.length : NaN;
                stats.replaceChildren(...[
                    readout('Hottest', hot ? format.temperature(hot.temp) : '---', hot ? hot.label : 'No sensors'),
                    live.length ? readout('Average', format.temperature(avg), 'Of every sensor read now') : null,
                    readout('Sensors', format.count(live.length),
                        readings.length > live.length ? `${readings.length - live.length} no longer read` : ''),
                ].filter(Boolean));

                const key = readings.map((s) => s.name).join('\n');
                if (key !== listKey) {
                    listKey = key;
                    list.replaceChildren(...readings.map((s) => row(s.name).node));
                }
                for (const s of readings) {
                    const r = row(s.name);
                    r.check.checked = graphedNames.has(s.name);
                    r.label.textContent = s.label;
                    r.now.textContent = s.live ? format.temperature(s.temp, 1) : 'gone';
                    // The history is already in the display unit
                    r.spread.textContent = s.range ? `${s.range.min.toFixed(1)} to ${s.range.max.toFixed(1)}` +
                        `${format.tempUnit()}, average ${s.range.avg.toFixed(1)}` : '';
                }
                status.textContent = `Updated ${format.time(at)}`;
            } catch (err) {
                status.textContent = err.status === 404 ? 'This server doesn\'t report temperatures' : err.message;
            } finally {
                reading = false;
            }
            // Once, so a size the user dragged it to stays
            if (!fitted) {
                fitted = true;
                d.fitContent({ grow: false });
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
