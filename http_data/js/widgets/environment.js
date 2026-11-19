// The Environment window: temperatures, fan speeds and batteries of the
// system the Kismet server runs on and of the data sources that report their
// own, a tab for each kind, over the last minute, hour or day.  The sensors
// are grouped by where they are: the server first, then each data source.
//
//   openEnvironment(tab) -> the window; tab is 'thermal', 'fan' or 'battery',
//       or null for the last one shown
//   load(maxAge) -> promise of { missing, history, sensors, sourceStale } read
//       from /system/environment_current (no history), or kept from a read
//       less than maxAge seconds ago
//   getCurrent() -> promise of /system/environment_current, or of
//       /system/environment from servers without it
//   peek(maxAge) -> what load() last read, or null; starts a new read in the
//       background when that is older than maxAge seconds
//   sensorList(kind) -> promise of [{ id, label, source }] by label, the
//       server's first; rejects with err.status 404 on older servers
//   valueText(kind, value) -> a reading in its unit
//   batteryText(sensor) -> the charging state, voltage and time left
//
// Sensor records are read by js/widgets/envdata.js.  The window's current
// values come from the ENVIRONMENT event every second; the history from
// /system/environment, at the pace of the chosen time span.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as rrd from '../core/rrd.js';
import * as clock from '../core/clock.js';
import * as format from '../core/format.js';
import * as settings from '../core/settings.js';
import * as eventbus from '../core/eventbus.js';
import * as sourcesApi from '../core/sources.js';
import * as envdata from './envdata.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';
import { series } from './charts.js';
import { aboutView } from './aboutview.js';
import { openSources } from './datasources.js';

const env = envdata.env;
const cpu = 'kismet.system.cpu';

const tabTitles = { thermal: 'Thermal', fan: 'Fans', battery: 'Battery' };
const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
const binSeconds = { minute: 1, hour: 60, day: 3600 };
const refresh = { minute: 2, hour: 15, day: 60 };
// Sensors graphed when none are picked: the hottest few, or the first fans and batteries
const defaultGraphed = { thermal: 4, fan: 6, battery: 6 };
// The setting with each tab's picked sensors; thermal.graphed is shared with the overview card
const pickedKey = { thermal: 'thermal.graphed', fan: 'environment.graphed.fan', battery: 'environment.graphed.battery' };

const emptyText = {
    thermal: 'Neither the server nor its data sources report a temperature.',
    fan: 'Neither the server nor its data sources report a fan.',
    battery: 'Neither the server nor its data sources report a battery.',
};

const historyText = 'The server keeps only the current values; set environment_history=true in kismet_site.conf ' +
    'for history.';

const aboutText = {
    thermal: [
        'Temperatures of the system the Kismet server runs on (its thermal zones and hardware monitors), and of ' +
            'data sources that report their own, such as a Wi-Fi radio or a Radiacode.',
        'The graph shows the sensors checked below, or the four hottest when none are checked, with the CPU load ' +
            'of the system and of Kismet against the right axis.  The range beside each sensor is over the time ' +
            'shown in the graph.',
        'A reading that hasn\'t been updated recently, or that comes from a data source which has closed or been ' +
            'removed, is marked and left out of the hottest and the average.',
    ],
    fan: [
        'Fan speeds, in revolutions per minute, from the hardware monitors of the system the Kismet server runs ' +
            'on, and from data sources that report them.',
        'The graph shows the fans checked below, or the first six when none are checked.  Many fans stop when ' +
            'the system is cool, so 0 RPM is not always a fault.',
        'A reading that hasn\'t been updated recently, or that comes from a data source which has closed or been ' +
            'removed, is marked.',
    ],
    battery: [
        'Battery charge, in percent, of the system the Kismet server runs on and of data sources with a battery, ' +
            'such as a Radiacode.  Batteries of devices plugged into the system, such as a mouse, are not included.',
        'The charging state, voltage and time left are shown when the battery reports them.  The time left is ' +
            'the battery\'s own estimate.',
        'A reading that hasn\'t been updated recently, or that comes from a data source which has closed or been ' +
            'removed, is marked.',
    ],
};

// Servers older than /system/environment_current answer 404; the full read is used then
let currentMissing = false;

export async function getCurrent() {
    if (!currentMissing) {
        try {
            return await api.get('system/environment_current.json');
        } catch (err) {
            if (err?.status !== 404)
                throw err;
            currentMissing = true;
        }
    }
    return api.get('system/environment.json');
}

const summary = (j) => ({ missing: false, history: !!j?.[`${env}.history`], sensors: envdata.sensors(j),
    sourceStale: envdata.sourceStaleSeconds(j) });
const noSensors = { missing: true, history: false, sensors: [], sourceStale: envdata.fallbackSourceStale };

// The sensors with their history, for graphs
async function loadHistory() {
    try {
        return summary(await api.get('system/environment.json'));
    } catch (err) {
        if (err?.status !== 404)
            throw err;
        return noSensors;
    }
}

// The last read of the current values, shared by everything that shows sensors without graphs
const cache = { at: 0, data: null, loading: null };

export function load(maxAge = 0) {
    if (cache.data && Date.now() - cache.at < maxAge * 1000)
        return Promise.resolve(cache.data);
    if (cache.loading)
        return cache.loading;
    cache.loading = getCurrent().then((j) => {
        cache.data = summary(j);
        // When the server answered (its clock) and when the answer came (ours), to judge ages by
        cache.data.served = envdata.servedAt(cache.data.sensors);
        cache.data.arrived = Date.now() / 1000;
        return cache.data;
    }, (err) => {
        if (err?.status !== 404)
            throw err;
        cache.data = noSensors;
        return cache.data;
    }).finally(() => {
        // Failed reads count too, so a server that errors isn't asked again at once
        cache.at = Date.now();
        cache.loading = null;
    });
    return cache.loading;
}

export function peek(maxAge) {
    if (!cache.loading && (!cache.data || Date.now() - cache.at >= maxAge * 1000))
        load(maxAge).catch(() => {});
    return cache.data;
}

export async function sensorList(kind) {
    const data = await load(0);
    if (data.missing)
        throw Object.assign(new Error('This server doesn\'t report sensors'), { status: 404 });
    return envdata.groups(data.sensors.filter((s) => s.kind === kind))
        .flatMap((g) => g.sensors.map((s) => ({ id: s.id, label: envdata.fullLabel(s), source: s.source })));
}

export function valueText(kind, v, digits = 0) {
    if (!Number.isFinite(v))
        return '-';
    if (kind === 'thermal')
        return format.temperature(v, digits);
    if (kind === 'fan')
        return `${format.count(Math.round(v))} RPM`;
    return `${Math.round(v)}%`;
}

export function batteryText(s) {
    const b = s.battery;
    if (!b)
        return '';
    return [envdata.batteryState(b),
        b.power === 1 && b.state !== 'charging' ? 'on external power' : b.power === 0 && b.state !== 'discharging' ? 'on battery' : '',
        b.voltage > 0 ? `${b.voltage.toFixed(2)} V` : '',
        b.remaining > 0 ? `${format.duration(b.remaining)} left` : ''].filter(Boolean).join(', ');
}

// The data sources, for their names and whether they're still open; null if they can't be read
async function readSources() {
    try {
        const list = await sourcesApi.list(['kismet.datasource.uuid', 'kismet.datasource.name', 'kismet.datasource.running']);
        return new Map((Array.isArray(list) ? list : []).filter((s) => envdata.validUuid(s['kismet.datasource.uuid']))
            .map((s) => [s['kismet.datasource.uuid'].toUpperCase(),
                { name: String(s['kismet.datasource.name'] ?? ''), running: !!s['kismet.datasource.running'] }]));
    } catch {
        return null;
    }
}

function tabs(choices, current, onPick) {
    const buttons = Object.entries(choices).map(([id, title]) => {
        const b = el('button', { type: 'button', onclick: () => {
            set(id);
            onPick(id);
        } }, title);
        b.dataset.id = id;
        return b;
    });
    const set = (id) => {
        current = id;
        buttons.forEach((b) => {
            b.classList.toggle('active', b.dataset.id === current);
            b.setAttribute('aria-pressed', String(b.dataset.id === current));
        });
    };
    set(current);
    return { node: el('div', { class: 'graph-tabs' }, buttons), set };
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

function readout(label, value, title = '') {
    return el('div', { class: 'mem-stat', title }, el('span', { class: 'mem-stat-label' }, label),
        el('span', { class: 'mem-stat-value' }, value));
}

let openWindow = null;

export function openEnvironment(tab = null) {
    if (openWindow?.dialog.node.isConnected) {
        if (tab)
            openWindow.showTab(tab);
        openWindow.dialog.raise();
        return openWindow.dialog;
    }

    let kind = tab ?? settings.get('environment.tab', 'thermal');
    if (!tabTitles[kind])
        kind = 'thermal';
    let span = settings.get('environment.span', settings.get('thermal.span', 'hour'));
    if (!spans[span])
        span = 'hour';

    let shown = { now: Date.now() / 1000, count: 0 };
    const pointLabel = (i) => pointTime(i, shown.now, span, shown.count);
    // History is converted to the display unit before drawing, so this only adds the unit
    const graphText = (v) => {
        if (!Number.isFinite(v))
            return '-';
        if (kind === 'thermal')
            return `${v.toFixed(1)}${format.tempUnit()}`;
        return kind === 'fan' ? `${format.count(Math.round(v))} RPM` : `${Math.round(v)}%`;
    };
    // A graph for each tab; fan speeds and charge are drawn from 0
    const graphs = Object.fromEntries(Object.keys(tabTitles).map((k) => [k, historyGraph({ type: 'line', height: '13rem',
        joinGaps: true, pointLabel, fmt: graphText, min: k === 'thermal' ? null : 0 })]));
    const graphBox = el('div', {});
    let graph = graphs[kind];
    graphBox.append(graph.node);
    const graphTitle = el('h3', {});
    const cpuText = (v) => Number.isFinite(v) ? `${v < 10 ? v.toFixed(1) : Math.round(v)}%` : '-';

    const status = el('span', { class: 'muted env-status' });
    const stats = el('div', { class: 'mem-stats' });
    const empty = el('p', { class: 'muted', hidden: true });
    const historyNote = el('p', { class: 'muted mem-note', hidden: true }, historyText);
    const groupsEl = el('div', { class: 'env-groups' });
    const listTitle = el('h3', {});
    const graphSection = el('section', {}, graphTitle, graphBox, historyNote);
    const listSection = el('section', {}, listTitle, groupsEl);
    const about = aboutView({ setting: 'environment.about' });

    const kindTabs = tabs(tabTitles, kind, (k) => showTab(k));
    const spanTabs = tabs(Object.fromEntries(Object.entries(spans).map(([k, v]) => [k, v[0]])), span, (s) => {
        span = s;
        settings.set('environment.span', s);
        read();
    });
    const bar = el('div', { class: 'pk-bar env-bar about-anchor' }, kindTabs.node, spanTabs.node, status, about.button);

    const body = el('div', { class: 'mem-window env-window' }, bar, stats, empty, graphSection, listSection, about.node);

    const w = Math.min(820, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 900);
    let userSized = false;
    let fittedHeight = h;
    const d = dialog({
        title: 'Environment', body, modal: false, className: 'pk-panel env-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onMove: (p) => {
            if (Math.abs((p?.height ?? fittedHeight) - fittedHeight) > 1)
                userSized = true;
        },
        onClose: () => {
            clearTimeout(timer);
            stopUnits();
            stopEvents();
            about.destroy();
            Object.values(graphs).forEach((g) => g.destroy());
            openWindow = null;
        },
    });

    let timer = null;
    let reading = false;
    let readAgain = false;
    let fitted = '';
    // What was read last: { data, sources, cpu, at }
    let last = null;
    const rows = new Map();
    const groupNodes = new Map();
    const askedFor = new Set();

    // Fit the window to what's in it, as far as the screen allows, until the user sizes it
    function fit() {
        if (userSized)
            return;
        requestAnimationFrame(() => {
            if (userSized || !d.node.isConnected)
                return;
            d.fitContent({ grow: true });
            fittedHeight = d.node.offsetHeight;
        });
    }

    function showTab(k) {
        if (!tabTitles[k])
            return;
        kind = k;
        kindTabs.set(k);
        graph = graphs[k];
        graphBox.replaceChildren(graph.node);
        settings.set('environment.tab', k);
        about.set(aboutText[k]);
        draw();
        read();
    }

    const picked = () => new Set(settings.get(pickedKey[kind], []));
    // What's graphed now, so a change to the default set starts from what's shown
    let graphedNow = new Set();
    function toggle(id, on) {
        const p = picked().size ? picked() : new Set(graphedNow);
        if (on)
            p.add(id);
        else
            p.delete(id);
        settings.set(pickedKey[kind], [...p]);
        draw();
    }

    function row(id) {
        let r = rows.get(id);
        if (r)
            return r;
        const check = el('input', { type: 'checkbox', onchange: (e) => toggle(id, e.target.checked) });
        const label = el('span', { class: 'thermal-label' });
        const now = el('span', { class: 'thermal-value' });
        const detail = el('span', { class: 'thermal-value muted' });
        r = { node: el('label', { class: 'thermal-row' }, check, label, now, detail), check, label, now, detail };
        r.node.title = id;
        rows.set(id, r);
        return r;
    }

    function groupNode(g) {
        const key = g.source || 'host';
        let n = groupNodes.get(key);
        if (!n) {
            const title = el('h4', { class: 'env-group-title' });
            const list = el('div', { class: 'thermal-rows' });
            n = { node: el('div', { class: 'env-group' }, title, list), title, list, key: '' };
            groupNodes.set(key, n);
        }
        const titleKey = `${g.name}|${g.state}`;
        if (n.key !== titleKey) {
            n.key = titleKey;
            n.title.replaceChildren(...(g.source ? [
                el('button', { type: 'button', class: 'link-button', title: 'Show the data sources', onclick: () => openSources() },
                    g.name),
                g.state ? el('span', { class: 'badge env-badge' }, g.state === 'removed' ? 'Removed' : 'Closed') : null,
            ].filter(Boolean) : ['This server']));
        }
        return n;
    }

    // Draw from what was read last; the current values may be newer, from the event
    function draw() {
        graphTitle.textContent = '';
        listTitle.textContent = kind === 'thermal' ? 'Sensors' : kind === 'fan' ? 'Fans' : 'Batteries';
        listTitle.title = 'Check one to graph it';
        if (!last) {
            stats.replaceChildren();
            return;
        }
        if (last.data.missing) {
            empty.hidden = false;
            empty.textContent = 'This server doesn\'t report environmental sensors.';
            stats.replaceChildren();
            graphSection.hidden = true;
            listSection.hidden = true;
            fitOnce();
            return;
        }

        const now = clock.isKnown() ? clock.now() : undefined;
        const at = now ?? last.at;
        // Ages are judged on the server's clock when it answered, plus the time since
        const ref = last.served + Date.now() / 1000 - last.arrived;
        const list = last.data.sensors.filter((s) => s.kind === kind);
        const toDisplay = (v) => (kind === 'thermal' && Number.isFinite(v) ? format.tempValue(v) : v);
        const readings = list.map((s) => {
            const hist = last.data.history ? rrd.history(s.rrd, now, span, { blank: NaN }).slice(0, -1).map(toDisplay) : [];
            return { s, why: envdata.stale(s, ref, last.sources, last.data.sourceStale), hist, range: range(hist) };
        });

        empty.hidden = list.length > 0;
        empty.textContent = emptyText[kind];
        graphSection.hidden = !list.length && kind !== 'thermal';
        listSection.hidden = !list.length;
        historyNote.hidden = last.data.history || !list.length;

        const current = readings.filter((r) => !r.why);
        const chosen = picked();
        const known = readings.filter((r) => chosen.has(r.s.id));
        const graphed = known.length ? known : (kind === 'thermal' ?
            [...current].sort((a, b) => b.s.value - a.s.value) : current).slice(0, defaultGraphed[kind]);
        const graphedIds = new Set(graphed.map((r) => r.s.id));
        graphedNow = graphedIds;
        // Labels in the graph name the source when sensors of several are shown
        const mixed = new Set(graphed.map((r) => r.s.source)).size > 1;

        const cpuHist = (f) => rrd.history(last.cpu[`${cpu}.${f}`], now, span, { blank: NaN }).slice(0, -1);
        const cpuLines = kind === 'thermal' && last.cpu?.[`${cpu}.available`] ? [
            { label: 'System CPU', values: cpuHist('total_rrd') },
            { label: 'Kismet CPU', values: cpuHist('kismet_rrd') },
        ] : [];
        const mainLines = last.data.history ? graphed.map((r) => ({
            label: mixed ? envdata.fullLabel(r.s) : r.s.label, values: r.hist,
        })) : [];
        const lines = [...mainLines, ...cpuLines.map((l) => ({ ...l, axis: 'right', unit: '%', fill: false, fmt: cpuText }))]
            .map((l, i) => ({ ...l, color: series(i) }));

        shown = { now: at, count: lines[0]?.values.length ?? 0 };
        const unit = kind === 'thermal' ? format.tempUnit() : kind === 'fan' ? 'RPM' : '%';
        const mainTitle = { thermal: 'Temperatures', fan: 'Fan speeds', battery: 'Battery charge' }[kind];
        graphTitle.textContent = [mainLines.length ? `${mainTitle}, ${unit}` : '', cpuLines.length ? 'CPU load' : '']
            .filter(Boolean).join(', and ') || mainTitle;
        if (lines.length)
            graph.draw(lines, [spans[span][1], 'now']);
        graph.node.hidden = !lines.length;

        if (list.length)
            drawStats(readings, current);
        else
            stats.replaceChildren();

        const gs = envdata.groups(list, last.sources);
        const order = gs.map((g) => groupNode(g).node);
        if (order.some((n, i) => groupsEl.children[i] !== n) || groupsEl.children.length !== order.length)
            groupsEl.replaceChildren(...order);
        const byId = new Map(readings.map((r) => [r.s.id, r]));
        for (const g of gs) {
            const n = groupNode(g);
            const want = g.sensors.map((s) => row(s.id).node);
            if (want.some((x, i) => n.list.children[i] !== x) || n.list.children.length !== want.length)
                n.list.replaceChildren(...want);
            for (const s of g.sensors)
                drawRow(row(s.id), byId.get(s.id), graphedIds.has(s.id), ref);
        }

        fitOnce();
    }

    // Once per tab, so a size the user dragged it to stays
    function fitOnce() {
        if (fitted !== kind) {
            fitted = kind;
            fit();
        }
    }

    function drawStats(readings, current) {
        const best = (cmp) => current.reduce((a, r) => (!a || cmp(r.s.value, a.s.value) ? r : a), null);
        const gone = readings.length - current.length;
        const goneText = gone ? `${gone} not current` : '';
        let parts;
        if (kind === 'thermal') {
            const hot = best((a, b) => a > b);
            const avg = current.length ? current.reduce((a, r) => a + r.s.value, 0) / current.length : NaN;
            parts = [
                readout('Hottest', hot ? format.temperature(hot.s.value) : '---', hot ? envdata.fullLabel(hot.s) : 'No sensors'),
                current.length ? readout('Average', format.temperature(avg), 'Of every current reading') : null,
                readout('Sensors', format.count(current.length), goneText),
            ];
        } else if (kind === 'fan') {
            const fast = best((a, b) => a > b);
            const stopped = current.filter((r) => r.s.value === 0).length;
            parts = [
                readout('Fastest', fast ? valueText('fan', fast.s.value) : '---', fast ? envdata.fullLabel(fast.s) : 'No fans'),
                readout('Fans', format.count(current.length), goneText),
                stopped ? readout('Stopped', format.count(stopped), 'Fans reading 0 RPM') : null,
            ];
        } else {
            const low = best((a, b) => a < b);
            parts = [
                readout('Lowest', low ? valueText('battery', low.s.value) : '---', low ? envdata.fullLabel(low.s) : 'No batteries'),
                readout('Batteries', format.count(current.length), goneText),
            ];
        }
        stats.replaceChildren(...parts.filter(Boolean));
    }

    function drawRow(r, reading, graphed, at) {
        const { s, why } = reading;
        r.check.checked = graphed;
        r.label.textContent = s.label;
        r.now.textContent = valueText(kind, s.value, kind === 'thermal' ? 1 : 0);
        r.node.classList.toggle('env-stale', !!why);
        const age = s.last_time && Number.isFinite(at) ? `, last read ${format.since(s.last_time, at)}` : '';
        const rng = reading.range;
        const spread = !rng ? '' : kind === 'thermal' ?
            `${rng.min.toFixed(1)} to ${rng.max.toFixed(1)}${format.tempUnit()}, average ${rng.avg.toFixed(1)}` :
            kind === 'fan' ? `${format.count(Math.round(rng.min))} to ${format.count(Math.round(rng.max))} RPM` : '';
        const detail = kind === 'battery' ? batteryText(s) : spread;
        r.detail.textContent = why ? [why[0].toUpperCase() + why.slice(1) + age, detail].filter(Boolean).join('; ') : detail;
    }

    // Current values every second, between reads of the history
    const stopEvents = eventbus.subscribe('ENVIRONMENT', [`${env}.sensors`], (e) => {
        if (!last || last.data.missing || document.visibilityState === 'hidden')
            return;
        const now = envdata.readings(e);
        let changed = false;
        for (const s of last.data.sensors) {
            const r = now[s.id];
            if (r && r.last_time >= s.last_time) {
                s.value = r.value;
                s.last_time = r.last_time;
                changed = true;
            }
        }
        const newest = Object.values(now).reduce((t, r) => Math.max(t, r.last_time), 0);
        if (newest > last.served + Date.now() / 1000 - last.arrived) {
            last.served = newest;
            last.arrived = Date.now() / 1000;
        }
        // A sensor that appeared is drawn on the next read; once each, in case the read doesn't have it yet
        const fresh = Object.keys(now).filter((id) => !askedFor.has(id) && !last.data.sensors.some((s) => s.id === id));
        if (fresh.length) {
            fresh.forEach((id) => askedFor.add(id));
            readSoon();
        }
        if (changed)
            draw();
    });

    function readSoon() {
        if (reading) {
            readAgain = true;
            return;
        }
        clearTimeout(timer);
        timer = setTimeout(read, 500);
    }

    async function read() {
        clearTimeout(timer);
        if (!d.node.isConnected)
            return;
        if (reading) {
            readAgain = true;
            return;
        }
        if (document.visibilityState !== 'hidden') {
            reading = true;
            try {
                const [data, sources, c] = await Promise.all([loadHistory(), readSources(),
                    api.get('system/cpu.json').catch(() => null)]);
                const at = clock.isKnown() ? clock.now() : Date.now() / 1000;
                last = { data, sources, cpu: c, at, served: envdata.servedAt(data.sensors) || at, arrived: Date.now() / 1000 };
                status.textContent = `Updated ${format.time(last.at)}`;
                draw();
            } catch (err) {
                status.textContent = err.message;
            } finally {
                reading = false;
            }
        }
        if (!d.node.isConnected)
            return;
        if (readAgain) {
            readAgain = false;
            timer = setTimeout(read, 0);
            return;
        }
        timer = setTimeout(read, refresh[span] * 1000);
    }

    const stopUnits = settings.watch('units.temperature', () => draw());

    about.set(aboutText[kind]);
    read();
    openWindow = { dialog: d, showTab };
    return d;
}
