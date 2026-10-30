// GPS status: every GPS's location, fix quality and satellites in view, for the
// ribbon and the GPS window.
//
// One poller serves every view: /gps/all_gps every few seconds while the page
// is visible (a request that fails is tried again soon, for poor links), and
// an hour of history per GPS (satellites used, signal quality, HDOP), kept by
// the page from when it was opened.
//
//   const stop = subscribe((gpses) => ...);   // called with each poll's GPS records
//   openGps();                                 // the GPS window

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as format from '../core/format.js';
import { dialog } from './dialog.js';
import { historyGraph } from './historygraph.js';

const g = 'kismet.gps';
const pollSeconds = 5;
const requestTimeout = 4000;
const retrySeconds = 1.5;
const retries = 3;
const historySamples = 3600 / pollSeconds;

// Signal bars run from no signal to a strong open-sky signal
export const cn0Max = 50;

const listeners = new Set();
const history = new Map();      // uuid -> { t: [], used: [], quality: [], hdop: [] }
let last = null;
let timer = null;

export const constellationColors = {
    GPS: 'var(--accent)',
    GLONASS: 'var(--error)',
    Galileo: 'var(--ok)',
    BeiDou: 'var(--warn)',
    QZSS: 'color-mix(in srgb, var(--accent) 50%, var(--text))',
    SBAS: 'var(--muted)',
    NavIC: 'color-mix(in srgb, var(--ok) 50%, var(--text))',
};
export const constellationColor = (c) => constellationColors[c] ?? 'var(--muted)';

export function satellites(gps) {
    return gps?.[`${g}.satellites`] ?? [];
}

const sat = (s, f) => s[`${g}.satellite.${f}`];

function record(gpses) {
    const now = Date.now() / 1000;
    for (const gps of gpses) {
        const uuid = gps[`${g}.uuid`];
        let h = history.get(uuid);
        if (!h)
            history.set(uuid, h = { t: [], used: [], quality: [], hdop: [] });
        h.t.push(now);
        h.used.push(gps[`${g}.satellites_used`] ?? NaN);
        h.quality.push(gps[`${g}.signal_quality`] ?? NaN);
        h.hdop.push(gps[`${g}.hdop`] ?? NaN);
        for (const k of ['t', 'used', 'quality', 'hdop'])
            if (h[k].length > historySamples)
                h[k].splice(0, h[k].length - historySamples);
    }
}

async function poll() {
    clearTimeout(timer);
    timer = null;
    if (!listeners.size)
        return;
    if (document.visibilityState !== 'hidden') {
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                last = await api.get('gps/all_gps.json', { timeout: requestTimeout });
                record(last);
                for (const fn of listeners)
                    fn(last);
                break;
            } catch {
                if (attempt < retries)
                    await new Promise((r) => setTimeout(r, retrySeconds * 1000));
            }
        }
    }
    if (listeners.size)
        timer = setTimeout(poll, pollSeconds * 1000);
}

export function subscribe(fn) {
    listeners.add(fn);
    if (last)
        fn(last);
    if (!timer)
        poll();
    return () => {
        listeners.delete(fn);
        if (!listeners.size) {
            clearTimeout(timer);
            timer = null;
        }
    };
}

// The GPS to show when only one fits: the one with the best fix, then quality
export function bestGps(gpses) {
    const fix = (x) => x[`${g}.location`]?.['kismet.common.location.fix'] ?? 0;
    return [...(gpses ?? [])].sort((a, b) => fix(b) - fix(a) ||
        (b[`${g}.signal_quality`] ?? -1) - (a[`${g}.signal_quality`] ?? -1))[0] ?? null;
}

export function fixName(gps) {
    const fix = gps?.[`${g}.location`]?.['kismet.common.location.fix'] ?? 0;
    return fix >= 3 ? '3D' : fix === 2 ? '2D' : 'No fix';
}

// One bar per satellite, its height the signal; filled when used in the fix,
// outlined when not, in its constellation's color
export function signalBars(sats, { large = false } = {}) {
    const ns = 'http://www.w3.org/2000/svg';
    const list = [...sats].sort((a, b) => sat(b, 'cn0') - sat(a, 'cn0'));
    const n = Math.max(list.length, large ? 1 : 8);
    const w = large ? 18 : 3, gap = large ? 6 : 1, h = large ? 100 : 16;
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', large ? 'gps-bars large' : 'gps-bars');
    svg.setAttribute('viewBox', `0 0 ${n * (w + gap)} ${h + (large ? 16 : 0)}`);
    svg.setAttribute('preserveAspectRatio', large ? 'xMinYMax meet' : 'none');
    list.forEach((s, i) => {
        const cn0 = sat(s, 'cn0') ?? 0;
        const bh = Math.max(1, (Math.min(cn0, cn0Max) / cn0Max) * h);
        const r = document.createElementNS(ns, 'rect');
        r.setAttribute('x', i * (w + gap) + 0.5);
        r.setAttribute('y', h - bh + 0.5);
        r.setAttribute('width', w - 1);
        r.setAttribute('height', Math.max(0.5, bh - 1));
        const color = constellationColor(sat(s, 'constellation'));
        const used = sat(s, 'used');
        r.style.fill = used === 0 ? 'transparent' : color;
        r.style.stroke = color;
        r.style.strokeWidth = large ? '1.5' : '0.6';
        const t = document.createElementNS(ns, 'title');
        t.textContent = `${sat(s, 'constellation')} ${sat(s, 'id')}: ${cn0 ? `${cn0} dB-Hz` : 'not tracked'}` +
            (used === 1 ? ', used in the fix' : used === 0 ? ', not used' : '');
        r.append(t);
        svg.append(r);
        if (large) {
            const label = document.createElementNS(ns, 'text');
            label.setAttribute('x', i * (w + gap) + w / 2);
            label.setAttribute('y', h + 12);
            label.setAttribute('text-anchor', 'middle');
            label.setAttribute('class', 'gps-bar-label');
            label.textContent = sat(s, 'id');
            svg.append(label);
        }
    });
    return svg;
}

// Where the satellites are: the sky seen from above, north up, the horizon at
// the edge and straight up in the middle
export function skyPlot(sats) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'gps-sky');
    svg.setAttribute('viewBox', '-110 -110 220 220');
    const mk = (tag, attrs) => {
        const e = document.createElementNS(ns, tag);
        for (const [k, v] of Object.entries(attrs))
            e.setAttribute(k, v);
        svg.append(e);
        return e;
    };
    for (const r of [100, 66.7, 33.3])
        mk('circle', { r, class: 'gps-sky-ring' });
    mk('line', { x1: -100, y1: 0, x2: 100, y2: 0, class: 'gps-sky-ring' });
    mk('line', { x1: 0, y1: -100, x2: 0, y2: 100, class: 'gps-sky-ring' });
    for (const [text, x, y] of [['N', 0, -103], ['E', 104, 4], ['S', 0, 110], ['W', -104, 4]])
        mk('text', { x, y, 'text-anchor': 'middle', class: 'gps-sky-label' }).textContent = text;
    for (const s of sats) {
        const el_ = sat(s, 'elevation'), az = sat(s, 'azimuth');
        if (el_ < 0 || az < 0)
            continue;
        const r = 100 * (1 - el_ / 90);
        const a = (az * Math.PI) / 180;
        const x = r * Math.sin(a), y = -r * Math.cos(a);
        const color = constellationColor(sat(s, 'constellation'));
        const used = sat(s, 'used');
        const c = mk('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: 7, class: 'gps-sky-sat' });
        c.style.fill = used === 0 ? 'var(--surface)' : color;
        c.style.stroke = color;
        const t = document.createElementNS(ns, 'title');
        t.textContent = `${sat(s, 'constellation')} ${sat(s, 'id')}: elevation ${el_}°, azimuth ${az}°, ` +
            `${sat(s, 'cn0') ? `${sat(s, 'cn0')} dB-Hz` : 'not tracked'}`;
        c.append(t);
        mk('text', { x: x.toFixed(1), y: (y + 2.5).toFixed(1), 'text-anchor': 'middle', class: 'gps-sky-id' })
            .textContent = sat(s, 'id');
    }
    return svg;
}

function legend(sats) {
    const seen = [...new Set(sats.map((s) => sat(s, 'constellation')))];
    return el('div', { class: 'timeline-legend' },
        seen.map((c) => el('span', {}, el('span', { class: 'timeline-mark', style: { background: constellationColor(c) } }), c)),
        el('span', { class: 'muted' }, 'Filled: used in the fix'));
}

function row(label, value) {
    return value === null || value === undefined || value === '' ? null :
        el('div', { class: 'gps-row' }, el('span', { class: 'muted' }, label), el('span', {}, value));
}

// One GPS's section of the window
function gpsSection(gps, state) {
    const loc = gps[`${g}.location`] ?? {};
    const L = (f) => loc[`kismet.common.location.${f}`];
    const fix = L('fix') ?? 0;
    const point = L('geopoint');
    const sats = satellites(gps);
    const num = (f, digits = 1) => (gps[`${g}.${f}`] === undefined ? null : Number(gps[`${g}.${f}`]).toFixed(digits));
    const meters = (f) => (gps[`${g}.${f}`] === undefined ? null : format.distance(gps[`${g}.${f}`], 1));

    const summary = el('div', { class: 'gps-summary' },
        row('Fix', `${fixName(gps)}${gps[`${g}.connected`] === 0 ? ' (not connected)' : ''}`),
        fix >= 2 && Array.isArray(point) ? row('Position', `${point[1].toFixed(6)}, ${point[0].toFixed(6)}`) : null,
        fix >= 3 ? row('Altitude', format.height(L('alt') ?? 0, 1)) : null,
        fix >= 2 ? row('Speed', `${format.speed(L('speed') ?? 0)}, heading ${Math.round(L('heading') ?? 0)}°`) : null,
        row('Error', [meters('precision_h') && `${meters('precision_h')} horizontal`, meters('precision_v') && `${meters('precision_v')} vertical`]
            .filter(Boolean).join(', ') + (gps[`${g}.precision_source`] ? ` (${gps[`${g}.precision_source`]})` : '')),
        row('Satellites', gps[`${g}.satellites_visible`] === undefined ? null :
            `${gps[`${g}.satellites_used`] ?? '?'} used of ${gps[`${g}.satellites_visible`]} in view`),
        row('DOP', [num('hdop') && `HDOP ${num('hdop')}`, num('vdop') && `VDOP ${num('vdop')}`].filter(Boolean).join(', ')),
        row('Signal', gps[`${g}.signal_cn0`] === undefined ? null : `${num('signal_cn0')} dB-Hz average of the strongest`),
        row('Quality', gps[`${g}.signal_quality`] === undefined ? null : `${gps[`${g}.signal_quality`]} of 100`));

    const sky = el('div', { class: 'gps-sky-wrap' }, sats.length ? skyPlot(sats) : el('div', { class: 'muted' }, 'No satellite positions'));
    const bars = sats.length ? el('div', { class: 'gps-bars-wrap' }, signalBars(sats, { large: true }), legend(sats)) :
        el('div', { class: 'muted' }, 'This GPS doesn\'t list its satellites.');

    if (!state.used) {
        state.used = historyGraph({ type: 'line', title: 'Satellites used', height: '5.5rem', joinGaps: true, fill: true });
        state.quality = historyGraph({ type: 'line', title: 'Signal quality', height: '5.5rem', joinGaps: true, fill: true, min: 0 });
    }
    const h = history.get(gps[`${g}.uuid`]);
    const age = h?.t.length ? format.duration(Date.now() / 1000 - h.t[0]) : '';
    const graphs = el('div', { class: 'gps-history' }, state.used.node, state.quality.node,
        el('div', { class: 'muted ov-note' }, h?.t.length > 1 ? `Since this page was opened, ${age} ago` : 'History starts when this page is opened'));

    const node = el('section', { class: 'gps-section' },
        el('h3', {}, gps[`${g}.name`] || 'GPS', el('span', { class: 'muted' }, ` ${gps[`${g}.definition`] ?? ''}`)),
        el('div', { class: 'gps-top' }, summary, sky), bars, graphs);
    return { node, draw: () => {
        if (!h || h.t.length < 2)
            return;
        // The whole hour, so the history grows in from the right
        const pad = (v) => [...new Array(historySamples - v.length).fill(NaN), ...v];
        state.used.draw(pad(h.used), ['-60m', 'now']);
        state.quality.draw(pad(h.quality), ['-60m', 'now']);
    } };
}

let openWindow = null;

export function openGps() {
    if (openWindow?.node.isConnected) {
        openWindow.node.dispatchEvent(new Event('pointerdown'));
        return openWindow;
    }
    const body = el('div', { class: 'gps-window' }, el('div', { class: 'muted' }, 'Waiting for the GPS status…'));
    const states = new Map();
    const w = Math.min(760, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 900);
    const d = dialog({
        title: 'GPS', body, modal: false, className: 'gps-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            stop();
            for (const st of states.values())
                for (const graph of [st.used, st.quality])
                    graph?.destroy();
            openWindow = null;
        },
    });
    const stop = subscribe((gpses) => {
        if (!gpses.length) {
            body.replaceChildren(el('div', { class: 'muted' }, 'No GPS is configured.  Add one with gps= in kismet_site.conf.'));
            return;
        }
        const scroller = body.closest('.dialog-body') ?? body;
        const scroll = scroller.scrollTop;
        const sections = gpses.map((gps) => {
            const uuid = gps[`${g}.uuid`];
            if (!states.has(uuid))
                states.set(uuid, {});
            return gpsSection(gps, states.get(uuid));
        });
        body.replaceChildren(...sections.map((s) => s.node));
        sections.forEach((s) => s.draw());
        scroller.scrollTop = scroll;
    });
    openWindow = d;
    return d;
}
