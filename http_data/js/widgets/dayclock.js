// The last 24 hours as a clock face: an hour of the day in each slot, with
// midnight at the top, and arcs for night, morning, afternoon, and evening.
// Each hour has a bar out from the middle and two rings of dots, all from
// the servers' hourly history (the day vector of an RRD):
//
//   bars        devices active, on average, summed over every frequency
//   inner dots  packets per second, on average
//   outer dots  devices added to the list (the tracked count's growth)
//
// Dots are sized by area.  A hand points at the current time; the hour it
// is in is still being counted, and the slot just past it is from a day
// ago.  Hours with no history (Kismet wasn't running) are left empty.
//
//   const c = dayClock();
//   body.append(c.node);
//   c.update({ devices: [...24], packets: [...24], tracked: [...24], now });
//
// The arrays are oldest first and end with the current hour, as
// rrd.history(r, now, 'day') returns them; null is an hour with no history.

import { el, fitCanvas } from '../core/dom.js';
import * as format from '../core/format.js';
import { themeColor, onChange } from '../core/theme.js';

const parts = [
    { from: 0, to: 6, title: 'Night' },
    { from: 6, to: 12, title: 'Morning' },
    { from: 12, to: 18, title: 'Afternoon' },
    { from: 18, to: 24, title: 'Evening' },
];

const num = (v) => (v > 0 && v < 10 && v % 1 ? v.toFixed(1) : format.count(Math.round(v)));
const pad = (n) => String(n).padStart(2, '0');

export function dayClock() {
    const canvas = el('canvas', { class: 'day-clock-canvas' });
    const tip = el('div', { class: 'day-clock-tip', hidden: true });
    const plot = el('div', { class: 'day-clock' }, canvas, tip);
    const node = el('div', { class: 'day-clock-wrap' },
        el('div', { class: 'day-clock-legend muted' },
            el('span', {}, el('span', { class: 'key bar' }), 'devices active'),
            el('span', {}, el('span', { class: 'key pk' }), 'packets/s'),
            el('span', {}, el('span', { class: 'key add' }), 'devices added')),
        plot);

    let data = null;
    let hover = null;       // hour of the day under the pointer
    let geo = null;

    const stopTheme = onChange(() => draw());
    const resize = new ResizeObserver(() => draw());
    resize.observe(plot);

    // Each hour of the day: its slot in the arrays, its values, and when it began
    function hours() {
        if (!data)
            return [];
        const n = data.devices?.length ?? 0;
        const endHour = Math.floor(data.now / 3600);
        const out = [];
        for (let i = 0; i < n; i++) {
            const start = (endHour - (n - 1 - i)) * 3600;
            const at = new Date(start * 1000);
            const tracked = data.tracked?.[i] ?? null;
            const before = i > 0 ? data.tracked?.[i - 1] ?? null : null;
            out.push({
                hour: at.getHours(), start, current: i === n - 1,
                devices: data.devices[i], packets: data.packets?.[i] ?? null,
                // Growth is only known when the hour before was counted too
                added: tracked !== null && before ? Math.max(0, tracked - before) : null,
                started: tracked !== null && !before,
            });
        }
        return out;
    }

    function draw() {
        geo = null;
        const cssW = plot.clientWidth;
        const cssH = plot.clientHeight;
        if (!cssW || !cssH)
            return;
        const { w: W, h: H, ratio } = fitCanvas(canvas, cssW, cssH);
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, W, H);

        const accent = themeColor('--accent') || '#4b9fe8';
        const ok = themeColor('--ok') || '#5c5';
        const text = themeColor('--text') || '#ddd';
        const muted = themeColor('--muted') || '#888';
        const grid = themeColor('--border') || '#444';
        const surface = themeColor('--surface') || '#111';
        const font = 11 * ratio;
        ctx.font = `${font}px system-ui, sans-serif`;

        const list = hours();
        const byHour = new Map(list.map((h) => [h.hour, h]));
        const cx = W / 2;
        const cy = H / 2;
        const R = Math.min(W, H) / 2 - 2 * ratio;
        const r0 = R * 0.22;
        const r1 = R * 0.52;
        const ringP = R * 0.6;
        const ringA = R * 0.7;
        const rHour = R * 0.79;
        const arc0 = R * 0.86;
        const arc1 = R * 0.97;
        const step = (2 * Math.PI) / 24;
        const angle = (hour) => -Math.PI / 2 + (hour + 0.5) * step;
        const point = (r, a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
        const sector = (rIn, rOut, a0, a1) => {
            ctx.beginPath();
            ctx.arc(cx, cy, rOut, a0, a1);
            ctx.arc(cx, cy, rIn, a1, a0, true);
            ctx.closePath();
        };
        const dim = (h) => (hover === null || hover === h ? 1 : 0.35);

        const vals = (k) => list.map((h) => h[k]).filter((v) => v !== null && v > 0);
        const peakDev = Math.max(1, ...vals('devices'));
        const peakPk = Math.max(0, ...vals('packets'));
        const peakAdd = Math.max(0, ...vals('added'));

        // The base circle and the rings the dots sit on
        ctx.strokeStyle = grid;
        ctx.lineWidth = ratio;
        ctx.beginPath();
        ctx.arc(cx, cy, r0, 0, 2 * Math.PI);
        ctx.stroke();
        ctx.setLineDash([3 * ratio, 4 * ratio]);
        for (const r of [ringP, ringA]) {
            ctx.beginPath();
            ctx.arc(cx, cy, r, 0, 2 * Math.PI);
            ctx.stroke();
        }
        ctx.setLineDash([]);

        // The parts of the day around the outside, named along the arc
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        parts.forEach((p, i) => {
            const a0 = -Math.PI / 2 + p.from * step + ratio / arc1;
            const a1 = -Math.PI / 2 + p.to * step - ratio / arc1;
            ctx.fillStyle = accent;
            ctx.globalAlpha = i % 2 ? 0.3 : 0.5;
            sector(arc0, arc1, a0, a1);
            ctx.fill();
            ctx.globalAlpha = 1;
            const mid = (a0 + a1) / 2;
            const [tx, ty] = point((arc0 + arc1) / 2, mid);
            ctx.save();
            ctx.translate(tx, ty);
            ctx.rotate(Math.sin(mid) > 0 ? mid - Math.PI / 2 : mid + Math.PI / 2);
            ctx.fillStyle = text;
            ctx.fillText(p.title, 0, 0);
            ctx.restore();
        });

        const dotMax = (r) => Math.max(2 * ratio, Math.min((step * r) / 2 - 2 * ratio, R * 0.045));
        const dot = (r, a, radius) => {
            const [x, y] = point(r, a);
            ctx.beginPath();
            ctx.arc(x, y, radius, 0, 2 * Math.PI);
        };

        for (let hour = 0; hour < 24; hour++) {
            const h = byHour.get(hour);
            const a = angle(hour);
            const half = step / 2 - ratio / r0;
            ctx.globalAlpha = dim(hour);

            if (!h || h.devices === null) {
                // No history: a faint outline where the bar would be
                ctx.strokeStyle = grid;
                ctx.lineWidth = ratio;
                ctx.setLineDash([2 * ratio, 3 * ratio]);
                sector(r0, r0 + (r1 - r0) * 0.15, a - half, a + half);
                ctx.stroke();
                ctx.setLineDash([]);
            } else {
                // Still being counted: lighter
                ctx.fillStyle = accent;
                ctx.globalAlpha = dim(hour) * (h.current ? 0.55 : 1);
                if (h.devices > 0) {
                    sector(r0, r0 + Math.max(2 * ratio, ((r1 - r0) * h.devices) / peakDev), a - half, a + half);
                    ctx.fill();
                }
                ctx.globalAlpha = dim(hour);
                if (h.packets > 0 && peakPk > 0) {
                    dot(ringP, a, Math.max(1.5 * ratio, dotMax(ringP) * Math.sqrt(h.packets / peakPk)));
                    ctx.fillStyle = ok;
                    ctx.fill();
                    ctx.strokeStyle = surface;
                    ctx.lineWidth = 2 * ratio;
                    ctx.stroke();
                }
                if (h.added > 0 && peakAdd > 0) {
                    dot(ringA, a, Math.max(2 * ratio, dotMax(ringA) * Math.sqrt(h.added / peakAdd)));
                    ctx.fillStyle = text;
                    ctx.globalAlpha = dim(hour) * 0.25;
                    ctx.fill();
                    ctx.globalAlpha = dim(hour);
                    ctx.strokeStyle = text;
                    ctx.lineWidth = 2 * ratio;
                    ctx.stroke();
                }
            }

            // The hour, outside the dots
            const [tx, ty] = point(rHour, a);
            ctx.fillStyle = hover === hour ? text : muted;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(String(hour), tx, ty);
        }
        ctx.globalAlpha = 1;

        // The hand, at the current time
        if (data?.now) {
            const t = new Date(data.now * 1000);
            const a = -Math.PI / 2 + (t.getHours() + t.getMinutes() / 60) * step;
            const [x0, y0] = point(r0, a);
            const [x1, y1] = point(arc0 - 2 * ratio, a);
            ctx.strokeStyle = text;
            ctx.lineWidth = 1.5 * ratio;
            ctx.beginPath();
            ctx.moveTo(x0, y0);
            ctx.lineTo(x1, y1);
            ctx.stroke();
        }

        // The middle: the hour pointed at, or the time now
        const big = Math.min(r0 * 0.42, 24 * ratio);
        const h = hover === null ? null : byHour.get(hover);
        let top;
        let under;
        if (h && h.devices !== null) {
            top = `${pad(h.hour)}:00`;
            under = h.current ? 'this hour' : (new Date(h.start * 1000).getDate() === new Date(data.now * 1000).getDate() ? 'today' : 'yesterday');
        } else if (hover !== null) {
            top = `${pad(hover)}:00`;
            under = 'no history';
        } else if (data?.now) {
            const t = new Date(data.now * 1000);
            top = `${pad(t.getHours())}:${pad(t.getMinutes())}`;
            under = 'last 24 hours';
        }
        if (top) {
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = text;
            ctx.font = `600 ${big}px system-ui, sans-serif`;
            ctx.fillText(top, cx, cy - big * 0.3);
            ctx.font = `${font}px system-ui, sans-serif`;
            ctx.fillStyle = muted;
            ctx.fillText(under, cx, cy + big * 0.6);
        }

        geo = { cx, cy, r0, outer: arc1, ratio, byHour };
    }

    function hourAt(e) {
        if (!geo)
            return null;
        const r = canvas.getBoundingClientRect();
        const dx = (e.clientX - r.left) * geo.ratio - geo.cx;
        const dy = (e.clientY - r.top) * geo.ratio - geo.cy;
        const d = Math.hypot(dx, dy);
        if (d < geo.r0 * 0.6 || d > geo.outer)
            return null;
        // Clockwise from the top
        const a = (Math.atan2(dy, dx) + Math.PI / 2 + 2 * Math.PI) % (2 * Math.PI);
        return Math.min(23, Math.floor(a / ((2 * Math.PI) / 24)));
    }

    canvas.addEventListener('pointermove', (e) => {
        const hour = hourAt(e);
        if (hour !== hover) {
            hover = hour;
            draw();
        }
        const h = hour === null ? null : geo?.byHour.get(hour);
        if (hour === null) {
            tip.hidden = true;
            return;
        }
        const lines = [el('b', {}, `${pad(hour)}:00 – ${pad((hour + 1) % 24)}:00`)];
        if (!h || h.devices === null) {
            lines.push(el('div', {}, 'No history for this hour'));
        } else {
            lines.push(el('div', {}, `${num(h.devices)} devices active on average`));
            if (h.packets !== null)
                lines.push(el('div', {}, `${num(h.packets)} packets/s on average`));
            if (h.added !== null)
                lines.push(el('div', {}, `${format.count(h.added)} devices added`));
            else if (h.started)
                lines.push(el('div', { class: 'muted' }, 'Kismet started this hour'));
            if (h.current)
                lines.push(el('div', { class: 'muted' }, 'Still being counted'));
        }
        tip.replaceChildren(...lines);
        tip.hidden = false;
        const nr = plot.getBoundingClientRect();
        tip.style.left = `${Math.min(Math.max(0, e.clientX - nr.left + 14), nr.width - tip.offsetWidth - 4)}px`;
        tip.style.top = `${Math.max(0, e.clientY - nr.top - tip.offsetHeight - 10)}px`;
    });
    canvas.addEventListener('pointerleave', () => {
        hover = null;
        tip.hidden = true;
        draw();
    });

    return {
        node,
        update(next) {
            data = next;
            draw();
        },
        destroy() {
            stopTheme();
            resize.disconnect();
        },
    };
}
