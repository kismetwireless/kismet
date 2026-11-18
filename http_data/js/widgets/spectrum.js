// Spectrum graphs: one value per bin across an axis, with labelled vertical
// markers, and a waterfall of spectra over time.  Used for gamma spectra by
// the radiation module; a plugin can use them for any spectrum, such as RF
// power across a sweep, through kismet.widgets.spectrum.
//
//   const s = spectrumChart({ height: '16rem' });
//   node.append(s.node);
//   s.draw({ values, axis, scale: 'log', markers });
//
//   const w = waterfall({ height: '10rem' });
//   w.draw({ rows: [{ label, values }, ...], axis });   // oldest first
//
// Both are canvases in the theme's colors; keep them and call draw() again
// with new data, and destroy() when done.
//
// The axis says what each bin is.  Make one with binAxis(), linearAxis(), or
// energyAxis(), or pass your own object with:
//   at(bin) -> axis value at the start of bin (rising with bin)
//   binOf(value) -> bin (fractional) for an axis value, or null
//   label(value) -> tick text, readout(value, bin) -> readout heading
// Without one, bins are numbered.
//
// spectrumChart draw() options:
//   values: numbers, one per bin
//   axis: as above
//   scale: 'log' (default; values must not be negative) or 'linear'
//   floor: 'zero' (default) starts a linear scale at zero, 'min' at the
//     lowest value, for values like dBm
//   markers: [{ at, label, color }]  lines across the graph at axis values,
//     labelled along the top (labels that would overlap are skipped); color
//     is a CSS color, var(--warn) if not given
//   format(v) -> readout and tick text for a value (counts if not given)
//   rows(bin, v) -> optional extra [label, text] rows in the readout
//   empty: text when there's nothing to draw
//
// waterfall draw() options:
//   rows: [{ label, values }] oldest first; drawn newest at the top, brighter
//     for more (on a log scale; floor: 'min' and a linear scale for values
//     that can be negative)
//   axis, format, scale ('log' or 'linear'), empty: as above

import { el, fitCanvas } from '../core/dom.js';
import { themeColor, onChange } from '../core/theme.js';
import * as format from '../core/format.js';

// Round steps of 1, 2, or 5 times a power of ten giving about `target` ticks
function niceStep(span, target) {
    if (!(span > 0))
        return 1;
    const raw = span / target;
    const pow = 10 ** Math.floor(Math.log10(raw));
    const n = raw / pow;
    return (n < 1.5 ? 1 : n < 3.5 ? 2 : n < 7.5 ? 5 : 10) * pow;
}

const trim = (v) => +v.toPrecision(4);

// Bins numbered from zero, named in the readout ('Channel 12')
export function binAxis({ name = 'Bin' } = {}) {
    return {
        at: (b) => b,
        binOf: (v) => v,
        label: (v) => `${Math.round(v)}`,
        readout: (v, b) => `${name} ${b}`,
    };
}

// Evenly spaced bins: bin n is start + n * step, in unit
export function linearAxis({ start = 0, step = 1, unit = '', fmt = null } = {}) {
    const text = fmt ?? ((v) => `${trim(v)}${unit ? ` ${unit}` : ''}`);
    return {
        at: (b) => start + b * step,
        binOf: (v) => (step ? (v - start) / step : null),
        label: text,
        readout: (v) => text(v),
    };
}

// A gamma calibration [a0, a1, a2]: channel n is a0 + a1*n + a2*n^2 keV.
// Null for a calibration that isn't one, or doesn't rise across the channels.
export function energyAxis(calibration) {
    if (!Array.isArray(calibration) || calibration.length !== 3 || !calibration.every(Number.isFinite))
        return null;
    const [a0, a1, a2] = calibration;
    if (!(a1 > 0) || a2 < 0)
        return null;
    const kev = (v) => (v >= 1000 ? `${trim(v / 1000)} MeV` : `${Math.round(v)} keV`);
    return {
        at: (ch) => a0 + a1 * ch + a2 * ch * ch,
        binOf: (e) => {
            if (Math.abs(a2) < 1e-12)
                return (e - a0) / a1;
            const disc = a1 * a1 - 4 * a2 * (a0 - e);
            return disc < 0 ? null : (-a1 + Math.sqrt(disc)) / (2 * a2);
        },
        label: kev,
        readout: (v, ch) => `${v.toFixed(1)} keV (channel ${ch})`,
    };
}

// Common gamma lines as markers for an energyAxis, as hints to what a peak
// might be, never an identification
export const gammaLines = [
    { at: 59.5, label: 'Am-241' },
    { at: 186.2, label: 'Ra-226' },
    { at: 238.6, label: 'Pb-212' },
    { at: 351.9, label: 'Pb-214' },
    { at: 364.5, label: 'I-131' },
    { at: 511.0, label: 'e+ 511' },
    { at: 609.3, label: 'Bi-214' },
    { at: 661.7, label: 'Cs-137' },
    { at: 1173.2, label: 'Co-60' },
    { at: 1332.5, label: 'Co-60' },
    { at: 1460.8, label: 'K-40' },
    { at: 2614.5, label: 'Tl-208' },
];

// Canvas needs a resolved color, not var() or color-mix()
function resolver(node) {
    const probe = el('span', { hidden: true });
    return (css) => {
        node.append(probe);
        probe.style.color = css;
        const c = getComputedStyle(probe).color;
        probe.remove();
        return c;
    };
}

function emptyText(ctx, w, h, ratio, text) {
    ctx.fillStyle = themeColor('--muted') || '#888';
    ctx.font = `${11 * ratio}px system-ui, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, w / 2, h / 2);
}

// Pixel columns across n bins, each the highest bin in it so narrow peaks
// survive a graph narrower than the spectrum
function columns(values, cols, n, pick = Math.max) {
    const out = new Array(cols).fill(NaN);
    for (let b = 0; b < n; b++) {
        const v = values[b];
        if (!Number.isFinite(v))
            continue;
        const c = Math.min(cols - 1, Math.floor((b / n) * cols));
        out[c] = Number.isFinite(out[c]) ? pick(out[c], v) : v;
    }
    return out;
}

function placeTip(tip, node, x, y) {
    tip.hidden = false;
    const tw = tip.offsetWidth;
    tip.style.left = `${x + 12 + tw <= node.clientWidth ? x + 12 : Math.max(0, x - 12 - tw)}px`;
    tip.style.top = `${y}px`;
}

export function spectrumChart({ height = '16rem' } = {}) {
    const canvas = el('canvas', { class: 'history-graph-canvas pointable' });
    const tip = el('div', { class: 'graph-tip', hidden: true });
    const node = el('figure', { class: 'history-graph', style: { height } }, canvas, tip);
    const resolve = resolver(node);
    let data = {};
    let layout = null;
    let hover = null;
    let hoverX = 0;

    function draw(newData = data) {
        data = newData ?? {};
        const { w, h, ratio } = fitCanvas(canvas);
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, w, h);
        layout = null;

        const values = Array.isArray(data.values) ? data.values : [];
        const n = values.length;
        const finite = values.filter(Number.isFinite);
        const log = data.scale !== 'linear';
        if (!finite.length || (log && !finite.some((v) => v > 0))) {
            emptyText(ctx, w, h, ratio, data.empty ?? (n ? 'Nothing counted yet' : 'No spectrum yet'));
            return;
        }

        const axis = data.axis ?? binAxis();
        const fmt = data.format ?? format.count;
        const font = 11 * ratio;
        ctx.font = `${font}px system-ui, sans-serif`;
        const text = themeColor('--muted') || '#888';
        const grid = themeColor('--border') || '#444';
        const color = themeColor('--accent') || '#4a8';

        // A log scale is log10(v + 1), so zero sits on the baseline
        const max = Math.max(...finite);
        const min = Math.min(...finite);
        let lo = log ? 0 : (data.floor === 'min' ? min : Math.min(0, min));
        let hi = log ? Math.max(1, Math.ceil(Math.log10(Math.max(0, max) + 1))) : max;
        if (hi === lo)
            hi = lo + 1;
        const yVal = (v) => (log ? Math.log10(Math.max(0, v) + 1) : v);

        const yTicks = [];
        if (log) {
            for (let p = 0; p <= hi; p++)
                yTicks.push({ v: p, label: fmt(10 ** p) });
        } else {
            const step = niceStep(hi - lo, 4);
            for (let v = Math.ceil(lo / step) * step; v <= hi + step * 1e-9; v += step)
                yTicks.push({ v, label: fmt(trim(v)) });
        }

        const left = Math.max(...yTicks.map((t) => ctx.measureText(t.label).width)) + 8 * ratio;
        const right = 6 * ratio;
        const bottomPad = font + 6 * ratio;
        const plotTop = font + 4 * ratio;
        const plotW = w - left - right;
        const plotH = h - bottomPad - plotTop;
        const x = (b) => left + (b / n) * plotW;
        const y = (v) => plotTop + plotH - ((v - lo) / (hi - lo)) * plotH;
        layout = { left, plotW, n, ratio };

        ctx.strokeStyle = grid;
        ctx.fillStyle = text;
        ctx.lineWidth = ratio;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (const t of yTicks) {
            const yy = Math.round(y(t.v)) + 0.5;
            ctx.fillText(t.label, left - 4 * ratio, yy);
            ctx.beginPath();
            ctx.moveTo(left, yy);
            ctx.lineTo(w - right, yy);
            ctx.stroke();
        }

        // Ticks at round axis values
        const x0 = axis.at(0);
        const x1 = axis.at(n);
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        if (Number.isFinite(x0) && Number.isFinite(x1) && x1 > x0) {
            const step = niceStep(x1 - x0, Math.max(2, Math.floor(plotW / (70 * ratio))));
            for (let v = Math.ceil(x0 / step) * step; v < x1; v += step) {
                const b = axis.binOf(v);
                if (b === null || !(b > 0) || b >= n)
                    continue;
                ctx.fillText(axis.label(trim(v)), x(b), h);
            }
        }

        const cols = Math.max(1, Math.floor(plotW));
        const colVal = columns(values.map(yVal), cols, n);
        const base = y(log ? 0 : Math.max(lo, Math.min(0, hi)));
        const pts = [];
        colVal.forEach((v, i) => {
            if (Number.isFinite(v))
                pts.push([left + i + 0.5, y(v)]);
        });
        if (pts.length) {
            ctx.fillStyle = color;
            ctx.globalAlpha = 0.25;
            ctx.beginPath();
            ctx.moveTo(pts[0][0], base);
            for (const [px, py] of pts)
                ctx.lineTo(px, py);
            ctx.lineTo(pts[pts.length - 1][0], base);
            ctx.closePath();
            ctx.fill();
            ctx.globalAlpha = 1;
            ctx.strokeStyle = color;
            ctx.lineWidth = 1.2 * ratio;
            ctx.beginPath();
            pts.forEach(([px, py], i) => (i ? ctx.lineTo(px, py) : ctx.moveTo(px, py)));
            ctx.stroke();
        }

        let lastRight = -Infinity;
        for (const m of data.markers ?? []) {
            const b = Number.isFinite(m?.at) ? axis.binOf(m.at) : null;
            if (b === null || !(b >= 0) || b >= n)
                continue;
            const xx = Math.round(x(b)) + 0.5;
            const mc = resolve(m.color ?? 'var(--warn)') || text;
            ctx.strokeStyle = mc;
            ctx.lineWidth = ratio;
            ctx.globalAlpha = 0.55;
            ctx.setLineDash([3 * ratio, 3 * ratio]);
            ctx.beginPath();
            ctx.moveTo(xx, plotTop);
            ctx.lineTo(xx, plotTop + plotH);
            ctx.stroke();
            ctx.setLineDash([]);
            ctx.globalAlpha = 1;
            const label = String(m.label ?? '');
            const tw = ctx.measureText(label).width;
            if (label && xx - tw / 2 > lastRight + 3 * ratio && xx + tw / 2 < w) {
                ctx.fillStyle = mc;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.fillText(label, xx, 0);
                lastRight = xx + tw / 2;
            }
        }

        if (hover !== null && hover < n) {
            const xx = Math.round(x(hover + 0.5)) + 0.5;
            ctx.strokeStyle = text;
            ctx.lineWidth = ratio;
            ctx.beginPath();
            ctx.moveTo(xx, plotTop);
            ctx.lineTo(xx, plotTop + plotH);
            ctx.stroke();
            showTip(hover, hoverX);
        }
    }

    function showTip(bin, px) {
        const values = data.values;
        // On a graph narrower than the spectrum the pointer covers several
        // bins; show the highest
        const span = Math.max(1, Math.ceil(layout.n / layout.plotW));
        let best = bin;
        for (let b = bin; b < Math.min(layout.n, bin + span); b++)
            if (values[b] > values[best])
                best = b;
        const axis = data.axis ?? binAxis();
        const fmt = data.format ?? format.count;
        const v = values[best];
        const rows = [['Value', Number.isFinite(v) ? fmt(v) : '-'], ...(data.rows?.(best, v) ?? [])];
        tip.replaceChildren(el('div', { class: 'graph-tip-head' }, axis.readout(axis.at(best), best)),
            ...rows.map(([k, t]) => el('div', { class: 'graph-tip-row' }, el('span', {}, k), el('b', {}, t))));
        placeTip(tip, node, px, canvas.offsetTop);
    }

    function point(e) {
        if (!layout)
            return;
        const px = e.clientX - canvas.getBoundingClientRect().left;
        const b = Math.floor(((px * layout.ratio - layout.left) / layout.plotW) * layout.n);
        if (b < 0 || b >= layout.n) {
            leave();
            return;
        }
        hoverX = px;
        hover = b;
        draw();
    }

    function leave() {
        tip.hidden = true;
        if (hover !== null) {
            hover = null;
            draw();
        }
    }

    canvas.addEventListener('pointermove', point);
    canvas.addEventListener('pointerdown', point);
    canvas.addEventListener('pointerleave', leave);

    const stop = onChange(() => draw());
    const resize = new ResizeObserver(() => draw());
    resize.observe(canvas);

    return {
        node,
        draw,
        destroy() {
            stop();
            resize.disconnect();
        },
    };
}

export function waterfall({ height = '10rem' } = {}) {
    const canvas = el('canvas', { class: 'history-graph-canvas pointable' });
    const tip = el('div', { class: 'graph-tip', hidden: true });
    const node = el('figure', { class: 'history-graph', style: { height } }, canvas, tip);
    let data = {};
    let layout = null;

    function draw(newData = data) {
        data = newData ?? {};
        const { w, h, ratio } = fitCanvas(canvas);
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, w, h);
        layout = null;

        const rows = Array.isArray(data.rows) ? data.rows : [];
        const n = rows.reduce((m, r) => Math.max(m, r?.values?.length ?? 0), 0);
        if (!rows.length || !n) {
            emptyText(ctx, w, h, ratio, data.empty ?? 'Nothing to show yet');
            return;
        }

        const log = data.scale !== 'linear';
        const cols = Math.max(1, Math.floor(w));
        const grid = rows.map((r) => columns(r?.values ?? [], cols, n));
        let lo = Infinity;
        let hi = -Infinity;
        for (const cells of grid)
            for (const c of cells)
                if (Number.isFinite(c)) {
                    lo = Math.min(lo, c);
                    hi = Math.max(hi, c);
                }
        if (log)
            lo = 0;
        else if (data.floor !== 'min')
            lo = Math.min(0, lo);
        const shade = (c) => {
            if (!Number.isFinite(c))
                return 0;
            if (log)
                return c > 0 ? Math.log10(c + 1) / Math.log10(Math.max(1, hi) + 1) : 0;
            return hi > lo ? (c - lo) / (hi - lo) : 0;
        };

        // Newest at the top, drawn small and stretched without smoothing
        const img = ctx.createImageData(cols, rows.length);
        const accent = parseColor(themeColor('--accent')) ?? [64, 160, 128];
        const bg = parseColor(themeColor('--surface')) ?? [0, 0, 0];
        grid.forEach((cells, r) => {
            const row = rows.length - 1 - r;
            cells.forEach((c, i) => {
                const f = Math.max(0, Math.min(1, shade(c)));
                const o = (row * cols + i) * 4;
                for (let k = 0; k < 3; k++)
                    img.data[o + k] = Math.round(bg[k] + (accent[k] - bg[k]) * f);
                img.data[o + 3] = 255;
            });
        });
        const off = document.createElement('canvas');
        off.width = cols;
        off.height = rows.length;
        off.getContext('2d').putImageData(img, 0, 0);
        ctx.imageSmoothingEnabled = false;
        ctx.drawImage(off, 0, 0, w, h);
        layout = { cols, rowH: h / rows.length, ratio, n, grid };
    }

    function point(e) {
        if (!layout)
            return;
        const rect = canvas.getBoundingClientRect();
        const px = e.clientX - rect.left;
        const py = e.clientY - rect.top;
        const col = Math.floor(((px * layout.ratio) / canvas.width) * layout.cols);
        const r = data.rows.length - 1 - Math.floor((py * layout.ratio) / layout.rowH);
        const row = data.rows[r];
        if (!row || col < 0 || col >= layout.cols) {
            tip.hidden = true;
            return;
        }
        const axis = data.axis ?? binAxis();
        const fmt = data.format ?? format.count;
        const b = Math.floor((col / layout.cols) * layout.n);
        const v = layout.grid[r][col];
        tip.replaceChildren(el('div', { class: 'graph-tip-head' }, String(row.label ?? '')),
            el('div', { class: 'graph-tip-row' }, el('span', {}, axis.readout(axis.at(b), b)),
                el('b', {}, Number.isFinite(v) ? fmt(v) : '-')));
        placeTip(tip, node, px, Math.max(0, py - 10));
    }

    canvas.addEventListener('pointermove', point);
    canvas.addEventListener('pointerdown', point);
    canvas.addEventListener('pointerleave', () => { tip.hidden = true; });

    const stop = onChange(() => draw());
    const resize = new ResizeObserver(() => draw());
    resize.observe(canvas);

    return {
        node,
        draw,
        destroy() {
            stop();
            resize.disconnect();
        },
    };
}

// A theme color as [r, g, b], for writing pixels
function parseColor(css) {
    if (!css)
        return null;
    const probe = document.createElement('canvas').getContext('2d');
    probe.fillStyle = '#000';
    probe.fillStyle = css;
    const v = probe.fillStyle;
    const hex = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(v);
    if (hex)
        return [parseInt(hex[1], 16), parseInt(hex[2], 16), parseInt(hex[3], 16)];
    const rgb = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(v);
    return rgb ? [+rgb[1], +rgb[2], +rgb[3]] : null;
}
