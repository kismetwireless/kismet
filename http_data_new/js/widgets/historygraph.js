// A labelled bar or line graph, for history in the device panel (packets
// per second, signal over time, packets per frequency).
//
//   const g = historyGraph({ type: 'bar', unit: 'packets/s' });
//   cell.append(g.node);
//   g.draw(values, labels);       // labels: [left, right] or one per value
//
// It's a canvas in the theme's colors.  Keep the graph and call draw() again
// with new values; it doesn't build anything new.
//
// minBar: true draws a sliver for bars with no value (a second with no
// packets), so quiet times read as a baseline rather than gaps.
// joinGaps: true carries a line graph straight across missing values (NaN)
// between readings, for values like signal that are only heard now and then.

import { el } from '../core/dom.js';
import { themeColor, onChange } from '../core/theme.js';

export function historyGraph({ type = 'bar', unit = '', height = '7rem', min = null, title = '', minBar = false,
    joinGaps = false } = {}) {
    const canvas = el('canvas', { class: 'history-graph-canvas' });
    const node = el('figure', { class: 'history-graph', style: { height } },
        title ? el('figcaption', {}, title) : null, canvas);
    let values = [];
    let labels = [];

    function draw(newValues = values, newLabels = labels) {
        values = newValues;
        labels = newLabels;

        const ratio = window.devicePixelRatio || 1;
        const w = Math.max(1, Math.round(canvas.clientWidth * ratio));
        const h = Math.max(1, Math.round(canvas.clientHeight * ratio));
        if (canvas.width !== w || canvas.height !== h) {
            canvas.width = w;
            canvas.height = h;
        }

        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, w, h);
        if (!values.length)
            return;

        const font = 11 * ratio;
        ctx.font = `${font}px system-ui, sans-serif`;
        const text = themeColor('--muted') || '#888';
        const grid = themeColor('--border') || '#444';
        const color = themeColor('--accent') || '#4a8';

        // Line graphs (signal levels) are scaled between their own min and
        // max; bars start from zero
        const finite = values.filter((v) => Number.isFinite(v));
        if (!finite.length) {
            ctx.fillStyle = themeColor('--muted') || '#888';
            ctx.font = `${12 * (window.devicePixelRatio || 1)}px system-ui, sans-serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('Nothing in this period', w / 2, h / 2);
            return;
        }
        let top = Math.max(...finite, type === 'bar' ? 1 : -Infinity);
        let bottom = type === 'bar' ? 0 : Math.min(...finite);
        if (min !== null)
            bottom = Math.min(bottom, min);
        if (top === bottom) {
            top += 1;
            bottom -= type === 'bar' ? 0 : 1;
        }

        const left = ctx.measureText(`${Math.round(top)}${unit ? ' ' + unit : ''}`).width + 8 * ratio;
        const bottomPad = font + 6 * ratio;
        const plotW = w - left - 4 * ratio;
        const plotH = h - bottomPad - font / 2;
        const y = (v) => font / 2 + plotH - ((v - bottom) / (top - bottom)) * plotH;

        // Axis labels and lines at the top and bottom of the range
        ctx.fillStyle = text;
        ctx.strokeStyle = grid;
        ctx.lineWidth = ratio;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (const v of [top, bottom]) {
            ctx.fillText(`${Math.round(v)}${unit ? ' ' + unit : ''}`, left - 4 * ratio, y(v));
            ctx.beginPath();
            ctx.moveTo(left, Math.round(y(v)) + 0.5);
            ctx.lineTo(w, Math.round(y(v)) + 0.5);
            ctx.stroke();
        }

        const step = plotW / values.length;
        ctx.fillStyle = color;
        ctx.strokeStyle = color;

        if (type === 'bar') {
            const sliver = 1.5 * ratio;
            values.forEach((v, i) => {
                if (!Number.isFinite(v))
                    return;
                let barTop = y(v);
                if (minBar)
                    barTop = Math.min(barTop, y(bottom) - sliver);
                ctx.fillRect(left + i * step + step * 0.1, barTop, Math.max(ratio, step * 0.8), y(bottom) - barTop);
            });
        } else {
            ctx.lineWidth = 1.5 * ratio;
            ctx.beginPath();
            let started = false;
            const px = (i) => left + i * step + step / 2;
            values.forEach((v, i) => {
                if (!Number.isFinite(v)) {
                    if (!joinGaps)
                        started = false;
                    return;
                }
                if (started)
                    ctx.lineTo(px(i), y(v));
                else
                    ctx.moveTo(px(i), y(v));
                started = true;
            });
            ctx.stroke();

            // A reading with no neighbour to join to would otherwise not show at all
            values.forEach((v, i) => {
                if (!Number.isFinite(v))
                    return;
                const prev = joinGaps ? values.slice(0, i).some(Number.isFinite) : Number.isFinite(values[i - 1]);
                const next = joinGaps ? values.slice(i + 1).some(Number.isFinite) : Number.isFinite(values[i + 1]);
                if (!prev && !next) {
                    ctx.beginPath();
                    ctx.arc(px(i), y(v), 2 * ratio, 0, Math.PI * 2);
                    ctx.fill();
                }
            });
        }

        // Labels under the graph: either [left, right] or one per value
        ctx.fillStyle = text;
        ctx.textBaseline = 'bottom';
        if (labels.length === 2 && values.length !== 2) {
            ctx.textAlign = 'left';
            ctx.fillText(labels[0], left, h);
            ctx.textAlign = 'right';
            ctx.fillText(labels[1], w, h);
        } else if (labels.length === values.length) {
            ctx.textAlign = 'center';
            // Skip labels that would overlap
            let lastRight = -Infinity;
            labels.forEach((label, i) => {
                const cx = left + i * step + step / 2;
                const half = ctx.measureText(label).width / 2;
                if (cx - half > lastRight + 4 * ratio) {
                    ctx.fillText(label, cx, h);
                    lastRight = cx + half;
                }
            });
        }
    }

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
