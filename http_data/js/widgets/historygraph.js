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
// fill: true shades a line graph from the line down to the bottom of the
// plot, following the line across joined gaps.
//
// A line graph can also draw several lines, with a legend: pass
// [{ label, color, values }, ...] instead of values.  Colors are CSS values,
// such as charts.series(i).
//
// type: 'mirror' draws two bar series back to back, the first above the
// axis and the second below it, such as packets sent and received:
// draw([{ label, color, values }, { label, color, values }], labels).

import { el } from '../core/dom.js';
import { themeColor, onChange } from '../core/theme.js';

export function historyGraph({ type = 'bar', unit = '', height = '7rem', min = null, title = '', minBar = false,
    joinGaps = false, fill = false } = {}) {
    const canvas = el('canvas', { class: 'history-graph-canvas' });
    const legend = el('div', { class: 'graph-legend', hidden: true });
    const node = el('figure', { class: 'history-graph', style: { height } },
        title ? el('figcaption', {}, title) : null, canvas, legend);
    let values = [];
    let labels = [];
    let lines = null;
    let legendKey = '';

    // Canvas needs a resolved color, not var() or color-mix()
    const probe = el('span', { hidden: true });
    function resolve(css) {
        node.append(probe);
        probe.style.color = css;
        const c = getComputedStyle(probe).color;
        probe.remove();
        return c;
    }

    function showLegend() {
        const key = lines ? lines.map((l) => `${l.label}\u0000${l.color}`).join('\u0001') : '';
        if (key === legendKey)
            return;
        legendKey = key;
        legend.hidden = !lines;
        // The legend goes under the plot, which keeps the graph's height
        node.style.height = lines ? 'auto' : height;
        canvas.style.height = lines ? height : '';
        canvas.style.flex = lines ? 'none' : '';
        legend.replaceChildren(...(lines ?? []).map((l) =>
            el('span', { class: 'graph-legend-item' }, el('span', { class: 'graph-swatch', style: { background: l.color } }), l.label)));
    }

    function draw(newValues = values, newLabels = labels) {
        labels = newLabels;
        // Several lines (or the two halves of a mirror): scale over all of
        // them, draw each in its color
        lines = (type === 'line' || type === 'mirror') && newValues.length &&
            Array.isArray(newValues[0]?.values) ? newValues : null;
        values = newValues;
        showLegend();
        const mirror = type === 'mirror' && lines;
        const all = mirror ? [...lines[0].values, ...(lines[1]?.values ?? []).map((v) => -v)] :
            lines ? lines.flatMap((l) => l.values) : values;
        const count = lines ? Math.max(...lines.map((l) => l.values.length)) : values.length;

        const ratio = window.devicePixelRatio || 1;
        const w = Math.max(1, Math.round(canvas.clientWidth * ratio));
        const h = Math.max(1, Math.round(canvas.clientHeight * ratio));
        if (canvas.width !== w || canvas.height !== h) {
            canvas.width = w;
            canvas.height = h;
        }

        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, w, h);
        if (!count)
            return;

        const font = 11 * ratio;
        ctx.font = `${font}px system-ui, sans-serif`;
        const text = themeColor('--muted') || '#888';
        const grid = themeColor('--border') || '#444';
        const color = themeColor('--accent') || '#4a8';

        // Line graphs (signal levels) are scaled between their own min and
        // max; bars start from zero
        const finite = all.filter((v) => Number.isFinite(v));
        if (!finite.length) {
            ctx.fillStyle = themeColor('--muted') || '#888';
            ctx.font = `${12 * (window.devicePixelRatio || 1)}px system-ui, sans-serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('Nothing in this period', w / 2, h / 2);
            return;
        }
        // A mirror is scaled the same both ways, so the halves compare at a glance
        const reach = Math.max(1, ...finite.map(Math.abs));
        let top = type === 'mirror' ? reach : Math.max(...finite, type === 'bar' ? 1 : -Infinity);
        let bottom = type === 'bar' ? 0 : type === 'mirror' ? -reach : Math.min(...finite);
        if (min !== null)
            bottom = Math.min(bottom, min);
        if (top === bottom) {
            top += 1;
            bottom -= type === 'bar' ? 0 : 1;
        }

        // A mirror's lower half counts down from the axis; label it as a count
        const axisText = (v) => `${Math.round(type === 'mirror' ? Math.abs(v) : v)}${unit ? ' ' + unit : ''}`;
        const left = Math.max(ctx.measureText(axisText(top)).width, ctx.measureText(axisText(bottom)).width) + 8 * ratio;
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
        for (const v of type === 'mirror' ? [top, 0, bottom] : [top, bottom]) {
            if (v !== 0)
                ctx.fillText(axisText(v), left - 4 * ratio, y(v));
            ctx.beginPath();
            ctx.moveTo(left, Math.round(y(v)) + 0.5);
            ctx.lineTo(w, Math.round(y(v)) + 0.5);
            ctx.stroke();
        }

        const step = plotW / count;
        ctx.fillStyle = color;
        ctx.strokeStyle = color;

        if (mirror) {
            // Bars up from the axis for the first series, down for the second
            const sliver = 1.5 * ratio;
            const zero = y(0);
            lines.slice(0, 2).forEach((l, half) => {
                ctx.fillStyle = resolve(l.color) || color;
                l.values.forEach((v, i) => {
                    if (!Number.isFinite(v))
                        return;
                    const edge = half === 0 ? Math.min(y(v), minBar ? zero - sliver : zero) :
                        Math.max(y(-v), minBar ? zero + sliver : zero);
                    ctx.fillRect(left + i * step + step * 0.1, Math.min(zero, edge), Math.max(ratio, step * 0.8), Math.abs(edge - zero));
                });
            });
        } else if (type === 'bar') {
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
            const px = (i) => left + i * step + step / 2;
            // The line's pieces: one between readings with joinGaps, else one per
            // run of neighbouring readings
            const segments = (vals) => {
                const out = [];
                let cur = null;
                vals.forEach((v, i) => {
                    if (!Number.isFinite(v)) {
                        if (!joinGaps)
                            cur = null;
                        return;
                    }
                    if (!cur)
                        out.push(cur = []);
                    cur.push([px(i), y(v)]);
                });
                return out;
            };

            const drawLine = (vals) => {
                const segs = segments(vals);
                if (fill) {
                    const floor = y(bottom);
                    ctx.globalAlpha = 0.2;
                    for (const seg of segs.filter((g) => g.length > 1)) {
                        ctx.beginPath();
                        ctx.moveTo(seg[0][0], floor);
                        for (const [x, yy] of seg)
                            ctx.lineTo(x, yy);
                        ctx.lineTo(seg[seg.length - 1][0], floor);
                        ctx.closePath();
                        ctx.fill();
                    }
                    ctx.globalAlpha = 1;
                }
                ctx.lineWidth = 1.5 * ratio;
                for (const seg of segs) {
                    if (seg.length === 1) {
                        // A reading with no neighbour to join to would otherwise not show at all
                        ctx.beginPath();
                        ctx.arc(seg[0][0], seg[0][1], 2 * ratio, 0, Math.PI * 2);
                        ctx.fill();
                        continue;
                    }
                    ctx.beginPath();
                    seg.forEach(([x, yy], i) => (i ? ctx.lineTo(x, yy) : ctx.moveTo(x, yy)));
                    ctx.stroke();
                }
            };

            if (lines) {
                for (const l of lines) {
                    const c = resolve(l.color) || color;
                    ctx.strokeStyle = c;
                    ctx.fillStyle = c;
                    drawLine(l.values);
                }
            } else {
                drawLine(values);
            }
        }

        // Labels under the graph: either [left, right] or one per value
        ctx.fillStyle = text;
        ctx.textBaseline = 'bottom';
        if (labels.length === 2 && count !== 2) {
            ctx.textAlign = 'left';
            ctx.fillText(labels[0], left, h);
            ctx.textAlign = 'right';
            ctx.fillText(labels[1], w, h);
        } else if (labels.length === count) {
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
