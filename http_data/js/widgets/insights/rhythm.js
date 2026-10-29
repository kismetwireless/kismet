// Activity rhythm: a row per device, a column per minute of the last hour,
// shaded by how much it sent.  Rows are ordered so devices with the same
// rhythm sit together, and devices that come and go together (a phone and
// its watch, people who arrived together) are bracketed and named.
//
//   const r = rhythm({ onPick: (key) => ... });
//   r.update(result)        a result of model.rhythm()

import { el, replace } from '../../core/dom.js';
import * as theme from '../../core/theme.js';
import * as charts from '../charts.js';

const rowH = 15;
const labelW = 210;
const groupW = 26;

export function rhythm({ onPick = null } = {}) {
    const summary = el('div', { class: 'rh-summary' });
    const canvas = el('canvas', { class: 'rh-canvas' });
    const tip = el('div', { class: 'cg-tip', hidden: true });
    const scroller = el('div', { class: 'rh-scroll' }, canvas);
    const node = el('div', { class: 'rh' }, summary, scroller, tip,
        el('div', { class: 'cg-hint muted' }, 'Each row is a device, each column a minute; darker is busier.  Rows with the same rhythm are placed together.'));
    const ctx = canvas.getContext('2d');
    let data = { rows: [], together: [] };
    let groupOf = new Map();
    let hoverRow = -1;
    let lit = null;
    let width = 0;

    const resize = new ResizeObserver(() => {
        width = scroller.clientWidth;
        draw();
    });
    resize.observe(scroller);
    const offTheme = theme.onChange(() => draw());

    function draw() {
        const rows = data.rows;
        const dpr = window.devicePixelRatio || 1;
        const h = Math.max(1, rows.length) * rowH + 26;
        const w = Math.max(420, width);
        canvas.style.width = `${w}px`;
        canvas.style.height = `${h}px`;
        canvas.width = Math.round(w * dpr);
        canvas.height = Math.round(h * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, w, h);
        const c = (n) => theme.themeColor(n) || '#888';
        const text = c('--text'), muted = c('--muted'), accent = c('--accent'), border = c('--border');
        const cols = rows[0]?.values.length ?? 59;
        const gridW = w - labelW - groupW - 8;
        const cw = gridW / cols;
        const max = Math.max(1, ...rows.flatMap((r) => r.values));
        const lmax = Math.log1p(max);

        // axis
        ctx.fillStyle = muted;
        ctx.font = '10.5px system-ui, sans-serif';
        ctx.textAlign = 'center';
        for (let m = 0; m <= cols; m += 10) {
            const x = labelW + m * cw;
            ctx.fillText(m === cols ? 'now' : `-${cols - m}m`, Math.min(x, labelW + gridW - 10), h - 8);
            ctx.fillStyle = border;
            ctx.fillRect(x, 0, 1, rows.length * rowH);
            ctx.fillStyle = muted;
        }

        rows.forEach((row, i) => {
            const y = i * rowH;
            const g = groupOf.get(row.key);
            const dim = lit && !lit.has(row.key);
            ctx.globalAlpha = dim ? 0.25 : 1;
            if (i === hoverRow) {
                ctx.fillStyle = c('--surface-2');
                ctx.fillRect(0, y, w, rowH);
            }
            ctx.fillStyle = g !== undefined ? c('--text') : text;
            ctx.font = `${g !== undefined ? '600 ' : ''}11px system-ui, sans-serif`;
            ctx.textAlign = 'left';
            let name = row.label;
            while (ctx.measureText(name).width > labelW - 12 && name.length > 4)
                name = `${name.slice(0, -2)}…`;
            ctx.fillText(name, 4, y + rowH - 4);
            const color = g !== undefined ? getComputedColor(charts.series(g + 1)) : accent;
            for (let k = 0; k < row.values.length; k++) {
                const v = row.values[k];
                if (!v)
                    continue;
                ctx.globalAlpha = (dim ? 0.25 : 1) * (0.18 + 0.82 * Math.log1p(v) / lmax);
                ctx.fillStyle = color;
                ctx.fillRect(labelW + k * cw + 0.5, y + 2, Math.max(1, cw - 1), rowH - 4);
            }
            ctx.globalAlpha = 1;
        });

        // brackets for each group that comes and goes together
        data.together.forEach((keys, gi) => {
            const idx = keys.map((k) => rows.findIndex((r) => r.key === k)).filter((i) => i >= 0).sort((a, b) => a - b);
            if (idx.length < 2)
                return;
            const x = labelW + gridW + 8 + (gi % 3) * 6;
            ctx.strokeStyle = getComputedColor(charts.series(gi + 1));
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.moveTo(x, idx[0] * rowH + 4);
            ctx.lineTo(x + 5, idx[0] * rowH + 4);
            ctx.moveTo(x, idx[0] * rowH + 4);
            ctx.lineTo(x, idx[idx.length - 1] * rowH + rowH - 4);
            ctx.lineTo(x + 5, idx[idx.length - 1] * rowH + rowH - 4);
            for (const i of idx.slice(1, -1)) {
                ctx.moveTo(x, i * rowH + rowH / 2);
                ctx.lineTo(x + 5, i * rowH + rowH / 2);
            }
            ctx.stroke();
        });
    }

    // charts.series gives CSS color expressions; resolve them for the canvas
    const probe = el('span', { hidden: true });
    document.body.append(probe);
    function getComputedColor(css) {
        probe.style.color = css;
        return getComputedStyle(probe).color;
    }

    function rowAt(ev) {
        const r = canvas.getBoundingClientRect();
        const i = Math.floor((ev.clientY - r.top) / rowH);
        return i >= 0 && i < data.rows.length ? i : -1;
    }

    canvas.addEventListener('pointermove', (ev) => {
        const i = rowAt(ev);
        if (i !== hoverRow) {
            hoverRow = i;
            draw();
        }
        if (i < 0) {
            tip.hidden = true;
            return;
        }
        const row = data.rows[i];
        const g = groupOf.get(row.key);
        const lines = [el('b', {}, row.label),
            el('div', {}, `Heard in ${Math.round(row.present * 100)}% of the last ${row.values.length} minutes`)];
        if (g !== undefined) {
            const others = data.together[g].filter((k) => k !== row.key).map((k) => data.rows.find((r) => r.key === k)?.label ?? k);
            lines.push(el('div', { class: 'ok-text' }, `Comes and goes with ${others.join(', ')}`));
        }
        tip.replaceChildren(...lines);
        tip.hidden = false;
        const nr = node.getBoundingClientRect();
        tip.style.left = `${Math.min(ev.clientX - nr.left + 14, nr.width - tip.offsetWidth - 8)}px`;
        tip.style.top = `${ev.clientY - nr.top + 12}px`;
    });
    canvas.addEventListener('pointerleave', () => {
        hoverRow = -1;
        tip.hidden = true;
        draw();
    });
    canvas.addEventListener('click', (ev) => {
        const i = rowAt(ev);
        if (i >= 0)
            onPick?.(data.rows[i].key);
    });

    function renderSummary() {
        const label = (k) => data.rows.find((r) => r.key === k)?.label ?? k;
        if (!data.rows.length) {
            summary.replaceChildren(el('p', { class: 'muted' }, 'No device has been heard for a full minute yet.'));
            return;
        }
        const chips = data.together.map((keys, gi) => el('button', {
            type: 'button', class: 'rh-chip', style: { borderColor: charts.series(gi + 1) },
            onclick: () => {
                lit = lit && keys.every((k) => lit.has(k)) ? null : new Set(keys);
                draw();
            },
        }, el('span', { class: 'rh-dot', style: { background: charts.series(gi + 1) } }), keys.map(label).join(' + ')));
        replace(summary,
            el('p', {}, data.together.length ?
                `${data.together.length} group${data.together.length === 1 ? '' : 's'} of devices come and go together.  They may be carried by the same person, or arrive and leave as a group:` :
                `${data.rows.length} devices; none come and go together yet (it takes a few comings and goings to tell).`),
            chips.length ? el('div', { class: 'rh-chips' }, ...chips) : null);
    }

    return {
        node,
        update(result) {
            data = result;
            groupOf = new Map();
            result.together.forEach((keys, gi) => keys.forEach((k) => groupOf.set(k, gi)));
            renderSummary();
            draw();
        },
        destroy() {
            resize.disconnect();
            offTheme();
            probe.remove();
        },
    };
}
