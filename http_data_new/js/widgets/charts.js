// Small charts for summaries, in the theme's colors: a list of labelled
// bars, a donut, a big number, a presence strip, and a timeline.  Each
// returns { node, update(...) }; keep it and call update() with new data
// instead of building a new one.
//
//   const bars = barList({ onPick: (item) => ... });
//   bars.update([{ id: 'ap', label: 'Wi-Fi AP', value: 12 }, ...]);
//
// Colors are CSS values, usually theme variables, so charts follow the theme
// without redrawing.  series(i) gives a color for the i-th of several things.

import { el } from '../core/dom.js';
import * as format from '../core/format.js';

const seriesColors = [
    'var(--accent)', 'var(--ok)', 'var(--warn)', 'var(--error)',
    'color-mix(in srgb, var(--accent) 55%, var(--text))', 'color-mix(in srgb, var(--ok) 55%, var(--text))',
    'color-mix(in srgb, var(--warn) 55%, var(--text))', 'color-mix(in srgb, var(--error) 55%, var(--text))',
];

export function series(i) {
    return seriesColors[i % seriesColors.length];
}

// Horizontal bars, longest first, scaled to the largest.  Items are
// { id, label, value, title?, color? }; onPick(item) makes them clickable.
export function barList({ onPick = null, empty = 'Nothing yet', fmt = format.count } = {}) {
    const node = el('ol', { class: ['bar-list', onPick && 'pickable'] });
    const rows = new Map();

    function update(items) {
        const sorted = [...items].sort((a, b) => b.value - a.value);
        const max = Math.max(1, ...sorted.map((i) => i.value));
        const keep = new Set();
        const order = sorted.map((item) => {
            keep.add(item.id);
            let r = rows.get(item.id);
            if (!r) {
                const fill = el('span', { class: 'bar-fill' });
                const label = el('span', { class: 'bar-label' });
                const value = el('span', { class: 'bar-value' });
                r = { node: el('li', { class: 'bar-row', tabindex: onPick ? 0 : null }, el('span', { class: 'bar-track' }, fill),
                    label, value), fill, label, value, item };
                if (onPick) {
                    r.node.addEventListener('click', () => onPick(r.item));
                    r.node.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter')
                            onPick(r.item);
                    });
                }
                rows.set(item.id, r);
            }
            r.item = item;
            r.fill.style.width = `${(100 * item.value) / max}%`;
            r.fill.style.background = item.color ?? 'var(--accent)';
            r.label.textContent = item.label;
            r.value.textContent = fmt(item.value);
            r.node.title = item.title ?? '';
            return r.node;
        });
        for (const [id, r] of rows) {
            if (!keep.has(id)) {
                r.node.remove();
                rows.delete(id);
            }
        }
        const current = node.children;
        if (current.length !== order.length || order.some((n, i) => current[i] !== n))
            node.replaceChildren(...order);
        if (!order.length)
            node.replaceChildren(el('li', { class: 'bar-empty muted' }, empty));
    }

    return { node, update };
}

// A donut with a legend.  Segments are { id, label, value, color }.
export function donut({ size = 120, empty = 'Nothing yet', centerLabel = '' } = {}) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 42 42');
    svg.setAttribute('width', String(size));
    svg.setAttribute('height', String(size));
    svg.classList.add('donut');
    const total = document.createElementNS(ns, 'text');
    total.setAttribute('x', '21');
    total.setAttribute('y', '21');
    total.classList.add('donut-total');
    const caption = document.createElementNS(ns, 'text');
    caption.setAttribute('x', '21');
    caption.setAttribute('y', '26.5');
    caption.classList.add('donut-caption');
    caption.textContent = centerLabel;
    const legend = el('ul', { class: 'donut-legend' });
    const node = el('div', { class: 'donut-chart' }, svg, legend);

    // r = 15.915 makes the circumference 100, so dash lengths are percentages
    const ring = (color, dash, offset) => {
        const c = document.createElementNS(ns, 'circle');
        c.setAttribute('cx', '21');
        c.setAttribute('cy', '21');
        c.setAttribute('r', '15.915');
        c.setAttribute('fill', 'none');
        c.setAttribute('stroke-width', '6');
        c.style.stroke = color;
        c.setAttribute('stroke-dasharray', dash);
        c.setAttribute('stroke-dashoffset', String(offset));
        return c;
    };

    function update(segments) {
        const shown = segments.filter((s) => s.value > 0);
        const sum = shown.reduce((a, s) => a + s.value, 0);
        const parts = [ring('var(--surface-2)', '100 0', 0)];
        let at = 25;
        for (const s of shown) {
            const pct = (100 * s.value) / sum;
            const r = ring(s.color, `${pct} ${100 - pct}`, at);
            const t = document.createElementNS(ns, 'title');
            t.textContent = `${s.label}: ${format.count(s.value)} (${Math.round(pct)}%)`;
            r.append(t);
            parts.push(r);
            at = (at - pct + 100) % 100;
        }
        total.textContent = sum ? format.count(sum) : '';
        svg.replaceChildren(...parts, total, caption);
        legend.replaceChildren(...(shown.length ? shown.map((s) => el('li', {},
            el('span', { class: 'swatch-dot', style: { background: s.color } }),
            el('span', { class: 'donut-label' }, s.label),
            el('span', { class: 'donut-value muted' }, `${format.count(s.value)} · ${Math.round((100 * s.value) / sum)}%`)))
            : [el('li', { class: 'muted' }, empty)]));
    }

    update([]);
    return { node, update };
}

// A big number with a caption under it
export function stat(caption = '') {
    const value = el('span', { class: 'big-stat-value' }, '–');
    const sub = el('span', { class: 'big-stat-caption muted' }, caption);
    const node = el('div', { class: 'big-stat' }, value, sub);
    return {
        node,
        update(v, c = null) {
            value.textContent = v;
            if (c !== null)
                sub.textContent = c;
        },
    };
}

// A strip of blocks, one per time slot, darker the more there was in it: a
// glance at when something was around.  Cells are { value, title }; labels
// are { at, text } under the strip, at cell indexes.
export function presenceStrip({ caption = '' } = {}) {
    const cells = el('div', { class: 'presence-cells' });
    const axis = el('div', { class: 'presence-axis muted' });
    const node = el('figure', { class: 'presence' },
        caption ? el('figcaption', {}, caption) : null, cells, axis);
    let blocks = [];

    function update(items, labels = []) {
        if (blocks.length !== items.length) {
            blocks = items.map(() => el('span', { class: 'presence-cell' }));
            cells.replaceChildren(...blocks);
        }
        // Log scale, so a few packets still show next to a busy hour
        const max = Math.log1p(Math.max(0, ...items.map((i) => i.value)));
        items.forEach((item, i) => {
            const b = blocks[i];
            const pct = item.value > 0 && max > 0 ? Math.round(20 + 80 * (Math.log1p(item.value) / max)) : 0;
            b.style.background = pct ? `color-mix(in srgb, var(--accent) ${pct}%, var(--surface-2))` : '';
            b.classList.toggle('empty', !pct);
            b.title = item.title ?? '';
        });
        // Centered under their block, except at the ends, where they'd be cut off
        axis.replaceChildren(...labels.map((l) => {
            const pct = (100 * (l.at + 0.5)) / Math.max(1, items.length);
            return el('span', { class: pct > 92 ? 'end' : pct < 8 ? 'start' : null, style: { left: `${pct}%` } }, l.text);
        }));
    }

    return { node, update };
}

// Horizontal bars on a shared time axis, one row per item: when each was
// around.  Items are { id, label, start, end, title?, color? } in seconds;
// update(items, from, to) draws them between from and to.  onPick(item)
// makes the rows clickable.
export function timeline({ onPick = null, empty = 'Nothing yet' } = {}) {
    const rows = el('div', { class: 'timeline-rows' });
    const axis = el('div', { class: 'timeline-axis muted' });
    const node = el('div', { class: ['timeline', onPick && 'pickable'] }, rows, axis);

    function update(items, from, to, axisLabels = null) {
        const span = Math.max(1, to - from);
        const pos = (t) => Math.min(100, Math.max(0, (100 * (t - from)) / span));
        rows.replaceChildren(...items.map((item) => {
            const left = pos(item.start);
            const width = Math.max(0.6, pos(item.end) - left);
            const row = el('div', { class: 'timeline-row', title: item.title ?? '', tabindex: onPick ? 0 : null },
                el('span', { class: 'timeline-label' }, item.label),
                el('span', { class: 'timeline-track' },
                    el('span', { class: 'timeline-bar', style: { left: `${left}%`, width: `${width}%`,
                        background: item.color ?? 'var(--accent)' } })));
            if (onPick) {
                row.addEventListener('click', () => onPick(item));
                row.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter')
                        onPick(item);
                });
            }
            return row;
        }));
        if (!items.length)
            rows.replaceChildren(el('div', { class: 'muted' }, empty));
        const [l, r] = axisLabels ?? [format.time(from), format.time(to)];
        axis.replaceChildren(el('span'), el('span', { class: 'timeline-axis-ends' }, el('span', {}, l), el('span', {}, r)));
    }

    return { node, update };
}
