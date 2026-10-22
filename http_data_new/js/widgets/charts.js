// Small charts for summaries, in the theme's colors: a list of labelled
// bars, a donut, and a big number.  Each returns { node, update(...) }; keep
// it and call update() with new data instead of building a new one.
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
