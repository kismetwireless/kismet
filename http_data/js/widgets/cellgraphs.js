// Small graphs for table cells.  They're plain SVG and HTML drawn in the
// current text color, so they're cheap to redraw with every refresh and they
// match highlighted rows.
//
//   barGraph([3, 0, 7, 2, ...])     // bars, scaled to the largest value
//   fillBar(42.5)                   // a bar filled to 42.5%, with the number on it

import { el } from '../core/dom.js';

const svgNS = 'http://www.w3.org/2000/svg';

export function barGraph(values, { title = null } = {}) {
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('class', 'bar-graph');
    svg.setAttribute('viewBox', `0 0 ${Math.max(1, values.length)} 10`);
    svg.setAttribute('preserveAspectRatio', 'none');

    // One path for every bar: each bar is a rectangle from the bottom up.
    // Quiet seconds still get a sliver, so the graph reads as a continuous
    // line instead of having gaps.
    const minHeight = 0.8;
    const max = Math.max(...values, 0);
    let d = '';
    values.forEach((v, i) => {
        const h = max > 0 ? minHeight + (v / max) * (10 - minHeight) : minHeight;
        d += `M${i + 0.1} 10h0.8v${-h}h-0.8z`;
    });
    const path = document.createElementNS(svgNS, 'path');
    path.setAttribute('d', d);
    svg.append(path);

    if (title) {
        const t = document.createElementNS(svgNS, 'title');
        t.textContent = title;
        svg.prepend(t);
    }
    return svg;
}

// Group values into bins of `size`, keeping the peak of each, so short bursts
// still show when there are more values than room for bars
export function peaks(values, size) {
    const out = [];
    for (let i = 0; i < values.length; i += size)
        out.push(Math.max(...values.slice(i, i + size)));
    return out;
}

export function fillBar(percent, text = null) {
    const p = Math.max(0, Math.min(100, Number(percent) || 0));
    return el('div', { class: 'fill-bar', title: text ?? `${p.toFixed(1)}%` },
        el('div', { class: 'fill-bar-fill', style: { width: `${p}%` } }),
        el('span', { class: 'fill-bar-text' }, text ?? `${p.toFixed(1)}%`));
}
