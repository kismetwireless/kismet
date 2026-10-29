// Loading placeholders: shimmering outlines shaped like the content that is
// on its way, so a card or panel shows where its numbers, graph, or rows
// will be instead of an empty "nothing yet".  (kismet.widgets.loading)
//
//   skeleton('graph')                    one shape
//   skeleton(['stat', 'tabs', 'graph'])  stacked; the last one fills the rest
//   skeleton({ kind: 'list', rows: 4 })
//   const l = overlay(region, shapes, { label, className });   laid over a region
//   l.done();  l.error(message);  l.retry()
//   const b = busyBar(region);  b.start();  b.stop();   refreshing content
//
// Shapes:
//   stat       a big number with a caption
//   tabs       a row of small buttons
//   graph      a line graph
//   histogram  a row of columns
//   bars       labelled horizontal bars, longest first (like barList)
//   list       rows of a name and a line of detail
//   log        rows of a time and a line of text
//   table      rows of columns
//   donut      a ring and its legend
//   text       a few lines of text

import { el } from '../core/dom.js';

// Fixed widths, so the outlines look like text without jumping around
const widths = [72, 54, 86, 63, 45, 78, 58, 90, 50, 68];
const w = (i, scale = 1) => `${Math.round(widths[i % widths.length] * scale)}%`;
const line = (width, cls = '') => el('span', { class: ['sk', 'sk-line', cls], style: { width } });

const shapes = {
    stat: () => el('div', { class: 'sk-stat' }, el('span', { class: 'sk sk-number' }), line('45%')),
    tabs: () => el('div', { class: 'sk-tabs' }, [0, 1, 2].map(() => el('span', { class: 'sk sk-pill' }))),
    graph: () => {
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', '0 0 100 40');
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('class', 'sk-graph-line');
        const path = document.createElementNS(ns, 'path');
        path.setAttribute('d', 'M0 30 C 12 26, 18 14, 30 18 S 48 32, 60 22 S 80 8, 100 14');
        path.setAttribute('vector-effect', 'non-scaling-stroke');
        svg.append(path);
        return el('div', { class: 'sk-graph' }, el('div', { class: 'sk sk-block' }, svg));
    },
    histogram: ({ rows = 12 }) => el('div', { class: 'sk-histogram' },
        Array.from({ length: rows }, (_, i) => el('span', { class: 'sk sk-column', style: { height: w(i + 3) } }))),
    bars: ({ rows = 5 }) => el('div', { class: 'sk-rows' },
        Array.from({ length: rows }, (_, i) => el('div', { class: 'sk-bar-row' },
            line(w(i, 0.5)), el('span', { class: 'sk sk-bar', style: { width: `${92 - i * (60 / rows)}%` } })))),
    list: ({ rows = 4 }) => el('div', { class: 'sk-rows' },
        Array.from({ length: rows }, (_, i) => el('div', { class: 'sk-list-row' }, line(w(i, 0.7), 'sk-strong'), line(w(i + 4))))),
    log: ({ rows = 8 }) => el('div', { class: 'sk-rows' },
        Array.from({ length: rows }, (_, i) => el('div', { class: 'sk-log-row' }, line('100%'), line(w(i + 1))))),
    table: ({ rows = 6, columns = 4 }) => el('div', { class: 'sk-rows' },
        Array.from({ length: rows }, (_, r) => el('div', { class: 'sk-table-row', style: { gridTemplateColumns: `repeat(${columns}, 1fr)` } },
            Array.from({ length: columns }, (_, c) => line(w(r + c, c ? 0.8 : 1)))))),
    donut: ({ rows = 4 }) => el('div', { class: 'sk-donut' }, el('span', { class: 'sk sk-ring' }),
        el('div', { class: 'sk-rows' }, Array.from({ length: rows }, (_, i) => line(w(i, 0.8))))),
    text: ({ rows = 3 }) => el('div', { class: 'sk-rows' }, Array.from({ length: rows }, (_, i) => line(w(i + 2)))),
};

export const kinds = Object.keys(shapes);

export function skeleton(spec = 'text') {
    const parts = (Array.isArray(spec) ? spec : [spec]).map((s) => (typeof s === 'string' ? { kind: s } : s));
    return el('div', { class: 'skeleton', 'aria-hidden': 'true' },
        parts.map((p) => (shapes[p.kind] ?? shapes.text)(p)));
}

// A skeleton laid over `region` until done(); error() says why it's still
// waiting, and retry() goes back to loading.  The region is given position:
// relative if it has none.
export function overlay(region, spec = 'text', { label = 'Loading', className = '' } = {}) {
    if (getComputedStyle(region).position === 'static')
        region.style.position = 'relative';
    const message = el('div', { class: 'sk-message', role: 'status' }, `${label}…`);
    const layer = el('div', { class: ['sk-layer', className], 'aria-busy': 'true' }, message, skeleton(spec));
    region.append(layer);
    return {
        node: layer,
        done() {
            layer.classList.add('sk-leaving');
            layer.setAttribute('aria-busy', 'false');
            setTimeout(() => layer.remove(), 180);
        },
        error(text) {
            layer.classList.add('sk-failed');
            message.textContent = `Couldn't load this yet${text ? `: ${text}` : ''}.  Trying again…`;
        },
        retry() {
            layer.classList.remove('sk-failed');
            message.textContent = `${label}…`;
        },
    };
}

// The sweeping bar along the top of `region`, for content being refreshed:
// it only appears once a refresh has taken `delay` ms, and then stays at
// least `minShow` ms, so quick refreshes never flicker.  start() and stop()
// pair up; overlapping refreshes keep it up until the last one ends.
export function busyBar(region, { delay = 2000, minShow = 400, label = 'Refreshing' } = {}) {
    if (getComputedStyle(region).position === 'static')
        region.style.position = 'relative';
    let depth = 0;
    let node = null;
    let shownAt = 0;
    let showTimer = null;
    let hideTimer = null;

    function show() {
        showTimer = null;
        node = el('div', { class: 'loading-bar', role: 'progressbar', 'aria-label': label });
        region.append(node);
        shownAt = Date.now();
    }
    function remove() {
        clearTimeout(hideTimer);
        hideTimer = null;
        node?.remove();
        node = null;
    }
    return {
        start() {
            depth++;
            clearTimeout(hideTimer);
            hideTimer = null;
            if (!node && !showTimer)
                showTimer = setTimeout(show, delay);
        },
        stop() {
            depth = Math.max(0, depth - 1);
            if (depth)
                return;
            clearTimeout(showTimer);
            showTimer = null;
            if (!node)
                return;
            const left = minShow - (Date.now() - shownAt);
            if (left > 0)
                hideTimer = setTimeout(() => { if (!depth) remove(); }, left);
            else
                remove();
        },
        destroy() {
            depth = 0;
            clearTimeout(showTimer);
            showTimer = null;
            remove();
        },
    };
}
