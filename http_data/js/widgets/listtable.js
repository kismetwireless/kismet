// A searchable, sortable table for long lists in the device panel (an
// access point's clients, say).  It shows ten rows at a time and scrolls,
// drawing more rows as the user scrolls down instead of all of them at once.
//
//   const t = listTable({
//       id: 'dot11-clients',                  // remembers the sort per list
//       load: async () => rows,               // all rows, with only the fields the columns use
//       columns: [
//           { id: 'mac', title: 'MAC', value: (r) => r.mac, render: (r) => link(r) },
//           { id: 'packets', title: 'Packets', value: (r) => r.packets, align: 'right', dir: 'desc' },
//       ],
//       search: 'Search MAC, name, or manufacturer',
//       empty: 'No clients.',
//       refreshSeconds: 5,
//   });
//   cell.append(t.node);
//
// value(row) is what a column sorts and searches by; render(row) draws the
// cell (default: the value as text).  dir is the direction a column sorts in
// first.  The rows are loaded again every refreshSeconds while the table is
// on screen, keeping the sort, search, and scroll position.
//
// Rows that are already at hand (a list inside the device record) can be
// given instead of loaded: leave out load, and call t.setRows(rows, version)
// with each update; version (the object the rows came from, say) lets the
// table skip redrawing when nothing changed.
//
// With rowKey(row) and detail(row, el), clicking a row shows its details
// under the table, kept open (and redrawn with fresh data) across updates.
// t.redraw() redraws the rows, for cells that fill in later.

import { el, debounce } from '../core/dom.js';
import { icon } from '../core/icons.js';
import * as settings from '../core/settings.js';

const chunk = 50;
const visibleRows = 10;
// Column widths per list, kept while the page is open so every window
// showing the same list lines up, and refreshes don't make columns jump
const listWidths = new Map();

export function listTable({ id, load = null, columns, search = 'Search', empty = 'Nothing to show.',
    refreshSeconds = 5, defaultSort = null, rowKey = null, detail = null }) {

    const sortKey = `listtable.${id}.sort`;
    let sort = settings.get(sortKey, null);
    if (!sort || !columns.some((c) => c.id === sort.column))
        sort = defaultSort ?? { column: columns[0].id, dir: columns[0].dir ?? 'asc' };

    let rows = [];          // everything loaded
    let shown = [];         // after search and sort
    let drawn = 0;          // how many of `shown` are in the table
    let loaded = false;
    let error = null;
    let timer = null;
    let destroyed = false;
    let version;
    let selected = null;    // rowKey of the row whose details show

    const input = el('input', { type: 'search', placeholder: search, 'aria-label': search });
    const count = el('span', { class: 'muted list-table-count' });
    const headRow = el('tr');
    const tbody = el('tbody');
    const cols = columns.map(() => el('col'));
    const table = el('table', { class: 'list-table-grid' }, el('colgroup', {}, cols), el('thead', {}, headRow), tbody);
    if (!listWidths.has(id))
        listWidths.set(id, new Map());
    const widths = listWidths.get(id);
    const sentinel = el('div', { class: 'list-table-sentinel', 'aria-hidden': 'true' });
    const scroll = el('div', { class: 'list-table-scroll' }, table, sentinel);
    const message = el('p', { class: 'muted list-table-empty', hidden: true });
    const detailBody = el('div', { class: 'list-table-detail-body' });
    const detailBox = el('div', { class: 'list-table-detail', hidden: true },
        el('button', { class: 'icon-button list-table-detail-close', type: 'button', title: 'Close',
            onclick: () => select(null) }, icon('close')),
        detailBody);
    const node = el('div', { class: 'list-table' },
        el('div', { class: 'list-table-search' }, el('label', { class: 'search-box' }, icon('search'), input), count),
        scroll, message, detailBox);

    if (detail)
        table.classList.add('selectable');

    function select(key) {
        selected = selected === key ? null : key;
        for (const tr of tbody.rows)
            tr.classList.toggle('selected', selected !== null && tr.dataset.key === selected);
        drawDetail();
    }

    function drawDetail() {
        const row = selected === null ? null : rows.find((r) => String(rowKey(r)) === selected);
        detailBox.hidden = !row;
        if (!row) {
            selected = null;
            return;
        }
        try {
            detail(row, detailBody);
        } catch (err) {
            console.error(`list table ${id} details failed:`, err);
        }
    }

    function drawHeader() {
        headRow.replaceChildren(...columns.map((c) => {
            const active = sort.column === c.id;
            const th = el('th', { class: ['sortable', active && 'sorted', `align-${c.align ?? 'left'}`],
                'aria-sort': active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none' },
                // Every heading keeps room for the arrow, so sorting doesn't widen a column
                c.title, el('span', { class: ['sort-mark', !active && 'sort-mark-off'] }, icon(active && sort.dir === 'asc' ? 'up' : 'down')));
            th.addEventListener('click', () => {
                sort = active ? { column: c.id, dir: sort.dir === 'asc' ? 'desc' : 'asc' } : { column: c.id, dir: c.dir ?? 'asc' };
                settings.set(sortKey, sort);
                drawHeader();
                apply(false);
            });
            return th;
        }));
    }

    // Search and sort what's loaded, then redraw as many rows as before
    function apply(keepScroll = true) {
        const q = input.value.trim().toLowerCase();
        const col = columns.find((c) => c.id === sort.column) ?? columns[0];
        const sign = sort.dir === 'asc' ? 1 : -1;

        shown = q ? rows.filter((r) => columns.some((c) => String(c.value(r) ?? '').toLowerCase().includes(q))) : rows.slice();
        shown.sort((a, b) => {
            const x = col.value(a);
            const y = col.value(b);
            if (x === y)
                return 0;
            if (x === undefined || x === null || x === '')
                return 1;
            if (y === undefined || y === null || y === '')
                return -1;
            return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * sign;
        });

        const top = scroll.scrollTop;
        const want = keepScroll ? Math.max(drawn, chunk) : chunk;
        tbody.replaceChildren();
        drawn = 0;
        drawMore(want);
        scroll.scrollTop = keepScroll ? top : 0;
        status();
        if (detail)
            drawDetail();
    }

    function drawMore(n = chunk) {
        const end = Math.min(shown.length, drawn + n);
        const frag = document.createDocumentFragment();
        for (let i = drawn; i < end; i++) {
            const r = shown[i];
            const key = rowKey ? String(rowKey(r)) : null;
            const tr = el('tr', { class: key !== null && key === selected ? 'selected' : null, dataset: key !== null ? { key } : null,
                onclick: detail ? (e) => {
                    // Links and buttons in a row do their own thing
                    if (!e.target.closest('a, button'))
                        select(key);
                } : null }, columns.map((c) => {
                let content;
                try {
                    content = c.render ? c.render(r) : c.value(r);
                } catch (err) {
                    console.error(`list table ${id} column ${c.id} failed:`, err);
                    content = '!';
                }
                return el('td', { class: `align-${c.align ?? 'left'}` }, content ?? '');
            }));
            frag.append(tr);
        }
        tbody.append(frag);
        drawn = end;
        fitColumns();
        fit();
    }

    // Columns start at the width their heading and first rows need, then only
    // ever grow (when a wider value turns up), so they don't shift as rows
    // reload, scroll in, or get searched
    function applyWidths() {
        let total = 0;
        columns.forEach((c, i) => {
            const w = widths.get(c.id) ?? 0;
            cols[i].style.width = w ? `${w}px` : '';
            total += w;
        });
        table.style.minWidth = `${total}px`;
        table.classList.add('fixed');
    }

    function fitColumns() {
        if (!tbody.rows.length || !table.offsetWidth)
            return;
        let changed = false;
        const grow = (i, px) => {
            px = Math.ceil(px);
            if (px > (widths.get(columns[i].id) ?? 0)) {
                widths.set(columns[i].id, px);
                changed = true;
            }
        };

        if (!table.classList.contains('fixed')) {
            // First time: let the browser lay out the rows naturally, and keep that
            [...headRow.cells].forEach((th, i) => grow(i, th.getBoundingClientRect().width));
        } else {
            [...headRow.cells].forEach((th, i) => {
                if (th.scrollWidth > th.clientWidth)
                    grow(i, th.scrollWidth + 1);
            });
            for (const tr of tbody.rows)
                [...tr.cells].forEach((td, i) => {
                    if (td.scrollWidth > td.clientWidth)
                        grow(i, td.scrollWidth + 1);
                });
        }

        if (changed || !table.classList.contains('fixed'))
            applyWidths();
    }

    // Another window already sized this list: start from its widths
    if (columns.every((c) => widths.has(c.id)))
        applyWidths();

    // Ten rows high once there are rows to measure; shorter lists take only what they need
    function fit() {
        const row = tbody.rows[0];
        if (!row || !row.offsetHeight)
            return;
        scroll.style.maxHeight = `${table.tHead.offsetHeight + visibleRows * row.offsetHeight + 2}px`;
    }

    function status() {
        const q = input.value.trim();
        count.textContent = !loaded ? 'Loading...' :
            (q ? `${shown.length.toLocaleString()} of ${rows.length.toLocaleString()}` : rows.length.toLocaleString());
        let text = '';
        if (error && !rows.length)
            text = `Could not load: ${error.message}`;
        else if (loaded && !shown.length)
            text = q ? 'Nothing matches.' : empty;
        message.textContent = text;
        message.hidden = text === '';
        scroll.hidden = loaded && !shown.length;
    }

    let everConnected = false;

    function setRows(newRows, newVersion = undefined) {
        if (destroyed || (newVersion !== undefined && newVersion === version && loaded))
            return;
        version = newVersion;
        rows = newRows ?? [];
        loaded = true;
        apply(true);
    }

    async function refresh() {
        clearTimeout(timer);
        if (destroyed || !load)
            return;
        // Taken off the page (its section or panel went away): stop for good
        if (node.isConnected)
            everConnected = true;
        else if (everConnected)
            return destroy();
        // Only while it's on screen: an open section in a visible page
        const onScreen = node.checkVisibility ? node.checkVisibility() : node.offsetParent !== null;
        if (node.isConnected && onScreen && document.visibilityState !== 'hidden') {
            try {
                rows = await load();
                error = null;
            } catch (err) {
                error = err;
            }
            loaded = true;
            if (destroyed)
                return;
            apply(true);
        }
        timer = setTimeout(refresh, (loaded ? refreshSeconds : 0.5) * 1000);
    }

    // Draw the next rows as the bottom comes into view
    const observer = new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting) && drawn < shown.length)
            drawMore();
    }, { root: scroll, rootMargin: '150px' });
    observer.observe(sentinel);

    input.addEventListener('input', debounce(200, () => apply(false)));

    drawHeader();
    status();
    if (load)
        refresh();

    function destroy() {
        destroyed = true;
        clearTimeout(timer);
        observer.disconnect();
    }

    return { node, refresh, destroy, setRows, redraw: () => loaded && apply(true) };
}
