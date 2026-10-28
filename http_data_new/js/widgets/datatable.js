// A live, scrolling table over a long server-side list: the device list,
// SSIDs, alerts, or a plugin's own.
//
// The server filters, sorts, and pages the rows, and sends only the fields
// the visible columns need.  The table scrolls through the whole list, but
// only the rows on screen are in the page: every row has the same height, so
// empty space above and below stands in for the rest, and the scrollbar covers
// every row.  Pages load as the user scrolls, with the next one fetched ahead
// of time, and only the pages on screen are refreshed.  Users can move,
// resize, and choose columns, and turn row highlights on and off.
//
//   createDataTable(el, {
//       id: 'ssids',                   // where its column choices are saved
//       endpoint: 'phy/phy80211/ssids/views/ssids.json',
//       columns,                       // a registry of columns (see js/registry/columns.js)
//       highlights,                    // optional registry of row highlights
//       icons,                         // optional registry of row icons (adds an icon column)
//       rowKey: (row) => row['dot11.ssidgroup.hash'],
//       onRowClick: (row) => openSsid(row),
//       defaultSort: { column: 'last_time', dir: 'desc' },
//       noun: 'SSIDs',
//   });
//
// endpoint is any Kismet list that pages like the device views (page,
// length, sort, sort_dir, search, and a fields list; answering with data,
// last_page, last_row, total_row), or a function giving the path, for a list
// that changes (the device view).

import { el, debounce } from '../core/dom.js';
import { icon } from '../core/icons.js';
import * as api from '../core/api.js';
import * as settings from '../core/settings.js';
import { fieldName } from '../registry/columns.js';
import { makeDraggable, makeResizable, moveColumn, defaultColumns, chooseColumns } from './columnedit.js';
import { createRowSource } from './rowsource.js';
import * as loading from './loading.js';
import { chooseHighlights, highlightSetting } from './highlightedit.js';

const pageSize = 50;
// Rows drawn beyond the edges of the screen, so short scrolls don't show gaps
const overscan = 8;
// Fitting columns to their contents: no column grows past this for its
// contents (headings always fit), and columns with no set width (the name)
// never shrink below the second
const maxFitEm = 28;
const minFlexEm = 8;

// The saved layout for a table: { columns: [ids in order], widths: { id: px },
// highlights: { id: { enabled, color } } }.  Until the user picks columns,
// the defaults are used.
function savedLayout(id, columns) {
    const chosen = settings.get(`${id}.columns`, null);
    return {
        columns: Array.isArray(chosen) ? chosen : defaultColumns(columns),
        widths: settings.get(`${id}.widths`, {}),
        highlights: settings.get(`${id}.highlights`, {}),
    };
}

// A layout that's just the defaults isn't saved, so columns that modules add
// later still show up for the user
function saveLayout(id, columns, layout) {
    settings.set(`${id}.highlights`, layout.highlights);
    settings.set(`${id}.widths`, layout.widths);
    if (layout.columns.join() === defaultColumns(columns).join())
        settings.remove(`${id}.columns`);
    else
        settings.set(`${id}.columns`, layout.columns);
}

export function createDataTable(container, {
    id,
    endpoint,
    columns,
    highlights = null,
    icons = null,
    rowKey = () => null,
    onRowClick = null,
    alwaysFields = [],
    searchFields = null,
    defaultSort = null,
    noun = 'rows',
    emptyText = null,
    toolbar = null,
    refreshSeconds = 2,
    watch = [],
}) {
    const firstSortable = columns.list().find((c) => c.sortField);
    const state = {
        sort: settings.get(`${id}.sort`, defaultSort ?? { column: firstSortable?.id, dir: 'desc' }),
        search: '',
        unfiltered: 0,
        timer: null,
        rowHeight: 0,
        lastScroll: 0,
        direction: 1,
        drawn: '',
        error: null,
        // Width each column needs to show its heading and contents, in px.
        // It only grows, as wider contents turn up, and is saved in the
        // browser, so columns keep their width across refreshes and visits.
        natural: new Map(Object.entries(settings.get(`${id}.fitWidths`, {}))),
        layout: savedLayout(id, columns),
        editing: false,
        snapshot: null,
    };

    const searchInput = el('input', { type: 'search', class: 'search', placeholder: 'Search',
        oninput: debounce(300, () => {
            state.search = searchInput.value.trim();
            restart(true);
        }) });

    const countInfo = el('span', { class: 'count-info' });
    const editButton = el('button', { class: 'icon-button', title: 'Edit columns', onclick: () => setEditing(true) }, icon('edit'));

    const toolbarEl = el('div', { class: 'table-toolbar' });

    // Shown instead of the toolbar while editing columns
    const editBar = el('div', { class: 'table-toolbar edit-bar', hidden: true },
        icon('edit'),
        el('span', {}, 'Drag headings to move columns, drag their edges to resize.'),
        el('div', { class: 'spacer' }),
        el('button', { onclick: () => chooseColumns(columns, state.layout.columns, (ids) => {
            state.layout.columns = ids;
            layoutChanged();
        }) }, icon('columns'), ' Choose columns'),
        highlights ? el('button', { onclick: () => chooseHighlights(highlights, state.layout.highlights, (h) => {
            state.layout.highlights = h;
            layoutChanged();
        }) }, icon('highlight'), ' Highlights') : null,
        el('button', { title: 'Default columns, widths, and highlights', onclick: () => {
            state.layout = { columns: defaultColumns(columns), widths: {}, highlights: {} };
            layoutChanged();
        } }, 'Defaults'),
        el('button', { onclick: () => setEditing(false, false) }, 'Cancel'),
        el('button', { class: 'primary', onclick: () => setEditing(false, true) }, 'Done'));

    const colgroup = el('colgroup');
    const thead = el('thead');
    const tbody = el('tbody');
    const table = el('table', { class: 'data-table' }, colgroup, thead, tbody);
    const holder = el('div', { class: 'table-holder' }, table);
    const message = el('div', { class: 'table-message', hidden: true });
    // Runs across the top of the table while rows on screen are loading
    const loadingBar = el('div', { class: 'loading-bar', hidden: true, role: 'progressbar', 'aria-label': `Loading ${noun}` });

    const area = el('div', { class: 'table-area' }, loadingBar, holder, message);
    container.append(toolbarEl, editBar, area);
    // An outline of rows under the header until the first page is in
    let outline = null;

    const rows = createRowSource({ pageSize, load: loadPage, onChange: (err) => {
        state.error = err ?? null;
        draw();
    } });

    let shownColumns = [];
    const iconCol = icons ? 1 : 0;

    function setEditing(on, keep = true) {
        if (on) {
            state.snapshot = JSON.stringify(state.layout);
        } else if (keep) {
            saveLayout(id, columns, state.layout);
        } else if (state.snapshot) {
            state.layout = JSON.parse(state.snapshot);
        }
        state.editing = on;
        toolbarEl.hidden = on;
        editBar.hidden = !on;
        table.classList.toggle('editing', on);
        layoutChanged();
    }

    // Redraw for a new layout, and refetch if the columns or highlights
    // changed the fields we need
    function layoutChanged() {
        const before = JSON.stringify([shownColumns.map((c) => c.id), wantedFields()]);
        buildHeader();
        if (JSON.stringify([shownColumns.map((c) => c.id), wantedFields()]) !== before)
            restart(false);
        else
            draw(true);
    }

    // The highlights in use, with their settings, in priority order
    function activeHighlights() {
        if (!highlights)
            return [];
        return highlights.list()
            .map((h) => ({ h, s: highlightSetting(h, state.layout.highlights) }))
            .filter((x) => x.s.enabled);
    }

    function sortBy(c) {
        if (state.sort.column === c.id)
            state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
        else
            state.sort = { column: c.id, dir: 'desc' };
        settings.set(`${id}.sort`, state.sort);
        buildHeader();
        restart(true);
    }

    let colEls = new Map();      // column id -> <col>

    function buildHeader() {
        shownColumns = state.layout.columns.map((cid) => columns.get(cid)).filter(Boolean);

        const cols = icons ? [el('col', { class: 'col-icon' })] : [];
        const cells = icons ? [el('th', { class: 'col-icon' })] : [];
        const labels = new Map();
        colEls = new Map();

        for (const c of shownColumns) {
            const col = el('col');
            cols.push(col);
            colEls.set(c.id, col);

            const sorted = state.sort.column === c.id;
            const th = el('th', {
                class: [c.sortField && !state.editing && 'sortable', sorted && 'sorted', `align-${c.align}`],
                title: c.description || c.title,
            }, el('span', { class: 'th-label' }, c.title, sorted ? icon(state.sort.dir === 'asc' ? 'up' : 'down') : null));
            labels.set(c.id, th.firstChild);

            if (c.sortField)
                th.addEventListener('click', () => {
                    if (!state.editing)
                        sortBy(c);
                });

            if (state.editing)
                makeDraggable(th, c.id, (from, to, before) => {
                    state.layout.columns = moveColumn(state.layout.columns, from, to, before);
                    layoutChanged();
                });

            // Resizing works any time; outside of editing it's saved straight away
            makeResizable(th, col, (px) => {
                const widths = { ...state.layout.widths };
                if (px === null)
                    delete widths[c.id];
                else
                    widths[c.id] = px;
                state.layout.widths = widths;
                if (!state.editing)
                    saveLayout(id, columns, state.layout);
                buildHeader();
            });

            cells.push(th);
        }

        colgroup.replaceChildren(...cols);
        thead.replaceChildren(el('tr', {}, cells));

        // Every heading fits in full
        const pad = emPx() * 1.2 + 8;
        for (const [cid, label] of labels)
            grow(cid, label.scrollWidth + pad, Infinity);
        applyWidths();
    }

    function emPx() {
        return parseFloat(getComputedStyle(table).fontSize) || 14;
    }

    // A column's declared width ('8em', '120px') in px
    function declaredPx(width) {
        const m = /^([\d.]+)(em|rem|px)?$/.exec(String(width ?? ''));
        if (!m)
            return 0;
        const n = parseFloat(m[1]);
        if (m[2] === 'px')
            return n;
        if (m[2] === 'rem')
            return n * parseFloat(getComputedStyle(document.documentElement).fontSize);
        return n * emPx();
    }

    const saveFit = debounce(1000, () => settings.set(`${id}.fitWidths`, Object.fromEntries(state.natural)));

    // Note that a column needs at least px; true if that's more than before
    function grow(cid, px, cap = maxFitEm * emPx()) {
        px = Math.ceil(Math.min(px, cap));
        if (!px || px <= (state.natural.get(cid) ?? 0))
            return false;
        state.natural.set(cid, px);
        saveFit();
        return true;
    }

    // Size the columns: widths the user set stay as set; the rest get the
    // larger of their own width and what their heading and contents need.
    // The table fills the space when that fits, and is wider than the space
    // (and scrolls sideways) when it doesn't, so columns never squeeze.
    function applyWidths() {
        let total = icons ? 2.6 * emPx() : 0;
        let flexible = null;
        for (const c of shownColumns) {
            const col = colEls.get(c.id);
            const user = state.layout.widths[c.id];
            const need = Math.max(declaredPx(c.width), state.natural.get(c.id) ?? 0);
            if (user) {
                col.style.width = `${user}px`;
                total += user;
            } else if (!c.width && !flexible) {
                // The first column with no set width (usually the name)
                // takes whatever room is left
                flexible = c;
                col.style.width = '';
                total += Math.max(need, minFlexEm * emPx());
            } else {
                const w = c.width ? need : Math.max(need, minFlexEm * emPx());
                col.style.width = `${w}px`;
                total += w;
            }
        }
        table.style.minWidth = `${Math.ceil(total)}px`;
    }

    // Widen columns whose contents on screen don't fit.  Runs right after
    // rows are drawn, before the browser shows them, so a wider value never
    // appears squeezed and then jumps.
    function fitContents() {
        // Placeholder rows have nothing to measure
        if (!tbody.querySelector('tr:not(.spacer):not(.placeholder)'))
            return;

        // Widening one column can squeeze the one with no set width, so look
        // again until nothing changes (widths only grow, so this ends quickly)
        for (let pass = 0; pass < 4; pass++) {
            let changed = false;
            for (const tr of tbody.rows) {
                if (tr.classList.contains('spacer') || tr.classList.contains('placeholder'))
                    continue;
                shownColumns.forEach((c, i) => {
                    if (state.layout.widths[c.id])
                        return;
                    const td = tr.cells[i + iconCol];
                    if (td && td.scrollWidth > td.clientWidth)
                        changed = grow(c.id, td.scrollWidth + 1) || changed;
                });
            }
            if (!changed)
                break;
            applyWidths();
        }
    }

    const listOf = (r) => (r ? (Array.isArray(r) ? r : r.list()) : []);

    // Fields to ask the server for: only what the visible columns, the icons,
    // and the enabled highlights need, plus any always wanted (for searching)
    function wantedFields() {
        const all = new Map();
        const add = (spec) => all.set(fieldName(spec), spec);
        alwaysFields.forEach(add);
        listOf(searchFields).forEach((f) => (f.fields ?? [f]).forEach(add));
        shownColumns.forEach((c) => c.fields.forEach(add));
        listOf(icons).forEach((i) => i.fields.forEach(add));
        activeHighlights().forEach(({ h }) => h.fields.forEach(add));
        return [...all.values()];
    }

    // Row height, measured from a real row: rows are sized in em, so the
    // height follows the font size and is usually fractional
    function measureRowHeight() {
        const probe = el('tr', {}, el('td', {}, icon('device')));
        tbody.append(probe);
        const h = probe.getBoundingClientRect().height;
        probe.remove();
        if (h > 0)
            state.rowHeight = h;
    }

    function makeRow(row, index, active, iconList) {
        row.key = rowKey(row);
        const cells = [];

        if (icons) {
            let iconNode = null;
            for (const i of iconList) {
                try {
                    iconNode = i.match(row);
                } catch (err) {
                    console.error(`${id} icon ${i.id} failed:`, err);
                }
                if (iconNode)
                    break;
            }
            cells.push(el('td', { class: 'col-icon' }, iconNode ?? icon('unknown')));
        }

        for (const c of shownColumns) {
            let content;
            try {
                content = c.render(row);
            } catch (err) {
                console.error(`${id} column ${c.id} failed:`, err);
                content = '!';
            }
            cells.push(el('td', { class: `align-${c.align}` }, content));
        }

        const tr = el('tr', { class: [index % 2 && 'alt', onRowClick && 'clickable'],
            dataset: row.key !== null && row.key !== undefined ? { key: row.key } : null,
            onclick: onRowClick ? (e) => {
                if (!e.target.closest('a, button'))
                    onRowClick(row);
            } : null }, cells);

        for (const { h, s } of active) {
            try {
                if (h.match(row)) {
                    tr.classList.add('highlighted');
                    tr.style.setProperty('--highlight', h.color ? h.color(row) : s.color);
                    break;
                }
            } catch (err) {
                console.error(`${id} highlight ${h.id} failed:`, err);
            }
        }

        return tr;
    }

    // A row that hasn't loaded yet
    function placeholderRow(index) {
        return el('tr', { class: ['placeholder', index % 2 && 'alt'] },
            el('td', { colspan: shownColumns.length + iconCol }, el('span', { class: 'sk placeholder-bar' })));
    }

    function spacer(height) {
        return el('tr', { class: 'spacer', 'aria-hidden': 'true' },
            el('td', { colspan: shownColumns.length + iconCol, style: { height: `${height}px` } }));
    }

    // The rows on screen: [first, last], by index into the whole list
    function visibleRange() {
        const h = state.rowHeight || 30;
        const headerHeight = thead.getBoundingClientRect().height;
        const first = Math.max(0, Math.floor(holder.scrollTop / h));
        const count = Math.ceil(Math.max(0, holder.clientHeight - headerHeight) / h);
        return [first, first + count];
    }

    // A table in a tab that isn't showing has nothing to draw or load
    const onScreen = () => (holder.checkVisibility ? holder.checkVisibility() : holder.offsetParent !== null);

    // Draw the rows on screen and ask for any that aren't loaded.  Cheap to
    // call often: it does nothing if the same rows are already drawn.
    function draw(force = false) {
        if (!onScreen())
            return;
        if (!state.rowHeight)
            measureRowHeight();

        const total = rows.total ?? 0;
        const [first, last] = visibleRange();
        const start = Math.max(0, first - overscan);
        const end = Math.min(total, last + 1 + overscan);

        rows.want(first, last, 1, state.direction);

        const key = `${start}:${end}:${total}:${rows.version}`;
        if (force || key !== state.drawn) {
            state.drawn = key;

            const active = activeHighlights();
            const iconList = listOf(icons);

            const out = [];
            if (start > 0)
                out.push(spacer(start * state.rowHeight));
            for (let i = start; i < end; i++) {
                const row = rows.row(i);
                out.push(row ? makeRow(row, i, active, iconList) : placeholderRow(i));
            }
            if (end < total)
                out.push(spacer((total - end) * state.rowHeight));
            tbody.replaceChildren(...out);
            fitContents();
        }

        // Preloads ahead of the user stay quiet; the bar is only for rows they're waiting on
        loadingBar.hidden = !rows.waiting(first, last) || (state.error !== null && rows.total === null);
        showOutline();
        updateInfo(first, last);
    }

    function showOutline() {
        if (rows.total !== null) {
            outline?.done();
            outline = null;
            return;
        }
        const cells = [...thead.querySelectorAll('th')];
        if (!outline)
            outline = loading.overlay(area, { kind: 'table', rows: 12, columns: Math.max(1, cells.length) },
                { label: `Loading ${noun}`, className: 'sk-table-layer' });
        outline.node.style.top = `${thead.offsetHeight}px`;
        // Line the outline up under the real columns
        if (cells.length) {
            const template = cells.map((c) => `${c.offsetWidth}px`).join(' ');
            for (const row of outline.node.querySelectorAll('.sk-table-row'))
                if (row.childElementCount === cells.length)
                    row.style.gridTemplateColumns = template;
        }
        if (state.error)
            outline.error(state.error.message);
        else
            outline.retry();
    }

    function updateInfo(first, last) {
        const total = rows.total;
        if (total === null) {
            countInfo.textContent = '';
        } else if (total === 0) {
            countInfo.textContent = state.search ? `0 of ${state.unfiltered.toLocaleString()} ${noun}` : `0 ${noun}`;
        } else {
            const shown = `${(first + 1).toLocaleString()}-${Math.min(total, last + 1).toLocaleString()}`;
            countInfo.textContent = state.search ?
                `${shown} of ${total.toLocaleString()} matching (${state.unfiltered.toLocaleString()} ${noun})` :
                `${shown} of ${total.toLocaleString()} ${noun}`;
        }

        let text = '';
        if (state.error && rows.total === null)
            text = `Could not load ${noun}: ${state.error.message}`;
        else if (total === 0)
            text = state.search ? `No ${noun} match the search` : (emptyText ?? `No ${noun} yet`);
        message.textContent = text;
        message.hidden = text === '';
    }

    async function loadPage(page, size, signal) {
        const sortColumn = columns.get(state.sort.column);
        const vars = {
            page,
            length: size,
            search: state.search || undefined,
            sort: sortColumn?.sortField,
            // Kismet's sort_dir is backwards on every list: "desc" sorts ascending
            sort_dir: sortColumn?.sortField ? (state.sort.dir === 'asc' ? 'desc' : 'asc') : undefined,
        };
        const path = typeof endpoint === 'function' ? endpoint() : endpoint;
        const result = await api.post(path, { fields: wantedFields() }, vars, { signal });
        state.unfiltered = result.total_row ?? 0;
        return { rows: result.data ?? [], total: result.last_row ?? 0 };
    }

    // Start the list over: for a new sort, search, or list (back to the
    // top), or new fields (stay where we are)
    function restart(toTop) {
        rows.reset();
        if (toTop)
            holder.scrollTop = 0;
        draw(true);
    }

    holder.addEventListener('scroll', () => {
        const top = holder.scrollTop;
        state.direction = top >= state.lastScroll ? 1 : -1;
        state.lastScroll = top;
        requestAnimationFrame(() => draw());
    }, { passive: true });

    // Keep what's on screen current, while it's on screen
    function tick() {
        if (document.visibilityState !== 'hidden' && onScreen()) {
            rows.refresh();
            draw();
        }
        state.timer = setTimeout(tick, refreshSeconds * 1000);
    }

    // Toolbar: the owner's controls, the search, the count, the edit button
    const handle = { restart, draw, element: container };
    toolbarEl.append(...[toolbar?.(handle)].flat().filter(Boolean),
        el('label', { class: 'search-box' }, icon('search'), searchInput),
        el('div', { class: 'spacer' }),
        countInfo,
        editButton);

    buildHeader();
    columns.watch(() => {
        // Columns from modules that loaded late; the defaults may have changed
        if (!state.editing)
            state.layout = savedLayout(id, columns);
        buildHeader();
        restart(false);
    });
    for (const r of [icons, highlights, searchFields?.watch ? searchFields : null, ...watch].filter(Boolean))
        r.watch(() => restart(false));
    for (const key of [`${id}.columns`, `${id}.highlights`]) {
        settings.watch(key, () => {
            if (!state.editing) {
                state.layout = savedLayout(id, columns);
                layoutChanged();
            }
        });
    }

    // More or fewer rows fit when the space changes size or the font does;
    // a table in a tab that's just been shown also starts here
    new ResizeObserver(debounce(100, () => {
        state.rowHeight = 0;
        buildHeader();
        draw(true);
    })).observe(holder);

    tick();
    return handle;
}
