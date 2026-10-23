// The Overview tab: a grid of cards (kismet.ui.dashboardCards) summing up
// everything Kismet sees.  The cards share their data: each refresh asks the
// server once for each kind of data any card needs, and hands every card
// the same results.  Nothing is fetched while the tab is hidden.
//
// The data a card can ask for, by name in its `needs`:
//   status     /system/status: device count and memory, with their RRDs
//   packets    /packetchain/packet_stats: packet rates
//   phys       /phy/all_phys: devices and packets per phy
//   channels   /channels/channels: the frequency map with its RRDs
//   alerts     the last hour of alerts
//   sources    the data sources
//   talkers    devices heard in the last 15 seconds, with their packets per
//              second over the last minute (pps, ending at ppst)
//   devices    every device heard in the chosen time window, with the
//              fields in deviceFields (renamed short), for counting
// plus `now` (server time) and `window` (seconds, or 0 for all devices).
//
// Layout: on wide screens the cards sit on a 12-column grid, each at an
// x, y, width, and height in grid cells, packed upward so there are no
// gaps.  "Edit layout" lets the user drag cards by their title, resize them
// from the corner, hide them, and add them back; other cards move out of the
// way.  The layout is kept per browser.  Narrower screens stack the cards in
// the same order, in two columns or one, at their natural height.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as clock from '../core/clock.js';
import * as settings from '../core/settings.js';
import { icon } from '../core/icons.js';
import { dashboardCards } from '../registry/ui.js';

const base = 'kismet.device.base';
const fastSeconds = 5;
const scanSeconds = 30;
const bigScanSeconds = 120;
const bigServer = 20000;

// The grid: columns, and the height of a row in pixels (cards span rows)
const columns = 12;
const rowPx = 30;
const gapPx = 10;
// Below this width the cards stack instead of using the grid
const gridMinWidth = 1000;
const minW = 2;
const minH = 3;

export const windows = [
    { id: 300, title: 'the last 5 minutes' },
    { id: 3600, title: 'the last hour' },
    { id: 6 * 3600, title: 'the last 6 hours' },
    { id: 0, title: 'all the time Kismet has run' },
];

// What the device scan reads, and the short names cards use
export const deviceFields = [
    [`${base}.phyname`, 'phy'], [`${base}.type`, 'type'], [`${base}.crypt`, 'crypt'],
    [`${base}.manuf`, 'manuf'], [`${base}.first_time`, 'first'], [`${base}.last_time`, 'last'],
    [`${base}.signal/kismet.common.signal.last_signal`, 'signal'],
    [`${base}.signal/kismet.common.signal.type`, 'sigtype'],
];

const talkerFields = [
    `${base}.key`, `${base}.macaddr`, `${base}.commonname`, `${base}.phyname`, `${base}.type`,
    [`${base}.packets.rrd/kismet.common.rrd.minute_vec`, 'pps'],
    [`${base}.packets.rrd/kismet.common.rrd.last_time`, 'ppst'],
];

const sourceFields = [
    'kismet.datasource.uuid', 'kismet.datasource.name', 'kismet.datasource.running',
    'kismet.datasource.channel', 'kismet.datasource.hopping', 'kismet.datasource.hop_channels',
    'kismet.datasource.num_packets', 'kismet.datasource.num_error_packets', 'kismet.datasource.num_dropped_packets',
    'kismet.datasource.packets_rrd', 'kismet.datasource.error', 'kismet.datasource.error_reason',
];

const loaders = {
    status: () => api.get('system/status.json'),
    packets: () => api.get('packetchain/packet_stats.json'),
    phys: () => api.get('phy/all_phys.json'),
    channels: () => api.get('channels/channels.json'),
    alerts: () => api.get('alerts/last-time/-3600/alerts.json'),
    sources: () => api.post('datasource/all_sources.json', { fields: sourceFields }),
    talkers: () => api.post('devices/views/all/last-time/-15/devices.json', { fields: talkerFields }),
};

// Grid layout, in cells.  An item is { id, x, y, w, h }.

const overlaps = (a, b) => a !== b && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

// Move every item as far up as it goes, top to bottom; `pinned` stays put
function compact(items, pinned = null) {
    const placed = pinned ? [pinned] : [];
    const order = items.filter((i) => i !== pinned).sort((a, b) => a.y - b.y || a.x - b.x);
    for (const it of order) {
        while (it.y > 0 && !placed.some((p) => overlaps({ ...it, y: it.y - 1 }, p)))
            it.y--;
        // Something pinned above it can leave it overlapping; push it below
        let hit;
        while ((hit = placed.find((p) => overlaps(it, p))))
            it.y = hit.y + hit.h;
        placed.push(it);
    }
}

// Put `item` at x, y and push whatever it lands on down out of the way
function moveTo(items, item, x, y) {
    item.x = Math.max(0, Math.min(columns - item.w, x));
    item.y = Math.max(0, y);
    pushDown(items, item);
}

function pushDown(items, item) {
    for (const other of items.filter((o) => overlaps(o, item)).sort((a, b) => a.y - b.y)) {
        other.y = item.y + item.h;
        pushDown(items, other);
    }
}

// The first spot, top to bottom and left to right, where a w × h card fits
function freeSpot(items, w, h) {
    for (let y = 0; ; y++) {
        for (let x = 0; x + w <= columns; x++) {
            const at = { x, y, w, h };
            if (!items.some((i) => overlaps(at, i)))
                return { x, y };
        }
    }
}

function defaultSize(entry) {
    return {
        w: Math.max(minW, Math.min(columns, entry.w ?? (entry.size === 'wide' ? 6 : 3))),
        h: Math.max(minH, entry.h ?? 5),
    };
}

export function createOverview(container, area = null) {
    const windowSelect = el('select', { 'aria-label': 'Which devices to count',
        onchange: () => {
            settings.set('overview.window', Number(windowSelect.value));
            scanAt = 0;
            refresh();
        } },
    windows.map((w) => el('option', { value: w.id, selected: w.id === settings.get('overview.window', 3600) }, w.title)));
    const status = el('span', { class: 'muted overview-status' });
    const grid = el('div', { class: 'overview-grid' });
    const placeholder = el('div', { class: 'ov-placeholder', hidden: true });
    const editBar = el('div', { class: 'overview-editbar', hidden: true });
    const root = el('div', { class: 'overview' },
        el('div', { class: 'overview-bar' }, el('label', {}, 'Count devices heard in ', windowSelect), status),
        editBar, grid);
    container.append(root);

    // Tab bar tools: arrange the cards, and fill the window with the overview
    const editButton = el('button', { class: 'icon-button tab-tool', title: 'Arrange the cards',
        onclick: () => setEditing(!editing) }, icon('edit'));
    const expandButton = el('button', { class: 'icon-button tab-tool',
        onclick: () => area?.setExpanded(!expanded) });
    const toolNode = el('span', { class: 'ov-tools' }, editButton, area ? expandButton : null);
    let expanded = false;

    function showExpanded(on) {
        expanded = on;
        expandButton.replaceChildren(icon(on ? 'collapse' : 'expand'));
        expandButton.title = on ? 'Back to the dashboard (Esc)' : 'Fill the window with the overview';
        expandButton.setAttribute('aria-pressed', on ? 'true' : 'false');
    }
    showExpanded(false);
    const stopExpand = area?.onExpand(showExpanded);

    const cards = new Map();   // id -> { entry, node, handle }
    const data = {};
    let visible = false;
    let timer = null;
    let busy = false;
    let scanAt = 0;
    let editing = false;
    let wide = true;

    // The saved layout: positions by card id, and the cards the user hid
    const saved = settings.get('overview.layout', null);
    let positions = new Map(Object.entries(saved?.cards ?? {}));
    let hidden = new Set(saved?.hidden ?? []);
    let items = [];

    function save() {
        settings.set('overview.layout', {
            cards: Object.fromEntries(items.map((i) => [i.id, { x: i.x, y: i.y, w: i.w, h: i.h }])),
            hidden: [...hidden],
        });
    }

    // What cards can do beyond drawing
    const actions = {
        showTab: (id) => area?.activate?.(id),
        showDevices: (viewId) => {
            settings.set('devicelist.view', viewId);
            area?.activate?.('devices');
        },
    };

    function makeCard(entry) {
        const body = el('div', { class: 'ov-card-body' });
        const hideButton = el('button', { class: 'icon-button ov-hide', title: 'Hide this card',
            onclick: () => hideCard(entry.id) }, icon('close'));
        const title = el('h3', { class: 'ov-card-title' }, el('span', {}, entry.title), hideButton);
        const resizer = el('span', { class: 'ov-resize', title: 'Drag to resize', 'aria-hidden': 'true' });
        const node = el('section', { class: 'ov-card', dataset: { card: entry.id } }, title, body, resizer);
        let handle = null;
        try {
            handle = entry.create(body, { actions }) ?? null;
        } catch (err) {
            console.error(`dashboard card ${entry.id} failed:`, err);
        }
        title.addEventListener('pointerdown', (e) => startDrag(e, entry.id, 'move'));
        resizer.addEventListener('pointerdown', (e) => startDrag(e, entry.id, 'resize'));
        return { entry, node, handle };
    }

    // Cards from the registry, placed where the user left them; new ones go
    // in the first free spot
    function build() {
        const list = dashboardCards.list();
        const ids = new Set(list.map((c) => c.id));
        for (const [id, c] of cards) {
            if (!ids.has(id)) {
                c.handle?.destroy?.();
                c.node.remove();
                cards.delete(id);
            }
        }
        for (const entry of list) {
            const c = cards.get(entry.id);
            if (!c || c.entry !== entry) {
                c?.handle?.destroy?.();
                c?.node.remove();
                cards.set(entry.id, makeCard(entry));
            }
        }

        const next = [];
        for (const entry of list) {
            if (hidden.has(entry.id))
                continue;
            const p = positions.get(entry.id);
            const size = defaultSize(entry);
            if (p && [p.x, p.y, p.w, p.h].every(Number.isFinite)) {
                const w = Math.max(minW, Math.min(columns, p.w));
                next.push({ id: entry.id, x: Math.max(0, Math.min(columns - w, p.x)), y: Math.max(0, p.y),
                    w, h: Math.max(minH, p.h) });
            } else {
                next.push({ id: entry.id, ...size, new: true });
            }
        }
        // Known positions first, then the new cards fill in
        items = next.filter((i) => !i.new);
        compact(items);
        for (const it of next.filter((i) => i.new)) {
            delete it.new;
            Object.assign(it, freeSpot(items, it.w, it.h));
            items.push(it);
        }
        positions = new Map(items.map((i) => [i.id, i]));
        apply();
        buildEditBar();
        if (visible)
            refresh();
    }

    // Grid positions onto the cards.  Stacked layouts go by the order of the
    // cards in the page, which is only rearranged when nothing is being
    // dragged (moving a card in the page would drop the drag).
    function apply(reorder = true) {
        const order = [...items].sort((a, b) => a.y - b.y || a.x - b.x);
        const shown = new Set(order.map((i) => i.id));
        for (const [id, c] of cards) {
            if (!shown.has(id))
                c.node.remove();
        }
        order.forEach((it, n) => {
            const c = cards.get(it.id);
            if (!c)
                return;
            c.node.style.gridColumn = `${it.x + 1} / span ${it.w}`;
            c.node.style.gridRow = `${it.y + 1} / span ${it.h}`;
            c.node.style.order = String(n);
            if (reorder || c.node.parentNode !== grid)
                grid.append(c.node);
        });
        if (placeholder.parentNode !== grid)
            grid.append(placeholder);
    }

    function hideCard(id) {
        hidden.add(id);
        items = items.filter((i) => i.id !== id);
        compact(items);
        apply();
        save();
        buildEditBar();
    }

    function showCard(id) {
        hidden.delete(id);
        const entry = cards.get(id)?.entry;
        if (!entry)
            return;
        const it = { id, ...defaultSize(entry) };
        Object.assign(it, freeSpot(items, it.w, it.h));
        items.push(it);
        apply();
        save();
        buildEditBar();
        cards.get(id).node.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    function buildEditBar() {
        const add = el('select', { 'aria-label': 'Add a card',
            onchange: () => {
                if (add.value)
                    showCard(add.value);
            } },
        el('option', { value: '' }, hidden.size ? 'Add a card…' : 'All cards are showing'),
        [...hidden].filter((id) => cards.has(id)).map((id) => el('option', { value: id }, cards.get(id).entry.title)));
        add.disabled = !hidden.size;
        editBar.replaceChildren(
            el('span', { class: 'muted' }, 'Drag a card by its title to move it, or by its corner to resize it.'),
            add,
            el('button', { onclick: resetLayout }, 'Reset layout'),
            el('button', { class: 'primary', onclick: () => setEditing(false) }, 'Done'));
    }

    function resetLayout() {
        positions = new Map();
        hidden = new Set();
        settings.remove('overview.layout');
        build();
    }

    function setEditing(on) {
        editing = on && wide;
        root.classList.toggle('editing', editing);
        editBar.hidden = !editing;
        editButton.classList.toggle('active', editing);
        editButton.setAttribute('aria-pressed', editing ? 'true' : 'false');
        editButton.title = editing ? 'Finish arranging (Esc)' : 'Arrange the cards';
    }

    // Escape finishes arranging first, then leaves the full window
    function onKey(e) {
        if (!visible || e.key !== 'Escape' || e.defaultPrevented || (!editing && !expanded))
            return;
        if (document.querySelector('dialog[open], .menu-list:not([hidden])'))
            return;
        if (e.target.matches?.('input, textarea') && e.target.value)
            return;
        e.preventDefault();
        if (editing)
            setEditing(false);
        else
            area?.setExpanded(false);
    }
    document.addEventListener('keydown', onKey);

    // Dragging a card's title moves it, its corner resizes it.  The card
    // follows the pointer; the placeholder shows where it will land, and the
    // other cards move out of the way as it goes.
    function startDrag(e, id, mode) {
        if (!editing || e.button !== 0 || e.target.closest('button, select, input, a'))
            return;
        const it = items.find((i) => i.id === id);
        const c = cards.get(id);
        if (!it || !c)
            return;
        e.preventDefault();
        const target = e.currentTarget;
        target.setPointerCapture(e.pointerId);

        const g = grid.getBoundingClientRect();
        const colStep = (g.width + gapPx) / columns;
        const rowStep = rowPx + gapPx;
        const startX = e.clientX;
        const startY = e.clientY;
        const start = { ...it };
        const before = items.map((i) => ({ ...i }));
        const rect = c.node.getBoundingClientRect();

        c.node.classList.add(mode === 'move' ? 'dragging' : 'resizing');
        placeholder.hidden = false;
        const showPlaceholder = () => {
            placeholder.style.gridColumn = `${it.x + 1} / span ${it.w}`;
            placeholder.style.gridRow = `${it.y + 1} / span ${it.h}`;
        };
        showPlaceholder();

        const move = (ev) => {
            const dx = ev.clientX - startX;
            const dy = ev.clientY - startY;
            // Start over from the layout before the drag each time, so cards
            // that were pushed aside come back when the drag moves on
            items.forEach((i) => Object.assign(i, before.find((b) => b.id === i.id)));
            if (mode === 'move') {
                const x = Math.max(0, Math.min(columns - it.w, Math.round(start.x + dx / colStep)));
                const y = Math.max(0, Math.round(start.y + dy / rowStep));
                // Landing squarely on a card the same size swaps the two;
                // anywhere else pushes what's there down
                const other = items.find((o) => o !== it && o.x === x && o.y === y && o.w === it.w && o.h === it.h);
                if (other) {
                    other.x = start.x;
                    other.y = start.y;
                    it.x = x;
                    it.y = y;
                } else {
                    moveTo(items, it, x, y);
                }
                compact(items, it);
                c.node.style.transform = '';
                apply(false);
                // The card itself follows the pointer from where its cell is now
                const cell = { left: g.left + it.x * colStep, top: g.top + it.y * rowStep };
                c.node.style.transform = `translate(${rect.left + dx - cell.left}px, ${rect.top + dy - cell.top}px)`;
            } else {
                it.w = Math.max(minW, Math.min(columns - it.x, Math.round(start.w + dx / colStep)));
                it.h = Math.max(minH, Math.round(start.h + dy / rowStep));
                pushDown(items, it);
                compact(items, it);
                apply(false);
            }
            showPlaceholder();
        };
        const up = () => {
            target.removeEventListener('pointermove', move);
            target.removeEventListener('pointerup', up);
            target.removeEventListener('pointercancel', up);
            c.node.classList.remove('dragging', 'resizing');
            c.node.style.transform = '';
            placeholder.hidden = true;
            compact(items);
            apply();
            save();
        };
        target.addEventListener('pointermove', move);
        target.addEventListener('pointerup', up);
        target.addEventListener('pointercancel', up);
    }

    // The grid on wide screens; stacked, at natural heights, on narrow ones
    const resize = new ResizeObserver(() => {
        const w = root.clientWidth;
        const nowWide = w >= gridMinWidth;
        root.classList.toggle('stacked', !nowWide);
        root.classList.toggle('two-up', !nowWide && w >= 640);
        if (nowWide !== wide) {
            wide = nowWide;
            if (!wide)
                setEditing(false);
        }
        editButton.hidden = !wide;
    });
    resize.observe(root);

    function needed() {
        const set = new Set();
        for (const it of items)
            for (const n of cards.get(it.id)?.entry.needs ?? [])
                set.add(n);
        return set;
    }

    async function scanDevices() {
        const w = Number(settings.get('overview.window', 3600));
        const path = w ? `devices/views/all/last-time/${-w}/devices.json` : 'devices/views/all/devices.json';
        const list = await api.post(path, { fields: deviceFields });
        data.window = w;
        return Array.isArray(list) ? list : [];
    }

    async function refresh() {
        if (busy || !visible)
            return;
        busy = true;
        try {
            const want = needed();
            const jobs = [];
            for (const name of want) {
                if (loaders[name])
                    jobs.push(loaders[name]().then((v) => { data[name] = v; }));
            }
            // The device scan is the expensive one; it runs less often, and
            // less still on servers with many devices
            if (want.has('devices')) {
                const count = data.status?.['kismet.system.devices.count'] ?? 0;
                const every = (count > bigServer ? bigScanSeconds : scanSeconds) * 1000;
                if (!scanAt || Date.now() - scanAt >= every) {
                    scanAt = Date.now();
                    jobs.push(scanDevices().then((v) => { data.devices = v; }));
                }
            }
            const results = await Promise.allSettled(jobs);
            const failed = results.filter((r) => r.status === 'rejected');
            status.textContent = failed.length ? `Some data could not be loaded: ${failed[0].reason?.message ?? failed[0].reason}` : '';
            data.now = clock.isKnown() ? clock.now() : Date.now() / 1000;
            for (const it of items) {
                const c = cards.get(it.id);
                try {
                    c?.handle?.update?.(data);
                } catch (err) {
                    console.error(`dashboard card ${it.id} failed to update:`, err);
                }
            }
        } finally {
            busy = false;
        }
    }

    const stopWatch = dashboardCards.watch(build);
    build();

    return {
        tools: [toolNode],
        show() {
            visible = true;
            refresh();
            timer = setInterval(refresh, fastSeconds * 1000);
        },
        hide() {
            visible = false;
            setEditing(false);
            clearInterval(timer);
            timer = null;
        },
        destroy() {
            clearInterval(timer);
            stopWatch();
            resize.disconnect();
            stopExpand?.();
            document.removeEventListener('keydown', onKey);
            for (const c of cards.values())
                c.handle?.destroy?.();
            root.remove();
        },
    };
}
