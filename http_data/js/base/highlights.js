// Device list row highlights: one for each phy Kismet reports, in the color
// phys register in kismet.ui.phyColors, and the Settings section where the
// user turns highlights on and off and picks their colors (Appearance >
// Device Highlights).  The user's choices win over the defaults; only what
// differs from the defaults is saved, so a changed default still shows.

import { onLogin } from '../core/auth.js';
import { pickColor } from '../widgets/colorpicker.js';

const base = 'kismet.device.base';
const savedKey = 'devicelist.highlights';

const categories = [
    // order: the setting the tags' dragged order is saved in
    { id: 'tag', title: 'Tag', order: 'ruletags.order', note: 'Devices tagged by the server\'s device rules.  ' +
        'Drag the tags by their handles to set their priority: a device with several tags takes the color of ' +
        'the highest one.' },
    { id: 'phy', title: 'Phy Type', note: 'Every device of a kind of radio.' },
    { id: '', title: 'Other', note: 'Devices the phys pick out themselves.' },
];

// A steady color for a phy or tag without one of its own
export function fallbackColor(name) {
    let h = 0;
    for (const c of name)
        h = (h * 31 + c.charCodeAt(0)) % 360;
    const f = (n) => {
        const k = (n + h / 30) % 12;
        const v = 0.78 - 0.18 * Math.max(-1, Math.min(k - 3, 9 - k, 1));
        return Math.round(v * 255).toString(16).padStart(2, '0');
    };
    return `#${f(0)}${f(8)}${f(4)}`;
}

export function register(kismet) {
    const { ui, dom, settings, api } = kismet;
    const { el } = dom;

    let phys = [];

    function addPhyHighlights() {
        const names = phys.map((p) => p['kismet.phy.phy_name']).filter((n) => typeof n === 'string' && n !== '');
        const titled = names.map((n) => ({ n, title: ui.phyColors.get(n)?.title ?? n }))
            .sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: 'base' }));
        titled.forEach(({ n, title }, i) => {
            const pc = ui.phyColors.get(n);
            ui.rowHighlights.add({
                id: `phy_${n}`, name: title, category: 'phy', priority: 200 + i / 1000,
                description: `Every ${title} device`,
                defaultColor: pc?.color ?? fallbackColor(n), defaultEnabled: pc?.enabled ?? false,
                fields: [`${base}.phyname`],
                match: (row) => row[`${base}.phyname`] === n,
            });
        });
    }

    async function loadPhys() {
        try {
            phys = await api.get('phy/all_phys.json') ?? [];
        } catch (err) {
            console.error('Could not load the phy list:', err);
            return;
        }
        addPhyHighlights();
    }

    loadPhys();
    onLogin(loadPhys);
    ui.phyColors.watch(addPhyHighlights);

    const saved = () => settings.get(savedKey, {}) ?? {};

    // A highlight's setting, with the user's choices over its defaults
    function current(h) {
        const s = saved()[h.id] ?? {};
        return { enabled: s.enabled ?? h.defaultEnabled, color: s.color ?? h.defaultColor };
    }

    // Save a change, keeping only what differs from the defaults
    function change(h, update) {
        const all = { ...saved() };
        const s = { ...(all[h.id] ?? {}), ...update };
        if (s.color === undefined || s.color === h.defaultColor)
            delete s.color;
        if (s.enabled === undefined || s.enabled === h.defaultEnabled)
            delete s.enabled;
        if (Object.keys(s).length)
            all[h.id] = s;
        else
            delete all[h.id];
        settings.set(savedKey, all);
    }

    ui.settingsPanes.add({
        id: 'highlights', title: 'Device Highlights', parent: 'appearance', priority: 5,
        create(body) {
            const holder = el('div', { class: 'dh-list' });

            // One highlight per row: on/off and name, what it matches, its color,
            // and a button to put just that color back to its default.  Tags also
            // get a handle to drag them into priority order, and their rules.
            function item(h, sortable) {
                const s = current(h);
                let shownColor = s.color;
                const sample = el('span', { class: 'highlight-sample' }, h.name);
                const swatch = el('button', { type: 'button', class: 'dh-swatch', title: 'Pick the row color',
                    'aria-label': `Row color for ${h.name}`, onclick: async () => {
                        const c = await pickColor({ title: `Row color: ${h.name}`, value: shownColor, onPreview: paint });
                        if (c) {
                            shownColor = c;
                            change(h, { color: c });
                        }
                        paint(shownColor);
                    } });
                const reset = el('button', { type: 'button', class: 'dh-default', title: 'Put the default color back',
                    onclick: () => {
                        change(h, { color: h.defaultColor });
                        shownColor = h.defaultColor;
                        paint(shownColor);
                    } }, 'Default');
                function paint(c) {
                    sample.style.setProperty('--highlight', c);
                    swatch.style.background = c;
                    reset.disabled = shownColor === h.defaultColor;
                }
                paint(shownColor);
                return el('li', { class: ['dh-item', sortable && 'sortable'], dataset: { id: h.id } },
                    sortable ? el('button', { type: 'button', class: 'dh-grip', title: 'Drag to set priority',
                        'aria-label': `Move ${h.name}; drag, or use the arrow keys` }, '⠿') : null,
                    el('label', { class: 'dh-name' },
                        el('input', { type: 'checkbox', checked: s.enabled, onchange: (e) => change(h, { enabled: e.target.checked }) }),
                        sample),
                    el('span', { class: 'dh-desc muted' }, h.description ?? '',
                        h.showRule ? el('button', { type: 'button', class: 'link-button dh-rule', onclick: () => h.showRule() }, 'Show rule') : null),
                    h.color ? el('span', { class: 'muted' }, 'Colored by its own rules') : swatch,
                    h.color ? null : reset);
            }

            // Drag a tag row by its handle (mouse or touch), or move it with the
            // arrow keys, then save the new order
            function sortableList(ul, onOrder) {
                const save = () => onOrder([...ul.children].map((li) => li.dataset.id));
                ul.addEventListener('keydown', (e) => {
                    const li = e.target.closest?.('.dh-grip') && e.target.closest('li');
                    if (!li || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown'))
                        return;
                    e.preventDefault();
                    if (e.key === 'ArrowUp' && li.previousElementSibling)
                        ul.insertBefore(li, li.previousElementSibling);
                    else if (e.key === 'ArrowDown' && li.nextElementSibling)
                        ul.insertBefore(li.nextElementSibling, li);
                    else
                        return;
                    li.querySelector('.dh-grip').focus();
                    save();
                });
                ul.addEventListener('pointerdown', (e) => {
                    const grip = e.target.closest('.dh-grip');
                    if (!grip || e.button !== 0)
                        return;
                    e.preventDefault();
                    // Moving the row in the page drops pointer capture, so follow the window
                    const li = grip.closest('li');
                    li.classList.add('dragging');
                    const move = (ev) => {
                        if (ev.pointerId !== e.pointerId)
                            return;
                        const over = [...ul.children].find((o) => {
                            const r = o.getBoundingClientRect();
                            return o !== li && ev.clientY >= r.top && ev.clientY <= r.bottom;
                        });
                        if (!over)
                            return;
                        const r = over.getBoundingClientRect();
                        ul.insertBefore(li, ev.clientY < r.top + r.height / 2 ? over : over.nextElementSibling);
                    };
                    const up = (ev) => {
                        if (ev.pointerId !== e.pointerId)
                            return;
                        window.removeEventListener('pointermove', move);
                        window.removeEventListener('pointerup', up);
                        window.removeEventListener('pointercancel', up);
                        li.classList.remove('dragging');
                        save();
                    };
                    window.addEventListener('pointermove', move);
                    window.addEventListener('pointerup', up);
                    window.addEventListener('pointercancel', up);
                });
                return ul;
            }

            function draw() {
                const all = ui.rowHighlights.list();
                holder.replaceChildren(...categories.map((cat) => {
                    const list = all.filter((h) => (categories.some((c) => c.id === h.category) ? h.category : '') === cat.id);
                    const ul = el('ul', { class: 'dh-items' }, list.map((h) => item(h, !!cat.order)));
                    if (cat.order)
                        sortableList(ul, (ids) => settings.set(cat.order,
                            ids.map((id) => ui.rowHighlights.get(id)?.tag).filter((t) => typeof t === 'string')));
                    return el('section', { class: 'dh-category', dataset: { category: cat.id || 'other' } },
                        el('h4', {}, cat.title),
                        el('p', { class: 'muted' }, cat.note),
                        list.length ? ul : el('p', { class: 'muted' }, 'None yet.'));
                }));
            }

            draw();
            body.append(el('p', { class: 'muted' }, 'Color the device list rows that match.  When a row matches ' +
                'more than one, tags come first, then the others, then phy types.'), holder);
            // Redraw for highlights that turn up later (the server's tags and phys), but
            // not while a color is being picked
            const stop = ui.rowHighlights.watch(() => {
                if (!holder.contains(document.activeElement))
                    draw();
            });
            return stop;
        },
    });
}
