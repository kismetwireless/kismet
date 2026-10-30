// Device list row highlights: one for each phy Kismet reports, in the color
// phys register in kismet.ui.phyColors, and the Settings section where the
// user turns highlights on and off and picks their colors (Appearance >
// Device Highlights).  The user's choices win over the defaults; only what
// differs from the defaults is saved, so a changed default still shows.

import { onLogin } from '../core/auth.js';

const base = 'kismet.device.base';
const savedKey = 'devicelist.highlights';

const categories = [
    { id: 'tag', title: 'Tag', note: 'Devices tagged by the server\'s device rules.  A device with several tags ' +
        'takes the color of the first one listed.' },
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

            function item(h) {
                const s = current(h);
                const sample = el('span', { class: 'highlight-sample' }, h.name);
                sample.style.setProperty('--highlight', s.color);
                const color = el('input', { type: 'color', value: s.color, title: 'Row color', hidden: !!h.color,
                    oninput: () => sample.style.setProperty('--highlight', color.value),
                    onchange: () => change(h, { color: color.value }) });
                return el('div', { class: 'highlight-item', dataset: { id: h.id } },
                    el('label', {},
                        el('input', { type: 'checkbox', checked: s.enabled, onchange: (e) => change(h, { enabled: e.target.checked }) }),
                        sample),
                    color,
                    h.description ? el('div', { class: 'muted' }, h.description) : null);
            }

            function draw() {
                const all = ui.rowHighlights.list();
                holder.replaceChildren(...categories.map((cat) => {
                    const list = all.filter((h) => (categories.some((c) => c.id === h.category) ? h.category : '') === cat.id);
                    return el('section', { class: 'dh-category', dataset: { category: cat.id || 'other' } },
                        el('div', { class: 'dh-head' }, el('h4', {}, cat.title),
                            el('button', { type: 'button', title: `Put the ${cat.title.toLowerCase()} colors back to their defaults`,
                                disabled: !list.length, onclick: () => {
                                    const out = { ...saved() };
                                    for (const h of list) {
                                        if (!out[h.id])
                                            continue;
                                        const { color: _drop, ...rest } = out[h.id];
                                        if (Object.keys(rest).length)
                                            out[h.id] = rest;
                                        else
                                            delete out[h.id];
                                    }
                                    settings.set(savedKey, out);
                                    draw();
                                } }, 'Default')),
                        el('p', { class: 'muted' }, cat.note),
                        list.length ? el('div', { class: 'highlight-list' }, list.map(item)) :
                            el('p', { class: 'muted' }, 'None yet.'));
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
