// The device list's search help: how searches and filters are written
// (js/core/filterquery.js), and the field names filters can use, by category.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import { dialog } from './dialog.js';

let openWindow = null;

const syntax = [
    ['Huawei', 'Plain words search the name, MAC, manufacturer and other text, as before'],
    ['"guest net"', 'A quoted phrase'],
    ['Huawei || Dell', 'Either one; || and "or" are the same'],
    ['packets > 1000 && signal > -60', 'Both; && and "and" are the same, as are two terms side by side'],
    ['!(manuf ~ apple)', 'Neither; ! and "not" are the same, and ( ) group terms'],
    ['ssid == guest', 'Equal; != is not equal'],
    ['packets >= 10', 'Numbers compare with < <= > >=, and can be hex: 0x1a2b'],
    ['manuf ~ apple', 'Contains, ignoring case'],
    ['name =~ /^corp-/', 'Matches a regular expression'],
    ['last_time < 5m', 'Time fields: seen within the last 5 minutes (s, m, h, d)'],
    ['uptime > 1d', 'Duration fields, in s, m, h or d'],
    ['00:11:22', 'Part of a MAC address, in any MAC field'],
    ['^00:11', 'A MAC address that starts with these octets'],
    ['22:33$', 'A MAC address that ends with these octets'],
    ['ssid* ~ guest', 'name* searches a wider set of fields, where there is one'],
    ['sort: signal desc, packets', 'Orders the list'],
];

const kinds = {
    text: 'text',
    number: 'number',
    time: 'time',
    mac: 'MAC',
    duration: 'duration',
};

function categorySection(category, entries) {
    const rows = entries.map((e) => el('tr', { 'data-find': [...e.names, e.help, ...e.paths].join(' ').toLowerCase() },
        el('td', {}, el('code', {}, e.names[0]),
            e.names.length > 1 ? el('div', { class: 'muted sh-also' }, `also ${e.names.slice(1).join(', ')}`) : null),
        el('td', { class: 'muted' }, kinds[e.kind] ?? e.kind),
        el('td', {}, e.help ? el('div', {}, e.help) : null,
            el('div', { class: 'muted sh-path' }, e.paths.join(', ')))));
    return el('section', { class: 'sh-category' },
        el('h3', {}, category || 'Common'),
        el('table', { class: 'sh-table' },
            el('thead', {}, el('tr', {}, el('th', {}, 'Name'), el('th', {}, 'Kind'), el('th', {}, 'What it is'))),
            el('tbody', {}, rows)));
}

// guide: fieldGuide() from js/core/filterquery.js
export function openSearchHelp(guide) {
    if (openWindow?.node.isConnected) {
        openWindow.raise();
        return openWindow;
    }

    const byCategory = new Map();
    for (const e of guide) {
        if (!byCategory.has(e.category))
            byCategory.set(e.category, []);
        byCategory.get(e.category).push(e);
    }
    const categories = [...byCategory.keys()].sort((a, b) => (a === '' ? -1 : b === '' ? 1 : a.localeCompare(b)));
    for (const c of categories)
        byCategory.get(c).sort((a, b) => a.names[0].localeCompare(b.names[0]));
    const sections = categories.map((c) => categorySection(c, byCategory.get(c)));

    const none = el('p', { class: 'muted', hidden: true }, 'No field names match.');
    const find = el('input', { type: 'search', class: 'search', placeholder: 'Find a field name', spellcheck: 'false',
        oninput: () => {
            const q = find.value.trim().toLowerCase();
            let shown = 0;
            for (const s of sections) {
                let n = 0;
                for (const tr of s.querySelectorAll('tbody tr')) {
                    tr.hidden = q !== '' && !tr.dataset.find.includes(q);
                    n += tr.hidden ? 0 : 1;
                }
                s.hidden = n === 0;
                shown += n;
            }
            none.hidden = shown > 0;
        } });

    const body = el('div', { class: 'search-help' },
        el('p', {}, 'Type words to search, or write a filter with field names and operators.  A filter runs on the server ' +
            'as a device rule, so it covers every device in the view, not only the ones loaded.'),
        el('table', { class: 'sh-table sh-syntax' },
            el('tbody', {}, syntax.map(([ex, what]) => el('tr', {}, el('td', {}, el('code', {}, ex)), el('td', {}, what))))),
        el('p', { class: 'muted' }, 'A comparison never matches a device that has no value for its field, negated or not.  ' +
            'Names below are the fields filters can use; column titles work too, with spaces as _.'),
        el('h3', {}, 'Field names'),
        el('label', { class: 'search-box' }, icon('search'), find),
        none,
        sections);

    const w = Math.min(820, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 900);
    openWindow = dialog({
        title: 'Search and filter help', body, modal: false, className: 'search-help-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            openWindow = null;
        },
    });
    return openWindow;
}
