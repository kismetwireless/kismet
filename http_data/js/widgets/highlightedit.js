// The row highlight chooser: turn each highlight on or off and pick its color.
//
// `current` is the saved choice, { id: { enabled, color } }; onApply gets the
// new one.  Highlights the user hasn't touched use their own defaults.

import { el } from '../core/dom.js';
import { dialog } from './dialog.js';

// A highlight's setting, from the saved choice or its defaults
export function highlightSetting(h, saved = {}) {
    const s = saved[h.id] ?? {};
    return {
        enabled: s.enabled ?? h.defaultEnabled,
        color: s.color ?? h.defaultColor,
    };
}

// highlights is the table's registry of row highlights
export function chooseHighlights(highlights, current, onApply) {
    const list = highlights.list();
    const inputs = [];

    const items = list.map((h) => {
        const s = highlightSetting(h, current);
        const box = el('input', { type: 'checkbox', checked: s.enabled });
        const color = el('input', { type: 'color', value: s.color, title: 'Highlight color', hidden: !!h.color });
        const swatch = el('span', { class: 'highlight-sample' }, h.name);
        const paint = () => swatch.style.setProperty('--highlight', color.value);
        color.addEventListener('input', paint);
        paint();
        inputs.push({ h, box, color });

        return el('div', { class: 'highlight-item' },
            el('label', {}, box, swatch),
            color,
            h.color ? el('span', { class: 'muted' }, ' (colors set elsewhere)') : null,
            h.description ? el('div', { class: 'muted' }, h.description) : null);
    });

    const form = el('form', { class: 'highlight-chooser' },
        el('p', { class: 'muted' }, 'Color the device rows that match.  When a row matches more than one, the first in this list wins.'),
        el('div', { class: 'highlight-list' }, list.length ? items : el('p', {}, 'No highlights are available.')),
        el('div', { class: 'form-buttons' },
            el('button', { type: 'button', onclick: () => {
                for (const { h, box, color } of inputs) {
                    box.checked = h.defaultEnabled;
                    color.value = h.defaultColor;
                    color.dispatchEvent(new Event('input'));
                }
            } }, 'Defaults'),
            el('div', { class: 'spacer' }),
            el('button', { type: 'button', onclick: () => d.close() }, 'Cancel'),
            el('button', { type: 'submit', class: 'primary' }, 'Apply')));

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const out = {};
        for (const { h, box, color } of inputs)
            out[h.id] = { enabled: box.checked, color: color.value };
        onApply(out);
        d.close();
    });

    const d = dialog({ title: 'Row highlights', body: form, className: 'highlights-dialog' });
}
