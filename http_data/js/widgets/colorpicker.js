// A color picker with OK and Cancel, for colors the user sets one at a time
// (row highlights).  The browser's own picker is one button away for any
// color not in the swatches.
//
//   const color = await pickColor({ title: 'handshake', value: '#ff0000', onPreview: (c) => ... });
//   // color is '#rrggbb', or null if cancelled
//
// onPreview is called as the choice changes, and with the starting color on cancel.

import { el } from '../core/dom.js';
import { dialog } from './dialog.js';

const swatches = [
    '#ff0000', '#ff5555', '#ff6b6b', '#ffa8a8', '#ffb3b3', '#f06595', '#cc5de8', '#aa66ff',
    '#845ef7', '#5c7cfa', '#0089ff', '#74c0fc', '#a5d8ff', '#22b8cf', '#99e9f2', '#20c997',
    '#40c057', '#69db7c', '#8ce99a', '#b2f2bb', '#fab005', '#ffd43b', '#ffe066', '#f49e42',
    '#ffa94d', '#fd7e14', '#adb5bd', '#cee1ff', '#ffffff', '#868e96', '#495057', '#000000',
];

const hexRe = /^#[0-9a-f]{6}$/i;

export function pickColor({ title = 'Color', value = '#000000', onPreview = null }) {
    const start = hexRe.test(value) ? value.toLowerCase() : '#000000';
    let current = start;

    return new Promise((resolve) => {
        let answer = null;

        const preview = el('span', { class: 'cp-preview' });
        const hex = el('input', { class: 'cp-hex mono', value: start, maxlength: 7, spellcheck: false, 'aria-label': 'Hex color',
            oninput: () => {
                const v = hex.value.trim();
                if (hexRe.test(v))
                    set(v, false);
            } });
        const native = el('input', { type: 'color', class: 'cp-native', value: start, tabindex: -1, 'aria-hidden': 'true',
            oninput: () => set(native.value) });
        const grid = el('div', { class: 'cp-swatches', role: 'listbox', 'aria-label': 'Colors' },
            swatches.map((c) => el('button', { type: 'button', class: 'cp-swatch', title: c, 'aria-label': c, dataset: { color: c },
                style: { background: c }, onclick: () => set(c) })));

        function set(c, updateHex = true) {
            current = c.toLowerCase();
            preview.style.background = current;
            if (updateHex)
                hex.value = current;
            native.value = current;
            for (const b of grid.children)
                b.classList.toggle('selected', b.dataset.color === current);
            onPreview?.(current);
        }

        const d = dialog({
            title, className: 'color-picker-dialog',
            body: el('div', { class: 'cp' },
                grid,
                el('div', { class: 'cp-row' }, preview, hex,
                    el('button', { type: 'button', onclick: () => (native.showPicker ? native.showPicker() : native.click()) },
                        'More colors…'),
                    native),
                el('div', { class: 'form-buttons' },
                    el('button', { type: 'button', onclick: () => d.close() }, 'Cancel'),
                    el('button', { type: 'button', class: 'primary', onclick: () => { answer = current; d.close(); } }, 'OK'))),
            onClose: () => {
                if (answer === null)
                    onPreview?.(start);
                resolve(answer);
            },
        });
        set(start);
    });
}
