// Editing the device list's columns: drag headings to reorder them, drag a
// heading's right edge to resize it, and pick the columns in a chooser.
//
// The layout being edited is { columns: [ids in order], widths: { id: px } }.

import { el } from '../core/dom.js';
import { dialog } from './dialog.js';

const minWidth = 40;

// Let a heading be dragged to a new place.  onMove(fromId, toId, before)
// is called on a drop.
export function makeDraggable(th, id, onMove) {
    th.draggable = true;

    th.addEventListener('dragstart', (e) => {
        // A drag that starts on the resize handle is a resize, not a move
        if (e.target.closest?.('.col-resize') || th.dataset.resizing) {
            e.preventDefault();
            return;
        }
        th.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/x-kismet-column', id);
    });

    th.addEventListener('dragend', () => {
        for (const h of th.parentElement?.children ?? [])
            h.classList.remove('dragging', 'drop-before', 'drop-after');
    });

    const isBefore = (e) => {
        const r = th.getBoundingClientRect();
        return e.clientX < r.left + r.width / 2;
    };

    th.addEventListener('dragover', (e) => {
        if (!e.dataTransfer.types.includes('text/x-kismet-column'))
            return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        th.classList.toggle('drop-before', isBefore(e));
        th.classList.toggle('drop-after', !isBefore(e));
    });

    th.addEventListener('dragleave', () => th.classList.remove('drop-before', 'drop-after'));

    th.addEventListener('drop', (e) => {
        e.preventDefault();
        const from = e.dataTransfer.getData('text/x-kismet-column');
        th.classList.remove('drop-before', 'drop-after');
        if (from && from !== id)
            onMove(from, id, isBefore(e));
    });
}

// Put a resize handle on a heading's right edge.  The <col> for the column
// takes the new width as it's dragged; onDone(px) gets the final width.
export function makeResizable(th, col, onDone) {
    const handle = el('span', { class: 'col-resize', title: 'Drag to resize' });
    th.append(handle);

    handle.addEventListener('click', (e) => e.stopPropagation());

    handle.addEventListener('pointerdown', (e) => {
        e.preventDefault();
        e.stopPropagation();
        handle.setPointerCapture(e.pointerId);
        th.dataset.resizing = '1';
        th.classList.add('resizing');

        const startX = e.clientX;
        const startWidth = th.getBoundingClientRect().width;
        let width = startWidth;

        const move = (ev) => {
            width = Math.max(minWidth, Math.round(startWidth + ev.clientX - startX));
            col.style.width = `${width}px`;
        };
        const up = () => {
            handle.removeEventListener('pointermove', move);
            handle.removeEventListener('pointerup', up);
            handle.removeEventListener('pointercancel', up);
            delete th.dataset.resizing;
            th.classList.remove('resizing');
            if (width !== startWidth)
                onDone(width);
        };

        handle.addEventListener('pointermove', move);
        handle.addEventListener('pointerup', up);
        handle.addEventListener('pointercancel', up);
    });

    // Double-click the edge to go back to the column's own width
    handle.addEventListener('dblclick', (e) => {
        e.stopPropagation();
        onDone(null);
    });
}

// Move column `from` next to column `to` in a list of ids
export function moveColumn(ids, from, to, before) {
    const out = ids.filter((x) => x !== from);
    const at = out.indexOf(to) + (before ? 0 : 1);
    out.splice(at, 0, from);
    return out;
}

// The default column choice from a table's columns: every one marked defaultVisible
export function defaultColumns(columns) {
    return columns.list().filter((c) => c.defaultVisible).map((c) => c.id);
}

// The column chooser: every one of a table's columns, grouped, ticked when
// shown.  Calls onApply(ids) with the new choice, keeping the order of
// columns already shown and adding newly ticked ones at the end.
export function chooseColumns(columns, current, onApply) {
    const groups = new Map();
    for (const c of columns.list()) {
        const g = c.group || 'General';
        if (!groups.has(g))
            groups.set(g, []);
        groups.get(g).push(c);
    }

    const boxes = [];
    const form = el('form', { class: 'column-chooser' });
    const groupList = el('div', { class: 'column-groups' });
    form.append(el('div', { class: 'column-scroll' }, groupList));
    for (const [group, cols] of groups) {
        groupList.append(el('fieldset', {},
            el('legend', {}, group),
            cols.map((c) => {
                const box = el('input', { type: 'checkbox', value: c.id, checked: current.includes(c.id) });
                boxes.push(box);
                return el('label', { class: 'check-item' }, box,
                    el('span', {}, c.title),
                    c.description ? el('span', { class: 'muted' }, c.description) : null);
            })));
    }

    const apply = () => {
        const ticked = new Set(boxes.filter((b) => b.checked).map((b) => b.value));
        const kept = current.filter((id) => ticked.has(id));
        for (const b of boxes)
            if (b.checked && !kept.includes(b.value))
                kept.push(b.value);
        onApply(kept);
        d.close();
    };

    const buttons = el('div', { class: 'form-buttons' },
        el('button', { type: 'button', onclick: () => {
            const defaults = new Set(defaultColumns(columns));
            for (const b of boxes)
                b.checked = defaults.has(b.value);
        } }, 'Defaults'),
        el('div', { class: 'spacer' }),
        el('button', { type: 'button', onclick: () => d.close() }, 'Cancel'),
        el('button', { type: 'submit', class: 'primary' }, 'Apply'));

    form.append(buttons);
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        apply();
    });

    const d = dialog({ title: 'Columns', body: form, className: 'columns-dialog' });
}
