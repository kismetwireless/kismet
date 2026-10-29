// Showing a device's fields as a labelled list, for the device panel.
//
//   kismet.ui.detailFields(el, device, [
//       { title: 'MAC', field: 'kismet.device.base.macaddr' },
//       { title: 'Signal', field: 'kismet.device.base.signal/kismet.common.signal.last_signal',
//         format: (v) => `${v} dBm`, hideZero: true },
//       { group: 'Location', show: (v, dev) => hasFix(dev), fields: [ ... ] },
//       { list: 'dot11.device/dot11.device.advertised_ssid_map', itemTitle: (ssid) => ssid['dot11.advertisedssid.ssid'],
//         fields: [ { title: 'Channel', field: 'dot11.advertisedssid.channel' }, ... ] },
//   ]);
//
// Call it again with fresh data and it updates what's there instead of
// starting over, so graphs, open groups, and half-typed edits survive.
//
// A field entry:
//   title       label
//   field       path into the record, like 'kismet.device.base.signal/kismet.common.signal.last_signal'
//   value(rec)  compute the value instead of reading a field
//   format(value, rec)  turn the value into text or a DOM node (default: as is)
//   draw(cell, value, rec, state, device)  draw into the cell yourself, for
//               graphs and editors; called even when the value is missing, and
//               the cell and state object are kept between updates.  Return
//               text or a node to replace the cell's content, or nothing.
//   show(value, rec)  return false to leave the row out
//   hideEmpty   leave the row out when the value is '' (or missing)
//   hideZero    leave the row out when the value is 0 (or missing)
//   empty       text for a missing value; without it, missing values hide the row
//   help        longer explanation, shown from the (i) next to the label
//   wide        use the whole width, no label column (graphs, tables)
//   id          stable name for the row (default: title or field)
//
// A group: { group: 'Title' or (rec) => title, fields: [...], show(rec), help }
// A list:  { list: path, or items(rec), giving an array or an object;
//            itemTitle(item, key, rec), fields: [...] read from each item,
//            show(rec), empty: 'text when there are no items' }
//
// Functions get the record the field is read from (`rec`: the device, or
// the list item inside a list) and then the whole device:
//   value(rec, device), format(value, rec, device), show(value, rec, device)

import { el } from '../core/dom.js';
import { field as getField } from '../core/api.js';
import { icon } from '../core/icons.js';

const missing = (v) => v === undefined || v === null;

function entryKey(e, i) {
    if (e.id)
        return e.id;
    if (e.group)
        return `group:${typeof e.group === 'string' ? e.group : i}`;
    if (e.list)
        return `list:${typeof e.list === 'string' ? e.list : i}`;
    // Rows can read the same field (formatted two ways, say), so the title counts too
    return `${e.field ?? ''}|${e.title ?? ''}` === '|' ? String(i) : `${e.field ?? ''}|${e.title ?? ''}`;
}

// Keep each row's DOM between updates, keyed by its place in the field list
class Rows {
    constructor(container) {
        this.container = container;
        this.rows = new Map();
    }

    begin() {
        this.seen = new Set();
        this.order = [];
    }

    use(key, make) {
        let row = this.rows.get(key);
        if (!row) {
            row = make();
            this.rows.set(key, row);
        }
        this.seen.add(key);
        this.order.push(row.node);
        return row;
    }

    end() {
        for (const [key, row] of this.rows) {
            if (!this.seen.has(key)) {
                row.destroy?.();
                this.rows.delete(key);
            }
        }
        // Put rows in order, moving only the ones that are out of place
        let at = this.container.firstChild;
        for (const node of this.order) {
            if (node !== at)
                this.container.insertBefore(node, at);
            else
                at = at.nextSibling;
        }
        while (at) {
            const next = at.nextSibling;
            at.remove();
            at = next;
        }
    }
}

function helpButton(text) {
    const note = el('div', { class: 'df-help', hidden: true }, text);
    const button = el('button', { class: 'df-help-button', type: 'button', title: text, 'aria-label': 'Explain',
        onclick: () => { note.hidden = !note.hidden; } }, icon('info'));
    return { button, note };
}

function makeFieldRow(e) {
    const label = el('div', { class: 'df-label' }, e.title ?? '');
    const value = el('div', { class: 'df-value' });
    const node = el('div', { class: ['df-row', e.wide && 'df-wide'] }, e.wide ? null : label, value);
    if (e.help && !e.wide) {
        const h = helpButton(e.help);
        label.append(h.button);
        return { node: el('div', { class: 'df-row-wrap' }, node, h.note), value, state: {}, text: null };
    }
    return { node, value, state: {}, text: null };
}

function setContent(row, content) {
    if (content instanceof Node) {
        row.value.replaceChildren(content);
        row.text = null;
        return;
    }
    const text = missing(content) ? '' : String(content);
    if (text !== row.text) {
        row.value.textContent = text;
        row.text = text;
    }
}

function renderInto(rows, entries, rec, device, prefix) {
    entries.forEach((e, i) => {
        const key = `${prefix}${entryKey(e, i)}`;

        try {
            if (e.group) {
                if (e.show && !e.show(rec, device))
                    return;
                const row = rows.use(key, () => {
                    const text = el('span');
                    const title = el('div', { class: 'df-group-title' }, text);
                    const body = el('div', { class: 'df-fields' });
                    const node = el('div', { class: 'df-group' }, title);
                    if (e.help) {
                        const h = helpButton(e.help);
                        title.append(h.button);
                        node.append(h.note);
                    }
                    node.append(body);
                    return { node, title: text, body, rows: new Rows(body) };
                });
                row.title.textContent = typeof e.group === 'function' ? e.group(rec, device) : e.group;
                row.rows.begin();
                renderInto(row.rows, e.fields ?? [], rec, device, '');
                row.rows.end();
                // An empty group isn't worth a heading
                row.node.hidden = row.body.childElementCount === 0;
                return;
            }

            if (e.list) {
                if (e.show && !e.show(rec, device))
                    return;
                const items = e.items ? e.items(rec, device) : getField(rec, e.list);
                const entriesOf = Array.isArray(items) ? items.map((v, k) => [k, v]) :
                    (items && typeof items === 'object' ? Object.entries(items) : []);

                if (entriesOf.length === 0) {
                    if (e.empty === undefined)
                        return;
                    const row = rows.use(`${key}:empty`, () => makeFieldRow({ title: e.title ?? '' }));
                    setContent(row, e.empty);
                    return;
                }

                entriesOf.forEach(([k, item], index) => {
                    const row = rows.use(`${key}:${k}`, () => {
                        const title = el('div', { class: 'df-group-title' });
                        const body = el('div', { class: 'df-fields' });
                        return { node: el('div', { class: 'df-group df-item' }, title, body), title, body, rows: new Rows(body) };
                    });
                    row.title.textContent = e.itemTitle ? e.itemTitle(item, k, device, index) : String(k);
                    row.rows.begin();
                    renderInto(row.rows, e.fields ?? [], item, device, '');
                    row.rows.end();
                });
                return;
            }

            const value = e.value ? e.value(rec, device) : (e.field ? getField(rec, e.field) : undefined);

            if (e.draw) {
                if (e.show && !e.show(value, rec, device))
                    return;
                const row = rows.use(key, () => makeFieldRow(e));
                const out = e.draw(row.value, value, rec, row.state, device);
                if (out !== undefined)
                    setContent(row, out);
                return;
            }

            const isMissing = missing(value) || (e.hideEmpty && value === '') || (e.hideZero && value === 0);
            if (isMissing && e.empty === undefined)
                return;
            if (!isMissing && e.show && !e.show(value, rec, device))
                return;

            const row = rows.use(key, () => makeFieldRow(e));

            if (isMissing) {
                setContent(row, typeof e.empty === 'function' ? e.empty(rec, device) : e.empty);
            } else {
                setContent(row, e.format ? e.format(value, rec, device) : value);
            }
        } catch (err) {
            console.error(`device detail field ${key} failed:`, err);
        }
    });
}

export function detailFields(container, device, entries) {
    if (!container._detailRows) {
        container.replaceChildren();
        container.classList.add('df-fields');
        container._detailRows = new Rows(container);
    }
    const rows = container._detailRows;
    rows.begin();
    renderInto(rows, entries, device, device, '');
    rows.end();
}

// A small helper for read-only text in muted italics, like "Unknown"
export function muted(text) {
    return el('i', { class: 'muted' }, text);
}
