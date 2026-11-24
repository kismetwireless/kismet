// The collapsible sections of a details window: the device panel's, and
// other windows that show one record the same way (an Ethernet flow's).
//
//   const s = detailSections({ closed: 'detail.closed', what: 'device' });
//   panel.append(s.node);
//   s.render(record, sections, fieldsOf);
//
// sections is the list to draw, in order: { id, title, match(record),
// fields: [...detailFields rows], render(record, el), open: false to start
// closed }.  fieldsOf(section) gives a section's rows (default: its fields).
// Sections whose match() is false are left out.  Which sections the user
// closed is kept in the `closed` setting, by section id.  Calling render()
// again updates the sections in place, so open groups, graphs and edits
// survive; onToggle is called when the user opens or closes one.

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';
import { detailFields } from './detailfields.js';

export function detailSections({ closed, what = 'record', onToggle = null }) {
    const node = el('div', { class: 'detail-sections' }, el('p', { class: 'muted' }, 'Loading...'));
    const sectionEls = new Map();

    const isClosed = (id) => settings.get(closed, {})[id];
    function setClosed(id, shut) {
        const all = { ...settings.get(closed, {}) };
        if (shut)
            all[id] = true;
        else
            delete all[id];
        settings.set(closed, all);
    }

    function render(record, sections, fieldsOf = (s) => s.fields ?? []) {
        const matching = sections.filter((s) => {
            try {
                return s.match ? s.match(record) : true;
            } catch (err) {
                console.error(`${what} section ${s.id} failed:`, err);
                return false;
            }
        });

        const wanted = new Set(matching.map((s) => s.id));
        for (const [id, section] of sectionEls) {
            if (!wanted.has(id)) {
                section.remove();
                sectionEls.delete(id);
            }
        }
        if (sectionEls.size === 0)
            node.replaceChildren();

        let at = node.firstElementChild;
        for (const s of matching) {
            let section = sectionEls.get(s.id);
            if (!section) {
                const fieldsEl = el('div', { class: 'detail-body' });
                const customEl = el('div', { class: 'detail-body detail-custom' });
                const startOpen = !isClosed(s.id) && s.open !== false;
                section = el('details', { class: 'detail-section', open: startOpen, dataset: { id: s.id } },
                    el('summary', {}, s.title), fieldsEl, customEl);
                section.addEventListener('toggle', () => {
                    setClosed(s.id, !section.open);
                    onToggle?.(s.id, section.open);
                });
                section.fieldsEl = fieldsEl;
                section.customEl = customEl;
                sectionEls.set(s.id, section);
            }
            // Keep sections in order, moving only one that's out of place
            if (section !== at)
                node.insertBefore(section, at);
            else
                at = at.nextElementSibling;

            try {
                const fields = fieldsOf(s);
                section.fieldsEl.hidden = fields.length === 0;
                if (fields.length)
                    detailFields(section.fieldsEl, record, fields);
                section.customEl.hidden = !s.render;
                if (s.render)
                    s.render(record, section.customEl);
            } catch (err) {
                console.error(`${what} section ${s.id} failed:`, err);
                section.customEl.hidden = false;
                section.customEl.replaceChildren(el('p', { class: 'form-error' }, `This section failed: ${err.message}`));
            }
        }
    }

    return { node, render };
}
