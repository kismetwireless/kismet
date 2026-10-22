// The settings dialog: a list of sections (kismet.ui.settingsPanes) on the
// left, the chosen section on the right.  Changes apply immediately.

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';
import { settingsPanes } from '../registry/ui.js';
import { dialog } from './dialog.js';

export function openSettings(startId = null) {
    const nav = el('nav', { class: 'settings-nav' });
    const content = el('div', { class: 'settings-content' });
    let cleanup = null;

    function show(pane) {
        cleanup?.();
        cleanup = null;
        content.replaceChildren(el('h3', {}, pane.title));
        const body = el('div', { class: 'settings-pane' });
        content.append(body);
        try {
            cleanup = pane.create(body) ?? null;
        } catch (err) {
            body.append(el('p', { class: 'form-error' }, `This section failed: ${err.message}`));
        }
        for (const b of nav.children)
            b.classList.toggle('active', b.dataset.id === pane.id);
        settings.set('settings.lastPane', pane.id);
    }

    const list = settingsPanes.list();
    for (const pane of list)
        nav.append(el('button', { class: 'nav-item', dataset: { id: pane.id }, onclick: () => show(pane) }, pane.title));

    dialog({
        title: 'Settings',
        body: el('div', { class: 'settings' }, nav, content),
        className: 'settings-dialog',
        onClose: () => cleanup?.(),
    });

    const start = settingsPanes.get(startId ?? settings.get('settings.lastPane')) ?? list[0];
    if (start)
        show(start);
}
