// A tabbed area of the page.  Its tabs are the kismet.ui.panes entries for
// that area; the last tab the user picked is remembered.

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';
import { panes } from '../registry/ui.js';

export function createPaneArea(container, area) {
    const tabs = el('div', { class: 'tabs', role: 'tablist' });
    const bodies = el('div', { class: 'tab-bodies' });
    container.append(tabs, bodies);

    const built = new Map();    // pane id -> { tab, body, handle }
    let active = null;

    function activate(id) {
        if (active === id || !built.has(id))
            return;
        if (active && built.has(active)) {
            const old = built.get(active);
            old.tab.setAttribute('aria-selected', 'false');
            old.body.hidden = true;
            old.handle?.hide?.();
        }
        const now = built.get(id);
        now.tab.setAttribute('aria-selected', 'true');
        now.body.hidden = false;
        now.handle?.show?.();
        active = id;
        settings.set(`panes.${area}.active`, id);
    }

    function build() {
        const list = panes.list().filter((p) => p.area === area);
        const ids = new Set(list.map((p) => p.id));

        for (const [id, b] of built) {
            if (!ids.has(id)) {
                b.handle?.destroy?.();
                b.tab.remove();
                b.body.remove();
                built.delete(id);
                if (active === id)
                    active = null;
            }
        }

        for (const p of list) {
            if (!built.has(p.id)) {
                const body = el('div', { class: 'tab-body', role: 'tabpanel', hidden: true });
                const tab = el('button', { class: 'tab', role: 'tab', 'aria-selected': 'false',
                    onclick: () => activate(p.id) }, p.title);
                let handle = null;
                try {
                    handle = p.create(body) ?? null;
                } catch (err) {
                    console.error(`pane ${p.id} failed:`, err);
                }
                handle?.hide?.();
                built.set(p.id, { tab, body, handle });
            }
            const b = built.get(p.id);
            tabs.append(b.tab);
            bodies.append(b.body);
        }

        const wanted = settings.get(`panes.${area}.active`, null);
        activate(built.has(wanted) ? wanted : list[0]?.id);
        container.hidden = list.length === 0;
    }

    panes.watch(build);
    build();
}
