// A tabbed area of the page.  Its tabs are the kismet.ui.panes entries for
// that area; the last tab the user picked is remembered.
//
// A pane's create(body, area) can return tools: nodes shown at the right of
// the tab bar while its tab is showing.  area.setExpanded(true) makes the
// whole area fill the window, until the user switches to another tab;
// area.activate(id) switches to another of the area's tabs.
//
// showPane(id) switches to a tab from anywhere on the page (a ribbon stat,
// say): id is a pane id, or the id given to kismet.ui.addTable.

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';
import { panes } from '../registry/ui.js';

const areas = new Map();        // area name -> its api

export function showPane(id) {
    const pane = panes.get(id) ?? panes.get(`table-${id}`);
    const areaApi = pane && areas.get(pane.area);
    if (!areaApi)
        return false;
    areaApi.activate(pane.id);
    return true;
}

export function createPaneArea(container, area) {
    const tabs = el('div', { class: 'tabs', role: 'tablist' });
    const tools = el('div', { class: 'tab-tools' });
    const bar = el('div', { class: 'tab-bar' }, tabs, tools);
    const bodies = el('div', { class: 'tab-bodies' });
    container.append(bar, bodies);

    const expandListeners = new Set();
    const areaApi = {
        setExpanded(on) {
            container.classList.toggle('expanded', on);
            for (const fn of expandListeners)
                fn(on);
        },
        isExpanded: () => container.classList.contains('expanded'),
        activate: (id) => activate(id),
        onExpand(fn) {
            expandListeners.add(fn);
            return () => expandListeners.delete(fn);
        },
    };
    areas.set(area, areaApi);

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
            if (areaApi.isExpanded())
                areaApi.setExpanded(false);
        }
        const now = built.get(id);
        now.tab.setAttribute('aria-selected', 'true');
        now.body.hidden = false;
        tools.replaceChildren(...(now.handle?.tools ?? []));
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
                    handle = p.create(body, areaApi) ?? null;
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
