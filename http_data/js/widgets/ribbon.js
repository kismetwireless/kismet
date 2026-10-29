// The stats ribbon across the top of the page.  Each stat is an entry in
// kismet.ui.ribbonStats; users can hide stats in settings.

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';
import { ribbonStats } from '../registry/ui.js';

export function isVisible(stat) {
    const chosen = settings.get('ribbon.visible', {});
    return chosen[stat.id] ?? stat.defaultVisible;
}

export function createRibbon(container) {
    let cleanups = [];

    function build() {
        for (const fn of cleanups)
            fn?.();
        cleanups = [];
        container.replaceChildren();

        for (const stat of ribbonStats.list()) {
            if (!isVisible(stat))
                continue;
            const body = el('div', { class: 'stat-body' });
            container.append(el('div', { class: 'stat', title: stat.description || stat.title, dataset: { stat: stat.id } },
                el('div', { class: 'stat-title' }, stat.title),
                body));
            try {
                cleanups.push(stat.create(body));
            } catch (err) {
                console.error(`ribbon stat ${stat.id} failed:`, err);
            }
        }
    }

    ribbonStats.watch(build);
    settings.watch('ribbon.visible', build);
    build();
}
