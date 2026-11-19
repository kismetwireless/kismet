// "About this view" for a window: a short description at the foot of the
// window that opens upward over the content, starts closed and remembers
// whether it was open.  On narrow screens it's a "?" button instead, for the
// window's button row, which opens the same text as a popup that scrolls.
//
//   const about = aboutView({ setting: 'gps.about' });
//   bar.append(about.button);       // the row the "?" goes at the right of
//   bar.classList.add('about-anchor');
//   body.append(..., about.node);   // last in the window's body
//   about.set(['A paragraph.', el('p', {}, ...)]);
//   about.destroy();                // when the window closes
//
// set() takes strings (each a paragraph) or nodes; call it again when the
// view changes (another tab).

import { el } from '../core/dom.js';
import * as settings from '../core/settings.js';

const narrow = window.matchMedia('(max-width: 640px)');

export function aboutView({ setting, title = 'About this view' } = {}) {
    const text = el('div', { class: 'about-view-body' });
    const node = el('details', { class: 'about-view', open: !!settings.get(setting, false) },
        el('summary', {}, title), text);
    node.addEventListener('toggle', () => settings.set(setting, node.open));

    const pop = el('div', { class: 'about-view-pop', hidden: true, role: 'dialog', 'aria-label': title });
    const button = el('button', { type: 'button', class: 'about-view-help', title, 'aria-label': title,
        'aria-expanded': 'false', onclick: () => showPop(pop.hidden) }, '?');

    function showPop(on) {
        pop.hidden = !on;
        button.classList.toggle('active', on);
        button.setAttribute('aria-expanded', String(on));
        if (on && !pop.isConnected)
            button.parentElement?.append(pop);
    }

    function layout() {
        const compact = narrow.matches;
        node.hidden = compact;
        button.hidden = !compact;
        (compact ? pop : node).append(text);
        if (!compact)
            showPop(false);
    }

    narrow.addEventListener('change', layout);
    layout();

    return {
        node,
        button,
        set(parts) {
            text.replaceChildren(...parts.map((p) => (typeof p === 'string' ? el('p', {}, p) : p)));
        },
        destroy() {
            narrow.removeEventListener('change', layout);
        },
    };
}
