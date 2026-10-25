// The main menu: a button that opens a list of kismet.ui.menuItems.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import { menuItems } from '../registry/ui.js';

// The list opens in the browser's top layer (a popover), so no window or
// expanded pane can cover it, however far it has been raised
export function createMenu(container) {
    const list = el('div', { class: 'menu-list', role: 'menu', popover: 'manual', hidden: true });
    const topLayer = typeof list.showPopover === 'function';
    const button = el('button', { class: 'icon-button menu-button', title: 'Menu', 'aria-haspopup': 'menu',
        onclick: (e) => {
            e.stopPropagation();
            list.hidden ? openMenu() : closeMenu();
        } }, icon('menu'));

    function openMenu() {
        list.replaceChildren(...menuItems.list().map((item) =>
            el('button', { class: 'menu-item', role: 'menuitem', onclick: () => {
                closeMenu();
                item.onClick();
            } }, item.icon ? icon(item.icon) : null, item.title)));
        list.hidden = false;
        if (topLayer) {
            const r = button.getBoundingClientRect();
            Object.assign(list.style, { left: `${Math.round(r.left)}px`, top: `${Math.round(r.bottom + 6)}px` });
            list.showPopover();
        }
        list.querySelector('button')?.focus();
    }

    function closeMenu() {
        if (topLayer && list.matches(':popover-open'))
            list.hidePopover();
        list.hidden = true;
    }

    // It's placed under the button when it opens, so a resize leaves it behind
    window.addEventListener('resize', () => {
        if (!list.hidden)
            closeMenu();
    });

    document.addEventListener('click', (e) => {
        if (!list.hidden && !list.contains(e.target))
            closeMenu();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !list.hidden) {
            // Used up here, so it doesn't also close a window
            e.preventDefault();
            closeMenu();
        }
    });

    container.append(button, list);
}
