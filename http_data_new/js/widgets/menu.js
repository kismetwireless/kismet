// The main menu: a button that opens a list of kismet.ui.menuItems.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import { menuItems } from '../registry/ui.js';

export function createMenu(container) {
    const list = el('div', { class: 'menu-list', role: 'menu', hidden: true });
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
        list.querySelector('button')?.focus();
    }

    function closeMenu() {
        list.hidden = true;
    }

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
