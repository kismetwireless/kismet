// Dialogs, built on the browser's <dialog> element.
//
//   const d = dialog({ title: 'Settings', body: someNode, onClose: () => ... });
//   d.close();
//
// modal: true blocks the page behind it (login); otherwise the dialog is a
// panel the user can leave open while using the page (device details).
// Panels can be moved by dragging their title bar and resized from their
// corner; position { left, top, width, height } places one, and onMove(position)
// is told where the user put it.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';

let topLayer = 10;

// Escape closes the panel in front.  Modal dialogs close themselves; Escape
// that something else used (cancelling an edit, closing the menu, clearing
// a search box) is left alone.
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || e.defaultPrevented || document.querySelector('dialog.modal[open], .menu-list:not([hidden])'))
        return;
    if (e.target.matches?.('input, textarea, select') && e.target.value)
        return;
    const panels = [...document.querySelectorAll('dialog.panel[open]')];
    if (!panels.length)
        return;
    const front = panels.reduce((a, b) => (Number(b.style.zIndex) > Number(a.style.zIndex) ? b : a));
    e.preventDefault();
    front.close();
});

export function dialog({ title, body, modal = true, closable = true, className = '', onClose = null,
    position = null, onMove = null }) {
    const closeButton = closable ?
        el('button', { class: 'icon-button', title: 'Close', onclick: () => close() }, icon('close')) : null;

    const titleEl = el('h2', {}, title);
    const content = el('div', { class: 'dialog-body' }, body);

    const header = el('header', { class: 'dialog-header' }, titleEl, closeButton);
    const node = el('dialog', { class: ['dialog', modal ? 'modal' : 'panel', className] }, header, content);

    if (!modal) {
        // Clicking a panel brings it in front of the other panels
        const raise = () => { node.style.zIndex = String(++topLayer); };
        node.addEventListener('pointerdown', raise);
        raise();
    }

    node.addEventListener('cancel', (e) => {
        if (!closable)
            e.preventDefault();
    });
    node.addEventListener('close', () => {
        node.remove();
        onClose?.();
    });

    document.body.append(node);
    if (modal) {
        node.showModal();
    } else {
        node.show();
        if (position)
            place(position);
        makeMovable();
    }

    function close() {
        if (node.open)
            node.close();
    }

    // Pin the panel at a position, instead of docked to the side of the window
    function place({ left, top, width, height }) {
        const w = Math.min(width ?? node.offsetWidth, window.innerWidth - 16);
        const h = Math.min(height ?? node.offsetHeight, window.innerHeight - 16);
        // Keep the title bar on screen, so the panel can always be dragged back
        left = Math.max(60 - w, Math.min(left, window.innerWidth - 60));
        top = Math.max(0, Math.min(top, window.innerHeight - 40));
        // Shorten it rather than let its bottom (and the end of its scrolling) go off screen
        const fit = Math.max(Math.min(h, 192), window.innerHeight - top - 8);
        Object.assign(node.style, { left: `${left}px`, top: `${top}px`, right: 'auto', bottom: 'auto',
            width: `${w}px`, height: `${Math.min(h, fit)}px` });
        node.classList.add('placed');
    }

    function currentPosition() {
        const r = node.getBoundingClientRect();
        return { left: Math.round(r.left), top: Math.round(r.top), width: Math.round(r.width), height: Math.round(r.height) };
    }

    function makeMovable() {
        header.addEventListener('pointerdown', (e) => {
            if (e.button !== 0 || e.target.closest('button'))
                return;
            e.preventDefault();
            header.setPointerCapture(e.pointerId);
            const start = currentPosition();
            const dx = e.clientX - start.left;
            const dy = e.clientY - start.top;
            node.classList.add('moving');

            const move = (ev) => place({ ...start, left: ev.clientX - dx, top: ev.clientY - dy });
            const up = () => {
                header.removeEventListener('pointermove', move);
                header.removeEventListener('pointerup', up);
                header.removeEventListener('pointercancel', up);
                node.classList.remove('moving');
                onMove?.(currentPosition());
            };
            header.addEventListener('pointermove', move);
            header.addEventListener('pointerup', up);
            header.addEventListener('pointercancel', up);
        });

        // Resizing from the corner; tell the owner the new size once it settles
        let timer = null;
        let firstSize = true;
        new ResizeObserver(() => {
            if (firstSize) {
                firstSize = false;
                return;
            }
            clearTimeout(timer);
            timer = setTimeout(() => {
                // Only a size the user set (by dragging the corner), not the
                // window changing size around a docked panel
                if (node.isConnected && !node.classList.contains('moving') && node.style.height)
                    onMove?.(currentPosition());
            }, 300);
        }).observe(node);
    }

    return {
        node,
        body: content,
        close,
        setTitle: (t) => titleEl.replaceChildren(t),
    };
}
