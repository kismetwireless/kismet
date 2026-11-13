// Dialogs, built on the browser's <dialog> element.
//
//   const d = dialog({ title: 'Settings', body: someNode, onClose: () => ... });
//   d.close();
//
// modal: true blocks the page behind it (login); otherwise the dialog is a
// panel the user can leave open while using the page (device details).
// Every dialog can be moved by dragging its title bar.  Panels can also be
// resized from their corner; position { left, top, width, height } places
// one, and onMove(position) is told where the user put it.  A panel that
// would cover nearly the whole window (most panels on a phone) fills it
// instead, below the menu and name.  A new panel moves to the nearest spot
// clear of the panels already open, when there is one.  fullSize: true gives
// a panel a button to fill the window and go back.  Modal dialogs keep the
// size their content gives them.

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
    position = null, onMove = null, fullSize = false }) {
    const closeButton = closable ?
        el('button', { class: 'icon-button', title: 'Close', onclick: () => close() }, icon('close')) : null;

    const titleEl = el('h2', {}, title);
    const content = el('div', { class: 'dialog-body' }, body);

    // Filling the window by choice, not because the window is small
    let maxed = false;
    const fullButton = fullSize && !modal ? el('button', { class: 'icon-button', onclick: () => {
        maxed = !maxed;
        fill();
    } }) : null;

    const header = el('header', { class: 'dialog-header' }, titleEl, fullButton, closeButton);
    // The size a panel was given, and when fill() last changed it
    let wanted = position;
    let filled = 0;
    const node = el('dialog', { class: ['dialog', modal ? 'modal' : 'panel', className] }, header, content);

    // Clicking a panel brings it in front of the other panels
    const raise = () => {
        if (!modal)
            node.style.zIndex = String(++topLayer);
    };
    if (!modal) {
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
        fill();
        avoidOthers();
        window.addEventListener('resize', fill);
        node.addEventListener('close', () => window.removeEventListener('resize', fill));
    }
    makeMovable();

    function close() {
        if (node.open)
            node.close();
    }

    // Panels stay below the top bar (menu and name), dialogs below the phone's
    // status bar; main.js keeps --topbar-bottom up to date
    function minTop() {
        const bar = document.querySelector('.topbar');
        if (!bar)
            return 0;
        if (modal)
            return Math.max(0, parseFloat(getComputedStyle(bar).paddingTop) - 6);
        return parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--topbar-bottom')) || 0;
    }

    // Pin the panel at a position, instead of docked to the side of the window
    function place({ left, top, width, height }) {
        const w = Math.min(width ?? node.offsetWidth, window.innerWidth - 16);
        const h = Math.min(height ?? node.offsetHeight, window.innerHeight - 16);
        // Keep the title bar on screen, so the panel can always be dragged back
        left = Math.max(60 - w, Math.min(left, window.innerWidth - 60));
        top = Math.max(minTop(), Math.min(top, window.innerHeight - 40));
        // Shorten it rather than let its bottom (and the end of its scrolling) go off screen
        const fit = Math.max(Math.min(h, 192), window.innerHeight - top - 8);
        Object.assign(node.style, { left: `${left}px`, top: `${top}px`, right: 'auto', bottom: 'auto',
            width: `${w}px`, height: `${Math.min(h, fit)}px` });
        node.classList.add('placed');
    }

    // Fill the window when the panel, at the size it was given, would cover
    // nearly all of it anyway; checked again (and a placed panel fitted back
    // on screen) when the window changes size, not when the user resizes it
    function fill() {
        filled = Date.now();
        node.classList.remove('full');
        if (wanted)
            place(wanted);
        const r = node.getBoundingClientRect();
        const below = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--topbar-bottom')) || 0;
        const full = maxed || (r.width >= window.innerWidth * 0.85 && r.height >= (window.innerHeight - below) * 0.75);
        if (fullButton) {
            // Nothing to go back to when the window is too small for the panel anyway
            fullButton.hidden = full && !maxed;
            fullButton.replaceChildren(icon(maxed ? 'collapse' : 'expand'));
            fullButton.title = maxed ? 'Back to its size' : 'Fill the window';
            fullButton.setAttribute('aria-pressed', maxed ? 'true' : 'false');
        }
        if (!full)
            return;
        node.classList.remove('placed');
        for (const k of ['left', 'top', 'right', 'bottom', 'width', 'height'])
            node.style.removeProperty(k);
        node.classList.add('full');
    }

    // Move a new panel off the panels already open: the free spot nearest
    // where it would have gone.  With no free spot, stay off the others'
    // title bars and out of the way of each one's corner, so they can still
    // be dragged, then cover as little of them as possible.  It keeps its
    // size, so it only goes where it fits whole.
    // The owner isn't told; it's not where the user put it.
    function avoidOthers() {
        if (node.classList.contains('full'))
            return;
        const others = [...document.querySelectorAll('dialog.panel[open]:not(.full)')]
            .filter((o) => o !== node && o.getClientRects().length)
            .map((o) => ({ r: o.getBoundingClientRect(), bar: o.querySelector('.dialog-header').getBoundingClientRect().bottom }));
        if (!others.length)
            return;
        const me = currentPosition();
        const { width: w, height: h } = me;
        const gap = 8;
        const top = minTop();
        const area = (x, y, l, t, r, b) =>
            Math.max(0, Math.min(x + w, r) - Math.max(x, l)) * Math.max(0, Math.min(y + h, b) - Math.max(y, t));
        const cascade = 32;
        const score = (x, y) => {
            let bars = 0, covered = 0;
            for (const { r, bar } of others) {
                // Right on top of another hides it, title and all
                if (Math.abs(x - r.left) < cascade && Math.abs(y - r.top) < cascade)
                    bars += w * h;
                bars += area(x, y, r.left, r.top, r.right, bar);
                covered += area(x, y, r.left, r.top, r.right, r.bottom);
            }
            return [bars, covered, Math.hypot(x - me.left, y - me.top)];
        };
        const better = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
        const here = score(me.left, me.top);
        if (!here[1])
            return;
        // Spots against the window's edges, and beside, above, below, just
        // under the title bar of, or a step off each panel
        const xs = [me.left, gap, window.innerWidth - w - gap,
            ...others.flatMap(({ r }) => [r.right + gap, r.left - w - gap, r.left + cascade, r.left - cascade])];
        const ys = [me.top, top + gap, window.innerHeight - h - gap,
            ...others.flatMap(({ r, bar }) => [r.bottom + gap, r.top - h - gap, r.top, bar + 4, r.top + cascade])];
        let best = null;
        for (const x of xs) {
            if (x < gap || x + w > window.innerWidth - gap)
                continue;
            for (const y of ys) {
                if (y < top || y + h > window.innerHeight - gap)
                    continue;
                const s = score(x, y);
                if (!best || better(s, best.s) < 0)
                    best = { x, y, s };
            }
        }
        if (!best || better(best.s, here) >= 0)
            return;
        wanted = { left: Math.round(best.x), top: Math.round(best.y), width: w, height: h };
        fill();
    }

    // A modal dialog only moves; its size follows its content (settings
    // sections differ), so only its height is held to what fits below its top
    function placeModal({ left, top }) {
        const w = node.offsetWidth;
        left = Math.max(60 - w, Math.min(left, window.innerWidth - 60));
        top = Math.max(minTop(), Math.min(top, window.innerHeight - 40));
        Object.assign(node.style, { left: `${left}px`, top: `${top}px`, right: 'auto', bottom: 'auto', margin: '0',
            maxHeight: `${Math.max(192, window.innerHeight - top - 8)}px` });
        node.classList.add('placed');
    }

    function currentPosition() {
        const r = node.getBoundingClientRect();
        return { left: Math.round(r.left), top: Math.round(r.top), width: Math.round(r.width), height: Math.round(r.height) };
    }

    function makeMovable() {
        header.addEventListener('pointerdown', (e) => {
            if (e.button !== 0 || e.target.closest('button') || node.classList.contains('full'))
                return;
            e.preventDefault();
            header.setPointerCapture(e.pointerId);
            const start = currentPosition();
            const dx = e.clientX - start.left;
            const dy = e.clientY - start.top;
            node.classList.add('moving');

            const move = (ev) => (modal ? placeModal : place)({ ...start, left: ev.clientX - dx, top: ev.clientY - dy });
            const up = () => {
                header.removeEventListener('pointermove', move);
                header.removeEventListener('pointerup', up);
                header.removeEventListener('pointercancel', up);
                node.classList.remove('moving');
                if (!modal)
                    wanted = currentPosition();
                onMove?.(currentPosition());
            };
            header.addEventListener('pointermove', move);
            header.addEventListener('pointerup', up);
            header.addEventListener('pointercancel', up);
        });

        if (modal) {
            // Keep a moved dialog on screen when the window gets smaller
            const refit = () => {
                if (node.classList.contains('placed'))
                    placeModal(currentPosition());
            };
            window.addEventListener('resize', refit);
            node.addEventListener('close', () => window.removeEventListener('resize', refit));
            return;
        }

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
                if (node.isConnected && !node.classList.contains('moving') && node.style.height && Date.now() - filled > 600) {
                    wanted = currentPosition();
                    onMove?.(wanted);
                }
            }, 300);
        }).observe(node);
    }

    return {
        node,
        body: content,
        close,
        raise,
        setTitle: (t) => titleEl.replaceChildren(t),
        // Widen a panel to `width` (no wider than the window), moving it left
        // if its right edge would go off screen
        widen(width) {
            if (modal)
                return;
            const p = currentPosition();
            const w = Math.min(width, window.innerWidth - 16);
            if (w <= p.width || node.classList.contains('full'))
                return;
            wanted = { ...p, width: w, left: Math.max(8, Math.min(p.left, window.innerWidth - 8 - w)) };
            place(wanted);
            fill();
        },
        // Shrink or grow a panel to the height of its content (no taller than
        // fits), keeping its top where it is; { grow: false } only shrinks it
        fitContent({ grow = true } = {}) {
            if (modal || node.classList.contains('full'))
                return;
            const p = currentPosition();
            // The body's scroll height is never less than the panel gives it, so measure what's in it
            // with unrounded sizes and the children's margins, or it's a pixel short and scrolls
            const pad = getComputedStyle(content);
            const kids = [...content.children].filter((c) => c.getClientRects().length);
            let inner = 0;
            if (kids.length) {
                const first = kids[0], last = kids.at(-1);
                inner = last.getBoundingClientRect().bottom + parseFloat(getComputedStyle(last).marginBottom) -
                    first.getBoundingClientRect().top + parseFloat(getComputedStyle(first).marginTop);
            }
            const h = Math.ceil(header.getBoundingClientRect().height + inner + parseFloat(pad.paddingTop) +
                parseFloat(pad.paddingBottom) + node.offsetHeight - node.clientHeight);
            if (h === p.height || (!grow && h > p.height))
                return;
            wanted = { ...p, height: h };
            place(wanted);
            fill();
        },
    };
}

// Ask before doing something that interrupts capture.  Resolves true for OK.
//   if (await confirm({ title: 'Restart?', text: 'Capture stops...', ok: 'Restart' })) ...
export function confirm({ title, text, ok = 'OK', cancel = 'Cancel', danger = false }) {
    return new Promise((resolve) => {
        let answer = false;
        const paragraphs = String(text ?? '').split('\n\n').map((t) => el('p', {}, t));
        const d = dialog({
            title,
            body: el('div', { class: 'form confirm' }, paragraphs,
                el('div', { class: 'form-buttons' },
                    el('button', { type: 'button', onclick: () => d.close() }, cancel),
                    el('button', { type: 'button', class: danger ? 'primary danger' : 'primary',
                        onclick: () => { answer = true; d.close(); } }, ok))),
            onClose: () => resolve(answer),
        });
        d.node.querySelector('.form-buttons .primary')?.focus();
    });
}
