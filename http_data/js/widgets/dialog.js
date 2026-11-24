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
// instead, below the menu and name.  A placed panel is kept wholly on
// screen, made smaller if the window is smaller than it; it goes back to the
// size and place it was given when the window grows again; one as tall as
// the window allowed stays as tall as the window.  A new panel moves to the nearest spot
// clear of the panels already open, when there is one.  fullSize: true gives
// a panel a button to fill the window and go back.  Modal dialogs keep the
// size their content gives them.

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';

let topLayer = 10;

// The notch and home indicator insets; scripts can't read env(), so a hidden
// probe is padded with them
let insetProbe = null;
function safeInsets() {
    if (!insetProbe?.isConnected) {
        insetProbe = el('div', { 'aria-hidden': 'true', style: 'position: fixed; top: 0; left: 0; visibility: hidden; ' +
            'pointer-events: none; padding: env(safe-area-inset-top) env(safe-area-inset-right) ' +
            'env(safe-area-inset-bottom) env(safe-area-inset-left)' });
        document.body.append(insetProbe);
    }
    const s = getComputedStyle(insetProbe);
    return { left: parseFloat(s.paddingLeft) || 0, right: parseFloat(s.paddingRight) || 0, bottom: parseFloat(s.paddingBottom) || 0 };
}

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
        // Fit it again when the window changes size or turns, and when the top
        // bar does (the ribbon wrapping to a row of its own)
        const bar = document.querySelector('.topbar');
        let barSeen = false;
        const barWatch = bar ? new ResizeObserver(() => {
            if (barSeen)
                fill();
            barSeen = true;
        }) : null;
        barWatch?.observe(bar);
        window.addEventListener('resize', fill);
        node.addEventListener('close', () => {
            window.removeEventListener('resize', fill);
            barWatch?.disconnect();
        });
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

    // Where a panel may be drawn, and the tallest it can be, measured now
    function room() {
        const s = safeInsets();
        const r = { left: s.left, top: minTop(), right: window.innerWidth - s.right, bottom: window.innerHeight - s.bottom };
        r.tallest = r.bottom - r.top - 8;
        return r;
    }

    // A position taken from the screen.  A panel as tall as the window
    // allows (docked, or dragged to the bottom) is marked fullHeight, so it
    // opens as tall as the window is then, not as tall as it was
    function measured(p, drawn = p.height) {
        return { ...p, fullHeight: drawn >= room().tallest - 24 };
    }

    // Pin the panel at a position, instead of docked to the side of the
    // window.  All of it stays on screen, below the top bar and clear of the
    // notch: no bigger than the window (its CSS minimum size still wins), then
    // moved in.  Only what's drawn changes, not `wanted`.
    function place({ left, top, width, height, fullHeight }) {
        const r = room();
        // A saved position from an older or damaged setting may not be numbers
        const num = (v, d) => (Number.isFinite(v) ? v : d);
        const w = Math.min(num(width, node.offsetWidth), r.right - r.left - 16);
        const h = fullHeight === true ? r.tallest : Math.min(num(height, node.offsetHeight), r.tallest);
        node.classList.add('placed');
        Object.assign(node.style, { right: 'auto', bottom: 'auto', width: `${w}px`, height: `${h}px` });
        const ow = node.offsetWidth, oh = node.offsetHeight;
        // Narrowed to fit: centred, rather than against one edge
        if (num(width, 0) > w)
            left = r.left + Math.round((r.right - r.left - ow) / 2);
        left = Math.max(r.left, Math.min(num(left, r.left), r.right - ow));
        top = Math.max(r.top, Math.min(num(top, r.top), r.bottom - oh));
        Object.assign(node.style, { left: `${left}px`, top: `${top}px` });
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
        const at = { left: Math.round(best.x), top: Math.round(best.y) };
        wanted = wanted ? { ...wanted, ...at } : measured({ ...at, width: w, height: h });
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
                if (modal) {
                    onMove?.(currentPosition());
                    return;
                }
                // Moved, not resized: keep the size it was given, though the
                // window may be showing it smaller
                const now = currentPosition();
                wanted = measured({ ...now, width: wanted?.width ?? now.width, height: wanted?.height ?? now.height }, now.height);
                onMove?.({ ...wanted });
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
                    wanted = measured(currentPosition());
                    onMove?.({ ...wanted });
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
            wanted = { ...(wanted ?? p), width: w };
            fill();
        },
        // Shrink or grow a panel to the height of its content (no taller than
        // fits), keeping its top where it is unless it would then run off the
        // bottom of the window; { grow: false } only shrinks it
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
            wanted = { ...(wanted ?? p), height: h, fullHeight: false };
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
