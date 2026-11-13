// Shortening text to fit the space it's shown in, for any part of the UI.
// 'middle' keeps both ends ("too l...ame"), 'end' keeps the start ("too long n...");
// the user picks one in Settings > Appearance.
//
//   shorten(text, fits, how)   the longest shortened text for which fits(s) is true
//   fitText(elem, text, how)   shows text in elem, shortened if it doesn't fit in
//                              elem's width; true when it was shortened
//   fitTexts(elems, texts, how)  the same for elements of one width and font,
//                              such as a table column's cells, measured once
//   fullText(elem)             the text fitText was given, as censor mode shows
//                              it, or null
//
// In censor mode the text is censored before it's shortened: the page's
// censor watcher only finds whole names, and would miss a shortened one.

import * as settings from './settings.js';
import * as censor from './censor.js';

export const modes = [
    { id: 'middle', title: 'In the middle (too l...ame)' },
    { id: 'end', title: 'At the end (too long n...)' },
];

const key = 'text.shorten';
const ellipsis = '...';

export function mode() {
    const m = settings.get(key);
    return modes.some((x) => x.id === m) ? m : 'middle';
}

export function setMode(m) {
    settings.set(key, m);
}

// Call fn(mode) when the user picks another; returns a function that stops watching
export function watch(fn) {
    return settings.watch(key, () => fn(mode()));
}

function cut(chars, keep, how) {
    if (how === 'end')
        return chars.slice(0, keep).join('') + ellipsis;
    const head = Math.ceil(keep / 2);
    return chars.slice(0, head).join('') + ellipsis + chars.slice(chars.length - (keep - head)).join('');
}

export function shorten(text, fits, how = mode()) {
    const s = String(text ?? '');
    if (fits(s))
        return s;
    // By code point, so a character outside the BMP is never split
    const chars = Array.from(s);
    let lo = 0;
    let hi = chars.length - 1;
    while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (fits(cut(chars, mid, how)))
            lo = mid;
        else
            hi = mid - 1;
    }
    return cut(chars, lo, how);
}

let ctx = null;
const full = new WeakMap();

// The width of elem's content box, and a measure of text in its font
function measurer(elem) {
    const style = getComputedStyle(elem);
    const room = elem.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    ctx ??= document.createElement('canvas').getContext('2d');
    ctx.font = style.font || `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    return { room, width: (t) => ctx.measureText(t).width };
}

export function fitTexts(elems, texts, how = mode()) {
    if (!elems.length)
        return [];
    // Every read before any write, so the layout is worked out once
    const { room, width } = measurer(elems[0]);
    return elems.map((elem, i) => {
        const s = censor.text(String(texts[i] ?? ''));
        full.set(elem, s);
        // Not laid out yet, or no room at all: leave it whole
        if (!(room > 0) || width(s) <= room) {
            elem.textContent = s;
            return false;
        }
        const short = shorten(s, (t) => width(t) <= room, how);
        elem.textContent = short;
        return short !== s;
    });
}

export function fitText(elem, text, how = mode()) {
    return fitTexts([elem], [text], how)[0];
}

export function fullText(elem) {
    return full.has(elem) ? full.get(elem) : null;
}
