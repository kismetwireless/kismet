// Censor mode: hides MAC addresses, the names and other identifiers of
// devices and networks, and locations, for screenshots, streams and demos.
//
// The options come from Settings, or from the page address, which wins and
// lasts only for that page:
//
//   ?censor=1           MAC addresses, names and locations, partly hidden
//   ?censor_heavy=1     all of them, completely hidden
//   ?censor_macs=1  ?censor_names=1  ?censor_location=1
//   ?censor_more=1      hide completely instead of partly
//
// Partly: a MAC address keeps its manufacturer's half, a name its first and
// last two characters, a position its whole degrees.  Hiding locations also
// hides the map.  Changing the options reloads the page, so nothing shown
// before stays on it.
//
// The data the UI works with is left alone, so lookups and links keep
// working; what's censored is what the page shows.  learn(json) is given
// everything read from the server and keeps the strings that name or identify
// something.  A watcher then rewrites the page's text and tooltips: MAC
// addresses and coordinates by their pattern, and the learned names wherever
// they appear, in tables, messages or alerts.  Text drawn on a canvas goes
// through text().

import * as settings from './settings.js';

const off = new Set(['0', 'false', 'no', 'off']);
const params = new URLSearchParams(location.search);
const param = (name) => params.has(name) && !off.has((params.get(name) ?? '').toLowerCase());

function fromUrl() {
    if (param('censor_heavy'))
        return { macs: true, names: true, locations: true, full: true };
    const o = { macs: false, names: false, locations: false, full: param('censor_more') };
    if (param('censor'))
        o.macs = o.names = o.locations = true;
    // The old UI's censor_macs hid names too
    if (param('censor_macs'))
        o.macs = o.names = true;
    if (param('censor_names'))
        o.names = true;
    if (param('censor_location'))
        o.locations = true;
    return o.macs || o.names || o.locations ? o : null;
}

const urlOptions = fromUrl();
const saved = settings.get('censor', {}) ?? {};
const options = Object.freeze(urlOptions ?? {
    macs: !!saved.macs, names: !!saved.names, locations: !!saved.locations, full: !!saved.full,
});

export const active = options.macs || options.names || options.locations;

// The options in effect, and whether the page address set them
export function current() {
    return { ...options, fromUrl: !!urlOptions };
}

export function hidesMaps() {
    return options.locations;
}

// Save new options and reload the page with them, dropping the address's
export function apply(next) {
    settings.set('censor', { macs: !!next.macs, names: !!next.names, locations: !!next.locations, full: !!next.full });
    const url = new URL(location.href);
    for (const p of ['censor', 'censor_heavy', 'censor_macs', 'censor_names', 'censor_location', 'censor_more'])
        url.searchParams.delete(p);
    location.replace(url.href);
}

// Fields that name or identify a device, a network or a person: by the end
// of the field's name, less the ones that name a kind of thing
const identField = /(?:^|[._])(?:name|commonname|username|longname|shortname|ssid|callsign|hostname|dhcp_host|identity|serial|serial_number|serialnumber|nodeid|owner|imei|imsi|cellid|address|gateway|ipv4|url|notes)$/;
const notIdent = /^kismet\.(?:system|datasource|gps|alert|devicerules|plugin|logfile|stream|httpd|phy|range|eventbus|messagebus)\.|(?:phyname|company_name|uuid_name|appearance_name|vendor_name|state_name|type_name|default_name|phy_name|dirname|model_name|ssidalert\.name)$/;
const alsoIdent = new Set(['kismet.datasource.cell.modem_imei']);

const macPattern = /\b([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\2[0-9A-Fa-f]{2}\b/g;
const macOnly = /^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$/;
// A device key is the phy's hash and the device's address in hex
const keyPattern = /\b([0-9A-F]{16})_[0-9A-F]+\b/g;
// Coordinates are shown to 5 or 6 places
const coordPattern = /(-?\d{1,3})\.\d{4,}/g;

// Names found anywhere in a text: a trie of the learned ones, matched
// longest first.  Short ones only when they're the whole text.
const minInside = 3;
const exact = new Set();
const trie = new Map();

function remember(s) {
    if (exact.has(s))
        return;
    exact.add(s);
    if (s.length < minInside)
        return;
    let node = trie;
    for (const ch of s) {
        if (!node.has(ch))
            node.set(ch, new Map());
        node = node.get(ch);
    }
    node.set('', true);
}

function learnValue(key, v) {
    if (typeof v === 'number')
        v = String(v);
    if (typeof v !== 'string')
        return;
    v = v.trim();
    // MAC addresses are caught by their pattern; a bare number only once it's
    // long enough not to be any other count on the page
    if (!v || macOnly.test(v) || (/^\d+$/.test(v) && v.length < 4))
        return;
    if (alsoIdent.has(key) || (identField.test(key) && !notIdent.test(key)))
        remember(v);
}

export function learn(json) {
    if (!options.names || json === null || typeof json !== 'object')
        return json;
    const stack = [json];
    while (stack.length) {
        const o = stack.pop();
        for (const [k, v] of Object.entries(o)) {
            if (v !== null && typeof v === 'object')
                stack.push(v);
            else
                learnValue(k, v);
        }
    }
    return json;
}

function mask(s) {
    const chars = Array.from(s);
    if (options.full || chars.length < 6)
        return 'X'.repeat(chars.length);
    return chars.slice(0, 2).join('') + 'X'.repeat(chars.length - 4) + chars.slice(-2).join('');
}

function maskNames(s) {
    if (exact.has(s.trim()))
        return s.replace(s.trim(), mask(s.trim()));
    let out = '';
    let i = 0;
    let changed = false;
    while (i < s.length) {
        let node = trie;
        let end = -1;
        for (let j = i; j < s.length; j++) {
            node = node.get(s[j]);
            if (!node)
                break;
            if (node.has(''))
                end = j + 1;
        }
        if (end > 0) {
            out += mask(s.slice(i, end));
            i = end;
            changed = true;
        } else {
            out += s[i++];
        }
    }
    return changed ? out : s;
}

// Censor a piece of text
export function text(s) {
    if (!active || typeof s !== 'string' || !s)
        return s;
    let out = s;
    if (options.macs)
        out = out.replace(macPattern, (m, a, sep, b, c) =>
            options.full ? ['XX', 'XX', 'XX', 'XX', 'XX', 'XX'].join(sep) : [a, b, c, 'XX', 'XX', 'XX'].join(sep))
            .replace(keyPattern, (m, phy) => `${phy}_XXXXXXXX`);
    if (options.locations)
        out = out.replace(coordPattern, (m, deg) => options.full ? 'XX.XXXXX' : `${deg}.XXXXX`);
    if (options.names && exact.size)
        out = maskNames(out);
    return out;
}

const attrs = ['title', 'aria-label', 'placeholder'];

function skip(el) {
    return !el || el.closest?.('[data-nocensor], script, style, .tab-bar');
}

function scrubText(node) {
    if (skip(node.parentElement))
        return;
    const v = text(node.data);
    if (v !== node.data)
        node.data = v;
}

function scrubAttrs(el) {
    if (skip(el))
        return;
    for (const a of attrs) {
        const v = el.getAttribute(a);
        if (v) {
            const c = text(v);
            if (c !== v)
                el.setAttribute(a, c);
        }
    }
}

function scrub(root) {
    if (root.nodeType === Node.TEXT_NODE) {
        scrubText(root);
        return;
    }
    if (root.nodeType !== Node.ELEMENT_NODE)
        return;
    scrubAttrs(root);
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
        if (n.nodeType === Node.TEXT_NODE)
            scrubText(n);
        else
            scrubAttrs(n);
    }
}

// Start censoring the page; the page's own UI text can opt out with data-nocensor
export function watch() {
    if (!active)
        return;
    document.documentElement.classList.add('censored');
    scrub(document.body);
    new MutationObserver((records) => {
        for (const r of records) {
            if (r.type === 'childList')
                r.addedNodes.forEach(scrub);
            else if (r.type === 'characterData')
                scrubText(r.target);
            else
                scrubAttrs(r.target);
        }
    }).observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: attrs });
}
