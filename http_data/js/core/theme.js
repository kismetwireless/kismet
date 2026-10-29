// Color schemes, light/dark mode, and accent palettes.
//
// The look of the page comes entirely from CSS variables.  The default
// scheme, Kismet, is css/themes.css, picked by attributes on <html>:
// data-theme (light or dark) and data-palette (its accent color).  Other
// schemes are entries in kismet.ui.colorSchemes (the built-in ones are in
// js/base/schemes.js; plugins can add more), and their colors are set as
// variables on <html> over the Kismet ones.  Changes restyle the page at once.

import * as settings from './settings.js';
import { colorSchemes } from '../registry/ui.js';

export const modes = ['auto', 'light', 'dark'];

// Palette ids match the [data-palette] blocks in css/themes.css
export const palettes = [
    { id: 'kismet', title: 'Kismet' },
    { id: 'ocean', title: 'Ocean' },
    { id: 'forest', title: 'Forest' },
    { id: 'amber', title: 'Amber' },
    { id: 'grape', title: 'Grape' },
];

// The default scheme, from css/themes.css
const kismetScheme = { id: 'kismet', title: 'Kismet', variants: ['light', 'dark'],
    preview: ['#141a22', '#1c232c', '#4b9fe8', '#dde3ea'] };

// Every scheme, the default first: { id, title, variants, preview, colors }
// variants are the versions a scheme has; one with a single version always
// uses it, whatever the mode says.  preview is [background, panel, accent,
// text] for the picker.
export function schemes() {
    return [kismetScheme, ...colorSchemes.list().map((s) => {
        const variants = ['light', 'dark'].filter((v) => s[v]);
        const c = s.dark ?? s.light ?? {};
        return { id: s.id, title: s.title, variants, colors: s,
            preview: [c.bg, c.surface ?? c.bg, c.accent, c.text] };
    }).filter((s) => s.variants.length)];
}

const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
const listeners = new Set();

export function mode() {
    return settings.get('theme.mode', 'auto');
}

export function palette() {
    return settings.get('theme.palette', 'kismet');
}

// The chosen scheme.  One from a plugin that hasn't loaded yet shows as
// Kismet until it does; the choice itself is kept.
export function scheme() {
    const id = settings.get('theme.scheme', 'kismet');
    const all = schemes();
    return all.find((s) => s.id === id) ?? all[0];
}

// The version actually showing: 'light' or 'dark'
export function current() {
    const variants = scheme().variants;
    if (variants.length === 1)
        return variants[0];
    const m = mode();
    if (m === 'auto')
        return darkQuery.matches ? 'dark' : 'light';
    return m;
}

export function setMode(m) {
    if (modes.includes(m))
        settings.set('theme.mode', m);
}

export function setPalette(p) {
    if (palettes.some((x) => x.id === p))
        settings.set('theme.palette', p);
}

export function setScheme(id) {
    if (schemes().some((x) => x.id === id))
        settings.set('theme.scheme', id);
}

// Read a theme color, e.g. themeColor('--accent'), for drawing graphs
export function themeColor(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Call fn() after the theme changes, e.g. to redraw a graph
export function onChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
}

// The variables a scheme can set, and how each is checked: a scheme comes
// from module code, but its values still only ever become colors (no
// url(), no other properties)
const colorVars = ['bg', 'surface', 'surface-2', 'border', 'text', 'muted', 'accent', 'accent-text',
    'ok', 'warn', 'error', 'accent-soft', 'row-alt', 'row-hover'];
const checks = {
    shadow: (v) => !/url\(|image|var\(/i.test(v) && CSS.supports('box-shadow', v),
    'highlight-mix': (v) => /^\d{1,3}(\.\d+)?%$/.test(v),
};
for (const name of colorVars)
    checks[name] = (v) => !/url\(|var\(/i.test(v) && CSS.supports('color', v);

// Worked out from the scheme's own colors when it doesn't give them
const derived = {
    'accent-soft': 'color-mix(in srgb, var(--accent) 22%, var(--surface))',
    'row-alt': 'color-mix(in srgb, var(--text) 3%, var(--surface))',
    'row-hover': 'color-mix(in srgb, var(--accent) 12%, var(--surface))',
};

let applied = [];

function apply() {
    const root = document.documentElement;
    const sc = scheme();
    const variant = current();

    for (const name of applied)
        root.style.removeProperty(`--${name}`);
    applied = [];
    root.style.colorScheme = '';

    const colors = sc.colors?.[variant];
    if (colors) {
        const set = (name, value) => {
            root.style.setProperty(`--${name}`, value);
            applied.push(name);
        };
        for (const [name, value] of Object.entries(colors)) {
            if (checks[name] && typeof value === 'string' && checks[name](value))
                set(name, value);
            else
                console.warn(`color scheme ${sc.id}: ignoring ${name}: ${value}`);
        }
        for (const [name, value] of Object.entries(derived))
            if (!applied.includes(name))
                set(name, value);
        root.style.colorScheme = variant;
    }

    root.dataset.scheme = sc.id;
    root.dataset.theme = variant;
    root.dataset.palette = palette();
    for (const fn of listeners)
        fn();
}

settings.watch('theme.mode', apply);
settings.watch('theme.palette', apply);
settings.watch('theme.scheme', apply);
// A plugin's scheme may be the chosen one, and arrive after the page starts
colorSchemes.watch(apply);
darkQuery.addEventListener('change', apply);
apply();
