// The server's device rules and sorts, grouped by what defined them: rules
// files, config lines, plugins and the API.
//
//   openRules()

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import { dialog } from './dialog.js';

let openWindow = null;

const kinds = {
    file: 'Rules file',
    config: 'Config file',
    plugin: 'Plugin',
    api: 'Set over the API',
};

function groupTitle(g) {
    const type = g['kismet.devicerules.source.type'];
    const name = g['kismet.devicerules.source.name'];
    if (type === 'api')
        return el('h3', {}, kinds.api);
    return el('h3', {}, `${kinds[type] ?? type}: `, el('span', { class: type === 'plugin' ? null : 'mono' }, name));
}

function ruleEntry(r) {
    const tags = r['kismet.devicerules.rule.tags'] ?? [];
    const flags = [
        r['kismet.devicerules.rule.live'] ? 'live' : null,
        r['kismet.devicerules.rule.alert'] ? 'alert' : null,
        r['kismet.devicerules.rule.view'] ? `view ${r['kismet.devicerules.rule.view']}` : null,
    ].filter(Boolean);
    const color = r['kismet.devicerules.rule.color'];
    const swatch = color ? el('span', { class: 'dr-color' }) : null;
    if (swatch)
        swatch.style.setProperty('--tag', color);
    return el('details', { class: 'dr-entry' },
        el('summary', {}, swatch, r['kismet.devicerules.rule.name'],
            tags.length ? el('span', { class: 'rule-tags' }, tags.map((t) => el('span', { class: 'rule-tag' }, t))) : null,
            flags.length ? el('span', { class: 'muted' }, ` ${flags.join(', ')}`) : null),
        r['kismet.devicerules.rule.description'] ? el('p', {}, r['kismet.devicerules.rule.description']) : null,
        r['kismet.devicerules.rule.origin'] ? el('p', { class: 'muted mono' }, r['kismet.devicerules.rule.origin']) : null,
        el('pre', { class: 'mono' }, r['kismet.devicerules.rule.source']));
}

function sortEntry(s) {
    return el('details', { class: 'dr-entry' },
        el('summary', {}, s['kismet.devicerules.sort.name']),
        s['kismet.devicerules.sort.origin'] ? el('p', { class: 'muted mono' }, s['kismet.devicerules.sort.origin']) : null,
        el('pre', { class: 'mono' }, s['kismet.devicerules.sort.source']));
}

const plural = (n, what) => `${n} ${what}${n === 1 ? '' : 's'}`;
const counts = (rules, sorts) => [rules && plural(rules, 'rule'), sorts && plural(sorts, 'sort')].filter(Boolean).join(', ');

function groupSection(g) {
    const rules = g['kismet.devicerules.source.rules'] ?? [];
    const sorts = g['kismet.devicerules.source.sorts'] ?? [];
    const files = g['kismet.devicerules.source.files'] ?? [];
    const replaced = g['kismet.devicerules.source.replaced'] ?? [];
    const name = g['kismet.devicerules.source.name'];
    // A plugin's or config file's rules can come from more than one file
    const shownFiles = files.filter((f) => f !== name);
    const count = counts(rules.length, sorts.length);
    return el('section', {},
        el('div', { class: 'dr-head' }, groupTitle(g), el('span', { class: 'muted' }, count)),
        shownFiles.length ? el('p', { class: 'muted' }, 'From ', el('span', { class: 'mono' }, shownFiles.join(', '))) : null,
        rules.length ? el('div', { class: 'dr-list' }, rules.map(ruleEntry)) : null,
        sorts.length ? el('h4', {}, 'Sorts') : null,
        sorts.length ? el('div', { class: 'dr-list' }, sorts.map(sortEntry)) : null,
        replaced.map((x) => el('p', { class: 'muted dr-replaced' }, x)));
}

export function openRules() {
    if (openWindow?.node.isConnected) {
        openWindow.raise();
        return openWindow;
    }

    const status = el('span', { class: 'muted' }, 'Loading...');
    const list = el('div', { class: 'dr-groups' });
    const body = el('div', { class: 'dr-window' },
        el('div', { class: 'pk-bar' }, status,
            el('button', { type: 'button', class: 'link-button', onclick: () => read() }, 'Reload')),
        list);

    const w = Math.min(760, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 860);
    openWindow = dialog({
        title: 'Device rules', body, modal: false, className: 'dr-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => { openWindow = null; },
    });

    async function read() {
        status.textContent = 'Loading...';
        try {
            const groups = (await api.get('devices/rules/sources.json'))?.['kismet.devicerules.sources'] ?? [];
            list.replaceChildren(...groups.map(groupSection));
            const total = (f) => groups.reduce((n, g) => n + (g[f]?.length ?? 0), 0);
            status.textContent = groups.length ?
                `${counts(total('kismet.devicerules.source.rules'), total('kismet.devicerules.source.sorts'))} from ${plural(groups.length, 'source')}` :
                'The server has no device rules';
        } catch (err) {
            status.textContent = '';
            list.replaceChildren(el('p', { class: 'form-error' }, err.message));
        }
    }

    read();
    return openWindow;
}
