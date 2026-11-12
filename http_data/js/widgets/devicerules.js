// The server's device rules and sorts, grouped by what defined them: rules
// files, config lines, plugins and the API.  Rules that tag devices or collect
// them in a view are marked, and can be listed on their own.  Each rule has a
// switch: a rule that's off isn't checked, and the server remembers the choice.
// Each rule that's on shows how many devices match it, kept current while the
// window is open.
//
//   openRules()

import { el } from '../core/dom.js';
import { icon } from '../core/icons.js';
import * as api from '../core/api.js';
import * as settings from '../core/settings.js';
import { dialog } from './dialog.js';
import { showPane } from './panes.js';
import { refreshAll } from './devicetable.js';

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

const tagsOf = (r) => r['kismet.devicerules.rule.tags'] ?? [];
const viewOf = (r) => r['kismet.devicerules.rule.view'] || null;
// Servers without the switch don't say, and all of their rules are on
const enabledOf = (r) => r['kismet.devicerules.rule.enabled'] !== 0;
// Older servers don't count matches
const matchingOf = (r) => r['kismet.devicerules.rule.matching'];
const matchText = (n) => `${n.toLocaleString()} ${n === 1 ? 'device' : 'devices'}`;
const countRefreshMs = 5000;

// Which rules each filter shows
const shows = {
    all: () => true,
    tags: (r) => tagsOf(r).length > 0,
    views: (r) => viewOf(r) !== null,
};

function showView(id) {
    settings.set('devicelist.view', id);
    showPane('devices');
}

function ruleEntry(r, onToggle, countEls) {
    const tags = tagsOf(r);
    const view = viewOf(r);
    const on = enabledOf(r);
    const name = r['kismet.devicerules.rule.name'];
    const toggle = el('input', { type: 'checkbox', class: 'dr-toggle', 'aria-label': `Use the rule ${name}`,
        title: on ? 'Switch this rule off' : 'Switch this rule on',
        // Don't open the entry as well
        onclick: (e) => e.stopPropagation(),
        onchange: () => onToggle(name, toggle.checked, toggle) });
    toggle.checked = on;
    const matching = matchingOf(r);
    const count = on && Number.isFinite(matching) ?
        el('span', { class: 'dr-mark dr-count', title: 'Devices matching this rule now' }, matchText(matching)) : null;
    if (count)
        countEls.set(name, count);
    const flags = [
        r['kismet.devicerules.rule.live'] ? 'live' : null,
        r['kismet.devicerules.rule.alert'] ? 'alert' : null,
    ].filter(Boolean);
    const color = r['kismet.devicerules.rule.color'];
    const swatch = color ? el('span', { class: 'dr-color' }) : null;
    if (swatch)
        swatch.style.setProperty('--tag', color);
    return el('details', { class: on ? 'dr-entry' : 'dr-entry dr-off' },
        el('summary', {}, toggle, swatch, name, count,
            on ? null : el('span', { class: 'dr-mark' }, 'Off'),
            tags.length ? el('span', { class: 'dr-mark', title: 'Tags the devices it matches' }, tags.length === 1 ? 'Tag' : 'Tags',
                el('span', { class: 'rule-tags' }, tags.map((t) => el('span', { class: 'rule-tag' }, t)))) : null,
            view ? el('span', { class: 'dr-mark', title: 'Collects the devices it matches in a view' }, 'View',
                el('button', { type: 'button', class: 'dr-view', title: 'Show this view in the device list', disabled: !on,
                    onclick: (e) => {
                        e.preventDefault();
                        showView(view);
                    } }, el('span', { class: 'mono' }, view), icon('right'))) : null,
            r['kismet.devicerules.rule.exclude'] ? el('span', { class: 'dr-mark',
                title: 'Leaves the devices it matches out of the Default device view' }, 'Excludes') : null,
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

// How many of the rules tag devices and make views
function marks(rules) {
    const tags = rules.filter(shows.tags).length;
    const views = rules.filter(shows.views).length;
    const off = rules.filter((r) => !enabledOf(r)).length;
    return [tags && `${tags} tagging`, views && plural(views, 'view'), off && `${off} off`].filter(Boolean).join(', ');
}

function groupSection(g, show, onToggle, countEls) {
    const all = g['kismet.devicerules.source.rules'] ?? [];
    const rules = all.filter(shows[show]);
    // Sorts and replacements are only listed with every rule
    const sorts = show === 'all' ? g['kismet.devicerules.source.sorts'] ?? [] : [];
    if (show !== 'all' && !rules.length)
        return null;
    const files = g['kismet.devicerules.source.files'] ?? [];
    const replaced = g['kismet.devicerules.source.replaced'] ?? [];
    const name = g['kismet.devicerules.source.name'];
    // A plugin's or config file's rules can come from more than one file
    const shownFiles = files.filter((f) => f !== name);
    const count = show === 'all' ? [counts(rules.length, sorts.length), marks(all) && `(${marks(all)})`].filter(Boolean).join(' ') :
        `${rules.length} of ${plural(all.length, 'rule')}`;
    return el('section', {},
        el('div', { class: 'dr-head' }, groupTitle(g), el('span', { class: 'muted' }, count)),
        shownFiles.length ? el('p', { class: 'muted' }, 'From ', el('span', { class: 'mono' }, shownFiles.join(', '))) : null,
        rules.length ? el('div', { class: 'dr-list' }, rules.map((r) => ruleEntry(r, onToggle, countEls))) : null,
        sorts.length ? el('h4', {}, 'Sorts') : null,
        sorts.length ? el('div', { class: 'dr-list' }, sorts.map(sortEntry)) : null,
        show === 'all' ? replaced.map((x) => el('p', { class: 'muted dr-replaced' }, x)) : null);
}

export function openRules() {
    if (openWindow?.node.isConnected) {
        openWindow.raise();
        return openWindow;
    }

    let show = settings.get('devicerules.show', 'all');
    if (!shows[show])
        show = 'all';
    let groups = [];
    // Each listed rule's count, updated in place so open entries and the scroll stay
    const countEls = new Map();
    let refreshing = false;

    const status = el('span', { class: 'muted' }, 'Loading...');
    const list = el('div', { class: 'dr-groups' });
    const showButtons = Object.entries({ all: 'All', tags: 'Tagging', views: 'Views' }).map(([id, title]) =>
        el('button', { type: 'button', 'data-id': id, onclick: () => {
            show = id;
            settings.set('devicerules.show', id);
            render();
        } }, title));
    const body = el('div', { class: 'dr-window' },
        el('div', { class: 'pk-bar' }, el('div', { class: 'graph-tabs', title: 'Which rules to list' }, showButtons), status,
            el('button', { type: 'button', class: 'link-button', onclick: () => read() }, 'Reload')),
        list);

    const w = Math.min(760, window.innerWidth - 32);
    const h = Math.min(Math.round(window.innerHeight * 0.85), 860);
    openWindow = dialog({
        title: 'Device rules', body, modal: false, className: 'dr-panel',
        position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
        onClose: () => {
            openWindow = null;
            clearInterval(timer);
        },
    });

    function render() {
        for (const b of showButtons) {
            b.classList.toggle('active', b.dataset.id === show);
            b.setAttribute('aria-pressed', String(b.dataset.id === show));
        }
        countEls.clear();
        const sections = groups.map((g) => groupSection(g, show, toggleRule, countEls)).filter(Boolean);
        list.replaceChildren(...sections);
        if (!sections.length && groups.length)
            list.append(el('p', { class: 'muted' }, show === 'tags' ? 'No rules tag devices.' : 'No rules make views.'));
        const rules = groups.flatMap((g) => g['kismet.devicerules.source.rules'] ?? []);
        const sorts = groups.reduce((n, g) => n + (g['kismet.devicerules.source.sorts']?.length ?? 0), 0);
        status.textContent = groups.length ?
            `${counts(rules.length, sorts)} from ${plural(groups.length, 'source')}${marks(rules) ? `; ${marks(rules)}` : ''}` :
            'The server has no device rules';
    }

    async function toggleRule(name, enabled, input) {
        input.disabled = true;
        try {
            const r = await api.post('devices/rules/enable.cmd', { rule: name, enabled });
            if (!r?.ok)
                throw new Error(r?.error ?? 'The server did not change the rule');
            await read();
            if (r.saved === false)
                status.textContent = `The server could not save this: ${r.save_error ?? 'unknown error'}`;
            // Tags, row colors and views follow the rules
            document.dispatchEvent(new CustomEvent('kismet-rules-changed'));
            refreshAll();
        } catch (err) {
            input.checked = !enabled;
            input.disabled = false;
            status.textContent = `Could not switch ${name} ${enabled ? 'on' : 'off'}: ${err.message}`;
        }
    }

    async function read() {
        status.textContent = 'Loading...';
        try {
            groups = (await api.get('devices/rules/sources.json'))?.['kismet.devicerules.sources'] ?? [];
            render();
        } catch (err) {
            status.textContent = '';
            list.replaceChildren(el('p', { class: 'form-error' }, err.message));
        }
    }

    // Which rules there are and which are on; counts alone change in place
    const shape = (gs) => JSON.stringify(gs.map((g) => [g['kismet.devicerules.source.name'],
        (g['kismet.devicerules.source.rules'] ?? []).map((r) => [r['kismet.devicerules.rule.name'], enabledOf(r)]),
        (g['kismet.devicerules.source.sorts'] ?? []).length]));

    async function refreshCounts() {
        if (refreshing || document.hidden)
            return;
        refreshing = true;
        try {
            const fresh = (await api.get('devices/rules/sources.json'))?.['kismet.devicerules.sources'] ?? [];
            if (shape(fresh) !== shape(groups)) {
                groups = fresh;
                render();
                return;
            }
            groups = fresh;
            for (const r of fresh.flatMap((g) => g['kismet.devicerules.source.rules'] ?? [])) {
                const span = countEls.get(r['kismet.devicerules.rule.name']);
                const n = matchingOf(r);
                if (span && Number.isFinite(n))
                    span.textContent = matchText(n);
            }
        } catch {
            // Keep the last counts; Reload shows the error
        } finally {
            refreshing = false;
        }
    }

    const timer = setInterval(refreshCounts, countRefreshMs);

    read();
    return openWindow;
}
