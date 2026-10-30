// Device tags: the server tags devices by its device rules.  Each tag gets a
// row highlight (Settings > Appearance > Device Highlights), in the color its
// rule sets, or a color the user picks instead.  The device panel lists a
// device's tags first, with the rules that set them; the (i) on a tag shows
// those rules in full.

import { onLogin } from '../core/auth.js';
import { fallbackColor } from './highlights.js';

const rules = 'kismet.device.base.rules';
const tagsPath = `${rules}/kismet.device.rules.tags`;
const tagsField = [tagsPath, 'rule_tags'];

// Colors for tags whose rule doesn't set one
const defaults = {
    'watchlist': '#ff6b6b',
    'handshake': '#ff0000',
    'pmkid': '#ff5555',
    'ais emergency': '#ff6666',
    'zigbee key': '#ff6666',
    'government': '#ffb3b3',
    'bodycam': '#0089ff',
    'open': '#ffa94d',
    'free wifi': '#ffd43b',
    'close': '#69db7c',
    'uav': '#f49e42',
    'quiet': '#adb5bd',
    'active': '#cee1ff',
};

const colorRe = /^#[0-9a-fA-F]{6}$/;
const highlightId = (tag) => `tag_${tag}`;

export function register(kismet) {
    const { ui, dom, settings, api, icons } = kismet;
    const { el } = dom;
    const { dialog } = kismet.widgets.dialog;

    let shown = new Set();
    // Rule name -> { name, description, source, origin, tags }
    let ruleInfo = new Map();
    // [tag, rule color] in rule order
    let tagList = [];
    let lastAdded = null;

    // The tags the server's rules set, in rule order, each with the color of
    // the first rule that sets both
    async function loadTags() {
        let list;
        try {
            list = (await api.get('devices/rules/rules.json'))?.['kismet.devicerules.rules'] ?? [];
        } catch (err) {
            console.error('Could not load the device rules:', err);
            return;
        }
        const tags = new Map();
        const info = new Map();
        for (const r of list) {
            const name = r['kismet.devicerules.rule.name'];
            if (typeof name === 'string')
                info.set(name, { name, description: r['kismet.devicerules.rule.description'] ?? '',
                    source: r['kismet.devicerules.rule.source'] ?? '', origin: r['kismet.devicerules.rule.origin'] ?? '',
                    tags: (r['kismet.devicerules.rule.tags'] ?? []).filter((t) => typeof t === 'string') });
            const color = r['kismet.devicerules.rule.color'];
            for (const t of r['kismet.devicerules.rule.tags'] ?? []) {
                if (typeof t !== 'string' || t === '')
                    continue;
                if (!tags.has(t) || (!tags.get(t) && colorRe.test(color ?? '')))
                    tags.set(t, colorRe.test(color ?? '') ? color.toLowerCase() : null);
            }
        }

        ruleInfo = info;
        tagList = [...tags];
        addHighlights();
    }

    // A highlight for each tag, in the order the user dragged them into
    // (Settings > Appearance > Device Highlights), then the rest in rule order
    function addHighlights() {
        const order = settings.get('ruletags.order', []);
        const rank = (tag) => {
            const i = Array.isArray(order) ? order.indexOf(tag) : -1;
            return i < 0 ? Infinity : i;
        };
        const sorted = tagList.map((t, i) => ({ t, i })).sort((a, b) => rank(a.t[0]) - rank(b.t[0]) || a.i - b.i).map((x) => x.t);
        // Re-adding redraws everything showing the highlights; only do it for a change
        const signature = JSON.stringify([sorted, [...ruleInfo.values()].map((rd) => [rd.tags, rd.description])]);
        if (signature === lastAdded)
            return;
        lastAdded = signature;

        const now = new Set();
        sorted.forEach(([tag, color], i) => {
            now.add(highlightId(tag));
            const described = [...new Set(rulesFor(tag).map((rd) => rd.description).filter(Boolean))];
            ui.rowHighlights.add({
                id: highlightId(tag), name: tag, tag, category: 'tag', priority: -1 + i / 1000, defaultEnabled: true,
                description: described.join('; '),
                defaultColor: color ?? defaults[tag] ?? fallbackColor(tag),
                fields: [tagsField],
                match: (row) => Array.isArray(row.rule_tags) && row.rule_tags.includes(tag),
                showRule: () => showRules(tag, rulesFor(tag)),
            });
        });
        for (const id of shown)
            if (!now.has(id))
                ui.rowHighlights.remove(id);
        shown = now;
    }

    loadTags();
    onLogin(loadTags);
    settings.watch('ruletags.order', addHighlights);
    // Rules can change over the API
    setInterval(loadTags, 60000);

    // The rules that set a tag; only those in `names` (a device's matched rules) when given
    function rulesFor(tag, names = null) {
        return [...ruleInfo.values()].filter((rd) => rd.tags.includes(tag) && (!names || names.includes(rd.name)));
    }

    // The full text of the rules behind a tag
    function showRules(tag, list) {
        dialog({
            title: `Tag: ${tag}`, className: 'rule-text-dialog',
            body: el('div', { class: 'rule-text' }, list.length ? list.map((rd) => el('section', {},
                el('h4', {}, rd.name, rd.origin ? el('span', { class: 'muted' }, ` ${rd.origin}`) : null),
                rd.description ? el('p', {}, rd.description) : null,
                el('pre', { class: 'mono' }, rd.source))) :
                el('p', { class: 'muted' }, 'The rules for this tag haven\'t loaded, or have changed since.')),
        });
    }

    // A tag's row color, as the user has it, for its badge
    function colorOf(tag) {
        const h = ui.rowHighlights.get(highlightId(tag));
        if (!h)
            return null;
        return settings.get('devicelist.highlights', {})?.[h.id]?.color ?? h.defaultColor;
    }

    function badge(tag) {
        const color = colorOf(tag);
        const b = el('span', { class: ['rule-tag', color && 'colored'] }, tag);
        if (color)
            b.style.setProperty('--tag', color);
        return b;
    }

    const badges = (tags) => (Array.isArray(tags) && tags.length ?
        el('span', { class: 'rule-tags' }, tags.map(badge)) : '');

    ui.deviceColumns.add({
        id: 'rule_tags', title: 'Tags', priority: 900, width: '12em', defaultVisible: true,
        description: 'Tags from the server device rules',
        fields: [tagsField],
        sortField: tagsPath,
        render: (row) => badges(row.rule_tags),
    });

    ui.searchFields.add({ id: 'rule_tags', description: 'Device rule tags', fields: [tagsField] });

    // A device's tags, each with the rules that set it, then any matched rules without a tag
    function deviceTags(dev) {
        const tags = dev[rules]?.['kismet.device.rules.tags'] ?? [];
        const matched = dev[rules]?.['kismet.device.rules.matched'] ?? [];
        const ruleLine = (rd) => el('li', {}, el('span', { class: 'mono' }, rd.name),
            rd.description ? ` - ${rd.description}` : '');
        const out = tags.map((tag) => {
            const list = rulesFor(tag, matched);
            return el('div', { class: 'device-tag' },
                el('div', { class: 'device-tag-head' }, badge(tag),
                    el('button', { type: 'button', class: 'icon-button rule-info', title: 'Show the rule',
                        'aria-label': `Show the rule for ${tag}`, onclick: () => showRules(tag, list) }, icons.icon('info'))),
                list.length ? el('ul', { class: 'device-tag-rules' }, list.map(ruleLine)) : null);
        });
        const untagged = matched.map((n) => ruleInfo.get(n)).filter((rd) => rd && !rd.tags.some((t) => tags.includes(t)));
        if (untagged.length)
            out.push(el('div', { class: 'device-tag' }, el('div', { class: 'muted' }, 'Other matching rules'),
                el('ul', { class: 'device-tag-rules' }, untagged.map(ruleLine))));
        return el('div', { class: 'device-tags' }, out);
    }

    ui.deviceDetails.add({
        id: 'device_rules', title: 'Tags', priority: -10,
        match: (dev) => (dev[rules]?.['kismet.device.rules.matched']?.length ?? 0) > 0 ||
            (dev[rules]?.['kismet.device.rules.tags']?.length ?? 0) > 0,
        fields: [
            { id: 'tags', wide: true, value: (dev) => dev, format: (dev) => deviceTags(dev),
                help: 'Tags from the server device rules this device matches; their colors are set in ' +
                    'Settings > Appearance > Device Highlights' },
        ],
    });
}
