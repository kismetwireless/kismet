// Device tags: the server tags devices by its device rules.  Each tag gets a
// row highlight (Settings > Appearance > Device Highlights), in the color its
// rule sets, or a color the user picks instead.

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
    const { ui, dom, settings, api } = kismet;
    const { el } = dom;

    let shown = new Set();

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
        for (const r of list) {
            const color = r['kismet.devicerules.rule.color'];
            for (const t of r['kismet.devicerules.rule.tags'] ?? []) {
                if (typeof t !== 'string' || t === '')
                    continue;
                if (!tags.has(t) || (!tags.get(t) && colorRe.test(color ?? '')))
                    tags.set(t, colorRe.test(color ?? '') ? color.toLowerCase() : null);
            }
        }

        const now = new Set();
        [...tags].forEach(([tag, color], i) => {
            now.add(highlightId(tag));
            ui.rowHighlights.add({
                id: highlightId(tag), name: tag, category: 'tag', priority: -1 + i / 1000, defaultEnabled: true,
                description: color ? 'Color set by its rule' : '',
                defaultColor: color ?? defaults[tag] ?? fallbackColor(tag),
                fields: [tagsField],
                match: (row) => Array.isArray(row.rule_tags) && row.rule_tags.includes(tag),
            });
        });
        for (const id of shown)
            if (!now.has(id))
                ui.rowHighlights.remove(id);
        shown = now;
    }

    loadTags();
    onLogin(loadTags);
    // Rules can change over the API
    setInterval(loadTags, 60000);

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

    ui.deviceDetails.add({
        id: 'device_rules', title: 'Device rules', priority: 50,
        match: (dev) => (dev[rules]?.['kismet.device.rules.matched']?.length ?? 0) > 0,
        fields: [
            { title: 'Matched rules', field: `${rules}/kismet.device.rules.matched`,
                help: 'Server device rules this device matches',
                format: (v) => v.join(', ') },
            { title: 'Tags', field: tagsPath,
                help: 'Tags from the matching rules; their colors are set in Settings > Appearance > Device Highlights',
                show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => badges(v) },
        ],
    });
}
