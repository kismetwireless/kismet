// Device rule tags: the server tags devices by its device rules, and the UI
// picks the colors.  A device with several tags takes the color of the first
// one in the user's list.

const rules = 'kismet.device.base.rules';
const tagsField = [`${rules}/kismet.device.rules.tags`, 'rule_tags'];

const defaults = [
    { tag: 'watchlist', color: '#ff6b6b' },
    { tag: 'handshake', color: '#ff0000' },
    { tag: 'pmkid', color: '#ff5555' },
    { tag: 'ais emergency', color: '#ff6666' },
    { tag: 'zigbee key', color: '#ff6666' },
    { tag: 'government', color: '#ffb3b3' },
    { tag: 'bodycam', color: '#0089ff' },
    { tag: 'open', color: '#ffa94d' },
    { tag: 'free wifi', color: '#ffd43b' },
    { tag: 'close', color: '#69db7c' },
    { tag: 'uav', color: '#f49e42' },
    { tag: 'quiet', color: '#adb5bd' },
    { tag: 'active', color: '#cee1ff' },
];

const colorRe = /^#[0-9a-fA-F]{6}$/;

export function register(kismet) {
    const { ui, dom, settings } = kismet;
    const { el } = dom;

    function load() {
        const stored = settings.get('ruletags.colors', null);
        if (!Array.isArray(stored))
            return defaults.slice();
        return stored.filter((e) => typeof e?.tag === 'string' && e.tag !== '' &&
            typeof e?.color === 'string' && colorRe.test(e.color));
    }

    let colors = load();

    function colorFor(tags) {
        if (!Array.isArray(tags))
            return null;
        return colors.find((e) => tags.includes(e.tag))?.color ?? null;
    }

    function badge(tag) {
        const color = colors.find((e) => e.tag === tag)?.color;
        const b = el('span', { class: ['rule-tag', color && 'colored'] }, tag);
        if (color)
            b.style.setProperty('--tag', color);
        return b;
    }

    const badges = (tags) => (Array.isArray(tags) && tags.length ?
        el('span', { class: 'rule-tags' }, tags.map(badge)) : '');

    const highlight = {
        id: 'rule_tags', name: 'Rule tags', priority: 0, defaultEnabled: true,
        description: 'Devices with a server device rule tag, in the color set for the tag in Settings > Rule tags',
        fields: [tagsField],
        match: (row) => colorFor(row.rule_tags) !== null,
        color: (row) => colorFor(row.rule_tags),
    };

    ui.rowHighlights.add(highlight);

    ui.deviceColumns.add({
        id: 'rule_tags', title: 'Rule tags', priority: 900, width: '12em', defaultVisible: true,
        description: 'Tags from the server device rules',
        fields: [tagsField],
        render: (row) => badges(row.rule_tags),
    });

    ui.deviceDetails.add({
        id: 'device_rules', title: 'Device rules', priority: 50,
        match: (dev) => (dev[rules]?.['kismet.device.rules.matched']?.length ?? 0) > 0,
        fields: [
            { title: 'Matched rules', field: `${rules}/kismet.device.rules.matched`,
                help: 'Server device rules this device matches',
                format: (v) => v.join(', ') },
            { title: 'Tags', field: `${rules}/kismet.device.rules.tags`,
                help: 'Tags from the matching rules; their colors are set in Settings > Rule tags',
                show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => badges(v) },
        ],
    });

    function save(list) {
        settings.set('ruletags.colors', list);
        colors = load();
        // Re-adding the highlight redraws the tables showing it
        ui.rowHighlights.add(highlight);
    }

    ui.settingsPanes.add({
        id: 'ruletags', title: 'Rule tags', priority: 40,
        create(body) {
            const list = el('div', { class: 'ruletag-list' });

            function current() {
                return [...list.querySelectorAll('.ruletag-row')]
                    .map((r) => ({ tag: r.querySelector('.ruletag-name').value.trim(), color: r.querySelector('input[type=color]').value }))
                    .filter((e) => e.tag !== '');
            }

            function row(e) {
                const r = el('div', { class: 'ruletag-row' },
                    el('input', { class: 'ruletag-name', value: e.tag, placeholder: 'tag', 'aria-label': 'Tag',
                        onchange: () => save(current()) }),
                    el('input', { type: 'color', value: e.color, title: 'Row color',
                        oninput: () => save(current()) }),
                    el('button', { type: 'button', title: 'Move up', onclick: () => {
                        if (r.previousElementSibling) {
                            list.insertBefore(r, r.previousElementSibling);
                            save(current());
                        }
                    } }, '↑'),
                    el('button', { type: 'button', onclick: () => { r.remove(); save(current()); } }, 'Remove'));
                return r;
            }

            function fill() {
                list.replaceChildren(...colors.map(row));
            }

            fill();
            body.append(
                el('p', { class: 'muted' }, 'Server device rules can tag devices.  Pick a row color for each tag; ' +
                    'a device with several tags takes the color of the first one in this list.'),
                list,
                el('div', { class: 'form-buttons' },
                    el('button', { type: 'button', onclick: () => {
                        const r = row({ tag: '', color: '#74c0fc' });
                        list.append(r);
                        r.querySelector('.ruletag-name').focus();
                    } }, 'Add tag'),
                    el('button', { type: 'button', onclick: () => { save(defaults.slice()); fill(); } }, 'Defaults')));
        },
    });
}
