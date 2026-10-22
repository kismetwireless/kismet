// The map tab, and its section in Settings: whether to load the map
// background from a tile server, and which server.

export function register(kismet) {
    const { ui, settings, dom } = kismet;
    const { el } = dom;
    const map = kismet.widgets.map;

    ui.panes.add({
        id: 'map', title: 'Map', area: 'main', priority: 40,
        create: (body, area) => map.createMap(body, area),
    });

    ui.settingsPanes.add({
        id: 'map', title: 'Map', priority: 20,
        create(body) {
            // On: always fetch tiles.  Off: never.  Until the user picks one,
            // the map asks the first time it opens.
            const fetchTiles = el('input', { type: 'checkbox', role: 'switch',
                onchange: () => settings.set('map.tiles', fetchTiles.checked ? 'allow' : 'deny') });
            const policyNote = el('span', { class: 'muted' });
            const askAgain = el('button', { class: 'link-button', onclick: () => settings.set('map.tiles', 'ask') },
                'Ask me when the map opens instead');
            const policy = el('div', { class: 'map-tile-policy' },
                el('label', { class: 'choice-item' }, fetchTiles, 'Fetch map tiles from a remote server'),
                el('p', {}, policyNote, ' ', askAgain));

            function showPolicy(v = map.tilePolicy()) {
                fetchTiles.checked = v === 'allow';
                policyNote.textContent = v === 'ask' ?
                    'Not chosen yet: the map asks before fetching any tiles.' :
                    v === 'allow' ? 'The map loads its background from the tile server below.' :
                        'The map is drawn on a blank background.';
                askAgain.hidden = v === 'ask';
            }
            showPolicy();

            const urlNote = el('p', { class: 'muted' });
            const url = el('input', { type: 'url', class: 'wide', placeholder: map.defaultTileUrl,
                value: settings.get('map.tileUrl', '') || '',
                onchange: () => {
                    settings.set('map.tileUrl', url.value.trim());
                    checkUrl();
                } });
            const attribution = el('input', { type: 'text', class: 'wide', placeholder: 'Map data © ...',
                value: settings.get('map.tileAttribution', '') || '',
                onchange: () => settings.set('map.tileAttribution', attribution.value.trim()) });

            function checkUrl() {
                const typed = url.value.trim();
                if (typed && !map.tileSource().custom)
                    urlNote.textContent = 'Not a usable tile address: it needs to start with http:// or https:// and contain {z}, {x}, and {y}.  Using OpenStreetMap.';
                else
                    urlNote.textContent = typed ? 'Using this server.' : 'Leave empty for OpenStreetMap.';
            }
            checkUrl();

            const dark = el('input', { type: 'checkbox', checked: settings.get('map.darkTiles', true) !== false,
                onchange: () => settings.set('map.darkTiles', dark.checked) });

            body.append(
                el('h4', {}, 'Map background'),
                el('p', { class: 'muted' }, 'The map background is loaded from a map tile server on the internet.  ' +
                    'Every tile the browser fetches tells that server which part of the world you are looking at, ' +
                    'which can reveal where you are.'),
                policy,
                el('h4', {}, 'Tile server'),
                el('label', { class: 'field' }, 'Tile address', url),
                urlNote,
                el('label', { class: 'field' }, 'Attribution', attribution),
                el('p', { class: 'muted' }, 'A local or self-hosted tile server keeps map lookups off the internet.  ' +
                    'The attribution is shown in the corner of the map, as the server\'s terms ask.'),
                el('label', { class: 'choice-item' }, dark, 'Darken the map in dark mode'));

            return settings.watch('map.tiles', (v) => showPolicy(v ?? 'ask'));
        },
    });
}
