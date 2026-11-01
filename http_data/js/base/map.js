// The map tab, and its section in Settings: whether to load the map
// background from a tile server, which server, and how long to keep paths.

export function register(kismet) {
    const { ui, settings, dom } = kismet;
    const { el } = dom;
    const map = kismet.widgets.map;

    ui.panes.add({
        id: 'map', title: 'Map', area: 'main', priority: 40,
        create(body, area) {
            // A map shows where its devices are, so censoring locations hides it
            if (kismet.censor.hidesMaps()) {
                body.append(el('p', { class: 'muted map-censored' }, 'The map is hidden while censor mode hides locations.'));
                return null;
            }
            return map.createMap(body, area);
        },
    });

    ui.settingsPanes.add({
        id: 'map', title: 'Map', priority: 20,
        create(body) {
            // On: fetch tiles from the tile server shown now, and ask again if it
            // changes.  Off: never.  Until the user picks one, the map does what
            // the server says (httpd_map_tiles), by default asking when it opens.
            const fetchTiles = el('input', { type: 'checkbox', role: 'switch',
                onchange: () => {
                    if (fetchTiles.checked && map.acceptedTileUrl() !== map.anyTiles)
                        settings.set('map.tilesAccepted', map.tileSource().url);
                    settings.set('map.tiles', fetchTiles.checked ? 'allow' : 'deny');
                } });
            // Off: tiles from any tile server, without asking when it changes
            const askEach = el('input', { type: 'checkbox',
                onchange: () => settings.set('map.tilesAccepted', askEach.checked ? map.tileSource().url : map.anyTiles) });
            const askEachItem = el('label', { class: 'choice-item' }, askEach, 'Ask before using a different tile server');
            const policyNote = el('span', { class: 'muted' });
            const askAgain = el('button', { class: 'link-button', onclick: () => settings.set('map.tiles', 'ask') },
                'Ask me when the map opens instead');
            const policy = el('div', { class: 'map-tile-policy' },
                el('label', { class: 'choice-item' }, fetchTiles, 'Fetch map tiles from a remote server'),
                askEachItem,
                el('p', {}, policyNote, ' ', askAgain));

            function showPolicy() {
                const v = map.tilePolicy();
                const host = map.tileHost(map.tileSource().url);
                const accepted = map.acceptedTileUrl();
                const anyServer = accepted === map.anyTiles;
                const current = v === 'allow' && (anyServer || accepted === map.tileSource().url);
                fetchTiles.checked = current;
                askEach.checked = !anyServer;
                askEachItem.hidden = !current;
                policyNote.textContent = v === 'ask' ?
                    'Not chosen yet: the map asks before fetching any tiles.' :
                    current && anyServer ? `The map loads its background from ${host}, and from any other tile server without asking.` :
                    current ? `The map loads its background from ${host}, and asks again if the tile server changes.` :
                        v === 'allow' ? `You agreed to tiles from ${map.tileHost(accepted || '') || 'another server'}; ` +
                            `the map asks before loading them from ${host}.` :
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
                const server = map.serverTileDefaults();
                const fallback = server.url ? 'the tile server set on the Kismet server' : 'OpenStreetMap';
                const source = map.tileSource();
                if (typed && (!source.custom || source.server))
                    urlNote.textContent = 'Not a usable tile address: it needs to start with http:// or https:// and ' +
                        `contain {z}, {x}, and {y}.  Using ${fallback}.`;
                else if (typed)
                    urlNote.textContent = 'Using this server.';
                else
                    urlNote.textContent = server.url ? `Leave empty for the tile server set on the Kismet server, ${server.url}.` :
                        'Leave empty for OpenStreetMap.';
            }
            checkUrl();

            // The Kismet server's defaults, shown where this browser has none
            map.loadServerTiles().then(() => {
                const server = map.serverTileDefaults();
                if (server.url)
                    url.placeholder = server.url;
                if (server.attribution)
                    attribution.placeholder = server.attribution;
                checkUrl();
                showPolicy();
            });

            const dark = el('input', { type: 'checkbox', checked: settings.get('map.darkTiles', true) !== false,
                onchange: () => settings.set('map.darkTiles', dark.checked) });

            const collect = el('input', { type: 'checkbox', checked: settings.get('map.pathsCollect', true) !== false,
                onchange: () => settings.set('map.pathsCollect', collect.checked) });
            const keep = el('select', { onchange: () => settings.set('map.pathsAge', Number(keep.value)) },
                map.pathAges.map((a) => el('option', { value: a.id,
                    selected: a.id === (Number(settings.get('map.pathsAge', 3600)) || 3600) }, a.title)));

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
                el('label', { class: 'choice-item' }, dark, 'Darken the map in dark mode'),
                el('h4', {}, 'Paths'),
                el('p', { class: 'muted' }, 'The browser remembers where each device on the map has been, so its path ' +
                    'can be drawn even when the Kismet server keeps no location history.  Paths last until the page ' +
                    'is reloaded.'),
                el('label', { class: 'choice-item' }, collect, 'Keep collecting paths while the map is not shown'),
                el('label', { class: 'field' }, 'Keep paths for', keep));

            const unwatch = ['map.tiles', 'map.tilesAccepted', 'map.tileUrl'].map((k) => settings.watch(k, () => showPolicy()));
            return () => unwatch.forEach((u) => u());
        },
    });
}
