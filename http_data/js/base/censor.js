// Censor mode's section in Settings (js/core/censor.js does the censoring).

export function register(kismet) {
    const { ui, dom, censor } = kismet;
    const { el } = dom;

    ui.settingsPanes.add({
        id: 'censor', title: 'Censor mode', priority: 40,
        create(body) {
            const now = censor.current();
            const box = (id, title, note) => el('label', { class: 'check-item' },
                el('input', { type: 'checkbox', name: id, checked: now[id] }), title, el('span', { class: 'muted' }, ` - ${note}`));
            const how = (full, title) => el('label', { class: 'choice-item' },
                el('input', { type: 'radio', name: 'censor-full', checked: now.full === full }), title);
            const macs = box('macs', 'MAC addresses', 'Bluetooth and other addresses too');
            const names = box('names', 'Names and identifiers',
                'device names, SSIDs, hostnames, serial numbers, node and cell IDs, IP addresses, notes');
            const locations = box('locations', 'Locations', 'coordinates, and the map is hidden');
            const partly = how(false, 'Partly: keep the manufacturer half of a MAC, the ends of a name, the whole degrees of a position');
            const fully = how(true, 'Completely');
            const pick = () => ({
                macs: macs.querySelector('input').checked,
                names: names.querySelector('input').checked,
                locations: locations.querySelector('input').checked,
                full: fully.querySelector('input').checked,
            });

            // dom.append skips the note when it's null, where body.append would print it
            dom.append(body,
                el('p', { class: 'muted' }, 'Hide what identifies devices, networks and places, for screenshots, ' +
                    'streams and demos.  Data sent to the server is not changed.'),
                macs, names, locations,
                el('h4', {}, 'How much to hide'),
                el('div', { class: 'choice', role: 'radiogroup' }, partly, fully),
                now.fromUrl ? el('p', { class: 'muted' }, 'These were set by the page address.  Applying saves them ' +
                    'here and reloads the page without them in the address.') : null,
                el('p', {}, el('button', { type: 'button', class: 'primary', onclick: () => censor.apply(pick()) }, 'Apply'),
                    el('span', { class: 'muted' }, ' The page reloads, so nothing shown before stays on it.')),
                el('p', { class: 'muted' }, 'From the page address: ?censor=1 hides them partly, ?censor_heavy=1 completely.'));
        },
    });
}
