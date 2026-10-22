// The standard device panel sections, for every phy: device info (with the
// name and notes you can edit), seen-by, and developer links.

const base = 'kismet.device.base';
const sig = `${base}.signal/kismet.common.signal`;
const loc = `${base}.location/kismet.common.location`;

export function register(kismet) {
    const { ui, format, dom, api, rrd, clock, icons } = kismet;
    const { el } = dom;
    const { historyGraph } = kismet.widgets;
    const muted = ui.muted;

    const now = () => (clock.isKnown() ? clock.now() : undefined);
    const point = (v) => (Array.isArray(v) && (v[0] || v[1]) ? `${v[1].toFixed(6)}, ${v[0].toFixed(6)}` : null);

    function copyButton(text) {
        return el('button', { class: 'copy-button', type: 'button', title: 'Copy',
            onclick: () => navigator.clipboard?.writeText(text) }, icons.icon('copy'));
    }

    // Text you can click to edit; save(newValue) sends it to the server.  The
    // state object keeps the editor open across updates.
    function editable(cell, state, shown, current, { multiline = false, placeholder = '', save }) {
        // Leave it alone while editing, or when nothing changed
        if (state.editing || (state.shown === shown && cell.childElementCount))
            return;
        state.shown = shown;

        const display = el('span', { class: 'df-editable', title: 'Click to edit', tabindex: 0 },
            shown || muted(placeholder));
        const startEdit = () => {
            state.editing = true;
            const input = multiline ?
                el('textarea', { value: current ?? '' }) :
                el('input', { value: current ?? '' });
            const done = (keep) => {
                state.editing = false;
                state.shown = keep ? input.value : shown;
                if (keep && input.value !== (current ?? ''))
                    save(input.value).catch((err) => alert(`Could not save: ${err.message}`));
                cell.replaceChildren(el('span', { class: 'df-editable' }, keep ? (input.value || muted(placeholder)) : (shown || muted(placeholder))));
            };
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    // Cancels the edit, without closing the window
                    e.preventDefault();
                    done(false);
                }
                else if (e.key === 'Enter' && (!multiline || e.ctrlKey || e.metaKey))
                    done(true);
            });
            cell.replaceChildren(el('div', { class: 'df-edit' }, input,
                el('button', { type: 'button', class: 'primary', onclick: () => done(true) }, 'Save'),
                el('button', { type: 'button', onclick: () => done(false) }, 'Cancel')));
            input.focus();
        };
        display.addEventListener('click', startEdit);
        display.addEventListener('keydown', (e) => e.key === 'Enter' && startEdit());

        dom.replace(cell, display, multiline ? null : copyButton(shown));
    }

    // A graph kept in the row's state, so it's drawn once and then updated
    function graphIn(cell, state, options) {
        if (!state.graph) {
            state.graph = historyGraph(options);
            cell.replaceChildren(state.graph.node);
        }
        return state.graph;
    }

    ui.deviceDetails.add({
        id: 'base', title: 'Device info', priority: 0,
        match: () => true,
        fields: [
            {
                id: 'name', title: 'Name',
                help: 'The device name: one you set, or one Kismet found in the device\'s packets, or its address.  Click to set your own.',
                draw: (cell, _v, dev, state) => {
                    const shown = dev[`${base}.username`] || dev[`${base}.commonname`] || dev[`${base}.macaddr`];
                    editable(cell, state, shown, dev[`${base}.username`], {
                        placeholder: 'Unnamed',
                        save: (name) => api.command(`devices/by-key/${encodeURIComponent(dev[`${base}.key`])}/set_name.cmd`, { username: name }),
                    });
                },
            },
            {
                id: 'notes', title: 'Notes',
                help: 'Your own notes about this device, kept by the server.',
                draw: (cell, _v, dev, state) => {
                    const notes = dev[`${base}.tags`]?.notes ?? '';
                    editable(cell, state, notes, notes, {
                        multiline: true, placeholder: 'Add notes',
                        save: (text) => api.command(`devices/by-key/${encodeURIComponent(dev[`${base}.key`])}/set_tag.cmd`,
                            { tagname: 'notes', tagvalue: text }),
                    });
                },
            },
            { title: 'MAC address', field: `${base}.macaddr`,
                format: (v) => el('span', {}, el('span', { class: 'mono' }, v), copyButton(v)) },
            { title: 'Manufacturer', field: `${base}.manuf`, empty: muted('Unknown') },
            { title: 'Type', field: `${base}.type`, empty: muted('Unknown') },
            { title: 'Phy', field: `${base}.phyname` },
            { title: 'Encryption', field: `${base}.crypt`, hideEmpty: true },
            { title: 'First seen', field: `${base}.first_time`, format: format.time },
            { title: 'Last seen', field: `${base}.last_time`, format: (v) => `${format.time(v)} (${format.ago(v, now())} ago)` },

            {
                group: 'Frequencies',
                fields: [
                    { title: 'Channel', field: `${base}.channel`, hideEmpty: true, empty: muted('None advertised'),
                        help: 'The channel the device uses, in its phy\'s terms, if it says or Kismet can tell.' },
                    { title: 'Main frequency', field: `${base}.frequency`, hideZero: true, format: format.frequency,
                        help: 'The frequency most of the device\'s packets were seen on.' },
                    {
                        id: 'freq_graph', wide: true,
                        field: `${base}.freq_khz_map`,
                        show: (v) => v && Object.keys(v).length > 1,
                        draw: (cell, map, _r, state) => {
                            const freqs = Object.keys(map).map(Number).sort((a, b) => a - b);
                            graphIn(cell, state, { type: 'bar', title: 'Packets per frequency', height: '8rem' })
                                .draw(freqs.map((f) => map[f]), freqs.map((f) => format.frequency(f)));
                        },
                    },
                ],
            },

            {
                group: 'Signal',
                show: (dev) => api.field(dev, `${sig}.last_signal`, 0) !== 0,
                fields: [
                    {
                        id: 'signal_graph', wide: true,
                        field: `${sig}.signal_rrd`,
                        draw: (cell, r, _d, state) => {
                            // Seconds with no packets have no signal, rather than a signal of 0
                            const values = rrd.history(r, now()).map((v) => (v === 0 ? NaN : v));
                            graphIn(cell, state, { type: 'line', unit: 'dBm', title: 'Signal, last minute', joinGaps: true })
                                .draw(values, ['-60s', 'now']);
                        },
                        show: (r) => r && Array.isArray(r['kismet.common.rrd.minute_vec']),
                    },
                    { title: 'Last signal', field: `${sig}.last_signal`, hideZero: true, format: format.signal },
                    { title: 'Last noise', field: `${sig}.last_noise`, hideZero: true, format: format.signal },
                    { title: 'Min signal', field: `${sig}.min_signal`, hideZero: true, format: format.signal },
                    { title: 'Max signal', field: `${sig}.max_signal`, hideZero: true, format: format.signal },
                    { title: 'Min noise', field: `${sig}.min_noise`, hideZero: true, format: format.signal },
                    { title: 'Max noise', field: `${sig}.max_noise`, hideZero: true, format: format.signal },
                    { title: 'Strongest signal at', field: `${sig}.peak_loc/kismet.common.location.geopoint`,
                        format: (v) => point(v), show: (v) => point(v) !== null,
                        help: 'Where the device was heard loudest, when Kismet has GPS.' },
                ],
            },

            {
                group: 'Packets',
                fields: [
                    {
                        id: 'packet_graph', wide: true,
                        field: `${base}.packets.rrd`,
                        show: (r) => r && Array.isArray(r['kismet.common.rrd.minute_vec']),
                        draw: (cell, r, _d, state) => {
                            if (!state.graph) {
                                state.span = 'minute';
                                state.graph = historyGraph({ type: 'bar', height: '7rem', minBar: true });
                                const spans = [['minute', 'Past minute'], ['hour', 'Past hour'], ['day', 'Past day']];
                                const buttons = spans.map(([id, label]) => el('button', { type: 'button',
                                    class: id === state.span ? 'active' : null,
                                    onclick: () => {
                                        state.span = id;
                                        buttons.forEach((b, i) => b.classList.toggle('active', spans[i][0] === id));
                                        state.redraw();
                                    } }, label));
                                cell.replaceChildren(el('div', { class: 'graph-tabs' }, buttons), state.graph.node);
                            }
                            const labels = { minute: ['-60s', 'now'], hour: ['-60m', 'now'], day: ['-24h', 'now'] };
                            state.redraw = () => state.graph.draw(rrd.history(state.rrd, now(), state.span), labels[state.span]);
                            state.rrd = r;
                            state.redraw();
                        },
                    },
                    { title: 'Total', field: `${base}.packets.total`, format: (v) => v.toLocaleString() },
                    { title: 'Received', field: `${base}.packets.rx_total`, hideZero: true, format: (v) => v.toLocaleString() },
                    { title: 'Sent', field: `${base}.packets.tx_total`, hideZero: true, format: (v) => v.toLocaleString() },
                    { title: 'Management', field: `${base}.packets.llc`, hideZero: true, format: (v) => v.toLocaleString(),
                        help: 'Management and control packets (LLC), which keep the network running but carry no data.' },
                    { title: 'Data', field: `${base}.packets.data`, hideZero: true, format: (v) => v.toLocaleString() },
                    { title: 'Encrypted', field: `${base}.packets.crypt`, hideZero: true, format: (v) => v.toLocaleString() },
                    { title: 'Errors', field: `${base}.packets.error`, hideZero: true, format: (v) => v.toLocaleString(),
                        help: 'Packets that were damaged or couldn\'t be understood.' },
                    { title: 'Filtered', field: `${base}.packets.filtered`, hideZero: true, format: (v) => v.toLocaleString(),
                        help: 'Packets dropped by a filter in the Kismet config.' },
                    { title: 'Data transferred', field: `${base}.datasize`, hideZero: true, format: format.size },
                ],
            },

            {
                group: 'Average location',
                show: (dev) => api.field(dev, `${loc}.avg_loc/kismet.common.location.fix`, 0) >= 2,
                fields: [
                    { title: 'Location', field: `${loc}.avg_loc/kismet.common.location.geopoint`,
                        format: (v) => point(v) ?? muted('Unknown') },
                    { title: 'Altitude', field: `${loc}.avg_loc/kismet.common.location.alt`,
                        show: (_v, dev) => api.field(dev, `${loc}.avg_loc/kismet.common.location.fix`, 0) >= 3,
                        format: (v) => `${v.toFixed(1)} m` },
                ],
            },
        ],
    });

    ui.deviceDetails.add({
        id: 'seenby', title: 'Seen by', priority: 900,
        match: (dev) => Object.keys(dev[`${base}.seenby`] ?? {}).length > 0,
        fields: [
            {
                list: `${base}.seenby`,
                itemTitle: (s) => s['kismet.common.seenby.source']?.['kismet.datasource.name'] ?? s['kismet.common.seenby.uuid'],
                fields: [
                    { title: 'UUID', field: 'kismet.common.seenby.uuid', format: (v) => el('span', { class: 'mono' }, v) },
                    { title: 'Hardware', field: 'kismet.common.seenby.source/kismet.datasource.hardware', hideEmpty: true },
                    { title: 'Interface', field: 'kismet.common.seenby.source/kismet.datasource.interface', hideEmpty: true },
                    { title: 'First seen', field: 'kismet.common.seenby.first_time', format: format.time },
                    { title: 'Last seen', field: 'kismet.common.seenby.last_time', format: format.time },
                    { title: 'Packets', field: 'kismet.common.seenby.num_packets', empty: '0', format: (v) => v.toLocaleString() },
                    { title: 'Last signal', field: 'kismet.common.seenby.signal/kismet.common.signal.last_signal',
                        hideZero: true, format: format.signal },
                ],
            },
        ],
    });

    ui.deviceDetails.add({
        id: 'devel', title: 'Developer', priority: 10000, open: false,
        match: () => true,
        fields: [
            { title: 'Device key', field: `${base}.key`,
                format: (v) => el('span', {}, el('span', { class: 'mono' }, v), copyButton(v)) },
            { title: 'Device JSON', field: `${base}.key`,
                format: (v) => el('a', { href: api.url(`devices/by-key/${encodeURIComponent(v)}/device.prettyjson`).href,
                    target: '_blank', rel: 'noopener' }, 'Open the raw device record') },
        ],
    });
}
