// The standard device panel sections, for every phy: device info (with the
// name and notes you can edit), seen-by, and developer links.

const base = 'kismet.device.base';
const sig = `${base}.signal/kismet.common.signal`;
const loc = `${base}.location/kismet.common.location`;
// Only on devices that report their own position (ADS-B, AIS, Remote ID...)
const rloc = `${base}.reported_location/kismet.common.location`;

export function register(kismet) {
    const { ui, format, dom, api, rrd, clock, icons } = kismet;
    const { el } = dom;
    const { historyGraph, charts } = kismet.widgets;
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

    // Past minute / hour / day buttons for a graph; the choice is kept in state.span
    const spans = [['minute', 'Past minute'], ['hour', 'Past hour'], ['day', 'Past day']];
    const spanLabels = { minute: ['-60s', 'now'], hour: ['-60m', 'now'], day: ['-24h', 'now'] };
    function spanTabs(state, redraw) {
        state.span = state.span ?? 'minute';
        const buttons = spans.map(([id, label]) => el('button', { type: 'button',
            class: id === state.span ? 'active' : null,
            onclick: () => {
                state.span = id;
                buttons.forEach((b, i) => b.classList.toggle('active', spans[i][0] === id));
                redraw();
            } }, label));
        return el('div', { class: 'graph-tabs' }, buttons);
    }

    // Empty slots have no signal, rather than a signal of 0
    const signalHistory = (r, span = 'minute') => rrd.history(r, now(), span).map((v) => (v === 0 ? NaN : v));

    // Each datasource's signal over the last minute, in name order.  The index
    // is the place in that order, so a source keeps its color as others come and go.
    function sourceSignals(seenby) {
        return Object.values(seenby ?? {})
            .map((s) => ({
                label: s['kismet.common.seenby.source']?.['kismet.datasource.name'] ?? s['kismet.common.seenby.uuid'],
                rrd: api.field(s, 'kismet.common.seenby.signal/kismet.common.signal.signal_rrd'),
            }))
            .filter((s) => Array.isArray(s.rrd?.['kismet.common.rrd.minute_vec']))
            .sort((a, b) => String(a.label).localeCompare(String(b.label)))
            .map((s, index) => {
                // Seconds with no packets have no signal, rather than a signal of 0
                const values = signalHistory(s.rrd);
                return { label: s.label, index, values, heard: values.some(Number.isFinite) };
            });
    }

    // When the device was around: packets per hour over the past day, and per
    // minute over the past hour.  The RRD keeps those as packets per second
    // averaged over each slot.
    function presence(state, r) {
        const t = now() ?? r['kismet.common.rrd.last_time'];
        const strip = (span, slot, every) => {
            const values = rrd.history(r, t, span);
            const start = (Math.floor(t / slot) - (values.length - 1)) * slot;
            const cells = values.map((v, i) => {
                const from = start + i * slot;
                const n = Math.round(v * slot);
                return { value: n, title: `${format.clock(from)}–${format.clock(from + slot)}: ` +
                    (n ? `${format.count(n)} packet${n === 1 ? '' : 's'}` : 'not heard') };
            });
            // Labels on round local times: every 6 hours, or every 15 minutes
            const unit = (sec) => (slot === 3600 ? new Date(sec * 1000).getHours() : new Date(sec * 1000).getMinutes());
            const labels = values.map((_v, i) => i).filter((i) => unit(start + i * slot) % every === 0)
                .map((i) => ({ at: i, text: format.clock(start + i * slot) }));
            return [cells, labels];
        };
        state.day.update(...strip('day', 3600, 6));
        state.hour.update(...strip('hour', 60, 15));
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
                group: 'Activity',
                help: 'When Kismet heard the device.  Each block is an hour (top) or a minute (bottom); the darker it is, the more packets.  Hover over a block for the count.',
                show: (dev) => Array.isArray(api.field(dev, `${base}.packets.rrd/kismet.common.rrd.day_vec`)),
                fields: [
                    {
                        id: 'presence', wide: true,
                        field: `${base}.packets.rrd`,
                        draw: (cell, r, _d, state) => {
                            if (!state.day) {
                                state.day = charts.presenceStrip({ caption: 'Past 24 hours' });
                                state.hour = charts.presenceStrip({ caption: 'Past hour' });
                                cell.replaceChildren(state.day.node, state.hour.node);
                            }
                            presence(state, r);
                        },
                    },
                ],
            },

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
                help: 'Signal strength in dBm; closer to 0 is stronger.  The graph shows the strongest reading in each second, minute, or hour, joined across the times the device wasn\'t heard.  When more than one datasource heard the device, each gets its own line: the loudest is usually the closest to it, or has the best antenna for it.  The server only keeps each datasource\'s signal when keep_per_datasource_stats=true is set in kismet_memory.conf.',
                fields: [
                    {
                        // Servers without the longer signal history only have the past minute
                        id: 'signal_graph', wide: true,
                        field: `${sig}.signal_rrd`,
                        draw: (cell, r, _d, state) => {
                            graphIn(cell, state, { type: 'line', unit: 'dBm', title: 'Signal, last minute', joinGaps: true, fill: true })
                                .draw(signalHistory(r), ['-60s', 'now']);
                        },
                        show: (r, dev) => r && Array.isArray(r['kismet.common.rrd.minute_vec']) &&
                            !Array.isArray(api.field(dev, `${sig}.max_signal_rrd/kismet.common.rrd.minute_vec`)),
                    },
                    {
                        // The strongest reading per second, minute, or hour
                        id: 'signal_history', wide: true,
                        field: `${sig}.max_signal_rrd`,
                        show: (r) => r && Array.isArray(r['kismet.common.rrd.minute_vec']),
                        draw: (cell, r, _d, state) => {
                            if (!state.graph) {
                                state.graph = historyGraph({ type: 'line', unit: 'dBm', joinGaps: true, fill: true });
                                cell.replaceChildren(spanTabs(state, () => state.redraw()), state.graph.node);
                            }
                            state.redraw = () => state.graph.draw(signalHistory(state.rrd, state.span), spanLabels[state.span]);
                            state.rrd = r;
                            state.redraw();
                        },
                    },
                    {
                        // One line per datasource that heard the device in the last minute; only
                        // worth it with two or more
                        id: 'signal_by_source', wide: true,
                        field: `${base}.seenby`,
                        show: (m) => sourceSignals(m).filter((s) => s.heard).length > 1,
                        draw: (cell, m, _d, state) => {
                            const lines = sourceSignals(m).filter((s) => s.heard)
                                .map((s) => ({ label: s.label, color: charts.series(s.index), values: s.values }));
                            graphIn(cell, state, { type: 'line', unit: 'dBm', title: 'Signal by datasource, last minute', joinGaps: true })
                                .draw(lines, ['-60s', 'now']);
                        },
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
                help: 'Sent are packets the device transmitted; received are packets addressed to it.  Packets it was only part of, such as an access point\'s traffic being passed between clients, or broadcasts, count in all packets but in neither.',
                fields: [
                    {
                        id: 'packet_graph', wide: true,
                        field: `${base}.packets.rrd`,
                        show: (r) => r && Array.isArray(r['kismet.common.rrd.minute_vec']),
                        draw: (cell, r, dev, state) => {
                            // All packets, then the ones the device sent (up) and the ones
                            // sent to it (down), on the same span
                            if (!state.graph) {
                                state.graph = historyGraph({ type: 'bar', height: '7rem', minBar: true, title: 'All packets' });
                                state.txrx = historyGraph({ type: 'mirror', height: '7rem', minBar: true, title: 'Sent and received' });
                                cell.replaceChildren(spanTabs(state, () => state.redraw()), state.graph.node, state.txrx.node);
                            }
                            state.redraw = () => {
                                state.graph.draw(rrd.history(state.rrd, now(), state.span), spanLabels[state.span]);
                                state.txrx.node.hidden = !state.tx && !state.rx;
                                if (!state.txrx.node.hidden)
                                    state.txrx.draw([
                                        { label: 'Sent', color: 'var(--accent)', values: rrd.history(state.tx, now(), state.span) },
                                        { label: 'Received', color: 'var(--ok)', values: rrd.history(state.rx, now(), state.span) },
                                    ], spanLabels[state.span]);
                            };
                            state.rrd = r;
                            // Only worth showing once either has been counted
                            const counted = (n) => api.field(dev, `${base}.packets.${n}_total`, 0) > 0;
                            state.tx = counted('tx') || counted('rx') ? dev[`${base}.tx_packets.rrd`] : null;
                            state.rx = counted('tx') || counted('rx') ? dev[`${base}.rx_packets.rrd`] : null;
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
                        format: (v) => point(v) ?? muted('Unknown'),
                        help: 'Where Kismet was, on average, when it heard the device, from Kismet\'s GPS.' },
                    { title: 'Altitude', field: `${loc}.avg_loc/kismet.common.location.alt`,
                        show: (_v, dev) => api.field(dev, `${loc}.avg_loc/kismet.common.location.fix`, 0) >= 3,
                        format: (v) => `${v.toFixed(1)} m` },
                ],
            },

            {
                group: 'Reported location',
                show: (dev) => api.field(dev, `${rloc}.last/kismet.common.location.fix`, 0) >= 2,
                fields: [
                    { title: 'Last reported', field: `${rloc}.last/kismet.common.location.geopoint`,
                        format: (v) => point(v) ?? muted('Unknown'),
                        help: 'The last position the device reported for itself.  This is where the device says it is, not where Kismet heard it.' },
                    { title: 'Altitude', field: `${rloc}.last/kismet.common.location.alt`,
                        show: (_v, dev) => api.field(dev, `${rloc}.last/kismet.common.location.fix`, 0) >= 3,
                        format: (v) => `${v.toFixed(1)} m` },
                    { title: 'Average', field: `${rloc}.avg_loc/kismet.common.location.geopoint`,
                        show: (_v, dev) => api.field(dev, `${rloc}.avg_loc/kismet.common.location.fix`, 0) >= 2,
                        format: (v) => point(v) ?? muted('Unknown'),
                        help: 'The average of the positions the device reported.' },
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
