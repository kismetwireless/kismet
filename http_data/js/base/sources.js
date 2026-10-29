// The Data sources window's menu entry and the sections every source gets:
// what it is and its controls (open, close, disable), its packets, and its
// channels (hop or lock, the hop rate, and which channels).  Phy modules add
// their own sections, and their own channel pickers, through the registries
// in js/registry/sources.js.

const ds = 'kismet.datasource';
const drv = `${ds}.type_driver/${ds}.driver`;

// Channel changes in hop mode are sent this long after the last click, so
// picking several channels is one change on the source
const hopDelay = 2000;

export function register(kismet) {
    const { ui, dom, format, rrd, clock, icons, datasources: sources } = kismet;
    const { el } = dom;
    const { historyGraph } = kismet.widgets;
    const driverField = (s, name) => s[`${ds}.type_driver`]?.[`${ds}.driver.${name}`];

    ui.menuItems.add({
        id: 'datasources', title: 'Data sources', icon: 'source', priority: 5,
        onClick: () => kismet.widgets.datasources.openSources(),
    });

    function retryText(s) {
        if (s[`${ds}.remote`])
            return 'Remote sources are not re-opened by Kismet; they come back when the remote capture reconnects.';
        if (s[`${ds}.passive`])
            return 'Passive sources aren\'t managed by Kismet; they take data sent from other programs.';
        if (s[`${ds}.retry`]) {
            const n = s[`${ds}.retry_attempts`];
            return 'Kismet re-opens this source if it fails' + (n && !s[`${ds}.running`] ? ` (tried ${n} times)` : '') + '.';
        }
        return 'Kismet won\'t re-open this source if it fails.';
    }

    // Open / close / disable, keeping the buttons between updates
    function controls(cell, s, state, ctx) {
        const uuid = s[`${ds}.uuid`];
        const running = !!s[`${ds}.running`];
        const key = `${running}|${!!s[`${ds}.remote`]}`;
        if (state.key === key)
            return;
        state.key = key;
        const button = (text, title, fn, busyText, cls = null) => el('button', { type: 'button', class: cls, title,
            onclick: () => ctx.busy(fn(), busyText) }, text);
        const parts = [];
        if (running) {
            parts.push(button('Close', 'Stop capturing and release the interface; the source stays listed',
                () => sources.close(uuid), 'Closing the source...'));
            if (!s[`${ds}.remote`])
                parts.push(button('Restart', 'Close the source, then open it again once it has closed',
                    () => sources.restart(uuid), 'Restarting the source...'));
        } else {
            parts.push(button('Open', 'Open the source again with the same settings',
                () => sources.open(uuid), 'Opening the source...', 'primary'));
        }
        parts.push(button('Disable', 'Close the source and stop Kismet from re-opening it',
            () => sources.disable(uuid), 'Disabling the source...'));
        cell.replaceChildren(el('div', { class: 'ds-buttons' }, parts));
    }

    ui.sourceSections.add({
        id: 'source', title: 'Source', priority: 0,
        fields: [
            { title: 'Error', field: `${ds}.error_reason`, show: (v, s) => !!s[`${ds}.error`],
                format: (v) => el('span', { class: 'error-text' }, icons.icon('alert'), ' ', v || 'failed') },
            { id: 'controls', title: 'Capture', draw: (cell, v, s, state, ctx) => controls(cell, s, state, ctx) },
            { title: 'Interface', value: (s) => s[`${ds}.interface`] + (s[`${ds}.capture_interface`] &&
                s[`${ds}.capture_interface`] !== s[`${ds}.interface`] ? ` (capturing on ${s[`${ds}.capture_interface`]})` : '') },
            { title: 'Capture driver', field: `${drv}.type`,
                format: (v, s) => el('span', {}, v, el('span', { class: 'ds-driver-desc muted' },
                    s[`${ds}.type_driver`]?.[`${ds}.driver.description`] ?? '')) },
            { title: 'Hardware', field: `${ds}.hardware`, hideEmpty: true },
            { title: 'Address', field: `${ds}.remote_ip`, hideEmpty: true,
                help: 'Where a remote capture is connecting from.' },
            { title: 'Process ID', field: `${ds}.ipc_pid`, hideZero: true,
                help: 'The capture helper Kismet runs for this source.' },
            { title: 'Version', field: `${ds}.datasource_version`, hideEmpty: true },
            { title: 'UUID', field: `${ds}.uuid`, format: (v) => el('span', { class: 'mono' }, v) },
            { title: 'Definition', field: `${ds}.definition`, hideEmpty: true,
                format: (v) => el('span', { class: 'mono' }, v),
                help: 'The source as Kismet opened it.  Changes made in this window last until Kismet restarts; to keep ' +
                    'them, put this in kismet_site.conf as a source= line.' },
            { title: 'Re-open on error', value: retryText },
        ],
    });

    ui.sourceSections.add({
        id: 'packets', title: 'Packets', priority: 10,
        fields: [
            { id: 'graph', title: 'Packets', wide: true, field: `${ds}.packets_rrd`,
                draw: (cell, v, s, state) => {
                    if (!state.graph) {
                        state.graph = historyGraph({ type: 'bar', unit: 'packets/s', title: 'Packets per second, last minute',
                            height: '5.5rem', minBar: true });
                        cell.replaceChildren(state.graph.node);
                    }
                    const now = clock.isKnown() ? clock.now() : undefined;
                    state.graph.draw(rrd.history(v, now).slice(0, -1), ['-60s', 'now']);
                } },
            { title: 'Packets', field: `${ds}.num_packets`, format: format.count },
            { title: 'Invalid', field: `${ds}.num_error_packets`, format: format.count,
                help: 'Packets the source delivered that Kismet couldn\'t read, often damaged frames.' },
            { title: 'Filtered', field: `${ds}.num_filtered_packets`, format: format.count,
                help: 'Packets dropped by a filter set on this source.' },
            { title: 'Dropped', field: `${ds}.num_dropped_packets`, format: format.count,
                help: 'Packets the capture helper lost because Kismet couldn\'t take them fast enough.' },
        ],
    });

    ui.sourceSections.add({
        id: 'channels', title: 'Channels', priority: 20, running: true,
        when: (s, type) => !!driverField(s, 'tuning_capable') && type?.channels !== false &&
            (s[`${ds}.channels`] ?? []).length > 0,
        render: (s, node, ctx) => {
            node._channels ??= channelControl(node, ctx);
            node._channels.update(s);
        },
    });

    // Hop or lock, the hop rate, and the channel picker, with the state the
    // picker shares: what the user has chosen but not sent yet
    function channelControl(node, ctx) {
        let source = null;
        let pickerEntry = null;
        let picker = null;
        let timer = null;
        const pickerEl = el('div', { class: 'ds-picker' });
        const readback = el('div', { class: 'ds-readback muted' });
        const pendingNote = el('span', { class: 'ds-pending', hidden: true });
        const rateValue = el('input', { type: 'number', min: 0, step: 'any', class: 'ds-rate-input' });
        const rateUnit = el('select', {},
            el('option', { value: 'sec' }, 'hops/second'),
            el('option', { value: 'min' }, 'hops/minute'),
            el('option', { value: 'dwell' }, 'seconds per hop'));
        const rateMax = el('span', { class: 'muted' });
        let rateEdited = false;
        rateValue.addEventListener('input', () => { rateEdited = true; });
        rateUnit.addEventListener('change', () => { rateEdited = true; });
        const rateForm = el('form', { class: 'ds-rate', onsubmit: (e) => {
            e.preventDefault();
            let rate = sources.inputToRate(rateValue.value, rateUnit.value);
            if (Number.isNaN(rate)) {
                ctx.message('That isn\'t a hop rate: give a number above 0.', 'error');
                return;
            }
            const max = driverField(source, 'max_hop_rate');
            if (max > 0 && rate > max)
                rate = max;
            rateEdited = false;
            ctx.busy(sources.hop(uuid(), null, rate), 'Setting the hop rate...');
        } }, el('span', {}, 'Hop rate'), rateValue, rateUnit, el('button', { type: 'submit' }, 'Set'), rateMax);

        const modeButtons = {
            hop: el('button', { type: 'button', title: 'Move through the chosen channels in turn',
                onclick: () => {
                    if (state.mode === 'hop' && !state.pending)
                        return;
                    const list = state.selected.size ? ordered(state.selected) : channels();
                    ctx.busy(sources.hop(uuid(), list), 'Starting to hop...');
                } }, 'Hop'),
            lock: el('button', { type: 'button', title: 'Stay on one channel',
                onclick: () => {
                    if (state.mode === 'lock')
                        return;
                    const ch = source[`${ds}.channel`] || channels()[0];
                    ctx.busy(sources.lock(uuid(), ch), `Locking to ${ch}...`);
                } }, 'Lock'),
        };
        node.replaceChildren(
            el('div', { class: 'ds-chan-bar' }, el('div', { class: 'graph-tabs' }, modeButtons.hop, modeButtons.lock), readback, pendingNote),
            rateForm, pickerEl);

        const uuid = () => source[`${ds}.uuid`];
        const channels = () => source[`${ds}.channels`] ?? [];
        const ordered = (set) => channels().filter((c) => set.has(c));

        function send() {
            clearTimeout(timer);
            timer = null;
            const list = ordered(state.selected);
            if (!list.length) {
                ctx.message('Choose at least one channel to hop on.', 'error');
                return;
            }
            pendingNote.hidden = true;
            ctx.busy(sources.hop(uuid(), list), `Hopping ${list.length} channel${list.length === 1 ? '' : 's'}...`)
                .finally(() => { state.pending = false; });
        }

        const state = {
            mode: 'hop',
            selected: new Set(),
            pending: false,
            current: '',
            get channels() { return channels(); },
            get source() { return source; },
            toggle(ch) {
                if (state.mode === 'lock')
                    return state.lock(ch);
                if (state.selected.has(ch))
                    state.selected.delete(ch);
                else
                    state.selected.add(ch);
                schedule();
            },
            setSelected(list) {
                state.selected = new Set(list);
                if (state.mode === 'lock')
                    return;
                schedule();
            },
            lock(ch) {
                clearTimeout(timer);
                state.pending = false;
                ctx.busy(sources.lock(uuid(), ch), `Locking to ${ch}...`);
            },
            applyNow: () => send(),
        };

        function schedule() {
            state.pending = true;
            clearTimeout(timer);
            timer = setTimeout(send, hopDelay);
            pendingNote.hidden = false;
            pendingNote.replaceChildren(`${state.selected.size} channels chosen; sending in a moment `,
                el('button', { type: 'button', class: 'link-button', onclick: send }, 'Send now'), ' ',
                el('button', { type: 'button', class: 'link-button', onclick: () => {
                    clearTimeout(timer);
                    state.pending = false;
                    pendingNote.hidden = true;
                    state.selected = new Set(source[`${ds}.hop_channels`] ?? []);
                    picker?.update(source, state);
                } }, 'Undo'));
            picker?.update(source, state);
        }

        return {
            update(s) {
                source = s;
                const hopping = !!s[`${ds}.hopping`];
                if (!state.pending) {
                    state.mode = hopping ? 'hop' : 'lock';
                    state.selected = new Set(hopping ? (s[`${ds}.hop_channels`] ?? []) : []);
                }
                state.current = s[`${ds}.channel`] ?? '';
                modeButtons.hop.classList.toggle('active', state.mode === 'hop');
                modeButtons.lock.classList.toggle('active', state.mode === 'lock');
                readback.textContent = hopping ?
                    `Hopping ${(s[`${ds}.hop_channels`] ?? []).length} of ${channels().length} channels, ${sources.rateText(s[`${ds}.hop_rate`])}` :
                    `Locked to ${state.current || 'an unknown channel'}`;
                rateForm.hidden = !hopping;
                if (!rateEdited && document.activeElement !== rateValue) {
                    const [v, u] = sources.rateToInput(s[`${ds}.hop_rate`] > 0 ? s[`${ds}.hop_rate`] : 1);
                    rateValue.value = v;
                    rateUnit.value = u;
                }
                const max = driverField(s, 'max_hop_rate');
                rateMax.textContent = max > 0 ? `at most ${sources.rateText(max)}` : '';

                // The picker for this source: the first that matches, else the generic one
                const entry = ui.channelPickers.list().find((p) => ui.sourceApplies(p, s));
                if (entry !== pickerEntry) {
                    picker?.destroy?.();
                    pickerEntry = entry;
                    pickerEl.replaceChildren();
                    picker = entry ? entry.create(pickerEl, ctx) : null;
                }
                picker?.update(s, state);
            },
        };
    }

    // The generic picker: a button per channel, in the source's own order
    ui.channelPickers.add({
        id: 'generic', priority: 1000,
        create(node) {
            const buttons = new Map();
            const grid = el('div', { class: 'ds-chan-grid' });
            const all = el('button', { type: 'button', class: 'link-button' }, 'All');
            const none = el('button', { type: 'button', class: 'link-button' }, 'None');
            const tools = el('div', { class: 'ds-chan-tools' }, el('span', { class: 'muted' }, 'Hop on:'), all, none);
            node.append(tools, grid);
            let st = null;
            all.addEventListener('click', () => st?.setSelected(st.channels));
            none.addEventListener('click', () => st?.setSelected([]));
            return {
                update(s, state) {
                    st = state;
                    tools.hidden = state.mode !== 'hop';
                    const chans = state.channels;
                    if (chans.join('\n') !== grid._key) {
                        grid._key = chans.join('\n');
                        buttons.clear();
                        grid.replaceChildren(...chans.map((c) => {
                            const b = el('button', { type: 'button', class: 'ds-chan', onclick: () => st.toggle(c) }, c);
                            buttons.set(c, b);
                            return b;
                        }));
                    }
                    for (const [c, b] of buttons) {
                        const on = state.mode === 'hop' ? state.selected.has(c) : c === state.current;
                        b.classList.toggle('on', on);
                        b.classList.toggle('pending', state.pending);
                        b.title = state.mode === 'hop' ? (on ? `Stop hopping on ${c}` : `Hop on ${c} too`) : `Lock to ${c}`;
                    }
                },
            };
        },
    });
}
