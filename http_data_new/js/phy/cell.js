// Cellular: towers heard by cell modems, and the modems' own data sources.
//
// A modem is usually two sources: cellat-<IMEI> reads the modem's AT
// command port (a survey of the serving and neighbor cells), and
// celldiag-<IMEI> its Qualcomm DIAG port (the radio's own logs).  Their
// sections here say what each is doing, and offer the settings each takes:
// some apply live, others re-open the source.
//
// Unreported is never shown as zero: the server sends every field of a
// source whether or not the helper reported it, so each row checks the
// field that says whether it was measured before showing a number.

const base = 'kismet.device.base';
const cd = 'cellular.device';
const ds = 'kismet.datasource';
const diag = `${ds}.celldiag`;
const at = `${ds}.cellat`;

const cellDrivers = ['cellat', 'celldiag'];
const captureLabel = { cellat: 'AT commands', celldiag: 'DIAG' };

// cellat-<IMEI> / celldiag-<IMEI> -> { driver, imei }
export function ifaceImei(iface) {
    const m = /^(cellat|celldiag)-(\d{15})$/.exec(iface ?? '');
    return m ? { driver: m[1], imei: m[2] } : null;
}

// The listers' hardware label: "<make> <model> (<firmware>) IMEI:<imei>", or
// with the make/model or firmware missing, and " DIAG" after it from the DIAG
// lister.  Anything else is shown as it is, never guessed at.
export function parseLabel(hw) {
    const s = String(hw ?? '').trim().replace(/\s+DIAG$/, '');
    const m = /^(.*?)\s*IMEI:(\d{14,16})$/.exec(s);
    if (!m)
        return null;
    const head = m[1].trim();
    const p = /^(.*\S)\s+\(([^()]*)\)$/.exec(head);
    if (p)
        return { name: p[1], firmware: p[2], imei: m[2] };
    if (/\s/.test(head))
        return { name: head, firmware: '', imei: m[2] };
    return { name: '', firmware: head, imei: m[2] };
}

const makeShort = [
    [/^sierra wireless[, ]*(incorporated|inc\.?)?\s*/i, 'Sierra Wireless '],
    [/^simcom( incorporated| wireless solutions[^ ]*)?\s*/i, 'SIMCom '],
];
const shortName = (name) => makeShort.reduce((n, [re, to]) => n.replace(re, to), name).trim();

export function rowTitle(parsed, driver) {
    const what = parsed ? (shortName(parsed.name) || parsed.firmware) : '';
    return `${what || 'Cell modem'} — ${captureLabel[driver] ?? driver}`;
}

// The modem a running source is, as it answered AT+CGMI/CGMM/CGMR/CGSN
function modemIdentity(s) {
    const m = (k) => s[`${ds}.cell.modem_${k}`];
    if (!m('identity_method'))
        return null;
    const parts = [];
    const name = [m('make'), m('model')].filter(Boolean).join(' ');
    if (name)
        parts.push(name);
    if (m('firmware'))
        parts.push(`firmware ${m('firmware')}`);
    if (m('imei'))
        parts.push(`IMEI ${m('imei')}`);
    if (m('at_port'))
        parts.push(`port ${m('at_port')}`);
    let text = parts.join(' · ');
    if (m('identity_method') === 'definition')
        text += ' (not asked over AT: this is the IMEI the source was opened with; its AT source names the modem)';
    return text;
}

function sourceLabel(s) {
    const m = (k) => s[`${ds}.cell.modem_${k}`] || '';
    const name = [m('make'), m('model')].filter(Boolean).join(' ');
    const id = ifaceImei(s[`${ds}.interface`]);
    if (!id)
        return '';
    if (name && m('firmware'))
        return `${name} (${m('firmware')}) IMEI:${id.imei}`;
    return `${name || m('firmware')} IMEI:${id.imei}`.trim();
}

const driverOf = (s) => s[`${ds}.type_driver`]?.[`${ds}.driver.type`] ?? '';
const siblingDriver = (t) => (t === 'cellat' ? 'celldiag' : 'cellat');

// One modem's sources sort together, AT first
export function sortKey(iface) {
    const id = ifaceImei(iface);
    return id ? `cell-${id.imei}-${id.driver === 'cellat' ? '0at' : '1diag'}` : iface;
}

// A cell source holding its modem's port: open, and not enabled=false
function holdsPort(s) {
    return !!s[`${ds}.running`] && s[`${at}.state`] !== 'disabled' && s[`${diag}.mask_preset`] !== 'disabled' &&
        s[`${diag}.mask_preset`] !== 'replay' && !('replay' in definitionOptions(s));
}

// While one of a modem's sources captures, its sibling driver's lister can't
// see the modem (the port is busy), so the modem would seem to have no
// sibling.  List it anyway, saying why it isn't in the list.
export function augmentInterfaces(intfs, sources) {
    const listed = new Set(intfs.map((i) => i['kismet.datasource.probed.interface']));
    const defined = new Set(sources.map((s) => s[`${ds}.interface`]));
    const extra = [];
    for (const s of sources) {
        const t = driverOf(s);
        const id = ifaceImei(s[`${ds}.interface`]);
        if (!cellDrivers.includes(t) || !id || !holdsPort(s))
            continue;
        const sib = siblingDriver(t);
        const sibIface = `${sib}-${id.imei}`;
        if (listed.has(sibIface) || defined.has(sibIface))
            continue;
        listed.add(sibIface);
        extra.push({
            'kismet.datasource.probed.interface': sibIface,
            'kismet.datasource.probed.in_use_uuid': '00000000-0000-0000-0000-000000000000',
            'kismet.datasource.probed.hardware': sourceLabel(s),
            'kismet.datasource.type_driver': {
                'kismet.datasource.driver.type': sib,
                'kismet.datasource.driver.description': sib === 'cellat' ? 'Cellular modem (AT commands)' : 'Cellular modem (Qualcomm DIAG)',
            },
            cellUnlisted: sib === 'celldiag' ?
                `Not in the DIAG list right now: the running AT source "${s[`${ds}.name`]}" holds the AT port the DIAG ` +
                    'lister identifies a modem by.  Enable still works; DIAG is addressed by IMEI.' :
                `Not in the AT list right now: the running DIAG source "${s[`${ds}.name`]}" may be holding the port the ` +
                    'AT lister reads.  Enable will try; if the port is held, the open fails and says so here.',
        });
    }
    return intfs.concat(extra);
}

// The definition Enable sends: only options changed from the driver's
// defaults, so a plain Enable leaves the defaults to the helper.  A comma
// separates options, so a value can't hold one.
export function enableDefinition(iface, driver, opts) {
    const parts = [];
    for (const [k, v] of opts) {
        const val = String(v ?? '').trim();
        if (val === '')
            continue;
        if (val.includes(','))
            return { error: `${k}= can't contain a comma (it separates options): ${val}` };
        parts.push(`${k}=${val}`);
    }
    return { definition: `${iface}:type=${driver}` + (parts.length ? `,${parts.join(',')}` : '') };
}

// The options in a source's definition, "iface:a=1,b=2"
function definitionOptions(s) {
    const def = String(s[`${ds}.definition`] ?? '');
    const at = def.indexOf(':');
    const out = {};
    if (at < 0)
        return out;
    for (const kv of def.slice(at + 1).split(',')) {
        const eq = kv.indexOf('=');
        if (eq > 0)
            out[kv.slice(0, eq).trim().toLowerCase()] = kv.slice(eq + 1).trim();
    }
    return out;
}

// The scan profiles cellat takes, for a source not open yet; a running
// source reports its own list.  Mirrors STRATEGIES[] in capture_cell_at/cellat_options.c.
export const enableProfiles = [
    ['driving', 'Driving'],
    ['walking', 'Walking'],
    ['stationary', 'Stationary survey'],
    ['serving_only', 'Serving cell only'],
];

const maskPresets = ['wardrive', 'full'];
const f3Presets = ['off', 'error', 'high', 'all'];
const f3Notes = {
    off: 'The firmware\'s debug messages aren\'t asked for at all.',
    error: 'Only messages from code that prints at ERROR or above (about 68% of them).',
    high: 'Messages from code that prints at HIGH or above (about 94% of them).',
    all: 'Every subsystem at every level: a flood, for diagnosis only.',
};

// The slowest full band scan any supported modem is given (AT#CSURVC: 180 s)
const fullScanMaxSeconds = 180;

export function parseStrategies(s) {
    if (!s)
        return [];
    return String(s).split(';').map((r) => r.split(','))
        .filter((c) => c.length === 3 && c[0].length > 0)
        .map((c) => ({ name: c[0], label: c[1], fullScan: parseInt(c[2], 10) }));
}

function intervalText(ms) {
    if (!ms)
        return 'off';
    const s = ms / 1000;
    return s < 120 ? `${s} s` : `${s / 60} min`;
}

export function register(kismet) {
    const { ui, icons, dom, format, datasources: sources } = kismet;
    const { el, replace } = dom;
    const { confirm } = kismet.widgets.dialog;
    const muted = ui.muted;
    const isCell = (row) => row[`${base}.phyname`] === 'Cellular';

    const now = () => Date.now() / 1000;
    const hint = (text) => el('div', { class: 'ds-hint' }, text);
    const ago = (epoch) => `${Math.round(Math.max(0, now() - epoch))} seconds ago`;
    const span = (cls, ...parts) => el('span', { class: cls }, ...parts);

    // ---- devices -------------------------------------------------------

    ui.deviceIcons.add({
        id: 'cell', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isCell(row) ? icons.icon('tower', 'Cell tower') : null),
    });

    ui.deviceColumns.add({
        id: 'cell_rat', title: 'Cell RAT', priority: 120, group: 'Cellular', width: '6em',
        description: 'The cell\'s radio access technology (GSM, UMTS, LTE, NR)',
        fields: [`${cd}/cellular.cell.rat`],
        sortField: `${cd}/cellular.cell.rat`,
        render: (row) => row['cellular.cell.rat'] || '',
    });
    ui.deviceColumns.add({
        id: 'cell_key', title: 'Cell key', priority: 121, group: 'Cellular', width: '14em',
        description: 'The cell\'s identity: MCC/MNC_TAC_CellID, or PCI and channel for a cell only heard as a neighbor',
        fields: [`${cd}/cellular.cell.key`],
        sortField: `${cd}/cellular.cell.key`,
        render: (row) => row['cellular.cell.key'] || '',
    });
    ui.searchFields.add({
        id: 'cell', description: 'Cell key and operator',
        fields: [`${cd}/cellular.cell.key`, `${cd}/cellular.cell.operator`],
    });

    const c = (f) => `${cd}/cellular.cell.${f}`;
    const unknown = muted('Unknown');
    const rsrpColor = (v) => (v > -80 ? 'ok-text' : v > -100 ? 'warn-text' : 'error-text');
    const yesNo = (v) => (v ? 'Yes' : 'No');

    ui.deviceDetails.add({
        id: 'cell', title: 'Cell', priority: 5,
        match: (dev) => !!dev[cd],
        fields: [
            { title: 'RAT', field: c('rat'), hideEmpty: true, empty: unknown,
                help: 'Radio access technology: GSM (2G), UMTS (3G), LTE (4G), or NR (5G).' },
            { title: 'Cell key', field: c('key'), hideEmpty: true, empty: unknown,
                help: 'How Kismet identifies the cell: country, network, tracking area, and cell ID when fully known; a cell only heard as a neighbor is keyed by its physical cell ID and channel.' },
            { title: 'Operator', field: c('operator'), hideEmpty: true,
                help: 'The network operator\'s name, as the modem reports it.' },
            { title: 'MCC', field: c('mcc'), hideEmpty: true, help: 'Mobile country code.' },
            { title: 'MNC', field: c('mnc'), hideEmpty: true, help: 'Mobile network code, within the country.' },
            { title: 'PLMN', field: c('plmn'), hideEmpty: true,
                help: 'The country and network codes together: the operator\'s network ID.' },
            { title: 'TAC', field: c('tac'), hideZero: true,
                help: 'Tracking area code (LTE and NR) or location area code (GSM and UMTS): the group of cells this one belongs to.' },
            { title: 'Cell ID', field: c('cellid'), hideZero: true,
                help: 'The cell\'s identity within its network.' },
            { title: 'eNB ID', field: c('enb_id'), hideZero: true,
                help: 'The LTE base station (eNodeB): the upper bits of the cell ID.  Cells with the same eNB ID are usually on one site.  Not known for NR.' },
            { title: 'Sector', field: c('sector'), hideZero: true,
                help: 'The LTE cell number within its base station, often the antenna sector.' },
            { title: 'PCI', field: c('pci'), hideEmpty: true,
                help: 'Physical cell ID, carried in the radio signal.  It\'s reused across the network, so it only identifies a cell together with its channel and place.' },
            { title: 'ARFCN', field: c('arfcn'), hideZero: true,
                help: 'The channel number the cell transmits on (EARFCN for LTE, NR-ARFCN for NR).' },
            { title: 'Band', field: c('band'), hideZero: true, help: 'The 3GPP band of the cell\'s channel.' },
            { title: 'Bandwidth', field: c('bandwidth'), hideZero: true, format: (v) => `${v} MHz` },
            { title: 'Duplex', field: c('duplex'), hideEmpty: true,
                help: 'FDD uses separate uplink and downlink frequencies; TDD takes turns on one.' },
            { title: 'RSRP', field: c('rsrp'), hideZero: true, format: (v) => span(rsrpColor(v), `${v} dBm`),
                help: 'Reference signal received power, the latest signal strength.  Above -80 dBm is strong, below -100 weak.' },
            { title: 'RSRQ', field: c('rsrq'), hideZero: true, format: (v) => `${v} dB`,
                help: 'Reference signal received quality, which counts interference and load; closer to 0 is better.' },
            { title: 'SINR', field: c('sinr'), hideZero: true, format: (v) => `${v} dB`,
                help: 'Signal to interference and noise ratio; higher is better.' },
            { title: 'RSRP range', value: (dev) => {
                const lo = dev[cd]?.['cellular.cell.min_rsrp'];
                const hi = dev[cd]?.['cellular.cell.max_rsrp'];
                return lo || hi ? `${lo} to ${hi} dBm` : null;
            }, help: 'The weakest and strongest signal seen from this cell.' },
            { title: 'Observations', field: c('observation_count'), hideZero: true, format: format.count,
                help: 'How many times the capture sources reported this cell.' },
            { title: 'Serving cell', field: c('seen_serving'), format: yesNo,
                help: 'Whether a modem used this cell, rather than only hearing it as a neighbor.' },
            { title: 'Neighbor measurements', field: c('seen_observed'), format: yesNo,
                help: 'Whether the cell was heard in neighbor measurements, which usually give only its physical cell ID and channel.' },
            { title: 'Seen via', field: c('seen_via'), wide: true,
                show: (v) => v && Object.keys(v).length > 0,
                format: (v) => el('table', { class: 'ds-census' },
                    el('tr', {}, ['Source', 'From', 'Observations', 'Last seen', 'Fields'].map((h) => el('th', {}, h))),
                    Object.keys(v).sort().map((src) => {
                        const rec = v[src];
                        const last = rec['cellular.prov.last_seen'];
                        return el('tr', {}, el('td', {}, el('b', {}, src)), el('td', {}, rec['cellular.prov.origin'] ?? ''),
                            el('td', {}, format.count(rec['cellular.prov.observation_count'] ?? 0)),
                            el('td', {}, last ? format.ago(last) + ' ago' : ''),
                            el('td', {}, (rec['cellular.prov.fields'] ?? []).join(', ')));
                    })),
                help: 'The capture pipes that reported this cell (AT or DIAG), the command or log each came from, and the fields each supplied.' },
        ],
    });

    // ---- data sources --------------------------------------------------

    // A select and an apply button, built once; the select keeps the user's
    // choice until they apply it or the source changes to it
    function chooser(cell, state, { options, current, label = 'Apply', onApply }) {
        if (!state.select) {
            state.optionsKey = null;
            state.select = el('select', { onchange: () => { state.touched = true; } });
            state.button = el('button', { type: 'button', onclick: () => {
                state.touched = false;
                state.onApply(state.select.value);
            } }, label);
            state.extra = el('div');
            replace(cell, el('span', { class: 'ds-buttons' }, state.shown = el('span'), state.select, state.button), state.extra);
        }
        const key = options.map((o) => `${o.value}:${o.label}:${o.disabled}`).join('|');
        if (key !== state.optionsKey) {
            state.optionsKey = key;
            replace(state.select, ...options.map((o) => el('option', { value: o.value, disabled: !!o.disabled }, o.label)));
            state.touched = false;
        }
        if (!state.touched && document.activeElement !== state.select && current !== undefined)
            state.select.value = current;
        state.onApply = onApply;
        return state;
    }

    // A setting shown without its control (a replay can't change it)
    function fixedText(cell, state, content) {
        state.select = null;
        replace(cell, content);
    }

    // The enabled= switch: a source that stays listed but releases the modem
    function captureSwitch(cell, s, state, ctx, disabledNow) {
        if (state.disabledNow === disabledNow)
            return;
        state.disabledNow = disabledNow;
        const uuid = s[`${ds}.uuid`];
        replace(cell, el('div', {},
            el('button', { type: 'button', class: disabledNow ? 'primary' : null, onclick: async () => {
                const ok = await confirm(disabledNow ? {
                    title: 'Turn capture on?',
                    text: 'The source is closed and opened again with enabled=true: the modem\'s port is opened and the full bring-up runs.',
                    ok: 'Turn on',
                } : {
                    title: 'Turn capture off?',
                    text: 'The source is closed and opened again with enabled=false: it stays listed, but the modem\'s port is ' +
                        'released and nothing is captured until it\'s turned back on.\n\nThis isn\'t Disable, which stops the source itself.',
                    ok: 'Turn off',
                });
                if (ok)
                    ctx.busy(sources.reopenWith(uuid, { enabled: disabledNow ? 'true' : 'false' }), 'Re-opening the source...');
            } }, disabledNow ? 'Turn capture on' : 'Turn capture off (keep the source)'),
            hint('Sets the source\'s enabled= option.  The rows above show the new state within a few seconds.')));
    }

    // Re-open with an option changed, after asking
    async function reopenAsk(ctx, s, options, title, text) {
        if (await confirm({ title, text: `${text}\n\nThe source is closed and opened again; capture stops for a few seconds, ` +
            'and a modem that doesn\'t come back leaves the source down.', ok: 'Re-open' }))
            ctx.busy(sources.reopenWith(s[`${ds}.uuid`], options), 'Re-opening the source...');
    }

    function cadenceInput(cell, state, { live, onSet }) {
        if (state.input)
            return;
        state.input = el('input', { type: 'number', min: 0, step: 1, placeholder: 'seconds', style: { width: '6em' } });
        cell.append(el('span', { class: 'ds-buttons', style: { marginTop: '0.3rem' } }, state.input,
            el('button', { type: 'button', onclick: () => {
                const v = state.input.value.trim();
                if (!/^\d+$/.test(v))
                    return;
                state.input.value = '';
                onSet(v);
            } }, live ? 'Set cadence' : 'Set cadence (re-opens)')));
    }

    ui.sourceTypes.add({
        id: 'cell', drivers: cellDrivers, icon: 'tower', channels: false,
        subtitle: (s) => {
            const parsed = parseLabel(sourceLabel(s));
            return parsed && (parsed.name || parsed.firmware) ? rowTitle(parsed, driverOf(s)) : captureLabel[driverOf(s)];
        },
        interfaceTitle: (intf) => rowTitle(parseLabel(intf['kismet.datasource.probed.hardware']), driverOf(intf)),
        interfaceSubtitle: (intf) => {
            const parsed = parseLabel(intf['kismet.datasource.probed.hardware']);
            const id = ifaceImei(intf['kismet.datasource.probed.interface']);
            const sub = [];
            if (id)
                sub.push(`IMEI ${id.imei}`);
            if (!parsed && intf['kismet.datasource.probed.hardware'])
                sub.push(intf['kismet.datasource.probed.hardware']);
            else if (parsed?.firmware && parsed.name)
                sub.push(parsed.firmware);
            sub.push(intf.cellUnlisted ? 'not in the list right now' : 'available');
            return sub.join(' · ');
        },
        interfaces: (list, ctx) => augmentInterfaces(list, ctx.sources),
        sortKey: (intf) => sortKey(intf['kismet.datasource.probed.interface']),
        enableForm: (intf, ctx) => enableForm(intf, ctx),
    });

    function enableForm(intf, ctx) {
        const iface = intf['kismet.datasource.probed.interface'];
        const driver = driverOf(intf);
        const row = (label, control, help) => el('div', { class: 'ds-form-row' }, el('label', {}, label), control,
            help ? el('div', { class: 'ds-form-help' }, help) : null);
        const name = el('input', { type: 'text', placeholder: iface, size: 26 });
        const anchor = el('input', { type: 'number', min: 0, step: 1, placeholder: 'default', style: { width: '7em' } });
        const status = el('div', { class: 'ds-status' });
        const form = el('div', { class: 'ds-form' });
        let options;

        if (intf.cellUnlisted)
            form.append(el('div', { class: 'warn-text ds-status' }, icons.icon('alert'), ' ', intf.cellUnlisted));

        if (driver === 'cellat') {
            const prof = el('select', {}, enableProfiles.map(([v, l]) => el('option', { value: v }, l + (v === 'driving' ? ' (default)' : ''))));
            const gps = el('input', { type: 'checkbox' });
            form.append(row('Scan profile', prof, 'Driving: the serving cell every 2 s and neighbors every 5 s, no full band scan.  ' +
                    'Walking adds a full scan every 5 minutes, Stationary every 60 s.  Can be changed later without re-opening.'),
                row('Use the modem\'s GPS', gps, 'Quectel modems: turn on the modem\'s own GPS and give its fixes to Kismet as a GPS.'));
            options = () => [['strategy', prof.value === 'driving' ? '' : prof.value], ['gps', gps.checked ? 'true' : '']];
        } else {
            const mask = el('select', {}, el('option', { value: 'wardrive' }, 'wardrive (default)'),
                el('option', { value: 'full' }, 'full: every log code (high volume)'));
            const f3 = el('select', {}, f3Presets.map((p) => el('option', { value: p }, p + (p === 'off' ? ' (default)' : ''))));
            const raw = el('input', { type: 'checkbox', checked: true });
            const nas = el('input', { type: 'checkbox' });
            const qsh = el('input', { type: 'checkbox' });
            form.append(
                row('DIAG mask', mask, 'wardrive asks for the cell-survey logs; full for every log the modem offers (diagnosis, not wardriving).'),
                row('Firmware debug messages', f3, 'The modem firmware\'s own debug prints (F3).  Anything but off is a lot of data.'),
                row('Keep raw DIAG', raw, 'On by default: the whole DIAG stream is kept in the kismetdb, so a drive can be decoded again later.'),
                row('NAS security checks', nas, 'Off by default.  Reads the modem\'s NAS signalling, for the null-cipher and identity-request ' +
                    'alerts; those messages carry this modem\'s own IMSI.'),
                row('QSH trace', qsh, 'Off by default.  The QSH trace tier and every firmware print: development captures only, very high volume.'));
            options = () => [['mask', mask.value === 'wardrive' ? '' : mask.value], ['f3', f3.value === 'off' ? '' : f3.value],
                ['rawpackets', raw.checked ? '' : 'off'], ['nas', nas.checked ? 'true' : ''], ['qsh', qsh.checked ? 'on' : '']];
        }
        form.append(row('Clock anchor every', el('span', {}, anchor, ' s'),
                'How often the modem\'s clock is read against this computer\'s.  Empty: the default; 0: only at start and stop.'),
            row('Source name', name, `Empty: ${iface}.`));

        const button = el('button', { type: 'button', class: 'primary', onclick: async () => {
            const d = enableDefinition(iface, driver, [...options(), ['clock_anchor_sec', anchor.value], ['name', name.value]]);
            if (d.error) {
                status.className = 'ds-status error-text';
                status.textContent = d.error;
                return;
            }
            status.className = 'ds-status muted';
            status.textContent = `Opening ${d.definition} ...`;
            button.disabled = true;
            try {
                await sources.add(d.definition);
                status.textContent = '';
                ctx.refresh();
            } catch (err) {
                status.className = 'ds-status error-text';
                status.textContent = err.message;
            } finally {
                button.disabled = false;
            }
        } }, 'Enable source');
        form.append(el('div', { class: 'ds-buttons' }, button), status);
        return form;
    }

    // ---- DIAG ----------------------------------------------------------

    const diagField = (s, k) => s[`${diag}.${k}`];
    const isDisabled = (s) => diagField(s, 'mask_preset') === 'disabled';
    const live = (s) => diagField(s, 'mask_preset') !== 'replay';

    function bringupText(s) {
        const f = (k) => diagField(s, k);
        const phases = f('bringup_phases') || '';
        if (f('bringup_error'))
            return span('error-text', icons.icon('alert'), ` failed after ${f('bringup_ms') || 0} ms: ${f('bringup_error')}` +
                (phases ? `  [done: ${phases}]` : ''));
        if (f('mask_preset') === 'opening')
            return span('', `Opening the modem: ${phases ? `done so far: ${phases}` : 'no step finished yet'}`);
        if (phases)
            return span('muted', `took ${f('bringup_ms') || 0} ms: ${phases}`);
        return null;
    }

    ui.sourceSections.add({
        id: 'celldiag', title: 'DIAG capture', priority: 5, drivers: ['celldiag'],
        fields: [
            { title: 'Decoder', value: (s) => s, format: (s) => {
                if (isDisabled(s))
                    return muted('Not running: capture is turned off (enabled=false), so no port is open and nothing is captured.');
                if (diagField(s, 'helper_alive'))
                    return span('ok-text', `Running${diagField(s, 'decode_mode') ? ` (${diagField(s, 'decode_mode')})` : ''}`);
                if (diagField(s, 'bringup_error'))
                    return span('warn-text', 'Not started: the bring-up failed (below).');
                if (diagField(s, 'mask_preset') === 'opening')
                    return muted('Not started yet: the bring-up is still running.');
                return span('error-text', icons.icon('alert'), ' Stopped: observations have stopped.  This is not "no cells in range".');
            }, help: 'The decoder turns the DIAG stream into cell observations.  A stopped decoder looks like an empty sky unless it\'s said here.' },
            { title: 'Bring-up', value: (s) => (isDisabled(s) ? null : bringupText(s)),
                help: 'Opening a modem takes several steps; this says how far it got, and why it failed.' },
            { title: 'Modem', value: (s) => (isDisabled(s) ? null : (modemIdentity(s) ?? muted('Not identified yet (the bring-up hasn\'t reported)'))) },
            { title: 'Cell observations', value: (s) => (isDisabled(s) ? null : s), format: (s) => {
                const out = span('', `${format.count(diagField(s, 'obs_total') ?? 0)} total, ${(diagField(s, 'obs_per_sec') || 0).toFixed(2)}/s`);
                if (diagField(s, 'obs_ring_dropped') > 0)
                    out.append(span('error-text', `, ${format.count(diagField(s, 'obs_ring_dropped'))} dropped (the output was full)`));
                return out;
            } },
            { title: 'Last observation', value: (s) => (isDisabled(s) ? null : (diagField(s, 'last_obs_epoch') ? ago(diagField(s, 'last_obs_epoch')) : muted('None yet'))) },
            { title: 'DIAG read', value: (s) => (isDisabled(s) ? null : format.size(diagField(s, 'bytes_read') ?? 0)) },
            { title: 'Frame checks', value: (s) => (isDisabled(s) ? null : s), format: (s) => {
                if (!diagField(s, 'crc_reported'))
                    return muted('Not reported yet');
                const text = `${format.count(diagField(s, 'crc_ok'))} of ${format.count(diagField(s, 'crc_checked'))} frames passed, ${format.count(diagField(s, 'crc_bad'))} failed`;
                if (diagField(s, 'crc_damage_alerts') > 0)
                    return span('error-text', `${text}: this stream lost bytes (${diagField(s, 'crc_damage_alerts')} damaged check windows)`);
                return span(diagField(s, 'crc_bad') > 0 ? 'warn-text' : '', text);
            }, help: 'A frame that fails its check is data the modem sent that never arrived whole; a full serial buffer loses bytes silently.' },
            { id: 'mask', title: 'DIAG mask', show: (v, s) => !isDisabled(s), draw: (cell, v, s, state, ctx) => {
                const reported = diagField(s, 'mask_preset') || '';
                if (!live(s))
                    return fixedText(cell, state, reported || muted('not reported'));
                const current = maskPresets.find((p) => reported.startsWith(p));
                chooser(cell, state, {
                    options: maskPresets.map((p) => ({ value: p, label: p })), current, label: 'Apply',
                    onApply: (want) => want !== current && reopenAsk(ctx, s, { mask: want }, `Change the DIAG mask to ${want}?`,
                        want === 'full' ? 'full asks the modem for every log it offers: diagnosis, not wardriving.' : 'wardrive asks for the cell-survey logs.'),
                });
                replace(state.shown, reported ? el('b', {}, reported) : muted('not reported'));
            }, help: 'Which logs the modem is asked for.  The value shown is what the modem armed, as the helper reports it; changing it re-opens the source.' },
            { id: 'f3', title: 'Firmware debug', show: (v, s) => !isDisabled(s), draw: (cell, v, s, state, ctx) => {
                const reported = diagField(s, 'f3_preset') || '';
                if (!live(s))
                    return fixedText(cell, state, reported || muted('not reported'));
                const armed = reported.replace(/\+norelay$/, '');
                const current = f3Presets.find((p) => p === armed);
                chooser(cell, state, {
                    options: f3Presets.map((p) => ({ value: p, label: p })), current,
                    onApply: (want) => want !== current && reopenAsk(ctx, s, { f3: want }, `Firmware debug messages: ${want}?`, f3Notes[want]),
                });
                replace(state.shown, reported ? el('b', {}, reported) : muted('not reported'));
            }, help: 'The modem firmware\'s own debug messages (F3).  "+norelay" means armed, but none reach Kismet\'s messages.' },
            { id: 'raw', title: 'Raw DIAG kept', show: (v, s) => !isDisabled(s) && diagField(s, 'switches_reported'), draw: (cell, v, s, state, ctx) => {
                const on = !!diagField(s, 'rawpackets_on');
                const text = on ? `On: ${format.count(diagField(s, 'rawpackets_slices'))} slices in the kismetdb` +
                    (diagField(s, 'rawpackets_dropped') > 0 ? `, ${format.count(diagField(s, 'rawpackets_dropped'))} dropped` : '') :
                    'Off: the raw DIAG stream isn\'t kept';
                const key = `${on}|${text}`;
                if (state.key === key)
                    return;
                state.key = key;
                replace(cell, el('span', { class: 'ds-buttons' }, on ? text : muted(text),
                    el('button', { type: 'button', onclick: () => reopenAsk(ctx, s, { rawpackets: on ? 'off' : 'on' },
                        on ? 'Stop keeping raw DIAG?' : 'Keep raw DIAG?',
                        on ? 'Cells are still decoded, but a drive recorded without it can\'t be decoded again later.' :
                            'The whole DIAG stream is kept in the kismetdb again.') }, on ? 'Turn off' : 'Turn on')));
            } },
            { id: 'nas', title: 'NAS security checks', show: (v, s) => !isDisabled(s) && live(s), draw: (cell, v, s, state, ctx) => {
                const on = /^(true|on|1|yes)$/i.test(definitionOptions(s).nas ?? '');
                if (state.on === on)
                    return;
                state.on = on;
                replace(cell, el('span', { class: 'ds-buttons' }, on ? 'On' : muted('Off'),
                    el('button', { type: 'button', onclick: () => reopenAsk(ctx, s, { nas: on ? 'false' : 'true' },
                        on ? 'Stop reading NAS signalling?' : 'Read NAS signalling?',
                        on ? 'The NAS null-cipher and identity-request alerts stop.' :
                            'Adds the NAS signalling logs, for the NAS null-cipher and identity-request alerts.  Those messages carry ' +
                            'this modem\'s own IMSI, and they are kept in the kismetdb with the rest of the DIAG stream.') }, on ? 'Turn off' : 'Turn on')));
            }, help: 'The cell security alerts (null cipher, 2G redirect, odd identity requests).  RRC checks always run; NAS checks need these logs.' },
            { id: 'qsh', title: 'QSH trace', show: (v, s) => !isDisabled(s) && live(s) && diagField(s, 'switches_reported'), draw: (cell, v, s, state, ctx) => {
                const on = !!diagField(s, 'qsh_requested');
                const text = !on ? 'Off' : diagField(s, 'qsh_armed') ? 'Armed: high volume' :
                    'Asked for, not armed yet (it\'s armed during the bring-up; a modem without QSH declines it)';
                const key = `${on}|${text}`;
                if (state.key === key)
                    return;
                state.key = key;
                replace(cell, el('span', { class: 'ds-buttons' }, on ? span('warn-text', text) : muted(text),
                    el('button', { type: 'button', onclick: () => reopenAsk(ctx, s, { qsh: on ? 'off' : 'on' },
                        on ? 'Turn off the QSH trace?' : 'Turn on the QSH trace?',
                        on ? 'The modem\'s QSH setting is cleared when the source stops.' :
                            'Very high volume: the QSH trace set, its event stream, and every firmware print.  For development captures, not wardriving.') },
                    on ? 'Turn off' : 'Turn on')));
            } },
            { id: 'anchor', title: 'Clock anchors', show: (v, s) => !isDisabled(s) && live(s) && diagField(s, 'switches_reported'), draw: (cell, v, s, state, ctx) => {
                state.text ??= el('div');
                if (!state.input)
                    replace(cell, state.text);
                const last = diagField(s, 'anchor_last_epoch');
                replace(state.text, last > 0 ? `${format.count(diagField(s, 'anchor_count'))} sent, last ${ago(last)}` : muted('None yet'),
                    diagField(s, 'anchor_ring_dropped') > 0 ? span('warn-text', `, ${diagField(s, 'anchor_ring_dropped')} not delivered`) : null);
                cadenceInput(cell, state, { live: false, onSet: (v) => reopenAsk(ctx, s, { clock_anchor_sec: v },
                    `A clock anchor every ${v} s?`, v === '0' ? 'Only at start and stop.' : 'The modem clock is read against this computer\'s that often.') });
            }, help: 'Readings of the modem\'s clock against this computer\'s, so DIAG timestamps can be lined up later.' },
            { title: 'Log census', value: (s) => (isDisabled(s) ? null : s), format: (s) => {
                if (!(diagField(s, 'inventory_distinct_codes') > 0))
                    return muted('No census reported yet');
                const text = `${diagField(s, 'inventory_distinct_codes')} log kinds, ${diagField(s, 'inventory_unrecognized')} unrecognized, ` +
                    `${diagField(s, 'inventory_silent')} silent, ${diagField(s, 'inventory_undecoded_native') || 0} with a known layout not decoded yet`;
                return span(diagField(s, 'inventory_silent') > 0 ? 'error-text' : diagField(s, 'inventory_unrecognized') > 0 ? 'warn-text' : '', text);
            }, help: 'Every (log code, version) the modem sent.  "Silent" is a log Kismet depends on that decoded but gave nothing; ' +
                '"unrecognized" is usually new firmware.' },
            { id: 'census', title: 'Census detail', wide: true, value: (s) => (isDisabled(s) ? null : diagField(s, 'inventory_table')),
                show: (v) => !!v, format: (v, s) => {
                    const rows = String(v).split(';').filter(Boolean).map((r) => r.split(',')).filter((cells) => cells.length === 7);
                    const flags = (f) => [f.includes('s') && 'silent', f.includes('u') && 'unrecognized', f.includes('e') && 'enrich failed'].filter(Boolean);
                    return el('div', {},
                        el('table', { class: 'ds-census' },
                            el('tr', {}, ['Log', 'Records', 'Decoded', 'Dropped', 'Emitted', 'Enrich failed', ''].map((h) => el('th', {}, h))),
                            rows.map((cells) => el('tr', {}, cells.slice(0, 6).map((x) => el('td', {}, x)),
                                el('td', { class: cells[6].includes('s') ? 'error-text' : flags(cells[6]).length ? 'warn-text' : '' }, flags(cells[6]).join(', '))))),
                        hint(`Showing ${rows.length} of ${diagField(s, 'inventory_distinct_codes') || rows.length} log kinds.`));
                } },
            { title: 'Native decode', value: (s) => (isDisabled(s) || !(diagField(s, 'native_total_records') > 0) ? null : s), format: (s) => {
                const f = (k) => diagField(s, k);
                const pct = (100 * f('native_records') / f('native_total_records')).toFixed(1);
                return `${format.count(f('native_records'))} of ${format.count(f('native_total_records'))} records (${pct}%), ` +
                    `${format.count(f('native_obs'))} observations, ${format.count(f('native_enriched'))} enriched, ${format.count(f('native_gps_fixes'))} GNSS fixes, ` +
                    `${format.count(f('native_declined'))} declined, ${format.count(f('native_fallback_records'))} not read by any decoder`;
            } },
            { id: 'capture', title: 'Capture', draw: (cell, v, s, state, ctx) => captureSwitch(cell, s, state, ctx, isDisabled(s)) },
        ],
    });

    // ---- AT ------------------------------------------------------------

    const atField = (s, k) => s[`${at}.${k}`];

    function atState(s) {
        const state = atField(s, 'state');
        const iv = atField(s, 'stats_interval_s') || 5;
        const age = Math.max(0, now() - atField(s, 'stats_epoch'));
        if (state === 'disabled')
            return muted('Off (enabled=false): no port is open and nothing is captured.');
        if (state === 'full_scan') {
            const ran = Math.max(0, now() - atField(s, 'fullscan_started_epoch'));
            if (ran > fullScanMaxSeconds + 30)
                return span('error-text', icons.icon('alert'), ` A full band scan started ${Math.round(ran)} s ago, longer than any modem needs; the source may be stuck.`);
            return span('', `Full band scan, ${Math.round(ran)} s so far: the AT port is busy, so the other polls wait (up to ${fullScanMaxSeconds / 60} minutes).`);
        }
        if (age > 3 * iv)
            return span('warn-text', icons.icon('alert'), ` No status for ${Math.round(age)} s (expected every ${iv} s); the source may be stuck.`);
        return span('ok-text', 'Surveying');
    }

    const atReported = (s) => !!atField(s, 'stats_epoch');
    const atOn = (s) => atReported(s) && atField(s, 'state') !== 'disabled';

    ui.sourceSections.add({
        id: 'cellat', title: 'AT survey', priority: 5, drivers: ['cellat'],
        fields: [
            { title: 'Status', value: (s) => (atReported(s) ? atState(s) : muted('No status reported yet')) },
            { id: 'profile', title: 'Scan profile', show: (v, s) => atReported(s), draw: (cell, v, s, state, ctx) => {
                const profiles = parseStrategies(atField(s, 'strategies'));
                const cur = atField(s, 'strategy');
                const incapable = !atField(s, 'fullscan_capable');
                if (!profiles.length || atField(s, 'state') === 'disabled') {
                    state.select = null;
                    replace(cell, cur ? `${atField(s, 'strategy_label') || cur}` : muted('Not reported'));
                    return;
                }
                chooser(cell, state, {
                    options: profiles.map((p) => ({ value: p.name, disabled: p.fullScan > 0 && incapable,
                        label: p.label + (p.fullScan > 0 ? `, full scan every ${intervalText(p.fullScan * 1000)}` : '') +
                            (p.fullScan > 0 && incapable ? ' (this modem has no full scan)' : '') })),
                    current: cur,
                    onApply: (want) => want && want !== cur && ctx.busy(sources.setting(s[`${ds}.uuid`], `strategy=${want}`), 'Changing the profile...'),
                });
                replace(state.shown);
                replace(state.extra, hint(`Now: serving cell ${intervalText(atField(s, 'serving_interval_ms'))}, neighbors ` +
                    `${intervalText(atField(s, 'neighbor_interval_ms'))}, full scan ` +
                    `${atField(s, 'fullscan_interval_ms') ? `every ${intervalText(atField(s, 'fullscan_interval_ms'))}` : 'off'}.  ` +
                    'Changes apply at the next poll, without re-opening.'),
                atField(s, 'fullscan_interval_ms') > 0 && incapable ?
                    el('div', { class: 'warn-text' }, 'This modem has no full band scan command (AT+QSCAN or AT#CSURVC), so the full scan won\'t run.') : null);
            }, help: 'How often the modem is asked about the serving cell, its neighbors, and the whole band; the cell counterpart of hop or lock.' },
            { id: 'lock', title: 'Band / RAT lock', show: (v, s) => atOn(s), draw: (cell, v, s, state, ctx) => lockControl(cell, s, state, ctx) },
            { title: 'Cell observations', value: (s) => (atOn(s) ? (atField(s, 'obs_total') > 0 ?
                `${format.count(atField(s, 'obs_total'))} total, ${(atField(s, 'obs_per_sec') || 0).toFixed(2)}/s` : '0 so far') : null) },
            { title: 'Last observation', value: (s) => (atOn(s) ? (atField(s, 'last_obs_epoch') ? ago(atField(s, 'last_obs_epoch')) : muted('None yet')) : null) },
            { title: 'AT exchanges kept', value: (s) => (atOn(s) ? s : null), format: (s) => span('',
                `${format.count(atField(s, 'rawat_records'))} in the kismetdb (always on)`,
                atField(s, 'rawat_dropped') > 0 ? span('error-text', `, ${format.count(atField(s, 'rawat_dropped'))} dropped`) : null),
            help: 'Every command and answer, kept as RawAT records; kismetdb_to_atlog prints them.' },
            { id: 'anchor', title: 'Clock anchors', show: (v, s) => atOn(s), draw: (cell, v, s, state, ctx) => {
                state.text ??= el('div');
                if (!state.input)
                    replace(cell, state.text);
                const last = atField(s, 'anchor_last_epoch');
                replace(state.text, last ? `${format.count(atField(s, 'anchor_count'))} sent, last ${ago(last)}` :
                    muted('None yet (the modem hasn\'t answered AT+CCLK?)'));
                cadenceInput(cell, state, { live: true, onSet: (v) => ctx.busy(sources.setting(s[`${ds}.uuid`], `clock_anchor_sec=${v}`), 'Setting the cadence...') });
            } },
            { title: 'GPS', value: (s) => {
                const gps = definitionOptions(s).gps;
                if (!gps || /^(false|off|no|0)$/i.test(gps))
                    return null;
                return `The modem's fixes go to Kismet's GPS ${/^(true|on|yes|1)$/i.test(gps) ? '(cellmodem)' : `"${gps}"`}`;
            }, help: 'With gps= set, the modem\'s own GPS is turned on while the source runs and its fixes are a Kismet GPS.' },
            { title: 'Modem', value: (s) => {
                if (!atReported(s))
                    return null;
                const id = modemIdentity(s);
                if (id)
                    return id;
                const parts = [atField(s, 'model'), atField(s, 'firmware') && `firmware ${atField(s, 'firmware')}`,
                    atField(s, 'at_port') && `port ${atField(s, 'at_port')}`].filter(Boolean);
                return parts.length ? parts.join(' · ') : muted('Not reported');
            } },
            { id: 'capture', title: 'Capture', show: (v, s) => atReported(s),
                draw: (cell, v, s, state, ctx) => captureSwitch(cell, s, state, ctx, atField(s, 'state') === 'disabled') },
        ],
    });

    // The band / RAT lock: the lock presets the helper reported as the
    // source's channels, locked one at a time, or hopped through slowly with
    // Kismet's own channel hopping
    function lockControl(cell, s, state, ctx) {
        const uuid = s[`${ds}.uuid`];
        if (!atField(s, 'lock_capable')) {
            if (state.mode !== 'none')
                replace(cell, muted('Not available on this modem (locking works on Quectel, Sierra AT!SELRAT, and AT+WS46 modems)'));
            state.mode = 'none';
            return;
        }
        const chans = (s[`${ds}.channels`] ?? []).filter((ch) => ch !== 'AUTO');
        if (!chans.length) {
            if (state.mode !== 'off')
                replace(cell, muted('Locking is off for this source.'),
                    hint('Add bandlock=true to the source definition to turn it on.  A lock changes the modem\'s saved settings.'));
            state.mode = 'off';
            return;
        }
        if (state.mode !== 'on' || state.chans !== chans.join('|')) {
            state.mode = 'on';
            state.chans = chans.join('|');
            state.now = el('div');
            state.pick = el('select', {}, chans.map((ch) => el('option', { value: ch }, ch)));
            state.hopList = el('div', { class: 'ds-chan-grid' });
            state.hopSel = new Set();
            for (const ch of chans) {
                const b = el('button', { type: 'button', class: 'ds-chan', onclick: () => {
                    if (state.hopSel.has(ch))
                        state.hopSel.delete(ch);
                    else
                        state.hopSel.add(ch);
                    b.classList.toggle('on', state.hopSel.has(ch));
                } }, ch);
                state.hopList.append(b);
            }
            state.dwell = el('input', { type: 'number', min: 5, step: 1, value: 60, style: { width: '5em' } });
            replace(cell, state.now,
                el('span', { class: 'ds-buttons' }, state.pick,
                    el('button', { type: 'button', onclick: () => ctx.busy(sources.lock(uuid, state.pick.value), `Locking to ${state.pick.value}...`) }, 'Lock'),
                    el('button', { type: 'button', onclick: () => ctx.busy(sources.lock(uuid, 'AUTO'), 'Unlocking...') }, 'Unlock (settings as found)')),
                el('details', { class: 'ds-lock-hop' }, el('summary', {}, 'Hop through locks'),
                    state.hopList,
                    el('span', { class: 'ds-buttons', style: { marginTop: '0.3rem' } }, 'Dwell', state.dwell, 's on each',
                        el('button', { type: 'button', onclick: () => {
                            const list = chans.filter((ch) => state.hopSel.has(ch));
                            const sec = parseInt(state.dwell.value, 10);
                            if (list.length < 2 || !(sec >= 5)) {
                                ctx.message('Choose at least two locks and a dwell of 5 s or more.', 'error');
                                return;
                            }
                            ctx.busy(sources.hop(uuid, list, 1 / sec), 'Starting to hop...');
                        } }, 'Hop'))),
                hint('Each lock re-registers the modem (a few seconds without service), and is written to the modem\'s memory: the ' +
                    'settings as found are saved first and put back on Unlock, on close, and after a crash at the next open.'));
        }
        const ch = atField(s, 'lock_channel') || '';
        replace(state.now, ch === 'AUTO' ? 'AUTO: the settings as found' : ch ? el('b', {}, `Locked to ${ch}`) : muted('Unknown'),
            s[`${ds}.hopping`] ? span('muted', `, hopping ${(s[`${ds}.hop_channels`] ?? []).length} locks, ` +
                `${Math.round(1 / (s[`${ds}.hop_rate`] || 1))} s each`) : null,
            atField(s, 'lock_error') ? el('div', { class: 'error-text' }, atField(s, 'lock_error')) : null);
    }

    // ---- the modem as a whole ------------------------------------------

    const stateWord = (s) => {
        if (s[`${at}.state`] === 'disabled' || s[`${diag}.mask_preset`] === 'disabled')
            return 'capture off';
        if (s[`${ds}.error`])
            return 'error';
        return s[`${ds}.running`] ? 'capturing' : 'stopped';
    };

    function siblings(s, all) {
        const id = ifaceImei(s[`${ds}.interface`]);
        if (!id)
            return [];
        return all.filter((o) => ifaceImei(o[`${ds}.interface`])?.imei === id.imei)
            .sort((a, b) => sortKey(a[`${ds}.interface`]).localeCompare(sortKey(b[`${ds}.interface`])));
    }

    ui.sourceSections.add({
        id: 'cellmodem', title: 'This modem', priority: 6, drivers: cellDrivers,
        match: (s) => !!ifaceImei(s[`${ds}.interface`]),
        fields: [
            { id: 'modem', title: 'Sources', draw: (cell, v, s, state, ctx) => {
                const sibs = siblings(s, ctx.sources);
                const key = sibs.map((o) => `${o[`${ds}.uuid`]}:${stateWord(o)}`).join('|') + (sibs.find((o) => o[`${at}.lock_capable`])?.[`${at}.lock_channel`] ?? '');
                if (state.key === key)
                    return;
                state.key = key;
                const anyOn = sibs.some((o) => stateWord(o) !== 'capture off');
                const anyOff = sibs.some((o) => stateWord(o) === 'capture off');
                const atSrc = sibs.find((o) => o[`${at}.lock_capable`]);
                const all = (want, label) => el('button', { type: 'button', onclick: async () => {
                    if (!await confirm({ title: `${label}?`, ok: label, text: `Each of this modem's ${sibs.length} sources is closed and ` +
                        `opened again with enabled=${want}, one after another, so two bring-ups never race for the same ports.` }))
                        return;
                    ctx.busy((async () => {
                        for (const o of sibs)
                            await sources.reopenWith(o[`${ds}.uuid`], { enabled: want }).catch(() => {});
                    })(), `${label}...`);
                } }, label);
                replace(cell, 
                    el('div', {}, sibs.map((o) => el('div', {}, `${o[`${ds}.name`]} — ${captureLabel[driverOf(o)] ?? driverOf(o)}: ${stateWord(o)}`))),
                    atSrc ? el('div', {}, `Band / RAT lock: ${atSrc[`${at}.lock_channel`] || 'unknown'}`) : null,
                    el('span', { class: 'ds-buttons', style: { marginTop: '0.3rem' } },
                        anyOn ? all('false', 'Turn this modem off') : null, anyOff ? all('true', 'Turn this modem on') : null),
                    hint('All of this modem\'s capture sources (the same IMEI).  Off releases the ports and keeps the sources listed.'));
            } },
        ],
    });
}
