"use strict";

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.datasources.css'
    });



/* Drivers that capture cellular towers, and so earn the tower icon.
 *
 * One list shared by both sites, so the DIAG capture source cannot be silently
 * left out of one of them. */
const cell_driver_types = ['cellat', 'celldiag'];

function is_cell_driver(t) {
    return cell_driver_types.indexOf(t) !== -1;
}

/* Convert a hop rate to human readable */
export const hop_to_human = (hop) => {
    if (hop >= 1) {
        return parseFloat(hop.toFixed(2)) + "/second";
    }

    var m = hop * 60;

    if (m >= 1) {
        return parseFloat(m.toFixed(2)) + "/minute";
    }

    return "1 per " + parseFloat((1 / hop).toFixed(2)) + " seconds";
}

/* Convert a hop rate input value and unit to hops/sec; NaN if invalid */
const hop_input_to_rate = (value, unit) => {
    var v = parseFloat(value);

    if (!isFinite(v) || v <= 0)
        return NaN;

    if (unit == 'sec')
        return v;
    if (unit == 'min')
        return v / 60;
    if (unit == 'dwell')
        return 1 / v;

    return NaN;
}

/* Pick the most readable unit for a hop rate and return [value, unit] */
const hop_rate_to_input = (rate) => {
    if (rate >= 1)
        return [parseFloat(rate.toFixed(2)), 'sec'];
    if (rate * 60 >= 1)
        return [parseFloat((rate * 60).toFixed(2)), 'min'];
    return [parseFloat((1 / rate).toFixed(2)), 'dwell'];
}

/* ------------------------------------------------------------------------
 * celldiag operator stats panel
 *
 * The one rule this panel exists to obey: unreported must never render as
 * zero.
 *
 * The helper -> C stats path is careful about this: a key with no value is
 * omitted from the JSON rather than sent as ("", 0), because "rawlog_bytes: 0"
 * reads as "tee on, nothing written" and "inventory_unrecognized: 0" reads as
 * "every code recognised" -- both the opposite of the truth.
 *
 * That omission does not survive the trip to the browser. Kismet's tracker
 * serialises every registered field whether or not the source ever set it, so
 * an omitted key arrives here as the field's default: "" or 0. The distinction
 * therefore has to be re-derived JS-side, from sentinels that are actually
 * unambiguous:
 *
 *   rawlog_path === ""                 -> no tee was ever configured. A
 *                                         configured tee always resolves to a
 *                                         path, so the empty string cannot mean
 *                                         anything else. Do not read
 *                                         rawlog_bytes at all in this state.
 *   rawlog_active === 0, path !== ""   -> a tee that was configured and is
 *                                         stopped. `rawlog=off` closes the sink
 *                                         and keeps the path on purpose, so the
 *                                         operator can still find the file --
 *                                         which means the path answers "where
 *                                         did the bytes go?" and never "is it
 *                                         writing?". Reading the path for
 *                                         liveness would make this control a
 *                                         one-way toggle: once stopped, only
 *                                         "Stop tee" would ever render again.
 *   inventory_distinct_codes === 0     -> no census has counted anything yet.
 *                                         Any record at all creates a (code,
 *                                         version) key, so a census that has
 *                                         seen data reports >= 1. Its
 *                                         unrecognized/silent companions are
 *                                         meaningless until then and are not
 *                                         rendered.
 *   native_total_records === 0         -> the native shadow tap is off (the
 *                                         baseline build, which is the shipping
 *                                         configuration). Coverage is a ratio;
 *                                         rendering a numerator without its
 *                                         denominator is how a fraction becomes
 *                                         a percentage.
 *
 * Per-source scoping: every row is written through set_row(sdiv, ...), and sdiv
 * is the individual source's accordion div. A multi-modem host therefore gets
 * one panel per source with no cross-talk by construction -- there is no
 * shared/global element here to collide on.
 */

/* Seconds since an epoch stamp, or null if the stamp is the never-set sentinel.
 * 0 is not a plausible last-observation time; it means "no observation yet". */
export const celldiag_obs_age = (epoch, now_s) => {
    if (!epoch)
        return null;
    var age = now_s - epoch;
    return age < 0 ? 0 : age;
}

/* Human-readable byte count. Kept local rather than pulled from kismet.js so
 * this panel has no load-order dependency on it. */
const celldiag_bytes_human = (b) => {
    if (b < 1024)
        return b + " B";
    if (b < 1024 * 1024)
        return (b / 1024).toFixed(1) + " KB";
    if (b < 1024 * 1024 * 1024)
        return (b / (1024 * 1024)).toFixed(1) + " MB";
    return (b / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

/* Undo the UI's own escaping, for a string that is about to go through .text().
 *
 * Every datasource object reaches the panels through kismet.sanitizeObject,
 * which HTML-escapes & < > " ' ` = and / in every string. Kismet's own rows
 * append those strings as HTML, so the entities decode. A row that uses
 * .text() -- the XSS-safe choice, and the one these panels make -- prints them
 * literally instead: a path renders as `&#x2F;dev&#x2F;pts&#x2F;5`. Structural
 * tests cannot see this, because the value is right -- only its rendering is
 * not.
 *
 * Decoding back to plain text and then using .text() keeps both properties:
 * the operator reads the real path, and nothing is ever parsed as markup. */
const cell_unsanitize = (s) => {
    if (s === undefined || s === null || s === '')
        return '';
    return $('<textarea>').html(String(s)).text();
}

/* The modem a cell source is, as the modem itself answered AT+CGMI /
 * +CGMM / +CGMR / +CGSN when the source opened -- the helper's ModemIdentity
 * record, which the server keeps in `kismet.datasource.cell.modem_*` for both
 * celldiag and cellat. Plain text for .text(); null until a record arrives.
 *
 * Verbatim: an EG25-G says `Quectel EG25`, not `EG25-G`. The panel shows
 * what the modem said, the same string the .kismet keeps. */
export const cell_modem_identity_text = (source) => {
    const m = (k) => source['kismet.datasource.cell.modem_' + k];
    if (!m('identity_method'))
        return null;
    const parts = [];
    const name = [m('make'), m('model')].filter((v) => v)
        .map(cell_unsanitize).join(' ');
    if (name)
        parts.push(name);
    if (m('firmware'))
        parts.push('firmware ' + cell_unsanitize(m('firmware')));
    if (m('imei'))
        parts.push('IMEI ' + cell_unsanitize(m('imei')));
    if (m('at_port'))
        parts.push('port ' + cell_unsanitize(m('at_port')));
    let s = parts.join(' · ');
    /* An MHI celldiag source whose AT node the paired cellat source holds
     * cannot ask the modem; say so rather than presenting the IMEI it was
     * addressed by as something the modem reported. */
    if (m('identity_method') === 'definition')
        s += ' (not identified over AT -- this is the IMEI the source was ' +
             'addressed by; its cellat source names the modem)';
    return s;
};

/* Keep a control's row out of the 1 s panel refresh while the operator is
 * using it.
 *
 * update_datasource2 re-renders every row every second, and set_row replaces
 * the cell. A control in that cell is therefore a new element each second:
 * without this hold, a profile chosen and not yet applied snaps back to the
 * armed one, and a path typed into "Start AT log" is wiped, within seconds.
 * The same applies to the celldiag mask/F3 selectors and raw-tee input.
 *
 * The control marks its <tr> on focus / change / input, and set_row skips a
 * marked row. The mark is cleared when the control acts (cell_release_row) or
 * when it loses focus while still pristine -- the value unchanged from what
 * the source reports -- so an abandoned control never freezes a row for good.
 * While a row is held its readback text is held too; the edit is the
 * operator's, and it is theirs to apply or undo. */
const cell_hold_row = (el, is_pristine) => {
    el.on('focus change input', () => el.closest('tr').data('cell-editing', true));
    el.on('blur', () => {
        if (is_pristine())
            el.closest('tr').removeData('cell-editing');
    });
    return el;
}

const cell_release_row = (el) => {
    el.closest('tr').removeData('cell-editing');
}

/* The italic "we have no value for this" rendering. One function so the panel
 * cannot drift into spelling absence three different ways -- and so a reviewer
 * can grep for every place absence is rendered. */
const celldiag_nodata = (why) => {
    return $('<i>').text(why);
}

/* True if this source is a celldiag source at all. Keyed on a field only
 * datasource_cell_diag registers, so every other datasource type skips the
 * whole panel rather than rendering a table of zeros. */
export const is_celldiag_source = (source) => {
    return 'kismet.datasource.celldiag.helper_alive' in source;
}

/* The raw-save toggle.
 *
 * This control deliberately does not report its own success. Three
 * independent reasons:
 *
 * 1. A refused setting comes back with `success = 1`. The framework maps only a
 *    negative chancontrol_cb return to failure on the wire, and a negative
 *    return also sets `spindown` -- so reporting a typo through the status code
 *    would end a running wardrive. celldiag returns 0 and puts the reason in
 *    the message. A control that rendered the HTTP status would show every
 *    rejection as applied.
 * 2. The reason cannot reach us over HTTP anyway. `datasourcetracker.cc`'s
 *    set_channel route takes `(t, success, e)` from the completion callback and
 *    keeps only `success` -- `e`, the message, is discarded before the response
 *    is built. There is no field to read.
 * 3. What the reason does reach is the Kismet message bus, as a MSGFLAG_ERROR
 *    line (capture-side cf_send_message -> kis_datasource::handle_msg_proxy ->
 *    _MSG), which the operator already has open.
 *
 * So the control confirms itself from the fields instead: `rawlog_path` and
 * `rawlog_bytes` are re-reported on every stats interval, and the row above
 * renders them live. A tee that actually started shows a path and a rising byte
 * count within one interval; one that was refused does not change. That is a
 * measurement of the thing itself rather than an ack from the transport. */
const celldiag_rawlog_control = (source, f) => {
    const uuid = source['kismet.datasource.uuid'];
    /* Liveness, not retention. `rawlog_path` is deliberately retained across
     * a `rawlog=off` so the operator can still find the file, so keying on it
     * would offer only "Stop tee" after one stop, forever. `rawlog_active` is
     * the sink's fd, published for exactly this. An unreported field arrives as 0, which is the correct
     * reading in the only state that produces it: no tee configured. */
    const on = !!f('rawlog_active');

    const send = (value) => {
        const cmd = { "channel": value };
        $.ajax({
            url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
            method: 'POST',
            data: "json=" + encodeURIComponent(JSON.stringify(cmd)),
            dataType: 'json',
            timeout: 30000,
        });
    };

    const wrap = $('<span>', { style: 'margin-left: 1em;' });

    if (on) {
        wrap.append($('<button>').text('Stop tee')
            .on('click', (e) => { cell_release_row($(e.target)); send('rawlog=off'); }));
    } else {
        const inp = $('<input>', {
            type: 'text', size: 28,
            placeholder: '/path/or/dir/ (%i %m %t)',
        });
        cell_hold_row(inp, () => (inp.val() || '').trim() === '');
        wrap.append(inp);
        wrap.append($('<button>').text('Start tee')
            .on('click', () => {
                const v = (inp.val() || '').trim();
                if (v === '')
                    return;
                cell_release_row(inp);
                send('rawlog=' + v);
            }));
    }

    /* Stated in the UI, not just in this comment. An operator who clicks and
     * sees nothing change needs to know where the reason went, or the honest
     * design above reads as a broken button. */
    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('Result appears in the row above within one stats interval; ' +
              'a refusal is reported on the message bus, not here.'));
    return wrap;
}

/* The mask-preset selector.
 *
 * Why this is not the rawlog toggle with a different string: `mask=` is
 * declined at runtime by the capture binary. Applying it re-issues a
 * LOG_CONFIG / SET_ALL_RT_MASKS handshake to the modem, on the same DIAG fd
 * `capture_thread` is blocked reading, from the framework's command thread. So
 * it is a bring-up option, and changing it means the source really does go
 * down and come back.
 *
 * close_source + open_source alone cannot do it. `open_source.cmd` re-opens
 * with `ds->get_source_definition()`, the string the source already has, so
 * close-then-reopen faithfully restores the same mask. The
 * `update_definition.cmd` route this posts to changes the definition, driving
 * parse_source_definition's folding of source_override_opts.
 *
 * Sequence: close_source -> update_definition -> open_source. The close must
 * be first. The route refuses a running source (`get_source_running()` ->
 * 500, "close_source first, then update_definition, then open_source"), so an
 * update-first chain fails on its very first call, and jQuery's `.then()` only
 * chains on resolve: the close and the open never happen.
 *
 * The reopen is `.always()`, not `.then()`. Closing first means the source is
 * down when the call that can fail is made (a rejected option, a source that
 * vanished). A reopen chained on success would leave the operator's capture
 * down and -- since this control reads nothing from the transport -- silent,
 * which is strictly worse than the button doing nothing. The invariant is "the
 * source always comes back up", and the sticky override from an earlier
 * successful Apply survives it.
 *
 * The steps chain because they are ordered -- you cannot update before the
 * close completes -- but the outcome is still not read from the transport. As
 * with the rawlog control, the answer is the `mask_preset` field re-reported
 * one row above on the next stats interval, which is the binary saying what it
 * actually armed ("wardrive", "full", "wardrive+f3", "passive") rather than
 * the server saying a request was accepted.
 *
 * A confirmation prompt, which the rawlog toggle deliberately does not have:
 * this one interrupts capture. */
const CELLDIAG_MASK_PRESETS = ['wardrive', 'full'];

const celldiag_mask_control = (source, f) => {
    const uuid = source['kismet.datasource.uuid'];
    /* The binary decorates the label ("wardrive+f3", "passive"), so match on
     * the preset it starts with rather than on equality -- an exact compare
     * leaves the selector showing `wardrive` for a source running `full+f3`. */
    const reported = f('mask_preset') || '';
    const current = CELLDIAG_MASK_PRESETS.find((p) => reported.startsWith(p));

    const sel = $('<select>');
    CELLDIAG_MASK_PRESETS.forEach((p) => {
        const o = $('<option>', { value: p }).text(p);
        if (p === current)
            o.attr('selected', 'selected');
        sel.append(o);
    });

    cell_hold_row(sel, () => sel.val() === current);
    const wrap = $('<span>', { style: 'margin-left: 1em;' });
    wrap.append(sel);
    wrap.append($('<button>').text('Apply (restarts source)')
        .on('click', () => {
            const want = sel.val();
            if (want === current)
                return;
            if (!window.confirm(
                    `Change the DIAG mask preset to '${want}'?\n\n` +
                    'This CLOSES and RE-OPENS the source. Capture stops for ' +
                    'the duration of the restart, and a modem that fails to ' +
                    're-open leaves the source down.'))
                return;

            cell_release_row(sel);
            const base = `${local_uri_prefix}datasource/by-uuid/${uuid}/`;
            $.get(base + 'close_source.cmd')
             .then(() => $.ajax({
                url: base + 'update_definition.cmd',
                method: 'POST',
                data: "json=" + encodeURIComponent(
                    JSON.stringify({ "options": { "mask": want } })),
                dataType: 'json',
                timeout: 30000,
             }))
             .always(() => $.get(base + 'open_source.cmd'));
        }));

    /* Said in the UI, because a control whose result appears elsewhere reads
     * as broken otherwise -- the same reason the rawlog control carries one. */
    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('The row above shows the preset the modem actually armed, ' +
              'within one stats interval after the source re-opens. ' +
              'A refusal is reported on the message bus, not here.'));
    return wrap;
}

/* The F3 severity selector.
 *
 * Same route and same three-step sequence as the mask selector above, because
 * `f3=` is a bring-up option for the identical reason: `diag_optset.c` lists it
 * `runtime = 0`, and its decline text says applying one means re-issuing
 * SET_ALL_RT_MASKS on the DIAG fd `capture_thread` is blocked reading.
 *
 * It is not a copy of the mask control, in one way that matters and one that
 * is worth stating:
 *
 * 1. The compare is equality, not `startsWith`. `mask_preset` is a decorated
 *    label -- the binary appends "+f3" / "+f3:error" and reports "passive"
 *    under nomask= -- which is the whole reason that control matches on a
 *    prefix. `f3_preset` is the resolved preset name, one of exactly
 *    `off|all|high|error` (capture_cell_diag.c: `sx->f3_preset = ...`), with
 *    one possible decoration: `<preset>+norelay`, a preset the modem armed
 *    while the relay is unavailable, so nothing reaches the message bus. The
 *    selector removes exactly that suffix and then compares by equality.
 *    Without that, no option matches `high+norelay`, the browser shows `off`
 *    as armed, and Apply restarts the source even for the preset already
 *    armed. The row above keeps the decoration, which is the operator's honest
 *    readout. `startsWith` would also pass today, since no preset is a prefix
 *    of another, but only by coincidence. The equality is the claim being
 *    made.
 *
 * 2. Applying this changes the row above too. F3 arming is what decorates
 *    `mask_preset`, so moving off->high renders "wardrive" as "wardrive+f3:high"
 *    one interval later. That is the binary reporting accurately, not the mask
 *    selector losing its value.
 *
 * The offered set is the canonical spellings only. The binary also accepts
 * `none` as an alias, and canonicalises it to `off` on the way out
 * (`f3_preset_lookup`), so offering both would put two options in the list that
 * can never be told apart in the report.
 *
 * `all` is a firehose -- millions of records in a real capture -- so its
 * confirmation says so. The presets are subtractive from `all`, and the
 * retention figures are measured on real captures, not inferred from the
 * names.
 *
 * As with the mask selector: close_source first (the route refuses a running
 * source), the reopen is `.always()` so a rejected update cannot leave the
 * source down, the calls chain because they are ordered, and they still report
 * nothing from the transport. A refused celldiag setting returns success=1,
 * so the outcome is `f3_preset`, re-reported one row up on the next stats
 * interval.
 *
 * Unlike `mask_preset`, this one is verifiable offline: `f3_preset` is
 * resolved before the live/replay split in `capture_cell_diag.c`, so a
 * `replay=` source reports it honestly (a replay source hard-codes
 * `mask_preset` to the literal "replay"). That lets this shared route be
 * exercised on a live server without a modem. */
const CELLDIAG_F3_PRESETS = ['off', 'error', 'high', 'all'];

/* The one decoration `f3_preset` can carry: armed, not relayed. */
const CELLDIAG_F3_NORELAY = '+norelay';

const CELLDIAG_F3_BLURB = {
    'off':   'the MSG/EXT_MSG handshake is not sent at all',
    'error': 'drops sites that only print below ERROR (~68% of records kept)',
    'high':  'drops sites that only print at LOW/MED (~94% of records kept)',
    'all':   'EVERY subsystem at every severity — a firehose, for diagnosis',
};

const celldiag_f3_control = (source, f) => {
    const uuid = source['kismet.datasource.uuid'];
    /* Equality, after removing the one decoration: see (1) above. */
    const reported = f('f3_preset') || '';
    const armed = reported.endsWith(CELLDIAG_F3_NORELAY)
        ? reported.slice(0, -CELLDIAG_F3_NORELAY.length) : reported;
    const current = CELLDIAG_F3_PRESETS.find((p) => armed === p);

    const sel = $('<select>');
    CELLDIAG_F3_PRESETS.forEach((p) => {
        const o = $('<option>', { value: p }).text(p);
        if (p === current)
            o.attr('selected', 'selected');
        sel.append(o);
    });

    cell_hold_row(sel, () => sel.val() === current);
    const wrap = $('<span>', { style: 'margin-left: 1em;' });
    wrap.append(sel);
    wrap.append($('<button>').text('Apply (restarts source)')
        .on('click', () => {
            const want = sel.val();
            if (want === current)
                return;
            if (!window.confirm(
                    `Change the F3 debug preset to '${want}'?\n\n` +
                    `${CELLDIAG_F3_BLURB[want]}\n\n` +
                    'This CLOSES and RE-OPENS the source. Capture stops for ' +
                    'the duration of the restart, and a modem that fails to ' +
                    're-open leaves the source down.'))
                return;

            cell_release_row(sel);
            const base = `${local_uri_prefix}datasource/by-uuid/${uuid}/`;
            $.get(base + 'close_source.cmd')
             .then(() => $.ajax({
                url: base + 'update_definition.cmd',
                method: 'POST',
                data: "json=" + encodeURIComponent(
                    JSON.stringify({ "options": { "f3": want } })),
                dataType: 'json',
                timeout: 30000,
             }))
             .always(() => $.get(base + 'open_source.cmd'));
        }));

    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('The row above shows the preset the modem actually armed, ' +
              'within one stats interval after the source re-opens. ' +
              'The DIAG mask row also changes, because F3 arming decorates ' +
              'that label. A refusal is reported on the message bus, not here.'));
    return wrap;
}

/* Restart.
 *
 * Why there is no enable or disable button here: `update_datasource2` builds
 * `pausediv` for every source unconditionally and renders it as the "Active"
 * row, so Activate / Close / Disable already ship for celldiag. Adding
 * celldiag-specific duplicates would give an operator two controls for one
 * action that can disagree about which is lit. Only restart is absent.
 *
 * A restart is not "click Close, then click Activate". Those are two
 * independent async requests; by hand there is nothing that makes the open wait
 * for the close, so an operator who clicks quickly re-opens against a source
 * that is still tearing down its helper and its DIAG fd. Chaining on the
 * responses is the entire value of this control -- the ordering, not the
 * clicking.
 *
 * It is deliberately the same sequence the mask and F3 selectors already end
 * with, minus the definition update. Not new machinery: the existing restart
 * exposed without a config change, so there is one code path for "take the
 * source down and bring it back" rather than two that can drift.
 *
 * Offered only while the source is running. Restarting something that is not
 * running is an Activate, and that button already exists two rows down; worse,
 * on a source the operator explicitly Disabled it would quietly undo that.
 *
 * Reports nothing from the transport, same rule as the selectors: the outcome
 * is `kismet.datasource.running` plus celldiag's own `helper_alive` and
 * `mask_preset`, re-reported on the next stats interval. A helper that fails to
 * respawn shows as helper=DEAD in the first row, which is the measurement. */
const celldiag_restart_control = (source) => {
    const uuid = source['kismet.datasource.uuid'];
    const wrap = $('<span>');

    if (!source['kismet.datasource.running']) {
        wrap.append($('<span>', { style: 'color: #666;' })
            .text('Source is not running — use Activate on the ' +
                  'Active row rather than restarting.'));
        return wrap;
    }

    wrap.append($('<button>').text('Restart source')
        .on('click', () => {
            if (!window.confirm(
                    'Restart this celldiag source?\n\n' +
                    'The DIAG port is released, the decode helper is torn ' +
                    'down, and both are rebuilt — the LOG_CONFIG handshake ' +
                    'is re-issued to the modem on re-open. Capture stops for ' +
                    'the duration.\n\n' +
                    'A modem that re-enumerated its USB device may come back ' +
                    'on a different node; if the re-open fails the source is ' +
                    'left DOWN.'))
                return;

            const base = `${local_uri_prefix}datasource/by-uuid/${uuid}/`;
            /* Chained, not fired together: the open must not start until the
             * close has returned. This is the ordering guarantee two manual
             * clicks cannot make. */
            $.get(base + 'close_source.cmd')
             .then(() => $.get(base + 'open_source.cmd'));
        }));

    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('The decode-helper and mask rows above report the outcome ' +
              'within one stats interval. A failure to re-open is reported ' +
              'on the message bus, not here.'));
    return wrap;
}

/* The capture switch -- the source's `enabled=` setting, from the UI.
 * Shared by the celldiag and cellat panels.
 *
 * Why it exists: a source defined `enabled=false` opens, idles, and shows as
 * running. Activate does nothing (it is already open), and Close -> Activate
 * and Restart all re-open the same definition, so without this switch the
 * only way to capture is to edit the config and restart Kismet.
 *
 * It is not Kismet's "Disable". The generic Active row's Disable closes the
 * source and marks it errored ("Source disabled"). This switch keeps the
 * source listed, running and on its UUID, and changes only whether it touches
 * the modem: on = port opened and capture running; off = port released,
 * nothing captured. Because these are two different "offs", this control
 * names itself by the option it sets, and never calls disable_source.cmd
 * (which would also give the Active row's buttons a second, disagreeing
 * control).
 *
 * The sequence is the one the mask and F3 selectors use, for the same reasons:
 * close first (update_definition refuses a running source), and the reopen is
 * `.always()` so a rejected update can never leave the source down. The
 * outcome is read from the fields on the next stats line, never from the
 * transport. */
const cell_capture_switch_control = (source, disabled_now) => {
    const uuid = source['kismet.datasource.uuid'];
    const want = disabled_now ? 'true' : 'false';
    const wrap = $('<div>');

    wrap.append($('<button>')
        .text(disabled_now ? 'Enable capture' : 'Disable capture (keep the source)')
        .on('click', () => {
            const prompt = disabled_now ?
                'Enable capture on this source?\n\n' +
                'It is closed and re-opened with enabled=true: the modem port ' +
                'is opened and the full bring-up runs (AT probe, or the DIAG ' +
                'handshake and decode helper).' :
                'Disable capture on this source?\n\n' +
                'It is closed and re-opened with enabled=false: it stays ' +
                'listed, but the modem port is released and nothing is ' +
                'captured until it is enabled again.';
            if (!window.confirm(prompt))
                return;

            const base = `${local_uri_prefix}datasource/by-uuid/${uuid}/`;
            $.get(base + 'close_source.cmd')
             .then(() => $.ajax({
                url: base + 'update_definition.cmd',
                method: 'POST',
                data: "json=" + encodeURIComponent(
                    JSON.stringify({ "options": { "enabled": want } })),
                dataType: 'json',
                timeout: 30000,
             }))
             .always(() => $.get(base + 'open_source.cmd'));
        }));

    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('Sets this source\'s enabled= option. Not the same as Disable on ' +
              'the Active row, which stops the source itself. The rows above ' +
              'report the new state within one stats interval; a failure is ' +
              'reported on the message bus.'));
    return wrap;
}

/* Re-open a source with changed bring-up options.
 *
 * The one sequence every restart-to-apply control uses, for the reasons the
 * mask/F3 selectors and the Capture switch spell out: close first
 * (update_definition refuses a running source), and the reopen is `.always()`
 * so a rejected update can never leave the source down. Nothing is read from
 * the transport; the panel rows report the outcome on the next stats line.
 * Pinned by celltools/tests/test_cell_enable_form.py. */
const cell_reopen_with_options = (uuid, options) => {
    const base = `${local_uri_prefix}datasource/by-uuid/${uuid}/`;
    $.get(base + 'close_source.cmd')
     .then(() => $.ajax({
        url: base + 'update_definition.cmd',
        method: 'POST',
        data: "json=" + encodeURIComponent(JSON.stringify({ "options": options })),
        dataType: 'json',
        timeout: 30000,
     }))
     .always(() => $.get(base + 'open_source.cmd'));
}

/* Raw DIAG into the kismetdb (rawpackets=). A restart, not a
 * runtime setting: the stream is sliced from the first byte of a session, and
 * a mid-session switch would leave a stream with a hole the readers cannot
 * tell from a loss. */
const celldiag_rawpackets_control = (source, f) => {
    const on = !!f('rawpackets_on');
    return $('<button>').text(on ? 'Turn off (restart)' : 'Turn on (restart)')
        .on('click', () => {
            if (!window.confirm((on ?
                    'Stop keeping the raw DIAG stream in the kismetdb?\n\n' +
                    'Decoded cells are still captured, but a drive recorded ' +
                    'without it cannot be re-decoded later.' :
                    'Keep the raw DIAG stream in the kismetdb again?') +
                    '\n\nThe source is closed and re-opened (a few seconds of ' +
                    'capture are lost).'))
                return;
            cell_reopen_with_options(source['kismet.datasource.uuid'],
                                     { rawpackets: on ? 'off' : 'on' });
        });
}

/* The QSH / full-F3 tier (qsh=). Off by default and a volume
 * risk, so the confirm says so; the helper disarms it on stop. */
const celldiag_qsh_control = (source, f) => {
    const on = !!f('qsh_requested');
    return $('<button>').text(on ? 'Disarm (restart)' : 'Arm (restart)')
        .on('click', () => {
            if (!window.confirm(on ?
                    'Disarm the QSH trace tier?\n\nThe source is closed and ' +
                    're-opened; the modem\'s QSH latch is cleared on the stop.' :
                    'Arm the QSH trace tier (the full F3 surface)?\n\n' +
                    'VERY HIGH VOLUME: the QSH trace mask set, the event stream ' +
                    'and every F3 print. Meant for a development or corpus ' +
                    'drive, not a wardrive. The source is closed and re-opened.'))
                return;
            cell_reopen_with_options(source['kismet.datasource.uuid'],
                                     { qsh: on ? 'off' : 'on' });
        });
}

/* The ClockAnchor cadence (celldiag). celldiag takes it at
 * bring-up only, so this is a restart; cellat changes it live. */
const celldiag_anchor_control = (source) => {
    const wrap = $('<span>', { style: 'margin-left: 8px;' });
    const inp = $('<input>', { type: 'number', min: 0, step: 1, style: 'width: 5em;',
                               placeholder: 'sec' });
    cell_hold_row(inp, () => (inp.val() || '').trim() === '');
    wrap.append(inp).append($('<button>').text('Set cadence (restart)')
        .on('click', () => {
            const v = (inp.val() || '').trim();
            if (!/^\d+$/.test(v))
                return;
            cell_release_row(inp);
            if (!window.confirm('Re-open this source with a clock anchor every ' +
                    v + ' s' + (v === '0' ? ' (periodic off; start and stop still ' +
                    'anchor)' : '') + '?'))
                return;
            cell_reopen_with_options(source['kismet.datasource.uuid'],
                                     { clock_anchor_sec: v });
        }));
    return wrap;
}

/* The bring-up row: what the deferred bring-up is doing, what it
 * finished, and -- the reason this exists -- why it failed. */
const celldiag_bringup_text = (f) => {
    const phases = cell_unsanitize(f('bringup_phases') || '');
    if (f('bringup_error')) {
        return $('<span>', { style: 'color: #b00;' })
            .html('<i class="fa fa-exclamation-circle"></i> ')
            .append($('<span>').text('failed after ' + (f('bringup_ms') || 0) +
                ' ms: ' + cell_unsanitize(f('bringup_error')) +
                (phases ? '  [completed: ' + phases + ']' : '')));
    }
    if (f('mask_preset') === 'opening') {
        return $('<span>')
            .html('<i class="fa fa-spinner"></i> ')
            .append($('<span>').text('opening the modem' +
                (phases ? ' — done so far: ' + phases : ' — no step finished yet')));
    }
    if (phases)
        return $('<span>', { style: 'color: #666;' }).text(
            'took ' + (f('bringup_ms') || 0) + ' ms: ' + phases);
    return null;
}

/* ---------------------------------------------------------------------------
 * Cell discovery rows and the Enable form
 *
 * The Wi-Fi flow this matches: open Data Sources, see every capturable thing
 * as an "Available Interface", pick options, Enable. A bare cell row would read
 * "Available Interface: cellat-351234567890123 (cellat)", and a bare
 * `<iface>:type=<driver>` Enable lets nothing be chosen at bring-up.
 * ------------------------------------------------------------------------- */

/* What each cell driver captures, in an operator's words. */
export const CELL_CAPTURE_LABEL = { cellat: 'AT commands', celldiag: 'DIAG' };

const cell_sibling_driver = (t) => (t === 'cellat' ? 'celldiag' : 'cellat');

/* `cellat-<IMEI>` / `celldiag-<IMEI>` -> {driver, imei}; null otherwise. */
export const cell_iface_imei = (iface) => {
    const m = /^(cellat|celldiag)-(\d{15})$/.exec(iface || '');
    return m ? { driver: m[1], imei: m[2] } : null;
}

/* Split a lister's hardware label into its parts.
 *
 * The label is built by one function, modemident_label() in
 * capture_cell_diag/diag_modemident.c, for both helpers:
 *
 *     "<make> <model> (<firmware>) IMEI:<imei>"   the modem named itself
 *     "<firmware> IMEI:<imei>"                    it did not (no +CGMI/+CGMM)
 *     "<make> <model> IMEI:<imei>"                no +CGMR
 *
 * with " DIAG" appended by celldiag's lister. Without the parentheses the head
 * is ambiguous; a firmware string has no spaces and a make + model does, so
 * that decides it. Anything else returns null and the caller shows the string
 * verbatim -- a label this does not understand is never guessed at. */
export const cell_parse_label = (hw) => {
    const s = cell_unsanitize(hw || '').trim().replace(/\s+DIAG$/, '');
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

/* Display-only short forms of the modem's own AT+CGMI answer. The kismetdb
 * keeps the answer verbatim; this only keeps a row title readable. */
const CELL_MAKE_SHORT = [
    [/^sierra wireless[, ]*(incorporated|inc\.?)?\s*/i, 'Sierra Wireless '],
    [/^simcom( incorporated| wireless solutions[^ ]*)?\s*/i, 'SIMCom '],
];
const cell_short_name = (name) => {
    let n = name;
    CELL_MAKE_SHORT.forEach(([re, to]) => { n = n.replace(re, to); });
    return n.trim();
}

/* "Quectel RM520N-GL — AT commands": the row title an operator chooses by. */
export const cell_row_title = (parsed, driver) => {
    const what = parsed ? (cell_short_name(parsed.name) || parsed.firmware) : '';
    return (what || 'Cell modem') + ' — ' + (CELL_CAPTURE_LABEL[driver] || driver);
}

/* The modem label of a running source, in the lister's format, from the
 * ModemIdentity fields -- so a synthesized row parses like a real one. */
const cell_source_label = (source) => {
    const m = (k) => cell_unsanitize(source['kismet.datasource.cell.modem_' + k] || '');
    const name = [m('make'), m('model')].filter((x) => x !== '').join(' ');
    const id = cell_iface_imei(source['kismet.datasource.interface']);
    if (!id)
        return '';
    if (name && m('firmware'))
        return `${name} (${m('firmware')}) IMEI:${id.imei}`;
    return `${name || m('firmware')} IMEI:${id.imei}`.trim();
}

/* A cell source is holding its modem's port: open, and not enabled=false. */
const cell_source_holds_port = (source) => {
    if (!source['kismet.datasource.running'])
        return false;
    if (source['kismet.datasource.cellat.state'] === 'disabled')
        return false;
    if (source['kismet.datasource.celldiag.mask_preset'] === 'disabled')
        return false;
    return true;
}

/* The rows the listers could not report, derived from the sources.
 *
 * A cell lister skips any port another process holds -- correct, it is what
 * stops two sources corrupting each other's AT reads -- so while one of a
 * modem's sources is capturing, the modem can drop out of its sibling
 * driver's list. An operator then sees "DIAG" vanish the moment they
 * enable "AT commands" and concludes the modem has no DIAG. So for every cell
 * source holding its port whose sibling is neither listed nor already a
 * source, a row is added that says why it is not in the list, and still offers
 * Enable: both drivers address a modem by IMEI, and a celldiag source opens
 * with its AT port held by its sibling.
 *
 * The synthetic row carries `cell_unlisted` (the reason) and is otherwise
 * shaped like a list answer, so one render path draws both. */
export const cell_augment_interfaces = (intfs, sources) => {
    const listed = new Set((intfs || []).map((i) => i['kismet.datasource.probed.interface']));
    const defined = new Set((sources || []).map((s) => s['kismet.datasource.interface']));
    const extra = [];
    (sources || []).forEach((s) => {
        const t = s['kismet.datasource.type_driver']['kismet.datasource.driver.type'];
        const id = cell_iface_imei(s['kismet.datasource.interface']);
        if (!is_cell_driver(t) || id === null || !cell_source_holds_port(s))
            return;
        const sib = cell_sibling_driver(t);
        const sib_iface = `${sib}-${id.imei}`;
        if (listed.has(sib_iface) || defined.has(sib_iface))
            return;
        listed.add(sib_iface);
        extra.push({
            'kismet.datasource.probed.interface': sib_iface,
            'kismet.datasource.probed.in_use_uuid': '00000000-0000-0000-0000-000000000000',
            'kismet.datasource.probed.hardware': cell_source_label(s),
            'kismet.datasource.type_driver': {
                'kismet.datasource.driver.type': sib,
                'kismet.datasource.driver.description':
                    sib === 'cellat' ? 'Cellular modem (AT commands)' : 'Cellular modem (Qualcomm DIAG)',
            },
            cell_unlisted: sib === 'celldiag' ?
                'Not in the DIAG list right now: the running AT source "' +
                    cell_unsanitize(s['kismet.datasource.name']) + '" holds the AT ' +
                    'port the DIAG lister identifies a modem by. Enable still ' +
                    'works; DIAG is addressed by IMEI.' :
                'Not in the AT list right now: the running DIAG source "' +
                    cell_unsanitize(s['kismet.datasource.name']) + '" is capturing ' +
                    'from this modem and may be holding the port the AT lister ' +
                    'reads. Enable will try; if the port is held, the open fails ' +
                    'and says so here.',
        });
    });
    return (intfs || []).concat(extra);
}

/* One modem's rows sort together, AT first: `cell-<imei>-0at` / `-1diag`. */
export const cell_sort_key = (iface) => {
    const id = cell_iface_imei(iface);
    return id ? `cell-${id.imei}-${id.driver === 'cellat' ? '0at' : '1diag'}` : iface;
}

/* The scan profiles cellat accepts, in the order the panel offers them.
 * Mirrors STRATEGIES[] in capture_cell_at/cellat_options.c; pinned by
 * celltools/tests/test_cell_enable_form.py, because two lists that must
 * agree drift. A running source reports its own table instead
 * (cellat_profile_control); this list exists only for a source not yet open. */
export const CELLAT_ENABLE_PROFILES = [
    ['driving', 'Driving'],
    ['walking', 'Walking'],
    ['stationary', 'Stationary survey'],
    ['serving_only', 'Serving cell only'],
];

/* Build the definition the Enable button sends.
 *
 * Returns {definition} or {error}. Only options the operator changed from the
 * driver's default are written, so a plain Enable sends a bare
 * `<iface>:type=<driver>` and the defaults stay the helper's to decide. A
 * value with a comma is refused: the definition's option separator is a comma,
 * and Kismet would split the value into a second, unknown option. */
export const cell_enable_definition = (iface, driver, opts) => {
    const parts = [];
    for (const [k, v] of opts) {
        const val = String(v).trim();
        if (val === '')
            continue;
        if (val.indexOf(',') >= 0)
            return { error: `${k}= cannot contain a comma (it separates options): ${val}` };
        parts.push(`${k}=${val}`);
    }
    return { definition: `${iface}:type=${driver}` + (parts.length ? ',' + parts.join(',') : '') };
}

/* The Enable form for one cell row. Built once per row and re-attached on
 * every refresh (a jQuery append moves the same elements), so a choice the
 * operator is making survives the 3 s list refresh (see cell_hold_row for the
 * same problem in the panels). */
const cell_enable_form = (idiv, iface, driver, on_done) => {
    let form = idiv.data('cell-enable-form');
    if (form)
        return form;

    const hint = (t) => $('<div>', { style: 'font-size: 0.85em; color: #666;' }).text(t);
    const row = (label, ctl, help) => $('<div>', { style: 'margin: 3px 0;' })
        .append($('<label>', { style: 'display: inline-block; min-width: 11em;' }).text(label))
        .append(ctl).append(help ? hint(help) : null);

    const name = $('<input>', { type: 'text', size: 24, placeholder: iface });
    const anchor = $('<input>', { type: 'number', min: 0, step: 1, style: 'width: 6em;',
                                  placeholder: 'default' });
    const status = $('<div>', { class: 'cell-enable-status', style: 'margin-top: 4px;' });
    const get = [];
    form = $('<div>', { class: 'cell-enable-form' });

    if (driver === 'cellat') {
        const prof = $('<select>', { class: 'cell-enable-profile' });
        CELLAT_ENABLE_PROFILES.forEach(([v, l]) =>
            prof.append($('<option>', { value: v }).text(l + (v === 'driving' ? ' (default)' : ''))));
        const atlog = $('<input>', { type: 'text', size: 28, class: 'cell-enable-atlog',
                                     placeholder: 'off  (a /path or dir/, %i %m %t)' });
        form.append(row('Scan profile', prof,
            'Driving: serving cell every 2 s, neighbors every 5 s, no full band ' +
            'scan. Walking adds a full scan every 5 min, Stationary every 60 s. ' +
            'Can be changed later without a restart.'));
        form.append(row('Raw AT log', atlog,
            'Every AT command and response, one JSON line each. Empty = off; it ' +
            'can be started later from the source panel.'));
        get.push(() => [['strategy', prof.val() === 'driving' ? '' : prof.val()],
                        ['atlog', atlog.val()]]);
    } else {
        const mask = $('<select>', { class: 'cell-enable-mask' })
            .append($('<option>', { value: 'wardrive' }).text('wardrive (default)'))
            .append($('<option>', { value: 'full' }).text('full: every log code (high volume)'));
        const f3 = $('<select>', { class: 'cell-enable-f3' });
        ['off', 'error', 'high', 'all'].forEach((p) =>
            f3.append($('<option>', { value: p }).text(p + (p === 'off' ? ' (default)' : ''))));
        const rawpk = $('<input>', { type: 'checkbox', class: 'cell-enable-rawpackets',
                                     checked: true });
        const qsh = $('<input>', { type: 'checkbox', class: 'cell-enable-qsh' });
        const rawlog = $('<input>', { type: 'text', size: 28, class: 'cell-enable-rawlog',
                                      placeholder: 'off  (e.g. /captures/%i-%t.hdlc)' });
        form.append(row('DIAG mask', mask,
            'wardrive subscribes to the cell-survey log codes; full to every code ' +
            'the modem advertises (diagnosis, not wardriving).'));
        form.append(row('F3 debug messages', f3,
            'Firmware debug prints. Anything but off is a flood; error keeps ~68%.'));
        form.append(row('Raw DIAG into the kismetdb', rawpk,
            'On by default: the whole DIAG stream is kept as packets (DLT 147), ' +
            'so a drive can be re-decoded later.'));
        form.append(row('QSH / full F3 surface', qsh,
            'Off by default. Arms the QSH trace mask set and event stream: a ' +
            'development/corpus drive only, very high volume.'));
        form.append(row('Raw DIAG tee file', rawlog,
            'A copy of the DIAG byte stream on disk. Empty = off; it can be ' +
            'started later from the source panel. A restart never overwrites ' +
            'it: a session that finds the file already written tees to a ' +
            'time-stamped sibling instead.'));
        get.push(() => [['mask', mask.val() === 'wardrive' ? '' : mask.val()],
                        ['f3', f3.val() === 'off' ? '' : f3.val()],
                        ['rawpackets', rawpk.prop('checked') ? '' : 'off'],
                        ['qsh', qsh.prop('checked') ? 'on' : ''],
                        ['rawlog', rawlog.val()]]);
    }
    form.append(row('Clock anchor every (s)', anchor,
        'How often the modem clock is read against the host clock. Empty = the ' +
        'driver default; 0 = only at start and stop.'));
    form.append(row('Source name', name, 'Empty = ' + iface + '.'));

    const button = $('<button>', { class: 'cell-enable-button' }).text('Enable source')
        .button()
        .on('click', () => {
            const opts = get[0]();
            opts.push(['clock_anchor_sec', anchor.val()]);
            opts.push(['name', name.val()]);
            const d = cell_enable_definition(iface, driver, opts);
            if (d.error) {
                status.css('color', '#b00').text(d.error);
                return;
            }
            status.css('color', '#666').text('Opening ' + d.definition + ' ...');
            button.button('disable');
            ds_state['defer_command_progress'] = true;
            $.ajax({
                url: local_uri_prefix + 'datasource/add_source.cmd',
                method: 'POST',
                data: 'json=' + encodeURIComponent(JSON.stringify({ definition: d.definition })),
                dataType: 'json',
                timeout: 120000,
            })
            .done(() => on_done())
            .fail((xhr) => {
                /* The reason, where the operator clicked. The
                 * server answers 500 "ERROR: unable to open ...: <why>". */
                const why = ((xhr && xhr.responseText) || '').trim() ||
                    ('no answer from the server (' + ((xhr && xhr.statusText) || 'error') + ')');
                status.css('color', '#b00').text(why);
                button.button('enable');
            })
            .always(() => { ds_state['defer_command_progress'] = false; });
        });
    form.append(button).append(status);
    idiv.data('cell-enable-form', form);
    return form;
}

/* The whole-modem switch.
 *
 * One modem is usually two sources -- cellat-<IMEI> and celldiag-<IMEI> -- and
 * each already has a Capture switch. This row lists the modem's sources with
 * their state, and turns all of them off or on with one click, one source at a
 * time: each is the Capture switch's close -> update_definition {enabled} ->
 * open, and the next starts only when the previous open has answered, so two
 * bring-ups never race for the same ports. */
const cell_set_enabled = (uuid, want) => {
    const base = `${local_uri_prefix}datasource/by-uuid/${uuid}/`;
    const reopen = () => $.get(base + 'open_source.cmd');
    return $.get(base + 'close_source.cmd')
        .then(() => $.ajax({
            url: base + 'update_definition.cmd',
            method: 'POST',
            data: "json=" + encodeURIComponent(JSON.stringify({ "options": { "enabled": want } })),
            dataType: 'json',
            timeout: 30000,
        }))
        .then(reopen, reopen);        /* the source is never left closed */
}

/* A cell source's own state, in one word the group row can show. */
const cell_source_state = (s) => {
    if (s['kismet.datasource.cellat.state'] === 'disabled' ||
        s['kismet.datasource.celldiag.mask_preset'] === 'disabled')
        return 'capture off';
    if (s['kismet.datasource.error'])
        return 'error';
    return s['kismet.datasource.running'] ? 'capturing' : 'stopped';
}

export const cell_modem_siblings = (source, sources) => {
    const id = cell_iface_imei(source['kismet.datasource.interface']);
    if (id === null)
        return [];
    return (sources || []).filter((s) => {
        const o = cell_iface_imei(s['kismet.datasource.interface']);
        return o !== null && o.imei === id.imei;
    }).sort((a, b) => cell_sort_key(a['kismet.datasource.interface'])
                      .localeCompare(cell_sort_key(b['kismet.datasource.interface'])));
}

const cell_modem_group_row = (source, sdiv, set_row) => {
    const sibs = cell_modem_siblings(source, ds_state['kismet_sources']);
    if (sibs.length === 0) {
        $('tr#cell_modem_group', sdiv).remove();
        return;
    }
    const wrap = $('<div>');
    sibs.forEach((s) => {
        const drv = s['kismet.datasource.type_driver']['kismet.datasource.driver.type'];
        wrap.append($('<div>').text(cell_unsanitize(s['kismet.datasource.name']) + ' \u2014 ' +
            (CELL_CAPTURE_LABEL[drv] || drv) + ': ' + cell_source_state(s)));
    });
    /* The modem's band/RAT lock lives on its AT source. */
    const at_src = sibs.find((s) => s['kismet.datasource.cellat.lock_capable']);
    if (at_src)
        wrap.append($('<div>').text('Band / RAT lock: ' +
            (cell_unsanitize(at_src['kismet.datasource.cellat.lock_channel'] || '') || 'unknown')));
    const any_on = sibs.some((s) => cell_source_state(s) !== 'capture off');
    const any_off = sibs.some((s) => cell_source_state(s) === 'capture off');
    const go = (want, label) => $('<button>', { class: 'cell-modem-' + (want === 'true' ? 'on' : 'off') })
        .text(label)
        .on('click', () => {
            if (!window.confirm(label + '?\n\nEach of this modem\'s ' + sibs.length +
                    ' source(s) is closed and re-opened with enabled=' + want +
                    ', one after another.'))
                return;
            sibs.reduce((p, s) => p.then(() => cell_set_enabled(s['kismet.datasource.uuid'], want)),
                        $.Deferred().resolve().promise());
        });
    if (any_on)
        wrap.append(go('false', 'Turn this modem off'));
    if (any_off)
        wrap.append(' ').append(go('true', 'Turn this modem on'));
    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('Every capture source of this modem (the same IMEI). Off releases ' +
              'the ports and keeps the sources listed; on runs each bring-up in turn.'));
    set_row(sdiv, 'cell_modem_group', '<b>This modem</b>', wrap);
}

/* Persistence matches Wi-Fi sources. Choices made in the UI --
 * Enable options, profile, lock, streams -- live in the running server only;
 * after a restart kismet_site.conf wins again, exactly as for a Wi-Fi source.
 * The row says so, and shows the definition in force, which is the line to
 * keep. Text only (.text()), and never an input: the definition is not edited
 * here. */
const cell_definition_row = (source, sdiv, set_row) => {
    const def = cell_unsanitize(source['kismet.datasource.definition'] || '');
    if (!def) {
        $('tr#cell_definition', sdiv).remove();
        return;
    }
    set_row(sdiv, 'cell_definition', '<b>Definition</b>',
        $('<span>')
            .append($('<code>', { style: 'word-break: break-all;' }).text(def))
            .append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
                .text('Changes made here last until Kismet restarts. To keep ' +
                      'them, put this in kismet_site.conf as source=' + def)));
}

/* Render the celldiag stats rows into this source's detail table.
 * `set_row(sdiv, id, title, content)` is update_datasource2's row writer. */
export const celldiag_render_rows = (source, sdiv, set_row, now_s) => {
    if (!is_celldiag_source(source))
        return false;

    const f = (k) => source['kismet.datasource.celldiag.' + k];

    /* --- a disabled source -----------------------------------------------
     * Checked first, before the helper row. enabled=false opens successfully
     * and idles, so Kismet shows it running -- and with no helper spawned,
     * helper_alive is 0, which the helper row would render as a red "DEAD --
     * observations have stopped". The helper reports mask_preset "disabled" at
     * once (capture_cell_diag.c, send_disabled_stats), and this renders it for
     * what it is: a neutral
     * "disabled", no counters (nothing was measured), and the switch that
     * turns capture on. */
    if (f('mask_preset') === 'disabled') {
        set_row(sdiv, 'celldiag_helper', '<b>Decoder</b>',
            $('<span>', { style: 'color: #666;' })
                .html('<i class="fa fa-pause-circle"></i> ')
                .append($('<span>').text('not running — capture is disabled ' +
                    '(enabled=false): no port opened, nothing is captured')));
        ['celldiag_modem', 'celldiag_obs', 'celldiag_lastobs', 'celldiag_bytes', 'celldiag_crc',
         'celldiag_mask', 'celldiag_f3', 'celldiag_lifecycle', 'celldiag_rawlog',
         'celldiag_inventory', 'celldiag_census_table', 'celldiag_native',
         'celldiag_bringup', 'celldiag_rawpackets', 'celldiag_qsh', 'celldiag_anchor']
            .forEach((r) => $('tr#' + r, sdiv).remove());
        set_row(sdiv, 'celldiag_capture', '<b>Capture</b>',
            cell_capture_switch_control(source, true));
        return true;
    }

    /* --- decoder liveness ------------------------------------------------
     * First row on purpose. A stalled decoder is the characteristic silent
     * failure: observations stop, and the operator sees obs=0 -- which is
     * indistinguishable from "no cells in range" unless something says so out
     * loud. */
    /* The bring-up, above the decoder -- a decoder that never started
     * because the bring-up failed is not a decoder that died. */
    const bringup = celldiag_bringup_text(f);
    if (bringup !== null)
        set_row(sdiv, 'celldiag_bringup', '<b>Bring-up</b>', bringup);
    else
        $('tr#celldiag_bringup', sdiv).remove();

    set_row(sdiv, 'celldiag_helper', '<b>Decoder</b>',
        f('helper_alive') ?
            $('<span>').html('<i class="fa fa-check-circle"></i> ')
                .append($('<span>').text('alive' +
                    (f('decode_mode') ? ' (' + f('decode_mode') + ')' : ''))) :
        f('bringup_error') ?
            $('<span>', { style: 'color: #b60;' })
                .text('not started — the bring-up failed (see Bring-up above)') :
        f('mask_preset') === 'opening' ?
            $('<span>', { style: 'color: #666;' })
                .text('not started yet — the bring-up is still running') :
            $('<span>', { style: 'color: #b00;' })
                .html('<i class="fa fa-exclamation-circle"></i> DEAD &mdash; ' +
                      'observations have stopped; this is not "no cells in range"'));

    /* --- which modem ---------------------------------------------------
     * Until the deferred bring-up reports, the source cannot say: its hardware
     * still reads "DIAG opening". */
    const modem_txt = cell_modem_identity_text(source);
    set_row(sdiv, 'celldiag_modem', '<b>Modem</b>',
        modem_txt ? $('<span>').text(modem_txt)
                  : celldiag_nodata('not identified yet (the bring-up has not reported)'));

    /* --- throughput ------------------------------------------------------ */
    /* A live source drops observations rather than stop reading the DIAG
     * port, so a full output ring is a loss the operator must see. */
    const obs_cell = $('<span>').text(f('obs_total') + ' total, ' +
        (f('obs_per_sec') || 0).toFixed(2) + '/sec');
    if (f('obs_ring_dropped') > 0)
        obs_cell.append($('<span>', { style: 'color: #b00;' })
            .text(', ' + f('obs_ring_dropped') + ' dropped (output ring full)'));
    set_row(sdiv, 'celldiag_obs', '<b>Cell observations</b>', obs_cell);

    var age = celldiag_obs_age(f('last_obs_epoch'), now_s);
    set_row(sdiv, 'celldiag_lastobs', '<b>Last observation</b>',
        age === null ? celldiag_nodata('none yet')
                     : Math.round(age) + ' seconds ago');

    set_row(sdiv, 'celldiag_bytes', '<b>DIAG bytes read</b>',
        celldiag_bytes_human(f('bytes_read')));

    /* --- frame integrity -------------------------------------------------
     * Gated on crc_reported: until the census arrives the crc_* fields are
     * zeros nobody measured, and "0 failed" would read as a clean stream.
     * A failed CRC is bytes the modem sent that never reached the capture (a
     * tty overflow drops them silently); a damage alert says a check window
     * crossed the floor, so the stream has gaps. */
    if (f('crc_reported')) {
        const crc = $('<span>').text(f('crc_ok') + ' of ' + f('crc_checked') +
            ' frames passed, ' + f('crc_bad') + ' failed');
        if (f('crc_damage_alerts') > 0) {
            crc.css('color', '#b00');
            crc.append($('<span>').text(' — this stream lost bytes (' +
                f('crc_damage_alerts') + ' damaged check windows)'));
        } else if (f('crc_bad') > 0) {
            crc.css('color', '#b60');
        }
        set_row(sdiv, 'celldiag_crc', '<b>DIAG frame CRC</b>', crc);
    } else {
        set_row(sdiv, 'celldiag_crc', '<b>DIAG frame CRC</b>',
            celldiag_nodata('not reported yet'));
    }

    /* --- capture configuration ------------------------------------------- */
    var mask_cell = $('<span>');
    mask_cell.append(f('mask_preset') ? f('mask_preset')
                                      : celldiag_nodata('not reported'));
    mask_cell.append(celldiag_mask_control(source, f));
    set_row(sdiv, 'celldiag_mask', '<b>DIAG mask preset</b>', mask_cell);
    var f3_cell = $('<span>');
    f3_cell.append(f('f3_preset') ? f('f3_preset')
                                  : celldiag_nodata('not reported'));
    f3_cell.append(celldiag_f3_control(source, f));
    set_row(sdiv, 'celldiag_f3', '<b>F3 debug preset</b>', f3_cell);

    /* --- lifecycle -------------------------------------------------------
     * Restart only. Activate / Close / Disable already ship on the generic
     * "Active" row for every source; duplicating them here would give one
     * action two controls that can disagree about which is lit. */
    set_row(sdiv, 'celldiag_lifecycle', '<b>Source lifecycle</b>',
        celldiag_restart_control(source));
    /* The enabled= switch, in its "on" state. Its own row rather
     * than inside the restart control: a panel contract test pins that the restart
     * control never duplicates Enable/Disable, and this is not Kismet's
     * Disable anyway (see cell_capture_switch_control). */
    set_row(sdiv, 'celldiag_capture', '<b>Capture</b>',
        cell_capture_switch_control(source, false));
    cell_definition_row(source, sdiv, set_row);

    /* --- the raw tee -----------------------------------------------------
     * The bytes count is read only inside the tee-on branch. Reading it
     * unconditionally is the bug: an unconfigured tee would render
     * "0 bytes written", which an operator correctly reads as "the tee is on
     * and something is wrong", when in fact nothing was ever asked to write. */
    var tee_cell = $('<span>');
    if (f('rawlog_path')) {
        /* The path alone cannot say whether this is a live capture or a
         * finished one -- a stop retains it. Saying "stopped" here keeps the
         * row and the control (which offers a restart) from visibly
         * disagreeing. */
        tee_cell.append($('<span>').text(cell_unsanitize(f('rawlog_path')) + '  (' +
            celldiag_bytes_human(f('rawlog_bytes')) + ' written' +
            (f('rawlog_active') ? '' : ', stopped') + ')'));
    } else {
        tee_cell.append(celldiag_nodata('off (no rawlog= configured)'));
    }
    tee_cell.append(celldiag_rawlog_control(source, f));
    set_row(sdiv, 'celldiag_rawlog', '<b>Raw DIAG tee</b>', tee_cell);

    /* --- the stream switches ---------------------------------------------
     * Gated on switches_reported: an older helper reports none of these, and
     * "off, 0 slices" from it would be a reading nobody took. */
    if (f('switches_reported')) {
        const live = f('mask_preset') !== 'replay';
        const rp = $('<span>');
        if (f('rawpackets_on')) {
            rp.append($('<span>').text('on — ' + f('rawpackets_slices') +
                ' slices into the kismetdb'));
            if (f('rawpackets_dropped') > 0)
                rp.append($('<span>', { style: 'color: #b00;' })
                    .text(', ' + f('rawpackets_dropped') + ' dropped'));
        } else {
            rp.append(celldiag_nodata('off — the raw DIAG stream is not kept'));
        }
        rp.append(' ').append(celldiag_rawpackets_control(source, f));
        set_row(sdiv, 'celldiag_rawpackets', '<b>Raw DIAG into the kismetdb</b>', rp);

        if (live) {
            const q = $('<span>');
            if (!f('qsh_requested'))
                q.append(celldiag_nodata('off'));
            else if (f('qsh_armed'))
                q.append($('<span>', { style: 'color: #b60;' })
                    .text('armed — high volume'));
            else
                q.append($('<span>', { style: 'color: #b60;' })
                    .text('requested, not armed yet (it is armed during the ' +
                          'bring-up; a part without QSH declines it)'));
            q.append(' ').append(celldiag_qsh_control(source, f));
            set_row(sdiv, 'celldiag_qsh', '<b>QSH / full F3</b>', q);

            const a = $('<span>');
            if (f('anchor_last_epoch') > 0)
                a.append($('<span>').text(f('anchor_count') + ' sent, last ' +
                    Math.round(Math.max(0, now_s - f('anchor_last_epoch'))) +
                    ' seconds ago'));
            else
                a.append(celldiag_nodata('none yet'));
            if (f('anchor_ring_dropped') > 0)
                a.append($('<span>', { style: 'color: #b60;' })
                    .text(', ' + f('anchor_ring_dropped') +
                          ' not delivered (output ring full; still in the sidecar)'));
            a.append(celldiag_anchor_control(source));
            set_row(sdiv, 'celldiag_anchor', '<b>Clock anchors</b>', a);
        } else {
            $('tr#celldiag_qsh', sdiv).remove();
            $('tr#celldiag_anchor', sdiv).remove();
        }
    }

    /* --- the (code,version) census ---------------------------------------
     * Gated on distinct > 0, which is the honest "has a census arrived?" test:
     * any record at all creates a key, so a census that has counted anything
     * reports at least one. Rendering "0 unrecognized, 0 silent" before that
     * would be the panel's most damaging possible lie -- it reads as a clean
     * bill of health for a source that has not yet reported on itself. */
    if (f('inventory_distinct_codes') > 0) {
        var inv = $('<span>').text(
            f('inventory_distinct_codes') + ' (code,version) keys, ' +
            f('inventory_unrecognized') + ' unrecognized, ' +
            f('inventory_silent') + ' silent, ' +
            (f('inventory_undecoded_native') || 0) +
            ' with a known layout no native leg reads yet');
        /* `silent` is the stronger signal of the two: a code the emit contract
         * depends on that parsed fine and produced nothing. `unrecognized` is
         * usually just new firmware. Colour follows that ranking. */
        if (f('inventory_silent') > 0)
            inv.css('color', '#b00');
        else if (f('inventory_unrecognized') > 0)
            inv.css('color', '#b60');
        set_row(sdiv, 'celldiag_inventory', '<b>DIAG code census</b>', inv);
    } else {
        set_row(sdiv, 'celldiag_inventory', '<b>DIAG code census</b>',
            celldiag_nodata('no census reported yet'));
    }

    /* --- the census table ------------------------------------------------
     * The counters above say a problem exists; only this says which
     * (code,version). Rows are ';'-separated,
     * `code/vN,count,decoded,dropped,emitted,enrich_failed,flags`.
     *
     * Gated on the string being empty, not on split(';').length. ''.split(';')
     * is [''] in both JS and Python, so the naive length test is truthy for an
     * empty census and renders exactly one blank row -- a table that looks like
     * it reported something.
     *
     * And the count is rendered as "showing N of M", never as a bare row
     * count. The producer caps the table at 24 rows and reports `distinct`
     * separately for precisely this reason: a bounded table that looks complete
     * is worse than no table at all. Dropping the denominator here would
     * reintroduce the silent cap one layer downstream. */
    var tbl_s = f('inventory_table');
    if (tbl_s) {
        var rows = tbl_s.split(';').filter((r) => r.length > 0);
        var tbl = $('<table>', { class: 'celldiag_census' });
        tbl.append($('<tr>').append(
            ['(code,version)', 'records', 'decoded', 'dropped', 'emitted',
             'enrich failed', ''].map((h) => $('<th>').text(h))));
        rows.forEach((r) => {
            var c = r.split(',');
            /* A malformed row is skipped rather than rendered short. A row with
             * missing cells silently shifts every value one column left, which
             * reads as real data in the wrong place -- worse than a gap. */
            if (c.length !== 7)
                return;
            var tr = $('<tr>');
            for (var i = 0; i < 6; i++)
                tr.append($('<td>').text(c[i]));
            /* Flags carry the reason a row is worth looking at, so they are
             * spelled out: 's'/'u'/'e' are opaque in a panel a human reads once. */
            var why = [];
            if (c[6].indexOf('s') >= 0) why.push('silent');
            if (c[6].indexOf('u') >= 0) why.push('unrecognized');
            if (c[6].indexOf('e') >= 0) why.push('enrich failed');
            var flagcell = $('<td>').text(why.join(', '));
            if (why.length > 0)
                flagcell.css('color', c[6].indexOf('s') >= 0 ? '#b00' : '#b60');
            tr.append(flagcell);
            tbl.append(tr);
        });
        var cap = $('<div>').text(
            'showing ' + rows.length + ' of ' +
            (f('inventory_distinct_codes') || rows.length) + ' (code,version) keys');
        set_row(sdiv, 'celldiag_census_table', '<b>Census detail</b>',
            $('<div>').append(tbl).append(cap));
    } else {
        $('tr#celldiag_census_table', sdiv).remove();
    }

    /* --- native decode coverage ------------------------------------------
     * Gated on total_records > 0: before the first DIAG LOG record there is
     * no denominator, and "0% coverage" would be a reading nobody took. */
    if (f('native_total_records') > 0) {
        var pct = (100.0 * f('native_records') /
                   f('native_total_records')).toFixed(1);
        /* The denominator is spelled out rather than aliased on purpose: every
         * value in this row must be traceable to the field it came from by
         * reading the row alone, so a dropped counter is visible in review. */
        set_row(sdiv, 'celldiag_native', '<b>Native decode coverage</b>',
            $('<span>').text(
                f('native_records') + '/' + f('native_total_records') +
                ' records (' + pct + '%), ' +
                f('native_obs') + ' obs, ' +
                f('native_enriched') + ' enriched, ' +
                f('native_gps_fixes') + ' GNSS fixes, ' +
                f('native_declined') + ' declined, ' +
                f('native_fallback_records') + ' unclaimed (no leg reads them)'));
    } else {
        $('tr#celldiag_native', sdiv).remove();
    }

    return true;
}

/* ------------------------------------------------------------------------
 * cellat operator panel
 *
 * Without this panel the generic rows say only "running": nothing says which
 * scan profile is armed, whether any observation has arrived, or whether the
 * raw AT tee is writing. Every row below binds a field the helper's `cellat_stats` line carries
 * (capture_cell_at/cellat_stats.h) and datasource_cell_at registers.
 *
 * Same one rule as the celldiag panel above: unreported must never render
 * as zero. The helper omits what it has not measured, but every registered
 * field still arrives here as its default ("" / 0), so absence is re-derived
 * from sentinels that cannot mean anything else:
 *
 *   stats_epoch === 0          -> no stats line yet. Nothing below it is a
 *                                 measurement; render one "not reported" row
 *                                 and stop, rather than a table of zeros.
 *   state === "disabled"       -> enabled=false: no port was opened. Render a
 *                                 neutral "disabled", never counters -- a row
 *                                 of zeros reads as "running and seeing
 *                                 nothing".
 *   atlog_path === ""          -> no atlog= tee was ever configured. Do not read
 *                                 atlog_records in this state.
 *   atlog_active === 0, path   -> a tee that ran and was stopped; the path is
 *                                 kept so the operator can find the file.
 *   last_obs_epoch === 0       -> no observation yet.
 *   anchor_last_epoch === 0    -> no clock anchor yet (the modem has not
 *                                 answered AT+CCLK?).
 *   obs_total === 0            -> the rate is not rendered: a rate over zero
 *                                 observations says nothing a count does not.
 *
 * Staleness is not absence. A stats line older than ~3 intervals means the
 * helper stopped reporting, which during a full band scan is expected (the scan
 * holds the AT port -- and the helper's only thread -- for up to 3 minutes).
 * The helper announces a scan before it blocks (state "full_scan" +
 * fullscan_started_epoch), which is what lets this panel tell a long scan from
 * a hung source instead of crying wolf on every stationary survey.
 */

/* True if this source is a cellat source. Keyed on a field only
 * datasource_cell_at registers, like is_celldiag_source. */
export const is_cellat_source = (source) => {
    return 'kismet.datasource.cellat.stats_epoch' in source;
}

/* The helper's profile vocabulary: ';'-separated `name,label,fullscan_s` rows
 * (cellat_stats_strategies). A row with the wrong cell count is skipped, the
 * census table's rule: a short row shifts every value one column left. */
export const cellat_parse_strategies = (s) => {
    if (!s)
        return [];
    return s.split(';')
        .map((r) => r.split(','))
        .filter((c) => c.length === 3 && c[0].length > 0)
        .map((c) => ({ name: c[0], label: c[1], fullscan_s: parseInt(c[2], 10) }));
}

/* "2 s" / "5 min" -- an interval in ms, or "off" for 0. */
const cellat_interval_human = (ms) => {
    if (!ms)
        return 'off';
    const s = ms / 1000;
    if (s < 120)
        return s + ' s';
    return (s / 60) + ' min';
}

/* The slowest full scan any supported modem is given (AT#CSURVC: 180 s). A
 * scan announced longer ago than this, plus margin, is not a slow scan. */
const CELLAT_FULLSCAN_MAX_S = 180;

/* Rows this panel owns, so a state that shows fewer of them (disabled, not yet
 * reported) removes the rest instead of leaving the previous state's numbers
 * standing beside the new one. */
const CELLAT_ROWS = ['cellat_state', 'cellat_profile', 'cellat_lock', 'cellat_obs',
    'cellat_lastobs', 'cellat_rawat', 'cellat_atlog', 'cellat_anchor',
    'cellat_modem', 'cellat_capture'];

/* Send one runtime setting to a cellat source.
 *
 * Reads nothing back from the transport, for celldiag's three reasons
 * (see celldiag_rawlog_control): a refused setting answers success=1 (a
 * negative chancontrol return would also tear the source down), the
 * set_channel route discards the message, and the reason reaches the message
 * bus instead. The panel row above is the confirmation: the helper sends a
 * stats line as soon as it applies a setting. */
const cellat_send_setting = (uuid, value) => {
    $.ajax({
        url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
        method: 'POST',
        data: "json=" + encodeURIComponent(JSON.stringify({ "channel": value })),
        dataType: 'json',
        timeout: 30000,
    });
}

/* The scan-profile selector -- the cell counterpart of a Wi-Fi source's
 * hop/lock mode.
 *
 * The options come from the helper, not from a list in this file: the
 * `strategies` field is the running binary's own profile table. A hardcoded
 * list would be two lists that drift, and would also let the panel offer a
 * profile an older helper refuses.
 *
 * No restart, and so no confirmation. Unlike celldiag's mask/F3 selectors,
 * which must close and re-open the source, a profile switch is applied by the
 * running helper at its next poll. Nothing is interrupted, so there is nothing
 * to confirm.
 *
 * A profile that needs a full band scan is disabled on a modem the
 * helper probed as having no full-scan command, and says why -- offering it
 * would run a driving survey under a stationary name. */
const cellat_profile_control = (source, g) => {
    const uuid = source['kismet.datasource.uuid'];
    const profs = cellat_parse_strategies(cell_unsanitize(g('strategies')));
    const wrap = $('<div>');
    if (profs.length === 0)
        return wrap;
    const cur = g('strategy');
    const incapable = !g('fullscan_capable');

    const sel = $('<select>');
    profs.forEach((p) => {
        let label = p.label;
        if (p.fullscan_s > 0)
            label += ' — full scan every ' + cellat_interval_human(p.fullscan_s * 1000);
        const o = $('<option>', { value: p.name });
        if (p.fullscan_s > 0 && incapable) {
            label += ' (this modem has no full-scan command)';
            o.attr('disabled', 'disabled');
        }
        o.text(label);
        if (p.name === cur)
            o.attr('selected', 'selected');
        sel.append(o);
    });

    cell_hold_row(sel, () => sel.val() === cur);
    wrap.append(sel);
    wrap.append($('<button>').text('Apply')
        .on('click', () => {
            const want = sel.val();
            if (!want || want === cur)
                return;
            cell_release_row(sel);
            cellat_send_setting(uuid, 'strategy=' + want);
        }));
    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('Applied at the next poll without restarting the source. The ' +
              'row above shows the profile the helper actually armed within ' +
              'one stats interval; a refusal is reported on the message bus, ' +
              'not here.'));
    return wrap;
}

/* The raw AT log (atlog=) toggle.
 *
 * Same shape as celldiag's raw-tee toggle, including its liveness rule:
 * liveness is `atlog_active`, not the path. A stop keeps the path so the
 * operator can find the file, so a control keyed on the path would offer only
 * "Stop" forever after the first stop. */
const cellat_atlog_control = (source, g) => {
    const uuid = source['kismet.datasource.uuid'];
    const wrap = $('<div>');
    if (g('atlog_active')) {
        wrap.append($('<button>').text('Stop AT log')
            .on('click', (e) => {
                cell_release_row($(e.target));
                cellat_send_setting(uuid, 'atlog=off');
            }));
    } else {
        const inp = $('<input>', {
            type: 'text', size: 28,
            placeholder: '/path/or/dir/ (%i %m %t)',
        });
        cell_hold_row(inp, () => (inp.val() || '').trim() === '');
        wrap.append(inp);
        wrap.append($('<button>').text('Start AT log')
            .on('click', () => {
                const v = (inp.val() || '').trim();
                if (v === '')
                    return;
                cell_release_row(inp);
                cellat_send_setting(uuid, 'atlog=' + v);
            }));
    }
    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('Every AT command and its full response, one JSON line each. ' +
              'The row above shows the file and its record count within one ' +
              'stats interval; a refusal is reported on the message bus.'));
    return wrap;
}

/* The ClockAnchor cadence (cellat), applied live (no restart) through
 * the same runtime-setting path as the profile. */
const cellat_anchor_control = (source) => {
    const uuid = source['kismet.datasource.uuid'];
    const wrap = $('<span>', { style: 'margin-left: 8px;' });
    const inp = $('<input>', { type: 'number', min: 0, step: 1, style: 'width: 5em;',
                               placeholder: 'sec' });
    cell_hold_row(inp, () => (inp.val() || '').trim() === '');
    wrap.append(inp).append($('<button>').text('Set cadence')
        .on('click', () => {
            const v = (inp.val() || '').trim();
            if (!/^\d+$/.test(v))
                return;
            cell_release_row(inp);
            cellat_send_setting(uuid, 'clock_anchor_sec=' + v);
        }));
    return wrap;
}

/* The Band / RAT lock -- the Wi-Fi channel buttons, Lock and
 * Hop, for a cell modem. The channels are the lock presets the helper
 * reported at open (kismet.datasource.channels): AUTO (the settings as found),
 * LTE, NR5G, LTE-B<n>, NR-n<n>. Lock is Kismet's set_channel; Hop is Kismet's
 * own channel hop, over the ticked channels at the chosen dwell -- one lock
 * per step, a synthetic slow scan. The row above the controls is the
 * readback: the lock in force, as the helper reports it (lock_channel), not
 * what was asked for.
 *
 * Every lock is written to the modem's NV. The helper saves the settings as
 * found before the first write and restores them on AUTO, on close, and at
 * the next open after a crash -- which is why this control can offer Lock at
 * all. */
const cellat_lock_control = (source, g) => {
    const uuid = source['kismet.datasource.uuid'];
    const chans = (source['kismet.datasource.channels'] || []).map(cell_unsanitize);
    const wrap = $('<div>');
    const post = (payload) => $.ajax({
        url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
        method: 'POST',
        data: "json=" + encodeURIComponent(JSON.stringify(payload)),
        dataType: 'json',
        timeout: 30000,
    });

    const sel = $('<select>', { class: 'cellat-lock-select' });
    chans.filter((c) => c !== 'AUTO').forEach((c) => sel.append($('<option>', { value: c }).text(c)));
    cell_hold_row(sel, () => false);
    wrap.append(sel).append(' ')
        .append($('<button>', { class: 'cellat-lock-button' }).text('Lock')
            .on('click', () => {
                cell_release_row(sel);
                post({ channel: sel.val() });
            }))
        .append(' ')
        .append($('<button>', { class: 'cellat-unlock-button' }).text('Unlock (settings as found)')
            .on('click', () => {
                cell_release_row(sel);
                post({ channel: 'AUTO' });
            }));

    const hop = $('<div>', { style: 'margin-top: 4px;' });
    const pick = $('<select>', { class: 'cellat-hop-select', multiple: true, size: 4 });
    chans.filter((c) => c !== 'AUTO').forEach((c) => pick.append($('<option>', { value: c }).text(c)));
    const dwell = $('<input>', { type: 'number', min: 5, step: 1, value: 60,
                                 class: 'cellat-hop-dwell', style: 'width: 5em;' });
    cell_hold_row(pick, () => false);
    cell_hold_row(dwell, () => false);
    hop.append($('<span>').text('Hop through ')).append(pick)
        .append($('<span>').text(' dwelling ')).append(dwell).append($('<span>').text(' s on each '))
        .append($('<button>', { class: 'cellat-hop-button' }).text('Hop')
            .on('click', () => {
                const list = pick.val() || [];
                const s = parseInt(dwell.val(), 10);
                if (list.length < 2 || !(s >= 5))
                    return;
                cell_release_row(pick);
                post({ channels: list, rate: 1.0 / s });
            }));
    wrap.append(hop);
    wrap.append($('<div>', { style: 'font-size: 0.85em; color: #666;' })
        .text('Each lock re-registers the modem (a few seconds without service). ' +
              'Written to the modem\'s memory: the settings as found are saved ' +
              'first and restored on Unlock, on close, and after a crash at the ' +
              'next open. Choices here last until Kismet restarts.'));
    return wrap;
}

export const cellat_render_rows = (source, sdiv, set_row, now_s) => {
    if (!is_cellat_source(source))
        return false;

    const g = (k) => source['kismet.datasource.cellat.' + k];
    const drop_rows_after = (id) => {
        CELLAT_ROWS.slice(CELLAT_ROWS.indexOf(id) + 1)
            .forEach((r) => $('tr#' + r, sdiv).remove());
    };
    /* The one spelling of absence, shared with the celldiag panel. */
    const nodata = celldiag_nodata;

    /* --- nothing reported yet ------------------------------------------- */
    if (!g('stats_epoch')) {
        set_row(sdiv, 'cellat_state', '<b>AT survey</b>',
            nodata('no status reported yet'));
        drop_rows_after('cellat_state');
        return true;
    }

    const state = g('state');
    const iv = g('stats_interval_s') || 5;
    const age = Math.max(0, now_s - g('stats_epoch'));

    /* --- state ----------------------------------------------------------- */
    let st;
    if (state === 'disabled') {
        st = $('<span>', { style: 'color: #666;' })
            .html('<i class="fa fa-pause-circle"></i> ')
            .append($('<span>').text('disabled (enabled=false) — no port ' +
                'opened, nothing is being captured'));
    } else if (state === 'full_scan') {
        const ran = Math.max(0, now_s - g('fullscan_started_epoch'));
        if (ran > CELLAT_FULLSCAN_MAX_S + 30) {
            st = $('<span>', { style: 'color: #b00;' })
                .html('<i class="fa fa-exclamation-circle"></i> ')
                .append($('<span>').text('full band scan started ' +
                    Math.round(ran) + ' s ago, longer than any supported ' +
                    'modem needs (' + CELLAT_FULLSCAN_MAX_S + ' s) — the ' +
                    'source may be stuck'));
        } else {
            st = $('<span>')
                .html('<i class="fa fa-spinner"></i> ')
                .append($('<span>').text('full band scan running for ' +
                    Math.round(ran) + ' s — the AT port is busy, so the ' +
                    'serving and neighbor polls wait (up to ' +
                    CELLAT_FULLSCAN_MAX_S / 60 + ' min)'));
        }
    } else if (age > 3 * iv) {
        st = $('<span>', { style: 'color: #b60;' })
            .html('<i class="fa fa-exclamation-triangle"></i> ')
            .append($('<span>').text('no status for ' + Math.round(age) +
                ' s (expected every ' + iv + ' s) — the source may be stuck'));
    } else {
        st = $('<span>').html('<i class="fa fa-check-circle"></i> surveying');
    }
    set_row(sdiv, 'cellat_state', '<b>AT survey</b>', st);

    /* --- scan profile ----------------------------------------------------
     * The intervals are the helper's report of what is in force, not a lookup
     * of the profile name -- after a runtime switch they are the readback that
     * the switch took. */
    const prof = $('<span>');
    if (g('strategy')) {
        prof.append($('<span>').text(cell_unsanitize(g('strategy_label') || g('strategy')) +
            ' (' + cell_unsanitize(g('strategy')) + ')'));
    } else {
        prof.append(nodata('not reported'));
    }
    if (state !== 'disabled' && g('strategy')) {
        prof.append($('<span>', { style: 'color: #666;' }).text(
            ' — serving ' + cellat_interval_human(g('serving_interval_ms')) +
            ', neighbors ' + cellat_interval_human(g('neighbor_interval_ms')) +
            ', full scan ' + (g('fullscan_interval_ms') ?
                'every ' + cellat_interval_human(g('fullscan_interval_ms')) :
                'off')));
        /* A profile that wants a scan this modem cannot run. The
         * helper also warns once on the message bus; this keeps it visible. */
        if (g('fullscan_interval_ms') > 0 && !g('fullscan_capable')) {
            prof.append($('<div>', { style: 'color: #b60;' }).text(
                'This modem has no full band scan command (AT+QSCAN / ' +
                'AT#CSURVC), so the full scan will not run.'));
        }
        prof.append(cellat_profile_control(source, g));
    }
    set_row(sdiv, 'cellat_profile', '<b>Scan profile</b>', prof);

    /* --- band / RAT lock ------------------------------------------------ */
    if (state !== 'disabled' && g('stats_epoch')) {
        const lk = $('<span>');
        if (!g('lock_capable')) {
            lk.append(nodata('not available on this modem (cellat locks Quectel ' +
                             'AT+QNWPREFCFG / AT+QCFG, Sierra AT!SELRAT and AT+WS46 modems)'));
        } else {
            const ch = cell_unsanitize(g('lock_channel') || '');
            lk.append($('<span>').text(ch === 'AUTO' ? 'AUTO — the settings as found' :
                                       ch ? 'locked to ' + ch : 'unknown'));
            if (source['kismet.datasource.hopping'])
                lk.append($('<span>', { style: 'color: #666;' }).text(
                    ' — hopping ' + (source['kismet.datasource.hop_channels'] || []).length +
                    ' channels, ' + Math.round(1 / (source['kismet.datasource.hop_rate'] || 1)) +
                    ' s each'));
            if (g('lock_error'))
                lk.append($('<div>', { style: 'color: #b00;' }).text(cell_unsanitize(g('lock_error'))));
            lk.append(cellat_lock_control(source, g));
        }
        set_row(sdiv, 'cellat_lock', '<b>Band / RAT lock</b>', lk);
    }

    if (state === 'disabled') {
        drop_rows_after('cellat_profile');
        /* The one control a disabled source needs. */
        set_row(sdiv, 'cellat_capture', '<b>Capture</b>',
            cell_capture_switch_control(source, true));
        return true;
    }

    /* --- observations ---------------------------------------------------- */
    set_row(sdiv, 'cellat_obs', '<b>Cell observations</b>',
        g('obs_total') > 0 ?
            g('obs_total') + ' total, ' + (g('obs_per_sec') || 0).toFixed(2) +
                '/sec' :
            '0 so far');

    set_row(sdiv, 'cellat_lastobs', '<b>Last observation</b>',
        g('last_obs_epoch') ?
            Math.round(Math.max(0, now_s - g('last_obs_epoch'))) + ' seconds ago' :
            nodata('none yet'));

    /* --- raw AT into the kismetdb ----------------------------------------
     * Always on while the source captures, and the row says so rather than
     * looking like a setting nobody can reach. */
    const rawat = $('<span>').text(g('rawat_records') +
        ' exchanges logged to the kismetdb (RawAT, always on)');
    if (g('rawat_dropped') > 0) {
        rawat.append($('<span>', { style: 'color: #b00;' })
            .text(', ' + g('rawat_dropped') + ' dropped'));
    }
    set_row(sdiv, 'cellat_rawat', '<b>Raw AT log</b>', rawat);

    /* --- the QMI feed and its raw log ----------------------------------
     * Every qmifeed_* / rawqmi_* value is read only when a feed was
     * configured, for the atlog_records reason below. */
    if (g('qmifeed_configured')) {
        const qmi = $('<span>').text(
            (g('qmifeed_active') ? 'running' : 'exited') + ': ' +
            g('qmifeed_sent') + ' QMI observations, ' +
            g('rawqmi_records') + ' exchanges logged to the kismetdb (RawQMI), ' +
            g('qmifeed_msgs') + ' notes');
        const lost = g('qmifeed_dropped') + g('qmifeed_dropped_imei') + g('rawqmi_dropped');
        if (lost > 0) {
            qmi.append($('<span>', { style: 'color: #b00;' })
                .text(', ' + lost + ' dropped (' + g('qmifeed_dropped_imei') +
                      ' for IMEI, ' + g('rawqmi_dropped') + ' raw)'));
        }
        set_row(sdiv, 'cellat_qmifeed', '<b>QMI feed</b>', qmi);
    }

    /* --- the atlog= file tee ---------------------------------------------
     * atlog_records is read only when a path exists: with no tee configured
     * it is an unset default, and "0 records" would read as "the tee is on
     * and writing nothing". */
    const tee = $('<span>');
    if (g('atlog_path')) {
        tee.text(cell_unsanitize(g('atlog_path')) + '  (' + g('atlog_records') + ' records' +
            (g('atlog_dropped') > 0 ? ', ' + g('atlog_dropped') + ' lost' : '') +
            (g('atlog_active') ? '' : ', stopped') + ')');
    } else {
        tee.append(nodata('off (no atlog= configured)'));
    }
    tee.append(cellat_atlog_control(source, g));
    set_row(sdiv, 'cellat_atlog', '<b>AT log file</b>', tee);

    /* --- clock anchors --------------------------------------------------- */
    const anc = $('<span>');
    anc.append(g('anchor_last_epoch') ?
            $('<span>').text(g('anchor_count') + ' sent, last ' +
                Math.round(Math.max(0, now_s - g('anchor_last_epoch'))) +
                ' seconds ago') :
            nodata('none yet (the modem has not answered AT+CCLK?)'));
    anc.append(cellat_anchor_control(source));
    set_row(sdiv, 'cellat_anchor', '<b>Clock anchors</b>', anc);

    /* --- identity ----------------------------------------------------------
     * The modem's own make/model/firmware/IMEI when the ModemIdentity
     * record has arrived -- for a Quectel, g('model') is derived from the
     * firmware string and cannot name the model. The stats fields remain the
     * fallback for a helper that predates the record. */
    const modem_txt = cell_modem_identity_text(source);
    const id = [];
    if (g('model')) id.push(cell_unsanitize(g('model')));
    if (g('firmware')) id.push('firmware ' + cell_unsanitize(g('firmware')));
    if (g('at_port')) id.push('port ' + cell_unsanitize(g('at_port')));
    set_row(sdiv, 'cellat_modem', '<b>Modem</b>',
        modem_txt ? $('<span>').text(modem_txt) :
        id.length ? $('<span>').text(id.join(' · ')) : nodata('not reported'));

    set_row(sdiv, 'cellat_capture', '<b>Capture</b>',
        cell_capture_switch_control(source, false));
    cell_definition_row(source, sdiv, set_row);

    return true;
}

/* Sidebar:  Channel coverage
 *
 * The channel coverage looks at the data sources and plots a moving graph
 * of all channels and how they're covered; it reflects how the pattern will
 * work, but not, necessarily, reality itself.
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'datasource_channel_coverage',
    listTitle: '<i class="fa fa-bar-chart-o"></i> Channel Coverage',
    clickCallback: function() {
        ChannelCoverage();
    },
});

var channelcoverage_backend_tid;
var channelcoverage_display_tid;
var channelcoverage_panel = null;
var channelcoverage_canvas = null;
var channelhop_canvas = null;
var channelcoverage_chart = null;
var channelhop_chart = null;
var cc_uuid_pos_map = {};


let sourcetitles = [];
let chantitles = [];

export const ChannelCoverage = () => {
    var w = $(window).width() * 0.85;
    var h = $(window).height() * 0.75;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    channelcoverage_chart = null;
    channelhop_chart = null;

    var content =
        $('<div>', {
            id: "k-cc-main",
            class: "k-cc-main",
        })
        .append(
            $('<ul>', {
                id: "k-cc-tab-ul"
            })
            .append(
                $('<li>', { })
                .append(
                    $('<a>', {
                        href: '#k-cc-tab-coverage'
                    })
                    .html("Channel Coverage")
                )
            )
            .append(
                $('<li>', { })
                .append(
                    $('<a>', {
                        href: '#k-cc-tab-estimate'
                    })
                    .html("Estimated Hopping")
                )
            )
        )
        .append(
            $('<div>', {
                id: 'k-cc-tab-coverage',
                class: 'k-cc-canvas'
            })
            .append(
                $('<canvas>', {
                    id: 'k-cc-cover-canvas',
                    class: 'k-cc-canvas'
                })
            )
        )
        .append(
            $('<div>', {
                id: 'k-cc-tab-estimate',
                class: 'k-cc-canvas'
            })
            .append(
                $('<canvas>', {
                    id: 'k-cc-canvas',
                    class: 'k-cc-canvas'
                })
            )
        );

    channelcoverage_panel = $.jsPanel({
        id: 'channelcoverage',
        headerTitle: '<i class="fa fa-bar-chart-o"></i> Channel Coverage',
        headerControls: {
            iconfont: 'jsglyph',
            minimize: 'remove',
            smallify: 'remove',
        },
        content: content,
        onclosed: function() {
            clearTimeout(channelcoverage_backend_tid);
            clearTimeout(channelcoverage_display_tid);
            channelhop_chart = null;
            channelhop_canvas = null;
            channelcoverage_canvas = null;
            channelcoverage_chart = null;
        },
        onresized: resize_channelcoverage,
        onmaximized: resize_channelcoverage,
        onnormalized: resize_channelcoverage,
    })
    .on('resize', function() {
        resize_channelcoverage();
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offy,
    }).front();

    content.tabs({
        heightStyle: 'fill'
    });


    channelcoverage_backend_refresh();
    channelcoverage_display_refresh();
}

function channelcoverage_backend_refresh() {
    clearTimeout(channelcoverage_backend_tid);

    if (channelcoverage_panel == null)
        return;

    if (channelcoverage_panel.is(':hidden'))
        return;

    $.get(local_uri_prefix + "datasource/all_sources.json")
    .done(function(data) {
        // Build a list of all devices we haven't seen before and set their
        // initial positions to match
        for (var di = 0; di < data.length; di++) {
            if (data[di]['kismet.datasource.running'] == 0) {
                if ((data[di]['kismet.datasource.uuid'] in cc_uuid_pos_map)) {
                   delete cc_uuid_pos_map[data[di]['kismet.datasource.uuid']];
                }
            } else if (!(data[di]['kismet.datasource.uuid'] in cc_uuid_pos_map)) {
                cc_uuid_pos_map[data[di]['kismet.datasource.uuid']] = {
                    uuid: data[di]['kismet.datasource.uuid'],
                    name: data[di]['kismet.datasource.name'],
                    interface: data[di]['kismet.datasource.interface'],
                    hopping: data[di]['kismet.datasource.hopping'],
                    channel: data[di]['kismet.datasource.channel'],
                    channels: data[di]['kismet.datasource.hop_channels'],
                    offset: data[di]['kismet.datasource.hop_offset'],
                    position: data[di]['kismet.datasource.hop_offset'],
                    skip: data[di]['kismet.datasource.hop_shuffle_skip'],
                };
            }

        }
    })
    .always(function() {
        channelcoverage_backend_tid = setTimeout(channelcoverage_backend_refresh, 5000);
    });
}

function resize_channelcoverage() {
    if (channelcoverage_panel == null)
        return;

    var container = $('#k-cc-main', channelcoverage_panel.content);

    var tabs = $('#k-cc-tab-ul', container);

    var w = container.width();
    var h = container.height() - tabs.outerHeight();

    $('#k-cc-tab-estimate', container)
        .css('width', w)
        .css('height', h);

    if (channelhop_canvas != null) {
        channelhop_canvas
            .css('width', w)
            .css('height', h);

        if (channelhop_chart != null)
             channelhop_chart.resize();
    }

    $('#k-cc-tab-coverage', container)
        .css('width', w)
        .css('height', h);

    if (channelcoverage_canvas != null) {
        channelcoverage_canvas
            .css('width', w)
            .css('height', h);

        if (channelcoverage_chart != null)
             channelcoverage_chart.resize();
    }

}

function channelcoverage_display_refresh() {
    clearTimeout(channelcoverage_display_tid);

    if (channelcoverage_panel == null)
        return;

    if (channelcoverage_panel.is(':hidden'))
        return;

    // Now we know all the sources; make a list of all channels and figure
    // out if we're on any of them; each entry in total_channel_list contains
    // an array of UUIDs on this channel in this sequence
    var total_channel_list = {}

    for (var du in cc_uuid_pos_map) {
        var d = cc_uuid_pos_map[du];

        if (d['hopping']) {
            for (var ci = 0; ci < d['channels'].length; ci++) {
                var chan = d['channels'][ci];
                if (!(chan in total_channel_list)) {
                    total_channel_list[chan] = [ ];
                }

                if ((d['position'] % d['channels'].length) == ci) {
                    total_channel_list[chan].push(du);
                }
            }

            // Increment the virtual channel position for the graph
            if (d['skip'] == 0) {
                d['position'] = d['position'] + 1;
            } else {
                d['position'] = d['position'] + d['skip'];
            }
        } else {
            // Non-hopping sources are always on their channel
            var chan = d['channel'];

            if (!(chan in total_channel_list)) {
                total_channel_list[chan] = [ du ];
            } else {
                total_channel_list[chan].push(du);
            }
        }
    }

    // Create the channel index for the x-axis, used in both the hopping and the coverage
    // graphs
    chantitles = []; 
    // var chantitles = new Array();
    for (var ci in total_channel_list) {
        chantitles.push(ci);
    }

    // Perform a natural sort on it to get it in order
    var ncollator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});
    chantitles.sort(ncollator.compare);

    // Create the source datasets for the animated estimated hopping graph, covering all
    // channels and highlighting the channels we have a UUID in
    var source_datasets = new Array()

    var ndev = 0;

    for (var du in cc_uuid_pos_map) {
        var d = cc_uuid_pos_map[du];

        var dset = [];

        for (var ci in chantitles) {
            var clist = total_channel_list[chantitles[ci]];

            if (clist.indexOf(du) < 0) {
                dset.push(0);
            } else {
                dset.push(1);
            }
        }

        var color = "hsl(" + parseInt(255 * (ndev / Object.keys(cc_uuid_pos_map).length)) + ", 100%, 50%)";

        source_datasets.push({
            label: d['name'],
            data: dset,
            borderColor: color,
            backgroundColor: color,
        });

	    ndev++;
    }

    // Create the source list for the Y axis of the coverage graph; we make an intermediary
    // which is sorted by name but includes UUID, then assemble the final one
    var sourcetitles_tmp = new Array();

    for (var ci in cc_uuid_pos_map) {
        sourcetitles_tmp.push({
            name: cc_uuid_pos_map[ci].name,
            uuid: ci
        });
    }

    sourcetitles_tmp.sort(function(a, b) {
        return a.name.localeCompare(b.name);
    });

    // Build the titles
    sourcetitles = [];
    for (const si in sourcetitles_tmp) {
        sourcetitles.push(sourcetitles_tmp[si].name);
    }

    var bubble_dataset = new Array();

    // Build the bubble data
    ndev = 0;
    for (var si in sourcetitles_tmp) {
        var d = cc_uuid_pos_map[sourcetitles_tmp[si].uuid];
        var ds = new Array;

        if (d.hopping) {
            for (var ci in d.channels) {
                const c = d.channels[ci];

                const cp = chantitles.indexOf(c);

                if (cp < 0)
                    continue;

                ds.push({
                    x: cp,
                    y: si,
                    r: 5
                });
            }
        } else {
            const cp = chantitles.indexOf(d.channel);
            if (cp >= 0) {
                ds.push({
                    x: cp,
                    y: si,
                    r: 5
                });
            }
        }

        const color = "hsl(" + parseInt(255 * (ndev / Object.keys(cc_uuid_pos_map).length)) + ", 100%, 50%)";

        bubble_dataset.push({
            label: d.name,
            data: ds,
            borderColor: color,
            backgroundColor: color,
        });

        ndev++;

    }

    if (channelhop_canvas == null) {
        channelhop_canvas = $('#k-cc-canvas', channelcoverage_panel.content);

        let bp = 5.0;

        if (chantitles.length < 14)
            bp = 2;

        channelhop_chart = new Chart(channelhop_canvas, {
            type: "bar",
            options: {
                responsive: true,
                maintainAspectRatio: false,
                barThickness: 15,
                scales: {
                    x: { barPercentage: bp, 
                        ticks: { 
                            autoSkip: false,
                            stepSize: 1,
                            callback: function(value, index, values) {
                                return chantitles[value];
                            },
                            min: 0,
                            max: chantitles.length,
                            position: 'bottom',
                            type: 'linear',
                        }
                    },
                    y: { display: false, },
                },
            },
            data: {
                labels: chantitles,
                datasets: source_datasets,
            },
        });
    } else {
        channelhop_chart.data.datasets = source_datasets;
        channelhop_chart.data.labels = chantitles;
        channelhop_chart.update('none');
    }

    if (channelcoverage_canvas == null && sourcetitles.length != 0) {
        channelcoverage_canvas = $('#k-cc-cover-canvas', channelcoverage_panel.content);

        channelcoverage_chart = new Chart(channelcoverage_canvas, {
            type: 'bubble',
            options: {
                title: {
                    display: true,
                    text: 'Per-Source Channel Coverage',
                },
                legend: {
                    display: false,
                },
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        ticks: {
                            autoSkip: false,
                            stepSize: 1,
                            callback: function(value, index, values) {
                                return chantitles[value];
                            },
                            min: 0,
                            max: chantitles.length,
                            position: 'bottom',
                            type: 'linear',
                        }
                    },
                    y: {
                        ticks: {
                            autoSkip: false,
                            stepSize: 1,
                            callback: function(value, index, values) {
                                return sourcetitles[value];
                            },
                            min: 0,
                            max: sourcetitles.length,
                            position: 'left',
                            type: 'linear',
                        },
                    },
                },
            },
            data: {
                labels: chantitles,
                yLabels: sourcetitles,
                datasets: bubble_dataset,
            },
        });
    } else if (sourcetitles.length != 0) {
        channelcoverage_chart.data.datasets = bubble_dataset;

        channelcoverage_chart.data.labels = chantitles;
        channelcoverage_chart.data.yLabels = sourcetitles;

        channelcoverage_chart.options.scales.x.ticks.min = 0;
        channelcoverage_chart.options.scales.x.ticks.max = chantitles.length;

        channelcoverage_chart.options.scales.y.ticks.min = 0;
        channelcoverage_chart.options.scales.y.ticks.max = sourcetitles.length;

        channelcoverage_chart.update('none');
    }

    channelcoverage_display_tid = setTimeout(channelcoverage_display_refresh, 500);
}

/* Sidebar:  Data sources (new)
 *
 * Data source management panel
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'datasource_sources2',
    listTitle: '<i class="fa fa-cogs"></i> Data Sources',
    priority: -500,
    clickCallback: function() {
        DataSources2();
    },
});

var ds_state = {};

function alpha_insert(container, clss, index, data) {
	var prev = null;
	var after = null;

	$(clss, container).each((i, v) => {
		if (prev != null) {
			return;
		}

		if ($(v).data(index) === undefined) {
			return;
		}

		var lt = String.prototype.localeCompare.call($(data).data(index).toLowerCase(), 
			$(v).data(index).toLowerCase());

		// Insert before the current item if less than, and stop processing
		if (lt < 0) {
			prev = v;
			after = null;
			return;
		}

		// Keep incrementing the after item, if we're greater than or equal
		after = v;
	});

	// If we have a prev item, we insert before
	if (prev != null) {
		$(prev).before(data);
		return;
	}

	// If we have an after item, we insert after
	if (after != null) {
		$(after).after(data);
		return;
	}

	// otherwise just append
	$(container).append(data);
}

function update_datasource2(data) {
    if (!"ds_content" in ds_state)
        return;

    var set_row = function(sdiv, id, title, content) {
        var r = $('tr#' + id, sdiv);

        /* A row whose control the operator is in the middle of using is
         * left alone -- see cell_hold_row. Without this the 1 s refresh
         * rebuilds the row under them: a chosen-but-not-applied preset snaps
         * back and a half-typed path vanishes. Only rows a control has marked
         * are affected. */
        if (r.length != 0 && r.data('cell-editing'))
            return;

        if (r.length == 0) {
            r = $('<tr>', { id: id })
            .append($('<td>'))
            .append($('<td>'));

            $('.k-ds-table', sdiv).append(r);
        }

        $('td:eq(0)', r).replaceWith($('<td>').append(title));

        // Controls are kept between refreshes; moving them would close an open menu
        // and lose focus, so leave them alone once they're in place
        if (content instanceof jQuery && content.parent().is($('td:eq(1)', r)))
            return;

        $('td:eq(1)', r).replaceWith($('<td>').append(content));
    }

    var top_row = function(sdiv, id, title, content) {
        var r = $('tr#' + id, sdiv);

        if (r.length == 0) {
            r = $('<tr>', { id: id })
            .append($('<td>'))
            .append($('<td>'));

            $('.k-ds-table', sdiv).prepend(r);
        }

        $('td:eq(0)', r).replaceWith($('<td>').append(title));
        $('td:eq(1)', r).replaceWith($('<td>').append(content));
    }

    for (var uuid of ds_state['remove_pending']) {
        var sdiv = $('#' + uuid, ds_state['ds_content']);
        $('.k-ds-modal', sdiv).hide();
    }
    ds_state['remove_pending'] = [];

    /*
    // Defer if we're waiting for a command to finish; do NOTHING else
    if ('defer_command_progress' in ds_state && ds_state['defer_command_progress'])
        return;
        */

    // Mark that we're loading interfaces
    if (ds_state['done_interface_update']) {
        $('#ds_loading_interfaces', ds_state['ds_content']).remove();
    } else {
        var loading_intf = $('#ds_loading_interfaces', ds_state['ds_content']);

        if (loading_intf.length == 0) {
            loading_intf = $('<div>', {
                id: 'ds_loading_interfaces',
                class: 'accordion',
                })
            .append(
                $('<h3>', {
                    id: 'header',
                })
                .append(
                    $('<span>', {
                        class: 'k-ds-source',
                    })
                    .html("<i class=\"fa fa-spin fa-cog\"></i> Finding available interfaces...")
                )
            ).append(
                $('<div>').html("Kismet is probing for available capture interfaces...")
            );

            loading_intf.accordion({ collapsible: true, active: false });

            ds_state['ds_content'].append(loading_intf);
        }
    }


    /* The listers' answers plus the cell rows they could not report
     * (a sibling's port held by a running source). One list feeds both the
     * clean-up below and the render, so a synthesized row is not removed and
     * re-created -- losing its Enable form -- on every refresh. */
    const all_intfs = cell_augment_interfaces(ds_state['kismet_interfaces'],
                                              ds_state['kismet_sources']);

    // Clean up missing probed interfaces
    $('.interface', ds_state['ds_content']).each(function(i) {
        var found = false;

        for (var intf of all_intfs) {
            if ($(this).attr('id') === intf['kismet.datasource.probed.interface']) {
                if (intf['kismet.datasource.probed.in_use_uuid'] !== '00000000-0000-0000-0000-000000000000') {
                    break;
                }
                found = true;
                break;
            }
        }

        if (!found) {
            // console.log("removing interface", $(this).attr('id'));
            $(this).remove();
        }
    });

    // Clean up missing sources
    $('.source', ds_state['ds_content']).each(function(i) {
        var found = false;

        for (var source of ds_state['kismet_sources']) {
            if ($(this).attr('id') === source['kismet.datasource.uuid']) {
                found = true;
                break;
            }
        }

        if (!found) {
            // console.log("removing source", $(this).attr('id'));
            $(this).remove();
        }
    });

    for (var intf of all_intfs) {
        if (intf['kismet.datasource.probed.in_use_uuid'] !== '00000000-0000-0000-0000-000000000000') {
            $('#' + intf['kismet.datasource.probed.interface'], ds_state['ds_content']).remove();
            continue;
        }

        var idiv = $('#' + intf['kismet.datasource.probed.interface'], ds_state['ds_content']);

        if (idiv.length == 0) {
            idiv = $('<div>', {
                id: intf['kismet.datasource.probed.interface'],
                class: 'accordion interface',
				'data-sortpname': cell_sort_key(intf['kismet.datasource.probed.interface']),
                })
            .append(
                $('<h3>', {
                    id: 'header',
                })
                .append(
                    $('<span>', {
                        class: 'k-ds-source',
                    })
                    .html(is_cell_driver(intf['kismet.datasource.type_driver']['kismet.datasource.driver.type']) ?
                        /* A cell row is titled by the modem and
                         * the capture type ("Quectel RM520N-GL — DIAG"),
                         * filled below on every refresh, as .text(). */
                        '<i class="fa fa-tower-cell" style="color: #33bb33; margin-right: 5px;"></i><span class="k-ds-cell-title"></span>' :
                        "Available Interface: " + intf['kismet.datasource.probed.interface'] + ' (' + intf['kismet.datasource.type_driver']['kismet.datasource.driver.type'] + ')')
                    /* For a cell source that is not open, which modem
                     * it is -- the list answer is read from the modem each
                     * refresh (make/model/firmware/IMEI), so an operator
                     * choosing between modems sees more than an IMEI. Filled
                     * below on every refresh, as .text(). */
                    .append($('<span>', {
                        class: 'k-ds-modem',
                        style: 'color: #666; margin-left: 8px;',
                    }))
                )
            ).append(
                $('<div>', {
                    // id: 'content',
                    class: 'k-ds_content',
                })
            );

            var table = $('<table>', {
                class: 'k-ds-table'
                });

            var wrapper = $('<div>', {
                "style": "position: relative;",
            });

            var modal = $('<div>', {
                class: 'k-ds-modal',
            }).append(
                $('<div>', {
                    class: 'k-ds-modal-content',
                })
                .append(
                    $('<div>', {
                        class: "k-ds-modal-message",
                        style: "font-size: 125%; margin-bottom: 5px;",
                    }).html("Loading...")
                ).append(
                    $('<i>', {
                        class: "fa fa-3x fa-cog fa-spin",
                    })
                )
            );

            wrapper.append(table);
            wrapper.append(modal);
            modal.hide();

            $('.k-ds_content', idiv).append(wrapper);

            idiv.accordion({ collapsible: true, active: false });

            // ds_state['ds_content'].append(idiv);
			alpha_insert(ds_state['ds_content'], '.interface', 'sortpname', idiv);
        }

        set_row(idiv, 'interface', '<b>Interface</b>', intf['kismet.datasource.probed.interface']);
        const intf_driver = intf['kismet.datasource.type_driver']['kismet.datasource.driver.type'];
        const is_cell_intf = is_cell_driver(intf_driver);
        if (is_cell_intf) {
            /* Title, then IMEI / firmware / availability, muted. */
            const parsed = cell_parse_label(intf['kismet.datasource.probed.hardware']);
            const id = cell_iface_imei(intf['kismet.datasource.probed.interface']);
            $('.k-ds-cell-title', idiv).text(cell_row_title(parsed, intf_driver));
            const sub = [];
            if (id !== null)
                sub.push('IMEI ' + id.imei);
            if (parsed === null && intf['kismet.datasource.probed.hardware'])
                sub.push(cell_unsanitize(intf['kismet.datasource.probed.hardware']));
            else if (parsed !== null && parsed.firmware && parsed.name)
                sub.push(parsed.firmware);
            sub.push(intf.cell_unlisted ? 'not in the list right now' : 'available');
            $('.k-ds-modem', idiv).text(sub.join(' \u00b7 '));
            if (intf.cell_unlisted)
                set_row(idiv, 'cell_unlisted', '<b>Availability</b>',
                    $('<span>', { style: 'color: #b60;' })
                        .html('<i class="fa fa-exclamation-triangle"></i> ')
                        .append($('<span>').text(intf.cell_unlisted)));
            else
                $('tr#cell_unlisted', idiv).remove();
        }
        set_row(idiv, 'driver', '<b>Capture Driver</b>', intf['kismet.datasource.type_driver']['kismet.datasource.driver.type']);
        if ('kismet.datasource.probed.hardware' in intf && intf['kismet.datasource.probed.hardware'] !== '')
            set_row(idiv, 'hardware', '<b>Hardware</b>', intf['kismet.datasource.probed.hardware']);
        if ('kismet.datasource.probed.datasource_version' in intf && intf['kismet.datasource.probed.datasource_version'] !== '')
            set_row(idiv, 'dsversion', '<b>Version</b>', intf['kismet.datasource.probed.datasource_version']);
        set_row(idiv, 'description', '<b>Type</b>', intf['kismet.datasource.type_driver']['kismet.datasource.driver.description']);

        /* A cell row gets the Enable form (profile, streams,
         * anchors, name) instead of the bare button. */
        if (is_cell_intf) {
            /* Attached once: re-attaching moves the elements, and a moved
             * input loses focus -- a path half-typed into it would stop
             * taking keystrokes at the next 1 s refresh. */
            if ($('tr#addsource .cell-enable-form', idiv).length === 0) {
                const the_idiv = idiv;
                set_row(idiv, 'addsource', '<b>Enable</b>',
                    cell_enable_form(idiv, intf['kismet.datasource.probed.interface'],
                                     intf_driver, () => the_idiv.remove()));
            }
            idiv.accordion("refresh");
            continue;
        }

        var addbutton = $('#add', idiv);
        if (addbutton.length == 0) {
            addbutton =
                $('<button>', {
                    id: 'addbutton',
                    interface: intf['kismet.datasource.probed.interface'],
                    intftype: intf['kismet.datasource.type_driver']['kismet.datasource.driver.type'],
                })
                .html('Enable Source')
                .button()
                .on('click', function() {
                    var intf = $(this).attr('interface');
                    var idiv = $('#' + intf, ds_state['ds_content']);

                    $('.k-ds-modal-message', idiv).html("Opening datasource...");
                    $('.k-ds-modal', idiv).show();

                    var jscmd = {
                        "definition": $(this).attr('interface') + ':type=' + $(this).attr('intftype')
                    };

                    ds_state['defer_command_progress'] = true;

                    var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));
                    $.post(local_uri_prefix + "datasource/add_source.cmd", postdata, "json")
                    .always(function() {
                        ds_state['defer_command_progress'] = false;
                        idiv.remove();
                    });

                });
        }

        set_row(idiv, 'addsource', $('<span>'), addbutton);

        idiv.accordion("refresh");
    }
    // console.log("updating with ", ds_state['kismet_sources'].length);

    for (var source of ds_state['kismet_sources']) {
        var sdiv = $('#' + source['kismet.datasource.uuid'], ds_state['ds_content']);

        if (sdiv.length == 0) {
            sdiv = $('<div>', {
                id: source['kismet.datasource.uuid'],
                class: 'accordion source',
				'data-sortname': source['kismet.datasource.name'],
                })
            .append(
                $('<h3>', {
                    id: 'header',
                })
                .append(
                    $('<span>', {
                        id: 'error',
                    })
                )
                .append(
                    $('<span>', {
                        id: 'paused',
                    })
                )
                .append(
                    $('<span>', {
                        class: 'k-ds-source',
                    })
                    .html((is_cell_driver(source['kismet.datasource.type_driver']['kismet.datasource.driver.type']) ? '<i class="fa fa-tower-cell" style="color: #33bb33; margin-right: 5px;"></i>' : '') + source['kismet.datasource.name'])
                    /* Which modem and what capture, beside the
                     * source name. Filled on every refresh, as .text(). */
                    .append($('<span>', {
                        class: 'k-ds-modem',
                        style: 'color: #666; margin-left: 8px;',
                    }))
                )
                .append(
                    $('<span>', {
                        id: 'rrd',
                        class: 'k-ds-rrd',
                    })
                )
            ).append(
                $('<div>', {
                    // id: 'content',
                    class: 'k-ds_content',
                })
            );

            var wrapper = $('<div>', {
                "style": "position: relative;",
            });

            var table = $('<table>', {
                class: 'k-ds-table'
                });

            var modal = $('<div>', {
                class: 'k-ds-modal',
            }).append(
                $('<div>', {
                    class: 'k-ds-modal-content',
                })
                .append(
                    $('<div>', {
                        class: "k-ds-modal-message",
                        style: "font-size: 150%; margin-bottom: 10px;",
                    }).html("Loading...")
                ).append(
                    $('<i>', {
                        class: "fa fa-3x fa-cog fa-spin",
                    })
                )
            );

            wrapper.append(table);
            wrapper.append(modal);
            modal.hide();

            $('.k-ds_content', sdiv).append(wrapper);

            sdiv.accordion({ collapsible: true, active: false });

			alpha_insert(ds_state['ds_content'], '.source', 'sortname', sdiv);

            // ds_state['ds_content'].append(sdiv);
        }

        if (typeof(source['kismet.datasource.packets_rrd']) !== 'undefined' &&
                source['kismet.datasource.packets_rrd'] != 0) {

            var simple_rrd =
                kismet.RecalcRrdData(
                    source['kismet.datasource.packets_rrd'],
                    source['kismet.datasource.packets_rrd']['kismet.common.rrd.last_time'],
                    kismet.RRD_SECOND,
                    source['kismet.datasource.packets_rrd']['kismet.common.rrd.minute_vec'], {
                        transform: function(data, opt) {
                        var slices = 3;
                        var peak = 0;
                        var ret = new Array();

                        for (var ri = 0; ri < data.length; ri++) {
                            peak = Math.max(peak, data[ri]);

                            if ((ri % slices) == (slices - 1)) {
                                ret.push(peak);
                                peak = 0;
                            }
                        }

                        return ret;
                    }
                    });

            // Render the sparkline
            $('#rrd', sdiv).sparkline(simple_rrd, {
                type: "bar",
                width: 100,
                height: 12,
                barColor: kismet_theme.sparkline_main,
                nullColor: kismet_theme.sparkline_main,
                zeroColor: kismet_theme.sparkline_main,
                });
        }

        // Find the channel buttons
        var chanbuttons = $('#chanbuttons', sdiv);

        if (chanbuttons.length == 0) {
            // Make a new one of all possible channels
            chanbuttons = $('<div>', {
                id: 'chanbuttons',
                uuid: source['kismet.datasource.uuid']
            });

            chanbuttons.append(
              $('<button>', {
                id: "all",
                uuid: source['kismet.datasource.uuid']
              }).html("All")
              .button()
              .on('click', function(){
                ds_state['defer_command_progress'] = true;

                var uuid = $(this).attr('uuid');
                var chans = [];
                $('button.chanbutton[uuid=' + uuid + ']', ds_state['ds_content']).each(function(i) {
                    chans.push(kismet.unsanitizeHTML($(this).attr('channel')));
                });
                var jscmd = {
                    "cmd": "hop",
                    "channels": chans,
                    "uuid": uuid
                };
                var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));

                  try {
                      $.ajax({
                          url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`, 
                          method: 'POST',
                          data: postdata,
                          dataType: 'json',
                          success: function(data) { },
                          timeout: 30000,
                      });
                  } finally {
                      ds_state['defer_command_progress'] = false;
                  }
                $('button.chanbutton[uuid=' + uuid + ']', ds_state['ds_content']).each(function(i){
                      $(this).removeClass('disable-chan-system');
                      $(this).removeClass('enable-chan-system');
                      $(this).removeClass('disable-chan-user');
                      $(this).addClass('enable-chan-user');
                    })
                })
              );

            for (var c of source['kismet.datasource.channels']) {
                chanbuttons.append(
                    $('<button>', {
                        id: c,
                        channel: c,
                        uuid: source['kismet.datasource.uuid'],
                        class: 'chanbutton'
                    }).html(c)
                    .button()
                    .on('click', function() {
                        var uuid = $(this).attr('uuid');

                        var sdiv = $('#' + uuid, ds_state['ds_content']);
                        sdiv.addClass("channel_pending");

                        // If we're in channel lock mode, we highlight a single channel
                        if ($('#lock[uuid=' + uuid + ']', ds_state['ds_content']).hasClass('enable-chan-user')) {
                            // Only do something if we're not selected
                            if (!($(this).hasClass('enable-chan-user'))) {
                                // Remove from all lock channels
                                $('button.chanbutton[uuid=' + uuid + ']').each(function(i) {
                                        $(this).removeClass('enable-chan-user');
                                    });
                                $('button.chanbutton[uuid=' + uuid + ']').removeClass('enable-chan-system');
                                // Set this channel
                                $(this).addClass('enable-chan-user');

                            } else {
                                return;
                            }

                            ds_state['defer_source_update'] = true;
                            ds_state['defer_command_progress'] = true;

                            // Clear any existing timer
                            if (uuid in ds_state['chantids'])
                               clearTimeout(ds_state['chantids'][uuid]);

                            // Immediately post w/out a timeout
                            var jscmd = {
                                "cmd": "lock",
                                "uuid": uuid,
                                "channel": kismet.unsanitizeHTML($(this).attr('channel')),
                            };

                            $('.k-ds-modal-message', sdiv).html("Setting channel...");
                            $('.k-ds-modal', sdiv).show();

                            var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));

                            try {
                                $.ajax({
                                    url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
                                    method: 'POST',
                                    data: postdata,
                                    dataType: 'json',
                                    success: function(data) {
                                        data = kismet.sanitizeObject(data);
                                        for (var u in ds_state['datasources']) {
                                            if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                                ds_state['datasources'][u] = data;
                                                ds_state['remove_pending'].push(uuid);
                                                update_datasource2(null);
                                                break;
                                            }
                                        }
                                    },
                                    timeout: 30000,
                                });
                            } finally {
                                ds_state['remove_pending'].push(uuid);
                                ds_state['defer_command_progress'] = false;
                                sdiv.removeClass("channel_pending");
                            }

                            return;
                        } else {
                            // we're in hop mode
                            if ($(this).hasClass('enable-chan-user') || $(this).hasClass('enable-chan-system')) {
                                $(this).removeClass('enable-chan-user');
                                $(this).removeClass('enable-chan-system');

                                $(this).addClass('disable-chan-user');
                            } else {
                                $(this).removeClass('disable-chan-user');
                                $(this).addClass('enable-chan-user');
                            }

                            // Clear any old timer
                            if (uuid in ds_state['chantids'])
                                clearTimeout(ds_state['chantids'][uuid]);

                            // Set a timer to trigger in the future setting any channels
                            ds_state['chantids'][uuid] = setTimeout(function() {
                                ds_state['defer_command_progress'] = true;
                                ds_state['defer_source_update'] = true;

                                var sdiv = $('#' + uuid, ds_state['ds_content']);
                                sdiv.addClass("channel_pending");

                                $('.k-ds-modal-message', sdiv).html("Setting channels...");
                                $('.k-ds-modal', sdiv).show();

                                var chans = [];

                                $('button.chanbutton[uuid=' + uuid + ']', ds_state['ds_content']).each(function(i) {
                                    // If we're hopping, collect user and system
                                    if ($(this).hasClass('enable-chan-user') ||
                                        $(this).hasClass('enable-chan-system')) {
                                        ds_state['refresh' + uuid] = true;
                                        chans.push(kismet.unsanitizeHTML($(this).attr('channel')));
                                    }
                                });

                                var jscmd = {
                                    "cmd": "hop",
                                    "uuid": uuid,
                                    "channels": chans
                                };

                                var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));
                                try {
                                    $.ajax({
                                        url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
                                        method: 'POST',
                                        data: postdata,
                                        dataType: 'json',
                                        success: function(data) {
                                            data = kismet.sanitizeObject(data);
                                            for (var u in ds_state['datasources']) {
                                                if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                                    ds_state['datasources'][u] = data;
                                                    ds_state['remove_pending'].push(uuid);
                                                    update_datasource2(null);
                                                    break;
                                                }
                                            }
                                        },
                                        timeout: 30000,
                                    });
                                } finally {
                                    ds_state['remove_pending'].push(uuid);
                                    ds_state['defer_command_progress'] = false;
                                    sdiv.removeClass("channel_pending");
                                }
                            }, 2000);
                        }
                    })
                );
            }
        }

        var pausediv = $('#pausediv', sdiv);
        if (pausediv.length == 0) {
            pausediv = $('<div>', {
                id: 'pausediv',
                uuid: source['kismet.datasource.uuid']
            });

            pausediv.append(
                $('<button>', {
                    id: "opencmd",
                    uuid: source['kismet.datasource.uuid']
                }).html('Activate')
                .button()
                .on('click', function() {
                    ds_state['defer_command_progress'] = true;
                    ds_state['defer_source_update'] = true;

                    var uuid = $(this).attr('uuid');
                    var sdiv = $('#' + uuid, ds_state['ds_content']);

                    $('.k-ds-modal-message', sdiv).html("Activating datasource...");
                    $('.k-ds-modal', sdiv).show();

                    $('#closecmd[uuid=' + uuid + ']', ds_state['ds_content']).removeClass('enable-chan-user');
                    $(this).addClass('enable-chan-user');

                    $.get(local_uri_prefix + '/datasource/by-uuid/' + uuid + '/open_source.cmd')
                    .done(function(data) {
                        data = kismet.sanitizeObject(data);

                        for (var u in ds_state['datasources']) {
                            if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                ds_state['datasources'][u] = data;
                                update_datasource2(null);
                                break;
                            }
                        }
                    })
                    .always(function() {
                            ds_state['defer_command_progress'] = false;
                            ds_state['remove_pending'].push(uuid);
                    });

                })
            );

            pausediv.append(
                $('<button>', {
                    id: "closecmd",
                    uuid: source['kismet.datasource.uuid']
                }).html('Close')
                .button()
                .on('click', function() {
                    ds_state['defer_command_progress'] = true;
                    ds_state['defer_source_update'] = true;

                    var uuid = $(this).attr('uuid');
                    var sdiv = $('#' + uuid, ds_state['ds_content']);

                    $('.k-ds-modal-message', sdiv).html("Closing datasource...");
                    $('.k-ds-modal', sdiv).show();
                        
                    $(this).addClass('enable-chan-user');
                    $('#opencmd[uuid=' + uuid + ']', ds_state['ds_content']).removeClass('enable-chan-user');

                    $.get(local_uri_prefix + '/datasource/by-uuid/' + uuid + '/close_source.cmd')
                    .done(function(data) {
                        data = kismet.sanitizeObject(data);

                        for (var u in ds_state['datasources']) {
                            if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                ds_state['remove_pending'].push(uuid);
                                ds_state['datasources'][u] = data;
                                update_datasource2(null);
                                break;
                            }
                        }
                    })
                    .always(function() {
                        ds_state['remove_pending'].push(uuid);
                        ds_state['defer_command_progress'] = false;
                    });

                })
            );

            pausediv.append(
                $('<button>', {
                    id: "disablecmd",
                    uuid: source['kismet.datasource.uuid']
                }).html('Disable')
                .button()
                .on('click', function() {
                    ds_state['defer_command_progress'] = true;
                    ds_state['defer_source_update'] = true;

                    var uuid = $(this).attr('uuid');
                    var sdiv = $('#' + uuid, ds_state['ds_content']);

                    $('.k-ds-modal-message', sdiv).html("Disabling datasource...");
                    $('.k-ds-modal', sdiv).show();
                        
                    $(this).addClass('enable-chan-user');
                    $('#opencmd[uuid=' + uuid + ']', ds_state['ds_content']).removeClass('enable-chan-user');

                    $.get(local_uri_prefix + '/datasource/by-uuid/' + uuid + '/disable_source.cmd')
                    .done(function(data) {
                        data = kismet.sanitizeObject(data);

                        for (var u in ds_state['datasources']) {
                            if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                ds_state['remove_pending'].push(uuid);
                                ds_state['datasources'][u] = data;
                                update_datasource2(null);
                                break;
                            }
                        }
                    })
                    .always(function() {
                        ds_state['remove_pending'].push(uuid);
                        ds_state['defer_command_progress'] = false;
                    });

                })
            );

            pausediv.append(
                $('<p>', {
                    id: 'pausetext',
                    uuid: source['kismet.datasource.uuid']
                })
                .html('Source is currently closed and inactive.')
            );
        }

        if (source['kismet.datasource.running']) {
            $('button#closecmd', sdiv).html("Close");
            $('button#opencmd', sdiv).html("Running");
        } else {
            $('button#closecmd', sdiv).html("Closed");
            $('button#opencmd', sdiv).html("Activate");
        }

        var quickopts = $('#quickopts', sdiv);
        if (quickopts.length == 0) {
          quickopts = $('<div>', {
              id: 'quickopts',
              uuid: source['kismet.datasource.uuid']
          });

          quickopts.append(
            $('<button>', {
              id: "lock",
              uuid: source['kismet.datasource.uuid']
            }).html("Lock")
            .button()
            .on('click', function(){
              ds_state['defer_source_update'] = true;
              ds_state['defer_command_progress'] = true;

              var uuid = $(this).attr('uuid');
              var sdiv = $('#' + uuid, ds_state['ds_content']);

              $('.k-ds-modal-message', sdiv).html("Locking channels...");
              $('.k-ds-modal', sdiv).show();

              $('#hop[uuid=' + uuid + ']', ds_state['ds_content']).removeClass('enable-chan-user');
              $('#lock[uuid=' + uuid + ']', ds_state['ds_content']).addClass('enable-chan-user');

              var firstchanobj = $('button.chanbutton[uuid=' + uuid + ']', ds_state['ds_content']).first();

              var chan = kismet.unsanitizeHTML(firstchanobj.attr('channel'));

              var jscmd = {
                  "cmd": "lock",
                  "channel": chan,
                  "uuid": uuid
              };
              var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));

                try {
                    $.ajax({
                        url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
                        method: 'POST',
                        data: postdata,
                        dataType: 'json',
                        success: function(data) {
                            data = kismet.sanitizeObject(data);
                            for (var u in ds_state['datasources']) {
                                if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                    ds_state['datasources'][u] = data;
                                    ds_state['remove_pending'].push(uuid);
                                    update_datasource2(null);
                                    break;
                                }
                            }
                        },
                        timeout: 30000,
                    });
                } finally {
                    ds_state['remove_pending'].push(uuid);
                }

              $('button.chanbutton[uuid='+ uuid + ']', ds_state['ds_content']).each(function(i) {
                      $(this).removeClass('enable-chan-system');
                      $(this).removeClass('disable-chan-user');
              });

              // Disable all but the first available channel
              firstchanobj.removeClass('disabled-chan-user');
              firstchanobj.removeClass('enable-chan-system');
              firstchanobj.addClass('enable-chan-user')

              })
            );

          quickopts.append(
            $('<button>', {
              id: "hop",
              uuid: source['kismet.datasource.uuid']
            }).html("Hop")
            .button()
            .on('click', function(){
              ds_state['defer_source_update'] = true;
              ds_state['defer_command_progress'] = true;

              var uuid = $(this).attr('uuid');
              var sdiv = $('#' + uuid, ds_state['ds_content']);

              $('.k-ds-modal-message', sdiv).html("Setting channel hopping...");
              $('.k-ds-modal', sdiv).show();

              $('#hop[uuid=' + uuid + ']', ds_state['ds_content']).addClass('enable-chan-user');
              $('#lock[uuid=' + uuid + ']', ds_state['ds_content']).removeClass('enable-chan-user');

              var chans = [];
              $('button.chanbutton[uuid=' + uuid + ']', ds_state['ds_content']).each(function(i) {
                      chans.push(kismet.unsanitizeHTML($(this).attr('channel')));
                });

              var jscmd = {
                  "cmd": "hop",
                  "channels": chans,
                  "uuid": uuid
              };

              var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));

                try {
                    $.ajax({
                        url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
                        method: 'POST',
                        data: postdata,
                        dataType: 'json',
                        success: function(data) {
                            data = kismet.sanitizeObject(data);
                            for (var u in ds_state['datasources']) {
                                if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                    ds_state['datasources'][u] = data;
                                    ds_state['remove_pending'].push(uuid);
                                    update_datasource2(null);
                                    break;
                                }
                            }
                        },
                        timeout: 30000,
                    });
                } finally {
                    ds_state['remove_pending'].push(uuid);
                }

              $('button.chanbutton[uuid='+ uuid + ']', ds_state['ds_content']).each(function(i) {
                  // Disable all but the first available channel
                  if ($(this).attr('channel') == 1) {
                      $(this).removeClass('disabled-chan-user');
                      $(this).removeClass('enable-chan-system');
                      $(this).addClass('enable-chan-user')
                  } else {
                      $(this).removeClass('enable-chan-system');
                      $(this).removeClass('disable-chan-user');
                  }
              });
              })
            );

          var max_hop_rate = source['kismet.datasource.type_driver']['kismet.datasource.driver.max_hop_rate'];
          var initial_rate = hop_rate_to_input(source['kismet.datasource.hop_rate'] > 0 ?
                  source['kismet.datasource.hop_rate'] : 1);

          if (max_hop_rate > 0 && source['kismet.datasource.hop_rate'] > max_hop_rate)
              initial_rate = hop_rate_to_input(max_hop_rate);

          quickopts.append(
            $('<span>', {
              id: "hopratectl",
              uuid: source['kismet.datasource.uuid']
            })
            .append(
              $('<input>', {
                id: "hopratevalue",
                uuid: source['kismet.datasource.uuid'],
                type: "number",
                min: "0",
                step: "any",
                style: "width: 5em;",
              }).val(initial_rate[0])
            )
            .append(
              $('<select>', {
                id: "hoprateunit",
                uuid: source['kismet.datasource.uuid']
              })
              .append($('<option>', { value: "sec" }).text("hops/sec"))
              .append($('<option>', { value: "min" }).text("hops/min"))
              .append($('<option>', { value: "dwell" }).text("sec per hop"))
              .val(initial_rate[1])
            )
            .append(
              $('<button>', {
                id: "hopratecmd",
                uuid: source['kismet.datasource.uuid']
              }).html("Set Rate")
              .button()
              .on('click', function() {
                var uuid = $(this).attr('uuid');
                var sdiv = $('#' + uuid, ds_state['ds_content']);
                var valinput = $('#hopratevalue[uuid=' + uuid + ']', sdiv);
                var unitinput = $('#hoprateunit[uuid=' + uuid + ']', sdiv);

                var rate = hop_input_to_rate(valinput.val(), unitinput.val());

                if (isNaN(rate)) {
                    $('#hopratemax', sdiv).text("  Invalid hop rate");
                    return;
                }

                var maxrate = 0;
                for (var u in ds_state['datasources']) {
                    if (ds_state['datasources'][u]['kismet.datasource.uuid'] == uuid) {
                        maxrate = ds_state['datasources'][u]['kismet.datasource.type_driver']['kismet.datasource.driver.max_hop_rate'];
                        break;
                    }
                }

                // Cap to the driver maximum and show the value actually used
                if (maxrate > 0 && rate > maxrate) {
                    rate = maxrate;
                    var capped = hop_rate_to_input(rate);
                    valinput.val(capped[0]);
                    unitinput.val(capped[1]).selectmenu('refresh');
                }

                ds_state['defer_source_update'] = true;
                ds_state['defer_command_progress'] = true;

                $('.k-ds-modal-message', sdiv).html("Setting channel hop rate...");
                $('.k-ds-modal', sdiv).show();

                var chans = [];
                $('button.chanbutton[uuid=' + uuid + ']', ds_state['ds_content']).each(function(i) {
                    chans.push(kismet.unsanitizeHTML($(this).attr('channel')));
                });

                var jscmd = {
                    "cmd": "hop",
                    "channels": chans,
                    "rate": rate,
                    "uuid": uuid
                };

                var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));

                try {
                    $.ajax({
                        url: `${local_uri_prefix}datasource/by-uuid/${uuid}/set_channel.cmd`,
                        method: 'POST',
                        data: postdata,
                        dataType: 'json',
                        success: function(data) {
                            data = kismet.sanitizeObject(data);
                            for (var u in ds_state['datasources']) {
                                if (ds_state['datasources'][u]['kismet.datasource.uuid'] == data['kismet.datasource.uuid']) {
                                    ds_state['datasources'][u] = data;
                                    ds_state['remove_pending'].push(uuid);
                                    update_datasource2(null);
                                    break;
                                }
                            }
                        },
                        timeout: 30000,
                    });
                } finally {
                    ds_state['remove_pending'].push(uuid);
                }
              })
            )
            .append(
              $('<span>', {
                id: "hopratemax"
              })
            )
          );

          quickopts.append(
            $('<span>', {
              id: "hoprate"
              }).html("")
            );

          // Themed like the other menus; it needs its container to put its button in.  The
          // menu itself is on the body, so lift it above the datasource panel when it opens
          $('#hoprateunit', quickopts).selectmenu({
              width: "9em",
              open: function() {
                  var z = parseInt($(this).closest('.jsPanel').css('z-index')) || 0;
                  $(this).selectmenu('menuWidget').parent().css('z-index', z + 1);
              },
          });
        }

        var max_hop_rate = source['kismet.datasource.type_driver']['kismet.datasource.driver.max_hop_rate'];

        if (max_hop_rate > 0)
            $('#hopratemax', quickopts).text("  (max " + hop_to_human(max_hop_rate) + ")");
        else
            $('#hopratemax', quickopts).text("");

        var uuid = source['kismet.datasource.uuid'];
        var hop_chans = source['kismet.datasource.hop_channels'];
        var lock_chan = source['kismet.datasource.channel'];
        var hopping = source['kismet.datasource.hopping'];

        if (!sdiv.hasClass('channel_pending')) {
            if (source['kismet.datasource.hopping']) {
                $('#hop', quickopts).addClass('enable-chan-user');
                $('#lock', quickopts).removeClass('enable-chan-user');
                $('#hoprate', quickopts).html("  (Hopping at " + 
                        hop_to_human(source['kismet.datasource.hop_rate']) + ")");
                $('#hoprate', quickopts).show();
            } else {
                $('#hop', quickopts).removeClass('enable-chan-user');
                $('#lock', quickopts).addClass('enable-chan-user');
                $('#hoprate', quickopts).hide();
            }

            $('button.chanbutton', chanbuttons).each(function(i) {
                var chan = $(this).attr('channel');

                // If locked, only highlight locked channel
                if (!hopping) {
                    if (chan === lock_chan) {
                        $(this).addClass('enable-chan-user');
                        $(this).removeClass('enable-chan-system');
                    } else {
                        $(this).removeClass('enable-chan-user');
                        $(this).removeClass('enable-chan-system');
                    }

                    return;
                }

                // Flag the channel if it's found, and not explicitly disabled
                if (hop_chans.indexOf(chan) != -1 && !($(this).hasClass('disable-chan-user'))) {
                    $(this)
                    .addClass('enable-chan-system');
                } else {
                    $(this)
                    .removeClass('enable-chan-system');
                }
            });

            if (source['kismet.datasource.running']) {
                $('#closecmd', pausediv).removeClass('enable-chan-user');
                $('#opencmd', pausediv).addClass('enable-chan-user');
                $('#pausetext', pausediv).hide();
            } else {
                $('#closecmd', pausediv).addClass('enable-chan-user');
                $('#opencmd', pausediv).removeClass('enable-chan-user');
                $('#pausetext', pausediv).show();
            }

        }

        var s = source['kismet.datasource.interface'];

        if (source['kismet.datasource.interface'] !==
                source['kismet.datasource.capture_interface']) {
            s = s + "(" + source['kismet.datasource.capture_interface'] + ")";
        }

        {
            const drv = source['kismet.datasource.type_driver']['kismet.datasource.driver.type'];
            if (is_cell_driver(drv)) {
                const parsed = cell_parse_label(cell_source_label(source));
                $('.k-ds-modem', sdiv).first().text(
                    parsed && (parsed.name || parsed.firmware) ?
                        cell_row_title(parsed, drv) : (CELL_CAPTURE_LABEL[drv] || ''));
            }
        }

        /* `span#error`, not `#error`. The header's icon span and the Error
         * row (top_row 'error') share the id, and a find() matches both: from
         * the second refresh on, .html(icon) would replace the row's cells
         * with the icon and top_row would find no <td> to fill, so every
         * errored source -- Wi-Fi too -- would show its reason for ~1 s, then
         * a blank row. */
        if (source['kismet.datasource.error']) {
            $('span#error', sdiv).html('<i class="k-ds-error fa fa-exclamation-circle"></i>');
            top_row(sdiv, 'error', '<i class="k-ds-error fa fa-exclamation-circle"></i><b>Error</b>',
                    source['kismet.datasource.error_reason']);
        } else {
            $('span#error', sdiv).empty();
            $('tr#error', sdiv).remove();
        }

        if (!source['kismet.datasource.running']) {
            $('#paused', sdiv).html('<i class="k-ds-paused fa fa-pause-circle"></i>');
        } else {
            $('#paused', sdiv).empty();
        }

        set_row(sdiv, 'interface', '<b>Interface</b>', s);
        if (source['kismet.datasource.hardware'] !== '')
            set_row(sdiv, 'hardware', '<b>Hardware</b>', source['kismet.datasource.hardware']);
        if ('kismet.datasource.remote_ip' in source && source['kismet.datasource.remote_ip'] !== '')
            set_row(sdiv, 'address', '<b>Address</b>', source['kismet.datasource.remote_ip']);
        if ('kismet.datasource.ipc_pid' in source && source['kismet.datasource.ipc_pid'] !== 0)
            set_row(sdiv, 'address', '<b>Process ID</b>', source['kismet.datasource.ipc_pid']);
        if ('kismet.datasource.datasource_version' in source && source['kismet.datasource.datasource_version'] !== '')
            set_row(sdiv, 'version', '<b>Version</b>', source['kismet.datasource.datasource_version']);
        set_row(sdiv, 'uuid', '<b>UUID</b>', source['kismet.datasource.uuid']);
        set_row(sdiv, 'packets', '<b>Packets</b>', source['kismet.datasource.num_packets']);
        set_row(sdiv, 'invalidpackets', '<b>Invalid Packets</b>', source['kismet.datasource.num_error_packets']);
        set_row(sdiv, 'filteredpackets', '<b>Filtered Packets</b>', source['kismet.datasource.num_filtered_packets']);
        set_row(sdiv, 'droppedpackets', '<b>Dropped Packets</b>', source['kismet.datasource.num_dropped_packets']);

        /* celldiag sources carry a second set of counters that no generic
         * datasource has. Rendered right after Packets because for this
         * source type `num_packets` is the least informative number on the
         * panel -- a celldiag source can be reading DIAG bytes healthily while
         * its observation count sits at zero, and vice versa. */
        celldiag_render_rows(source, sdiv, set_row, Date.now() / 1000);
        /* The cellat equivalent. Each renderer returns false for any
         * source that is not its own type, so both are called for every
         * source and exactly one (or neither) renders. */
        cellat_render_rows(source, sdiv, set_row, Date.now() / 1000);
        /* The whole-modem switch, on every cell source. */
        if (is_cell_driver(source['kismet.datasource.type_driver']['kismet.datasource.driver.type']))
            cell_modem_group_row(source, sdiv, set_row);

        var rts = "";
        if (source['kismet.datasource.remote']) {
            rts = 'Remote sources are not re-opened by Kismet, but will be re-opened when the ' +
                'remote source reconnects.';
        } else if (source['kismet.datasource.passive']) {
            rts = 'Passive sources are not directly managed by Kismet, they accept data ' +
                'from external services.';
        } else if (source['kismet.datasource.retry']) {
            rts = 'Kismet will try to re-open this source if an error occurs';
            if (source['kismet.datasource.retry_attempts'] && 
                    source['kismet.datasource.running'] == 0) {
                rts = rts + ' (Tried ' + source['kismet.datasource.retry_attempts'] + ' times)';
            }
        } else {
            rts = 'Kismet will not re-open this source';
        }

        set_row(sdiv, 'retry', '<b>Retry on Error</b>', rts);
        set_row(sdiv, 'pausing', '<b>Active</b>', pausediv);

        if (source['kismet.datasource.running']) {
            if (source['kismet.datasource.type_driver']['kismet.datasource.driver.tuning_capable']) {
                set_row(sdiv, 'chanopts', '<b>Channel Options</b>', quickopts);
                set_row(sdiv, 'channels', '<b>Channels</b>', chanbuttons);
            } else {
                $('tr#chanopts', sdiv).remove();
                $('tr#channels', sdiv).remove();
            }
        } else {
            $('tr#chanopts', sdiv).remove();
            $('tr#channels', sdiv).remove();
        }

        try {
            sdiv.accordion("refresh");
        } catch (e) { 
            ;
        }
    }
}

export const DataSources2 = () => {
    var w = $(window).width() * 0.95;
    var h = $(window).height() * 0.75;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    ds_state = {};
    ds_state['remove_pending'] = []
    ds_state['chantids'] = {}

    var content =
        $('<div class="k-ds-contentdiv">');

    ds_state['closed'] = 0;

    ds_state['panel'] = $.jsPanel({
        id: 'datasources',
        headerTitle: '<i class="fa fa-cogs"></i> Data Sources',
        headerControls: {
            iconfont: 'jsglyph',
            minimize: 'remove',
            smallify: 'remove',
        },
        content: content,

        resizable: {
            stop: function(event, ui) {
                $('div.accordion', ui.element).accordion("refresh");
            }
        },

        onmaximized: function() {
            $('div.accordion', this.content).accordion("refresh");
        },

        onnormalized: function() {
            $('div.accordion', this.content).accordion("refresh");
        },

        onclosed: function() {
            ds_state['closed'] = 1;

            if ('datasource_get_tid' in ds_state)
                clearTimeout(ds_state['datasource_get_tid']);
            if ('datasource_interface_tid' in ds_state)
                clearTimeout(ds_state['datasource_interface_tid']);
        }
    })
    .resize({
        width: w,
        height: h
    })
    .reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offy,
    })
    .front()
    .contentResize();

    ds_state["content"] = content;
    ds_state["ds_content"] = content;
    ds_state["kismet_sources"] = [];
    ds_state["kismet_interfaces"] = [];

    datasource_source_refresh(function(data) {
        update_datasource2(data);
        });
    datasource_interface_refresh(function(data) {
        update_datasource2(data);
        });
}

/* Get the list of active sources */
function datasource_source_refresh(cb) {
    var grab_sources = function(cb) {
        $.get(local_uri_prefix + "datasource/all_sources.json")
        .done(function(data) {
            ds_state['kismet_sources'] = kismet.sanitizeObject(data);
            cb(data);
            ds_state['defer_source_update'] = false;
        })
        .always(function() {
            if (ds_state['closed'] == 1)
                return;

            ds_state['datasource_get_tid'] = setTimeout(function() {
                datasource_source_refresh(cb)
            }, 1000);
        });
    };

    grab_sources(cb);

}

/* Get the list of potential interfaces */
function datasource_interface_refresh(cb) {
    var grab_interfaces = function(cb) {
        try {
            $.ajax({
                url: local_uri_prefix + "datasource/list_interfaces.json",
                success: function(data) {
                    ds_state['kismet_interfaces'] = kismet.sanitizeObject(data);
                    ds_state['done_interface_update'] = true;
                    cb(data);
                    ds_state['defer_interface_update'] = false;
                },
                timeout: 30000,
            });
        } finally {
            if (ds_state['closed'] == 1)
                return;

            ds_state['datasource_interface_tid'] = setTimeout(function() {
                datasource_interface_refresh(cb)
            }, 3000);
        }
    };

    grab_interfaces(cb);
}

