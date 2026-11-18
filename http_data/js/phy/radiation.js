// Radiation sensors (Radiacode, Radview): count rate and dose rate in the
// ribbon and on the overview, and a Radiation window with their history and
// gamma spectrum.
//
// The sensors are at /radiation/sensors/all_sensors and arrive every few
// seconds on the RADIATION eventbus topic, as a map of sensor UUID to sensor.
// A sensor with a spectrum has its windows (device, session, past hour, and
// per-minute) at /radiation/sensors/by-uuid/<uuid>/spectrum.

import { spectrumChart, waterfall, energyAxis, gammaLines } from '../widgets/spectrum.js';

const rs = 'radiation.sensor';
const sp = 'radiation.spectrum';

const spans = { minute: ['Minute', '-60s'], hour: ['Hour', '-60m'], day: ['Day', '-24h'] };
const binSeconds = { minute: 1, hour: 60, day: 3600 };
const refresh = { minute: 2, hour: 15, day: 60 };
const windows = { session: 'Session', hour: 'Past hour', device: 'Device' };
const windowHelp = {
    session: 'Counted since Kismet started tracking the sensor',
    hour: 'Counted over the past hour',
    device: 'Everything the sensor has added up itself since its spectrum was last reset',
};
const spectrumRefresh = 10;

// A spectrum window from the server as chart options: counts on the keV axis,
// with the count rate per channel in the readout
function gammaSpectrum(win, { scale = 'log', markers = false } = {}) {
    const dur = win?.[`${sp}.duration`] ?? 0;
    return {
        values: win?.[`${sp}.counts`] ?? [],
        axis: energyAxis(win?.[`${sp}.calibration`]) ?? undefined,
        scale,
        markers: markers ? gammaLines : [],
        rows: dur > 0 ? (ch, v) => [['Rate', `${((v || 0) / dur).toFixed(3)} CPS`]] : null,
    };
}

// Common gamma lines, as hints to what a peak might be, never an identification

const safetyNote = 'Readings depend on the detector, its calibration, and how it is held.  ' +
    'Never use them to decide whether an area is safe.';

const noSourcesNote = 'Not shown while the server has no radiation detection sources.';
const noSourcesText = 'No radiation detection sources yet.  This shows readings once the server has one.';

const uuidRe = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;

const sensorFields = [
    `${rs}.type`, `${rs}.cps_rrd`, `${rs}.usv_rrd`, `${rs}.cps_err`, `${rs}.usv_err`,
    `${rs}.dose_total`, `${rs}.dose_total_duration`, `${rs}.temperature`, `${rs}.battery`,
    `${rs}.last_status_time`, `${rs}.spectrum_channels`, `${rs}.spectrum_time`,
    [`${rs}.datasource/kismet.datasource.name`, 'name'],
    [`${rs}.datasource/kismet.datasource.uuid`, 'source'],
];

// Dose rate in uSv/h to three figures
function doseText(v) {
    if (!Number.isFinite(v))
        return '-';
    if (v === 0)
        return '0';
    return v < 1 ? v.toFixed(3) : v.toPrecision(3);
}

const cpsText = (v) => (Number.isFinite(v) ? v.toFixed(v < 100 ? 2 : 0) : '-');

export function register(kismet) {
    const { ui, eventbus, api, format, rrd, dom, icons, settings, clock } = kismet;
    const { el } = dom;
    const { dialog } = kismet.widgets.dialog;
    const { historyGraph } = kismet.widgets;
    const { series, stat } = kismet.widgets.charts;

    icons.define('radiation', '<circle cx="12" cy="12" r="1.6"/>' +
        '<path d="M10.3 9 7.5 4.2a9 9 0 0 1 9 0L13.7 9a3.4 3.4 0 0 0-3.4 0z"/>' +
        '<path d="M15.4 12h5.6a9 9 0 0 1-4.5 7.8l-2.8-4.9a3.4 3.4 0 0 0 1.7-2.9z"/>' +
        '<path d="M8.6 12H3a9 9 0 0 0 4.5 7.8l2.8-4.9A3.4 3.4 0 0 1 8.6 12z"/>');

    const serverNow = () => (clock.isKnown() ? clock.now() : undefined);
    const hasDose = (s) => s[`${rs}.type`] !== 'Radview';

    // The highest current reading across the sensors in a RADIATION event
    function highest(event, field) {
        let best = null;
        for (const s of Object.values(event ?? {})) {
            const r = s?.[field];
            if (!r || (field === `${rs}.usv_rrd` && !hasDose(s)))
                continue;
            const v = rrd.latest(r, serverNow());
            if (best === null || v > best)
                best = v;
        }
        return best;
    }

    function ribbonValue(name) {
        const value = el('span', { class: 'stat-value' }, '-');
        return { node: el('span', { class: 'stat-line' }, icons.icon(name), value), value };
    }

    function clickToOpen(body) {
        const s = body.parentElement;
        s.classList.add('clickable');
        s.title = 'Show the radiation sensors';
        s.addEventListener('click', () => openRadiation());
    }

    ui.menuItems.add({
        id: 'radiation', title: 'Radiation', icon: 'radiation',
        onClick: () => openRadiation(),
    });

    // The ribbon stats and overview cards are always offered, but the stats
    // are only on by default once the server knows a radiation sensor (added
    // again then, so the ribbon picks up the new default).  The cards stay out
    // of the default overview until added.
    let sensorsKnown = null;
    function addSensorViews(known) {
        if (sensorsKnown === true || sensorsKnown === known)
            return;
        sensorsKnown = known;

        ui.ribbonStats.add({
            id: 'radiation-cps', title: 'Radiation counts', priority: 60, defaultVisible: known,
            description: 'Counts per second from the radiation sensors (the highest, with more than one); ' +
                `click for the sensors.  ${noSourcesNote}`,
            create(body) {
                body.parentElement.hidden = !known;
                const v = ribbonValue('radiation');
                body.append(v.node);
                clickToOpen(body);
                return eventbus.subscribe('RADIATION', null, (e) => {
                    const c = highest(e, `${rs}.cps_rrd`);
                    v.value.textContent = c === null ? '-' : `${cpsText(c)} CPS`;
                });
            },
        });

        ui.ribbonStats.add({
            id: 'radiation-dose', title: 'Radiation dose rate', priority: 61, defaultVisible: known,
            description: 'Dose rate from the radiation sensors that report one, in uSv/h; ' +
                `click for the sensors.  ${noSourcesNote}`,
            create(body) {
                body.parentElement.hidden = !known;
                const v = ribbonValue('radiation');
                body.append(v.node);
                clickToOpen(body);
                return eventbus.subscribe('RADIATION', null, (e) => {
                    const d = highest(e, `${rs}.usv_rrd`);
                    v.value.textContent = d === null ? '-' : `${doseText(d)} µSv/h`;
                });
            },
        });

        ui.dashboardCards.add({
            id: 'radiation', title: 'Radiation', priority: 80, w: 3, h: 5, defaultHidden: true,
            description: `Count and dose rate from the radiation sensors.  ${noSourcesNote}`,
            loading: ['stat', 'graph'],
            onClick: () => openRadiation(),
            create(body) {
                if (!known) {
                    body.append(el('p', { class: 'muted' }, noSourcesText));
                    return {};
                }
                const dose = stat('µSv/h');
                const graph = historyGraph({ type: 'line', unit: 'CPS', height: null, joinGaps: true });
                body.append(dose.node, graph.node);
                const stop = eventbus.subscribe('RADIATION', null, (e) => {
                    const d = highest(e, `${rs}.usv_rrd`);
                    const c = highest(e, `${rs}.cps_rrd`);
                    if (d !== null)
                        dose.update(doseText(d), `µSv/h, ${cpsText(c)} CPS`);
                    else
                        dose.update(c === null ? '-' : cpsText(c), c === null ? 'No radiation sensors' : 'CPS');
                    // The first sensor's last minute of counts
                    const first = Object.values(e ?? {}).find((s) => s?.[`${rs}.cps_rrd`]);
                    if (first)
                        graph.draw(rrd.history(first[`${rs}.cps_rrd`], serverNow(), 'minute', { blank: NaN }).slice(0, -1),
                            [spans.minute[1], 'now']);
                });
                return { destroy: () => { stop(); graph.destroy(); } };
            },
        });

        ui.dashboardCards.add({
            id: 'radiation-spectrum', title: 'Radiation spectrum', priority: 81, w: 6, h: 6, defaultHidden: true,
            description: `Gamma spectrum from a radiation sensor that sends one.  ${noSourcesNote}`,
            fill: true, loading: 'graph',
            onClick: () => openRadiation(),
            settings: [
                { id: 'window', title: 'Window', type: 'choice', default: 'hour',
                    options: Object.entries(windows).map(([id, title]) => ({ id, title })) },
                { id: 'linear', title: 'Linear scale', type: 'bool', default: false },
                { id: 'markers', title: 'Mark common gamma lines', type: 'bool', default: false },
            ],
            create(body, { settings: cs }) {
                if (!known) {
                    body.append(el('p', { class: 'muted' }, noSourcesText));
                    return {};
                }
                const win = windows[cs.get('window')] ? cs.get('window') : 'hour';
                const caption = el('div', { class: 'muted' });
                const chart = spectrumChart({ height: null });
                body.append(caption, chart.node);
                let sensor = null;
                let showing = true;
                let timer = null;
                let fetching = false;

                // The first sensor with a spectrum, from the live sensor list
                const stop = eventbus.subscribe('RADIATION', null, (e) => {
                    const found = Object.entries(e ?? {}).find(([, s]) => s?.[`${rs}.spectrum_channels`] > 0);
                    const next = found && uuidRe.test(found[0]) ? found[0] : null;
                    if (next !== sensor) {
                        sensor = next;
                        load();
                    }
                    if (!sensor) {
                        caption.textContent = 'No radiation sensor here sends a spectrum';
                        chart.draw({ values: [] });
                    }
                });

                async function load() {
                    clearTimeout(timer);
                    if (fetching)
                        return;
                    if (!sensor || !showing || document.visibilityState === 'hidden') {
                        timer = setTimeout(load, spectrumRefresh * 1000);
                        return;
                    }
                    const asked = sensor;
                    fetching = true;
                    try {
                        const r = await api.get(`radiation/sensors/by-uuid/${asked}/spectrum.json`);
                        if (asked === sensor) {
                            const w = r?.[`${sp}.${win}`];
                            const dur = w?.[`${sp}.duration`] ?? 0;
                            caption.textContent = w ? `${windows[win]}: ${format.count(w[`${sp}.total`] ?? 0)} counts` +
                                (dur > 0 ? `, ${((w[`${sp}.total`] ?? 0) / dur).toFixed(2)} CPS` : '') :
                                `${windows[win]}: nothing counted yet`;
                            chart.draw(gammaSpectrum(w, { scale: cs.get('linear') ? 'linear' : 'log',
                                markers: cs.get('markers') }));
                        }
                    } catch (err) {
                        caption.textContent = err.message;
                    } finally {
                        fetching = false;
                    }
                    timer = setTimeout(load, spectrumRefresh * 1000);
                }

                return {
                    show() {
                        showing = true;
                        load();
                    },
                    hide() {
                        showing = false;
                    },
                    destroy() {
                        stop();
                        clearTimeout(timer);
                        chart.destroy();
                    },
                };
            },
        });
    }

    addSensorViews(false);

    // Known now, or once the server first sends the sensor list (it only does
    // when it has sensors)
    (async () => {
        try {
            const sensors = await api.post('radiation/sensors/all_sensors.json', { fields: [`${rs}.type`] });
            if (sensors && Object.keys(sensors).length) {
                addSensorViews(true);
                return;
            }
        } catch {
            // A server without the radiation phy; the event below never comes
        }
        const stop = eventbus.subscribe('RADIATION', null, (e) => {
            if (e && Object.keys(e).length) {
                addSensorViews(true);
                stop();
            }
        });
    })();

    function tabs(choices, current, onPick) {
        const buttons = Object.entries(choices).map(([id, title]) => {
            const b = el('button', { type: 'button', onclick: () => {
                current = id;
                show();
                onPick(id);
            } }, title);
            b.dataset.id = id;
            return b;
        });
        const show = () => buttons.forEach((b) => {
            b.classList.toggle('active', b.dataset.id === current);
            b.setAttribute('aria-pressed', String(b.dataset.id === current));
        });
        show();
        return el('div', { class: 'graph-tabs' }, buttons);
    }

    function readout(label, value, title = '') {
        return el('div', { class: 'mem-stat', title }, el('span', { class: 'mem-stat-label' }, label),
            el('span', { class: 'mem-stat-value' }, value));
    }

    function pointTime(i, now, span, count) {
        const bin = binSeconds[span];
        const t = (Math.floor(now / bin) - count + i) * bin;
        if (span === 'minute')
            return format.time(t).slice(-8);
        if (span === 'hour')
            return format.clock(t);
        return `${format.clock(t)} to ${format.clock(t + bin)}`;
    }

    let openWindow = null;

    function openRadiation() {
        if (openWindow?.node.isConnected) {
            openWindow.raise();
            return openWindow;
        }

        let span = settings.get('radiation.span', 'minute');
        if (!spans[span])
            span = 'minute';
        let specWindow = settings.get('radiation.window', 'session');
        if (!windows[specWindow])
            specWindow = 'session';
        let scale = settings.get('radiation.scale', 'log') === 'linear' ? 'linear' : 'log';
        let picked = settings.get('radiation.sensor', null);

        let shown = { now: Date.now() / 1000, count: 0 };
        const graph = historyGraph({ type: 'line', height: '11rem', joinGaps: true,
            pointLabel: (i) => pointTime(i, shown.now, span, shown.count), fmt: cpsText });

        const status = el('span', { class: 'muted' });
        const picker = el('select', { hidden: true, onchange: (e) => {
            picked = e.target.value;
            settings.set('radiation.sensor', picked);
            read();
        } });
        const stats = el('div', { class: 'mem-stats' });
        const empty = el('p', { class: 'muted', hidden: true },
            'No radiation sensors yet.  Add a Radiacode or Radview data source to see one here.');

        const spectrum = spectrumChart({ height: '15rem' });
        const fall = waterfall({ height: '9rem' });
        const specSummary = el('p', { class: 'muted' });
        const markers = el('input', { type: 'checkbox', checked: settings.get('radiation.markers', false),
            onchange: (e) => {
                settings.set('radiation.markers', e.target.checked);
                drawSpectrum();
            } });
        const fallCheck = el('input', { type: 'checkbox', checked: settings.get('radiation.waterfall', false),
            onchange: (e) => {
                settings.set('radiation.waterfall', e.target.checked);
                fallBox.hidden = !e.target.checked;
                fit();
                readSpectrum();
            } });
        const fallBox = el('div', { hidden: !fallCheck.checked },
            el('h3', { title: 'Each row is one minute, newest at the top; brighter is more counts' }, 'Past hour, by minute'),
            fall.node);
        const specNone = el('p', { class: 'muted', hidden: true });
        const specBody = el('div', { hidden: true },
            el('div', { class: 'pk-bar' },
                tabs(windows, specWindow, (w) => {
                    specWindow = w;
                    settings.set('radiation.window', w);
                    drawSpectrum();
                }),
                tabs({ log: 'Log', linear: 'Linear' }, scale, (s) => {
                    scale = s;
                    settings.set('radiation.scale', s);
                    drawSpectrum();
                }),
                el('label', { title: 'Mark where common gamma lines fall; a peak near one is only a hint' },
                    markers, ' Gamma lines'),
                el('label', {}, fallCheck, ' Waterfall')),
            specSummary, spectrum.node, fallBox);
        const specSection = el('details', { class: 'detail-section', hidden: true,
            open: settings.get('radiation.spectrum_open', true) },
            el('summary', {}, 'Spectrum'), specNone, specBody);
        // Not read while it's closed; opening it reads it again
        specSection.addEventListener('toggle', () => {
            settings.set('radiation.spectrum_open', specSection.open);
            fit();
            if (specSection.open)
                readSpectrum();
        });

        const historySection = el('details', { class: 'detail-section', open: settings.get('radiation.history_open', true) },
            el('summary', {}, 'History'),
            tabs(Object.fromEntries(Object.entries(spans).map(([k, v]) => [k, v[0]])), span, (s) => {
                span = s;
                settings.set('radiation.span', s);
                read();
            }),
            graph.node);
        historySection.addEventListener('toggle', () => {
            settings.set('radiation.history_open', historySection.open);
            fit();
        });

        const body = el('div', { class: 'mem-window' },
            el('div', { class: 'pk-bar' }, picker, status),
            empty,
            stats,
            el('p', { class: 'muted mem-note' }, safetyNote),
            historySection,
            specSection);

        const w = Math.min(860, window.innerWidth - 32);
        const h = Math.min(Math.round(window.innerHeight * 0.85), 960);
        const d = dialog({
            title: 'Radiation', body, modal: false, className: 'pk-panel',
            position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
            // A height the user dragged it to stays; moving it doesn't count
            onMove: (p) => {
                if (Math.abs((p?.height ?? fittedHeight) - fittedHeight) > 1)
                    userSized = true;
            },
            onClose: () => {
                clearTimeout(timer);
                clearTimeout(specTimer);
                graph.destroy();
                spectrum.destroy();
                fall.destroy();
                openWindow = null;
            },
        });

        let timer = null;
        let specTimer = null;
        let reading = false;
        let specReading = false;
        let userSized = false;
        let fittedHeight = h;
        let layoutKey = '';
        let current = null;
        let report = null;
        let reportFor = null;

        // Fit the window to everything in it, as far as the screen allows,
        // until the user sizes it themselves
        function fit() {
            if (userSized)
                return;
            requestAnimationFrame(() => {
                if (userSized || !d.node.isConnected)
                    return;
                d.fitContent({ grow: true });
                fittedHeight = d.node.offsetHeight;
            });
        }

        function chosen(sensors) {
            const ids = Object.keys(sensors);
            if (picked && sensors[picked])
                return picked;
            return ids[0] ?? null;
        }

        function showPicker(sensors) {
            const ids = Object.keys(sensors);
            picker.hidden = ids.length < 2;
            const key = ids.join('\n');
            if (picker.dataset.key !== key) {
                picker.dataset.key = key;
                picker.replaceChildren(...ids.map((id) =>
                    el('option', { value: id }, sensors[id].name || sensors[id][`${rs}.type`] || id)));
            }
            picker.value = current ?? '';
        }

        async function read() {
            clearTimeout(timer);
            if (!d.node.isConnected)
                return;
            if (!reading && document.visibilityState !== 'hidden') {
                reading = true;
                try {
                    const sensors = await api.post('radiation/sensors/all_sensors.json', { fields: sensorFields });
                    const now = serverNow();
                    const at = now ?? Date.now() / 1000;
                    current = chosen(sensors);
                    showPicker(sensors);
                    empty.hidden = current !== null;

                    const s = current ? sensors[current] : null;
                    stats.replaceChildren();
                    graph.node.hidden = !s;
                    if (s) {
                        const cps = rrd.latest(s[`${rs}.cps_rrd`], now);
                        const dose = rrd.latest(s[`${rs}.usv_rrd`], now);
                        const cpsErr = s[`${rs}.cps_err`];
                        const doseErr = s[`${rs}.usv_err`];
                        const hasStatus = s[`${rs}.last_status_time`] > 0;
                        stats.append(...[
                            readout('Count rate', `${cpsText(cps)} CPS`, cpsErr ? `±${cpsErr.toFixed(1)}%` : ''),
                            hasDose(s) ? readout('Dose rate', `${doseText(dose)} µSv/h`,
                                doseErr ? `±${doseErr.toFixed(1)}%` : '') : null,
                            hasStatus ? readout('Accumulated dose', `${doseText(s[`${rs}.dose_total`])} µSv`,
                                `Over ${format.duration(s[`${rs}.dose_total_duration`])}, as the sensor counts it`) : null,
                            hasStatus ? readout('Temperature', format.temperature(s[`${rs}.temperature`], 1)) : null,
                            hasStatus ? readout('Battery', `${Math.round(s[`${rs}.battery`])}%`) : null,
                            readout('Sensor', s[`${rs}.type`] || 'Unknown', s.name ?? ''),
                        ].filter(Boolean));

                        const hist = (f) => rrd.history(s[f], now, span, { blank: NaN }).slice(0, -1)
                            .map((v) => (v === 0 ? NaN : v));
                        const lines = [{ label: 'Counts per second', values: hist(`${rs}.cps_rrd`), color: series(0) }];
                        if (hasDose(s))
                            lines.push({ label: 'Dose rate', values: hist(`${rs}.usv_rrd`), color: series(1),
                                axis: 'right', unit: 'µSv/h', fill: false, fmt: (v) => `${doseText(v)} µSv/h` });
                        shown = { now: at, count: lines[0].values.length };
                        graph.draw(lines, [spans[span][1], 'now']);
                    }

                    // The spectrum follows the sensor shown, and appears once it sends one
                    const hadSpectrum = !specBody.hidden;
                    const hasSpectrum = s?.[`${rs}.spectrum_channels`] > 0;
                    specSection.hidden = !s;
                    specBody.hidden = !hasSpectrum;
                    specNone.hidden = !s || hasSpectrum;
                    if (s && !hasSpectrum)
                        specNone.textContent = s[`${rs}.type`] === 'Radiacode' ?
                            'No spectrum data from this sensor; its data source may have spectrum_interval=0 set.' :
                            'Spectrum data isn\'t available with this detector.';
                    if (reportFor !== current) {
                        report = null;
                        reportFor = current;
                        if (hasSpectrum)
                            drawSpectrum();
                        if (hasSpectrum && hadSpectrum)
                            readSpectrum();
                    }
                    if (hasSpectrum && !hadSpectrum)
                        readSpectrum();

                    const key = `${!!s}|${hasSpectrum}|${stats.children.length}|${picker.hidden}`;
                    if (key !== layoutKey) {
                        layoutKey = key;
                        fit();
                    }
                    status.textContent = `Updated ${format.time(at)}`;
                } catch (err) {
                    status.textContent = err.status === 404 ? 'This server doesn\'t track radiation sensors' : err.message;
                } finally {
                    reading = false;
                }
            }
            timer = setTimeout(read, refresh[span] * 1000);
        }

        async function readSpectrum() {
            clearTimeout(specTimer);
            if (!d.node.isConnected)
                return;
            if (!specReading && current && uuidRe.test(current) && !specBody.hidden && specSection.open &&
                    document.visibilityState !== 'hidden') {
                specReading = true;
                const sensor = current;
                try {
                    const path = `radiation/sensors/by-uuid/${sensor}/spectrum.json` +
                        (fallCheck.checked ? '?minutes=1' : '');
                    const r = await api.get(path);
                    // Dropped if the sensor shown changed while it loaded
                    if (sensor === current) {
                        report = r;
                        drawSpectrum();
                        fit();
                    }
                } catch (err) {
                    specSummary.textContent = err.message;
                } finally {
                    specReading = false;
                }
            }
            specTimer = setTimeout(readSpectrum, spectrumRefresh * 1000);
        }

        function drawSpectrum() {
            const win = report?.[`${sp}.${specWindow}`];
            const dur = win?.[`${sp}.duration`] ?? 0;
            const total = win?.[`${sp}.total`] ?? 0;
            if (win) {
                const parts = [`${format.count(total)} counts over ${format.duration(dur)}`];
                if (dur > 0)
                    parts.push(`${(total / dur).toFixed(2)} CPS`);
                if (win[`${sp}.start_time`] > 0)
                    parts.push(`since ${format.time(win[`${sp}.start_time`])}`);
                specSummary.textContent = parts.join(', ');
                specSummary.title = windowHelp[specWindow];
            } else {
                specSummary.textContent = specWindow === 'device' ? 'This sensor doesn\'t keep a spectrum of its own' :
                    'Nothing counted in this window yet';
                specSummary.title = '';
            }
            spectrum.draw(gammaSpectrum(win, { scale, markers: markers.checked }));

            if (fallCheck.checked) {
                const rows = (report?.[`${sp}.minutes`] ?? []).map((m) => ({
                    label: format.time(m[`${sp}.start_time`]), values: m[`${sp}.counts`] ?? [],
                }));
                const any = report?.[`${sp}.session`] ?? report?.[`${sp}.hour`];
                fall.draw({ rows, axis: energyAxis(any?.[`${sp}.calibration`]) ?? undefined,
                    empty: 'No minutes counted yet' });
            }
        }

        read();
        openWindow = d;
        return d;
    }
}
