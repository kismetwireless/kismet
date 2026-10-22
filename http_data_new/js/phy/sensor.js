// RF sensors (weather stations, thermometers, tire pressure, switches, air
// quality, ...) decoded by rtl_433 and similar SDR tools.

const base = 'kismet.device.base';
const s = 'sensor.device';

const spans = { minute: ['kismet.common.rrd.minute_vec', 1], hour: ['kismet.common.rrd.hour_vec', 60], day: ['kismet.common.rrd.day_vec', 3600] };

// A reading's history, oldest first, with null where nothing was recorded
function series(rrd, now, span) {
    const [name, bin] = spans[span];
    const data = rrd?.[name];
    if (!Array.isArray(data) || data.length === 0)
        return [];
    const lastTime = rrd['kismet.common.rrd.last_time'] ?? 0;
    const blank = rrd['kismet.common.rrd.blank_val'];
    const last = Math.floor(lastTime / bin);
    const end = Math.floor((now ?? lastTime) / bin);
    const len = data.length;
    const out = new Array(len);
    for (let i = 0; i < len; i++) {
        const t = end - (len - 1 - i);
        const v = data[((t % len) + len) % len];
        out[i] = (t > last || t <= last - len || v === blank) ? null : v;
    }
    return out;
}

// Gaps carry the last known value forward (or the next one back, at the start)
function fillGaps(values) {
    const first = values.find((v) => v !== null) ?? 0;
    let last = first;
    return values.map((v) => (v === null ? last : (last = v)));
}

// For counters (rain, lightning strikes, meter readings): how much it went up
// in each interval.  A counter that goes down was reset, and counts as 0.
function deltas(values) {
    let last = null;
    return values.map((v) => {
        if (v === null)
            return 0;
        const d = last === null || v < last ? 0 : v - last;
        last = v;
        return d;
    });
}

// A value with its past minute, hour, and day as small bar graphs.  Used as a
// field's draw(); `counter` readings graph the change per interval.
export function readingWithHistory(kismet, { rrdField, show = (v) => String(v), counter = false }) {
    const { el } = kismet.dom;
    const { barGraph } = kismet.widgets.cellgraphs;

    return (cell, value, rec, state) => {
        if (!state.value) {
            state.value = el('div', { class: 'reading-value' });
            state.graphs = {};
            const rows = Object.keys(spans).map((span) => {
                state.graphs[span] = el('span', { class: 'reading-graph', style: { display: 'inline-block', width: '10em' } });
                return el('div', { class: 'reading-history' },
                    el('span', { class: 'muted', style: { display: 'inline-block', width: '1.5em' } }, span[0].toUpperCase()),
                    state.graphs[span]);
            });
            cell.replaceChildren(state.value, ...rows);
        }

        state.value.textContent = value === undefined || value === null ? '' : show(value);

        const rrd = kismet.api.field(rec, rrdField);
        const now = kismet.clock.isKnown() ? kismet.clock.now() : undefined;
        for (const span of Object.keys(spans)) {
            const raw = series(rrd, now, span);
            let values = counter ? deltas(raw) : fillGaps(raw);
            // Bars grow up from the lowest value, so readings below zero still draw
            const low = Math.min(0, ...values);
            values = values.map((v) => v - low);
            state.graphs[span].replaceChildren(barGraph(values, {
                title: `Past ${span}${counter ? ', change per interval' : ''}`,
            }));
        }
    };
}

// 16-point compass direction for a bearing in degrees
function compass(deg) {
    const points = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
    return points[Math.round((((deg % 360) + 360) % 360) / 22.5) % 16];
}

const temperature = (c) => `${Number(c).toFixed(1)} °C (${(c * 9 / 5 + 32).toFixed(1)} °F)`;
const speed = (kph) => `${Number(kph).toFixed(1)} km/h (${(kph / 1.609344).toFixed(1)} mph)`;

export function register(kismet) {
    const { ui, icons, dom } = kismet;
    const isSensor = (row) => row[`${base}.phyname`] === 'RFSENSOR';
    const reading = (opts) => readingWithHistory(kismet, opts);

    icons.define('gauge', '<path d="M4.5 18a9 9 0 1 1 15 0"/><path d="M12 13l4-5"/><circle cx="12" cy="13" r="1.2"/>');

    ui.deviceIcons.add({
        id: 'rfsensor', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isSensor(row) ? icons.icon('gauge', 'RF sensor') : null),
    });

    ui.rowHighlights.add({
        id: 'rfsensor_all', name: 'Sensor device', priority: 100,
        description: 'RF sensors (weather, temperature, tire pressure, and more)',
        defaultColor: '#ffb3cc', defaultEnabled: true,
        fields: [`${base}.phyname`],
        match: isSensor,
    });

    const c = `${s}/${s}.common`;
    const therm = `${s}/${s}.thermometer`;
    const moist = `${s}/${s}.moisturesensor`;
    const weather = `${s}/${s}.weatherstation`;
    const tpms = `${s}/${s}.tpms`;
    const sw = `${s}/${s}.switch`;
    const light = `${s}/${s}.lightningsensor`;
    const aqi = `${s}/${s}.aqi`;
    // A group is shown only when the sensor has that kind of reading
    const has = (path) => (dev) => {
        const v = kismet.api.field(dev, path);
        return v !== undefined && v !== null && v !== 0 && v !== '';
    };

    ui.deviceDetails.add({
        id: 'rfsensor', title: 'RF sensor', priority: 5,
        match: (device) => device[`${base}.phyname`] === 'RFSENSOR',
        fields: [
            { title: 'Model', field: `${c}/${s}.model`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'The device model, as rtl_433 reports it.' },
            { title: 'Device ID', field: `${c}/${s}.id`, hideEmpty: true,
                help: 'The device ID sent in the radio protocol, if there is one.' },
            { title: 'SNR', field: `${c}/${s}.snr`, hideEmpty: true, hideZero: true,
                help: 'The signal-to-noise ratio the decoder reported, when the signal level in dBm isn\'t known.' },
            { title: 'RSSI', field: `${c}/${s}.rssi`, hideEmpty: true, hideZero: true,
                help: 'The signal level the decoder reported, when its units aren\'t known.' },
            { title: 'Noise', field: `${c}/${s}.noise`, hideEmpty: true, hideZero: true,
                help: 'The noise level the decoder reported, when its units aren\'t known.' },
            { title: 'Sub-channel', field: `${c}/${s}.subchannel`, hideZero: true,
                help: 'Some devices send an extra channel number to tell them apart.' },
            { title: 'Battery', field: `${c}/${s}.battery`, hideEmpty: true,
                help: 'The battery status the sensor sends.  Vendors differ: it may be a word like "OK" or a number, which may be a level or just a flag.' },

            {
                group: 'Thermometer', show: has(therm),
                fields: [
                    { title: 'Temperature', field: `${therm}/${s}.temperature`, show: (v) => v !== undefined && v !== '',
                        draw: reading({ rrdField: `${therm}/${s}.temperature_rrd`, show: temperature }),
                        help: 'The temperature the sensor reports, with its past minute (M), hour (H), and day (D).' },
                ],
            },
            {
                group: 'Moisture', show: has(moist),
                fields: [
                    { title: 'Moisture', field: `${moist}/${s}.moisture`, show: (v) => v !== undefined && v !== '',
                        draw: reading({ rrdField: `${moist}/${s}.moisture_rrd`, show: (v) => `${v}%` }),
                        help: 'Moisture or humidity, usually as a percentage, with its past minute (M), hour (H), and day (D).  Not every sensor reports a percentage.' },
                ],
            },
            {
                group: 'Weather', show: has(weather),
                fields: [
                    { title: 'Wind direction', field: `${weather}/${s}.wind_dir`, hideEmpty: true, hideZero: true,
                        format: (v) => `${v}° (${compass(v)})` },
                    { title: 'Wind speed', field: `${weather}/${s}.wind_speed`, show: (v) => !!v,
                        draw: reading({ rrdField: `${weather}/${s}.wind_speed_rrd`, show: speed }) },
                    { title: 'Wind gust', field: `${weather}/${s}.wind_gust`, show: (v) => !!v,
                        draw: reading({ rrdField: `${weather}/${s}.wind_gust_rrd`, show: speed }),
                        help: 'The strongest wind speed (the gust) the sensor reported.' },
                    { title: 'Rain', field: `${weather}/${s}.rain`, show: (v) => !!v,
                        draw: reading({ rrdField: `${weather}/${s}.rain_rrd`, counter: true }),
                        help: 'The rain total, often in mm.  The graphs show how much fell in each interval.' },
                    { title: 'Rain (raw)', field: `${weather}/${s}.rain_raw`, hideEmpty: true, hideZero: true,
                        help: 'The sensor\'s raw rain value.' },
                    { title: 'UV index', field: `${weather}/${s}.uv_index`, show: (v) => !!v,
                        draw: reading({ rrdField: `${weather}/${s}.uv_index_rrd` }) },
                    { title: 'Light', field: `${weather}/${s}.lux`, show: (v) => !!v,
                        draw: reading({ rrdField: `${weather}/${s}.lux_rrd`, show: (v) => `${v} lux` }) },
                ],
            },
            {
                group: 'Tire pressure', show: has(tpms),
                fields: [
                    { title: 'Pressure', id: 'bar', field: `${tpms}/${s}.tpms.pressure_bar`, hideZero: true, format: (v) => `${v} bar` },
                    { title: 'Pressure', id: 'kpa', field: `${tpms}/${s}.tpms.pressure_kpa`, hideZero: true, format: (v) => `${v} kPa` },
                    { title: 'Pressure', id: 'psi', field: `${tpms}/${s}.tpms.pressure_psi`, hideZero: true, format: (v) => `${v} PSI` },
                    { title: 'Tire temperature', field: `${tpms}/${s}.tpms.temperature`, hideZero: true, format: temperature },
                    { title: 'State', field: `${tpms}/${s}.tpms.state`, hideEmpty: true },
                ],
            },
            {
                group: 'Switch', show: has(sw),
                fields: [1, 2, 3, 4, 5].map((i) => (
                    { title: `Switch ${i}`, field: `${sw}/${s}.switch.${i}`, hideEmpty: true })),
            },
            {
                group: 'Lightning sensor', show: has(light),
                fields: [
                    { title: 'Strike count', field: `${light}/${s}.lightning_strike_count`, show: (v) => v !== undefined && v !== '',
                        draw: reading({ rrdField: `${light}/${s}.lightning_strike_count_rrd`, counter: true }),
                        help: 'The last strike count the sensor reported (it may reset at any time).  The graphs show strikes per interval.' },
                    { title: 'Storm', field: `${light}/${s}.lightning_storm_active`, format: (v) => (v ? 'Active' : 'Inactive'),
                        help: 'Whether the sensor says a storm is going on.' },
                    { title: 'Interference', field: `${light}/${s}.lightning_rfi`, hideEmpty: true,
                        help: 'Radio interference the sensor picked up, often from other electronics.' },
                    { title: 'Storm distance', field: `${light}/${s}.lightning_storm_distance`, hideEmpty: true,
                        help: 'How far away the sensor thinks the storm is (it doesn\'t give units).' },
                ],
            },
            {
                group: 'Air quality', show: has(aqi),
                fields: [
                    { title: 'PM2.5', field: `${aqi}/${s}.pm2_5`, show: (v) => v !== undefined && v !== '',
                        draw: reading({ rrdField: `${aqi}/${s}.pm2_5_rrd` }),
                        help: 'Fine particles (2.5 microns and smaller) the sensor estimates.' },
                    { title: 'PM10', field: `${aqi}/${s}.pm10`, show: (v) => v !== undefined && v !== '',
                        draw: reading({ rrdField: `${aqi}/${s}.pm10_rrd` }),
                        help: 'Particles 10 microns and smaller the sensor estimates.' },
                ],
            },
            { title: 'Last record', field: `${c}/${s}.last_record`, hideEmpty: true,
                format: (v) => dom.el('pre', { class: 'mono', style: { whiteSpace: 'pre-wrap', margin: 0 } }, typeof v === 'string' ? v : JSON.stringify(v, null, 2)),
                help: 'The last raw record from the decoder, for troubleshooting.' },
        ],
    });
}
