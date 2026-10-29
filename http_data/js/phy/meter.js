// Utility meters (electric, gas, water) heard over the air by SDR tools.

import { readingWithHistory } from './sensor.js';

const base = 'kismet.device.base';
const m = 'meter.device';

export function register(kismet) {
    const { ui, icons, dom } = kismet;
    const isMeter = (row) => row[`${base}.phyname`] === 'METER';

    icons.define('meter', '<path d="M4 11l8-7 8 7v9H4z"/><circle cx="12" cy="14.5" r="3"/><path d="M12 14.5l1.5-1.5"/>');

    ui.deviceIcons.add({
        id: 'meter', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isMeter(row) ? icons.icon('meter', 'Utility meter') : null),
    });

    ui.mapSources.add({
        id: 'meter', title: 'Utility meters', priority: 71, icon: 'meter', view: 'phy-METER', position: 'average',
        defaultVisible: false,
        fields: [[`${m}/${m}.meter_type`, 'meter_type']],
        detail: (d) => d.meter_type ?? '',
        color: () => 'hsl(160 60% 42%)',
    });

    ui.rowHighlights.add({
        id: 'meter_all', name: 'RF meter device', priority: 100,
        description: 'Power, water, and gas meters',
        defaultColor: '#b3ffe6', defaultEnabled: true,
        fields: [`${base}.phyname`],
        match: isMeter,
    });

    const hex = (v) => `0x${v.toString(16)}`;

    ui.deviceDetails.add({
        id: 'rfmeter', title: 'Meter', priority: 5,
        match: (device) => m in device,
        fields: [
            { title: 'Meter ID', field: `${m}/${m}.meter_id`, empty: ui.muted('Unknown') },
            { title: 'Meter type', field: `${m}/${m}.meter_type`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'What the meter measures: electricity, gas, or water.' },
            { title: 'Models', field: `${m}/${m}.model_vec`, show: (v) => Array.isArray(v) && v.length > 0,
                format: (v) => dom.el('div', {}, v.map((model) => dom.el('div', {}, model))),
                help: 'A meter\'s signal can match more than one model\'s format, so it may be listed as several.' },
            { title: 'Consumption', field: `${m}/${m}.consumption`, show: (v) => v !== undefined,
                draw: readingWithHistory(kismet, { rrdField: `${m}/${m}.consumption_rrd`, counter: true }),
                help: 'The meter\'s reading (units depend on the meter), with how much it went up over the past minute (M), hour (H), and day (D).' },
            { title: 'Tamper flags', field: `${m}/${m}.phy_tamper_flags`, hideZero: true, format: hex,
                help: 'Tamper indicators the meter sends about its radio.' },
            { title: 'Endpoint tamper flags', field: `${m}/${m}.endpoint_tamper_flags`, hideZero: true, format: hex,
                help: 'Tamper indicators the meter sends about itself.' },
        ],
    });
}
