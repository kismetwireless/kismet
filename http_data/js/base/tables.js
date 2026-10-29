// The standard tabs in the main area: the device list and the alerts.

const a = 'kismet.alert';

export function register(kismet) {
    const { ui, format, dom } = kismet;
    const { el } = dom;
    const noMac = (v) => !v || v === '00:00:00:00:00:00';
    const mac = (v) => (noMac(v) ? '' : el('span', { class: 'mono' }, v));

    ui.panes.add({
        id: 'devices', title: 'Devices', area: 'main', priority: 0,
        create: (body) => kismet.widgets.devicetable.createDeviceTable(body),
    });

    // Severity bands, for the column and the highlights
    const severity = (v) => (v >= 15 ? 'Critical' : v >= 10 ? 'High' : v >= 5 ? 'Medium' : 'Low');

    ui.addTable({
        id: 'alerts', title: 'Alerts', area: 'main', priority: 30,
        endpoint: 'alerts/alerts_view.json',
        noun: 'alerts',
        emptyText: 'No alerts.',
        rowKey: (r) => `${r[`${a}.header`]}:${r[`${a}.timestamp`]}`,
        onRowClick: (r) => openAlert(r),
        defaultSort: { column: 'time', dir: 'desc' },
        // Everything the alert's panel shows comes with the row
        alwaysFields: [`${a}.header`, `${a}.timestamp`, `${a}.text`, `${a}.severity`, `${a}.class`, `${a}.device_key`,
            `${a}.source_mac`, `${a}.dest_mac`, `${a}.transmitter_mac`, `${a}.other_mac`, `${a}.channel`, `${a}.frequency`],
        columns: [
            { id: 'time', title: 'Time', priority: 0, defaultVisible: true, width: '11.5em',
                fields: [`${a}.timestamp`], sortField: `${a}.timestamp`,
                render: (r) => format.time(Math.floor(r[`${a}.timestamp`])) },
            { id: 'header', title: 'Alert', priority: 10, defaultVisible: true, width: '10em',
                description: 'The kind of alert', fields: [`${a}.header`], sortField: `${a}.header`,
                render: (r) => el('b', {}, r[`${a}.header`]) },
            { id: 'severity', title: 'Severity', priority: 20, defaultVisible: true, width: '6em',
                fields: [`${a}.severity`], sortField: `${a}.severity`,
                render: (r) => severity(r[`${a}.severity`]) },
            { id: 'class', title: 'Class', priority: 30, defaultVisible: true, width: '7em',
                description: 'What kind of problem: a denial of service, a probe, a spoofed device, or the system itself',
                fields: [`${a}.class`], sortField: `${a}.class`,
                render: (r) => (r[`${a}.class`] ?? '').toLowerCase() },
            { id: 'text', title: 'Details', priority: 40, defaultVisible: true,
                fields: [`${a}.text`],
                render: (r) => r[`${a}.text`] },
            { id: 'source', title: 'Source', priority: 50, defaultVisible: true, width: '11em',
                fields: [`${a}.source_mac`], sortField: `${a}.source_mac`, render: (r) => mac(r[`${a}.source_mac`]) },
            { id: 'dest', title: 'Destination', priority: 60, width: '11em',
                fields: [`${a}.dest_mac`], sortField: `${a}.dest_mac`, render: (r) => mac(r[`${a}.dest_mac`]) },
            { id: 'transmitter', title: 'Transmitter', priority: 70, width: '11em',
                fields: [`${a}.transmitter_mac`], render: (r) => mac(r[`${a}.transmitter_mac`]) },
            { id: 'channel', title: 'Channel', priority: 80, width: '6em', align: 'right',
                fields: [`${a}.channel`, `${a}.frequency`], sortField: `${a}.frequency`,
                render: (r) => r[`${a}.channel`] || (r[`${a}.frequency`] ? format.frequency(r[`${a}.frequency`]) : '') },
        ],
        highlights: [
            { id: 'critical', name: 'Critical alerts', priority: 0, description: 'Severity 15 and up',
                fields: [`${a}.severity`], defaultColor: '#e03131', defaultEnabled: true,
                match: (r) => r[`${a}.severity`] >= 15 },
            { id: 'high', name: 'High alerts', priority: 10, description: 'Severity 10 to 14',
                fields: [`${a}.severity`], defaultColor: '#f08c00', defaultEnabled: true,
                match: (r) => r[`${a}.severity`] >= 10 },
            { id: 'medium', name: 'Medium alerts', priority: 20, description: 'Severity 5 to 9',
                fields: [`${a}.severity`], defaultColor: '#fab005', defaultEnabled: false,
                match: (r) => r[`${a}.severity`] >= 5 },
        ],
    });

    // An alert in its own panel: everything about it, and the device it's about
    function openAlert(r) {
        const body = el('div');
        kismet.widgets.dialog.dialog({ title: r[`${a}.header`], body, modal: false, className: 'detail-panel' });
        ui.detailFields(body, r, [
            { title: 'Time', field: `${a}.timestamp`, format: (v) => format.time(Math.floor(v)) },
            { title: 'Severity', field: `${a}.severity`, format: (v) => `${severity(v)} (${v})` },
            { title: 'Class', field: `${a}.class`, format: (v) => v.toLowerCase() },
            { title: 'Details', field: `${a}.text` },
            { title: 'Device', field: `${a}.device_key`, show: (v) => v && v !== '00_0' && v !== '0',
                format: (k) => el('a', { href: '#', onclick: (e) => { e.preventDefault(); ui.openDevice(k); } }, 'Open the device') },
            { title: 'Source', field: `${a}.source_mac`, show: (v) => !noMac(v), format: mac },
            { title: 'Destination', field: `${a}.dest_mac`, show: (v) => !noMac(v), format: mac },
            { title: 'Transmitter', field: `${a}.transmitter_mac`, show: (v) => !noMac(v), format: mac },
            { title: 'Other', field: `${a}.other_mac`, show: (v) => !noMac(v), format: mac },
            { title: 'Channel', field: `${a}.channel`, hideEmpty: true },
            { title: 'Frequency', field: `${a}.frequency`, hideZero: true, format: format.frequency },
        ]);
    }
}
