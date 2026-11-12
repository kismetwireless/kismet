// The standard device list columns, icon, and highlights, for every phy.

const base = 'kismet.device.base';

export function register(kismet) {
    const { ui, format, icons, dom, rrd, clock } = kismet;
    const { barGraph, peaks } = kismet.widgets.cellgraphs;
    // The server's time: a replayed capture, or this browser's clock, can be far from it
    const now = () => (clock.isKnown() ? clock.now() : Date.now() / 1000);

    // Always fetched, so searches match them even when their columns are hidden
    // The reported location; meters, and km/h
    const loc = `${base}.reported_location/kismet.common.location.last/kismet.common.location`;
    ui.filterHints.add({ id: 'altitude', names: ['altitude', 'alt'], fields: [`${loc}.alt`], filterKind: 'number',
        help: 'Altitude of the device\'s location, in meters' });
    ui.filterHints.add({ id: 'speed', names: ['speed'], fields: [`${loc}.speed`], filterKind: 'number', help: 'Speed of the device\'s location' });

    ui.searchFields.add({
        id: 'base', description: 'Phy and MAC address',
        fields: [`${base}.phyname`, `${base}.macaddr`],
        help: 'Phy name and MAC address',
    });

    ui.deviceColumns.add({
        id: 'name', title: 'Name', priority: 0, defaultVisible: true, minWidth: '32ch', shorten: true,
        description: 'Device name: a name you set, the advertised name, or the MAC address',
        fields: [`${base}.commonname`, `${base}.macaddr`],
        sortField: `${base}.commonname`,
        render: (row) => row[`${base}.commonname`] || row[`${base}.macaddr`],
    });

    ui.deviceColumns.add({
        id: 'type', title: 'Type', priority: 10, defaultVisible: true, width: '10em',
        description: 'What the device is shown as, such as Wi-Fi AP; it sorts by the type of its phy, such as Wi-Fi',
        fields: [`${base}.type`, `${base}.display_type`],
        sortField: `${base}.type`,
        render: (row) => format.deviceType(row),
    });

    ui.deviceColumns.add({
        id: 'phy', title: 'Phy', priority: 15, width: '8em',
        description: 'Which kind of radio the device uses',
        fields: [`${base}.phyname`],
        sortField: `${base}.phyname`,
        render: (row) => row[`${base}.phyname`],
    });

    ui.deviceColumns.add({
        id: 'crypt', title: 'Encryption', priority: 20, defaultVisible: true, width: '9em',
        fields: [`${base}.crypt`],
        sortField: `${base}.crypt`,
        render: (row) => row[`${base}.crypt`] || dom.el('i', { class: 'muted' }, 'n/a'),
    });

    ui.deviceColumns.add({
        id: 'signal', title: 'Signal', priority: 30, defaultVisible: true, width: 'fit', align: 'right',
        description: 'Last signal level',
        fields: [[`${base}.signal/kismet.common.signal.last_signal`, 'signal']],
        sortField: `${base}.signal/kismet.common.signal.last_signal`,
        render: (row) => format.signal(row.signal),
    });

    ui.deviceColumns.add({
        id: 'channel', title: 'Channel', priority: 40, defaultVisible: true, width: '6em', align: 'right',
        description: 'Last channel, or the last frequency when there is no channel',
        fields: [`${base}.channel`, `${base}.frequency`],
        sortField: `${base}.channel`,
        render: (row) => {
            if (row[`${base}.channel`])
                return row[`${base}.channel`];
            if (row[`${base}.frequency`])
                return format.frequency(row[`${base}.frequency`]);
            return dom.el('i', { class: 'muted' }, 'n/a');
        },
    });

    ui.deviceColumns.add({
        id: 'frequency', title: 'Frequency', priority: 45, width: '8em', align: 'right',
        fields: [`${base}.frequency`],
        sortField: `${base}.frequency`,
        render: (row) => format.frequency(row[`${base}.frequency`]),
    });

    ui.deviceColumns.add({
        id: 'packets', title: 'Packets', priority: 50, defaultVisible: true, width: '7em', align: 'right',
        fields: [`${base}.packets.total`],
        sortField: `${base}.packets.total`,
        render: (row) => format.count(row[`${base}.packets.total`]),
    });

    ui.deviceColumns.add({
        id: 'datasize', title: 'Data', priority: 55, width: '7em', align: 'right',
        fields: [`${base}.datasize`],
        sortField: `${base}.datasize`,
        render: (row) => format.size(row[`${base}.datasize`]),
    });

    ui.deviceColumns.add({
        id: 'first_time', title: 'First seen', priority: 60, width: '11.5em', align: 'right',
        fields: [`${base}.first_time`],
        sortField: `${base}.first_time`,
        render: (row) => format.time(row[`${base}.first_time`]),
    });

    ui.deviceColumns.add({
        id: 'last_time', title: 'Last seen', priority: 65, defaultVisible: true, width: '11.5em', align: 'right',
        description: 'When the device was last seen, as a time or how long ago; hover a cell for the other',
        fields: [`${base}.last_time`],
        sortField: `${base}.last_time`,
        render: (row) => format.time(row[`${base}.last_time`]),
        // Whichever way it's shown, the tooltip shows the other
        tooltip: (row) => format.since(row[`${base}.last_time`], now()),
        variants: [
            { id: 'time', title: 'Date and time' },
            { id: 'since', title: 'Time since last seen',
                render: (row) => format.since(row[`${base}.last_time`], now()),
                tooltip: (row) => format.time(row[`${base}.last_time`]) },
        ],
    });

    ui.deviceColumns.add({
        id: 'macaddr', title: 'MAC', priority: 70, defaultVisible: true, width: '11em',
        fields: [`${base}.macaddr`],
        sortField: `${base}.macaddr`,
        render: (row) => dom.el('span', { class: 'mono' }, row[`${base}.macaddr`]),
    });

    ui.deviceColumns.add({
        id: 'manuf', title: 'Manufacturer', priority: 80, defaultVisible: true, width: '12em',
        fields: [`${base}.manuf`],
        sortField: `${base}.manuf`,
        render: (row) => row[`${base}.manuf`] || '',
    });

    ui.deviceColumns.add({
        id: 'seenby', title: 'Seen by', priority: 90, width: '5em', align: 'right',
        description: 'How many data sources have seen the device',
        // '#' asks the server for the number of entries instead of the entries
        fields: [[`#${base}.seenby`, 'seenby_count']],
        render: (row) => row.seenby_count || '',
    });

    ui.deviceColumns.add({
        id: 'packet_graph', title: 'Activity', priority: 52, defaultVisible: true, width: '7em',
        description: 'Packets per second over the last minute',
        fields: [[`${base}.packets.rrd/kismet.common.rrd.minute_vec`, 'packets_minute'],
            [`${base}.packets.rrd/kismet.common.rrd.last_time`, 'packets_last']],
        sortField: `${base}.packets.rrd/kismet.common.rrd.last_value`,
        filterKind: 'number',
        render: (row) => {
            const history = rrd.history({
                'kismet.common.rrd.minute_vec': row.packets_minute,
                'kismet.common.rrd.last_time': row.packets_last,
            }, clock.isKnown() ? clock.now() : undefined);
            if (!history.length)
                return '';
            const total = history.reduce((a, b) => a + b, 0);
            return barGraph(peaks(history, 3), { title: `${total.toLocaleString()} packets in the last minute` });
        },
    });

    ui.deviceIcons.add({
        id: 'generic', priority: 100000,
        match: () => icons.icon('device'),
    });
}
