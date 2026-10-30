// AIS: ships, base stations, navigation aids, and emergency beacons, from SDR captures.

const base = 'kismet.device.base';
const ais = 'ais.device';
const emergency = ['AIS-SART', 'AIS-MOB', 'AIS-EPIRB'];

export function register(kismet) {
    const { ui, icons, dom, api, format } = kismet;
    const { el } = dom;
    const isAis = (row) => row[`${base}.phyname`] === 'AIS';

    const link = (href, text) => el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);
    const aisField = (dev, name) => api.field(dev, `${ais}/${ais}.${name}`);
    const isClass = (dev, classes) => classes.includes(aisField(dev, 'class'));
    // Base stations and navigation aids don't move, so speed and course mean nothing for them
    const moves = (dev) => !isClass(dev, ['Base Station', 'AtoN']);

    // Searches match a vessel's MMSI, name, and callsign
    ui.searchFields.add({
        id: 'ais', description: 'AIS MMSI, name, and callsign',
        fields: [`${ais}/${ais}.mmsi`, `${ais}/${ais}.name`, `${ais}/${ais}.callsign`],
    });

    ui.deviceIcons.add({
        id: 'ais', priority: 0,
        fields: [`${base}.phyname`, [`${ais}/${ais}.class`, 'ais_class']],
        match: (row) => {
            if (!isAis(row))
                return null;
            const c = row.ais_class;
            if (c === 'Base Station')
                return icons.icon('tower', 'AIS base station');
            if (c === 'AtoN')
                return icons.icon('anchor', 'Aid to navigation');
            if (c === 'SAR Aircraft')
                return icons.icon('plane', 'Search and rescue aircraft');
            if (emergency.includes(c))
                return icons.icon('lifebuoy', 'Emergency beacon');
            return icons.icon('ship', 'Vessel');
        },
    });

    // Stations on the map; moving vessels point where they're heading
    const underway = (d) => (d.sog ?? 0) > 0.5 && !['Base Station', 'AtoN'].includes(d.ais_class);
    ui.mapSources.add({
        id: 'ais', title: 'Vessels (AIS)', priority: 10, view: 'phy-AIS', maxAge: 1800, legacy: true, layerIcon: 'ship',
        fields: [[`${ais}/${ais}.name`, 'shipname'], [`${ais}/${ais}.class`, 'ais_class'], [`${ais}/${ais}.sog`, 'sog']],
        icon: (d) => {
            const c = d.ais_class;
            if (c === 'Base Station')
                return 'tower';
            if (c === 'AtoN')
                return 'anchor';
            if (c === 'SAR Aircraft')
                return 'plane';
            if (emergency.includes(c))
                return 'lifebuoy';
            return underway(d) ? 'vessel' : 'ship';
        },
        label: (d) => String(d.shipname ?? '').trim() || d.name,
        detail: (d) => [d.ais_class, underway(d) ? `${d.sog.toFixed(1)} kn` : null].filter(Boolean).join(', '),
        color: (d) => (emergency.includes(d.ais_class) ? 'var(--error)' : 'var(--ok)'),
        heading: (d) => (underway(d) || d.ais_class === 'SAR Aircraft' ? d.rep_heading || 0 : null),
    });

    ui.rowHighlights.add({
        id: 'ais_emergency', name: 'AIS emergency', priority: 10,
        description: 'AIS SART, MOB, and EPIRB emergency beacons',
        defaultColor: '#ff6666', defaultEnabled: true,
        fields: [`${base}.phyname`, [`${ais}/${ais}.class`, 'ais_class']],
        match: (row) => isAis(row) && emergency.includes(row.ais_class),
    });

    ui.deviceDetails.add({
        id: 'ais', title: 'AIS (SDR)', priority: 5,
        match: (dev) => dev[`${base}.phyname`] === 'AIS',
        fields: [
            {
                title: 'MMSI', field: `${ais}/${ais}.mmsi`,
                help: 'Maritime Mobile Service Identity: the station\'s unique number.',
                format: (v) => el('span', {}, `${v} `,
                    link(`https://www.marinetraffic.com/en/ais/details/ships/mmsi:${encodeURIComponent(v)}`, 'View on MarineTraffic')),
            },
            { title: 'Station class', field: `${ais}/${ais}.class`, hideEmpty: true, empty: ui.muted('Unknown') },
            { title: 'Flag', field: `${ais}/${ais}.country`, hideEmpty: true,
                help: 'Country of registration, from the first digits of the MMSI (the maritime identification digits, or MID).',
                format: (v, dev) => `${v} (MID ${aisField(dev, 'mid')})` },
            { title: 'Name', field: `${ais}/${ais}.name`, hideEmpty: true },
            { title: 'Callsign', field: `${ais}/${ais}.callsign`, hideEmpty: true },
            { title: 'IMO number', field: `${ais}/${ais}.imo`, hideZero: true },
            { title: 'Ship type', field: `${ais}/${ais}.ship_type_str`, hideEmpty: true,
                format: (v, dev) => `${v} (${aisField(dev, 'ship_type')})` },
            {
                title: 'Aid to navigation', field: `${ais}/${ais}.aton_type_str`,
                show: (_v, dev) => isClass(dev, ['AtoN']),
                format: (v, dev) => el('span', {}, v,
                    aisField(dev, 'aton_virtual') ? ' (virtual)' : null,
                    aisField(dev, 'aton_off_position') ? el('b', {}, ' off position') : null),
            },
            { title: 'Navigation status', field: `${ais}/${ais}.nav_status_str`, hideEmpty: true },
            {
                title: 'Dimensions',
                help: 'Overall length and beam, from the distances the ship reports between its AIS antenna and the bow, stern, port, and starboard sides.',
                value: (dev) => {
                    const d = dev[ais] ?? {};
                    const length = (d[`${ais}.dim_bow`] ?? 0) + (d[`${ais}.dim_stern`] ?? 0);
                    const beam = (d[`${ais}.dim_port`] ?? 0) + (d[`${ais}.dim_starboard`] ?? 0);
                    return length > 0 ? `${format.distance(length)} × ${format.distance(beam)}` : null;
                },
            },
            { title: 'Draught', field: `${ais}/${ais}.draught`, hideZero: true, format: (v) => format.distance(v, 1),
                help: 'How deep the ship sits in the water.' },
            { title: 'Destination', field: `${ais}/${ais}.destination`, hideEmpty: true },
            { title: 'ETA (UTC)', field: `${ais}/${ais}.eta`, hideEmpty: true },
            { title: 'Transponder vendor', field: `${ais}/${ais}.vendor`, hideEmpty: true },
            { title: 'Speed', field: `${ais}/${ais}.sog`, show: (_v, dev) => moves(dev), format: (v) => format.speed(v * 1.852),
                help: 'Speed over ground.' },
            { title: 'Course', field: `${ais}/${ais}.cog`, show: (_v, dev) => moves(dev), format: (v) => `${v.toFixed(1)}°`,
                help: 'Course over ground: the direction the ship is actually moving.' },
            {
                title: 'Heading', field: `${ais}/${ais}.heading`, show: (_v, dev) => moves(dev),
                help: 'The direction the bow points, which can differ from the course in wind or current.',
                format: (v) => {
                    const arrow = icons.icon('up', `Heading ${Math.round(v)}°`);
                    arrow.style.transform = `rotate(${v}deg)`;
                    return el('span', {}, `${Math.round(v)}° `, arrow);
                },
            },
            { title: 'Rate of turn', field: `${ais}/${ais}.rot`, hideZero: true, format: (v) => `${v.toFixed(1)}°/min` },
            { title: 'Altitude', field: `${ais}/${ais}.altitude`, show: (_v, dev) => isClass(dev, ['SAR Aircraft']),
                format: (v) => format.height(v) },
            { title: 'Station UTC time', field: `${ais}/${ais}.utc_time`, hideEmpty: true },
            {
                title: 'Reported location', field: `${base}.reported_location/kismet.common.location.last/kismet.common.location.geopoint`,
                show: (v) => Array.isArray(v) && (v[0] !== 0 || v[1] !== 0),
                format: (v) => el('span', {}, `${v[1].toFixed(5)}, ${v[0].toFixed(5)} `,
                    link(`https://www.openstreetmap.org/?mlat=${v[1]}&mlon=${v[0]}`, 'View on OpenStreetMap')),
            },
            { title: 'Last message type', field: `${ais}/${ais}.last_msg_type` },
        ],
    });
}
