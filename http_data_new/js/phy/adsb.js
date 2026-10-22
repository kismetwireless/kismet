// ADS-B: aircraft, from SDR captures.

const base = 'kismet.device.base';
const adsb = 'adsb.device';
// The aircraft record from the ICAO database Kismet loads, kept in the device
// under the record's own name
const icao = `${adsb}/kismet.adsb.icao_record`;
// The aircraft's own position, altitude, speed, and heading; the device's
// location is where Kismet heard it
const pos = `${base}.reported_location/kismet.common.location.last/kismet.common.location`;

// Owners that mark government and related aircraft, and words that rule a match out again
const governmentWords = ['department', 'police', 'agency', 'dep', 'gov', 'federal', 'royal', 'force',
    'state', 'army', 'navy', 'patrol', 'sqdn', 'city of', 'sheriff'];
const notGovernment = ['express', 'air freight'];

// Known government aircraft without a telling owner name
const governmentIcao = new Set([
    'acf181', 'a980fa', 'a7fb8f', 'ae4bd7', 'a47604', 'a03bc8', 'a0b8d6', 'a0d9f2', 'a12d51', 'a15f1d',
    'a169d7', 'a16c6d', 'a193c1', 'a32524', 'a328db', 'a32c92', 'a33049', 'a33dc3', 'a3c1be', 'a3c92c',
    'a3e6e3', 'a3e6e4', 'a410bc', 'a4182a', 'a44360', 'a4724d', 'a483df', 'a4bc36', 'a4bfed', 'a51a10',
    'a51dc7', 'a54b56', 'a54f0d', 'a552c4', 'a5ed09', 'a5f9f7', 'a64217', 'a645ce', 'a64985', 'a64d3c',
    'a654aa', 'aac551', 'abaf9c', 'ac742b', 'ac7b99',
]);

function isGovernment(owner, icao) {
    owner = String(owner ?? '').toLowerCase();
    if (governmentWords.some((w) => owner.includes(w)) && !notGovernment.some((w) => owner.includes(w)))
        return true;
    return governmentIcao.has(String(icao ?? '').toLowerCase());
}

export function register(kismet) {
    const { ui, icons, dom, api } = kismet;
    const { el } = dom;
    const isAdsb = (row) => row[`${base}.phyname`] === 'ADSB';

    const link = (href, text) => el('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);

    ui.searchFields.add({
        id: 'adsb', description: 'ADS-B callsign',
        fields: [`${adsb}/${adsb}.callsign`],
    });

    ui.deviceIcons.add({
        id: 'adsb', priority: 0,
        fields: [`${base}.phyname`],
        match: (row) => (isAdsb(row) ? icons.icon('plane', 'Aircraft') : null),
    });

    ui.rowHighlights.add({
        id: 'adsb_government', name: 'ADS-B government', priority: 50,
        description: 'Government and related aircraft',
        defaultColor: '#ffb3b3', defaultEnabled: true,
        fields: [`${base}.phyname`,
            [`${icao}/adsb.icao.owner`, 'adsb_owner'],
            [`${adsb}/${adsb}.icao`, 'adsb_icao']],
        match: (row) => isAdsb(row) && isGovernment(row.adsb_owner, row.adsb_icao),
    });

    ui.deviceDetails.add({
        id: 'adsb', title: 'ADS-B (SDR)', priority: 5,
        match: (dev) => dev[`${base}.phyname`] === 'ADSB',
        fields: [
            { title: 'ICAO address', field: `${adsb}/${adsb}.icao`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'The aircraft\'s unique 24-bit ICAO address, sent in every ADS-B message.' },
            { title: 'Callsign', field: `${adsb}/${adsb}.callsign`, hideEmpty: true, hideZero: true,
                help: 'The flight\'s callsign or registration, as the aircraft broadcasts it.' },
            { id: 'flightaware', title: 'FlightAware', field: `${adsb}/${adsb}.callsign`, hideEmpty: true, hideZero: true,
                format: (v) => link(`https://www.flightaware.com/live/flight/${encodeURIComponent(String(v).trim())}`,
                    `Track ${String(v).trim()} on FlightAware`) },
            { title: 'Registration', field: `${icao}/adsb.icao.regid`, hideEmpty: true, hideZero: true,
                help: 'The aircraft\'s registration or tail number, from the ICAO database.' },
            { title: 'Classification', field: `${icao}/adsb.icao.atype`, hideEmpty: true, hideZero: true,
                help: 'The kind of aircraft, from the ICAO database.' },
            { title: 'Model', field: `${icao}/adsb.icao.model`, hideEmpty: true, hideZero: true,
                help: 'The general aircraft model.' },
            { title: 'Type', field: `${icao}/adsb.icao.type`, hideEmpty: true, hideZero: true,
                help: 'The specific model type.' },
            { title: 'Operator', field: `${icao}/adsb.icao.owner`, hideEmpty: true, hideZero: true,
                help: 'The operator or registered owner of the aircraft.' },
            {
                group: 'Position',
                show: (dev) => api.field(dev, `${pos}.fix`, 0) >= 2,
                fields: [
                    { title: 'Altitude', field: `${pos}.alt`, hideZero: true, format: (v) => `${Math.round(v)} m` },
                    { title: 'Speed', field: `${pos}.speed`, hideZero: true, format: (v) => `${v.toFixed(0)} km/h` },
                    {
                        title: 'Heading', field: `${pos}.heading`, hideZero: true,
                        format: (v) => {
                            // The plane icon points up, so turning it by the heading points it where it's going
                            const plane = icons.icon('plane', `Heading ${Math.round(v)}°`);
                            plane.style.transform = `rotate(${v}deg)`;
                            return el('span', {}, `${Math.round(v)}° `, plane);
                        },
                    },
                    {
                        title: 'Location', field: `${pos}.geopoint`,
                        show: (v) => Array.isArray(v) && (v[0] !== 0 || v[1] !== 0),
                        format: (v) => el('span', {}, `${v[1].toFixed(5)}, ${v[0].toFixed(5)} `,
                            link(`https://www.openstreetmap.org/?mlat=${v[1]}&mlon=${v[0]}`, 'View on OpenStreetMap')),
                    },
                ],
            },
            { title: 'Airspeed (AS) / ground speed (GS)', field: `${adsb}/${adsb}.gsas`, hideEmpty: true, hideZero: true },
        ],
    });
}
