// UAVs and drones: devices Kismet recognizes as drones from their Wi-Fi or
// Bluetooth traffic, DJI DroneID, or Open Drone ID / Remote ID broadcasts.
// They're Wi-Fi or Bluetooth devices with an extra 'uav.device' record.

const base = 'kismet.device.base';
const uav = 'uav.device';
const rid = `${uav}/uav.remoteid/uav.remoteid`;

// Open Drone ID / Remote ID values (ASTM F3411), by the number the drone sends
const versions = ['F3411-19 (1.0)', 'F3411-20 (1.1)', 'F3411-22 (2.0)'];
const uaTypes = ['Undeclared', 'Aeroplane', 'Helicopter or multirotor', 'Gyroplane', 'Hybrid lift',
    'Ornithopter', 'Glider', 'Kite', 'Free balloon', 'Captive balloon', 'Airship',
    'Free fall or parachute', 'Rocket', 'Tethered powered aircraft', 'Ground obstacle', 'Other'];
const statuses = ['Undeclared', 'Ground', 'Airborne', 'Emergency', 'Remote ID system failure'];
const heightTypes = ['Above takeoff', 'Above ground'];
const horizAccuracy = ['Unknown', '< 18.52 km', '< 7.408 km', '< 3.704 km', '< 1852 m', '< 926 m',
    '< 555.6 m', '< 185.2 m', '< 92.6 m', '< 30 m', '< 10 m', '< 3 m', '< 1 m'];
const vertAccuracy = ['Unknown', '< 150 m', '< 45 m', '< 25 m', '< 10 m', '< 3 m', '< 1 m'];
const speedAccuracy = ['Unknown', '< 10 m/s', '< 3 m/s', '< 1 m/s', '< 0.3 m/s'];
const operatorLocationTypes = ['Takeoff', 'Live GNSS', 'Fixed'];
const classificationTypes = ['Undeclared', 'European Union'];
const euCategories = ['Undeclared', 'Open', 'Specific', 'Certified'];
const euClasses = ['Undeclared', 'Class 0', 'Class 1', 'Class 2', 'Class 3', 'Class 4', 'Class 5', 'Class 6'];
const selfIdTypes = ['Text', 'Emergency', 'Extended status'];
const authTypes = ['None', 'UAS ID signature', 'Operator ID signature', 'Message set signature',
    'Network Remote ID', 'Specific method'];

// A value from one of the tables above, or the raw number if it's not in the table
const named = (table) => (v) => table[v] ?? `Unknown (${v})`;
const meters = (v) => `${Number(v).toFixed(1)} m`;

// Locations read 0,0 until the drone reports one
function locationText(v) {
    if (!Array.isArray(v) || (v[0] === 0 && v[1] === 0))
        return null;
    return `${v[1].toFixed(6)}, ${v[0].toFixed(6)}`;
}

export function register(kismet) {
    const { ui, icons, api, format } = kismet;

    icons.define('drone', '<circle cx="5.5" cy="5.5" r="2.5"/><circle cx="18.5" cy="5.5" r="2.5"/>' +
        '<circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/>' +
        '<rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M7.5 7.5l2 2M16.5 7.5l-2 2M7.5 16.5l2-2M16.5 16.5l-2-2"/>');

    // 'uav.match_type' is in every drone record; for other devices the server
    // sends 0 for the missing field.  Asking for it instead of the whole
    // record keeps the device list light.
    const isUav = (row) => row.uav_match_type !== undefined && row.uav_match_type !== 0;
    const uavFields = [[`${uav}/uav.match_type`, 'uav_match_type']];

    // Ahead of the Wi-Fi and Bluetooth icons, so drones look like drones
    ui.deviceIcons.add({
        id: 'uav', priority: -10,
        fields: uavFields,
        match: (row) => (isUav(row) ? icons.icon('drone', 'UAV / drone') : null),
    });

    // Drones on the map: Remote ID and DroneID report where they are; drones
    // only recognized by their radio are shown where Kismet heard them
    ui.mapSources.add({
        id: 'uav', title: 'Drones', priority: 20, icon: 'drone', view: 'all', position: 'reported-or-heard', maxAge: 600,
        interval: 5000,
        regex: [[`${uav}/uav.manufacturer`, '.*']],
        fields: [[`${uav}/uav.manufacturer`, 'uav_manuf'], [`${uav}/uav.model`, 'uav_model'],
            [`${uav}/uav.serialnumber`, 'uav_serial']],
        label: (d) => String(d.uav_serial ?? '').trim() || d.name,
        detail: (d) => [String(d.uav_manuf ?? '').trim(), String(d.uav_model ?? '').trim(),
            d.rep_alt ? `${Math.round(d.rep_alt)} m` : null].filter(Boolean).join(' '),
        color: () => 'var(--warn)',
    });

    ui.rowHighlights.add({
        id: 'uav', name: 'UAV/drones', priority: 100,
        description: 'UAV and drone devices',
        defaultColor: '#f49e42', defaultEnabled: true,
        fields: uavFields,
        match: isUav,
    });

    ui.searchFields.add({
        id: 'uav', description: 'Drone serial numbers',
        fields: [`${uav}/uav.serialnumber`],
    });

    const has = (dev, path) => {
        const v = api.field(dev, path);
        return v !== undefined && v !== null && v !== 0 && v !== '';
    };

    ui.deviceDetails.add({
        id: 'uav', title: 'UAV / drone', priority: 4,
        match: (dev) => has(dev, uav),
        fields: [
            { title: 'Manufacturer', field: `${uav}/uav.manufacturer`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'Worked out from the device\'s MAC address and SSID, or read from DroneID or Remote ID data it broadcasts.' },
            { title: 'Model', field: `${uav}/uav.model`, hideEmpty: true,
                help: 'Worked out from the device\'s MAC address and SSID, or read from DroneID or Remote ID data it broadcasts.' },
            { title: 'Serial number', field: `${uav}/uav.serialnumber`, hideEmpty: true,
                help: 'Sent by drones that broadcast DJI DroneID or Open Drone ID / Remote ID.' },
            { title: 'Identified by', field: `${uav}/uav.match_type`, hideEmpty: true, empty: ui.muted('Unknown'),
                help: 'How Kismet knew this is a drone: "WifiMatch" compares the MAC address and SSID with known drones; "DroneID" means the device sends DJI DroneID data; Remote ID means it broadcasts Open Drone ID.' },
            { title: 'Home location', field: `${uav}/uav.telemetry.home_location/kismet.common.location.geopoint`,
                show: (v) => locationText(v) !== null, format: locationText,
                help: 'The last home location the drone reported: where it flies back to if it loses its signal or is told to return home.' },
            { title: 'App location', field: `${uav}/uav.telemetry.app_location/kismet.common.location.geopoint`,
                show: (v) => locationText(v) !== null, format: locationText,
                help: 'The last location the drone reported for the operator\'s app or controller.' },

            {
                group: 'Telemetry',
                show: (dev) => has(dev, `${uav}/uav.last_telemetry`),
                fields: [
                    { title: 'Motor', field: `${uav}/uav.last_telemetry/uav.telemetry.motor_on`, empty: ui.muted('Unknown'),
                        format: (v) => (v ? 'On' : 'Off'), help: 'Whether the drone says its propellers are turning.' },
                    { title: 'Airborne', field: `${uav}/uav.last_telemetry/uav.telemetry.airborne`, empty: ui.muted('Unknown'),
                        format: (v) => (v ? 'Yes' : 'No'), help: 'Whether the drone says it\'s flying.' },
                    { title: 'Last location', field: `${uav}/uav.last_telemetry/uav.telemetry.location/kismet.common.location.geopoint`,
                        show: (v) => locationText(v) !== null, format: locationText, help: 'The last location the drone reported.' },
                    { title: 'Altitude', field: `${uav}/uav.last_telemetry/uav.telemetry.location/kismet.common.location.alt`,
                        show: (_v, dev) => api.field(dev, `${uav}/uav.last_telemetry/uav.telemetry.location/kismet.common.location.fix`, 0) >= 3,
                        format: meters, help: 'The last altitude the drone reported.' },
                    { title: 'Height', field: `${uav}/uav.last_telemetry/uav.telemetry.height`, format: meters,
                        help: 'Height above the ground, as the drone reports it.' },
                ],
            },

            {
                group: 'Remote ID',
                show: (dev) => has(dev, `${uav}/uav.remoteid`),
                help: 'Open Drone ID / Remote ID (ASTM F3411, ASD-STAN EN 4709-002), as broadcast by the drone.  It isn\'t authenticated: these are the values the drone sent.',
                // Remote ID fields only exist once the drone has sent them, so
                // missing fields simply leave their rows out
                fields: [
                    { title: 'Transport', field: `${rid}.transport`, hideEmpty: true,
                        help: 'How the last Remote ID broadcast arrived: Wi-Fi beacon, Wi-Fi NAN, Bluetooth LE legacy or extended advertising, or Linux HCI scanning.' },
                    { title: 'Protocol', field: `${rid}.protocol_version`, format: named(versions) },
                    { title: 'Serial number', field: `${rid}.serial_number`, hideEmpty: true,
                        help: 'The drone\'s ANSI/CTA-2063-A serial number.' },
                    { title: 'Registration', field: `${rid}.registration_id`, hideEmpty: true,
                        help: 'The drone\'s civil aviation authority registration ID.' },
                    { title: 'UTM ID', field: `${rid}.utm_id`, hideEmpty: true,
                        help: 'An ID given by a UTM (UAS traffic management) service.' },
                    { title: 'Session ID', field: `${rid}.session_id`, hideEmpty: true,
                        help: 'An ID for this flight, which some drones send instead of a fixed serial number.' },
                    { title: 'UA type', field: `${rid}.ua_type`, format: named(uaTypes) },
                    { title: 'Message counter', field: `${rid}.message_counter`,
                        help: 'The counter in the last Remote ID message or message pack.' },

                    {
                        group: 'Location',
                        show: (dev) => api.field(dev, `${rid}.status`) !== undefined,
                        fields: [
                            { title: 'Status', field: `${rid}.status`, format: named(statuses) },
                            { title: 'Direction', field: `${rid}.direction`, format: (v) => `${v}°`,
                                help: 'Direction of travel, clockwise from true north.' },
                            { title: 'Ground speed', field: `${rid}.speed_horizontal`, format: (v) => `${(v * 3.6).toFixed(1)} km/h` },
                            { title: 'Vertical speed', field: `${rid}.speed_vertical`, format: (v) => `${Number(v).toFixed(1)} m/s`,
                                help: 'Climbing when positive, descending when negative.' },
                            { title: 'Geodetic altitude', field: `${rid}.altitude_geo`, format: meters,
                                help: 'Altitude above the WGS-84 ellipsoid (the GPS reference shape of the Earth).' },
                            { title: 'Pressure altitude', field: `${rid}.altitude_baro`, format: meters,
                                help: 'Altitude from air pressure, measured against standard pressure.' },
                            { title: 'Height', field: `${rid}.height`, format: meters },
                            { title: 'Height reference', field: `${rid}.height_type`, format: named(heightTypes) },
                            { title: 'Horizontal accuracy', field: `${rid}.horiz_accuracy`, format: named(horizAccuracy) },
                            { title: 'Vertical accuracy', field: `${rid}.vert_accuracy`, format: named(vertAccuracy) },
                            { title: 'Pressure altitude accuracy', field: `${rid}.baro_accuracy`, format: named(vertAccuracy) },
                            { title: 'Speed accuracy', field: `${rid}.speed_accuracy`, format: named(speedAccuracy) },
                            {
                                title: 'Timestamp', field: `${rid}.location_timestamp`,
                                help: 'When the location was measured, in minutes and seconds past the hour (UTC).',
                                format: (v) => {
                                    const m = Math.floor(v / 60);
                                    const s = v - m * 60;
                                    return `${m}:${s < 10 ? '0' : ''}${s.toFixed(1)} past the hour`;
                                },
                            },
                            { title: 'Timestamp accuracy', field: `${rid}.timestamp_accuracy`,
                                format: (v) => (v === 0 ? 'Unknown' : `${(v / 10).toFixed(1)} s`) },
                        ],
                    },

                    {
                        group: 'Operator',
                        show: (dev) => api.field(dev, `${rid}.operator_location_type`) !== undefined ||
                            api.field(dev, `${rid}.self_id_type`) !== undefined ||
                            has(dev, `${rid}.operator_id`),
                        fields: [
                            { title: 'Operator ID', field: `${rid}.operator_id`, hideEmpty: true,
                                help: 'The operator\'s registration ID, if the drone sends one.' },
                            { title: 'Description', field: `${rid}.self_id`, hideEmpty: true,
                                help: 'The operator\'s own description of the flight.' },
                            { title: 'Description type', field: `${rid}.self_id_type`, format: named(selfIdTypes) },
                            { title: 'Operator location', field: `${rid}.operator_location_type`, format: named(operatorLocationTypes),
                                help: 'Where the operator location (shown as the app location above) comes from.  A takeoff location is also shown as the home location.' },
                            { title: 'Operator altitude', field: `${rid}.operator_altitude`, format: meters },
                            { title: 'Classification', field: `${rid}.classification_type`, format: named(classificationTypes) },
                            { title: 'EU category', field: `${rid}.eu_category`, format: named(euCategories),
                                show: (_v, dev) => api.field(dev, `${rid}.classification_type`) === 1 },
                            { title: 'EU class', field: `${rid}.eu_class`, format: named(euClasses),
                                show: (_v, dev) => api.field(dev, `${rid}.classification_type`) === 1 },
                            { title: 'Aircraft in area', field: `${rid}.area_count`,
                                help: 'How many aircraft the operator has in the operating area.' },
                            { title: 'Area radius', field: `${rid}.area_radius`, format: meters },
                            { title: 'Area ceiling', field: `${rid}.area_ceiling`, format: meters },
                            { title: 'Area floor', field: `${rid}.area_floor`, format: meters },
                            { title: 'System timestamp', field: `${rid}.system_timestamp`, hideZero: true, format: format.time },
                        ],
                    },

                    {
                        group: 'Authentication',
                        show: (dev) => api.field(dev, `${rid}.auth_type`) !== undefined,
                        help: 'Put back together from its pages and shown as sent; Kismet doesn\'t check it.',
                        fields: [
                            { title: 'Type', field: `${rid}.auth_type`, format: named(authTypes) },
                            { title: 'Timestamp', field: `${rid}.auth_timestamp`, hideZero: true, format: format.time },
                            { title: 'Data', field: `${rid}.auth_data`, hideEmpty: true,
                                format: (v) => kismet.dom.el('span', { class: 'mono' }, v) },
                        ],
                    },
                ],
            },
        ],
    });
}
