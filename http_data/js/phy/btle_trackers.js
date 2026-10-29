// Location trackers (AirTag and other Find My devices, SmartTag, Google Find Hub
// tags, DULT, Tile...) decoded from BTLE and Bluetooth (HCI) advertisements.
// The server keeps the same tracker record under both phys.

const base = 'kismet.device.base';
const paths = ['btle.device/btle.device.tracker', 'bluetooth.device/bluetooth.device.tracker'];
const t = 'btle.device.tracker';

const typeNames = {
    apple_findmy: 'Apple Find My',
    samsung_smarttag: 'Samsung SmartTag',
    google_fmdn: 'Google Find Hub',
    dult: 'Unwanted tracking (DULT)',
    tile: 'Tile',
    chipolo: 'Chipolo',
    pebblebee: 'Pebblebee',
};

const classNames = {
    airtag: 'AirTag',
    airpods: 'AirPods',
    findmy_accessory: 'Find My accessory',
    apple_device: 'Apple device (iPhone, iPad, Mac, Watch)',
};

const stateNames = {
    separated: 'Away from its owner',
    near_owner: 'Near its owner',
    unwanted_tracking_protection: 'Away from its owner (tracking protection)',
    normal: 'Normal',
    premature_offline: 'Away from its owner (recently)',
    offline: 'Away from its owner',
    overmature_offline: 'Away from its owner for over a day',
    connected: 'Connected to its owner',
    activated: 'Activated',
    not_activated: 'Not activated',
};

// Fields read for the device list and Insights, renamed per phy so either works
const fieldsFor = (prefix) => paths.flatMap((p, i) => [
    [`${p}/${t}.type`, `${prefix}${i}_type`],
    [`${p}/${t}.separated`, `${prefix}${i}_sep`],
    [`${p}/${t}.subtype`, `${prefix}${i}_class`],
    [`${p}/${t}.follow_time`, `${prefix}${i}_ft`],
    [`${p}/${t}.follow_locations`, `${prefix}${i}_fl`],
    [`${p}/${t}.battery`, `${prefix}${i}_batt`],
]);

function trackerOf(row, prefix) {
    for (let i = 0; i < paths.length; i++) {
        const type = row[`${prefix}${i}_type`];
        if (typeof type === 'string' && type)
            return {
                type, separated: !!row[`${prefix}${i}_sep`], deviceClass: row[`${prefix}${i}_class`] || '',
                followTime: row[`${prefix}${i}_ft`] || 0, followLocations: row[`${prefix}${i}_fl`] || 0,
                battery: row[`${prefix}${i}_batt`] || '',
            };
    }
    return null;
}

export const trackerName = (tr) => classNames[tr.deviceClass] ?? typeNames[tr.type] ?? tr.type;

export function registerTrackers(kismet) {
    const { ui, format, icons } = kismet;

    const listFields = fieldsFor('trk');

    icons.define('tag', '<path d="M3 12l9-9h9v9l-9 9z"/><circle cx="16" cy="8" r="1.5"/>');

    ui.deviceIcons.add({
        id: 'tracker', priority: -10,
        fields: listFields,
        match: (row) => (trackerOf(row, 'trk') ? icons.icon('tag', 'Location tracker') : null),
    });

    ui.rowHighlights.add({
        id: 'tracker_separated', name: 'Separated location tracker', priority: 90,
        description: 'Location trackers advertising that they are away from their owner',
        defaultColor: '#ffa8a8', defaultEnabled: true,
        fields: listFields,
        match: (row) => trackerOf(row, 'trk')?.separated === true,
    });

    ui.rowHighlights.add({
        id: 'tracker_all', name: 'Location tracker', priority: 91,
        description: 'Every location tracker (AirTag, SmartTag, Find Hub, Tile...)',
        defaultColor: '#ffd8a8',
        fields: listFields,
        match: (row) => trackerOf(row, 'trk') !== null,
    });

    const section = (p) => [
        { title: 'Network', field: `${p}/${t}.type`, format: (v) => typeNames[v] ?? v,
            help: 'The finding network the tracker reports to.  DULT is the common format for trackers that follow the IETF unwanted tracking rules.' },
        { title: 'Kind of device', field: `${p}/${t}.subtype`, hideEmpty: true, format: (v) => classNames[v] ?? v,
            help: 'What the tracker says it is.  Second generation AirTags call themselves a Find My accessory.' },
        { title: 'State', field: `${p}/${t}.state_name`, format: (v) => stateNames[v] ?? v },
        { title: 'Separated', field: `${p}/${t}.separated`, format: (v) => (v ? 'Yes' : 'No'),
            help: 'The tracker advertises that it is away from its owner.  A tracker that is with its owner is normal; one that is separated and stays with you may be following you.' },
        { title: 'Battery', field: `${p}/${t}.battery`, hideEmpty: true,
            format: (v) => ({ full: 'Full', medium: 'Medium', low: 'Low', very_low: 'Very low' })[v] ?? v,
            help: 'The battery level the tracker advertises.' },
        { title: 'Owner seen recently', field: `${p}/${t}.maintained`, show: (v) => v !== undefined,
            format: (v) => (v ? 'Yes' : 'No'),
            help: 'Find My devices advertise whether their owner connected to them in the last 15 minutes.' },
        { title: 'Seen while separated', field: `${p}/${t}.follow_time`, hideZero: true, format: format.duration,
            help: 'How long Kismet has seen the tracker, without a gap of over 20 minutes, while it says it is separated.' },
        { title: 'Places seen', field: `${p}/${t}.follow_locations`, hideZero: true,
            help: 'Places at least 100 meters apart where Kismet saw the separated tracker (needs GPS).  Over 30 minutes at three or more places raises a TRACKERFOLLOW alert.' },
        { title: 'Privacy ID', field: `${p}/${t}.privacy_id`, hideEmpty: true,
            help: 'A short ID which stays the same while the tracker keeps its rotating ID, so its advertisements can be grouped.  For Tile it is a hash, salted fresh each time Kismet starts, so it never reveals the ID and does not match between runs.' },
        { title: 'Ephemeral ID', field: `${p}/${t}.ephemeral_id`, hideEmpty: true,
            help: 'A salted hash of the Find Hub ephemeral ID, which the tag changes every 1024 seconds; it groups advertisements within this run of Kismet only.' },
        { title: 'Network ID', field: `${p}/${t}.network_id`, show: (v) => v !== undefined,
            help: 'The finding network the tracker reports to, from its DULT advertisement.' },
        { title: 'Last tracker advertisement', field: `${p}/${t}.last_time`, hideZero: true, format: format.time },
    ];

    ui.deviceDetails.add({
        id: 'btle_tracker', title: 'Location tracker', priority: 3,
        match: (device) => paths.some((p) => kismet.api.field(device, `${p}/${t}.type`)),
        render(device, el) {
            const p = paths.find((x) => kismet.api.field(device, `${x}/${t}.type`));
            ui.detailFields(el, device, section(p));
        },
    });

    // Insights: mark trackers in the graph, and list the separated ones
    const insightFields = fieldsFor('ins');

    ui.insightRelations.add({
        id: 'trackers', fields: insightFields,
        relate(rec, g) {
            const tr = trackerOf(rec, 'ins');
            if (!tr)
                return;
            const n = g.device(rec[`${base}.key`]);
            if (!n)
                return;
            n.tracker = tr;
            n.label = trackerName(tr);
            if (tr.separated)
                g.flag(n, 'separated tracker');
        },
    });

    ui.insightFindings.add({
        id: 'trackers',
        fields: insightFields,
        alerts: ['TRACKERFOLLOW'],
        find({ records }) {
            const out = [];
            const separated = [];
            for (const rec of records) {
                const tr = trackerOf(rec, 'ins');
                if (!tr?.separated)
                    continue;
                const key = rec[`${base}.key`];
                const mac = rec[`${base}.macaddr`];
                if (tr.followTime >= 1800 && tr.followLocations >= 3) {
                    out.push({
                        id: `tracker-follow:${key}`, severity: 'high',
                        title: `${/^[AEIOU]/.test(trackerName(tr)) ? 'An' : 'A'} ${trackerName(tr)} away from its owner is moving with you`,
                        text: `${mac} (${typeNames[tr.type] ?? tr.type}) says it is separated from its owner and has been seen for ` +
                            `${format.duration(tr.followTime)} at ${tr.followLocations} places at least 100 m apart.  ` +
                            'Someone may have hidden it to follow you; look for it, or use the network\'s tracker detection ' +
                            '(Find My on an iPhone, unknown tracker alerts on Android) to make it play a sound.',
                        devices: [key],
                    });
                } else {
                    separated.push({ key, mac, tr });
                }
            }
            if (separated.length)
                out.push({
                    id: 'tracker-separated', severity: 'info',
                    title: `${separated.length} location tracker${separated.length > 1 ? 's' : ''} away from ${separated.length > 1 ? 'their owners' : 'its owner'}`,
                    text: separated.map(({ mac, tr }) => `${mac} (${trackerName(tr)}` +
                        (tr.followTime ? `, ${format.duration(tr.followTime)}` : '') + ')').join(', ') + '.  ' +
                        'Lost or forgotten trackers are common.  One that stays with you for half an hour across ' +
                        'several places (Kismet needs GPS to tell) is worth looking for.',
                    devices: separated.map((s) => s.key),
                });
            return out;
        },
    });
}
