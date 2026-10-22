// Registries for device views, device details, and channel naming.

import { createRegistry } from './registry.js';

// Device views: the lists the server keeps (all devices, per phy, per
// datasource, Wi-Fi access points, ...).  The server's views are found on
// their own; modules add entries here to give one a better title or group.
//   id (the server's view id, e.g. 'phydot11_accesspoints'), title, group, priority
export const deviceViews = createRegistry('deviceViews', {
    required: ['title'],
    defaults: { group: '' },
});

// Sections of the device panel.
//   id, title, priority
//   match(device) -> bool   whether this section applies to the device
//   fields                  the section's rows, in the form detailFields() takes
//                           (see js/widgets/detailfields.js)
//   render(device, el)      or draw the section yourself; called again with
//                           fresh data every time the device changes
//   open                    start expanded (default true); the user's choice
//                           is remembered
//
// A section has fields, render, or both (render runs after the fields, into
// its own space below them).
export const deviceDetails = createRegistry('deviceDetails', {
    required: ['title', 'match'],
    defaults: { open: true },
});

// Rows added to someone else's section: a plugin adding a line to Wi-Fi, say.
//   id, section (the section's id), priority, and the field entry itself
//   (title, field, format, ...; see js/widgets/detailfields.js)
// A section's own rows have priorities 0, 10, 20, ... in the order it lists
// them, so priority 15 lands between its second and third rows.
export const deviceDetailFields = createRegistry('deviceDetailFields', {
    required: ['section'],
});

// Channel numbering per phy, for labelling frequencies (in the channel
// coverage window, say).
//   id (phy name, e.g. 'IEEE802.11'), title (short, e.g. 'Wi-Fi'), priority
//   name(khz) -> the channel at that frequency, or null if it isn't one of
//                this phy's channels
//   frequency(channel) -> kHz, or null (optional; the reverse of name)
// Where channel plans overlap (Wi-Fi and Bluetooth LE at 2.4 GHz), the
// lowest priority names the frequency and the others are listed with it.
export const channelNames = createRegistry('channelNames', {
    required: ['name'],
});

// Turning a data source's channel names into frequencies, for the channel
// coverage window.  Sources only report channels in their own terms ("6",
// "36HT40+", "5W6e", "37"), so each phy says how to read its sources'.
//   id, priority,
//   match(source) -> bool    whether this applies; source is the datasource record
//   frequency(channel) -> kHz, or null if it can't tell
// Channels that are plain frequencies ("2412", "433.92MHz") work without one.
export const sourceChannels = createRegistry('sourceChannels', {
    required: ['match', 'frequency'],
});
