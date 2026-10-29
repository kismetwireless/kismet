// Registries for the Data sources window (js/widgets/datasources.js).
//
// A data source's card is built from sections, like the device panel.  The
// standard ones (js/base/sources.js) work for every source; a phy module adds
// its own for the capture drivers it knows (Wi-Fi channel layouts, a cell
// modem's scan profile, an SDR's gain, ...).
//
// Entries here pick the sources they apply to with either
//   drivers: ['linuxwifi', ...]   the capture driver types (the
//                                 kismet.datasource.driver.type field)
//   match(source) -> bool         or any test of the source record

import { createRegistry } from './registry.js';

// Sections of a data source's card.
//   id, title, priority, drivers or match,
//   fields      rows in the form detailFields() takes (js/widgets/detailfields.js);
//               draw(cell, value, source, state, ctx) gets the window's
//               context (below) last, for controls
//   render(source, el, ctx)   or draw the section yourself; called again
//               about once a second with fresh data, so update in place
//   open        start expanded (default true); the user's choice is kept
//   running     only while the source is open and running
//   when(source, type) -> bool   a further test, given the source's sourceTypes entry
//
// ctx, for sections and the entries below:
//   ctx.sources            every source, as last read
//   ctx.busy(promise, text)  cover the card with text until promise settles
//   ctx.refresh()          read the sources again now
//   ctx.message(text, kind)  a note under the card's title ('error', 'ok', or plain)
export const sourceSections = createRegistry('sourceSections', {
    required: ['title'],
    defaults: { open: true, running: false },
});

// Rows added to someone else's section, as deviceDetailFields does for the
// device panel.  id, section, priority, and the field entry itself.
export const sourceFields = createRegistry('sourceFields', {
    required: ['section'],
});

// What a kind of source is, for the window's titles and lists.  The first
// match (by priority) wins.
//   id, priority, drivers or match,
//   icon                     icon name (js/core/icons.js) for the card
//   subtitle(source, ctx)    short text after the name (a modem's model, say)
//   channels: false          hide the standard channel section, for sources
//                            whose "channels" aren't radio channels; their
//                            own section takes over
//   interfaceTitle(intf)     title for an available interface of this driver
//   interfaceSubtitle(intf)  text after it
//   enableForm(intf, ctx) -> node   the options asked for before Enable, in
//                            place of a plain Enable button; built once per
//                            interface and kept while it's listed
//   interfaces(list, ctx) -> list   add or change listed interfaces (for
//                            drivers whose lister can't see a busy device)
//   sortKey(intf)            order interfaces; default the interface name
export const sourceTypes = createRegistry('sourceTypes', {
    required: [],
});

// Channel pickers: how a source's channels are shown and chosen in the
// standard channel section.  The first match (by priority) is used; the
// generic one, a button per channel, matches anything.
//   id, priority, drivers or match,
//   create(el, ctx) -> { update(source, state), destroy() }
//     state is the section's shared hop/lock state (js/base/sources.js):
//       state.mode 'hop' | 'lock', state.selected (Set of channels to hop),
//       state.pending (true while a change is waiting to be sent),
//       state.toggle(channel), state.lock(channel), state.setSelected(list)
export const channelPickers = createRegistry('channelPickers', {
    required: ['create'],
});

// The driver type of a source or interface record, whichever way it was read
export function driverOf(rec) {
    return rec?.['kismet.datasource.type_driver']?.['kismet.datasource.driver.type'] ??
        rec?.['kismet.datasource.driver.type'] ?? '';
}

// Whether a registry entry applies to a record
export function applies(entry, rec) {
    try {
        if (entry.drivers)
            return entry.drivers.includes(driverOf(rec)) && (!entry.match || entry.match(rec));
        return entry.match ? !!entry.match(rec) : true;
    } catch (err) {
        console.error(`data source entry ${entry.id} failed:`, err);
        return false;
    }
}

export function typeOf(rec) {
    return sourceTypes.list().find((t) => applies(t, rec)) ?? null;
}
