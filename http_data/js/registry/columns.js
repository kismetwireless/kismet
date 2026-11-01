// Device list columns, icons, and row highlights.
//
// The device list asks the server only for the fields that the visible
// columns, icons, and highlights say they need, so each of them lists its
// `fields`.  A field is a path into the device record, or a [path, name] pair
// to give it a shorter name:
//
//   'kismet.device.base.channel'          -> row['kismet.device.base.channel']
//   'dot11.device/dot11.device.last_bssid' -> row['dot11.device.last_bssid']
//                                             (a path is named by its last part)
//   ['kismet.device.base.signal/kismet.common.signal.last_signal', 'signal']
//                                         -> row.signal
//
// Renderers get a `row`: the requested fields by name, plus row.key (the
// device key).

import { createRegistry } from './registry.js';

// Every table has registries like these (see kismet.ui.tableColumns and
// kismet.ui.tableHighlights for other tables); the device list's are here.
//
// Column:
//   id            unique id, also saved in the user's column settings
//   title         header text
//   description   longer text shown in the column picker
//   fields        fields this column needs (see above)
//   sortField     field path the server sorts on; omit for unsortable columns
//   render(row)   returns a string or a DOM node for the cell
//   group         heading in the column chooser, e.g. 'Wi-Fi' (default 'General')
//   width         starting CSS width, e.g. '8em' (optional; users can resize)
//   align         'left' | 'right' | 'center' (optional)
//   defaultVisible  shown until the user changes their columns
//   filterKind    what sortField holds, for the search box's filters: 'text',
//                 'number', 'time' (a timestamp), 'mac', or 'duration' (a length
//                 of time) (optional; see js/core/filterquery.js)
//   filterConvert for a duration, seconds to the field's units, such as
//                 ui.durationIn.us (optional; seconds when not given)
//   filterWide    field paths the search box uses for name* (optional)
//   filterEmpty   the value, or list of values, sortField holds when it has no
//                 data; filters on the column skip those devices (optional)
//   filterPresent a field that is 0 or missing when sortField has no data
//                 (optional)
//   filterNames   more names for the column in the search box; a name several
//                 columns or search fields give matches any of their fields
export function createColumnRegistry(name) {
    return createRegistry(name, {
        required: ['title', 'render'],
        defaults: { fields: [], align: 'left', defaultVisible: false, description: '' },
    });
}

export const deviceColumns = createColumnRegistry('deviceColumns');

// Icon shown at the start of each row.  The first icon (by priority) whose
// match(row) returns a node is used.
//   id, priority, fields, match(row) -> Node | null
export const deviceIcons = createRegistry('deviceIcons', {
    required: ['match'],
    defaults: { fields: [] },
});

// Row highlight: colors rows that match.  Users turn highlights on and off and
// pick the colors in settings.
//   id, name, description, priority, fields, match(row) -> bool,
//   defaultColor (CSS color), defaultEnabled,
//   category: 'tag', 'phy', or '' for the rest, to group them in settings,
//   color(row) -> CSS color: optional, for highlights that color each row
//     themselves (set elsewhere) instead of in one color the user picks
export function createHighlightRegistry(name) {
    return createRegistry(name, {
        required: ['name', 'match'],
        defaults: { fields: [], defaultColor: '#6aa36f', defaultEnabled: false, description: '', category: '' },
    });
}

export const rowHighlights = createHighlightRegistry('rowHighlights');

// The default row color for every device of a phy, which the user can change
// in Settings; each phy Kismet reports gets a highlight in that color.
//   id: the phy name as the server reports it ('IEEE802.11'), title, color,
//   enabled: whether the highlight is on by default
export const phyColors = createRegistry('phyColors', {
    required: ['color'],
    defaults: { enabled: false },
});

// Fields always fetched for the device list, whatever columns are showing.
// The server searches only the fields a request asks for, so phys add the
// fields people will search for (a ship's name, an aircraft's callsign) here.
// The id names them all in the search box's filters.
//   id, description, fields,
//   filterKind: the kind of the fields that aren't text, as { path: kind }
//   filterConvert: for duration fields, as { path: function } (see columns)
//   filterEmpty, filterPresent: as for columns, one for all or { path: ... }
//   filterNames: more names for these fields in the search box
export const searchFields = createRegistry('searchFields', {
    required: ['fields'],
    defaults: { description: '' },
});

// Fields every row gets: the key, to open the device
export const alwaysFields = ['kismet.device.base.key'];

// The name a field shows up under in a row
export function fieldName(spec) {
    return Array.isArray(spec) ? spec[1] : spec.split('/').pop();
}
