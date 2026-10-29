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
//   color(row) -> CSS color: optional, for highlights that color each row
//     themselves (set elsewhere) instead of in one color the user picks
export function createHighlightRegistry(name) {
    return createRegistry(name, {
        required: ['name', 'match'],
        defaults: { fields: [], defaultColor: '#6aa36f', defaultEnabled: false, description: '' },
    });
}

export const rowHighlights = createHighlightRegistry('rowHighlights');

// Fields always fetched for the device list, whatever columns are showing.
// The server searches only the fields a request asks for, so phys add the
// fields people will search for (a ship's name, an aircraft's callsign) here.
//   id, description, fields
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
