// Registries for the parts of the page around the device list.

import { createRegistry } from './registry.js';

// Main menu entries.
//   id, title, icon (optional name from js/core/icons.js), priority, onClick()
export const menuItems = createRegistry('menuItems', {
    required: ['title', 'onClick'],
});

// Stats in the ribbon across the top of the page.
//   id, title, priority, description,
//   create(el) -> optional cleanup function.  Fill `el` and keep it updated,
//   usually by subscribing to the eventbus.
export const ribbonStats = createRegistry('ribbonStats', {
    required: ['title', 'create'],
    defaults: { description: '', defaultVisible: true },
});

// Tabs in the page's tabbed areas: 'main' (the device list, SSIDs, alerts)
// or 'bottom' (messages).
//   id, title, area, priority,
//   create(el) -> optional { show(), hide(), destroy() }.  show/hide are called
//   as the user switches tabs, so a hidden tab can stop its updates.
// For a table over a Kismet list, kismet.ui.addTable makes the tab for you.
export const panes = createRegistry('panes', {
    required: ['title', 'create'],
    defaults: { area: 'bottom' },
});

// Kinds of device drawn on the map tab, each with a checkbox in the map's
// list.  Phys and plugins add one for each kind of device that has a place
// on the map.  Each is read from a device view, optionally narrowed by a
// Kismet regex, every couple of seconds while the map is showing (and every
// 15 s while it's hidden, to keep paths going).  A device claimed by more
// than one kind is drawn by the one with the lowest priority.
//
// What to read:
//   view: device view id (default 'all'), regex: optional [[field, regex], ...],
//   fields: extra [path, name] pairs the functions below read from dev,
//   maxAge: seconds a device stays on the map after it's last heard,
//   interval: optional ms between reads, for kinds that are slow to query
// Where to draw it:
//   position: 'reported' (default): where the device says it is,
//     'heard': where Kismet last heard it, 'average': the middle of where
//     Kismet has heard it (a fixed device's best guess), 'reported-or-heard':
//     reported, or heard when it reports nothing; or fn(dev) -> [lon, lat] or
//     null, treated as a reported position
//   paths: draw the path a reported position leaves (default true)
//   legacy: on servers older than 2026-10, the device location is the position
//     the device reported (ADS-B, AIS)
// How it looks:
//   id, title, priority, defaultVisible, icon (icon name, or fn(dev) -> name),
//   layerIcon: icon for the checkbox when icon is a function,
//   label(dev), detail(dev) -> short text, color(dev) -> CSS color,
//   heading(dev) -> degrees to point the icon, or null,
//   legend() -> optional node shown on the map while the kind is visible
// dev has key, name, phy, type, last_time, rep, heard and avg ([lon, lat] or
// null), rep_alt, rep_speed, rep_heading, plus the kind's own fields.
export const mapSources = createRegistry('mapSources', {
    required: ['title'],
    defaults: { view: 'all', icon: 'gps', maxAge: 600, position: 'reported', paths: true, defaultVisible: true },
});

// Cards on the Overview tab.
//   id, title, priority,
//   w, h: the card's starting size on the 12-column grid, in columns and
//     rows of 40 px (3 × 5 if not given; size: 'wide' starts it 6 wide),
//   needs: the shared data it reads ('status', 'packets', 'phys', 'channels',
//     'alerts', 'sources', 'talkers', 'devices'; see js/widgets/overview.js),
//   loading: the outline shown until that data arrives, as shapes from
//     kismet.widgets.loading ('stat', 'tabs', 'graph', 'histogram', 'bars',
//     'list', 'table', 'donut', 'text'), one or a list stacked top to
//     bottom, each a name or { kind, rows }; 'text' if not given,
//   create(body, { actions }) -> { update(data), destroy() }
//     update() is first called once all of `needs` has arrived
//     actions.showTab(id), actions.showDevices(viewId)
export const dashboardCards = createRegistry('dashboardCards', {
    required: ['title', 'create'],
    defaults: { size: 'small', needs: [] },
});

// Sections of the settings dialog.
//   id, title, priority, create(el) -> optional cleanup function
// Settings take effect as they change; there is no save button.
export const settingsPanes = createRegistry('settingsPanes', {
    required: ['title', 'create'],
});

// Color schemes, listed in Settings > Appearance.
//   id, title, priority,
//   dark: { ...colors }, light: { ...colors }   one or both versions
// The colors (all optional except bg, surface, text, and accent):
//   bg, surface, surface-2, border     page, panels, raised parts, lines
//   text, muted                        text, and quieter text
//   accent, accent-text                the highlight color, and text on it
//   ok, warn, error                    status colors
//   accent-soft, row-alt, row-hover    worked out from the others if left out
//   shadow                             a CSS box-shadow for dialogs
//   highlight-mix                      how strongly row highlights tint rows, e.g. '30%'
// The default scheme, 'kismet', comes from css/themes.css instead.
export const colorSchemes = createRegistry('colorSchemes', {
    required: ['title'],
});
