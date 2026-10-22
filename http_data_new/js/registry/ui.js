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
