// Tables as tabs: any module can add a live table over a Kismet list as a
// tab in either tabbed area of the page.
//
//   kismet.ui.addTable({
//       id: 'ssids', title: 'SSIDs', area: 'main', priority: 20,
//       endpoint: 'phy/phy80211/ssids/views/ssids.json',
//       noun: 'SSIDs',
//       rowKey: (row) => row['dot11.ssidgroup.hash'],
//       onRowClick: (row) => ...,
//       defaultSort: { column: 'last_time', dir: 'desc' },
//       columns: [ { id, title, fields, sortField, render, width, align, defaultVisible, description, group }, ... ],
//       highlights: [ { id, name, description, fields, match, defaultColor, defaultEnabled }, ... ],
//   });
//
// Columns and highlights work exactly as the device list's (see
// js/registry/columns.js).  Each table keeps its own registries, so another
// module can add a column to someone else's table, before or after the
// table itself is added:
//
//   kismet.ui.tableColumns('ssids').add({ id: 'mine', title: 'Mine', ... });
//
// The rest of the options are the data table's (js/widgets/datatable.js).

import { createColumnRegistry, createHighlightRegistry } from '../registry/columns.js';
import { panes } from '../registry/ui.js';
import { createDataTable } from './datatable.js';

const columnRegistries = new Map();
const highlightRegistries = new Map();

// The column registry for a table, made the first time anyone asks for it
export function tableColumns(id) {
    if (!columnRegistries.has(id))
        columnRegistries.set(id, createColumnRegistry(`${id} columns`));
    return columnRegistries.get(id);
}

export function tableHighlights(id) {
    if (!highlightRegistries.has(id))
        highlightRegistries.set(id, createHighlightRegistry(`${id} highlights`));
    return highlightRegistries.get(id);
}

export function addTable({ id, title, area = 'main', priority = 0, columns = [], highlights = [], ...options }) {
    const cols = tableColumns(id);
    for (const c of columns)
        cols.add(c);
    const hls = tableHighlights(id);
    for (const h of highlights)
        hls.add(h);

    panes.add({
        id: `table-${id}`, title, area, priority,
        create: (el) => createDataTable(el, { id: `table.${id}`, columns: cols, highlights: hls, ...options }),
    });
}
