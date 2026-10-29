// The Kismet UI API: everything a module (built-in, phy, or plugin) uses.
//
// A module is an ES module that exports a register() function:
//
//   export function register(kismet) {
//       kismet.ui.deviceColumns.add({ id: 'channel', title: 'Channel', ... });
//   }
//
// Built-in parts of the UI register themselves the same way (see js/base/).

import * as api from './core/api.js';
import * as eventbus from './core/eventbus.js';
import * as settings from './core/settings.js';
import * as theme from './core/theme.js';
import * as format from './core/format.js';
import * as rrd from './core/rrd.js';
import * as clock from './core/clock.js';
import * as dom from './core/dom.js';
import * as icons from './core/icons.js';
import { createRegistry } from './registry/registry.js';
import { deviceColumns, deviceIcons, rowHighlights, searchFields, alwaysFields, fieldName } from './registry/columns.js';
import { menuItems, ribbonStats, panes, settingsPanes, colorSchemes, mapSources, dashboardCards } from './registry/ui.js';
import { deviceViews, deviceDetails, deviceDetailFields, channelNames, sourceChannels } from './registry/devices.js';
import * as modules from './core/modules.js';
import * as servers from './core/servers.js';
import * as pwa from './core/pwa.js';
import { detailFields, muted } from './widgets/detailfields.js';
import { historyGraph } from './widgets/historygraph.js';
import { listTable } from './widgets/listtable.js';
import * as coverage from './widgets/coverage.js';
import * as datatable from './widgets/datatable.js';
import { addTable, tableColumns, tableHighlights } from './widgets/tables.js';
import { openDevice } from './widgets/detailpanel.js';
import * as dialog from './widgets/dialog.js';
import * as devicetable from './widgets/devicetable.js';
import * as messages from './widgets/messages.js';
import * as ribbon from './widgets/ribbon.js';
import * as settingsdialog from './widgets/settingsdialog.js';
import * as serversdialog from './widgets/serversdialog.js';
import { sparkline } from './widgets/sparkline.js';
import * as cellgraphs from './widgets/cellgraphs.js';
import * as map from './widgets/map.js';
import * as charts from './widgets/charts.js';
import * as overview from './widgets/overview.js';
import * as gps from './widgets/gps.js';
import * as loading from './widgets/loading.js';
import * as panesWidget from './widgets/panes.js';

export const kismet = {
    api,
    eventbus,
    settings,
    theme,
    format,
    rrd,
    clock,
    dom,
    icons,
    modules,
    servers,
    pwa,

    // Building blocks for modules that draw their own UI
    widgets: {
        dialog,
        devicetable,
        messages,
        ribbon,
        settingsdialog,
        serversdialog,
        sparkline,
        cellgraphs,
        historyGraph,
        listTable,
        coverage,
        datatable,
        map,
        charts,
        overview,
        gps,
        loading,
        panes: panesWidget,
    },

    ui: {
        deviceColumns,
        deviceIcons,
        rowHighlights,
        searchFields,
        deviceViews,
        deviceDetails,
        deviceDetailFields,
        channelNames,
        sourceChannels,
        menuItems,
        ribbonStats,
        panes,
        settingsPanes,
        colorSchemes,
        mapSources,
        dashboardCards,

        alwaysFields,
        fieldName,
        createRegistry,

        addTable,
        tableColumns,
        tableHighlights,

        detailFields,
        muted,
        openDevice,
    },
};

// For scripts that aren't modules and for poking at the UI from the browser console
window.kismet2 = kismet;
