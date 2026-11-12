// The device list: a data table (js/widgets/datatable.js) over one of the
// server's device views, with the view picker, per-phy icons, and row
// highlights.  Clicking a device opens its panel.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as settings from '../core/settings.js';
import * as sources from '../core/sources.js';
import { onLogin } from '../core/auth.js';
import { compileQuery, fieldContext } from '../core/filterquery.js';
import { deviceColumns, deviceIcons, rowHighlights, searchFields, filterHints, alwaysFields } from '../registry/columns.js';
import { deviceViews } from '../registry/devices.js';
import { openDevice } from './detailpanel.js';
import { createDataTable } from './datatable.js';
import { openSettings } from './settingsdialog.js';

// Device lists on screen, to refresh at once when the user changes a device
const tables = new Set();

export function refreshAll() {
    for (const t of tables) {
        if (t.table.element.isConnected) {
            t.table.refresh();
            // The view picker's counts too
            t.loadViews();
        } else {
            tables.delete(t);
        }
    }
}

export function createDeviceTable(container) {
    // 'default' leaves out the devices that 'exclude' device rules match
    let view = settings.get('devicelist.view', 'default');
    let lastViews = null;
    let table = null;
    // The phys this server has, so filters leave out hints for the others
    let serverPhys = null;

    const viewSelect = el('select', { class: 'view-select', title: 'Which devices to list',
        onchange: () => {
            view = viewSelect.value;
            settings.set('devicelist.view', view);
            table.restart(true);
        } });

    // The server's device views, grouped for the picker
    async function loadViews() {
        const [serverViews, sourceList] = await Promise.all([
            api.get('devices/views/all_views.json').catch((err) => {
                console.error('Could not load device views:', err);
                return [];
            }),
            sources.list(['kismet.datasource.uuid', 'kismet.datasource.name', 'kismet.datasource.interface'])
                .catch(() => []),
        ]);

        // Data source views are named by uuid; show the source's name, and its
        // interface too when sources share a name
        const sourceNames = new Map();
        const nameCount = new Map();
        for (const s of sourceList) {
            const name = s['kismet.datasource.name'];
            if (name)
                nameCount.set(name, (nameCount.get(name) ?? 0) + 1);
        }
        for (const s of sourceList) {
            const name = s['kismet.datasource.name'];
            const iface = s['kismet.datasource.interface'];
            if (name && s['kismet.datasource.uuid'])
                sourceNames.set(s['kismet.datasource.uuid'].toUpperCase(),
                    nameCount.get(name) > 1 && iface && iface !== name ? `${name} (${iface})` : name);
        }

        const groups = new Map();
        const addOption = (group, id, title, count) => {
            if (!groups.has(group))
                groups.set(group, []);
            groups.get(group).push({ id, title, count });
        };

        for (const v of serverViews) {
            const id = v['kismet.devices.view.id'];
            if (v['kismet.devices.view.indexed'] === false)
                continue;
            const count = v['kismet.devices.view.size'];
            const custom = deviceViews.get(id);
            if (custom)
                addOption(custom.group, id, custom.title, count);
            else if (id === 'all')
                addOption('', id, 'All devices', count);
            else if (id === 'default')
                addOption('', id, 'Default', count);
            else if (id.startsWith('phy-'))
                addOption('Phy types', id, v['kismet.devices.view.description'] || id.slice(4), count);
            else if (id.startsWith('seenby-'))
                addOption('Data sources', id, sourceNames.get(id.slice(7).toUpperCase()) ||
                    v['kismet.devices.view.description'] || id, count);
            else
                addOption('Other', id, v['kismet.devices.view.description'] || id, count);
        }

        if (!groups.size)
            addOption('', 'all', 'All devices');

        // Rebuilding the menu closes it, so leave it alone while it's open or unchanged
        const signature = JSON.stringify([...groups]);
        if (signature === lastViews || document.activeElement === viewSelect)
            return;
        lastViews = signature;

        // Default and all devices at the top, then the groups, each in alphabetical order
        const ordered = [...groups].sort(([a], [b]) => (b === '') - (a === ''));
        for (const [, list] of ordered)
            list.sort((a, b) => (b.id === 'default') - (a.id === 'default') || (b.id === 'all') - (a.id === 'all') ||
                a.title.localeCompare(b.title, undefined, { numeric: true, sensitivity: 'base' }));

        const options = [];
        for (const [group, list] of ordered) {
            const opts = list.map((o) => el('option', { value: o.id },
                Number.isFinite(o.count) ? `${o.title} (${o.count.toLocaleString()})` : o.title));
            options.push(group ? el('optgroup', { label: group }, opts) : opts);
        }
        viewSelect.replaceChildren(...options.flat());
        viewSelect.value = view;
        if (viewSelect.value !== view) {
            view = 'all';
            viewSelect.value = 'all';
            table?.restart(true);
        }
    }

    table = createDataTable(container, {
        id: 'devicelist',
        endpoint: () => `devices/views/${encodeURIComponent(view)}/devices.json`,
        columns: deviceColumns,
        icons: deviceIcons,
        highlights: rowHighlights,
        editHighlights: () => openSettings('highlights'),
        searchFields,
        alwaysFields,
        rowKey: (row) => row['kismet.device.base.key'],
        onRowClick: (row) => openDevice(row.key),
        defaultSort: { column: 'last_time', dir: 'desc' },
        noun: 'devices',
        toolbar: () => viewSelect,
        pausable: true,
        // Filters in the search box name the device list's columns, search fields and hints
        query: (text) => compileQuery(text, fieldContext(deviceColumns.list(), searchFields.list(),
            filterHints.list(), serverPhys)),
    });

    tables.add({ table, loadViews: () => loadViews() });

    async function loadPhys() {
        try {
            const list = await api.get('phy/all_phys.json');
            serverPhys = Array.isArray(list) ? new Set(list.map((p) => p['kismet.phy.phy_name'])) : null;
        } catch {
            serverPhys = null;
        }
    }

    loadViews();
    loadPhys();
    onLogin(loadViews);
    onLogin(loadPhys);
    // Keep the counts in the picker current
    const viewTimer = setInterval(() => {
        if (!container.isConnected)
            clearInterval(viewTimer);
        else if (document.visibilityState !== 'hidden')
            loadViews();
    }, 15000);
    // Another part of the UI can pick the view (the Overview's phy counts)
    settings.watch('devicelist.view', (v) => {
        if (!v || v === view)
            return;
        view = v;
        viewSelect.value = v;
        if (viewSelect.value !== v) {
            lastViews = null;
            loadViews();
        }
        table.restart(true);
    });
    // Views come and go with datasources and phys
    setInterval(() => {
        if (document.visibilityState !== 'hidden')
            loadViews();
    }, 30000);

    return table;
}
