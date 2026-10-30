// The device list: a data table (js/widgets/datatable.js) over one of the
// server's device views, with the view picker, per-phy icons, and row
// highlights.  Clicking a device opens its panel.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as settings from '../core/settings.js';
import { onLogin } from '../core/auth.js';
import { deviceColumns, deviceIcons, rowHighlights, searchFields, alwaysFields } from '../registry/columns.js';
import { deviceViews } from '../registry/devices.js';
import { openDevice } from './detailpanel.js';
import { createDataTable } from './datatable.js';
import { openSettings } from './settingsdialog.js';

export function createDeviceTable(container) {
    let view = settings.get('devicelist.view', 'all');
    let lastViews = null;
    let table = null;

    const viewSelect = el('select', { class: 'view-select', title: 'Which devices to list',
        onchange: () => {
            view = viewSelect.value;
            settings.set('devicelist.view', view);
            table.restart(true);
        } });

    // The server's device views, grouped for the picker
    async function loadViews() {
        let serverViews = [];
        try {
            serverViews = await api.get('devices/views/all_views.json');
        } catch (err) {
            console.error('Could not load device views:', err);
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
            else if (id.startsWith('phy-'))
                addOption('Phy types', id, v['kismet.devices.view.description'] || id.slice(4), count);
            else if (id.startsWith('seenby-'))
                addOption('Data sources', id, v['kismet.devices.view.description'] || id, count);
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

        // All devices at the top, then the groups, each in alphabetical order
        const ordered = [...groups].sort(([a], [b]) => (b === '') - (a === ''));
        for (const [, list] of ordered)
            list.sort((a, b) => (b.id === 'all') - (a.id === 'all') ||
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
    });

    loadViews();
    onLogin(loadViews);
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
