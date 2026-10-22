// The device list: a data table (js/widgets/datatable.js) over one of the
// server's device views, with the view picker, per-phy icons, and row
// highlights.  Clicking a device opens its panel.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as settings from '../core/settings.js';
import { deviceColumns, deviceIcons, rowHighlights, searchFields, alwaysFields } from '../registry/columns.js';
import { deviceViews } from '../registry/devices.js';
import { openDevice } from './detailpanel.js';
import { createDataTable } from './datatable.js';

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
        const addOption = (group, id, title) => {
            if (!groups.has(group))
                groups.set(group, []);
            groups.get(group).push({ id, title });
        };

        for (const v of serverViews) {
            const id = v['kismet.devices.view.id'];
            if (v['kismet.devices.view.indexed'] === false)
                continue;
            const custom = deviceViews.get(id);
            if (custom)
                addOption(custom.group, id, custom.title);
            else if (id === 'all')
                addOption('', id, 'All devices');
            else if (id.startsWith('phy-'))
                addOption('Phy types', id, v['kismet.devices.view.description'] || id.slice(4));
            else if (id.startsWith('seenby-'))
                addOption('Data sources', id, v['kismet.devices.view.description'] || id);
            else
                addOption('Other', id, v['kismet.devices.view.description'] || id);
        }

        if (!groups.size)
            addOption('', 'all', 'All devices');

        // Rebuilding the menu closes it, so leave it alone while it's open or unchanged
        const signature = JSON.stringify([...groups]);
        if (signature === lastViews || document.activeElement === viewSelect)
            return;
        lastViews = signature;

        const options = [];
        for (const [group, list] of groups) {
            const opts = list.map((o) => el('option', { value: o.id }, o.title));
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
        searchFields,
        alwaysFields,
        rowKey: (row) => row['kismet.device.base.key'],
        onRowClick: (row) => openDevice(row.key),
        defaultSort: { column: 'last_time', dir: 'desc' },
        noun: 'devices',
        toolbar: () => viewSelect,
    });

    loadViews();
    // Views come and go with datasources and phys
    setInterval(() => {
        if (document.visibilityState !== 'hidden')
            loadViews();
    }, 30000);

    return table;
}
