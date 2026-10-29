// Loading UI modules the server asks for.
//
// The server lists the UI modules for its phys and plugins at /dynamic.json:
//   { "dynamicjs": [ { "module": "kismet_ui_dot11", "js": "js/kismet.ui.dot11.js" }, ... ] }
//
// Entries with a "ui2" path are modules for this UI and are loaded from there.
// Entries without one are for the old UI; for the phys this UI already has a
// module for, that module is loaded instead, and the rest are skipped.
//
// Each module exports register(kismet).  Modules load in parallel, and one that
// fails to load doesn't stop the others or the page.

import * as api from './api.js';

const builtin = {
    kismet_ui_dot11: './phy/dot11.js',
    kismet_ui_bluetooth: './phy/bluetooth.js',
    kismet_ui_btle: './phy/btle.js',
    kismet_ui_802_15_4: './phy/802154.js',
    kismet_ui_ais: './phy/ais.js',
    kismet_ui_adsb: './phy/adsb.js',
    kismet_ui_uav: './phy/uav.js',
    kismet_ui_sensor: './phy/sensor.js',
    kismet_ui_meter: './phy/meter.js',
    kismet_ui_meshtastic: './phy/meshtastic.js',
    kismet_ui_meshcore: './phy/meshcore.js',
    kismet_ui_zwave: './phy/zwave.js',
    kismet_ui_cell: './phy/cell.js',
};

export const loaded = [];
export const skipped = [];

async function loadOne(name, src, kismet) {
    try {
        const mod = await import(src);
        if (typeof mod.register !== 'function')
            throw new Error('module has no register() function');
        await mod.register(kismet);
        loaded.push(name);
    } catch (err) {
        console.error(`UI module ${name} (${src}) failed:`, err);
        skipped.push({ name, reason: err.message });
    }
}

export async function loadServerModules(kismet) {
    let list = [];
    try {
        list = (await api.get('dynamic.json')).dynamicjs ?? [];
    } catch (err) {
        console.error('Could not get the module list from the server:', err);
    }

    const jobs = [];
    for (const entry of list) {
        // Only ever load code from the Kismet server itself
        if (entry.ui2 && api.url(entry.ui2).origin === api.root.origin)
            jobs.push(loadOne(entry.module, api.url(entry.ui2).href, kismet));
        else if (builtin[entry.module])
            jobs.push(loadOne(entry.module, new URL(builtin[entry.module], new URL('..', import.meta.url)).href, kismet));
        else
            skipped.push({ name: entry.module, reason: 'no module for this UI yet' });
    }

    await Promise.all(jobs);
}
