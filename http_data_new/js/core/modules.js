// Loading UI modules the server asks for.
//
// The server lists the UI modules for its phys and plugins at /dynamic.json:
//   { "build": "<token>",
//     "dynamicjs": [ { "module": "kismet_ui_dot11", "js": "js/kismet.ui.dot11.js" }, ... ] }
//
// Entries with a "ui2" path are modules for this UI and are loaded from there.
// Entries without one are for the old UI; for the phys this UI already has a
// module for, that module is loaded instead, and the rest are skipped.
//
// The build token changes with the server's build and modules; the service
// worker uses it to know when its copies of the UI and of the server's plugin
// modules are stale (js/core/pwa.js).  Servers older than the token still
// work, their plugin modules fetched fresh each time.
//
// Plugin modules from a server other than the one the UI came from run with
// this app's keys for every server, so they only load once allowed for that
// server in the Servers window.
//
// Each module exports register(kismet).  Modules load in parallel, and one that
// fails to load doesn't stop the others or the page.

import * as api from './api.js';
import * as pwa from './pwa.js';
import * as eventbus from './eventbus.js';

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

// The server's build token, once the module list has loaded (null from older servers)
export let build = null;
let pluginHrefs = [];
let lastCheck = 0;
let offered = null;

export async function loadServerModules(kismet) {
    let info = null;
    try {
        info = await api.get('dynamic.json');
    } catch (err) {
        console.error('Could not get the module list from the server:', err);
    }

    const list = Array.isArray(info?.dynamicjs) ? info.dynamicjs : [];
    build = typeof info?.build === 'string' ? info.build : null;
    const trusted = !api.remote || api.remote.trustPlugins === true;

    const plugins = [];
    const builtins = [];
    for (const entry of list) {
        const ui2 = typeof entry.ui2 === 'string' ? api.url(entry.ui2) : null;
        if (ui2 && ui2.origin === api.root.origin && trusted)
            plugins.push([entry.module, ui2.href]);
        else if (builtin[entry.module])
            builtins.push([entry.module, new URL(builtin[entry.module], new URL('..', import.meta.url)).href]);
        else if (ui2 && ui2.origin === api.root.origin)
            skipped.push({ name: entry.module, reason: 'plugin UI from another server; allow it in Servers' });
        else
            skipped.push({ name: entry.module, reason: ui2 ? 'module on another site' : 'no module for this UI yet' });
    }

    // Bring the kept copies up to date first, so the modules load from them
    pluginHrefs = plugins.map(([, href]) => href);
    lastCheck = Date.now();
    if (info)
        await pwa.syncServer({ root: api.root.href, build, home: !api.remote, modules: pluginHrefs });
    watchForUpdates();

    await Promise.all([...builtins, ...plugins].map(([name, href]) => loadOne(name, href, kismet)));
}

// An installed app is resumed rather than reloaded, so look for a new server
// build again when it comes back into view, or the server comes back
async function recheck() {
    if (build === null || Date.now() - lastCheck < 5000)
        return;
    lastCheck = Date.now();
    let info;
    try {
        info = await api.get('dynamic.json');
    } catch {
        return;
    }
    if (typeof info?.build !== 'string' || info.build === build || info.build === offered)
        return;
    const result = await pwa.syncServer({ root: api.root.href, build: info.build, home: !api.remote, modules: pluginHrefs });
    // The modules running now are the old ones, whatever the worker kept
    if (!result.stale) {
        offered = info.build;
        pwa.showUpdated();
    }
}

let watching = false;

function watchForUpdates() {
    if (watching)
        return;
    watching = true;
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible')
            recheck();
    });
    eventbus.onState((up) => {
        if (up)
            recheck();
    });
}
