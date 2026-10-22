// Page startup: log in, load the built-in and server-provided modules, then
// build the dashboard.

import { kismet } from './kismet.js';
import { ensureSession } from './core/auth.js';
import { loadServerModules } from './core/modules.js';
import { createRibbon } from './widgets/ribbon.js';
import { createPaneArea } from './widgets/panes.js';
import { createMenu } from './widgets/menu.js';

import * as baseColumns from './base/columns.js';
import * as baseRibbon from './base/ribbon_stats.js';
import * as baseDetails from './base/details.js';
import * as baseMenu from './base/menu.js';
import * as baseSettings from './base/settings.js';
import * as baseSchemes from './base/schemes.js';
import * as baseTables from './base/tables.js';
import * as baseMap from './base/map.js';
import * as baseOverview from './base/overview.js';

const builtins = [baseColumns, baseRibbon, baseDetails, baseMenu, baseSettings, baseTables, baseMap, baseOverview];

function showConnection(up) {
    const status = document.getElementById('connection');
    status.classList.toggle('up', up);
    status.title = up ? 'Connected to the Kismet server' : 'Not connected; retrying';
}

async function loadServerName() {
    try {
        const s = await kismet.api.post('system/status.json', { fields: ['kismet.system.server_name'] });
        const name = s['kismet.system.server_name'];
        if (name) {
            document.getElementById('server-name').textContent = name;
            document.title = `${name} - Kismet`;
        }
    } catch (err) {
        console.error('Could not load the server name:', err);
    }
}

async function start() {
    // Color schemes first, so even the login screen is in the chosen colors
    baseSchemes.register(kismet);
    await ensureSession();

    for (const mod of builtins)
        mod.register(kismet);
    await loadServerModules(kismet);

    kismet.eventbus.onState(showConnection);
    kismet.eventbus.connect();

    createMenu(document.getElementById('menu'));
    createRibbon(document.getElementById('ribbon'));
    createPaneArea(document.getElementById('main'), 'main');
    createPaneArea(document.getElementById('bottom'), 'bottom');
    setupSplit();
    loadServerName();
}

// Drag the bar between the device list and the bottom panes to resize them
function setupSplit() {
    const bar = document.getElementById('split');
    const bottom = document.getElementById('bottom');
    const saved = kismet.settings.get('layout.bottomHeight', null);
    if (saved)
        bottom.style.height = `${saved}px`;

    bar.addEventListener('pointerdown', (e) => {
        bar.setPointerCapture(e.pointerId);
        const startY = e.clientY;
        const startHeight = bottom.offsetHeight;
        const move = (ev) => {
            const h = Math.max(60, Math.min(window.innerHeight * 0.8, startHeight - (ev.clientY - startY)));
            bottom.style.height = `${h}px`;
        };
        const up = () => {
            bar.removeEventListener('pointermove', move);
            kismet.settings.set('layout.bottomHeight', bottom.offsetHeight);
        };
        bar.addEventListener('pointermove', move);
        bar.addEventListener('pointerup', up, { once: true });
    });
}

start().catch((err) => {
    console.error(err);
    document.getElementById('main').textContent = `The UI failed to start: ${err.message}`;
});
