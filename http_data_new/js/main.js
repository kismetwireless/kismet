// Page startup: log in, load the built-in and server-provided modules, then
// build the dashboard.

import { kismet } from './kismet.js';
import { ensureSession } from './core/auth.js';
import * as api from './core/api.js';
import { ApiError } from './core/api.js';
import * as servers from './core/servers.js';
import { el } from './core/dom.js';
import { openServers } from './widgets/serversdialog.js';
import { loadServerModules } from './core/modules.js';
import { createRibbon } from './widgets/ribbon.js';
import { createPaneArea } from './widgets/panes.js';
import { createMenu } from './widgets/menu.js';
import * as loading from './widgets/loading.js';
import * as pwa from './core/pwa.js';

import * as baseColumns from './base/columns.js';
import * as baseRibbon from './base/ribbon_stats.js';
import * as baseDetails from './base/details.js';
import * as baseMenu from './base/menu.js';
import * as baseSettings from './base/settings.js';
import * as baseInstall from './base/install.js';
import * as baseSchemes from './base/schemes.js';
import * as baseTables from './base/tables.js';
import * as baseMap from './base/map.js';
import * as baseOverview from './base/overview.js';
import * as baseSources from './base/sources.js';
import * as baseInsights from './base/insights.js';

const builtins = [baseColumns, baseRibbon, baseDetails, baseMenu, baseSettings, baseInstall, baseTables, baseMap, baseOverview, baseSources, baseInsights];

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

// Log in, waiting for the server if it can't be reached: an installed app can
// open before the phone is on the server's network
async function reachServer(outline) {
    const wait = (ms) => new Promise((resolve) => {
        const done = () => {
            clearTimeout(timer);
            window.removeEventListener('online', done);
            document.removeEventListener('visibilitychange', visible);
            resolve();
        };
        const visible = () => {
            if (document.visibilityState === 'visible')
                done();
        };
        const timer = setTimeout(done, ms);
        window.addEventListener('online', done);
        document.addEventListener('visibilitychange', visible);
    });

    for (let delay = 2000; ; delay = Math.min(delay * 2, 30000)) {
        try {
            await ensureSession();
            outline.retry();
            return;
        } catch (err) {
            if (!(err instanceof ApiError) || err.status !== 0)
                throw err;
            outline.error(api.remote ? `can't reach ${api.remote.name}` : "can't reach the Kismet server");
            if ((servers.installed() || api.remote) && !outline.node.querySelector('.sk-switch'))
                outline.node.querySelector('.sk-message').after(el('button', { type: 'button', class: 'sk-switch', onclick: () => openServers() }, 'Switch server'));
            await wait(delay);
        }
    }
}

// Full-window panes and docked panels keep the menu and name above them.  On a
// narrow window the stats ribbon wraps to a row of its own, which a full-window
// pane covers; otherwise they start below the whole top bar.
function trackTopbar() {
    const bar = document.querySelector('.topbar');
    const ribbon = document.getElementById('ribbon');
    const head = [document.getElementById('menu'), bar?.querySelector('.brand')].filter(Boolean);
    if (!bar || !ribbon)
        return;
    const set = () => {
        const all = Math.ceil(bar.getBoundingClientRect().bottom);
        const r = ribbon.getBoundingClientRect();
        // Wrapped when the ribbon starts below the middle of the menu and name
        const middle = Math.max(...head.map((e) => { const b = e.getBoundingClientRect(); return (b.top + b.bottom) / 2; }));
        document.documentElement.style.setProperty('--topbar-bottom', `${all}px`);
        document.documentElement.style.setProperty('--pane-top', `${r.height > 0 && r.top > middle ? Math.floor(r.top) : all}px`);
    };
    new ResizeObserver(set).observe(bar, { box: 'border-box' });
    set();
}

async function start() {
    trackTopbar();
    // Color schemes first, so even the login screen is in the chosen colors
    baseSchemes.register(kismet);
    pwa.start(kismet.theme);
    // Outlines of the panels while logging in and loading modules, which
    // can take a while on a slow link
    const mainOutline = loading.overlay(document.getElementById('main'),
        ['tabs', { kind: 'table', rows: 14, columns: 6 }], { label: 'Starting', className: 'sk-pane-layer' });
    const bottomOutline = loading.overlay(document.getElementById('bottom'),
        ['tabs', { kind: 'log', rows: 6 }], { label: 'Starting', className: 'sk-pane-layer' });
    await reachServer(mainOutline);

    for (const mod of builtins)
        mod.register(kismet);
    await loadServerModules(kismet);

    kismet.eventbus.onState(showConnection);
    kismet.eventbus.connect();

    createMenu(document.getElementById('menu'));
    createRibbon(document.getElementById('ribbon'));
    createPaneArea(document.getElementById('main'), 'main');
    createPaneArea(document.getElementById('bottom'), 'bottom');
    mainOutline.done();
    bottomOutline.done();
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
