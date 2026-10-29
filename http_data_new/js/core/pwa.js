// Running as an installed app: the service worker, and the browser's color
// for the status bar.
//
// Browsers only allow service workers on https:// or localhost, so over plain
// http the UI works as before, just not installable on most phones.

import { el } from './dom.js';

let registration = null;

// The browser's install prompt (Chrome, Edge, Samsung Internet), held until
// the user asks to install; Safari and Firefox don't have one
let installPrompt = null;
const installListeners = new Set();

function installChanged() {
    for (const fn of installListeners)
        fn();
}

window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    installPrompt = e;
    installChanged();
});

window.addEventListener('appinstalled', () => {
    installPrompt = null;
    installChanged();
});

export function canInstall() {
    return installPrompt !== null;
}

// Show the browser's install prompt; resolves 'accepted' or 'dismissed'
export async function install() {
    const p = installPrompt;
    if (!p)
        return 'dismissed';
    installPrompt = null;
    await p.prompt();
    const { outcome } = await p.userChoice;
    installChanged();
    return outcome;
}

// Call fn() when installing becomes possible or the app is installed
export function onInstallChange(fn) {
    installListeners.add(fn);
    return () => installListeners.delete(fn);
}

export function start(theme) {
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
        const update = () => {
            const bar = document.querySelector('.topbar') ?? document.body;
            meta.content = getComputedStyle(bar).backgroundColor;
        };
        theme.onChange(update);
        update();
    }

    if (window.isSecureContext && 'serviceWorker' in navigator) {
        registration = navigator.serviceWorker.register(new URL('../../sw.js', import.meta.url),
            { scope: new URL('../../', import.meta.url).pathname })
            .catch((err) => {
                console.warn('Could not start the service worker; the UI works, but cannot be installed:', err);
                return null;
            });
    }
}

// Tell the service worker a server's build token and plugin modules, so it
// refreshes its copies when the server has changed.  Resolves once the copies
// are up to date (or after a few seconds, so a slow worker never holds up the UI).
export async function syncServer({ root, build, home, modules }) {
    if (!registration || typeof build !== 'string')
        return {};
    const reg = await registration;
    const worker = navigator.serviceWorker.controller ?? reg?.active;
    if (!worker)
        return {};

    const reply = new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (e) => resolve(e.data ?? {});
        worker.postMessage({ type: 'server', root, build, home, modules }, [channel.port2]);
    });
    const timeout = new Promise((resolve) => setTimeout(() => resolve({}), 8000));
    const result = await Promise.race([reply, timeout]);

    if (result.shellUpdated)
        showUpdated();
    return result;
}

// Offer to reload for a new version of the UI
export function showUpdated() {
    if (document.querySelector('.update-notice'))
        return;
    // An open modal dialog makes the rest of the page inert and covers it, so
    // the notice moves into the front modal while one is open
    const place = () => {
        const modals = document.querySelectorAll('dialog.modal[open]');
        const host = modals.length ? modals[modals.length - 1] : document.body;
        if (notice.parentNode !== host)
            host.append(notice);
    };
    const watch = new MutationObserver(place);

    const notice = el('div', { class: 'update-notice', role: 'status' },
        el('span', {}, 'Kismet was updated on the server.'),
        el('button', { type: 'button', class: 'primary', onclick: () => location.reload() }, 'Reload'),
        el('button', { type: 'button', onclick: () => { watch.disconnect(); notice.remove(); } }, 'Later'));

    place();
    watch.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['open'] });
}
