// Running as an installed app: the service worker, and the browser's color
// for the status bar.
//
// Browsers only allow service workers on https:// or localhost, so over plain
// http the UI works as before, just not installable on most phones.

import { el } from './dom.js';

let registration = null;

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

function showUpdated() {
    if (document.querySelector('.update-notice'))
        return;
    const notice = el('div', { class: 'update-notice', role: 'status' },
        el('span', {}, 'Kismet was updated on the server.'),
        el('button', { type: 'button', class: 'primary', onclick: () => location.reload() }, 'Reload'),
        el('button', { type: 'button', onclick: () => notice.remove() }, 'Later'));
    document.body.append(notice);
}
