// The device panel, opened by clicking a device.
//
// Its sections come from kismet.ui.deviceDetails, and any module can add
// rows to any section through kismet.ui.deviceDetailFields.  The device is
// loaded once, then kept current over the device monitor websocket, which
// sends it again when it changes; the panel also redraws every second, so
// times ("4s ago") and history graphs keep moving for quiet devices.
// Sections update in place, so the scroll position, open groups, graphs, and
// edits survive the updates.

const redrawSeconds = 1;

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as censor from '../core/censor.js';
import * as settings from '../core/settings.js';
import { deviceDetails, deviceDetailFields } from '../registry/devices.js';
import { detailSections } from './detailsections.js';
import { dialog } from './dialog.js';

const open = new Map();     // device key -> panel

// A section's rows: its own, with rows other modules added slotted in by priority
function sectionFields(section) {
    const own = (section.fields ?? []).map((f, i) => ({ priority: i * 10, entry: f, order: 0 }));
    const added = deviceDetailFields.list()
        .filter((f) => f.section === section.id)
        .map((f) => ({ priority: f.priority, entry: f, order: 1 }));
    return [...own, ...added]
        .sort((a, b) => a.priority - b.priority || a.order - b.order)
        .map((x) => x.entry);
}

export function openDevice(key) {
    if (!key)
        return;

    if (open.has(key)) {
        open.get(key).focus();
        return;
    }

    const sections = detailSections({ closed: 'detail.closed', what: 'device' });
    const subtitle = el('div', { class: 'detail-subtitle muted' });
    let socket = null;
    let closed = false;
    let last = null;

    // Open where the user last put a panel, each further one a little offset
    const saved = settings.get('detail.position', null);
    const offset = open.size * 24;
    const d = dialog({
        title: 'Device',
        body: el('div', {}, subtitle, sections.node),
        modal: false,
        className: 'detail-panel',
        position: saved ? { ...saved, left: saved.left + offset, top: saved.top + offset } : null,
        onMove: (pos) => settings.set('detail.position', pos),
        onClose: () => {
            closed = true;
            open.delete(key);
            socket?.close();
            clearInterval(ticker);
            stopWatching();
        },
    });

    open.set(key, { focus: () => d.node.querySelector('button')?.focus() });

    function render(device) {
        last = device;
        // Nothing below should move the view, but keep it put regardless
        const scrollTop = d.body.scrollTop;
        const base = 'kismet.device.base';
        d.setTitle(device[`${base}.username`] || device[`${base}.commonname`] || device[`${base}.macaddr`] || 'Device');
        subtitle.textContent = [device[`${base}.phyname`], device[`${base}.type`], device[`${base}.macaddr`]]
            .filter(Boolean).join(' · ');

        sections.render(device, deviceDetails.list(), sectionFields);

        if (d.body.scrollTop !== scrollTop)
            d.body.scrollTop = scrollTop;
    }

    const ticker = setInterval(() => {
        if (last && document.visibilityState !== 'hidden')
            render(last);
    }, redrawSeconds * 1000);

    // Sections and rows added after the panel opened show up on the next draw
    const redraw = () => last && render(last);
    const stops = [deviceDetails.watch(redraw), deviceDetailFields.watch(redraw)];
    const stopWatching = () => stops.forEach((s) => s());

    function watch() {
        if (closed)
            return;
        socket = new WebSocket(api.wsUrl('devices/monitor.ws'));
        socket.addEventListener('open', () => {
            socket.send(JSON.stringify({ monitor: key, request: 1, rate: 1, format: 'json' }));
        });
        socket.addEventListener('message', (msg) => {
            try {
                render(censor.learn(JSON.parse(msg.data)));
            } catch (err) {
                console.error('device update failed:', err);
            }
        });
        socket.addEventListener('close', () => {
            if (!closed)
                setTimeout(watch, 2000);
        });
    }

    api.get(`devices/by-key/${encodeURIComponent(key)}/device.json`)
        .then((device) => {
            if (closed)
                return;
            render(device);
            watch();
        })
        .catch((err) => {
            sections.node.replaceChildren(el('p', { class: 'form-error' }, `Could not load the device: ${err.message}`));
        });
}
