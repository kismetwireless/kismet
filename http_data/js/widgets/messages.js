// The server's messages (startup notes, datasource errors, alerts...),
// newest first.  Loads what the server has kept, then follows new ones live.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as eventbus from '../core/eventbus.js';
import * as format from '../core/format.js';
import * as loading from './loading.js';

const keep = 250;

// Message flags from messagebus.h
const flagClasses = [
    [16, 'fatal'],
    [4, 'error'],
    [8, 'alert'],
    [1, 'debug'],
];

function levelOf(flags) {
    for (const [bit, name] of flagClasses)
        if (flags & bit)
            return name;
    return 'info';
}

function messageRow(m) {
    const flags = m['kismet.messagebus.message_flags'] ?? 0;
    return el('li', { class: `message level-${levelOf(flags)}` },
        el('time', {}, format.time(m['kismet.messagebus.message_time'])),
        el('span', { class: 'message-text' }, m['kismet.messagebus.message_string'] ?? ''));
}

const retrySeconds = [2, 5, 10];

// The same message from the backlog and from the live feed shows once
const keyOf = (m) => `${m['kismet.messagebus.message_time']}\u0000${m['kismet.messagebus.message_flags']}\u0000` +
    `${m['kismet.messagebus.message_string']}`;
const timeOf = (m) => m['kismet.messagebus.message_time'] ?? 0;

export function createMessages(container) {
    const list = el('ol', { class: 'messages' });
    // Below the live messages while the earlier ones are still loading
    const note = el('div', { class: 'messages-note muted', hidden: true });
    container.append(list, note);

    const shown = [];       // newest first, with their rows
    const seen = new Set();

    function add(m) {
        const key = keyOf(m);
        if (seen.has(key))
            return;
        seen.add(key);
        const item = { m, key, row: messageRow(m) };
        // Usually the newest; a backlog message goes in its place by time
        let at = 0;
        while (at < shown.length && timeOf(shown[at].m) > timeOf(m))
            at++;
        shown.splice(at, 0, item);
        if (at < shown.length - 1)
            list.insertBefore(item.row, shown[at + 1].row);
        else
            list.append(item.row);
        while (shown.length > keep) {
            const old = shown.pop();
            old.row.remove();
            seen.delete(old.key);
        }
        // Live messages have started; show them, and say the rest is coming
        if (!loaded) {
            outline.done();
            note.hidden = false;
        }
    }

    const outline = loading.overlay(container, { kind: 'log', rows: 10 }, { label: 'Loading messages', className: 'sk-pane-layer' });
    let loaded = false;
    let attempt = 0;
    let timer = null;
    let inFlight = false;

    // The messages the server has kept, tried again until they load
    async function loadBacklog() {
        clearTimeout(timer);
        timer = null;
        if (loaded || inFlight)
            return;
        inFlight = true;
        try {
            const r = await api.get('messagebus/last-time/0/messages.json');
            const backlog = r['kismet.messagebus.list'] ?? [];
            backlog.sort((a, b) => timeOf(b) - timeOf(a));
            loaded = true;
            outline.done();
            note.hidden = true;
            backlog.slice(0, keep).forEach(add);
        } catch (err) {
            const wait = retrySeconds[Math.min(attempt++, retrySeconds.length - 1)];
            outline.error(err.message);
            note.textContent = `Earlier messages couldn't be loaded (${err.message}); trying again…`;
            timer = setTimeout(loadBacklog, wait * 1000);
        } finally {
            inFlight = false;
        }
    }

    const stop = eventbus.subscribe('MESSAGE', null, (event) => add(event));
    // Back in touch with the server: try straight away
    const stopState = eventbus.onState((up) => {
        if (up && !loaded) {
            attempt = 0;
            loadBacklog();
        }
    });
    note.textContent = 'Loading earlier messages…';
    loadBacklog();

    return {
        destroy() {
            stop();
            stopState();
            clearTimeout(timer);
        },
    };
}
