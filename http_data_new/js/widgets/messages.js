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

export function createMessages(container) {
    const list = el('ol', { class: 'messages' });
    container.append(list);

    function add(m, top = true) {
        const row = messageRow(m);
        if (top)
            list.prepend(row);
        else
            list.append(row);
        while (list.childElementCount > keep)
            list.lastElementChild.remove();
    }

    let stop = null;
    const outline = loading.overlay(container, { kind: 'log', rows: 10 }, { label: 'Loading messages', className: 'sk-pane-layer' });

    api.get('messagebus/last-time/0/messages.json')
        .then((r) => {
            const backlog = r['kismet.messagebus.list'] ?? [];
            backlog.sort((a, b) => b['kismet.messagebus.message_time'] - a['kismet.messagebus.message_time']);
            backlog.slice(0, keep).forEach((m) => add(m, false));
        })
        .catch((err) => add({
            'kismet.messagebus.message_string': `Could not load messages: ${err.message}`,
            'kismet.messagebus.message_flags': 4,
            'kismet.messagebus.message_time': Date.now() / 1000,
        }))
        .finally(() => {
            outline.done();
            stop = eventbus.subscribe('MESSAGE', null, (event) => add(event));
        });

    return { destroy: () => stop?.() };
}
