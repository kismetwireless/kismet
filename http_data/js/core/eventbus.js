// The Kismet event bus: one websocket that carries live events from the
// server (timestamps, stats, messages, alerts, new devices, ...).
//
//   const stop = eventbus.subscribe('TIMESTAMP', ['kismet.system.timestamp.sec'],
//       (event) => console.log(event['kismet.system.timestamp.sec']));
//   stop();   // unsubscribe
//
// Handlers also get the whole message as a second argument, for the few
// topics that send more than one record (e.g. DOT11_ADVERTISED_SSID).
//
// Many parts of the UI can subscribe to the same topic; the server gets one
// subscription per topic, asking for the fields everyone wants combined.
// If the connection drops it reconnects and re-subscribes on its own.

import * as api from './api.js';
import * as censor from './censor.js';

const topics = new Map();         // topic -> { subscribers: Set, sentFields }
const stateListeners = new Set();
let socket = null;
let connected = false;
let retryDelay = 500;

// fields is a list of field paths inside the event (or [path, name] pairs to
// rename them), or null for the whole event.
export function subscribe(topic, fields, fn) {
    if (!topics.has(topic))
        topics.set(topic, { subscribers: new Set(), sentFields: undefined });

    const sub = { fields: fields?.length ? fields : null, fn };
    topics.get(topic).subscribers.add(sub);
    sync(topic);

    return () => {
        const t = topics.get(topic);
        if (!t)
            return;
        t.subscribers.delete(sub);
        sync(topic);
    };
}

export function isConnected() {
    return connected;
}

// Call fn(connected) when the websocket connects or drops
export function onState(fn) {
    stateListeners.add(fn);
    return () => stateListeners.delete(fn);
}

export function connect() {
    if (socket)
        return;

    socket = new WebSocket(api.wsUrl('eventbus/events.ws'));

    socket.addEventListener('open', () => {
        retryDelay = 500;
        setConnected(true);
        for (const [topic, t] of topics) {
            t.sentFields = undefined;
            sync(topic);
        }
    });

    socket.addEventListener('message', (msg) => dispatch(msg.data));

    socket.addEventListener('close', () => {
        socket = null;
        setConnected(false);
        setTimeout(connect, retryDelay);
        retryDelay = Math.min(retryDelay * 2, 10000);
    });
}

function setConnected(state) {
    if (connected === state)
        return;
    connected = state;
    for (const fn of stateListeners)
        fn(state);
}

// The field list to request for a topic: null (everything) if any subscriber
// wants everything, otherwise every subscriber's fields combined.
function wantedFields(t) {
    const all = new Map();
    for (const sub of t.subscribers) {
        if (sub.fields === null)
            return null;
        for (const f of sub.fields) {
            const [path, name] = Array.isArray(f) ? f : [f, f.split('/').pop()];
            all.set(name, path);
        }
    }
    return all;
}

// Tell the server what we want for a topic, if that changed
function sync(topic) {
    const t = topics.get(topic);

    if (t.subscribers.size === 0) {
        topics.delete(topic);
        send({ UNSUBSCRIBE: topic });
        return;
    }

    const wanted = wantedFields(t);
    const key = wanted === null ? null : JSON.stringify([...wanted]);
    if (key === t.sentFields)
        return;

    const request = { SUBSCRIBE: topic };
    if (wanted !== null)
        request.fields = [...wanted].map(([name, path]) => (name === path ? path : [path, name]));

    if (send(request))
        t.sentFields = key;
}

function send(obj) {
    if (!socket || socket.readyState !== WebSocket.OPEN)
        return false;
    socket.send(JSON.stringify(obj));
    return true;
}

function dispatch(text) {
    let msg;
    try {
        msg = JSON.parse(text);
    } catch {
        return;
    }
    if (msg === null || typeof msg !== 'object')
        return;
    censor.learn(msg);

    // Messages are { TOPIC: event }, with only the requested fields in the
    // event when the subscription asked for some
    const events = Object.entries(msg);

    for (const [topic, event] of events) {
        const t = topics.get(topic);
        if (!t)
            continue;
        for (const sub of t.subscribers) {
            try {
                sub.fn(event, msg);
            } catch (err) {
                console.error(`eventbus ${topic} handler failed:`, err);
            }
        }
    }
}
