// Linked records: a Wi-Fi record and an Ethernet record of one device, which
// the server links by their shared MAC address (an entity).
//
//   entities.linked(device)        the reply of /entities/by-device/KEY/linked.json:
//                                  { 'kismet.entity.entity_id', 'kismet.entity.edges': [...] },
//                                  or undefined until it's been read, or null when
//                                  the server doesn't link records
//   entities.peer(device, phyname) the first linked record of that phy and its link,
//                                  { record, edge }, or null
//   entities.status()              the last /entities/status.json, read again when
//                                  it's older than statusSeconds; null when the
//                                  server has none (or before the first read)
//   entities.refreshStatus()       read the status now: a promise of the reply, or
//                                  null when the server has none
//   entities.supported()           false once the server answered that it has no
//                                  entity endpoints
//
// The device panel draws every second, so a section can call these from
// match() and render(): a read starts when the kept reply is too old, and the
// next draw shows it.  Links are read every few seconds while a record is
// linked, less often while it isn't.
//
// They're meant for open device panels and windows, not for every row of a
// device list or table: only the last 64 records are kept, and each one asks
// the server on its own.  Replies are shared by every caller, so treat them as
// read-only; copy before sorting or changing them.

import * as api from './api.js';

const linkedSeconds = 5;
const unlinkedSeconds = 30;
// The settings in it rarely change; views that show its counters read it with refreshStatus()
const statusSeconds = 60;
const keep = 64;

const base = 'kismet.device.base';
const cache = new Map();        // device key -> { at, reply, pending }
let gone = false;               // the server has no entity endpoints
let statusAt = 0;
let statusReply = null;
let statusPending = false;

const hasEdges = (reply) => Array.isArray(reply?.['kismet.entity.edges']) && reply['kismet.entity.edges'].length > 0;

async function read(key, entry) {
    entry.pending = true;
    try {
        const reply = await api.get(`entities/by-device/${encodeURIComponent(key)}/linked.json`);
        entry.reply = reply && typeof reply === 'object' ? reply : { 'kismet.entity.edges': [] };
    } catch (err) {
        if (err.status === 404)
            gone = true;
        // A bad key gets no links; other failures keep the last reply
        else if (err.status === 400)
            entry.reply = { 'kismet.entity.edges': [] };
    }
    entry.at = Date.now();
    entry.pending = false;
}

export function linked(device) {
    const key = device?.[`${base}.key`];
    if (gone || typeof key !== 'string' || key === '')
        return gone ? null : undefined;

    let entry = cache.get(key);
    if (entry) {
        // Most recently used last, so the oldest go first
        cache.delete(key);
        cache.set(key, entry);
    } else {
        // Nothing to ask about when the server says it isn't linking and the record isn't linked
        if (statusReply && !statusReply['kismet.entity.status.enabled'] && device[`${base}.entity_id`] === undefined)
            return { 'kismet.entity.edges': [] };
        entry = { at: 0, reply: undefined, pending: false };
        cache.set(key, entry);
        while (cache.size > keep)
            cache.delete(cache.keys().next().value);
    }

    const age = linkedRecord(device, entry.reply) ? linkedSeconds : unlinkedSeconds;
    if (!entry.pending && Date.now() - entry.at > age * 1000)
        read(key, entry);
    return entry.reply;
}

const linkedRecord = (device, reply) => device[`${base}.entity_id`] !== undefined || hasEdges(reply);

// The first linked record of a phy, with its link: { record, edge }, or null
export function peer(device, phyname) {
    const reply = linked(device);
    for (const edge of reply?.['kismet.entity.edges'] ?? []) {
        const p = edge?.['kismet.entity.edge.peer'];
        const record = Array.isArray(p) ? p[0] : null;
        if (record && typeof record === 'object' && record[`${base}.phyname`] === phyname)
            return { record, edge };
    }
    return null;
}

async function readStatus() {
    statusPending = true;
    try {
        statusReply = await api.get('entities/status.json');
    } catch (err) {
        if (err.status === 404) {
            gone = true;
            statusReply = null;
        }
    }
    statusAt = Date.now();
    statusPending = false;
}

export function status() {
    if (!gone && !statusPending && Date.now() - statusAt > statusSeconds * 1000)
        readStatus();
    return gone ? null : statusReply;
}

// Read the status now, for a view that has just opened
export async function refreshStatus() {
    if (gone)
        return null;
    if (!statusPending)
        await readStatus();
    return statusReply;
}

export const supported = () => !gone;
