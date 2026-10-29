// Data source commands, for the Data sources window and modules that add
// controls to it.
//
//   await sources.lock(uuid, '6');
//   await sources.hop(uuid, ['1', '6', '11'], 5);
//   await sources.reopenWith(uuid, { mask: 'full' });
//
// Each resolves with the source as the server reports it afterwards, when
// the server sends it back, and throws ApiError with the server's reason when
// it refuses.  Some refusals (a channel the driver turned down) only give
// their reason in the server's messages; the error says so.

import * as api from './api.js';

const base = (uuid) => `datasource/by-uuid/${encodeURIComponent(uuid)}`;

// The .cmd routes answer with the source record, or with text
function parse(text) {
    try {
        const v = JSON.parse(text);
        return v && typeof v === 'object' && v['kismet.datasource.uuid'] ? v : null;
    } catch {
        return null;
    }
}

async function cmd(path, json = null, options = {}) {
    const body = new URLSearchParams();
    if (json !== null)
        body.set('json', JSON.stringify(json));
    try {
        const r = await api.probe(path, { method: 'POST', ...api.formBody(body), timeout: options.timeout ?? 30000 });
        const text = await r.text();
        if (!r.ok) {
            const why = text.trim() && text.trim() !== '{}' ? text.trim() :
                `the server refused (HTTP ${r.status}); the reason is in Messages`;
            throw new api.ApiError(r.status, why);
        }
        return parse(text);
    } catch (err) {
        if (err.name === 'TimeoutError')
            throw new api.ApiError(0, 'no answer from the server in time');
        throw err;
    }
}

export const list = (fields = null) => api.post('datasource/all_sources.json', fields ? { fields } : null);
export const interfaces = () => api.get('datasource/list_interfaces.json', { timeout: 30000 });

export const add = (definition) => cmd('datasource/add_source.cmd', { definition }, { timeout: 120000 });
export const open = (uuid) => cmd(`${base(uuid)}/open_source.cmd`, null, { timeout: 120000 });
export const close = (uuid) => cmd(`${base(uuid)}/close_source.cmd`);
export const disable = (uuid) => cmd(`${base(uuid)}/disable_source.cmd`);
export const pause = (uuid) => cmd(`${base(uuid)}/pause_source.cmd`);
export const resume = (uuid) => cmd(`${base(uuid)}/resume_source.cmd`);

export const lock = (uuid, channel) => cmd(`${base(uuid)}/set_channel.cmd`, { channel });

// rate in hops per second; leave channels or rate null to keep the source's own
export function hop(uuid, channels = null, rate = null) {
    const json = {};
    if (channels)
        json.channels = channels;
    if (rate !== null)
        json.rate = rate;
    return cmd(`${base(uuid)}/set_channel.cmd`, json);
}

// A driver setting sent through the channel route ("strategy=walking" on a
// cell modem, say), which some helpers read as runtime settings
export const setting = (uuid, value) => cmd(`${base(uuid)}/set_channel.cmd`, { channel: value });

// Re-open a source with changed bring-up options.  The server only changes a
// closed source's definition, so this closes it first, and re-opens it even
// when the change is refused, so the source is never left down.
export async function reopenWith(uuid, options) {
    await close(uuid);
    let failure = null;
    try {
        await cmd(`${base(uuid)}/update_definition.cmd`, { options });
    } catch (err) {
        failure = err;
    }
    const reopened = await open(uuid);
    if (failure)
        throw failure;
    return reopened;
}

// Close, then open once the close has answered, so a helper is never
// re-opened while it's still shutting down
export async function restart(uuid) {
    await close(uuid);
    return open(uuid);
}

// Hop rates: hops per second <-> what reads best ([value, 'sec'|'min'|'dwell'])
export function rateText(rate) {
    if (!(rate > 0))
        return 'not hopping';
    if (rate >= 1)
        return `${+rate.toFixed(2)} per second`;
    if (rate * 60 >= 1)
        return `${+(rate * 60).toFixed(2)} per minute`;
    return `every ${+(1 / rate).toFixed(2)} seconds`;
}

export function rateToInput(rate) {
    if (rate >= 1)
        return [+rate.toFixed(2), 'sec'];
    if (rate * 60 >= 1)
        return [+(rate * 60).toFixed(2), 'min'];
    return [+(1 / rate).toFixed(2), 'dwell'];
}

export function inputToRate(value, unit) {
    const v = parseFloat(value);
    if (!Number.isFinite(v) || v <= 0)
        return NaN;
    return { sec: v, min: v / 60, dwell: 1 / v }[unit] ?? NaN;
}
