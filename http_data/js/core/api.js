// Talking to the Kismet server over HTTP.
//
//   const status = await api.get('system/status.json');
//   const page = await api.post('devices/views/all/devices.json',
//       { fields: [...] }, { page: 0, length: 50 });
//
// Paths are relative to the Kismet server root, set by the
// <meta name="kismet-root"> tag in index.html, so the UI works behind a
// reverse proxy or from a sub-directory.  The installed app can use another
// server instead (js/core/servers.js), with its API key as a bearer token.

import * as servers from './servers.js';

const server = servers.current();
export const root = server ? new URL(server.url) : servers.home;
export const remote = server;

export class ApiError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

const authListeners = new Set();

// Call fn() when the server says we're not logged in (HTTP 401)
export function onAuthRequired(fn) {
    authListeners.add(fn);
    return () => authListeners.delete(fn);
}

export function url(path) {
    return new URL(path.replace(/^\/+/, ''), root);
}

// A URL the browser opens by itself (a link, a download, a websocket), which
// can't carry the bearer token, so on another server it goes in the URL
export function linkUrl(path) {
    const u = url(path);
    if (server?.token)
        u.searchParams.set('KISMET', server.token);
    return u;
}

// Websocket URL for a path, e.g. wsUrl('eventbus/events.ws')
export function wsUrl(path) {
    const u = linkUrl(path);
    u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
    return u;
}

// Request options for the server in use: the home server's session cookie,
// or another server's API key, unless the caller logs in with its own header
function withAuth(options) {
    if (!server)
        return { credentials: 'same-origin', ...options };
    const headers = new Headers(options.headers ?? {});
    if (server.token && !headers.has('Authorization'))
        headers.set('Authorization', `Bearer ${server.token}`);
    return { ...options, credentials: 'omit', headers };
}

async function request(path, options = {}) {
    let response;
    try {
        response = await fetch(url(path), withAuth({
            ...options,
            signal: options.signal ?? AbortSignal.timeout(options.timeout ?? 15000),
        }));
    } catch (err) {
        if (err.name === 'AbortError')
            throw err;
        throw new ApiError(0, `Kismet server unreachable (${err.message})`);
    }

    if (response.status === 401 && !options.noAuthEvent)
        for (const fn of authListeners)
            fn();

    if (!response.ok)
        throw new ApiError(response.status, await errorText(response));

    return response;
}

// The reason in an error reply.  Kismet and most proxies send a small HTML
// page; DOMParser reads it as inert text, without running or loading anything.
async function errorText(response) {
    let text = '';
    try {
        text = (await response.text()).trim();
    } catch {
        text = '';
    }
    const html = /html/i.test(response.headers.get('Content-Type') ?? '') || /^<(!doctype|html|head|body)\b/i.test(text);
    if (text && html) {
        const doc = new DOMParser().parseFromString(text, 'text/html');
        const clean = (s) => (s ?? '').replace(/\s+/g, ' ').trim();
        const parts = [...doc.querySelectorAll('h1, h2, h3, p, pre')].map((n) => clean(n.textContent)).filter(Boolean);
        text = parts.length ? parts.join(': ') : clean(doc.body?.textContent) || clean(doc.title);
    }
    if (text.length > 300)
        text = `${text.slice(0, 300)}…`;
    return text || `${response.status} ${response.statusText}`.trim();
}

// GET a JSON endpoint
export async function get(path, options = {}) {
    return (await request(path, options)).json();
}

// POST to a JSON endpoint.  `json` is the Kismet command body (fields, regex,
// and so on); `vars` are plain form variables such as paging options.
export async function post(path, json = null, vars = {}, options = {}) {
    const body = new URLSearchParams();
    if (json !== null)
        body.set('json', JSON.stringify(json));
    for (const [key, value] of Object.entries(vars))
        if (value !== undefined && value !== null)
            body.set(key, String(value));

    return (await request(path, { ...options, method: 'POST', ...formBody(body) })).json();
}

// Send a command (the server's .cmd endpoints, which answer in plain text).
// Returns the server's reply text.
export async function command(path, json = null) {
    const body = new URLSearchParams();
    if (json !== null)
        body.set('json', JSON.stringify(json));
    return (await request(path, { method: 'POST', ...formBody(body) })).text();
}

// A form-encoded request body.  The Content-Type is set by hand because
// browsers add ";charset=UTF-8" with no space, which Kismet doesn't recognize.
export function formBody(params) {
    return {
        body: params.toString(),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    };
}

// Fetch without parsing, for status checks: returns the Response, never throws on HTTP errors
export async function probe(path, options = {}) {
    try {
        return await fetch(url(path), withAuth({
            ...options,
            signal: AbortSignal.timeout(options.timeout ?? 10000),
        }));
    } catch (err) {
        throw new ApiError(0, `Kismet server unreachable (${err.message})`);
    }
}

// Read a value out of a Kismet record by path, e.g.
//   field(device, 'kismet.device.base.signal/kismet.common.signal.last_signal')
export function field(record, path, fallback = undefined) {
    let value = record;
    for (const part of path.split('/')) {
        if (value === null || typeof value !== 'object' || !(part in value))
            return fallback;
        value = value[part];
    }
    return value;
}
