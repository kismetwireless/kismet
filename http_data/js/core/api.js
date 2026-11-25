// Talking to the Kismet server over HTTP.
//
//   const status = await api.get('system/status.json');
//   const page = await api.post('devices/views/all/devices.json',
//       { fields: [...] }, { page: 0, length: 50 });
//
// A read the server turns away while busy (503 with Retry-After) is tried again
// a few times; pass { alive: () => shown } so a closed view stops asking.
//
// Paths are relative to the Kismet server root, set by the
// <meta name="kismet-root"> tag in index.html, so the UI works behind a
// reverse proxy or from a sub-directory.  The installed app can use another
// server instead (js/core/servers.js), with its API key as a bearer token.

import * as servers from './servers.js';
import * as censor from './censor.js';

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

// The marked version of a message, alert, or event bus endpoint, whose messages
// and alerts mark the parts that identify something, for censoring; plain once
// the server turns out not to have them
const markedRoot = /^(alerts|messagebus|eventbus)\//;
const markedPath = /^(alerts|messagebus|eventbus)\/marked\//;
let noMarked = false;

export function marked(path) {
    return noMarked ? path : path.replace(markedRoot, '$1/marked/');
}

// Find out whether the server has the marked endpoints, after a marked
// websocket didn't open
export async function probeMarked() {
    if (noMarked)
        return;
    try {
        await request(marked('messagebus/last-time/9999999999/messages.json'), { noAuthEvent: true });
    } catch {
        // Unreachable; asked again next time
    }
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

// A server already building as many large lists as it allows (httpd_max_large_lists)
// answers a request for another with 503 and Retry-After.  Reads wait and ask again a
// few times while the caller keeps showing what it has.  They give up early, throwing
// the 503 with err.stopped set, when options.alive() turns false or the tab is hidden,
// and throw an AbortError when options.signal aborts.
const busyTries = 3;
const busyDefaultMs = 2000;
const busyMaxMs = 10000;

function retryAfterMs(value, attempt) {
    // Seconds, or an HTTP date; anything else gets the default
    let ms = busyDefaultMs;
    if (/^\s*\d+(\.\d+)?\s*$/.test(value))
        ms = Number(value) * 1000;
    else if (/[a-z]/i.test(value) && Number.isFinite(Date.parse(value)))
        ms = Math.max(0, Date.parse(value) - Date.now());
    return Math.min(busyMaxMs, ms * (1 + attempt / 2) + Math.random() * 1000);
}

// Resolves true after ms, or false at once if the tab is hidden; rejects if the
// caller aborts
function busyWait(ms, signal) {
    return new Promise((resolve, reject) => {
        const finish = (fn) => {
            clearTimeout(timer);
            document.removeEventListener('visibilitychange', onVisibility);
            signal?.removeEventListener('abort', onAbort);
            fn();
        };
        const onVisibility = () => {
            if (document.visibilityState === 'hidden')
                finish(() => resolve(false));
        };
        const onAbort = () => finish(() => reject(new DOMException('The request was aborted', 'AbortError')));
        const timer = setTimeout(() => finish(() => resolve(true)), ms);
        document.addEventListener('visibilitychange', onVisibility);
        signal?.addEventListener('abort', onAbort);
        if (signal?.aborted)
            onAbort();
        else
            onVisibility();
    });
}

async function request(path, options = {}) {
    const tries = options.busyTries ?? busyTries;
    for (let attempt = 0; ; attempt++) {
        const response = await send(path, options);
        if (response.ok)
            return response;
        const err = new ApiError(response.status, await errorText(response));
        const after = response.headers.get('Retry-After');
        if (response.status !== 503 || after === null || attempt >= tries)
            throw err;
        const alive = () => !options.alive || options.alive();
        if (!alive() || !await busyWait(retryAfterMs(after, attempt), options.signal) || !alive()) {
            err.stopped = true;
            throw err;
        }
    }
}

// One request; HTTP errors come back as the Response
async function send(path, options) {
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

    // An older server without the marked endpoints
    if (response.status === 404 && markedPath.test(path)) {
        noMarked = true;
        return send(path.replace(markedPath, '$1/'), options);
    }

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
    return censor.learn(await (await request(path, options)).json());
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

    return censor.learn(await (await request(path, { ...options, method: 'POST', ...formBody(body) })).json());
}

// Send a command (the server's .cmd endpoints, which answer in plain text).
// Returns the server's reply text.
export async function command(path, json = null) {
    const body = new URLSearchParams();
    if (json !== null)
        body.set('json', JSON.stringify(json));
    return (await request(path, { method: 'POST', busyTries: 0, ...formBody(body) })).text();
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
