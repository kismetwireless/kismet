// Other Kismet servers the UI can connect to, for the installed app.
//
// The server the UI was loaded from is always available as the "home"
// server, and uses its session cookie as before.  Other servers are reached
// directly: they need httpd_allow_cors=true (and httpd_allowed_origin set to
// this UI's address), and the UI logs in to each with an API key it makes
// there, sent as a bearer token.  Passwords are never kept.
//
// Saved, per browser:
//   servers.list     [{ id, name, url, token, tokenName, trustPlugins }]
//   servers.current  the id in use, or null for the home server

import * as settings from './settings.js';

export const home = new URL(document.querySelector('meta[name="kismet-root"]')?.content || './', document.baseURI);

export function list() {
    const saved = settings.get('servers.list', []);
    return Array.isArray(saved) ? saved.filter((s) => s && typeof s.id === 'string' && validUrl(s.url)) : [];
}

// The server in use: a saved server, or null for the home server
export function current() {
    const id = settings.get('servers.current', null);
    return id === null ? null : list().find((s) => s.id === id) ?? null;
}

// Whether the UI runs as an installed app rather than in a browser tab
export function installed() {
    return window.matchMedia('(display-mode: standalone), (display-mode: fullscreen), (display-mode: minimal-ui)').matches ||
        navigator.standalone === true;
}

// Server URLs are http or https, end in '/', and carry no login or query
export function normalize(text) {
    let u;
    try {
        u = new URL(/^[a-z]+:\/\//i.test(text.trim()) ? text.trim() : `http://${text.trim()}`);
    } catch {
        return null;
    }
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password)
        return null;
    u.search = '';
    u.hash = '';
    if (!u.pathname.endsWith('/'))
        u.pathname += '/';
    return u.href;
}

function validUrl(text) {
    return typeof text === 'string' && normalize(text) === text;
}

// A page loaded over https can't reach an http server
export function blockedMixed(url) {
    return location.protocol === 'https:' && new URL(url).protocol === 'http:' &&
        !['localhost', '127.0.0.1', '[::1]'].includes(new URL(url).hostname);
}

export function add(name, url) {
    const href = normalize(url);
    if (!href)
        throw new Error('Not a server address; use something like https://kismet.example:2501/');
    if (href === home.href)
        throw new Error('That is the server this app was loaded from; it is always in the list');
    const servers = list();
    if (servers.some((s) => s.url === href))
        throw new Error('That server is already in the list');
    const id = crypto.randomUUID();
    servers.push({ id, name: name.trim() || new URL(href).host, url: href, token: null, tokenName: null, trustPlugins: false });
    settings.set('servers.list', servers);
    return id;
}

function update(id, changes) {
    settings.set('servers.list', list().map((s) => (s.id === id ? { ...s, ...changes } : s)));
}

export function setToken(id, token, tokenName) {
    update(id, { token, tokenName });
}

// Whether to run a server's own UI plugins, which could read this app's keys
// for the other servers
export function setTrustPlugins(id, trust) {
    update(id, { trustPlugins: trust === true });
}

// Forget a server, and revoke the app's key there if it can be reached
export async function remove(id) {
    const s = list().find((x) => x.id === id);
    if (!s)
        return;
    settings.set('servers.list', list().filter((x) => x.id !== id));
    if (settings.get('servers.current', null) === id)
        settings.set('servers.current', null);
    const logins = { ...settings.get('logins', {}) };
    delete logins[new URL(s.url).href];
    settings.set('logins', logins);
    if (s.token && s.tokenName) {
        try {
            const body = new URLSearchParams({ json: JSON.stringify({ name: s.tokenName }) });
            await fetch(new URL('auth/apikey/revoke.cmd', s.url), {
                method: 'POST', credentials: 'omit', body: body.toString(),
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Bearer ${s.token}` },
                signal: AbortSignal.timeout(5000),
            });
        } catch {
            // Unreachable; the key stays on that server until removed there
        }
    }
}

// Switch servers; the page reloads to start over against the new one
export function select(id) {
    settings.set('servers.current', id);
    location.reload();
}
