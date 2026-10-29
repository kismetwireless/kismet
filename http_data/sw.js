// Service worker for installing the UI as an app.
//
// It keeps copies of the UI's own files and of each server's UI plugin
// modules, so the app starts quickly and keeps its plugins on a poor link.
// Copies are served first and refreshed when a server's build token (the
// "build" in its /dynamic.json) changes: the page sends the token after it
// starts (see js/core/pwa.js).  Requests to the Kismet API and websockets
// pass straight through and are never kept.
//
// Caches:
//   kismet-ui2-shell              the UI, for the server it was loaded from
//   kismet-ui2-plugins-<server>   one server's plugin modules and its module list
// Each has a record of the build it holds, under metaKey.

const shellCache = 'kismet-ui2-shell';
const pluginPrefix = 'kismet-ui2-plugins-';
const scope = new URL(self.registration.scope);
const metaKey = new URL('__kismet_cache__', scope).href;
const shellPrefixes = ['css/', 'js/', 'vendor/', 'icons/'];
const shellFiles = ['', 'index.html', 'manifest.webmanifest'];
const precache = ['./', 'index.html', 'manifest.webmanifest', 'css/themes.css', 'css/base.css', 'js/main.js',
    'icons/icon.svg', 'icons/icon-192.png'];

function isShell(url) {
    if (url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname) || url.search)
        return false;
    const rel = url.pathname.slice(scope.pathname.length);
    return shellFiles.includes(rel) || shellPrefixes.some((p) => rel.startsWith(p) && !rel.includes('..'));
}

// A short, stable cache name for a server root
function serverKey(root) {
    let h = 0x811c9dc5;
    for (const c of new TextEncoder().encode(root))
        h = Math.imul(h ^ c, 0x01000193) >>> 0;
    return pluginPrefix + h.toString(16).padStart(8, '0');
}

async function readMeta(cache) {
    try {
        return await (await cache.match(metaKey))?.json() ?? null;
    } catch {
        return null;
    }
}

function writeMeta(cache, meta) {
    return cache.put(metaKey, new Response(JSON.stringify(meta), { headers: { 'Content-Type': 'application/json' } }));
}

// Plugin files each server's cache answers for: its modules, the folders they
// sit in (for modules that import their neighbours), and its module list.
// A module at the server's top level only matches itself, so the cache never
// claims the API.
let pluginRoutes = null;

async function loadRoutes() {
    const routes = [];
    for (const name of await caches.keys()) {
        if (!name.startsWith(pluginPrefix))
            continue;
        const meta = await readMeta(await caches.open(name));
        if (meta)
            routes.push({ cache: name, root: meta.root, files: meta.files ?? [], dirs: meta.dirs ?? [], fresh: meta.build === null });
    }
    pluginRoutes = routes;
    return routes;
}

function matchRoute(routes, url) {
    const href = url.origin + url.pathname;
    for (const r of routes) {
        if (href === new URL('dynamic.json', r.root).href)
            return { cache: r.cache, networkFirst: true };
        // A server without a build token can't say when its files change, so
        // they're fetched each time, with the copy for when it's out of reach
        if (r.files.includes(href) || r.dirs.some((d) => href.startsWith(d)))
            return { cache: r.cache, networkFirst: r.fresh };
    }
    return null;
}

function keep(res) {
    return res.ok && (res.type === 'basic' || res.type === 'cors') && !res.redirected;
}

// Copy first; fetch and keep it when there's none
async function cacheFirst(cacheName, req, key) {
    const cache = await caches.open(cacheName);
    const hit = await cache.match(key, { ignoreVary: true, ignoreSearch: true });
    if (hit)
        return hit;
    const res = await fetch(req);
    if (keep(res))
        await cache.put(key, res.clone());
    return res;
}

// Server first, for the module list; the copy when it can't be reached
async function networkFirst(cacheName, req, key) {
    const cache = await caches.open(cacheName);
    try {
        const res = await fetch(req);
        if (keep(res))
            await cache.put(key, res.clone());
        return res;
    } catch (err) {
        const hit = await cache.match(key, { ignoreVary: true, ignoreSearch: true });
        if (hit)
            return hit;
        throw err;
    }
}

self.addEventListener('install', (event) => {
    event.waitUntil(caches.open(shellCache)
        .then((c) => c.addAll(precache))
        .catch(() => { /* the first start still works without the copy */ })
        .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
    // Caches from earlier versions of this worker
    event.waitUntil(caches.keys()
        .then((keys) => Promise.all(keys.filter((k) => k.startsWith('kismet-ui2-v')).map((k) => caches.delete(k))))
        .then(() => self.clients.claim()));
});

self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.method !== 'GET')
        return;
    const url = new URL(req.url);

    if (isShell(url)) {
        const key = req.mode === 'navigate' ? new URL('./', scope).href : url.href;
        event.respondWith(cacheFirst(shellCache, req, key));
        return;
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:')
        return;

    // Kept without any login in the URL
    const key = url.origin + url.pathname;
    const serve = (route) => (route.networkFirst ? networkFirst(route.cache, req, key) : cacheFirst(route.cache, req, key));

    // Only plugin files are answered here; everything else goes to the network
    // untouched.  Right after the worker starts, the routes are read first.
    if (pluginRoutes === null) {
        event.respondWith(loadRoutes().then((routes) => {
            const route = matchRoute(routes, url);
            return route ? serve(route) : fetch(req);
        }));
        return;
    }

    const route = matchRoute(pluginRoutes, url);
    if (route)
        event.respondWith(serve(route));
});

// Fetch every file again.  Nothing changes unless the server answers for all
// of them: if it can't be reached, this throws and the copies stay as they
// are, to be used until it can.  A file the new build no longer has is dropped.
async function fetchAll(urls) {
    return Promise.all(urls.map(async (u) => {
        const res = await fetch(u, { cache: 'reload', credentials: 'omit', mode: 'cors' });
        if (keep(res))
            return [u, res];
        if (res.status === 404 || res.status === 410)
            return [u, null];
        throw new Error(`${u}: ${res.status}`);
    }));
}

async function store(cache, fresh) {
    for (const [u, res] of fresh) {
        if (res)
            await cache.put(u, res);
        else
            await cache.delete(u);
    }
}

// The page tells us each server's build token (null from servers too old to
// have one) and plugin modules:
//   { type: 'server', root, build, home, modules: [url, ...] }
// and gets back { shellUpdated, pluginsUpdated, stale }.  stale means the
// server has changed but its new files couldn't be fetched, so the copies in
// hand are still in use.
async function onServer({ root, build, home, modules }) {
    const result = { shellUpdated: false, pluginsUpdated: false, stale: false };
    if (typeof root !== 'string' || (build !== null && typeof build !== 'string') || !Array.isArray(modules))
        return result;

    // The UI itself only follows a real build token
    if (home && build !== null) {
        const cache = await caches.open(shellCache);
        const meta = await readMeta(cache);
        if (meta && meta.build !== build) {
            const urls = (await cache.keys()).map((r) => r.url).filter((u) => u !== metaKey && isShell(new URL(u)));
            try {
                await store(cache, await fetchAll(urls));
                await writeMeta(cache, { build });
                result.shellUpdated = true;
            } catch {
                result.stale = true;
            }
        } else if (!meta) {
            await writeMeta(cache, { build });
        }
    }

    const rootUrl = new URL(root);
    const files = [];
    const dirs = new Set();
    for (const m of modules) {
        const u = new URL(m);
        if (u.origin !== rootUrl.origin || !u.pathname.startsWith(rootUrl.pathname))
            continue;
        files.push(u.origin + u.pathname);
        const dir = u.origin + u.pathname.replace(/[^/]*$/, '');
        if (dir !== rootUrl.href)
            dirs.add(dir);
    }

    const name = serverKey(root);
    const cache = await caches.open(name);
    const meta = await readMeta(cache);
    if (!meta || meta.build !== build || JSON.stringify(meta.files) !== JSON.stringify(files)) {
        let fresh = null;
        try {
            fresh = await fetchAll(files);
        } catch {
            // Keep what we have; with nothing yet, files are kept as the page loads them
            if (meta) {
                result.stale = true;
                return result;
            }
        }
        // Swap in the new copies only now that they've all arrived
        if (meta) {
            await caches.delete(name);
            result.pluginsUpdated = true;
        }
        const next = await caches.open(name);
        if (fresh)
            await store(next, fresh);
        await writeMeta(next, { root, build, files, dirs: [...dirs] });
        pluginRoutes = null;
    }

    return result;
}

self.addEventListener('message', (event) => {
    if (event.data?.type !== 'server' || !event.ports[0])
        return;
    event.waitUntil(onServer(event.data)
        .catch((err) => {
            console.warn('Kismet service worker:', err);
            return { shellUpdated: false, pluginsUpdated: false };
        })
        .then((r) => event.ports[0].postMessage(r)));
});
