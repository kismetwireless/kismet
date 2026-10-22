// Per-browser settings, kept in localStorage as JSON.
//
//   settings.get('theme.mode', 'auto')
//   settings.set('theme.mode', 'dark')
//   settings.watch('theme.mode', (value) => ...)
//
// Storage can be missing or full (private windows, blocked site data); the UI
// then keeps settings in memory for the session.

const prefix = 'kismet.ui2.';
const memory = new Map();
const watchers = new Map();

function storage() {
    try {
        return window.localStorage;
    } catch {
        return null;
    }
}

export function get(key, fallback = undefined) {
    if (memory.has(key))
        return memory.get(key);

    try {
        const raw = storage()?.getItem(prefix + key);
        if (raw !== null && raw !== undefined)
            return JSON.parse(raw);
    } catch {
        // Unreadable or corrupt value; use the default
    }

    return fallback;
}

export function set(key, value) {
    memory.set(key, value);

    try {
        if (value === undefined)
            storage()?.removeItem(prefix + key);
        else
            storage()?.setItem(prefix + key, JSON.stringify(value));
    } catch {
        // Kept in memory only
    }

    for (const fn of watchers.get(key) ?? [])
        fn(value);
}

export function remove(key) {
    set(key, undefined);
    memory.delete(key);
}

// Call fn(value) whenever key changes.  Returns a function that stops watching.
export function watch(key, fn) {
    if (!watchers.has(key))
        watchers.set(key, new Set());
    watchers.get(key).add(fn);
    return () => watchers.get(key).delete(fn);
}
