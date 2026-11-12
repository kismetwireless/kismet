// Per-browser settings, kept in localStorage as JSON.
//
//   settings.get('theme.mode', 'auto')
//   settings.set('theme.mode', 'dark')
//   settings.watch('theme.mode', (value) => ...)
//
// Storage can be missing or full (private windows, blocked site data); the UI
// then keeps settings in memory for the session.
//
// Stored settings carry a version; migrations bring older ones up to date once,
// when this module loads.

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

// Each migration takes the settings from its index to the next version
const migrations = [
    // 0 -> 1: the device list opens on the 'default' view, which leaves out the
    // devices 'exclude' device rules match; 'all' was the old default
    () => {
        if (get('devicelist.view', 'all') === 'all')
            set('devicelist.view', 'default');
    },
];

function migrate() {
    let version = get('settings.version', 0);
    if (!Number.isInteger(version) || version < 0)
        version = 0;

    for (; version < migrations.length; version++) {
        try {
            migrations[version]();
        } catch (err) {
            console.error(`Settings migration to version ${version + 1} failed:`, err);
        }
    }

    if (get('settings.version') !== version)
        set('settings.version', version);
}

migrate();
