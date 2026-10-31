// A registry is a named list of things modules add to the UI: device columns,
// menu items, ribbon stats, and so on.  Every entry has an `id`; adding an
// entry with an id that's already there replaces it.  Entries come back sorted
// by `priority` (lower first), so it doesn't matter what order modules load in.
//
// Widgets that show a registry watch it, so entries added after the page is
// built (by a slow-loading plugin, say) still show up.

export function createRegistry(name, { required = [], defaults = {} } = {}) {
    const entries = new Map();
    const listeners = new Set();
    let order = new Map();
    let notifyQueued = false;

    function notify() {
        // Many entries are usually added at once; tell watchers once
        if (notifyQueued)
            return;
        notifyQueued = true;
        queueMicrotask(() => {
            notifyQueued = false;
            for (const fn of listeners)
                fn();
        });
    }

    return {
        name,

        add(entry) {
            for (const key of ['id', ...required]) {
                if (entry?.[key] === undefined) {
                    console.error(`${name}: entry is missing '${key}'`, entry);
                    return null;
                }
            }
            const full = { priority: 0, ...defaults, ...entry };
            entries.set(full.id, full);
            notify();
            return full;
        },

        remove(id) {
            if (entries.delete(id))
                notify();
        },

        get(id) {
            return entries.get(id);
        },

        list() {
            const all = [...entries.values()].sort((a, b) => a.priority - b.priority);
            if (!order.size)
                return all;
            // the entries given an order trade places among themselves; the rest stay put
            const slots = all.map((e, i) => (order.has(e.id) ? i : -1)).filter((i) => i >= 0);
            const moved = slots.map((i) => all[i]).sort((a, b) => order.get(a.id) - order.get(b.id));
            slots.forEach((i, n) => { all[i] = moved[n]; });
            return all;
        },

        // Put the entries with these ids in this order among themselves, in the
        // places their priorities give them; ids not here keep their places
        setOrder(ids) {
            const next = new Map((Array.isArray(ids) ? ids : []).map((id, i) => [id, i]));
            if (next.size === order.size && [...next].every(([id, i]) => order.get(id) === i))
                return;
            order = next;
            notify();
        },

        // Call fn() whenever entries are added or removed
        watch(fn) {
            listeners.add(fn);
            return () => listeners.delete(fn);
        },
    };
}
