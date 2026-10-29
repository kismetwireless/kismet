// Rows of a long server-side list, fetched a page at a time as they're needed.
//
//   const rows = createRowSource({ pageSize: 50, load, onChange });
//   rows.want(first, last, ahead)   // make sure rows first..last are loaded (or loading),
//                                   // plus `ahead` pages beyond them in the scroll direction
//   rows.row(i)                     // the row, or undefined while it loads
//
// load(page, size, signal) returns { rows, total }.  onChange() is called when
// rows arrive or the total changes.
//
// refresh() marks every page out of date but keeps showing it; want() then
// reloads the out-of-date pages it's asked for, so only what's on screen is
// refetched.  Pages far from where the user is looking are dropped to keep
// memory flat however long the list is.

const maxLoading = 3;
const keepPages = 8;

export function createRowSource({ pageSize, load, onChange }) {
    let pages = new Map();     // page -> { rows, stale, loading: AbortController | null }
    let total = null;          // null until the first page arrives
    let generation = 0;
    let version = 0;

    function loadingCount() {
        let n = 0;
        for (const p of pages.values())
            if (p.loading)
                n++;
        return n;
    }

    async function fetchPage(page) {
        let entry = pages.get(page);
        if (!entry) {
            entry = { rows: null, stale: true, loading: null };
            pages.set(page, entry);
        }
        if (entry.loading || !entry.stale)
            return;

        const gen = generation;
        const abort = new AbortController();
        entry.loading = abort;

        try {
            const result = await load(page, pageSize, abort.signal);
            if (gen !== generation || pages.get(page) !== entry)
                return;
            entry.rows = result.rows;
            entry.stale = false;
            if (result.total !== total)
                total = result.total;
            version++;
            onChange();
        } catch (err) {
            if (err.name !== 'AbortError' && gen === generation) {
                // Wait a little before trying this page again
                entry.retryAt = Date.now() + 3000;
                onChange(err);
            }
        } finally {
            if (entry.loading === abort)
                entry.loading = null;
        }
    }

    return {
        pageSize,

        // Total rows the server has, or null before anything has loaded
        get total() {
            return total;
        },

        // Changes whenever any loaded row does; lets the table skip redraws
        get version() {
            return version;
        },

        row(i) {
            const p = pages.get(Math.floor(i / pageSize));
            return p?.rows?.[i % pageSize];
        },

        // Whether any row in first..last has no data yet
        waiting(first, last) {
            if (total === null)
                return true;
            last = Math.min(last, total - 1);
            for (let page = Math.floor(first / pageSize); page <= Math.floor(last / pageSize); page++)
                if (!pages.get(page)?.rows)
                    return true;
            return false;
        },

        // Whether a load is running for any of first..last
        loading(first, last) {
            for (let page = Math.floor(first / pageSize); page <= Math.floor(Math.max(first, last) / pageSize); page++)
                if (pages.get(page)?.loading)
                    return true;
            return false;
        },

        want(first, last, ahead = 1, direction = 1) {
            const firstPage = Math.floor(Math.max(0, first) / pageSize);
            let lastPage = Math.floor(Math.max(first, last) / pageSize);
            const maxPage = total === null ? lastPage : Math.max(0, Math.ceil(total / pageSize) - 1);
            lastPage = Math.min(lastPage, maxPage);

            // On-screen pages first, reloaded when out of date; then the
            // preloads in the direction of travel, fetched only if missing
            // (they're refreshed once they come on screen)
            const order = [];
            for (let p = firstPage; p <= lastPage; p++)
                order.push([p, true]);
            for (let n = 1; n <= ahead; n++) {
                const p = direction >= 0 ? lastPage + n : firstPage - n;
                if (p >= 0 && p <= maxPage)
                    order.push([p, false]);
            }

            for (const [p, onScreen] of order) {
                if (loadingCount() >= maxLoading)
                    break;
                const entry = pages.get(p);
                const due = entry && !entry.loading && !(entry.retryAt > Date.now()) &&
                    (onScreen ? entry.stale : !entry.rows);
                if (!entry || due)
                    fetchPage(p);
            }

            // Forget pages far from here
            for (const [p, entry] of pages) {
                if (p < firstPage - keepPages || p > lastPage + keepPages) {
                    entry.loading?.abort();
                    pages.delete(p);
                }
            }
        },

        // Everything may have changed on the server; reload pages as they're wanted
        refresh() {
            for (const entry of pages.values())
                entry.stale = true;
        },

        // Start over (new sort, search, view, or fields)
        reset() {
            generation++;
            for (const entry of pages.values())
                entry.loading?.abort();
            pages = new Map();
            total = null;
            version++;
        },
    };
}
