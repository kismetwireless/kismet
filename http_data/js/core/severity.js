// Kismet's alert severity scale, as the server defines it (alertracker.h):
// info 0, low 5, medium 10, high 15, critical 20.  Each level has a name and
// a colour; level() finds the level for a severity number.  No DOM or
// settings here, so it can be tested on its own.

export const levels = Object.freeze([
    { id: 'critical', label: 'Critical', min: 20, color: 'var(--error)' },
    { id: 'high', label: 'High', min: 15, color: 'color-mix(in srgb, var(--error) 50%, var(--warn))' },
    { id: 'medium', label: 'Medium', min: 10, color: 'var(--warn)' },
    { id: 'low', label: 'Low', min: 5, color: 'color-mix(in srgb, var(--warn) 40%, var(--muted))' },
    { id: 'info', label: 'Info', min: -Infinity, color: 'var(--muted)' },
].map((l) => Object.freeze(l)));

// The level for a severity; anything that isn't a number counts as info
export function level(sev) {
    const v = typeof sev === 'number' ? sev : Number(sev ?? NaN);
    return levels.find((l) => v >= l.min) ?? levels[levels.length - 1];
}

export const label = (sev) => level(sev).label;
export const color = (sev) => level(sev).color;
