// Inline SVG icons.  They draw in the current text color and scale with the
// font size, so they fit in text, buttons, and table rows without changing
// the row height.
//
//   icons.icon('wifi')                  -> <svg class="icon">...</svg>
//   icons.icon('wifi', 'Access point')  -> with a tooltip
//
// Modules can add their own with icons.define(name, svgPathMarkup).

const paths = {
    menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
    close: '<path d="M6 6l12 12M18 6L6 18"/>',
    left: '<path d="M15 5l-7 7 7 7"/>',
    right: '<path d="M9 5l7 7-7 7"/>',
    first: '<path d="M17 5l-7 7 7 7M7 5v14"/>',
    last: '<path d="M7 5l7 7-7 7M17 5v14"/>',
    up: '<path d="M6 15l6-6 6 6"/>',
    down: '<path d="M6 9l6 6 6-6"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
    highlight: '<path d="M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z"/>',
    ship: '<path d="M3 15l2 5h14l2-5zM12 3v9M8 12l4-6 4 6"/>',
    plane: '<path d="M12 2.5c.8 0 1.5.7 1.5 1.5v5l7 4.5v2l-7-2.2v4.4l2.2 1.6v1.7L12 20l-3.7 1v-1.7l2.2-1.6v-4.4l-7 2.2v-2l7-4.5V4c0-.8.7-1.5 1.5-1.5z"/>',
    anchor: '<circle cx="12" cy="5" r="2"/><path d="M12 7v14M5 13a7 7 0 0 0 14 0M8 11h8"/>',
    tower: '<path d="M12 10v11M9 21l3-11 3 11"/><path d="M7.8 5.8a6 6 0 0 0 0 8.4M16.2 5.8a6 6 0 0 1 0 8.4"/><circle cx="12" cy="10" r="1.5"/>',
    lifebuoy: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M5.6 5.6l3.6 3.6M14.8 14.8l3.6 3.6M18.4 5.6l-3.6 3.6M9.2 14.8l-3.6 3.6"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
    columns: '<rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M9 4v16M15 4v16"/>',
    search: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    wifi: '<path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1" fill="currentColor"/>',
    bluetooth: '<path d="M7 7l10 10-5 5V2l5 5L7 17"/>',
    radio: '<circle cx="12" cy="12" r="2"/><path d="M7.8 7.8a6 6 0 0 0 0 8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.9 4.9a10 10 0 0 0 0 14.2M19.1 4.9a10 10 0 0 1 0 14.2"/>',
    zigbee: '<path d="M5 6h14L5 18h14"/>',
    device: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
    unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14"/><circle cx="12" cy="17" r=".6" fill="currentColor"/>',
    packets: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
    memory: '<rect x="4" y="7" width="16" height="10" rx="1"/><path d="M8 7v10M12 7v10M16 7v10M6 17v3M18 17v3"/>',
    gps: '<path d="M12 22s7-6.5 7-12a7 7 0 0 0-14 0c0 5.5 7 12 7 12z"/><circle cx="12" cy="10" r="2.5"/>',
    alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v5"/><circle cx="12" cy="18" r=".6" fill="currentColor"/>',
    battery: '<rect x="2" y="7" width="17" height="10" rx="2"/><path d="M22 11v2"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    source: '<path d="M12 12v10M8 22h8"/><circle cx="12" cy="9" r="2"/><path d="M7.8 4.8a6 6 0 0 0 0 8.4M16.2 4.8a6 6 0 0 1 0 8.4"/>',
    link: '<circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><circle cx="12" cy="7.5" r=".6" fill="currentColor"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    expand: '<path d="M14 4h6v6M10 20H4v-6M20 4l-6.5 6.5M4 20l6.5-6.5"/>',
    collapse: '<path d="M4 14h6v6M20 10h-6V4M14 10l6.5-6.5M10 14l-6.5 6.5"/>',
    target: '<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="1.5"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
    vessel: '<path d="M12 2.5l4.5 7V21h-9V9.5z"/><path d="M12 9v7"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
};

export function define(name, svgInner) {
    paths[name] = svgInner;
}

export function has(name) {
    return name in paths;
}

export function icon(name, title = null) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', `icon icon-${name}`);
    svg.setAttribute('aria-hidden', title ? 'false' : 'true');
    // Icon markup is fixed, trusted text from this file or a module's define()
    svg.innerHTML = paths[name] ?? paths.unknown;
    if (title) {
        const t = document.createElementNS('http://www.w3.org/2000/svg', 'title');
        t.textContent = title;
        svg.prepend(t);
    }
    return svg;
}
