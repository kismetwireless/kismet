// The map tab: the kinds of device that phys and plugins register in
// kismet.ui.mapSources.  Devices that report their own position (aircraft,
// vessels, drones, mesh nodes) are drawn where they say they are, with a line
// back to where Kismet was when it heard them; others (Wi-Fi access points,
// sensors) are drawn where Kismet heard them.  A list of the devices runs
// down the side, marking the ones inside the map view.
//
// Each refresh also adds to the paths the browser keeps (tracks.js), and the
// map keeps collecting them, more slowly, while it is hidden.  A device's
// path joins those with the server's location history, when it keeps one.
// The same positions build the receiver range outline (maprange.js).
//
// The map background comes from a public tile server, so nothing is loaded
// from it until the user agrees (see askTiles).  Without tiles the devices
// are drawn on a blank map.

import { el } from '../core/dom.js';
import * as api from '../core/api.js';
import * as settings from '../core/settings.js';
import * as theme from '../core/theme.js';
import * as eventbus from '../core/eventbus.js';
import * as format from '../core/format.js';
import * as clock from '../core/clock.js';
import * as tracks from './tracks.js';
import { createRangeStore, destination, ringStep } from './maprange.js';
import { icon } from '../core/icons.js';
import { mapSources } from '../registry/ui.js';
import { openDevice } from './detailpanel.js';
import { confirm } from './dialog.js';

const base = 'kismet.device.base';
const refreshMs = 2000;
const collectMs = 15000;            // while the map is hidden
const maxListed = 1000;
const maxMarkers = 5000;
const rangeLimit = 500000;          // m; further positions are taken as bad decodes

export const defaultTileUrl = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const defaultAttribution = '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors';

// Map ages offered in the list, in seconds; 0 is each kind's own default
export const ages = [
    { id: 0, title: 'Default for each kind' },
    { id: 300, title: '5 minutes' },
    { id: 600, title: '10 minutes' },
    { id: 1800, title: '30 minutes' },
    { id: 3600, title: '1 hour' },
    { id: 6 * 3600, title: '6 hours' },
    { id: 24 * 3600, title: '24 hours' },
];

// How long the browser keeps paths, in seconds
export const pathAges = [
    { id: 900, title: '15 minutes' },
    { id: 3600, title: '1 hour' },
    { id: 6 * 3600, title: '6 hours' },
    { id: 24 * 3600, title: '24 hours' },
];

export const pathModes = [
    { id: 'all', title: 'all devices' },
    { id: 'selected', title: 'the selected device' },
];

function pathScope() {
    const m = settings.get('map.paths', 'all');
    return pathModes.some((p) => p.id === m) ? m : 'all';
}

function showPaths() {
    return settings.get('map.showPaths', true) !== false;
}

function pathMode() {
    return showPaths() ? pathScope() : 'off';
}

function rangeChoice() {
    return String(settings.get('map.range', 'auto') ?? 'auto');
}

// Kinds whose devices say where they are can show how far away they're heard
function ranged(src) {
    return src.range !== false && !['heard', 'average'].includes(src.position);
}

function km(m) {
    return `${(m / 1000).toLocaleString(undefined, { maximumFractionDigits: m < 10000 ? 1 : 0 })} km`;
}

function collecting() {
    return settings.get('map.pathsCollect', true) !== false;
}

function pathAge() {
    return Number(settings.get('map.pathsAge', 3600)) || 3600;
}

const last = (set, f) => `${base}.${set}/kismet.common.location.last/kismet.common.location.${f}`;
const commonFields = [
    [`${base}.key`, 'key'], [`${base}.commonname`, 'name'], [`${base}.phyname`, 'phy'],
    [`${base}.type`, 'type'], [`${base}.last_time`, 'last_time'],
    [last('location', 'geopoint'), 'heard'], [last('location', 'fix'), 'heard_fix'],
    [last('location', 'alt'), 'heard_alt'], [last('location', 'speed'), 'heard_speed'],
    [last('location', 'heading'), 'heard_heading'], [last('location', 'time_sec'), 'heard_time'],
    [last('reported_location', 'geopoint'), 'rep'], [last('reported_location', 'fix'), 'rep_fix'],
    [last('reported_location', 'alt'), 'rep_alt'], [last('reported_location', 'speed'), 'rep_speed'],
    [last('reported_location', 'heading'), 'rep_heading'], [last('reported_location', 'time_sec'), 'rep_time'],
    [`${base}.location/kismet.common.location.avg_loc/kismet.common.location.geopoint`, 'avg'],
    [`${base}.location/kismet.common.location.avg_loc/kismet.common.location.fix`, 'avg_fix'],
    [`${base}.reported_location_cloud/kis.gps.rrd.last_sample_ts`, 'cloud_ts'],
];

// A usable [lon, lat]: missing fields and "no fix" both come back as zeros
function point(p, fix) {
    return Array.isArray(p) && (p[0] || p[1]) && (fix ?? 2) >= 2 ? p : null;
}

// The tile server the settings name, if it's a plain http(s) template
export function tileSource() {
    const url = String(settings.get('map.tileUrl', '') || '').trim();
    if (url && /^https?:\/\/[^\s"'<>]+$/i.test(url) && ['{z}', '{x}', '{y}'].every((k) => url.includes(k)))
        return { url, custom: true };
    return { url: defaultTileUrl, custom: false };
}

function tileHost(url) {
    try {
        return new URL(url.replace(/\{[a-z]\}/g, 'a')).host;
    } catch {
        return url;
    }
}

// 'allow', 'deny', or 'ask'; a choice made without "don't ask again" lasts
// until the page is reloaded
let sessionChoice = null;

export function tilePolicy() {
    return settings.get('map.tiles', 'ask');
}

function tilesAllowed() {
    const policy = tilePolicy();
    if (policy === 'allow' || policy === 'deny')
        return policy === 'allow';
    return sessionChoice === 'allow';
}

function mustAsk() {
    return tilePolicy() === 'ask' && sessionChoice === null;
}

// Servers older than 2026-10 don't keep a reported location; ADS-B and AIS
// positions are in the device location instead
let legacyCheck = null;

function legacyServer() {
    if (!legacyCheck) {
        legacyCheck = api.probe('system/tracked_fields.html')
            .then(async (r) => r.ok && !(await r.text()).includes(`${base}.reported_location`))
            .catch(() => false);
    }
    return legacyCheck;
}

let leafletLoad = null;

// Leaflet is only loaded when the map is first shown
function loadLeaflet() {
    if (window.L)
        return Promise.resolve(window.L);
    if (!leafletLoad) {
        leafletLoad = new Promise((resolve, reject) => {
            const css = el('link', { rel: 'stylesheet', href: new URL('../../vendor/leaflet/leaflet.css', import.meta.url).href });
            const js = el('script', { src: new URL('../../vendor/leaflet/leaflet.js', import.meta.url).href });
            js.addEventListener('load', () => resolve(window.L));
            js.addEventListener('error', () => {
                leafletLoad = null;
                reject(new Error('Could not load the map library'));
            });
            document.head.append(css, js);
        });
    }
    return leafletLoad;
}

export function createMap(container, area = null) {
    const mapEl = el('div', { class: 'map-canvas' });
    const overlay = el('div', { class: 'map-overlay', hidden: true });
    const legends = el('div', { class: 'map-legends' });
    const status = el('div', { class: 'map-status', hidden: true });

    const tilesButton = el('button', { class: 'map-tool', title: 'Load the map background',
        onclick: () => askTiles(true) }, icon('gps'), 'Blank map');
    const fitButton = el('button', { class: 'map-tool icon-only', title: 'Show all devices', onclick: () => fitAll() },
        icon('target'));
    // Lives in the tab bar, so it's only there while the map is
    const expandButton = el('button', { class: 'icon-button tab-tool', onclick: () => setExpanded(!expanded) });
    const tools = el('div', { class: 'map-tools' }, tilesButton, fitButton);

    const search = el('input', { type: 'search', class: 'map-search', placeholder: 'Search the map',
        'aria-label': 'Search the map devices', oninput: () => render() });
    const ageSelect = el('select', { 'aria-label': 'How long devices stay on the map',
        onchange: () => { settings.set('map.maxAge', Number(ageSelect.value)); fetched.clear(); refresh(); } },
        ages.map((a) => el('option', { value: a.id, selected: a.id === settings.get('map.maxAge', 0) }, a.title)));
    const pathBox = el('input', { type: 'checkbox', checked: showPaths(),
        onchange: () => settings.set('map.showPaths', pathBox.checked) });
    const pathSelect = el('select', { 'aria-label': 'Which devices show their path', disabled: !showPaths(),
        onchange: () => settings.set('map.paths', pathSelect.value) },
        pathModes.map((m) => el('option', { value: m.id, selected: m.id === pathScope() }, m.title)));
    // Shown while the paths come only from what this page has seen
    const pathNoteText = el('p');
    const pathNote = el('details', { class: 'map-paths-note', hidden: true, open: settings.get('map.pathsNoteOpen', true),
        ontoggle: () => settings.set('map.pathsNoteOpen', pathNote.open) },
        el('summary', {}, icon('alert'), 'Paths only go back to when this page was loaded'),
        pathNoteText);
    const rangeSelect = el('select', { 'aria-label': 'Which kind of device shows the receiver range',
        onchange: () => settings.set('map.range', rangeSelect.value) });
    const rangeClear = el('button', { class: 'link-button', title: 'Forget the range collected for this kind of device',
        onclick: async () => {
            const src = rangeSource();
            if (src && await confirm({ title: 'Clear the receiver range?', ok: 'Clear', danger: true,
                text: `The range this browser collected for ${src.title.toLowerCase()} on this server is forgotten, ` +
                    'and starts again from the next positions heard.' })) {
                range.clear(src.id);
                drawRange();
            }
        } }, 'Clear');
    const rangeInfo = el('div', { class: 'map-range-info muted' });
    const inViewOnly = el('input', { type: 'checkbox', checked: settings.get('map.listInView', false),
        onchange: () => { settings.set('map.listInView', inViewOnly.checked); render(); } });
    const layerList = el('div', { class: 'map-layers' });
    const summary = el('div', { class: 'map-summary muted' });
    const list = el('ul', { class: 'map-list' });

    const side = el('aside', { class: 'map-side' },
        search,
        layerList,
        el('label', { class: 'map-age' }, 'Heard in the last ', ageSelect),
        el('div', { class: 'map-paths' }, el('label', {}, pathBox, 'Show paths for'), pathSelect),
        pathNote,
        el('div', { class: 'map-range-pick' }, el('label', {}, 'Receiver range'), rangeSelect, rangeClear),
        rangeInfo,
        el('label', { class: 'map-inview' }, inViewOnly, 'List only devices in view'),
        summary,
        list);

    const view = el('div', { class: 'map-view' }, mapEl, tools, legends, status, overlay);
    const root = el('div', { class: 'map-pane' }, view, side);
    container.append(root);

    let L = null;
    let map = null;
    let tileLayer = null;
    let tileUrl = null;
    let markerLayer = null;
    let linkLayer = null;
    let rangeLayer = null;
    let rangeShape = null;
    let rangeRings = [];
    let rangeRingKey = '';
    let selfMarker = null;
    let trail = null;
    let visible = false;
    let expanded = false;
    let timer = null;
    let collectTimer = null;
    let busy = false;
    let fitted = false;
    let stopGps = null;
    let selected = null;
    let legacy = false;
    legacyServer().then((v) => { legacy = v; });
    // Whether the server keeps location history: unknown until a device
    // with a reported position turns up
    let serverHistory = null;

    // The receiver range, kept by this browser for each server
    const range = createRangeStore(`${api.root.host}${api.root.pathname}`);
    // device key -> the last position added to the range
    const rangeSeen = new Map();

    // key -> { src, dev, pos, how, heardOnly, tracked, marker, glyph, link, heardDot, path, row }
    const entries = new Map();
    const counts = new Map();
    let skipped = 0;

    function enabled(src) {
        return settings.get(`map.layers.${src.id}`, src.defaultVisible) !== false;
    }

    function maxAge(src) {
        return Number(settings.get('map.maxAge', 0)) || src.maxAge;
    }

    function call(src, name, dev, fallback = null) {
        try {
            return typeof src[name] === 'function' ? src[name](dev) : (src[name] ?? fallback);
        } catch (err) {
            console.error(`map source ${src.id}: ${name} failed:`, err);
            return fallback;
        }
    }

    // Expanding fills the window with the map's tab area; with no area to
    // expand (the map shown somewhere else), only the map itself does
    function setExpanded(on) {
        if (area)
            area.setExpanded(on);
        else
            showExpanded(on);
    }

    function showExpanded(on) {
        expanded = on;
        if (!area)
            root.classList.toggle('expanded', on);
        expandButton.replaceChildren(icon(on ? 'collapse' : 'expand'));
        expandButton.title = on ? 'Back to the dashboard (Esc)' : 'Fill the window with the map';
        expandButton.setAttribute('aria-pressed', on ? 'true' : 'false');
        requestAnimationFrame(() => map?.invalidateSize());
    }
    showExpanded(false);
    const stopExpand = area?.onExpand(showExpanded);

    function onKey(e) {
        if (!expanded || !visible || e.key !== 'Escape' || e.defaultPrevented)
            return;
        if (document.querySelector('dialog[open], .menu-list:not([hidden])'))
            return;
        if (e.target.matches?.('input, textarea, select') && e.target.value)
            return;
        e.preventDefault();
        setExpanded(false);
    }
    document.addEventListener('keydown', onKey);
    const flushRange = () => range.flush();
    window.addEventListener('pagehide', flushRange);

    // The question about the public map server, shown over the map
    function askTiles(force = false) {
        if (!force && !mustAsk())
            return;
        const { url, custom } = tileSource();
        const host = tileHost(url);
        const remember = el('input', { type: 'checkbox' });
        const choose = (choice) => {
            sessionChoice = choice;
            if (remember.checked)
                settings.set('map.tiles', choice);
            overlay.hidden = true;
            overlay.replaceChildren();
            applyTiles();
        };
        overlay.replaceChildren(el('div', { class: 'map-consent', role: 'dialog', 'aria-label': 'Load the map background?' },
            el('h3', {}, 'Load the map background from the internet?'),
            el('p', {}, 'The map background comes from ', custom ? 'the map server set in Settings, ' : 'a public map server, ',
                el('strong', {}, host), '.  Showing it needs internet access, and it can reveal your location: every ',
                'piece of map your browser fetches tells that server, along with your IP address, which part of the ',
                'world you are looking at, and the map follows the devices around you.'),
            el('p', { class: 'muted' }, 'Without it, devices are still drawn, on a blank map.  You can change this later in ',
                'Settings > Map.'),
            el('label', { class: 'map-consent-remember' }, remember, 'Don\'t ask me again'),
            el('div', { class: 'form-buttons' },
                el('button', { onclick: () => choose('deny') }, 'Use a blank map'),
                el('button', { class: 'primary', onclick: () => choose('allow') }, 'Load the map'))));
        overlay.hidden = false;
    }

    function applyTiles() {
        if (!map)
            return;
        const allowed = tilesAllowed();
        const { url, custom } = tileSource();
        if (tileLayer && (!allowed || url !== tileUrl)) {
            tileLayer.remove();
            tileLayer = null;
        }
        if (allowed && !tileLayer) {
            // A custom server's attribution is the user's own text, shown as text
            const attribution = custom ?
                el('span', {}, String(settings.get('map.tileAttribution', '') || '')).innerHTML : defaultAttribution;
            tileLayer = L.tileLayer(url, { maxZoom: 19, attribution }).addTo(map);
            tileUrl = url;
        }
        root.classList.toggle('no-tiles', !allowed);
        tilesButton.hidden = allowed;
        applyTheme();
    }

    function applyTheme() {
        root.classList.toggle('dark-tiles', theme.current() === 'dark' && settings.get('map.darkTiles', true) !== false);
    }

    async function init() {
        try {
            L = await loadLeaflet();
        } catch (err) {
            status.textContent = err.message;
            status.hidden = false;
            return;
        }
        map = L.map(mapEl, { worldCopyJump: true, zoomSnap: 0.5 });
        map.attributionControl.setPrefix('<a href="https://leafletjs.com" target="_blank" rel="noopener">Leaflet</a>');
        L.control.scale({ position: 'bottomleft' }).addTo(map);
        rangeLayer = L.layerGroup().addTo(map);
        linkLayer = L.layerGroup().addTo(map);
        markerLayer = L.layerGroup().addTo(map);

        const saved = settings.get('map.view', null);
        if (saved && Array.isArray(saved.center) && Number.isFinite(saved.zoom)) {
            map.setView(saved.center, saved.zoom);
            fitted = true;
        } else {
            map.setView([20, 0], 2);
        }
        map.on('moveend', () => {
            const c = map.getCenter();
            settings.set('map.view', { center: [c.lat, c.lng], zoom: map.getZoom() });
            render();
        });

        legacy = await legacyServer();
        applyTiles();
        askTiles();
        start();
    }

    function selfPosition(e) {
        const p = point(e['kismet.common.location.geopoint'], e['kismet.common.location.fix']);
        if (!map)
            return;
        if (!p) {
            selfMarker?.remove();
            selfMarker = null;
            return;
        }
        const ll = [p[1], p[0]];
        if (!selfMarker) {
            selfMarker = L.marker(ll, {
                icon: L.divIcon({ className: 'map-self', html: el('span', { class: 'map-self-glyph' }, icon('gps')),
                    iconSize: [26, 26], iconAnchor: [13, 24] }),
                keyboard: false, zIndexOffset: -1000,
            }).bindTooltip(el('div', {}, 'Kismet (this server\'s GPS)'), { className: 'map-tip', direction: 'top', offset: [0, -20] })
                .addTo(map);
        } else {
            selfMarker.setLatLng(ll);
        }
        drawRange();
    }

    function start() {
        if (!map || !visible || timer)
            return;
        stopCollecting();
        timer = setInterval(refresh, refreshMs);
        stopGps = eventbus.subscribe('GPS_LOCATION',
            ['kismet.common.location.fix', 'kismet.common.location.geopoint'], selfPosition);
        refresh();
    }

    function stop() {
        clearInterval(timer);
        timer = null;
        stopGps?.();
        stopGps = null;
    }

    function startCollecting() {
        if (collectTimer || visible || !collecting())
            return;
        collectTimer = setInterval(refresh, collectMs);
    }

    function stopCollecting() {
        clearInterval(collectTimer);
        collectTimer = null;
    }

    // Sources with an interval (a regex over every device, say) are read less often
    const fetched = new Map();      // source id -> { at, list }

    // How many devices each server view holds, so kinds with none (phys
    // nothing has been seen on) can leave the list
    let viewSizes = null;
    let viewsAt = 0;

    async function loadViews() {
        viewsAt = Date.now();
        try {
            const views = await api.get('devices/views/all_views.json');
            viewSizes = new Map((Array.isArray(views) ? views : [])
                .map((v) => [v['kismet.devices.view.id'], Number(v['kismet.devices.view.size']) || 0]));
        } catch {
            viewSizes = null;
        }
        layers(mapSources.list());
    }

    async function fetchSource(src) {
        const cached = fetched.get(src.id);
        if (src.interval && cached && Date.now() - cached.at < src.interval)
            return cached.list;
        const fields = [...commonFields, ...(src.fields ?? [])];
        const body = { fields };
        if (src.regex)
            body.regex = src.regex;
        const path = `devices/views/${encodeURIComponent(src.view)}/last-time/${-Math.round(maxAge(src))}/devices.json`;
        const reply = await api.post(path, body);
        const list = Array.isArray(reply) ? reply : [];
        fetched.set(src.id, { at: Date.now(), list });
        return list;
    }

    async function refresh() {
        if (busy || (visible ? !map : !collecting()))
            return;
        busy = true;
        if (visible && Date.now() - viewsAt > 30000)
            loadViews();
        try {
            const sources = mapSources.list();
            // While hidden, only the kinds that leave paths are worth reading
            const wanted = sources.filter((src) => enabled(src) && (visible ||
                (src.paths !== false && !['heard', 'average'].includes(src.position))));
            const results = await Promise.all(wanted.map(async (src) => {
                try {
                    return { src, list: await fetchSource(src) };
                } catch (err) {
                    console.error(`map source ${src.id}:`, err);
                    return { src, list: [], error: err };
                }
            }));
            tracks.prune(clock.now() - pathAge());
            if (!visible || !map) {
                for (const { src, list } of results) {
                    for (const dev of list)
                        positions(src, dev);
                }
                return;
            }
            update(sources, results);
            if (selected)
                loadTrail(selected);
        } finally {
            busy = false;
        }
    }

    // Sort out where a device says it is and where Kismet heard it, add the
    // reported position to its path, and pick where the source draws it:
    // { pos: [lon, lat], how: 'reported' | 'heard' | 'average' }, or null
    function positions(src, dev) {
        let rep = point(dev.rep, dev.rep_fix);
        let heard = point(dev.heard, dev.heard_fix);
        let repTime = dev.rep_time;
        if (legacy && src.legacy) {
            rep = heard;
            heard = null;
            repTime = dev.heard_time;
            dev.rep_alt = dev.heard_alt;
            dev.rep_speed = dev.heard_speed;
            dev.rep_heading = dev.heard_heading;
        }
        dev.heard = heard;
        dev.avg = point(dev.avg, dev.avg_fix);
        if (typeof src.position === 'function') {
            const p = call(src, 'position', dev, null);
            rep = Array.isArray(p) && Number.isFinite(p[0]) && Number.isFinite(p[1]) &&
                Math.abs(p[0]) <= 180 && Math.abs(p[1]) <= 90 ? point(p) : null;
        }
        dev.rep = rep;
        if (rep && dev.key && src.paths !== false)
            tracks.record(dev.key, rep[0], rep[1], repTime || dev.last_time || clock.now());
        if (rep && heard && dev.key && ranged(src))
            addRange(src, dev, rep, heard);

        switch (typeof src.position === 'function' ? 'reported' : src.position) {
        case 'heard':
            return heard ? { pos: heard, how: 'heard' } : null;
        case 'average':
            return dev.avg ? { pos: dev.avg, how: 'average' } : heard ? { pos: heard, how: 'heard' } : null;
        case 'reported-or-heard':
            return rep ? { pos: rep, how: 'reported' } : heard ? { pos: heard, how: 'heard' } : null;
        default:
            return rep ? { pos: rep, how: 'reported' } : null;
        }
    }

    // Each new position, paired with where Kismet was when it last heard the
    // device; the server doesn't time either one, so a position counts once,
    // when it changes
    function addRange(src, dev, rep, heard) {
        const at = `${rep[0]},${rep[1]}`;
        if (rangeSeen.get(dev.key) === at)
            return;
        if (rangeSeen.size > 50000)
            rangeSeen.clear();
        rangeSeen.set(dev.key, at);
        range.record(src.id, dev.key, heard, rep, src.rangeLimit ?? rangeLimit);
    }

    // The kind picked for the range, or with 'auto', the one with the most positions
    function rangeSource() {
        const choice = rangeChoice();
        const sources = mapSources.list().filter(ranged);
        if (choice === 'off')
            return null;
        if (choice !== 'auto')
            return sources.find((s) => s.id === choice) ?? null;
        let best = null;
        for (const s of sources) {
            if (enabled(s) && range.has(s.id) && (!best || range.get(s.id).samples > range.get(best.id).samples))
                best = s;
        }
        return best;
    }

    let rangeIds = '';

    function rangeOptions() {
        const sources = mapSources.list().filter(ranged);
        const ids = sources.map((s) => s.id).join(' ');
        if (ids !== rangeIds) {
            rangeIds = ids;
            rangeSelect.replaceChildren(
                el('option', { value: 'off' }, 'Off'),
                el('option', { value: 'auto', title: 'The kind of device with the most positions' }, 'Automatic'),
                ...sources.map((s) => el('option', { value: s.id }, s.title)));
        }
        rangeSelect.value = [...rangeSelect.options].some((o) => o.value === rangeChoice()) ? rangeChoice() : 'auto';
    }

    // The outline around where Kismet is, and rings to read it by
    function drawRange() {
        if (!map)
            return;
        rangeOptions();
        const src = rangeSource();
        const rec = src && range.get(src.id);
        const outline = src && range.outline(src.id);
        const self = selfMarker?.getLatLng();
        const center = self ? [self.lng, self.lat] : rec?.center;
        rangeClear.hidden = !rec;
        if (!outline || !center) {
            rangeShape?.remove();
            rangeShape = null;
            for (const r of rangeRings)
                r.remove();
            rangeRings = [];
            rangeRingKey = '';
            rangeInfo.textContent = rangeChoice() === 'off' ? '' : rec?.samples ?
                `${rec.samples.toLocaleString()} positions so far; the outline is drawn once there are more directions.` :
                'No positions yet from devices that say where they are, heard with a GPS or a fixed source location.';
            return;
        }
        const pts = outline.dist.map((d, i) => (d > 0 ? destination(center, (i + 0.5) * outline.step, d) : [center[1], center[0]]));
        if (!rangeShape)
            rangeShape = L.polygon(pts, { className: 'map-range', weight: 1.5, interactive: false }).addTo(rangeLayer);
        else
            rangeShape.setLatLngs(pts);

        let far = 0, farBin = 0;
        rec.bins.forEach((d, i) => {
            if (d > far) {
                far = d;
                farBin = i;
            }
        });
        const step = ringStep(far);
        const ringKey = `${center[0]},${center[1]},${step},${Math.floor(far / step)}`;
        if (ringKey !== rangeRingKey) {
            rangeRingKey = ringKey;
            for (const r of rangeRings)
                r.remove();
            rangeRings = [];
            const ll = [center[1], center[0]];
            for (let r = step; r <= far; r += step) {
                rangeRings.push(L.circle(ll, { radius: r, className: 'map-range-ring', weight: 1, fill: false, interactive: false })
                    .addTo(rangeLayer));
                rangeRings.push(L.marker(destination(center, 0, r), { interactive: false, keyboard: false,
                    icon: L.divIcon({ className: 'map-range-label', html: el('span', {}, km(r)), iconSize: null }) })
                    .addTo(rangeLayer));
            }
        }
        rangeInfo.textContent = `${src.title}: furthest ${km(far)}, to the ${compass(range.bearing(farBin))}; ` +
            `${rec.samples.toLocaleString()} positions.`;
    }

    function compass(deg) {
        return ['north', 'northeast', 'east', 'southeast', 'south', 'southwest', 'west', 'northwest'][Math.round(deg / 45) % 8];
    }

    // Merge a refresh into the map: move, add, and remove markers in place
    function update(sources, results) {
        const seen = new Set();
        let reporting = 0, history = 0;
        skipped = 0;
        counts.clear();
        for (const { src, list } of results) {
            let n = 0;
            for (const dev of list) {
                const key = dev.key;
                if (!key || seen.has(key))
                    continue;
                const at = positions(src, dev);
                if (dev.rep) {
                    reporting++;
                    if (!legacy && dev.cloud_ts > 0)
                        history++;
                }
                if (!at)
                    continue;
                if (seen.size >= maxMarkers) {
                    skipped++;
                    continue;
                }
                seen.add(key);
                n++;
                place(key, src, dev, at.pos, at.how);
            }
            counts.set(src.id, n);
        }
        for (const [key, e] of entries) {
            if (!seen.has(key))
                drop(key, e);
        }
        if (reporting)
            serverHistory = history > 0;
        showPathNote();
        if (selected && !entries.has(selected))
            select(null);
        if (!fitted && entries.size) {
            fitted = true;
            fitAll();
        }
        layers(sources);
        drawRange();
        render();
    }

    function place(key, src, dev, pos, how) {
        const heardOnly = how !== 'reported';
        const ll = [pos[1], pos[0]];
        let e = entries.get(key);
        if (!e) {
            const glyph = el('span', { class: 'map-marker-glyph' });
            const tip = el('div');
            const node = el('div', { class: 'map-marker' }, glyph);
            const marker = L.marker(ll, {
                icon: L.divIcon({ className: 'map-marker-box', html: node, iconSize: [26, 26], iconAnchor: [13, 13] }),
                keyboard: false,
            }).bindTooltip(tip, { className: 'map-tip', direction: 'top', offset: [0, -12] });
            marker.on('click', () => {
                select(key, false);
                entries.get(key)?.row?.scrollIntoView({ block: 'nearest' });
            });
            marker.on('dblclick', () => openDevice(key));
            marker.addTo(markerLayer);
            e = { key, marker, node, glyph, tip, iconName: null };
            entries.set(key, e);
        } else {
            e.marker.setLatLng(ll);
        }
        Object.assign(e, { src, dev, pos, how, heardOnly, tracked: !heardOnly && src.paths !== false });

        const name = call(src, 'icon', dev, 'gps') || 'gps';
        if (name !== e.iconName) {
            e.glyph.replaceChildren(icon(name));
            e.iconName = name;
        }
        const heading = heardOnly ? null : call(src, 'heading', dev, null);
        e.glyph.style.transform = Number.isFinite(heading) ? `rotate(${heading}deg)` : '';
        e.node.style.setProperty('--marker-color', call(src, 'color', dev, null) || 'var(--accent)');
        e.node.classList.toggle('heard-only', heardOnly);
        e.node.classList.toggle('selected', key === selected);
        e.tip.replaceChildren(el('strong', {}, label(e)), el('br'), detail(e));

        // The line from where Kismet heard it to where it says it is
        const showLink = !heardOnly && dev.heard && (dev.heard[0] !== pos[0] || dev.heard[1] !== pos[1]);
        if (showLink) {
            const hl = [dev.heard[1], dev.heard[0]];
            if (!e.link) {
                e.link = L.polyline([hl, ll], { className: 'map-link', weight: 1.5, dashArray: '4 5', interactive: false })
                    .addTo(linkLayer);
                e.heardDot = L.circleMarker(hl, { className: 'map-heard', radius: 3, weight: 1, interactive: false })
                    .addTo(linkLayer);
            } else {
                e.link.setLatLngs([hl, ll]);
                e.heardDot.setLatLng(hl);
            }
        } else if (e.link) {
            e.link.remove();
            e.heardDot.remove();
            e.link = e.heardDot = null;
        }
        drawPath(e);
    }

    function showPathNote() {
        pathNote.hidden = !showPaths() || serverHistory !== false;
        pathNoteText.textContent = (legacy ? 'This Kismet server is too old to keep the history of where devices say they were, ' :
            'This Kismet server isn\'t keeping the history of where devices say they were, ') +
            'so the paths are collected by this browser.  They only cover the time since the web UI was loaded' +
            (collecting() ? '' : ', and only while the map is shown') +
            ', and reloading the page starts them over.' +
            (legacy ? '' : '  To keep the history on the server, set keep_location_cloud_history=true in the Kismet ' +
                'configuration; it takes more memory for each device.');
    }

    // The faint path every device leaves, from the browser's own collection
    function drawPath(e) {
        const runs = pathMode() === 'all' && e.tracked && tracks.has(e.key) ?
            tracks.segments(tracks.get(e.key)) : [];
        if (!runs.length) {
            e.path?.remove();
            e.path = null;
        } else if (!e.path) {
            e.path = L.polyline(runs, { className: 'map-path', weight: 1.5, interactive: false }).addTo(linkLayer);
        } else {
            e.path.setLatLngs(runs);
        }
        e.path?.getElement()?.style.setProperty('stroke', e.node.style.getPropertyValue('--marker-color'));
    }

    function drop(key, e) {
        e.marker.remove();
        e.link?.remove();
        e.heardDot?.remove();
        e.path?.remove();
        e.row?.remove();
        entries.delete(key);
    }

    function label(e) {
        return String(call(e.src, 'label', e.dev, null) || e.dev.name || e.key);
    }

    function detail(e) {
        const parts = [e.src.title];
        const extra = call(e.src, 'detail', e.dev, null);
        if (extra)
            parts.push(extra);
        if (e.how === 'heard')
            parts.push('where Kismet heard it');
        else if (e.how === 'average')
            parts.push('around where Kismet heard it');
        parts.push(format.ago(e.dev.last_time));
        return parts.join(' · ');
    }

    // One checkbox per kind of device, with how many are on the map
    const layerRows = new Map();
    let layerIds = '';

    function layers(sources) {
        const ids = sources.map((s) => s.id).join(' ');
        if (ids !== layerIds) {
            layerIds = ids;
            layerRows.clear();
            layerList.replaceChildren(...sources.map((src) => {
                const box = el('input', { type: 'checkbox', checked: enabled(src),
                    onchange: () => { settings.set(`map.layers.${src.id}`, box.checked); fetched.clear(); refresh(); } });
                const count = el('span', { class: 'map-layer-count muted' });
                const name = src.layerIcon ?? (typeof src.icon === 'string' ? src.icon : 'gps');
                const rowEl = el('label', { class: 'map-layer' }, box, icon(name), el('span', {}, src.title), count);
                layerRows.set(src.id, { row: rowEl, count });
                return rowEl;
            }));
        }
        for (const src of sources) {
            const { row: rowEl, count } = layerRows.get(src.id);
            count.textContent = enabled(src) ? String(counts.get(src.id) ?? 0) : '';
            rowEl.hidden = !!viewSizes && src.view !== 'all' && !viewSizes.get(src.view) && !counts.get(src.id);
        }

        legends.replaceChildren(...sources.filter((s) => enabled(s) && s.legend && !layerRows.get(s.id).row.hidden).map((s) => {
            try {
                return s.legend();
            } catch {
                return null;
            }
        }).filter(Boolean));
    }

    // The side list, newest first, with the devices inside the view marked
    function render() {
        if (!map)
            return;
        const bounds = map.getBounds();
        const q = search.value.trim().toLowerCase();
        const onlyInView = inViewOnly.checked;
        let inView = 0;
        const shown = [];

        for (const e of entries.values()) {
            const within = bounds.contains([e.pos[1], e.pos[0]]);
            if (within)
                inView++;
            const text = `${label(e)} ${e.key} ${e.dev.type ?? ''} ${detail(e)}`.toLowerCase();
            const match = !q || text.includes(q);
            e.marker.getElement()?.classList.toggle('filtered', !match);
            e.path?.getElement()?.classList.toggle('filtered', !match);
            e.within = within;
            if (match && (within || !onlyInView))
                shown.push(e);
            else
                e.row?.remove();
        }

        // In view first, then by name, so rows don't jump around as devices update
        for (const e of shown)
            e.sortLabel = label(e);
        shown.sort((a, b) => (b.within - a.within) || a.sortLabel.localeCompare(b.sortLabel) || a.key.localeCompare(b.key));
        const rows = shown.slice(0, maxListed).map(row);
        for (const e of shown.slice(maxListed))
            e.row?.remove();
        // Only touch the list when its order changed, so focus and hover survive updates
        const current = list.children;
        if (current.length !== rows.length || rows.some((r, i) => current[i] !== r))
            list.replaceChildren(...rows);

        summary.textContent = (entries.size ?
            `${entries.size} on the map, ${inView} in view${shown.length > maxListed ? `; first ${maxListed} listed` : ''}` :
            'No devices with a position yet') +
            (skipped ? `; ${skipped} more not drawn, over the limit of ${maxMarkers.toLocaleString()}` : '') +
            (legacy ? '.  This Kismet server is older than 2026-10, so it keeps one position for each device: ' +
                'aircraft and vessels are drawn where they say they are, with no line to where they were heard, ' +
                'and other devices where Kismet heard them.' : '');
    }

    function row(e) {
        if (!e.row) {
            e.rowIcon = el('span', { class: 'map-row-icon' });
            e.rowLabel = el('span', { class: 'map-row-label' });
            e.rowDetail = el('span', { class: 'map-row-detail muted' });
            e.row = el('li', { class: 'map-row', tabindex: 0,
                onclick: () => select(e.key, true),
                ondblclick: () => openDevice(e.key),
                onkeydown: (ev) => {
                    if (ev.key === 'Enter')
                        openDevice(e.key);
                },
                onmouseenter: () => e.node.classList.add('hover'),
                onmouseleave: () => e.node.classList.remove('hover') },
            e.rowIcon,
            el('span', { class: 'map-row-text' }, e.rowLabel, e.rowDetail),
            el('button', { class: 'icon-button', title: 'Device details',
                onclick: (ev) => { ev.stopPropagation(); openDevice(e.key); } }, icon('info')));
        }
        if (e.rowIconName !== e.iconName) {
            e.rowIcon.replaceChildren(icon(e.iconName));
            e.rowIconName = e.iconName;
        }
        e.rowIcon.style.color = e.node.style.getPropertyValue('--marker-color');
        e.rowLabel.textContent = label(e);
        e.rowDetail.textContent = detail(e);
        e.row.classList.toggle('in-view', e.within);
        e.row.classList.toggle('selected', e.key === selected);
        return e.row;
    }

    function select(key, pan = true) {
        const old = selected && entries.get(selected);
        old?.node.classList.remove('selected');
        old?.row?.classList.remove('selected');
        trail?.remove();
        trail = null;
        selected = key;
        const e = key && entries.get(key);
        if (!e)
            return;
        e.node.classList.add('selected');
        e.row?.classList.add('selected');
        if (pan)
            map.flyTo([e.pos[1], e.pos[0]], Math.max(map.getZoom(), 9), { duration: 0.6 });
        loadTrail(key);
    }

    // Where the selected device has said it was: the server's location
    // history, when it keeps one, joined with the browser's own path
    async function loadTrail(key) {
        if (pathMode() === 'off') {
            trail?.remove();
            trail = null;
            return;
        }
        let rec = null;
        if (!legacy) {
            try {
                rec = await api.post(`devices/by-key/${encodeURIComponent(key)}/device.json`, {
                    fields: [[`${base}.reported_location_cloud/kis.gps.rrd.samples_100`, 'samples']],
                });
            } catch {
                rec = null;
            }
        }
        if (selected !== key || !map)
            return;
        const e = entries.get(key);
        const local = e?.tracked ? tracks.get(key) : [];
        const since = local.length ? local[0].t : Infinity;
        // The server's history fills in before the browser started collecting
        const older = (Array.isArray(rec?.samples) ? rec.samples : [])
            .map((s) => {
                const p = s['kismet.historic.location.geopoint'];
                const t = s['kismet.historic.location.time_sec'] ?? 0;
                return point(p) && t < since ? { t, lon: p[0], lat: p[1] } : null;
            })
            .filter(Boolean)
            .sort((a, b) => a.t - b.t);
        const all = [...older, ...local];
        if (e?.tracked && !local.length)
            all.push({ t: clock.now(), lon: e.pos[0], lat: e.pos[1] });
        const runs = tracks.segments(all);
        if (!runs.length) {
            trail?.remove();
            trail = null;
            return;
        }
        if (!trail)
            trail = L.polyline(runs, { className: 'map-trail', weight: 2.5, interactive: false }).addTo(linkLayer);
        else
            trail.setLatLngs(runs);
    }

    function fitAll() {
        if (!map)
            return;
        const pts = [...entries.values()].map((e) => [e.pos[1], e.pos[0]]);
        if (selfMarker)
            pts.push(selfMarker.getLatLng());
        if (pts.length === 1)
            map.setView(pts[0], 12);
        else if (pts.length)
            map.fitBounds(pts, { padding: [32, 32], maxZoom: 14 });
    }

    const unwatch = [
        settings.watch('map.tiles', () => applyTiles()),
        settings.watch('map.tileUrl', () => { sessionChoice = null; applyTiles(); askTiles(); }),
        settings.watch('map.tileAttribution', () => { tileLayer?.remove(); tileLayer = null; applyTiles(); }),
        settings.watch('map.darkTiles', applyTheme),
        theme.onChange(applyTheme),
        settings.watch('map.paths', () => {
            pathSelect.value = pathScope();
            for (const e of entries.values())
                drawPath(e);
            if (selected)
                loadTrail(selected);
        }),
        settings.watch('map.showPaths', () => {
            pathBox.checked = showPaths();
            pathSelect.disabled = !showPaths();
            showPathNote();
            for (const e of entries.values())
                drawPath(e);
            if (selected)
                loadTrail(selected);
        }),
        settings.watch('map.pathsCollect', () => {
            showPathNote();
            return collecting() ? startCollecting() : stopCollecting();
        }),
        settings.watch('map.pathsAge', () => tracks.prune(clock.now() - pathAge())),
        mapSources.watch(() => refresh()),
        settings.watch('map.range', () => drawRange()),
        () => { window.removeEventListener('pagehide', flushRange); range.flush(); },
        () => document.removeEventListener('keydown', onKey),
        () => stopExpand?.(),
    ];

    return {
        tools: [expandButton],
        show() {
            visible = true;
            if (!L && !leafletLoad)
                init();
            else {
                map?.invalidateSize();
                askTiles();
                start();
            }
        },
        hide() {
            visible = false;
            if (expanded)
                setExpanded(false);
            stop();
            startCollecting();
        },
        destroy() {
            stop();
            stopCollecting();
            for (const fn of unwatch)
                fn();
            map?.remove();
            root.remove();
        },
    };
}
