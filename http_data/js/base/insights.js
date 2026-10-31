// The Insights tab: the devices heard lately as a graph of how they relate,
// their rhythm over the last hour, and the unusual things in both.  Phy
// modules add relations and findings (js/registry/insights.js); this file
// reads the devices, runs them, and adds the findings that hold for any phy.

import { flow } from '../widgets/insights/flow.js';
import { apCards } from '../widgets/insights/apcards.js';
import { rhythm as rhythmView } from '../widgets/insights/rhythm.js';
import * as model from '../widgets/insights/model.js';

const base = 'kismet.device.base';
const windows = [[300, '5 minutes'], [900, '15 minutes'], [3600, 'hour']];
const maxDevices = 500;

export function register(kismet) {
    const { ui, api, dom, settings, clock, rrd, format, icons } = kismet;
    const { el } = dom;

    // A device whose signal rose sharply over the last minute is coming closer
    ui.insightFindings.add({
        id: 'closer',
        find({ graph, now }) {
            const out = [];
            for (const n of graph.nodes.values()) {
                const h = rrd.history(n.rec?.['kismet.common.signal.signal_rrd'], now, 'minute').slice(0, -1);
                const heard = h.map((v, i) => [i, v]).filter(([, v]) => v < 0);
                if (heard.length < 12)
                    continue;
                const early = heard.slice(0, 5), late = heard.slice(-5);
                if (late[0][0] - early[early.length - 1][0] < 20)
                    continue;
                const avg = (a) => a.reduce((s, [, v]) => s + v, 0) / a.length;
                const rise = avg(late) - avg(early);
                if (rise < 15)
                    continue;
                out.push({
                    id: `closer:${n.key}`, severity: 'medium',
                    title: `${n.label} is coming closer`,
                    text: `Its signal rose ${Math.round(rise)} dB in the last minute, to ${Math.round(avg(late))} dBm.  ` +
                        'Signal that climbs this quickly usually means the device is moving toward you (or you toward it).',
                    devices: [n.key],
                });
            }
            return out;
        },
    });

    // Kismet's own alerts, on the devices they name
    const zero = '00:00:00:00:00:00';
    ui.insightFindings.add({
        id: 'alerts',
        find({ graph, alerts = [] }) {
            // Alerts a phy's own finding already explains
            const covered = new Set(ui.insightFindings.list().flatMap((f) => f.alerts ?? []));
            const groups = new Map();
            for (const a of alerts) {
                if (/^SOURCE/.test(a['kismet.alert.header']) || a['kismet.alert.class'] === 'SYSTEM' ||
                        covered.has(a['kismet.alert.header']))
                    continue;
                const nodes = new Set();
                const byKey = graph.nodes.get(a['kismet.alert.device_key']);
                if (byKey)
                    nodes.add(byKey);
                for (const f of ['transmitter_mac', 'source_mac', 'dest_mac', 'other_mac']) {
                    const mac = a[`kismet.alert.${f}`];
                    const n = mac && mac !== zero ? graph.byMac.get(mac.toUpperCase()) : null;
                    if (n)
                        nodes.add(n);
                }
                // alerts about no device here stay in the Alerts tab
                if (!nodes.size)
                    continue;
                const id = `${a['kismet.alert.header']}|${[...nodes].map((n) => n.id).sort().join()}`;
                const g = groups.get(id) ?? { alerts: [], nodes };
                g.alerts.push(a);
                groups.set(id, g);
            }
            const out = [];
            for (const [id, g] of groups) {
                const last = g.alerts.reduce((m, a) => (a['kismet.alert.timestamp'] > m['kismet.alert.timestamp'] ? a : m));
                const sev = Math.max(...g.alerts.map((a) => a['kismet.alert.severity'] ?? 0));
                for (const n of g.nodes)
                    if (!n.flags.includes('alert'))
                        n.flags.push('alert');
                out.push({
                    id: `alert:${id}`, severity: sev >= 15 ? 'high' : sev >= 10 ? 'medium' : 'info',
                    title: `Kismet alert ${last['kismet.alert.header']}` + (g.alerts.length > 1 ? ` (${g.alerts.length} times)` : ''),
                    text: last['kismet.alert.text'], devices: [...g.nodes].map((n) => n.key).filter(Boolean),
                });
            }
            return out;
        },
    });

    ui.panes.add({
        id: 'insights', title: 'Insights', area: 'main', priority: 50,
        create(body, area) {
            let view = settings.get('insights.tab', 'flow');
            let wanted = view;
            let win = settings.get('insights.window', 900);
            let graph = null;
            let records = [];
            let found = [];
            let timer = null;
            let showing = false;
            let rhythmMinute = -1;
            let rhythmKeys = '';

            const pick = (key) => ui.openDevice(key);
            const flowView = flow({ linkKinds: ui.linkKinds, onPick: pick });
            const cardsView = apCards({ linkKinds: ui.linkKinds, onPick: pick });
            const rh = rhythmView({ onPick: pick });
            const unusual = el('div', { class: 'in-unusual' });
            const status = el('span', { class: 'muted in-status' });

            const tabs = el('div', { class: 'graph-tabs in-tabs', role: 'tablist' });
            const tabButtons = {};
            const views = { flow: flowView.node, aps: cardsView.node, rhythm: rh.node, unusual };
            const titles = { flow: 'Flow', aps: 'Access points', rhythm: 'Rhythm', unusual: 'Unusual' };
            for (const id of Object.keys(views)) {
                tabButtons[id] = el('button', { type: 'button', onclick: () => setView(id) }, titles[id]);
                tabs.append(tabButtons[id]);
            }
            const winSel = el('select', { onchange: () => {
                win = +winSel.value;
                settings.set('insights.window', win);
                read();
            } }, ...windows.map(([s, t]) => el('option', { value: s, selected: s === win }, `Last ${t}`)));
            const bar = el('div', { class: 'in-bar' }, tabs, winSel, status);
            const stage = el('div', { class: 'in-stage' }, ...Object.values(views));
            body.classList.add('insights');
            body.append(bar, stage);

            // Fills the window with the tab's area, like the map
            let expanded = false;
            const expandButton = el('button', { class: 'icon-button tab-tool',
                onclick: () => area?.setExpanded(!expanded) });
            function showExpanded(on) {
                expanded = on;
                expandButton.replaceChildren(icons.icon(on ? 'collapse' : 'expand'));
                expandButton.title = on ? 'Back to the dashboard (Esc)' : 'Fill the window with the insights';
                expandButton.setAttribute('aria-pressed', on ? 'true' : 'false');
            }
            showExpanded(false);
            const stopExpand = area?.onExpand(showExpanded);

            function onKey(e) {
                if (!expanded || !showing || e.key !== 'Escape' || e.defaultPrevented)
                    return;
                if (document.querySelector('dialog[open], .menu-list:not([hidden])'))
                    return;
                if (e.target.matches?.('input, textarea, select') && e.target.value)
                    return;
                e.preventDefault();
                area.setExpanded(false);
            }
            document.addEventListener('keydown', onKey);

            // views phy modules add, after the built-in ones
            const extra = new Map();
            const ctx = { api, openDevice: pick, showing: () => showing };
            function addViews() {
                for (const v of ui.insightViews.list()) {
                    if (extra.has(v.id) || views[v.id])
                        continue;
                    const node = el('div', { class: 'in-view', hidden: true });
                    let handle = null;
                    try {
                        handle = v.create(node, ctx);
                    } catch (err) {
                        console.error(`insight view ${v.id} failed:`, err);
                        continue;
                    }
                    extra.set(v.id, handle);
                    views[v.id] = node;
                    stage.append(node);
                    tabButtons[v.id] = el('button', { type: 'button', onclick: () => setView(v.id) }, v.title);
                    tabButtons.unusual.before(tabButtons[v.id]);
                }
                // the view last shown may be one that registered after the tab was built
                if (wanted && extra.has(wanted)) {
                    setView(wanted);
                    wanted = null;
                }
            }

            function setView(id) {
                view = views[id] ? id : 'flow';
                settings.set('insights.tab', view);
                for (const [k, v] of Object.entries(views))
                    v.hidden = k !== view;
                for (const [k, b] of Object.entries(tabButtons)) {
                    b.classList.toggle('active', k === view);
                    b.setAttribute('aria-pressed', String(k === view));
                }
                if (view === 'rhythm')
                    updateRhythm(true);
                for (const [id, h] of extra) {
                    if (id === view && showing)
                        h.show?.();
                    else
                        h.hide?.();
                }
            }

            async function updateRhythm(force = false) {
                const now = clock.isKnown() ? clock.now() : Date.now() / 1000;
                const minute = Math.floor(now / 60);
                const keys = records.map((r) => r[`${base}.key`]).join();
                // the hour columns change once a minute; don't re-cluster in between
                if (!force && minute === rhythmMinute && keys === rhythmKeys)
                    return;
                rhythmMinute = minute;
                rhythmKeys = keys;
                // which sources heard each device, and when each was delivering
                // packets, so a stopped source isn't read as devices leaving
                let listen = new Map();
                try {
                    const wanted = records.filter((r) => rrd.history(r[`${base}.packets.rrd`], now, 'hour').some((v) => v > 0))
                        .map((r) => r[`${base}.key`]);
                    const [sources, seen] = await Promise.all([
                        api.post('datasource/all_sources.json', { fields: ['kismet.datasource.uuid', 'kismet.datasource.packets_rrd'] }),
                        wanted.length ? api.post('devices/multikey/devices.json', {
                            devices: wanted, fields: [`${base}.key`, `${base}.seenby`] }) : [],
                    ]);
                    const seenby = new Map(seen.map((d) => [d[`${base}.key`],
                        (d[`${base}.seenby`] ?? []).map((sb) => sb['kismet.common.seenby.uuid'])]));
                    listen = model.listening(sources, seenby, now);
                } catch (err) {
                    console.error('Could not read which sources heard each device:', err);
                }
                rh.update(model.rhythm(records, now, { listen }));
            }

            // The element the findings scroll in: the tab itself, or the page around it on a phone
            function scroller() {
                for (let e = unusual; e; e = e.parentElement)
                    if (e.scrollHeight > e.clientHeight && /auto|scroll/.test(getComputedStyle(e).overflowY))
                        return e;
                return document.scrollingElement;
            }

            // Redraw only when the findings change, keeping the reader's place
            let unusualShown = null;
            function renderUnusual() {
                const sev = { high: 'High', medium: 'Worth a look', info: 'Good to know' };
                const rank = { high: 0, medium: 1, info: 2 };
                const label = (k) => graph?.nodes.get(k)?.label ?? k;
                const rows = [...found].sort((a, b) => (rank[a.severity] ?? 3) - (rank[b.severity] ?? 3) ||
                    (b.devices?.length ?? 0) - (a.devices?.length ?? 0) || String(a.id).localeCompare(String(b.id)));
                const signature = JSON.stringify(rows.map((f) => [f.id, f.severity, f.title, f.text,
                    (f.devices ?? []).slice(0, 8).map((k) => [k, label(k)]), f.devices?.length ?? 0]));
                if (signature === unusualShown)
                    return;
                unusualShown = signature;
                // the first finding in view, and where it sits, to put back after the redraw
                const box = scroller();
                const boxTop = () => (box === document.scrollingElement ? 0 : box.getBoundingClientRect().top);
                const first = [...unusual.querySelectorAll('tr[data-id]')].find((tr) => tr.getBoundingClientRect().bottom > boxTop());
                const anchor = first ? { id: first.dataset.id, at: first.getBoundingClientRect().top - boxTop() } : null;
                if (!found.length) {
                    unusual.replaceChildren(el('p', { class: 'muted' }, 'Nothing unusual among the devices heard in this window.'));
                    return;
                }
                unusual.replaceChildren(el('table', { class: 'in-utable' },
                    el('thead', {}, el('tr', {}, el('th', {}, 'Severity'), el('th', {}, 'Finding'), el('th', { class: 'in-u-text' }, 'Details'),
                        el('th', {}, 'Devices'))),
                    el('tbody', {}, ...rows.map((f) => {
                        const devs = f.devices ?? [];
                        return el('tr', { class: `sev-${f.severity}`, dataset: { id: String(f.id) } },
                            el('td', { class: 'in-u-sev' }, sev[f.severity] ?? f.severity),
                            el('td', { class: 'in-u-title' }, f.title, el('span', { class: 'in-u-inline muted' }, f.text)),
                            el('td', { class: 'in-u-text' }, f.text),
                            el('td', { class: 'in-u-devs' },
                                ...devs.slice(0, 8).map((k) => {
                                    // access points go by their network's name; the address tells them apart
                                    const n = graph?.nodes.get(k);
                                    const tail = n?.mac && n.label !== n.mac ? n.mac.slice(-5) : null;
                                    return el('button', { type: 'button', class: 'link-button', title: n?.mac ?? null, onclick: () => pick(k) },
                                        label(k), tail ? el('span', { class: 'muted' }, ` ${tail}`) : null);
                                }),
                                devs.length > 8 ? el('span', { class: 'muted' }, `and ${format.count(devs.length - 8)} more`) : null));
                    }))));
                const again = anchor && [...unusual.querySelectorAll('tr[data-id]')].find((tr) => tr.dataset.id === anchor.id);
                if (again && box)
                    box.scrollTop += again.getBoundingClientRect().top - boxTop() - anchor.at;
            }

            async function read() {
                clearTimeout(timer);
                if (!showing)
                    return;
                try {
                    const relations = ui.insightRelations.list();
                    const finders = ui.insightFindings.list();
                    const fields = model.fieldsFor(relations, finders);
                    const [devices, alerts] = await Promise.all([
                        api.post(`devices/views/all/last-time/${-win}/devices.json`, { fields }),
                        api.get(`alerts/last-time/${-win}/alerts.json`).catch(() => []),
                    ]);
                    let list = devices;
                    if (list.length > maxDevices)
                        list = list.sort((a, b) => b[`${base}.last_time`] - a[`${base}.last_time`]).slice(0, maxDevices);
                    records = list;
                    graph = model.buildGraph(records, relations, graph);
                    const now = clock.isKnown() ? clock.now() : Date.now() / 1000;
                    found = model.findAll({ records, graph, now, alerts }, finders);
                    flowView.update(graph, found);
                    cardsView.update(graph, found);
                    renderUnusual();
                    if (view === 'rhythm')
                        updateRhythm();
                    extra.get(view)?.update?.({ records, graph, now, alerts, findings: found });
                    const high = found.filter((f) => f.severity === 'high').length;
                    tabButtons.unusual.textContent = found.length ? `Unusual (${found.length})` : 'Unusual';
                    tabButtons.unusual.classList.toggle('alerting', high > 0);
                    status.textContent = `${format.count(records.length)} devices, ${format.count(graph.links.length)} links` +
                        (list.length >= maxDevices ? ` (the ${maxDevices} heard most recently)` : '');
                } catch (err) {
                    status.textContent = `Could not read the devices: ${err.message}`;
                }
                timer = setTimeout(read, 3000);
            }

            setView(view);
            addViews();
            const offViews = ui.insightViews.watch(addViews);
            return {
                tools: area ? [expandButton] : [],
                show() {
                    showing = true;
                    setView(view);
                    read();
                },
                hide() {
                    showing = false;
                    clearTimeout(timer);
                    if (expanded)
                        area.setExpanded(false);
                },
                destroy() {
                    showing = false;
                    clearTimeout(timer);
                    offViews?.();
                    stopExpand?.();
                    document.removeEventListener('keydown', onKey);
                    flowView.destroy();
                    rh.destroy();
                    for (const h of extra.values())
                        h.destroy?.();
                },
            };
        },
    });
}
