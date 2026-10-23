// The Overview tab and its standard cards: device counts, activity, packet
// rates, what kinds of device are around, Wi-Fi security, manufacturers,
// new arrivals, signal strength, the busiest channels, alerts, the top
// talkers, and the data sources.

const base = 'kismet.device.base';

export function register(kismet) {
    const { ui, dom, rrd, format, widgets } = kismet;
    const { el } = dom;
    const { historyGraph } = widgets;
    const { barGraph } = widgets.cellgraphs;
    const { barList, donut, stat, series } = widgets.charts;
    const { frequencyLabel, openCoverage } = widgets.coverage;

    ui.panes.add({
        id: 'overview', title: 'Overview', area: 'main', priority: -10,
        create: (body, area) => widgets.overview.createOverview(body, area),
    });

    const spanLabels = { minute: ['-60s', 'now'], hour: ['-60m', 'now'], day: ['-24h', 'now'] };

    // Minute / hour / day buttons for a graph; the choice is kept per card
    function spanTabs(id, onPick) {
        let span = kismet.settings.get(`overview.span.${id}`, 'hour');
        const buttons = Object.keys(spanLabels).map((s) => el('button', { type: 'button',
            onclick: () => {
                span = s;
                kismet.settings.set(`overview.span.${id}`, s);
                show();
                onPick(s);
            } }, s[0].toUpperCase() + s.slice(1)));
        const show = () => buttons.forEach((b, i) => b.classList.toggle('active', Object.keys(spanLabels)[i] === span));
        show();
        return { node: el('div', { class: 'graph-tabs' }, buttons), get span() { return span; } };
    }

    // A count against the window the devices were counted over
    const windowNote = (data) => `heard in ${widgets.overview.windows.find((w) => w.id === data.window)?.title ?? 'the chosen time'}`;

    ui.dashboardCards.add({
        id: 'devices', title: 'Devices', priority: 0, w: 2, h: 5, needs: ['status'],
        create(body) {
            const total = stat('devices tracked');
            const tabs = spanTabs('devices', () => draw());
            const graph = historyGraph({ type: 'line', unit: 'devices', height: null });
            body.append(total.node, tabs.node, graph.node);
            let last = null;
            function draw() {
                if (!last?.status)
                    return;
                const r = last.status['kismet.system.devices.rrd'];
                graph.draw(rrd.history(r, last.now, tabs.span), spanLabels[tabs.span]);
            }
            return {
                update(data) {
                    last = data;
                    total.update(format.count(data.status?.['kismet.system.devices.count'] ?? 0));
                    draw();
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'active', title: 'Active devices', priority: 10, w: 2, h: 5, needs: ['channels'],
        create(body) {
            const now = stat('heard in the last 30 seconds');
            const tabs = spanTabs('active', () => draw());
            const graph = historyGraph({ type: 'line', unit: 'devices', height: null });
            body.append(now.node, tabs.node, graph.node);
            let last = null;
            // Devices are counted on their main frequency, so adding up the
            // frequencies counts each device once
            function sum(span) {
                const recs = Object.values(last?.channels?.['kismet.channeltracker.frequency_map'] ?? {});
                let out = null;
                for (const rec of recs) {
                    const h = rrd.history(rec['kismet.channelrec.device_rrd'], last.now, span);
                    out = out ? out.map((v, i) => v + (h[i] ?? 0)) : h.slice();
                }
                return out ?? [];
            }
            function draw() {
                if (!last)
                    return;
                graph.draw(sum(tabs.span), spanLabels[tabs.span]);
            }
            return {
                update(data) {
                    last = data;
                    const m = sum('minute');
                    now.update(format.count(Math.round(m.length > 1 ? m[m.length - 2] : 0)));
                    draw();
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'packets', title: 'Packets', priority: 20, w: 2, h: 5, needs: ['packets'],
        create(body) {
            const rate = stat('packets per second');
            const tabs = spanTabs('packets', () => draw());
            const graph = historyGraph({ type: 'bar', unit: 'packets/s', height: null, minBar: true });
            const problems = el('div', { class: 'muted ov-note' });
            body.append(rate.node, tabs.node, graph.node, problems);
            let last = null;
            const p = (name) => last?.packets?.[`kismet.packetchain.${name}`];
            function draw() {
                if (!last?.packets)
                    return;
                graph.draw(rrd.history(p('packets_rrd'), last.now, tabs.span), spanLabels[tabs.span]);
            }
            return {
                update(data) {
                    last = data;
                    if (!data.packets)
                        return;
                    rate.update(format.count(Math.round(rrd.latest(p('packets_rrd'), data.now))));
                    // Problems over the last minute
                    const total = (name) => rrd.history(p(name), data.now).reduce((a, v) => a + v, 0);
                    const parts = [['dropped_packets_rrd', 'dropped'], ['error_packets_rrd', 'with errors'],
                        ['dupe_packets_rrd', 'duplicates']]
                        .map(([n, t]) => [Math.round(total(n)), t]).filter(([v]) => v > 0)
                        .map(([v, t]) => `${format.count(v)} ${t}`);
                    problems.textContent = parts.length ? `Last minute: ${parts.join(', ')}` : '';
                    draw();
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'phys', title: 'Devices by type of radio', priority: 30, w: 3, h: 5, needs: ['phys'],
        create(body, { actions }) {
            const bars = barList({ onPick: (item) => actions.showDevices(`phy-${item.id}`) });
            body.append(bars.node, el('div', { class: 'muted ov-note' }, 'All devices Kismet has seen.  Click one to list them.'));
            return {
                update(data) {
                    bars.update((data.phys ?? []).filter((p) => p['kismet.phy.device_count'] > 0).map((p, i) => ({
                        id: p['kismet.phy.phy_name'], label: p['kismet.phy.phy_name'], value: p['kismet.phy.device_count'],
                        title: `${format.count(p['kismet.phy.packet_count'])} packets`, color: series(i),
                    })));
                },
            };
        },
    });

    // Counts of a field over the device scan, the top n, the rest as "Other"
    function tally(devices, key, n, skip = () => false) {
        const counts = new Map();
        for (const d of devices ?? []) {
            const v = String(d[key] ?? '').trim();
            if (skip(v, d))
                continue;
            counts.set(v, (counts.get(v) ?? 0) + 1);
        }
        const sorted = [...counts].sort((a, b) => b[1] - a[1]);
        const top = sorted.slice(0, n).map(([v, c]) => ({ id: v, label: v, value: c }));
        const rest = sorted.slice(n).reduce((a, [, c]) => a + c, 0);
        if (rest)
            top.push({ id: '\u0000other', label: 'Other', value: rest, color: 'var(--muted)' });
        return top;
    }

    ui.dashboardCards.add({
        id: 'types', title: 'Kinds of device', priority: 40, w: 3, h: 5, needs: ['devices'],
        create(body) {
            const bars = barList();
            const note = el('div', { class: 'muted ov-note' });
            body.append(bars.node, note);
            return {
                update(data) {
                    if (!data.devices)
                        return;
                    bars.update(tally(data.devices, 'type', 8, (v) => !v).map((t, i) => ({ ...t, color: t.color ?? series(i) })));
                    note.textContent = `${format.count(data.devices.length)} devices ${windowNote(data)}`;
                },
            };
        },
    });

    // Wi-Fi security, from the summary the server keeps for each AP
    // (kismet.device.base.crypt, e.g. "WPA2 WPA2-PSK" or "WPA3 WPA3-PSK WPA3-SAE")
    const security = [
        { id: 'open', label: 'Open', color: 'var(--error)' },
        { id: 'wep', label: 'WEP', color: 'color-mix(in srgb, var(--error) 50%, var(--warn))' },
        { id: 'wpa', label: 'WPA (original)', color: 'var(--warn)' },
        { id: 'wpa2', label: 'WPA2', color: 'var(--accent)' },
        { id: 'wpa2e', label: 'WPA2 Enterprise', color: 'color-mix(in srgb, var(--accent) 55%, var(--text))' },
        { id: 'mixed', label: 'WPA2/WPA3', color: 'color-mix(in srgb, var(--accent) 50%, var(--ok))' },
        { id: 'wpa3', label: 'WPA3', color: 'var(--ok)' },
        { id: 'wpa3e', label: 'WPA3 Enterprise', color: 'color-mix(in srgb, var(--ok) 55%, var(--text))' },
        { id: 'other', label: 'Other', color: 'var(--muted)' },
    ];

    function securityOf(crypt) {
        const c = String(crypt ?? '');
        if (c === 'Open')
            return 'open';
        if (c.startsWith('WEP'))
            return 'wep';
        const eap = c.includes('-EAP');
        if (c.includes('WPA3'))
            return c.includes('-PSK') && c.includes('-SAE') ? 'mixed' : (eap ? 'wpa3e' : 'wpa3');
        if (c.includes('WPA2'))
            return eap ? 'wpa2e' : 'wpa2';
        if (/\bWPA1?\b/.test(c))
            return 'wpa';
        return 'other';
    }

    ui.dashboardCards.add({
        id: 'security', title: 'Wi-Fi security', priority: 50, w: 3, h: 5, needs: ['devices'],
        create(body) {
            const chart = donut({ size: 96, centerLabel: 'APs', empty: 'No Wi-Fi access points' });
            body.append(chart.node);
            return {
                update(data) {
                    if (!data.devices)
                        return;
                    const counts = new Map();
                    for (const d of data.devices) {
                        if (d.phy !== 'IEEE802.11' || !String(d.type ?? '').includes('AP') || !d.crypt)
                            continue;
                        const s = securityOf(d.crypt);
                        counts.set(s, (counts.get(s) ?? 0) + 1);
                    }
                    chart.update(security.map((s) => ({ ...s, value: counts.get(s.id) ?? 0 })));
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'manuf', title: 'Top manufacturers', priority: 60, w: 3, h: 5, needs: ['devices'],
        create(body) {
            const bars = barList({ empty: 'No manufacturers known yet' });
            body.append(bars.node);
            return {
                update(data) {
                    if (data.devices)
                        bars.update(tally(data.devices, 'manuf', 8, (v) => !v || v === 'Unknown'));
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'new', title: 'New devices', priority: 70, w: 3, h: 5, needs: ['devices'],
        create(body) {
            const recent = stat('first seen in the last 5 minutes');
            const graph = historyGraph({ type: 'bar', unit: 'new devices', height: null, minBar: true });
            const note = el('div', { class: 'muted ov-note' }, 'First seen, per minute, over the last hour');
            body.append(recent.node, graph.node, note);
            return {
                update(data) {
                    if (!data.devices)
                        return;
                    const now = Math.floor(data.now);
                    const bins = new Array(60).fill(0);
                    let five = 0;
                    for (const d of data.devices) {
                        const ago = now - (d.first ?? 0);
                        if (ago < 0 || ago >= 3600)
                            continue;
                        bins[59 - Math.floor(ago / 60)]++;
                        if (ago < 300)
                            five++;
                    }
                    recent.update(format.count(five));
                    graph.draw(bins, ['-60m', 'now']);
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'channels', title: 'Busiest channels', priority: 80, needs: ['channels'], w: 6, h: 6,
        create(body) {
            let metric = kismet.settings.get('overview.channels.metric', 'devices');
            const buttons = [['devices', 'Devices'], ['packets', 'Packets/s']].map(([id, t]) => el('button', { type: 'button',
                onclick: () => {
                    metric = id;
                    kismet.settings.set('overview.channels.metric', id);
                    show();
                    redraw();
                } }, t));
            const show = () => buttons.forEach((b, i) => b.classList.toggle('active', ['devices', 'packets'][i] === metric));
            show();
            const bars = barList({ onPick: () => openCoverage({ view: 'heat' }),
                fmt: (v) => (v > 0 && v < 10 && v % 1 ? v.toFixed(1) : format.count(Math.round(v))) });
            body.append(el('div', { class: 'graph-tabs' }, buttons), bars.node,
                el('div', { class: 'muted ov-note' }, 'Right now.  Click one for the channel heat map.'));
            let last = null;
            function redraw() {
                if (!last?.channels)
                    return;
                const recs = Object.values(last.channels['kismet.channeltracker.frequency_map'] ?? {});
                const rrdName = metric === 'devices' ? 'kismet.channelrec.device_rrd' : 'kismet.channelrec.packets_rrd';
                const items = recs.map((rec) => {
                    const khz = rec['kismet.channelrec.frequency'];
                    return { id: String(khz), value: rrd.latest(rec[rrdName], last.now),
                        label: `${frequencyLabel(khz, rec['kismet.channelrec.channel'])} (${format.frequency(khz)})` };
                }).filter((i) => i.value > 0).sort((a, b) => b.value - a.value).slice(0, 10);
                bars.update(items);
            }
            return {
                update(data) {
                    last = data;
                    redraw();
                },
            };
        },
    });

    const severities = [
        { id: 'critical', label: 'Critical', min: 15, color: 'var(--error)' },
        { id: 'high', label: 'High', min: 10, color: 'color-mix(in srgb, var(--error) 50%, var(--warn))' },
        { id: 'medium', label: 'Medium', min: 5, color: 'var(--warn)' },
        { id: 'low', label: 'Low', min: -Infinity, color: 'var(--muted)' },
    ];

    ui.dashboardCards.add({
        id: 'alerts', title: 'Alerts, last hour', priority: 75, w: 3, h: 5, needs: ['alerts'],
        create(body, { actions }) {
            const bars = barList({ onPick: () => actions.showTab('alerts'), empty: 'No alerts in the last hour' });
            const graph = historyGraph({ type: 'bar', unit: 'alerts', height: null, minBar: true });
            body.append(bars.node, graph.node, el('div', { class: 'muted ov-note' }, 'Per 5 minutes.  Click for the alerts.'));
            return {
                update(data) {
                    const list = data.alerts ?? [];
                    const counts = new Map();
                    const bins = new Array(12).fill(0);
                    for (const a of list) {
                        const sev = severities.find((s) => (a['kismet.alert.severity'] ?? 0) >= s.min);
                        counts.set(sev.id, (counts.get(sev.id) ?? 0) + 1);
                        const ago = data.now - (a['kismet.alert.timestamp'] ?? 0);
                        if (ago >= 0 && ago < 3600)
                            bins[11 - Math.floor(ago / 300)]++;
                    }
                    bars.update(severities.filter((s) => counts.get(s.id)).map((s) => ({ ...s, value: counts.get(s.id) })));
                    graph.draw(bins, ['-60m', 'now']);
                },
            };
        },
    });

    // Signal strength across the devices in the window: who's close, who's at
    // the edge of range.  Only dBm readings; some phys report RSSI instead.
    const signalBins = { low: -100, high: -20, step: 5 };
    const nearby = -60, edge = -85;

    ui.dashboardCards.add({
        id: 'signal', title: 'Signal strength', priority: 72, w: 3, h: 5, needs: ['devices'],
        create(body) {
            const counts = el('div', { class: 'ov-signal-counts' });
            const near = stat(`nearby (stronger than ${nearby} dBm)`);
            const far = stat(`at the edge (weaker than ${edge} dBm)`);
            counts.append(near.node, far.node);
            const graph = historyGraph({ type: 'bar', unit: '', height: null, minBar: true });
            const note = el('div', { class: 'muted ov-note' }, 'Devices by their last signal, in 5 dBm steps');
            body.append(counts, graph.node, note);
            return {
                update(data) {
                    if (!data.devices)
                        return;
                    const n = (signalBins.high - signalBins.low) / signalBins.step;
                    const bins = new Array(n).fill(0);
                    let close = 0, weak = 0;
                    for (const d of data.devices) {
                        const s = d.signal;
                        if (d.sigtype !== 'dbm' || !s || s >= 0)
                            continue;
                        const i = Math.min(n - 1, Math.max(0, Math.floor((s - signalBins.low) / signalBins.step)));
                        bins[i]++;
                        if (s > nearby)
                            close++;
                        else if (s < edge)
                            weak++;
                    }
                    near.update(format.count(close));
                    far.update(format.count(weak));
                    graph.draw(bins, bins.map((_v, i) => (i % 4 === 0 ? `${signalBins.low + i * signalBins.step}` : '')));
                },
            };
        },
    });

    // The devices sending the most right now: packets per second over the
    // last 10 seconds, with the last minute as bars
    const talkersShown = 10;

    ui.dashboardCards.add({
        id: 'talkers', title: 'Top talkers', priority: 85, w: 6, h: 6, needs: ['talkers'],
        create(body) {
            const list = el('ol', { class: 'ov-talkers' });
            const note = el('div', { class: 'muted ov-note' }, 'Packets per second over the last 10 seconds');
            body.append(list, note);
            const rows = new Map();
            return {
                update(data) {
                    const ranked = (data.talkers ?? []).map((d) => {
                        const minute = rrd.history({ 'kismet.common.rrd.minute_vec': d.pps,
                            'kismet.common.rrd.last_time': d.ppst }, data.now);
                        // The current second is still filling; rate over the 10 before it
                        const recent = minute.slice(-11, -1);
                        const rate = recent.reduce((a, b) => a + b, 0) / Math.max(1, recent.length);
                        return { d, minute, rate };
                    }).filter((t) => t.rate > 0)
                        .sort((a, b) => b.rate - a.rate)
                        .slice(0, talkersShown);

                    const order = ranked.map(({ d, minute, rate }) => {
                        const key = d[`${base}.key`];
                        let r = rows.get(key);
                        if (!r) {
                            r = { name: el('a', { href: '#', class: 'ov-talker-name',
                                onclick: (e) => { e.preventDefault(); ui.openDevice(key); } }),
                            type: el('span', { class: 'ov-talker-type muted' }), graph: el('span', { class: 'ov-talker-graph' }),
                            rate: el('span', { class: 'ov-talker-rate' }) };
                            r.node = el('li', { class: 'ov-talker' }, r.name, r.type, r.graph, r.rate);
                            rows.set(key, r);
                        }
                        const mac = d[`${base}.macaddr`];
                        const name = d[`${base}.commonname`];
                        r.name.textContent = name && name !== mac ? name : mac;
                        r.name.title = `${name && name !== mac ? `${name} (${mac})` : mac}: open this device`;
                        r.type.textContent = d[`${base}.type`] || d[`${base}.phyname`] || '';
                        r.rate.textContent = `${rate >= 10 ? format.count(Math.round(rate)) : rate.toFixed(1)}/s`;
                        r.graph.replaceChildren(barGraph(minute.length ? minute : new Array(60).fill(0),
                            { title: 'Packets per second over the last minute' }));
                        return r.node;
                    });
                    const shown = new Set(ranked.map((t) => t.d[`${base}.key`]));
                    for (const [key, r] of rows)
                        if (!shown.has(key))
                            rows.delete(key);
                    list.replaceChildren(...order);
                    if (!order.length)
                        list.replaceChildren(el('li', { class: 'muted' }, 'Nothing heard in the last 10 seconds'));
                },
            };
        },
    });

    ui.dashboardCards.add({
        id: 'sources', title: 'Data sources', priority: 100, needs: ['sources'], w: 6, h: 6,
        create(body) {
            const list = el('ul', { class: 'ov-sources' });
            body.append(list);
            const rows = new Map();
            return {
                update(data) {
                    const srcs = data.sources ?? [];
                    const keep = new Set();
                    const seen = new Map();
                    for (const s of srcs) {
                        // Sources reading the same file share a UUID; keep each one
                        const uuid = s['kismet.datasource.uuid'];
                        const nth = seen.get(uuid) ?? 0;
                        seen.set(uuid, nth + 1);
                        const id = `${uuid}/${nth}`;
                        keep.add(id);
                        let r = rows.get(id);
                        // A tile per source: name and rate, state, the last minute
                        // as bars (quiet seconds still get a sliver), and totals
                        if (!r) {
                            r = { name: el('span', { class: 'ov-source-name' }), rate: el('span', { class: 'ov-source-rate' }),
                                state: el('span', { class: 'ov-source-state muted' }), graph: el('span', { class: 'ov-source-graph' }),
                                count: el('span', { class: 'ov-source-count muted' }) };
                            r.node = el('li', { class: 'ov-source' }, el('span', { class: 'ov-source-head' }, r.name, r.rate),
                                r.state, r.graph, r.count);
                            rows.set(id, r);
                        }
                        const running = s['kismet.datasource.running'];
                        const err = s['kismet.datasource.error'];
                        r.name.textContent = s['kismet.datasource.name'];
                        r.state.textContent = err ? `Error: ${s['kismet.datasource.error_reason'] || 'failed'}` :
                            !running ? 'Not running' :
                                s['kismet.datasource.hopping'] ? `Hopping ${(s['kismet.datasource.hop_channels'] ?? []).length} channels` :
                                    `On ${s['kismet.datasource.channel'] || 'no channel'}`;
                        r.node.classList.toggle('error', !!err);
                        const minute = rrd.history(s['kismet.datasource.packets_rrd'], data.now);
                        const now = rrd.latest(s['kismet.datasource.packets_rrd'], data.now);
                        r.rate.textContent = `${format.count(Math.round(now))}/s`;
                        r.graph.replaceChildren(barGraph(minute.length ? minute : new Array(60).fill(0),
                            { title: `Packets per second over the last minute; ${format.count(Math.round(now))}/s now` }));
                        const errs = s['kismet.datasource.num_error_packets'] ?? 0;
                        const drops = s['kismet.datasource.num_dropped_packets'] ?? 0;
                        r.count.textContent = `${format.count(s['kismet.datasource.num_packets'] ?? 0)} packets` +
                            (errs ? `, ${format.count(errs)} errors` : '') + (drops ? `, ${format.count(drops)} dropped` : '');
                        list.append(r.node);
                    }
                    for (const [id, r] of rows) {
                        if (!keep.has(id)) {
                            r.node.remove();
                            rows.delete(id);
                        }
                    }
                    if (!srcs.length)
                        list.replaceChildren(el('li', { class: 'muted' }, 'No data sources'));
                    else
                        list.querySelector(':scope > li.muted')?.remove();
                },
            };
        },
    });
}
