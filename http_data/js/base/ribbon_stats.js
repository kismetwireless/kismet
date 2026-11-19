// The standard stats in the top ribbon.  All of them are fed by the eventbus
// websocket; only the datasource and alert counts load a starting value over
// HTTP, and load it again whenever the websocket reconnects.

export function register(kismet) {
    const { ui, eventbus, api, format, rrd, dom, icons } = kismet;
    const { el } = dom;
    // The battery stat is marked at or below this charge
    const lowBattery = 20;

    // A stat that shows one value with an icon
    function valueStat(name) {
        const value = el('span', { class: 'stat-value' }, '-');
        return { node: el('span', { class: 'stat-line' }, icons.icon(name), value), value };
    }

    ui.ribbonStats.add({
        id: 'packets', title: 'Packets', priority: 0,
        description: 'Packets per second, over the last minute; click for the packet rates',
        create(body) {
            const spark = kismet.widgets.sparkline();
            const v = valueStat('packets');
            // Room for up to 99,999/s, so the entry keeps its width as the rate changes
            v.value.classList.add('stat-value-pps');
            body.append(el('div', { class: 'stat-graph' }, spark.canvas), v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            stat.title = 'Show the packet rates';
            stat.addEventListener('click', () => kismet.widgets.packetgraphs.openPackets());
            let now = 0;
            const stopTime = eventbus.subscribe('TIMESTAMP', ['kismet.system.timestamp.sec'], (e) => {
                now = e['kismet.system.timestamp.sec'];
            });
            const stop = eventbus.subscribe('PACKETCHAIN_STATS',
                [['kismet.packetchain.packets_rrd', 'packets']], (e) => {
                    if (document.visibilityState === 'hidden')
                        return;
                    const history = rrd.history(e.packets, now || undefined);
                    spark.draw(history.slice(0, -1));
                    v.value.textContent = `${format.count(rrd.latest(e.packets, now || undefined))}/s`;
                });
            return () => { stop(); stopTime(); spark.destroy(); };
        },
    });

    ui.ribbonStats.add({
        id: 'devices', title: 'Devices', priority: 10,
        create(body) {
            const v = valueStat('device');
            body.append(v.node);
            return eventbus.subscribe('STATISTICS', ['kismet.system.devices.count'], (e) => {
                v.value.textContent = format.count(e['kismet.system.devices.count']);
            });
        },
    });

    ui.ribbonStats.add({
        id: 'sources', title: 'Sources', priority: 20,
        description: 'Data sources running, and any with errors; click for the data sources',
        create(body) {
            const v = valueStat('source');
            body.append(v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            stat.title = 'Show the data sources';
            stat.addEventListener('click', () => kismet.widgets.datasources.openSources());
            const fields = ['kismet.datasource.uuid', 'kismet.datasource.running', 'kismet.datasource.error'];

            async function update() {
                try {
                    const sources = await api.post('datasource/all_sources.json', { fields });
                    const running = sources.filter((s) => s['kismet.datasource.running']).length;
                    const errors = sources.filter((s) => s['kismet.datasource.error']).length;
                    dom.replace(v.value, `${running}/${sources.length}`,
                        errors ? el('span', { class: 'badge error', title: `${errors} with errors` }, errors) : null);
                } catch {
                    v.value.textContent = '?';
                }
            }

            const refresh = dom.debounce(500, update);
            const topics = ['NEW_DATASOURCE', 'DATASOURCE_OPENED', 'DATASOURCE_CLOSED', 'DATASOURCE_ERROR'];
            const stops = topics.map((t) => eventbus.subscribe(t, null, refresh));
            stops.push(eventbus.onState((up) => up && refresh()));
            update();
            return () => stops.forEach((s) => s());
        },
    });

    ui.ribbonStats.add({
        id: 'alerts', title: 'Alerts', priority: 30,
        description: 'Alerts since the server started; click for the alerts',
        create(body) {
            const v = valueStat('alert');
            body.append(v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            stat.title = 'Show the alerts';
            stat.addEventListener('click', () => kismet.widgets.panes.showPane('alerts'));
            let count = 0;
            const show = () => {
                dom.replace(v.value, count ? el('span', { class: 'badge alert' }, format.count(count)) : '0');
            };
            const timeOf = (a) => a['kismet.alert.timestamp'] ?? 0;

            // Loaded again after every reconnect, since alerts raised while the connection
            // was down (or a restarted server) leave the running count wrong.  Live alerts
            // that arrive during the load count only if they're newer than the list.
            let pending = null;
            let generation = 0;
            async function load() {
                const gen = ++generation;
                pending = [];
                try {
                    const r = await api.get('alerts/wrapped/last-time/0/alerts.json');
                    if (gen !== generation)
                        return;
                    const list = r['kismet.alert.list'] ?? [];
                    const newest = list.reduce((t, a) => Math.max(t, timeOf(a)), 0);
                    count = list.length + pending.filter((t) => t > newest).length;
                    show();
                } catch {
                    if (gen === generation)
                        v.value.textContent = '?';
                } finally {
                    if (gen === generation)
                        pending = null;
                }
            }

            const stop = eventbus.subscribe('ALERT', ['kismet.alert.timestamp'], (e) => {
                if (pending) {
                    pending.push(timeOf(e));
                    return;
                }
                count++;
                show();
            });
            const stopState = eventbus.onState((up) => up && load());
            load();
            return () => { stop(); stopState(); generation++; };
        },
    });

    ui.ribbonStats.add({
        id: 'memory', title: 'Memory', priority: 40,
        description: 'Memory used by the Kismet server; click for the memory window',
        create(body) {
            const v = valueStat('memory');
            body.append(v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            stat.title = 'Show the memory window';
            stat.addEventListener('click', () => kismet.widgets.memory.openMemory());
            return eventbus.subscribe('STATISTICS', ['kismet.system.memory.rss'], (e) => {
                // 0 where the server can't read its memory use (no /proc)
                const kb = e['kismet.system.memory.rss'];
                v.value.textContent = kb ? format.size(kb * 1024) : 'n/a';
            });
        },
    });

    ui.ribbonStats.add({
        id: 'cpu', title: 'CPU', priority: 42,
        description: 'CPU load of the system, and of the Kismet server, over the last minute; click for the CPU window',
        create(body) {
            const spark = kismet.widgets.sparkline({ max: 100 });
            const v = valueStat('cpu');
            v.value.textContent = '---';
            body.append(el('div', { class: 'stat-graph' }, spark.canvas), v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            const open = () => kismet.widgets.cpu.openCpu();
            stat.addEventListener('click', open);
            const pct = (p) => `${p < 10 ? p.toFixed(1) : Math.round(p)}%`;
            let history = [];

            // A minute of history to start the graph with; servers without it start empty
            api.get('system/cpu.json').then((c) => {
                const h = rrd.history(c['kismet.system.cpu.total_rrd'], undefined, 'minute', { blank: null })
                    .slice(0, -1).filter((x) => x !== null);
                if (!history.length)
                    history = h;
                spark.draw(history);
            }).catch(() => {});

            const stop = eventbus.subscribe('STATISTICS',
                ['kismet.system.cpu.available', 'kismet.system.cpu.total', 'kismet.system.cpu.kismet'], (e) => {
                    // Older servers send none of these; 0 where it can't be read (no /proc)
                    if (!e['kismet.system.cpu.available']) {
                        v.value.textContent = '---';
                        stat.title = 'The server can\'t read its CPU load';
                        return;
                    }
                    const total = e['kismet.system.cpu.total'];
                    const kis = e['kismet.system.cpu.kismet'];
                    history = [...history, total].slice(-60);
                    v.value.textContent = `${pct(total)} / ${pct(kis)}`;
                    stat.title = `System: ${pct(total)} of the CPUs\nKismet: ${pct(kis)}`;
                    if (document.visibilityState !== 'hidden')
                        spark.draw(history);
                });
            return () => { stop(); spark.destroy(); stat.removeEventListener('click', open); };
        },
    });

    ui.ribbonStats.add({
        id: 'thermal', title: 'Sensors', priority: 45,
        description: 'Temperatures of the Kismet server and its data sources: the hottest sensor, or the ones ' +
            'chosen below; click for the environment window',
        create(body) {
            const { environment, envdata } = kismet.widgets;
            const v = valueStat('thermometer');
            v.value.textContent = '---';
            body.append(v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            const open = () => environment.openEnvironment('thermal');
            stat.addEventListener('click', open);
            // id -> { value, last_time, source }: every thermal sensor from the ENVIRONMENT
            // event, or the server's own from THERMAL on servers without it
            let temps = {};
            let fromEnv = false;
            let labels = {};
            // How old a data source's reading may get, from the server's report interval
            let sourceLimit = envdata.fallbackSourceStale;
            const relabel = () => environment.load(60).then((d) => {
                labels = Object.fromEntries(d.sensors.map((s) => [s.id, envdata.fullLabel(s)]));
                sourceLimit = d.sourceStale;
                show();
            }).catch(() => {});
            const label = (id) => labels[id] ?? id;
            const now = () => (kismet.clock.isKnown() ? kismet.clock.now() : NaN);
            const current = (id) => temps[id] &&
                !envdata.stale({ ...temps[id], kind: 'thermal' }, now(), null, sourceLimit) ? temps[id] : null;
            // The sensors chosen in settings, or the hottest when none are
            const show = () => {
                const chosen = kismet.settings.get('ribbon.thermal', []);
                if (chosen.length) {
                    const read = chosen.filter((id) => current(id));
                    v.value.textContent = read.length ? read.map((id) => format.temperature(temps[id].value)).join(' · ') : '---';
                    stat.title = [...(read.length ? read.map((id) => `${label(id)}: ${format.temperature(temps[id].value, 1)}`) :
                        ['The chosen sensors aren\'t being read']), 'Click for the environment window'].join('\n');
                    return;
                }
                const hot = Object.keys(temps).filter((id) => current(id))
                    .reduce((a, id) => (!a || temps[id].value > temps[a].value ? id : a), null);
                v.value.textContent = hot ? format.temperature(temps[hot].value) : '---';
                stat.title = hot ? `Hottest: ${label(hot)}\nClick for the environment window` :
                    'No temperature sensors; click for the environment window';
            };
            relabel();
            const stopEnv = eventbus.subscribe('ENVIRONMENT', ['kismet.system.environment.sensors'], (e) => {
                fromEnv = true;
                const all = envdata.readings(e);
                temps = Object.fromEntries(Object.entries(all).filter(([, r]) => r.kind === 'thermal'));
                if (Object.keys(temps).some((id) => !(id in labels)))
                    relabel();
                show();
            });
            const stopThermal = eventbus.subscribe('THERMAL', ['kismet.system.sensors.temp'], (e) => {
                if (fromEnv)
                    return;
                const at = now();
                temps = Object.fromEntries(Object.entries(e['kismet.system.sensors.temp'] ?? {})
                    .filter(([, c]) => Number.isFinite(c)).map(([id, c]) => [id, { value: c, last_time: at, source: '' }]));
                show();
            });
            // Readings from before a dropped connection aren't current
            const stopState = eventbus.onState((up) => {
                if (!up) {
                    temps = {};
                    show();
                }
            });
            const stopUnits = kismet.settings.watch('units.temperature', show);
            const stopChosen = kismet.settings.watch('ribbon.thermal', show);
            return () => { stopEnv(); stopThermal(); stopState(); stopUnits(); stopChosen(); stat.removeEventListener('click', open); };
        },
    });

    ui.ribbonStats.add({
        id: 'gps', title: 'GPS', priority: 50,
        description: 'GPS fix and satellites; click for the GPS window',
        create(body) {
            const gps = kismet.widgets.gps;
            const v = valueStat('gps');
            const bars = el('span', { class: 'stat-graph gps-mini' });
            body.append(v.node, bars);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            const open = () => gps.openGps();
            stat.addEventListener('click', open);
            const stop = gps.subscribe((gpses) => {
                const best = gps.bestGps(gpses);
                if (!best) {
                    v.value.textContent = 'None';
                    stat.title = 'No GPS is configured';
                    bars.replaceChildren();
                    return;
                }
                const fix = gps.fixName(best);
                const used = best['kismet.gps.satellites_used'];
                const visible = best['kismet.gps.satellites_visible'];
                const sats = gps.satellites(best);
                dom.replace(v.value,
                    el('span', { class: ['badge', fix === 'No fix' ? 'error' : 'ok'] }, fix),
                    visible === undefined ? null : ` ${used ?? '?'}/${visible}`);
                bars.replaceChildren(...(sats.length ? [gps.signalBars(sats)] : []));
                const point = best['kismet.gps.location']?.['kismet.common.location.geopoint'];
                stat.title = [
                    `${best['kismet.gps.name'] || 'GPS'}: ${fix}`,
                    fix !== 'No fix' && Array.isArray(point) ? `${point[1].toFixed(5)}, ${point[0].toFixed(5)}` : null,
                    visible === undefined ? null : `${used ?? '?'} satellites used of ${visible} in view`,
                    gpses.length > 1 ? `${gpses.length} GPS devices` : null,
                    'Click for the GPS window',
                ].filter(Boolean).join('\n');
            });
            return () => { stop(); stat.removeEventListener('click', open); };
        },
    });

    ui.ribbonStats.add({
        id: 'battery', title: 'Battery', priority: 60,
        description: 'Battery of the Kismet server, and of data sources with one (such as a Radiacode); ' +
            `marked when one is at ${lowBattery}% or less; click for the environment window`,
        create(body) {
            const { environment, envdata } = kismet.widgets;
            const v = valueStat('battery');
            body.append(v.node);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            const open = () => environment.openEnvironment('battery');
            stat.addEventListener('click', open);
            let host = null;
            // id -> reading, for the batteries of data sources
            let others = {};
            let names = {};
            let sourceLimit = envdata.fallbackSourceStale;
            const rename = () => environment.load(60).then((d) => {
                names = Object.fromEntries(d.sensors.map((s) => [s.id, envdata.fullLabel(s)]));
                sourceLimit = d.sourceStale;
                show();
            }).catch(() => {});
            const now = () => (kismet.clock.isKnown() ? kismet.clock.now() : NaN);
            let offline = false;
            function show() {
                if (offline) {
                    v.value.textContent = '---';
                    v.value.classList.remove('warn-text');
                    stat.title = 'Not connected to the Kismet server';
                    return;
                }
                // Machines with no battery report 0%
                const hostPct = host?.['kismet.system.battery.percentage'] ?? 0;
                const state = host?.['kismet.system.battery.charging'];
                const ac = !!host?.['kismet.system.battery.ac'];
                const live = Object.entries(others).filter(([, r]) => Number.isFinite(r.value) &&
                    !envdata.stale({ ...r, kind: 'battery' }, now(), null, sourceLimit));
                const lowest = live.reduce((a, b) => (!a || b[1].value < a[1].value ? b : a), null);
                stat.hidden = hostPct === 0 && !lowest;
                if (stat.hidden)
                    return;
                const lines = [];
                let text;
                let low;
                if (hostPct > 0) {
                    const remaining = host['kismet.system.battery.remaining'];
                    const how = state === 'charging' ? 'charging' : ac ? 'on AC power' : 'on battery';
                    text = `${hostPct}%${state === 'charging' ? ' (charging)' : ac ? ' (on AC)' : ''}`;
                    low = hostPct <= lowBattery && !ac;
                    lines.push(`Kismet server: ${hostPct}%, ${how}` +
                        (state === 'discharging' && remaining > 0 ? `, ${format.duration(remaining)} left` : ''));
                } else {
                    text = `${Math.round(lowest[1].value)}%`;
                    low = lowest[1].value <= lowBattery;
                }
                for (const [id, r] of live.sort((a, b) => a[1].value - b[1].value)) {
                    lines.push(`${names[id] ?? id}: ${Math.round(r.value)}%`);
                    low ||= r.value <= lowBattery;
                }
                v.value.textContent = text;
                v.value.classList.toggle('warn-text', low);
                stat.title = [...lines, 'Click for the environment window'].join('\n');
            }
            const stopHost = eventbus.subscribe('BATTERY',
                ['kismet.system.battery.percentage', 'kismet.system.battery.charging', 'kismet.system.battery.ac',
                    'kismet.system.battery.remaining'], (e) => {
                    host = e;
                    show();
                });
            const stopEnv = eventbus.subscribe('ENVIRONMENT', ['kismet.system.environment.sensors'], (e) => {
                others = Object.fromEntries(Object.entries(envdata.readings(e))
                    .filter(([, r]) => r.kind === 'battery' && r.source));
                if (Object.keys(others).some((id) => !(id in names)))
                    rename();
                show();
            });
            // Kept showing (as ---) while the connection is down, so the ribbon doesn't jump
            const stopState = eventbus.onState((up) => {
                offline = !up;
                show();
            });
            return () => { stopHost(); stopEnv(); stopState(); stat.removeEventListener('click', open); };
        },
    });

    ui.ribbonStats.add({
        id: 'legacy', title: 'Legacy UI', priority: 200,
        description: 'Open the previous Kismet web UI',
        create(body) {
            const link = el('a', { class: 'stat-line stat-link', href: api.url('legacy/').href },
                icons.icon('share'), el('span', { class: 'stat-value' }, 'Open'));
            body.append(link);
            const stat = body.parentElement;
            stat.classList.add('clickable');
            stat.title = 'Open the legacy web UI';
            stat.addEventListener('click', (e) => {
                if (!link.contains(e.target))
                    link.click();
            });
        },
    });

    ui.ribbonStats.add({
        id: 'time', title: 'Server time', priority: 100,
        create(body) {
            const v = valueStat('clock');
            body.append(v.node);
            return eventbus.subscribe('TIMESTAMP', ['kismet.system.timestamp.sec'], (e) => {
                v.value.textContent = format.time(e['kismet.system.timestamp.sec']);
            });
        },
    });
}
