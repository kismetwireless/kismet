// The standard stats in the top ribbon.  All of them are fed by the eventbus
// websocket; only the datasource and alert counts load a starting value over
// HTTP.

export function register(kismet) {
    const { ui, eventbus, api, format, rrd, dom, icons } = kismet;
    const { el } = dom;

    // A stat that shows one value with an icon
    function valueStat(name) {
        const value = el('span', { class: 'stat-value' }, '-');
        return { node: el('span', { class: 'stat-line' }, icons.icon(name), value), value };
    }

    ui.ribbonStats.add({
        id: 'packets', title: 'Packets', priority: 0,
        description: 'Packets per second, over the last minute',
        create(body) {
            const spark = kismet.widgets.sparkline();
            const v = valueStat('packets');
            body.append(el('div', { class: 'stat-graph' }, spark.canvas), v.node);
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
        description: 'Data sources running, and any with errors',
        create(body) {
            const v = valueStat('source');
            body.append(v.node);
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
        create(body) {
            const v = valueStat('alert');
            body.append(v.node);
            let count = 0;
            const show = () => {
                dom.replace(v.value, count ? el('span', { class: 'badge alert' }, format.count(count)) : '0');
            };
            api.get('alerts/wrapped/last-time/0/alerts.json')
                .then((r) => { count += (r['kismet.alert.list'] ?? []).length; show(); })
                .catch(() => { v.value.textContent = '?'; });
            return eventbus.subscribe('ALERT', ['kismet.alert.hash'], () => { count++; show(); });
        },
    });

    ui.ribbonStats.add({
        id: 'memory', title: 'Memory', priority: 40,
        description: 'Memory used by the Kismet server',
        create(body) {
            const v = valueStat('memory');
            body.append(v.node);
            return eventbus.subscribe('STATISTICS', ['kismet.system.memory.rss'], (e) => {
                // 0 where the server can't read its memory use (no /proc)
                const kb = e['kismet.system.memory.rss'];
                v.value.textContent = kb ? format.size(kb * 1024) : 'n/a';
            });
        },
    });

    ui.ribbonStats.add({
        id: 'gps', title: 'GPS', priority: 50,
        create(body) {
            const v = valueStat('gps');
            body.append(v.node);
            return eventbus.subscribe('GPS_LOCATION',
                ['kismet.common.location.fix', 'kismet.common.location.geopoint'], (e) => {
                    const fix = e['kismet.common.location.fix'] ?? 0;
                    const point = e['kismet.common.location.geopoint'];
                    if (fix < 2 || !Array.isArray(point)) {
                        v.value.textContent = 'No fix';
                        v.value.title = '';
                    } else {
                        v.value.textContent = `${point[1].toFixed(5)}, ${point[0].toFixed(5)}`;
                        v.value.title = fix >= 3 ? '3D fix' : '2D fix';
                    }
                });
        },
    });

    ui.ribbonStats.add({
        id: 'battery', title: 'Battery', priority: 60,
        create(body) {
            const v = valueStat('battery');
            body.append(v.node);
            const stat = body.parentElement;
            return eventbus.subscribe('BATTERY',
                ['kismet.system.battery.percentage', 'kismet.system.battery.charging', 'kismet.system.battery.ac'], (e) => {
                    const pct = e['kismet.system.battery.percentage'] ?? 0;
                    // Machines with no battery report 0%
                    stat.hidden = pct === 0;
                    v.value.textContent = `${pct}%${e['kismet.system.battery.charging'] ? ' (charging)' : ''}`;
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
