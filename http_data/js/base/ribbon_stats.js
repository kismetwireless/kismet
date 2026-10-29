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
