// Airspace: Wi-Fi traffic per channel over time, as a waterfall.  A column
// per 20 MHz channel, grouped by band; the newest time at the top.  The top
// block is the last minute a second per row, the block under it the last
// hour a minute per row, so a burst shows at once and a pattern over the hour.

import { center, isDfs, isPsc } from './dot11_channels.js';

const ch5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
const gutter = 54;
const head = 38;
const secRow = 3;
const minRow = 4;
const gap = 12;

export function registerAirspace(kismet) {
    const { ui, dom, rrd, clock, format, theme } = kismet;
    const { el, replace } = dom;

    ui.insightViews.add({
        id: 'dot11-airspace', title: 'Airspace', priority: 10,
        create(node, ctx) {
            const summary = el('div', { class: 'as-summary' });
            const canvas = el('canvas', { class: 'as-canvas' });
            const scroller = el('div', { class: 'as-scroll' }, canvas);
            const tip = el('div', { class: 'cg-tip', hidden: true });
            node.classList.add('as');
            node.append(summary, scroller, tip, el('div', { class: 'cg-hint muted' },
                'Packets heard on each channel; darker is busier.  A hopping source hears each channel only part of the time, ' +
                'so compare channels it visits equally.'));

            let freqs = new Map();      // MHz -> channel record
            let timer = null;
            let columns = [];
            let layout = null;

            const resize = new ResizeObserver(() => draw());
            resize.observe(scroller);
            const offTheme = theme.onChange(() => draw());

            function buildColumns() {
                const seen = (mhz) => freqs.has(mhz);
                const cols = [];
                const add = (band, n) => cols.push({ band, n, mhz: center(band, n) });
                for (let n = 1; n <= 13; n++)
                    add('2.4', n);
                if (seen(2484))
                    add('2.4', 14);
                for (const n of ch5)
                    add('5', n);
                for (const n of [169, 173, 177])
                    if (seen(center('5', n)))
                        add('5', n);
                // 6 GHz: only channels heard, it is a wide band to show empty
                for (let n = 1; n <= 233; n += 4)
                    if (seen(center('6', n)))
                        add('6', n);
                columns = cols;
            }

            function series(mhz, span) {
                const rec = freqs.get(mhz);
                if (!rec)
                    return null;
                const now = clock.isKnown() ? clock.now() : undefined;
                return rrd.history(rec['kismet.channelrec.packets_rrd'], now, span);
            }

            function draw() {
                const width = scroller.clientWidth;
                if (!width || !columns.length)
                    return;
                const bands = [...new Set(columns.map((c) => c.band))];
                const cw = Math.max(10, (width - gutter - gap * (bands.length - 1) - 4) / columns.length);
                const w = gutter + cw * columns.length + gap * (bands.length - 1) + 4;
                const top2 = head + 60 * secRow + 18;
                const h = top2 + 60 * minRow + 6;
                const dpr = window.devicePixelRatio || 1;
                canvas.style.width = `${w}px`;
                canvas.style.height = `${h}px`;
                canvas.width = Math.round(w * dpr);
                canvas.height = Math.round(h * dpr);
                const c = canvas.getContext('2d');
                c.setTransform(dpr, 0, 0, dpr, 0, 0);
                c.clearRect(0, 0, w, h);
                const col = (name) => theme.themeColor(name) || '#888';
                const accent = col('--accent'), muted = col('--muted'), text = col('--text'), warn = col('--warn'), border = col('--border');

                // x of each column, with a gap between bands
                let x = gutter;
                let lastBand = null;
                const xs = columns.map((cc) => {
                    if (lastBand && cc.band !== lastBand)
                        x += gap;
                    lastBand = cc.band;
                    const at = x;
                    x += cw;
                    return at;
                });
                layout = { xs, cw, top2 };

                const sec = columns.map((cc) => series(cc.mhz, 'minute')?.slice(0, -1) ?? []);
                const hour = columns.map((cc) => series(cc.mhz, 'hour')?.slice(0, -1) ?? []);
                const maxOf = (arr) => Math.max(1, ...arr.flat());
                const ls = Math.log1p(maxOf(sec)), lh = Math.log1p(maxOf(hour));

                // header: band names, channel numbers
                c.font = '600 11px system-ui, sans-serif';
                c.textAlign = 'left';
                c.fillStyle = text;
                for (const band of bands) {
                    const i = columns.findIndex((cc) => cc.band === band);
                    c.fillText(`${band} GHz`, xs[i] + 1, 12);
                }
                c.font = `${cw < 16 ? 8.5 : 10}px system-ui, sans-serif`;
                c.textAlign = 'center';
                columns.forEach((cc, i) => {
                    const dfs = cc.band === '5' && isDfs(cc.mhz);
                    c.fillStyle = dfs ? warn : cc.band === '6' && isPsc(cc.n) ? accent : muted;
                    c.fillText(String(cc.n), xs[i] + cw / 2, head - 8);
                    if (dfs) {
                        c.fillStyle = warn;
                        c.globalAlpha = 0.5;
                        c.fillRect(xs[i] + 1, head - 4, cw - 2, 1.5);
                        c.globalAlpha = 1;
                    }
                });

                // time axis
                c.textAlign = 'right';
                c.fillStyle = muted;
                c.font = '10px system-ui, sans-serif';
                c.fillText('now', gutter - 6, head + 8);
                c.fillText('-30s', gutter - 6, head + 30 * secRow + 4);
                c.fillText('-1m', gutter - 6, head + 60 * secRow);
                c.fillText('-30m', gutter - 6, top2 + 30 * minRow + 4);
                c.fillText('-1h', gutter - 6, top2 + 60 * minRow);
                c.textAlign = 'left';
                c.fillText('▲ the last minute, a second per row     ▼ the last hour, a minute per row', gutter, head + 60 * secRow + 13);

                const block = (data, top, rowH, lmax) => {
                    columns.forEach((cc, i) => {
                        const d = data[i];
                        for (let k = 0; k < d.length; k++) {
                            const v = d[d.length - 1 - k];
                            if (!v)
                                continue;
                            c.globalAlpha = 0.12 + 0.88 * Math.log1p(v) / lmax;
                            c.fillStyle = accent;
                            c.fillRect(xs[i] + 0.5, top + k * rowH, cw - 1, rowH);
                        }
                    });
                    c.globalAlpha = 1;
                    c.strokeStyle = border;
                    c.lineWidth = 1;
                    for (let b = 0; b < bands.length; b++) {
                        const idx = columns.map((cc, i) => [cc, i]).filter(([cc]) => cc.band === bands[b]).map(([, i]) => i);
                        c.strokeRect(xs[idx[0]] - 0.5, top - 0.5, xs[idx[idx.length - 1]] + cw - xs[idx[0]] + 1, d0(data) * rowH + 1);
                    }
                };
                const d0 = (data) => Math.max(1, ...data.map((d) => d.length));
                block(sec, head, secRow, ls);
                block(hour, top2, minRow, lh);
            }

            function renderSummary() {
                const total = (mhz) => (series(mhz, 'hour') ?? []).reduce((a, v) => a + v, 0);
                const named = (cc) => `${cc.n}${cc.band === '6' ? ' (6 GHz)' : ''}`;
                const ranked = columns.map((cc) => ({ cc, t: total(cc.mhz) })).filter((r) => freqs.has(r.cc.mhz));
                if (!ranked.length) {
                    replace(summary, el('p', { class: 'muted' }, 'No Wi-Fi channel has been heard yet.'));
                    return;
                }
                const busiest = [...ranked].sort((a, b) => b.t - a.t).slice(0, 3).filter((r) => r.t > 0);
                const quiet24 = [1, 6, 11].map((n) => ranked.find((r) => r.cc.band === '2.4' && r.cc.n === n)).filter(Boolean).sort((a, b) => a.t - b.t)[0];
                const quiet5 = ranked.filter((r) => r.cc.band === '5' && !isDfs(r.cc.mhz)).sort((a, b) => a.t - b.t)[0];
                replace(summary, el('p', {},
                    busiest.length ? `Busiest over the hour: ${busiest.map((r) => `${named(r.cc)} (${format.count(Math.round(r.t * 60))} packets)`).join(', ')}.  ` : '',
                    quiet24 ? `Quietest of 1, 6 and 11: ${quiet24.cc.n}.  ` : '',
                    quiet5 ? `Quietest 5 GHz channel without radar rules: ${quiet5.cc.n}.` : ''));
            }

            async function read() {
                clearTimeout(timer);
                if (!ctx.showing() || node.hidden)
                    return;
                try {
                    const r = await ctx.api.get('channels/channels.json');
                    const next = new Map();
                    for (const rec of Object.values(r['kismet.channeltracker.frequency_map'] ?? {})) {
                        const khz = rec['kismet.channelrec.frequency'];
                        if (khz)
                            next.set(Math.round(khz / 1000), rec);
                    }
                    freqs = next;
                    buildColumns();
                    renderSummary();
                    draw();
                } catch (err) {
                    replace(summary, el('p', { class: 'error-text' }, `Could not read the channels: ${err.message}`));
                }
                timer = setTimeout(read, 2000);
            }

            canvas.addEventListener('pointermove', (ev) => {
                if (!layout)
                    return;
                const r = canvas.getBoundingClientRect();
                const mx = ev.clientX - r.left, my = ev.clientY - r.top;
                const i = layout.xs.findIndex((x0) => mx >= x0 && mx < x0 + layout.cw);
                let span = null, k = -1;
                if (my >= head && my < head + 60 * secRow) {
                    span = 'minute';
                    k = Math.floor((my - head) / secRow);
                } else if (my >= layout.top2 && my < layout.top2 + 60 * minRow) {
                    span = 'hour';
                    k = Math.floor((my - layout.top2) / minRow);
                }
                if (i < 0 || !span) {
                    tip.hidden = true;
                    return;
                }
                const cc = columns[i];
                const d = series(cc.mhz, span)?.slice(0, -1) ?? [];
                const v = d[d.length - 1 - k] ?? 0;
                const when = span === 'minute' ? `${k + 1} s ago` : `${k + 1} min ago`;
                replace(tip, el('b', {}, `Channel ${cc.n}`), el('div', {}, `${cc.mhz} MHz${cc.band === '5' && isDfs(cc.mhz) ? ', DFS' : ''}`),
                    el('div', {}, `${when}: ${format.count(Math.round(v * 10) / 10)} packets${span === 'hour' ? '/s on average' : ''}`));
                tip.hidden = false;
                const nr = node.getBoundingClientRect();
                tip.style.left = `${Math.min(ev.clientX - nr.left + 14, nr.width - tip.offsetWidth - 8)}px`;
                tip.style.top = `${ev.clientY - nr.top + 12}px`;
            });
            canvas.addEventListener('pointerleave', () => { tip.hidden = true; });

            return {
                show() {
                    read();
                },
                hide() {
                    clearTimeout(timer);
                },
                destroy() {
                    clearTimeout(timer);
                    resize.disconnect();
                    offTheme();
                },
            };
        },
    });
}
