// The Wi-Fi channel picker for the Data sources window: each band drawn to
// scale, with a row per channel width, so a 40, 80, or 160 MHz channel sits
// over the 20 MHz channels it covers, the way Wi-Fi channels are laid out on
// the air.  DFS channels, the UNII sub-bands, and 6 GHz preferred scanning
// channels are marked, and each 20 MHz channel shows how many devices Kismet
// heard there in the last minute.
//
// Channels are the source's own strings (as linuxwifi and the other Wi-Fi
// drivers list them): "6", "6HT20", "36HT40+", "40HT40-", "36VHT80",
// "36VHT160", "37W6e".  Any the picker can't place are listed after the bands
// as plain buttons.

// MHz centre of a primary channel number in a band
export const center = (band, n) => (band === '2.4' ? (n === 14 ? 2484 : 2407 + 5 * n) : band === '4.9' ? 4000 + 5 * n :
    band === '6' ? (n === 2 ? 5935 : 5950 + 5 * n) : 5000 + 5 * n);

// The band and channel number at a Wi-Fi frequency in MHz, or null
function channelAt(mhz) {
    const on = (band, n, lo, hi) => (Number.isInteger(n) && n >= lo && n <= hi ? { band, n } : null);
    if (mhz === 2484)
        return { band: '2.4', n: 14 };
    if (mhz < 2500)
        return on('2.4', (mhz - 2407) / 5, 1, 13);
    if (mhz >= 4910 && mhz <= 4980)
        return on('4.9', (mhz - 4000) / 5, 182, 196);
    if (mhz === 5935)
        return { band: '6', n: 2 };
    if (mhz < 5950)
        return on('5', (mhz - 5000) / 5, 32, 177);
    return on('6', (mhz - 5950) / 5, 1, 233);
}

// A Wi-Fi channel string, as the Wi-Fi drivers write them: a channel number or
// a frequency in MHz, plain or with HT20, HT40+, HT40-, VHT80, VHT160 (either
// with an optional -MHz centre), W5 or W10; or a 6 GHz channel number with
// W6e.  -> { band, n, mhz, kind, center1, byMhz } (band and n null off the
// channel grid), or null for anything else: other radios' channels, like
// HaLow's '37ah', aren't Wi-Fi.
export function wifiChannel(s) {
    const m = /^(\d+)(?:(-?W6e)|(HT20|HT40[+-]|W5|W10)|(VHT80|VHT160)(?:-(\d+))?)?$/i.exec(String(s ?? '').trim());
    if (!m)
        return null;
    const v = +m[1];
    const kind = (m[3] ?? m[4] ?? '').toUpperCase();
    const center1 = m[5] ? +m[5] : null;
    if (m[2])
        return v >= 1 && v <= 233 ? { band: '6', n: v, mhz: center('6', v), kind: '', center1: null, byMhz: false } : null;
    if (v === 0)
        return null;
    if (v > 196) {
        const at = channelAt(v);
        return { band: at?.band ?? null, n: at?.n ?? null, mhz: v, kind, center1, byMhz: true };
    }
    const band = v <= 14 ? '2.4' : v >= 182 ? '4.9' : v >= 32 && v <= 177 ? '5' : null;
    return { band, n: band ? v : null, mhz: center(band ?? '5', v), kind, center1, byMhz: false };
}

// 5 GHz primaries sit every 20 MHz
const isPrimary5 = (n) => (n <= 144 ? n % 4 === 0 : n % 4 === 1);

// 80 and 160 MHz blocks in 5 GHz, by their first 20 MHz channel
const blocks80 = [36, 52, 100, 116, 132, 149, 165];
const blocks160 = [36, 100, 149];

// The MHz range a wide channel takes in, or null for one 20 MHz or narrower
export function wifiSpan(w) {
    if (!w)
        return null;
    if (w.kind === 'HT40+')
        return { lo: w.mhz - 10, hi: w.mhz + 30 };
    if (w.kind === 'HT40-')
        return { lo: w.mhz - 30, hi: w.mhz + 10 };
    if (w.kind !== 'VHT80' && w.kind !== 'VHT160')
        return null;
    const span = w.kind === 'VHT80' ? 80 : 160;
    if (w.center1)
        return { lo: w.center1 - span / 2, hi: w.center1 + span / 2 };
    if (w.band !== '5' || !isPrimary5(w.n))
        return null;
    const start = (span === 80 ? blocks80 : blocks160).find((g) => w.n >= g && w.n < g + span / 5);
    if (start === undefined)
        return null;
    const lo = center('5', start) - 10;
    return { lo, hi: lo + span };
}

// Each band's drawn spans; 5 GHz has no channels between 64 and 100, so that
// stretch is drawn as a narrow break
const bands = {
    '2.4': { title: '2.4 GHz', spans: [[2402, 2489]] },
    5: { title: '5 GHz', spans: [[5170, 5330], [5490, 5895]] },
    6: { title: '6 GHz', spans: [[5945, 7125]] },
};
const gapMhz = 16;
for (const b of Object.values(bands))
    b.total = b.spans.reduce((t, [lo, hi]) => t + hi - lo, 0) + gapMhz * (b.spans.length - 1);

// A frequency's place along its band's drawing, 0-1
function place(band, mhz) {
    const b = bands[band];
    let x = 0;
    for (const [i, [lo, hi]] of b.spans.entries()) {
        if (mhz <= hi || i === b.spans.length - 1)
            return (x + Math.min(Math.max(mhz, lo), hi) - lo) / b.total;
        x += hi - lo + gapMhz;
    }
    return 1;
}

// 5 GHz sub-bands, and the ones that need radar detection (DFS)
const unii5 = [
    { name: 'UNII-1', lo: 5170, hi: 5250 },
    { name: 'UNII-2A', lo: 5250, hi: 5330, dfs: true },
    { name: 'UNII-2C', lo: 5490, hi: 5730, dfs: true },
    { name: 'UNII-3', lo: 5735, hi: 5835 },
    { name: 'UNII-4', lo: 5835, hi: 5895 },
];
const unii6 = [
    { name: 'UNII-5', lo: 5925, hi: 6425 },
    { name: 'UNII-6', lo: 6425, hi: 6525 },
    { name: 'UNII-7', lo: 6525, hi: 6875 },
    { name: 'UNII-8', lo: 6875, hi: 7125 },
];

export const isDfs = (mhz) => (mhz > 5250 && mhz < 5330) || (mhz > 5490 && mhz < 5730);
// 6 GHz preferred scanning channels: 5, 21, 37, ... 229
export const isPsc = (n) => n >= 5 && (n - 5) % 16 === 0;

// The picker's band of a channel string, including channels off the band's usual grid
function bandOf(s) {
    const w = wifiChannel(s);
    return w && !w.byMhz && w.band !== '4.9' ? w.band : null;
}

// A channel string the picker can place -> { band, n, width, lo, hi, primary } or null
export function parseChannel(s) {
    const w = wifiChannel(s);
    if (!w || w.byMhz || w.center1 || !['2.4', '5', '6'].includes(w.band) || w.kind === 'W5' || w.kind === 'W10')
        return null;
    const { band, n } = w;
    if (band === '6' && !(n % 4 === 1 || n === 2))
        return null;
    // anything between 5 GHz primaries is drawn as an "other" channel
    if (band === '5' && !isPrimary5(n))
        return null;
    if (w.kind === '' || w.kind === 'HT20')
        return { band, n, width: 20, lo: w.mhz - 10, hi: w.mhz + 10, primary: n };
    const sp = wifiSpan(w);
    if (!sp)
        return null;
    const side = w.kind === 'HT40+' ? '+' : w.kind === 'HT40-' ? '-' : undefined;
    return { band, n, width: sp.hi - sp.lo, lo: sp.lo, hi: sp.hi, primary: n, ...(side && { side }) };
}

export function registerChannelPicker(kismet, isWifiSource) {
    const { ui, dom, api, rrd, clock, format } = kismet;
    const { el } = dom;

    // Device counts per frequency, shared by every open picker, read every few
    // seconds while one is showing
    const activity = { byMhz: new Map(), users: 0, timer: null, at: 0 };
    async function readActivity() {
        if (activity.users === 0)
            return;
        if (document.visibilityState !== 'hidden') {
            try {
                const r = await api.get('channels/channels.json');
                const now = clock.isKnown() ? clock.now() : undefined;
                const next = new Map();
                for (const rec of Object.values(r['kismet.channeltracker.frequency_map'] ?? {})) {
                    const khz = rec['kismet.channelrec.frequency'];
                    if (khz)
                        next.set(Math.round(khz / 1000), rrd.recent(rec['kismet.channelrec.device_rrd'], now, 60, 'max'));
                }
                activity.byMhz = next;
                activity.at = Date.now();
            } catch {
                // keep the last reading
            }
        }
        activity.timer = setTimeout(readActivity, 3000);
    }

    const pct = (band, mhz) => `${(100 * place(band, mhz)).toFixed(3)}%`;

    // Wi-Fi sources whose channels are mostly 2.4/5/6 GHz channels
    const applies = (s) => {
        const chans = s['kismet.datasource.channels'] ?? [];
        return isWifiSource(s) && chans.length > 0 && chans.filter((c) => parseChannel(c)).length >= chans.length / 2;
    };

    ui.channelPickers.add({
        id: 'dot11', priority: 10, match: applies,
        create(node) {
            activity.users++;
            if (activity.users === 1)
                readActivity();

            let st = null;
            let key = '';
            let blocks = [];        // { node, chans: [strings], info, cell }
            const bandEls = new Map();
            const other = el('div', { class: 'ds-chan-grid wc-other' });
            const otherWrap = el('div', { class: 'wc-other-wrap', hidden: true }, el('div', { class: 'wc-row-title' }, 'Other channels'), other);
            const pass = el('div', { class: 'ds-hint wc-pass' });
            const root = el('div', { class: 'wc' });
            node.append(root, otherWrap, pass);

            const selectedIn = (chans) => chans.some((c) => st.selected.has(c));

            function click(b) {
                if (!st)
                    return;
                if (st.mode === 'lock')
                    return st.lock(b.chans[0]);
                const next = new Set(st.selected);
                if (b.chans.some((c) => next.has(c)))
                    b.chans.forEach((c) => next.delete(c));
                else
                    next.add(b.chans[0]);
                st.setSelected([...next]);
            }

            function preset(band, which) {
                const next = new Set([...st.selected].filter((c) => bandOf(c) !== band));
                for (const b of blocks) {
                    if (b.info.band !== band || b.info.width !== 20)
                        continue;
                    const n = b.info.primary;
                    const pick = which === 'all' ||
                        (which === 'nodfs' && !isDfs((b.info.lo + b.info.hi) / 2)) ||
                        (which === '1611' && [1, 6, 11].includes(n)) ||
                        (which === 'psc' && isPsc(n));
                    if (pick)
                        next.add(b.chans[0]);
                }
                st.setSelected([...next]);
            }

            // Build the bands for this channel list; kept until the list changes
            function build(chans) {
                root.replaceChildren();
                bandEls.clear();
                blocks = [];
                const groups = new Map();       // band -> width -> key -> block
                const unplaced = [];
                for (const c of chans) {
                    const info = parseChannel(c);
                    if (!info) {
                        unplaced.push(c);
                        continue;
                    }
                    const bw = groups.get(info.band) ?? new Map();
                    groups.set(info.band, bw);
                    const row = bw.get(info.width) ?? new Map();
                    bw.set(info.width, row);
                    // 2.4 GHz 40 MHz channels overlap, so each primary and side is its own;
                    // elsewhere one bonded block covers both of its primaries
                    const k = info.band === '2.4' ? `${info.lo}|${info.side ?? ''}` : `${info.lo}`;
                    const blk = row.get(k) ?? { info, chans: [] };
                    blk.chans.push(c);
                    row.set(k, blk);
                }

                for (const band of ['2.4', '5', '6']) {
                    const bw = groups.get(band);
                    if (!bw)
                        continue;
                    const b = bands[band];
                    const count = el('span', { class: 'muted' });
                    const presetButtons = [];
                    const mk = (label, which, title) => {
                        const btn = el('button', { type: 'button', class: 'link-button', title, onclick: () => preset(band, which) }, label);
                        presetButtons.push(btn);
                        return btn;
                    };
                    const head = el('div', { class: 'wc-head' }, el('b', {}, b.title), count,
                        el('span', { class: 'wc-presets' },
                            band === '2.4' ? mk('1, 6, 11', '1611', 'The three 2.4 GHz channels that don\'t overlap') : null,
                            band === '5' ? mk('No DFS', 'nodfs', 'Every 20 MHz channel outside the radar (DFS) sub-bands') : null,
                            band === '6' ? mk('PSC', 'psc', 'The preferred scanning channels, where 6 GHz access points are told to beacon') : null,
                            mk('All 20 MHz', 'all', 'Every 20 MHz channel in this band'),
                            mk('None', 'none', 'Nothing in this band')));
                    const plot = el('div', { class: `wc-plot wc-band-${band.replace('.', '')}` });

                    // Sub-band shading and labels, behind the rows
                    // What the hovered channel actually occupies on the air
                    const span = el('div', { class: 'wc-span', hidden: true });
                    const shade = el('div', { class: 'wc-shade' }, span);
                    const axis = el('div', { class: 'wc-axis' });
                    for (const u of band === '5' ? unii5 : band === '6' ? unii6 : []) {
                        const lo = Math.max(u.lo, b.spans[0][0]);
                        const hi = Math.min(u.hi, b.spans[b.spans.length - 1][1]);
                        if (u.dfs)
                            shade.append(el('div', { class: 'wc-dfs', style: { left: pct(band, lo), width: `calc(${pct(band, hi)} - ${pct(band, lo)})` },
                                title: `${u.name}: DFS, access points here must watch for radar` }));
                        axis.append(el('div', { class: ['wc-unii', u.dfs && 'dfs'], style: { left: pct(band, lo), width: `calc(${pct(band, hi)} - ${pct(band, lo)})` } },
                            u.name + (u.dfs ? ' · DFS' : '')));
                    }
                    for (let i = 1; i < b.spans.length; i++)
                        shade.append(el('div', { class: 'wc-break', style: { left: pct(band, b.spans[i - 1][1]), width: `calc(${pct(band, b.spans[i][0])} - ${pct(band, b.spans[i - 1][1])})` },
                            title: `No Wi-Fi channels between ${b.spans[i - 1][1]} and ${b.spans[i][0]} MHz` }));
                    if (band === '2.4')
                        axis.append(el('div', { class: 'wc-unii', style: { left: '0', width: '100%' } }, 'ISM 2.4 GHz'));

                    // 2.4 GHz channels are 5 MHz apart: draw each as its slot, not its full width
                    const drawn = (info) => (band === '2.4' ? [center('2.4', info.primary) - 2.5, center('2.4', info.primary) + 2.5] : [info.lo, info.hi]);
                    const rows = el('div', { class: 'wc-rows' });
                    const widths = [...bw.keys()].sort((x, y) => y - x);
                    for (const width of widths) {
                        const blks = [...bw.get(width).values()].sort((x, y) => x.info.lo - y.info.lo);
                        // 2.4 GHz 40 MHz: a lane each for HT40+ and HT40-; elsewhere blocks that
                        // overlap (a driver's off-grid pairing) stack into another lane
                        let lanes;
                        if (band === '2.4' && width === 40) {
                            lanes = [['40 +', blks.filter((x) => x.info.side === '+')], ['40 −', blks.filter((x) => x.info.side === '-')]];
                        } else {
                            const ends = [];
                            lanes = [];
                            for (const blk of blks) {
                                const [lo, hi] = drawn(blk.info);
                                let i = ends.findIndex((end) => end <= lo);
                                if (i < 0) {
                                    i = ends.length;
                                    lanes.push([i ? '' : String(width), []]);
                                }
                                ends[i] = hi;
                                lanes[i][1].push(blk);
                            }
                        }
                        for (const [label, laneBlks] of lanes) {
                            if (!laneBlks.length)
                                continue;
                            const track = el('div', { class: 'wc-track' });
                            rows.append(el('div', { class: ['wc-row', `w${width}`] }, el('div', { class: 'wc-row-title', title: `${width} MHz channels` }, label), track));
                            for (const blk of laneBlks) {
                                const { info } = blk;
                                const mid = (info.lo + info.hi) / 2;
                                const [lo, hi] = drawn(info);
                                const text = width === 20 ? String(info.primary) :
                                    band === '2.4' ? `${info.primary}${info.side}` :
                                        `${Math.round((info.lo + 10 - 5000) / 5)}–${Math.round((info.hi - 10 - 5000) / 5)}`;
                                const cell = el('button', { type: 'button', class: ['wc-cell', isDfs(mid) && 'dfs', band === '6' && isPsc(info.primary) && width === 20 && 'psc'],
                                    style: { left: pct(band, lo), width: `calc(${pct(band, hi)} - ${pct(band, lo)} - 2px)` } },
                                el('span', { class: 'wc-label' }, text),
                                width === 20 ? el('span', { class: 'wc-act' }) : null);
                                const b2 = { node: cell, chans: blk.chans, info, act: cell.querySelector('.wc-act') };
                                cell.addEventListener('click', () => click(b2));
                                cell.addEventListener('pointerenter', () => {
                                    Object.assign(span.style, { left: pct(band, info.lo), width: `calc(${pct(band, info.hi)} - ${pct(band, info.lo)})` });
                                    span.hidden = false;
                                });
                                cell.addEventListener('pointerleave', () => { span.hidden = true; });
                                blocks.push(b2);
                                track.append(cell);
                            }
                        }
                    }
                    plot.append(shade, rows, axis);
                    const scroller = el('div', { class: 'wc-scroll' }, plot);
                    const sec = el('div', { class: 'wc-band' }, head, scroller);
                    root.append(sec);
                    bandEls.set(band, { count, presets: presetButtons, head });
                }

                other.replaceChildren(...unplaced.map((c) => {
                    const btn = el('button', { type: 'button', class: 'ds-chan' }, c);
                    const b2 = { node: btn, chans: [c], info: { band: 'other', width: 0 } };
                    btn.addEventListener('click', () => click(b2));
                    blocks.push(b2);
                    return btn;
                }));
                otherWrap.hidden = unplaced.length === 0;
            }

            function cellTitle(b, on, devices) {
                const i = b.info;
                if (i.band === 'other')
                    return b.chans[0];
                const parts = [`${b.chans.join(' / ')}: ${i.lo}–${i.hi} MHz, ${i.width} MHz wide`];
                if (isDfs((i.lo + i.hi) / 2))
                    parts.push('DFS (radar) channel');
                if (i.band === '6' && i.width === 20 && isPsc(i.primary))
                    parts.push('preferred scanning channel');
                if (devices !== undefined)
                    parts.push(`${format.count(devices)} device${devices === 1 ? '' : 's'} heard in the last minute`);
                parts.push(st.mode === 'lock' ? 'click to lock to it' : on ? 'click to stop hopping on it' : 'click to hop on it too');
                return parts.join('\n');
            }

            return {
                update(s, state) {
                    st = state;
                    const chans = state.channels;
                    if (chans.join('\n') !== key) {
                        key = chans.join('\n');
                        build(chans);
                    }
                    const maxAct = Math.max(1, ...blocks.filter((b) => b.act).map((b) => activity.byMhz.get(b.info.primary === undefined ? 0 : center(b.info.band, b.info.primary)) ?? 0));
                    const isOn = (b) => (state.mode === 'hop' ? selectedIn(b.chans) : b.chans.includes(state.current));
                    const wide = blocks.filter((b) => b.info.width > 20 && isOn(b));
                    for (const b of blocks) {
                        const on = isOn(b);
                        // a 20 MHz channel inside a chosen wider one is heard too
                        b.node.classList.toggle('covered', !on && b.info.width === 20 &&
                            wide.some((w) => w.info.band === b.info.band && w.info.lo <= b.info.lo && w.info.hi >= b.info.hi));
                        b.node.classList.toggle('on', on);
                        b.node.classList.toggle('pending', state.pending && on);
                        b.node.classList.toggle('lock', state.mode === 'lock');
                        let devices;
                        if (b.act) {
                            devices = activity.byMhz.get(center(b.info.band, b.info.primary));
                            const v = devices ?? 0;
                            b.act.style.height = v ? `${Math.max(12, Math.round(100 * v / maxAct))}%` : '0';
                            b.act.style.opacity = v ? '1' : '0';
                        }
                        b.node.title = cellTitle(b, on, devices);
                    }
                    for (const [band, e] of bandEls) {
                        const inBand = blocks.filter((b) => b.info.band === band);
                        const chosen = state.mode === 'hop' ? inBand.filter((b) => selectedIn(b.chans)).length : inBand.filter((b) => b.chans.includes(state.current)).length;
                        e.count.textContent = state.mode === 'hop' ? `${chosen} of ${inBand.length} chosen` : chosen ? 'locked here' : '';
                        e.presets.forEach((p) => { p.hidden = state.mode !== 'hop'; });
                    }
                    const n = state.selected.size;
                    const rate = s['kismet.datasource.hop_rate'];
                    pass.textContent = state.mode === 'hop' && n > 1 && rate > 0 ?
                        `A pass over ${n} channels takes ${(n / rate).toFixed(n / rate < 10 ? 1 : 0)} s, so each is heard ${(100 / n).toFixed(n > 20 ? 1 : 0)}% of the time.` : '';
                },
                destroy() {
                    activity.users--;
                    if (activity.users === 0)
                        clearTimeout(activity.timer);
                },
            };
        },
    });
}
