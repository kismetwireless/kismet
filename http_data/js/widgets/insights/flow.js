// The flow view: who relates to whom, in columns: devices that look for a
// name, the names, the hubs (an access point's addresses together), and the
// devices on them.  The links between two groups are drawn as one line, as
// thick as the number of links in it, so a busy area stays readable.  The
// table shows the same links address by address.
//
//   const f = flow({ onPick: (key) => ..., linkKinds });
//   f.update(graph, findings)    after each read

import { el } from '../../core/dom.js';
import * as format from '../../core/format.js';
import * as settings from '../../core/settings.js';
import { gather } from './groups.js';

const svgNs = 'http://www.w3.org/2000/svg';
const rowH = 34;
const bothMin = 1150;

function svgEl(tag, attrs = {}, text = null) {
    const n = document.createElementNS(svgNs, tag);
    for (const [k, v] of Object.entries(attrs))
        if (v !== null && v !== undefined)
            n.setAttribute(k, v);
    if (text !== null)
        n.textContent = text;
    return n;
}

const plural = (n, one, many) => `${format.count(n)} ${n === 1 ? one : many}`;
// dash patterns grow with the line so a thick dotted line still reads as dots
const dash = { dashed: (w) => `${(w * 2 + 4).toFixed(1)} ${(w + 3).toFixed(1)}`, dotted: (w) => `0.1 ${(w * 1.5 + 2).toFixed(1)}` };

// Order each column by where its neighbors sit, so lines cross less
function barycenter(items, edges, side, placed) {
    const pos = new Map();
    for (const e of edges) {
        const [mine, other] = side === 'right' ? [e.to, e.from] : [e.from, e.to];
        if (!placed.has(other.id))
            continue;
        const p = pos.get(mine.id) ?? [0, 0];
        p[0] += placed.get(other.id) * e.count;
        p[1] += e.count;
        pos.set(mine.id, p);
    }
    const at = (it) => {
        const p = pos.get(it.id);
        return p ? p[0] / p[1] : Infinity;
    };
    return [...items].sort((a, b) => at(a) - at(b));
}

export function flow({ onPick = null, linkKinds }) {
    const svgBox = el('div', { class: 'fl-lines' });
    const tableBox = el('div', { class: 'fl-table', hidden: true });
    const quiet = el('p', { class: 'muted fl-quiet' });
    const pop = el('div', { class: 'fl-pop', hidden: true });
    const modeButtons = {};
    const modes = el('div', { class: 'graph-tabs fl-modes' }, ...['lines', 'table'].map((m) => {
        modeButtons[m] = el('button', { type: 'button', onclick: () => setMode(m) }, m === 'lines' ? 'Lines' : 'Table');
        return modeButtons[m];
    }));
    const legend = el('div', { class: 'cg-legend fl-legend' });
    const divider = el('div', { class: 'fl-divider', role: 'separator', 'aria-orientation': 'vertical', tabindex: '0',
        title: 'Drag to share the room between the lines and the table; double-click to reset' });
    const views = el('div', { class: 'fl-views' }, svgBox, divider, tableBox);
    const node = el('div', { class: 'fl' }, el('div', { class: 'fl-bar' }, modes, legend), views, quiet, pop);
    let mode = 'lines';
    let both = false;
    let last = null;
    let width = 0;
    let measureCtx = null;

    const kindOf = (id) => linkKinds.get(id) ?? { title: id, color: '--muted', style: 'solid' };

    // side by side, the lines get this share of the room
    let split = settings.get('insights.flowSplit', 0.6);
    function setSplit(f, save = false) {
        split = Number.isFinite(f) ? Math.min(0.8, Math.max(0.25, f)) : 0.6;
        views.style.gridTemplateColumns = `minmax(0, ${split.toFixed(3)}fr) 0.9rem minmax(0, ${(1 - split).toFixed(3)}fr)`;
        divider.setAttribute('aria-valuenow', String(Math.round(split * 100)));
        if (save)
            settings.set('insights.flowSplit', split);
    }
    setSplit(split);
    let redrawing = false;
    const redrawSoon = () => {
        if (redrawing)
            return;
        redrawing = true;
        requestAnimationFrame(() => {
            redrawing = false;
            if (last && !svgBox.hidden)
                drawLines(last);
        });
    };
    divider.addEventListener('pointerdown', (e) => {
        if (e.button !== 0)
            return;
        e.preventDefault();
        divider.setPointerCapture(e.pointerId);
        divider.classList.add('dragging');
        const box = views.getBoundingClientRect();
        const move = (ev) => {
            setSplit((ev.clientX - box.left) / box.width);
            redrawSoon();
        };
        const up = () => {
            divider.classList.remove('dragging');
            divider.removeEventListener('pointermove', move);
            divider.removeEventListener('pointerup', up);
            divider.removeEventListener('pointercancel', up);
            setSplit(split, true);
        };
        divider.addEventListener('pointermove', move);
        divider.addEventListener('pointerup', up);
        divider.addEventListener('pointercancel', up);
    });
    divider.addEventListener('dblclick', () => {
        setSplit(0.6, true);
        redrawSoon();
    });
    divider.addEventListener('keydown', (e) => {
        const step = { ArrowLeft: -0.03, ArrowRight: 0.03 }[e.key];
        if (!step)
            return;
        e.preventDefault();
        setSplit(split + step, true);
        redrawSoon();
    });

    // wide enough: the lines and the table side by side
    function layout() {
        both = node.clientWidth >= bothMin;
        node.classList.toggle('both', both);
        divider.hidden = !both;
        svgBox.hidden = !both && mode !== 'lines';
        tableBox.hidden = !both && mode !== 'table';
    }

    function setMode(m) {
        mode = m;
        for (const [k, b] of Object.entries(modeButtons)) {
            b.classList.toggle('active', k === m);
            b.setAttribute('aria-pressed', String(k === m));
        }
        layout();
        draw();
    }

    // A group of several devices offers a list to pick from
    function pick(item, evt) {
        const devs = item.members.filter((m) => m.kind === 'device');
        if (devs.length === 1) {
            onPick?.(devs[0].key);
            return;
        }
        if (!devs.length)
            return;
        const r = node.getBoundingClientRect();
        pop.replaceChildren(el('div', { class: 'fl-pop-title' }, item.title ?? item.label),
            ...devs.slice(0, 60).map((d) => el('button', { type: 'button', class: 'link-button', onclick: () => {
                pop.hidden = true;
                onPick?.(d.key);
            } }, d.label === d.mac ? d.mac : `${d.label} (${d.mac})`)),
            devs.length > 60 ? el('div', { class: 'muted' }, `and ${devs.length - 60} more`) : null);
        pop.style.left = `${Math.max(4, Math.min(evt.clientX - r.left, r.width - 260))}px`;
        pop.style.top = `${evt.clientY - r.top + node.scrollTop + 8}px`;
        pop.hidden = false;
        evt.stopPropagation();
    }
    node.addEventListener('click', () => {
        pop.hidden = true;
    });

    function groupLabel(g) {
        const k = kindOf(g.kind);
        if (g.members.length === 1)
            return g.members[0].label;
        return `${format.count(g.members.length)} ${k.groupTitle ?? 'devices'}`;
    }

    function drawLines(r) {
        width = svgBox.clientWidth || node.clientWidth || 360;
        const narrow = width < 600;
        // a phone gets smaller text, shapes and lines, and tighter rows
        const fs = narrow ? { main: 10, sub: 8.5 } : { main: 12, sub: 10 };
        const rh = narrow ? 25 : rowH;
        const shrink = narrow ? 0.7 : 1;
        const pad = 8;
        const family = getComputedStyle(node).fontFamily;
        const measure = (text, px) => {
            measureCtx ??= document.createElement('canvas').getContext('2d');
            measureCtx.font = `${px}px ${family}`;
            return measureCtx.measureText(text).width;
        };
        const cols = [];
        if (r.seekers.length)
            cols.push('seek');
        cols.push('name', 'hub', 'att');

        // items by column, ordered by their neighbors so lines cross less
        const names = r.names;
        const namePos = new Map(names.map((n, i) => [n.id, i]));
        const hubs = barycenter(r.hubs, r.edges, 'right', namePos);
        const hubPos = new Map(hubs.map((h, i) => [h.id, i]));
        const att = barycenter(r.attached, r.edges, 'right', hubPos);
        const seek = r.seekers;

        // what each item says
        const hubRad = (h) => Math.min(5 + h.members.length, 12) * shrink;
        const grpRad = (g) => Math.min(4 + Math.sqrt(g.members.length) * 1.6, 11) * shrink;
        const hubText = (h) => (narrow ?
            [h.parts.short, [h.channels.length ? `ch ${h.channels.join(',')}` : '', h.parts.named ? '' : h.parts.maker].filter(Boolean).join(' · ')] :
            [h.label, `${plural(h.members.length, 'address', 'addresses')}${h.channels.length ? ` · ch ${h.channels.join(', ')}` : ''}`]);
        const grpText = (g) => {
            if (g.id.startsWith('seek:'))
                return narrow ? [] : [groupLabel(g)];
            return narrow && g.members.length > 1 ? [format.count(g.members.length), kindOf(g.kind).groupTitle ?? 'devices'] : [groupLabel(g)];
        };
        const textW = (t) => Math.max(measure(t[0] ?? '', fs.main), measure(t[1] ?? '', fs.sub));

        // columns are as wide as their labels; the space between them holds the lines
        const cap = narrow ? width * 0.3 : 230;
        // where labels start, after a column's shapes
        const textX = narrow ? { name: 7, hub: 23, att: 22 } : { name: 10, hub: 30, att: 28 };
        const colW = {
            seek: narrow ? 20 : 34 + Math.max(0, ...seek.map((g) => textW(grpText(g)))),
            name: Math.max(40, ...names.map((n) => measure(n.label, fs.main) + textX.name * 2 + 2)),
            hub: textX.hub + 6 + Math.max(0, ...hubs.map((h) => textW(hubText(h)))),
            att: textX.att + 6 + Math.max(0, ...att.map((g) => textW(grpText(g)))),
        };
        for (const c of cols)
            colW[c] = Math.min(colW[c], c === 'seek' && narrow ? 20 : cap);
        const gaps = cols.length - 1;
        let fixed = cols.reduce((t, c) => t + colW[c], 0);
        const gap = Math.max(narrow ? 12 : 40, Math.min(narrow ? 90 : 240, (width - fixed) / gaps));
        if (fixed + gap * gaps > width) {
            const scale = (width - gap * gaps) / fixed;
            for (const c of cols)
                if (!(c === 'seek' && narrow))
                    colW[c] *= scale;
            fixed = cols.reduce((t, c) => t + colW[c], 0);
        }
        const colX = {};
        let x0 = 0;
        for (const c of cols) {
            colX[c] = x0;
            x0 += colW[c] + gap;
        }
        const drawnW = Math.min(width, fixed + gap * gaps);

        // names and access points spread evenly; groups sit level with what they relate to
        const rows = Math.max(names.length, hubs.length, att.length, seek.length, 3);
        const H = rows * rh + 16;
        const at = new Map();
        const spread = (list, c) => {
            const step = (H - 16) / Math.max(list.length, 1);
            list.forEach((it, i) => at.set(it.id, { y: 8 + step * (i + 0.5), col: c }));
        };
        spread(names, 'name');
        spread(hubs, 'hub');
        const settle = (list, c, side) => {
            const want = new Map(list.map((it) => {
                let sum = 0, n = 0;
                for (const e of r.edges) {
                    const other = side === 'right' && e.to === it ? e.from : side === 'left' && e.from === it ? e.to : null;
                    const p = other && at.get(other.id);
                    if (p) {
                        sum += p.y * e.count;
                        n += e.count;
                    }
                }
                return [it, n ? sum / n : H / 2];
            }));
            const sorted = [...list].sort((a, b) => want.get(a) - want.get(b));
            const lo = 8 + rh / 2, hi = H - 8 - rh / 2;
            const ys = sorted.map((it) => want.get(it));
            for (let i = 0; i < ys.length; i++)
                ys[i] = Math.max(ys[i], i ? ys[i - 1] + rh : lo);
            for (let i = ys.length - 1; i >= 0; i--)
                ys[i] = Math.min(ys[i], i < ys.length - 1 ? ys[i + 1] - rh : hi);
            sorted.forEach((it, i) => at.set(it.id, { y: ys[i], col: c }));
        };
        settle(att, 'att', 'right');
        settle(seek, 'seek', 'left');

        const svg = svgEl('svg', { viewBox: `0 0 ${drawnW} ${H}`, width: drawnW, height: H, class: `fl-svg${narrow ? ' narrow' : ''}` });
        const linesG = svgEl('g');
        const nodesG = svgEl('g');
        svg.append(linesG, nodesG);

        // shapes in a column share a center line; lines leave after a column's labels
        const shapeX = narrow ? { seek: 9, name: 0, hub: 9, att: 8 } : { seek: 12, name: 0, hub: 12, att: 11 };
        const radOf = (it) => {
            const p = at.get(it.id);
            return p.col === 'hub' ? hubRad(it) : p.col === 'name' ? 0 : grpRad(it);
        };
        const out = (it) => {
            const c = at.get(it.id).col;
            return c === 'seek' && narrow ? colX.seek + shapeX.seek + radOf(it) : colX[c] + colW[c] + (c === 'name' ? 0 : narrow ? 4 : 8);
        };
        const inn = (it) => {
            const c = at.get(it.id).col;
            return colX[c] + shapeX[c] - radOf(it);
        };
        const maxCount = Math.max(1, ...r.edges.map((e) => e.count));
        for (const e of r.edges) {
            const a = at.get(e.from.id), b = at.get(e.to.id);
            if (!a || !b)
                continue;
            const k = kindOf(e.kind);
            const x1 = out(e.from), x2 = inn(e.to);
            const mid = (x1 + x2) / 2;
            // dots get lost in a thick line
            const w = narrow ? Math.min(k.style === 'dotted' ? 2.2 : 4, 0.8 + 3.5 * Math.sqrt(e.count / maxCount)) :
                Math.min(k.style === 'dotted' ? 3.5 : 9, 1.2 + 8 * Math.sqrt(e.count / maxCount));
            const path = svgEl('path', {
                d: `M${x1.toFixed(1)},${a.y.toFixed(1)} C${mid.toFixed(1)},${a.y.toFixed(1)} ${mid.toFixed(1)},${b.y.toFixed(1)} ${x2.toFixed(1)},${b.y.toFixed(1)}`,
                class: 'fl-line', stroke: `var(${k.color})`, 'stroke-width': w.toFixed(1), 'stroke-dasharray': dash[k.style]?.(w) ?? null,
            });
            path.append(svgEl('title', {}, `${k.title}: ${plural(e.count, 'link', 'links')}`));
            linesG.append(path);
        }

        const label = (x, y, text, cls = null, max = 100) => {
            const px = cls === 'fl-sub' ? fs.sub : fs.main;
            let t = text;
            while (t.length > 2 && measure(t, px) > max)
                t = `${t.slice(0, -2)}…`;
            return svgEl('text', { x, y, class: cls }, t);
        };
        const flagRing = (g, x, y, rad) => g.append(svgEl('circle', { cx: x, cy: y, r: rad + (narrow ? 3 : 4), class: 'fl-flag' }));

        for (const n of names) {
            const p = at.get(n.id);
            const g = svgEl('g', { class: ['fl-node', 'fl-name', n.sought && 'sought'].filter(Boolean).join(' ') });
            const rr = narrow ? 8.5 : 11;
            g.append(svgEl('rect', { x: colX.name, y: p.y - rr, width: colW.name, height: rr * 2, rx: rr }),
                label(colX.name + textX.name, p.y + fs.main / 3, n.label, null, colW.name - textX.name * 2 + 2),
                svgEl('title', {}, n.sought ? `${n.label}: looked for, not advertised here` : n.label));
            nodesG.append(g);
        }
        for (const h of hubs) {
            const p = at.get(h.id);
            const rad = hubRad(h);
            const cx = colX.hub + shapeX.hub;
            const room = colW.hub - textX.hub - 4;
            const [t1, t2] = hubText(h);
            const g = svgEl('g', { class: 'fl-node fl-hub' });
            if (h.flags.length)
                flagRing(g, cx, p.y, rad);
            g.append(svgEl('circle', { cx, cy: p.y, r: rad }),
                label(colX.hub + textX.hub, p.y, t1, null, room),
                label(colX.hub + textX.hub, p.y + fs.main, t2, 'fl-sub', room),
                svgEl('title', {}, `${h.label}\n${h.members.map((m) => m.mac).join('\n')}`));
            g.addEventListener('click', (e) => pick({ ...h, title: h.label }, e));
            nodesG.append(g);
        }
        for (const it of [...att, ...seek]) {
            const p = at.get(it.id);
            const k = kindOf(it.kind);
            const isSeek = it.id.startsWith('seek:');
            const rad = grpRad(it);
            const cx = colX[p.col] + shapeX[p.col];
            const room = colW[p.col] - textX.att - 4;
            const t = grpText(it);
            const g = svgEl('g', { class: ['fl-node', 'fl-group', isSeek && 'seek', it.shared && 'shared'].filter(Boolean).join(' ') });
            if (it.flags.length)
                flagRing(g, cx, p.y, rad);
            g.append(it.shared ? svgEl('rect', { x: cx - rad, y: p.y - rad, width: rad * 2, height: rad * 2, rx: 3, fill: `var(${k.color})` }) :
                svgEl('circle', { cx, cy: p.y, r: rad, fill: isSeek ? 'none' : `var(${k.color})`, stroke: `var(${k.color})` }));
            if (isSeek && narrow)
                g.append(svgEl('text', { x: cx, y: p.y + rad + fs.main + 2, 'text-anchor': 'middle' }, format.count(it.members.length)));
            else if (t.length === 2)
                g.append(label(colX[p.col] + textX.att, p.y, t[0], null, room), label(colX[p.col] + textX.att, p.y + fs.main, t[1], 'fl-sub', room));
            else
                g.append(label(colX[p.col] + textX.att, p.y + fs.main / 3, t[0], null, room));
            g.append(svgEl('title', {}, `${k.title}: ${groupLabel(it)}${it.flags.length ? `\n${[...new Set(it.flags.map((f) => f.title))].join('\n')}` : ''}`));
            g.addEventListener('click', (e) => pick({ ...it, title: `${k.title}: ${groupLabel(it)}` }, e));
            nodesG.append(g);
        }
        // column headings
        const heads = { seek: narrow ? '' : 'Looking', name: 'Networks', hub: narrow ? 'APs' : 'Access points', att: 'On them' };
        const headH = narrow ? 16 : 20;
        const top = svgEl('svg', { viewBox: `0 0 ${drawnW} ${headH}`, width: drawnW, height: headH, class: `fl-heads${narrow ? ' narrow' : ''}` });
        for (const c of cols)
            top.append(svgEl('text', { x: colX[c], y: headH - 6 }, heads[c]));
        svgBox.replaceChildren(top, svg);
    }

    function drawTable(r) {
        const cols = [...r.names.filter((n) => !n.sought).map((n) => ({ id: n.id, label: n.label, item: n })),
            ...r.attached.flatMap((g) => g.members.map((d) => ({ id: d.id, label: d.label, dev: d, kind: g.kind })))];
        const seen = new Set();
        const uniq = cols.filter((c) => !seen.has(c.id) && seen.add(c.id));
        const has = (a, b) => linkKind.get(`${a.id}|${b.id}`);
        const table = el('table', { class: 'fl-mx' });
        table.append(el('thead', {}, el('tr', {}, el('th', { class: 'corner' }),
            ...uniq.map((c) => el('th', { title: c.label }, el('span', { class: c.dev ? 'dev' : 'name', onclick: () => c.dev && onPick?.(c.dev.key) }, c.label))))));
        const body = el('tbody');
        for (const h of r.hubs) {
            h.members.forEach((m, i) => {
                body.append(el('tr', { class: i === 0 ? 'grp' : null },
                    el('th', { title: m.mac, onclick: () => onPick?.(m.key) }, i === 0 ? el('span', { class: 'fl-mx-hub' }, h.label) : null, el('span', { class: 'muted mono' }, m.mac ?? '')),
                    ...uniq.map((c) => {
                        const k = has(m, c.item?.thing ?? c.dev);
                        return el('td', { style: k ? { background: `var(${kindOf(k).color})` } : null, title: k ? kindOf(k).title : null });
                    })));
            });
        }
        table.append(body);
        tableBox.replaceChildren(table);
    }

    let linkKind = new Map();
    function draw() {
        if (!last)
            return;
        const r = last;
        if (!r.hubs.length && !r.names.length) {
            svgBox.replaceChildren(el('p', { class: 'muted fl-empty' }, 'No relations among the devices heard in this window yet.'));
            tableBox.replaceChildren();
        } else {
            if (!svgBox.hidden)
                drawLines(r);
            if (!tableBox.hidden)
                drawTable(r);
        }
        quiet.textContent = r.quietHubs.length ?
            `${plural(r.quietHubs.length, 'more access point', 'more access points')} with nothing else related in this window.` : '';
        const kinds = [...new Set(r.edges.map((e) => e.kind))];
        legend.replaceChildren(...kinds.map((id) => {
            const k = kindOf(id);
            return el('span', {}, el('span', { class: ['cg-line', k.style].join(' '), style: { borderColor: `var(${k.color})` } }), k.title);
        }));
    }

    const resize = new ResizeObserver(() => {
        const was = both;
        layout();
        if (was !== both || (!svgBox.hidden && Math.abs((svgBox.clientWidth || 0) - width) > 4))
            draw();
    });
    resize.observe(node);
    setMode('lines');

    return {
        node,
        update(graph, findings) {
            linkKind = new Map(graph.links.flatMap((l) => [[`${l.a.id}|${l.b.id}`, l.kind], [`${l.b.id}|${l.a.id}`, l.kind]]));
            last = gather(graph, findings);
            draw();
        },
        destroy() {
            resize.disconnect();
        },
    };
}
