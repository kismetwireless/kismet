// The device graph: devices and the things they share (a network name),
// pulled together by how they relate, laid out by a small force simulation.
// Packets a device sent since the last read travel along its live links as
// dots, so busy links visibly flow.  Findings ring the devices they name,
// and groups (several addresses that are one device) get a shaded hull.
//
//   const c = constellation({ onPick: (node) => ..., linkKinds });
//   c.update(graph, findings);    after each read
//   c.focus(keys)                 light up some devices and center on them
//   c.show() / c.hide()           run the animation only while showing

import { el, replace } from '../../core/dom.js';
import * as theme from '../../core/theme.js';
import * as format from '../../core/format.js';

const pollSeconds = 3;
const roleSize = { ap: 7, client: 4, probe: 3.5, bridge: 5, other: 4 };

function convexHull(points) {
    const p = [...points].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    if (p.length < 3)
        return p;
    const cross = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
    const lower = [], upper = [];
    for (const pt of p) {
        while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], pt) <= 0)
            lower.pop();
        lower.push(pt);
    }
    for (const pt of p.reverse()) {
        while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], pt) <= 0)
            upper.pop();
        upper.push(pt);
    }
    return [...lower.slice(0, -1), ...upper.slice(0, -1)];
}

export function constellation({ onPick = null, linkKinds }) {
    const canvas = el('canvas', { class: 'cg-canvas' });
    const tip = el('div', { class: 'cg-tip', hidden: true });
    const legend = el('div', { class: 'cg-legend' });
    const hint = el('div', { class: 'cg-hint muted' }, 'Drag to move, scroll to zoom, double-click to fit.  Click a device for its details.');
    const node = el('div', { class: 'cg' }, canvas, legend, tip, hint);
    const ctx = canvas.getContext('2d');

    let nodes = [];
    let links = [];
    let byId = new Map();
    let findings = [];
    let particles = [];
    let alpha = 1;
    let view = { x: 0, y: 0, k: 1 };
    let fitted = false;
    let width = 0, height = 0, dpr = 1;
    let hover = null;
    let focusSet = null;
    let drag = null;
    let running = false;
    let raf = 0;
    let colors = {};

    function readColors() {
        for (const name of ['--accent', '--ok', '--warn', '--error', '--text', '--muted', '--border', '--surface', '--surface-2', '--bg'])
            colors[name] = theme.themeColor(name) || '#888';
    }
    readColors();
    const offTheme = theme.onChange(() => {
        readColors();
        draw();
    });

    const resize = new ResizeObserver(() => {
        const r = canvas.getBoundingClientRect();
        dpr = window.devicePixelRatio || 1;
        width = r.width;
        height = r.height;
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
        if (!fitted && nodes.length)
            fit();
        draw();
    });
    resize.observe(canvas);

    const radius = (n) => {
        if (n.kind === 'thing')
            return n.w ? Math.max(n.w, n.h) / 2 : 12;
        const r = roleSize[n.role] ?? 4;
        return n.role === 'ap' ? r + Math.min(8, 1.6 * Math.sqrt(n.degree)) : r + Math.min(3, Math.log1p((n.sentSince + n.gotSince) / pollSeconds));
    };

    function kindOf(l) {
        return linkKinds.get(l.kind) ?? { style: 'solid', color: '--muted', length: 60, live: false };
    }

    // ---- simulation

    function tick() {
        const n = nodes.length;
        const cx = 0, cy = 0;
        for (const l of links) {
            const a = l.a, b = l.b;
            let dx = b.x - a.x, dy = b.y - a.y;
            const d = Math.hypot(dx, dy) || 0.01;
            const len = kindOf(l).length;
            const f = ((d - len) / d) * alpha * 0.25;
            dx *= f;
            dy *= f;
            const wa = b.degree / (a.degree + b.degree), wb = 1 - wa;
            if (!b.fixed) {
                b.vx -= dx * wb;
                b.vy -= dy * wb;
            }
            if (!a.fixed) {
                a.vx += dx * wa;
                a.vy += dy * wa;
            }
        }
        for (let i = 0; i < n; i++) {
            const a = nodes[i];
            for (let j = i + 1; j < n; j++) {
                const b = nodes[j];
                let dx = b.x - a.x, dy = b.y - a.y;
                let d2 = dx * dx + dy * dy;
                if (d2 > 160000)
                    continue;
                if (d2 < 1) {
                    dx = Math.random() - 0.5;
                    dy = Math.random() - 0.5;
                    d2 = 1;
                }
                const ra = radius(a) + radius(b) + 6;
                const strength = (a.charge + b.charge) * alpha / d2;
                let fx = dx * strength, fy = dy * strength;
                // keep them from overlapping
                if (d2 < ra * ra) {
                    const d = Math.sqrt(d2);
                    const push = ((ra - d) / d) * 0.5;
                    fx += dx * push;
                    fy += dy * push;
                }
                if (!a.fixed) {
                    a.vx -= fx;
                    a.vy -= fy;
                }
                if (!b.fixed) {
                    b.vx += fx;
                    b.vy += fy;
                }
            }
            if (!a.fixed) {
                a.vx += (cx - a.x) * 0.025 * alpha;
                a.vy += (cy - a.y) * 0.025 * alpha;
            }
        }
        for (const a of nodes) {
            if (a.fixed)
                continue;
            a.vx *= 0.55;
            a.vy *= 0.55;
            a.x += a.vx;
            a.y += a.vy;
        }
        alpha = Math.max(0, alpha * 0.985);
    }

    function fit() {
        if (!nodes.length || !width)
            return;
        let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
        for (const n of nodes) {
            x0 = Math.min(x0, n.x);
            y0 = Math.min(y0, n.y);
            x1 = Math.max(x1, n.x);
            y1 = Math.max(y1, n.y);
        }
        const k = Math.min(2, 0.88 * Math.min(width / Math.max(80, x1 - x0), height / Math.max(80, y1 - y0)));
        view = { k, x: width / 2 - k * (x0 + x1) / 2, y: height / 2 - k * (y0 + y1) / 2 };
        fitted = true;
    }

    // ---- drawing

    function setDash(style) {
        ctx.setLineDash(style === 'dashed' ? [5, 4] : style === 'dotted' ? [1.5, 3] : []);
    }

    function lit(n) {
        if (!focusSet)
            return true;
        return focusSet.has(n.id);
    }

    function measureThing(n) {
        ctx.font = '11px system-ui, sans-serif';
        n.w = Math.ceil(ctx.measureText(n.label).width) + 14;
        n.h = 18;
    }

    function draw(now = performance.now()) {
        if (!width)
            return;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);
        ctx.setTransform(dpr * view.k, 0, 0, dpr * view.k, dpr * view.x, dpr * view.y);
        const pulse = 0.5 + 0.5 * Math.sin(now / 350);

        // hulls around groups that are one device
        for (const f of findings) {
            if (!f.hull)
                continue;
            const members = f.devices.map((k) => byId.get(k)).filter(Boolean);
            if (members.length < 2)
                continue;
            const pts = [];
            for (const m of members)
                for (let a = 0; a < 8; a++)
                    pts.push([m.x + 16 * Math.cos(a * Math.PI / 4), m.y + 16 * Math.sin(a * Math.PI / 4)]);
            const hull = convexHull(pts);
            ctx.globalAlpha = focusSet && !members.some(lit) ? 0.25 : 1;
            ctx.beginPath();
            hull.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
            ctx.closePath();
            ctx.fillStyle = colors['--accent'];
            ctx.globalAlpha *= 0.09;
            ctx.fill();
            ctx.globalAlpha = focusSet && !members.some(lit) ? 0.25 : 0.7;
            ctx.strokeStyle = colors['--accent'];
            ctx.lineWidth = 1 / view.k;
            ctx.setLineDash([4 / view.k, 3 / view.k]);
            ctx.stroke();
            ctx.setLineDash([]);
            const top = hull.reduce((m, p) => (p[1] < m[1] ? p : m), hull[0]);
            ctx.fillStyle = colors['--accent'];
            ctx.font = `${11 / Math.max(1, view.k * 0.9)}px system-ui, sans-serif`;
            ctx.textAlign = 'center';
            ctx.fillText(`${members.length} addresses, one device?`, top[0], top[1] - 4);
        }

        // links
        for (const l of links) {
            const k = kindOf(l);
            const on = lit(l.a) && lit(l.b);
            ctx.globalAlpha = on ? (k.style === 'solid' ? 0.55 : 0.45) : 0.06;
            ctx.strokeStyle = colors[k.color] ?? colors['--muted'];
            ctx.lineWidth = (k.live ? 1.4 : 1) / Math.sqrt(view.k);
            setDash(k.style);
            ctx.beginPath();
            ctx.moveTo(l.a.x, l.a.y);
            ctx.lineTo(l.b.x, l.b.y);
            ctx.stroke();
        }
        ctx.setLineDash([]);

        // packets in flight
        const t = performance.now();
        particles = particles.filter((p) => t < p.t0 + p.dur);
        for (const p of particles) {
            if (t < p.t0)
                continue;
            const f = (t - p.t0) / p.dur;
            const [from, to] = p.up ? [p.l.a, p.l.b] : [p.l.b, p.l.a];
            const x = from.x + (to.x - from.x) * f, y = from.y + (to.y - from.y) * f;
            ctx.globalAlpha = (lit(p.l.a) && lit(p.l.b) ? 0.9 : 0.1) * Math.sin(Math.PI * f);
            ctx.fillStyle = p.up ? colors['--ok'] : colors['--accent'];
            ctx.beginPath();
            ctx.arc(x, y, 1.9, 0, 2 * Math.PI);
            ctx.fill();
        }

        // nodes
        for (const n of nodes) {
            const on = lit(n);
            ctx.globalAlpha = on ? 1 : 0.15;
            if (n.kind === 'thing') {
                if (!n.w)
                    measureThing(n);
                const x = n.x - n.w / 2, y = n.y - n.h / 2;
                const sought = n.thingKind === 'ssid-sought';
                ctx.beginPath();
                ctx.roundRect(x, y, n.w, n.h, 9);
                ctx.fillStyle = colors['--surface'];
                ctx.fill();
                ctx.lineWidth = 1;
                ctx.strokeStyle = n.flags.length ? colors['--error'] : sought ? colors['--muted'] : colors['--accent'];
                setDash(sought ? 'dashed' : 'solid');
                ctx.stroke();
                ctx.setLineDash([]);
                ctx.fillStyle = sought ? colors['--muted'] : colors['--text'];
                ctx.font = `${sought ? 'italic ' : ''}11px system-ui, sans-serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(n.label, n.x, n.y + 0.5);
                ctx.textBaseline = 'alphabetic';
                continue;
            }
            const r = radius(n);
            const open = n.role === 'ap' && /^(Open|None)?$/i.test(n.crypt ?? '');
            const fill = n.role === 'ap' ? (open ? colors['--warn'] : colors['--accent']) :
                n.role === 'client' ? colors['--ok'] : colors['--muted'];
            ctx.beginPath();
            if (n.role === 'bridge')
                ctx.roundRect(n.x - r, n.y - r, 2 * r, 2 * r, 2);
            else
                ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
            const probeOnly = n.role === 'client' && !n.aps?.length;
            if (probeOnly) {
                ctx.fillStyle = colors['--surface'];
                ctx.fill();
                ctx.lineWidth = 1.4;
                ctx.strokeStyle = colors['--ok'];
                ctx.stroke();
            } else {
                ctx.fillStyle = fill;
                ctx.fill();
                if (n.role === 'ap') {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, r * 0.38, 0, 2 * Math.PI);
                    ctx.fillStyle = colors['--surface'];
                    ctx.fill();
                }
            }
            if (n.flags.length) {
                ctx.beginPath();
                ctx.arc(n.x, n.y, r + 4 + 3 * pulse, 0, 2 * Math.PI);
                ctx.strokeStyle = colors['--error'];
                ctx.lineWidth = 1.6;
                ctx.globalAlpha = on ? 0.5 + 0.5 * (1 - pulse) : 0.15;
                ctx.stroke();
                ctx.globalAlpha = on ? 1 : 0.15;
            }
            const showLabel = n === hover || (focusSet && focusSet.has(n.id) && focusSet.size < 14) ||
                view.k > 1.7 || (n.role === 'ap' && !n.named);
            if (showLabel) {
                ctx.font = '10.5px system-ui, sans-serif';
                ctx.textAlign = 'left';
                ctx.fillStyle = colors['--text'];
                ctx.fillText(n.label, n.x + r + 3, n.y + 3.5);
            }
        }
        ctx.globalAlpha = 1;
    }

    function loop() {
        if (!running)
            return;
        if (alpha > 0.004 && !drag) {
            tick();
        } else if (drag) {
            alpha = Math.max(alpha, 0.08);
            tick();
        }
        draw();
        raf = requestAnimationFrame(loop);
    }

    // ---- interaction

    const toWorld = (ev) => {
        const r = canvas.getBoundingClientRect();
        return [(ev.clientX - r.left - view.x) / view.k, (ev.clientY - r.top - view.y) / view.k];
    };

    function hit(x, y) {
        let best = null, bd = Infinity;
        for (const n of nodes) {
            const d = n.kind === 'thing' && n.w ?
                (Math.abs(x - n.x) <= n.w / 2 && Math.abs(y - n.y) <= n.h / 2 ? 0 : Infinity) :
                Math.hypot(x - n.x, y - n.y) - radius(n);
            if (d < 5 / view.k && d < bd) {
                bd = d;
                best = n;
            }
        }
        return best;
    }

    function neighbours(n) {
        const s = new Set([n.id]);
        for (const l of links) {
            if (l.a === n)
                s.add(l.b.id);
            else if (l.b === n)
                s.add(l.a.id);
        }
        return s;
    }

    function showTip(n, ev) {
        if (!n) {
            tip.hidden = true;
            return;
        }
        const lines = [];
        if (n.kind === 'thing') {
            lines.push(el('b', {}, n.label));
            const ads = n.advertisers?.length ?? 0;
            lines.push(el('div', {}, n.thingKind === 'ssid-sought' ? 'A network name devices look for, not heard advertised' :
                `A network name, advertised by ${ads} access point${ads === 1 ? '' : 's'}`));
            const seekers = links.filter((l) => l.b === n && l.kind === 'dot11-probe').length;
            if (seekers)
                lines.push(el('div', {}, `${seekers} device${seekers === 1 ? '' : 's'} looked for it`));
        } else {
            const rec = n.rec ?? {};
            lines.push(el('b', {}, n.label));
            if (n.label !== n.mac)
                lines.push(el('div', { class: 'mono' }, n.mac));
            lines.push(el('div', {}, [rec['kismet.device.base.type'], rec['kismet.device.base.manuf'] !== 'Unknown' && rec['kismet.device.base.manuf']].filter(Boolean).join(' · ')));
            if (n.crypt !== undefined && n.role === 'ap')
                lines.push(el('div', {}, `Security: ${n.crypt || 'unknown'}`));
            const sig = rec['kismet.device.base.signal/kismet.common.signal.last_signal'] ?? rec['kismet.common.signal.last_signal'];
            if (sig)
                lines.push(el('div', {}, `Signal ${sig} dBm`));
            const rate = (n.sentSince + n.gotSince) / pollSeconds;
            lines.push(el('div', {}, `${format.count(Math.round(rate * 10) / 10)} packets/s just now`));
            for (const f of findings)
                if (f.devices?.includes(n.key))
                    lines.push(el('div', { class: f.severity === 'high' ? 'error-text' : 'warn-text' }, f.title));
        }
        tip.replaceChildren(...lines);
        tip.hidden = false;
        const r = node.getBoundingClientRect();
        const x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 12;
        tip.style.left = `${Math.min(x, r.width - tip.offsetWidth - 8)}px`;
        tip.style.top = `${Math.min(y, r.height - tip.offsetHeight - 8)}px`;
    }

    let downAt = null;
    canvas.addEventListener('pointerdown', (ev) => {
        canvas.setPointerCapture(ev.pointerId);
        const [x, y] = toWorld(ev);
        const n = hit(x, y);
        downAt = [ev.clientX, ev.clientY];
        drag = n ? { node: n, moved: false } : { pan: true, x: ev.clientX - view.x, y: ev.clientY - view.y, moved: false };
        if (n) {
            n.fixed = true;
            n.x = x;
            n.y = y;
        }
    });
    canvas.addEventListener('pointermove', (ev) => {
        if (drag) {
            if (Math.hypot(ev.clientX - downAt[0], ev.clientY - downAt[1]) > 3)
                drag.moved = true;
            if (drag.node) {
                const [x, y] = toWorld(ev);
                drag.node.x = x;
                drag.node.y = y;
                drag.node.vx = drag.node.vy = 0;
            } else {
                view.x = ev.clientX - drag.x;
                view.y = ev.clientY - drag.y;
            }
            if (!running)
                draw();
            return;
        }
        const [x, y] = toWorld(ev);
        const n = hit(x, y);
        if (n !== hover) {
            hover = n;
            focusSet = n ? neighbours(n) : pinned;
            canvas.style.cursor = n ? 'pointer' : 'grab';
        }
        showTip(n, ev);
        if (!running)
            draw();
    });
    canvas.addEventListener('pointerleave', () => {
        hover = null;
        focusSet = pinned;
        tip.hidden = true;
    });
    let pinned = null;
    canvas.addEventListener('pointerup', () => {
        if (!drag)
            return;
        const d = drag;
        drag = null;
        if (d.node) {
            // a dragged device stays where it was put; a click releases it
            if (!d.moved) {
                d.node.fixed = false;
                if (d.node.kind === 'device')
                    onPick?.(d.node);
            }
        } else if (!d.moved) {
            pinned = null;
            focusSet = null;
        }
    });
    canvas.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const r = canvas.getBoundingClientRect();
        const mx = ev.clientX - r.left, my = ev.clientY - r.top;
        const k = Math.min(6, Math.max(0.15, view.k * Math.exp(-ev.deltaY * 0.0015)));
        view.x = mx - (mx - view.x) * (k / view.k);
        view.y = my - (my - view.y) * (k / view.k);
        view.k = k;
        if (!running)
            draw();
    }, { passive: false });
    canvas.addEventListener('dblclick', () => {
        fit();
        if (!running)
            draw();
    });

    function renderLegend() {
        const kinds = [...new Set(links.map((l) => l.kind))].map((k) => linkKinds.get(k)).filter(Boolean);
        const swatch = (cls, style) => el('span', { class: ['cg-sw', cls], style });
        replace(legend,
            el('span', {}, swatch('ap'), 'Access point'),
            el('span', {}, swatch('ap open'), 'Open'),
            el('span', {}, swatch('client'), 'Client'),
            el('span', {}, swatch('probe'), 'Only looking'),
            el('span', {}, swatch('ssid'), 'Network name'),
            ...kinds.map((k) => el('span', {}, el('span', { class: ['cg-line', k.style], style: { borderTopColor: `var(${k.color})` } }), k.title)));
    }

    return {
        node,
        update(graph, found, { lone = false } = {}) {
            const first = nodes.length === 0;
            const old = byId;
            nodes = [...graph.nodes.values()].filter((n) => lone || n.degree > 0 || n.flags.length > 0);
            byId = new Map(nodes.map((n) => [n.id, n]));
            links = graph.links;
            findings = found;
            let fresh = 0;
            for (const n of nodes)
                n.named = false;
            for (const l of links)
                if (kindOf(l).names)
                    l.a.named = true;
            for (const n of nodes) {
                n.charge = n.kind === 'thing' ? 260 : n.role === 'ap' ? 420 : 140;
                if (n.kind === 'thing')
                    measureThing(n);
                if (n.x === undefined) {
                    fresh++;
                    // start next to something it links to, if that has a place
                    const l = links.find((x) => (x.a === n && x.b.x !== undefined) || (x.b === n && x.a.x !== undefined));
                    const anchor = l ? (l.a === n ? l.b : l.a) : null;
                    const ang = Math.random() * 2 * Math.PI;
                    const d = anchor ? 30 : 150 + Math.random() * 150;
                    n.x = (anchor?.x ?? 0) + d * Math.cos(ang);
                    n.y = (anchor?.y ?? 0) + d * Math.sin(ang);
                    n.vx = n.vy = 0;
                }
            }
            if (first || fresh || old.size !== byId.size)
                alpha = Math.max(alpha, first ? 1 : 0.35);
            if (first) {
                for (let i = 0; i < 300; i++)
                    tick();
                fit();
            }

            // packets since the last read, spread over the next interval
            const t = performance.now();
            for (const l of links) {
                if (!kindOf(l).live)
                    continue;
                const dev = l.a.kind === 'device' ? l.a : null;
                if (!dev)
                    continue;
                const up = Math.min(10, Math.round(dev.sentSince / 2));
                const down = Math.min(10, Math.round(dev.gotSince / 2));
                for (let i = 0; i < up; i++)
                    particles.push({ l, up: true, t0: t + Math.random() * pollSeconds * 1000, dur: 700 + Math.random() * 400 });
                for (let i = 0; i < down; i++)
                    particles.push({ l, up: false, t0: t + Math.random() * pollSeconds * 1000, dur: 700 + Math.random() * 400 });
            }
            if (particles.length > 3000)
                particles = particles.slice(-3000);
            if (hover && !byId.has(hover.id))
                hover = null;
            renderLegend();
            if (!running)
                draw();
        },
        focus(keys) {
            const s = new Set(keys.filter((k) => byId.has(k)));
            for (const k of [...s])
                for (const id of neighbours(byId.get(k)))
                    if (byId.get(id)?.kind === 'thing')
                        s.add(id);
            pinned = s.size ? s : null;
            focusSet = pinned;
            const pts = keys.map((k) => byId.get(k)).filter(Boolean);
            if (pts.length && width) {
                const cx = pts.reduce((a, n) => a + n.x, 0) / pts.length, cy = pts.reduce((a, n) => a + n.y, 0) / pts.length;
                view.k = Math.max(view.k, 1.2);
                view.x = width / 2 - view.k * cx;
                view.y = height / 2 - view.k * cy;
            }
            if (!running)
                draw();
        },
        show() {
            if (running)
                return;
            running = true;
            raf = requestAnimationFrame(loop);
        },
        hide() {
            running = false;
            cancelAnimationFrame(raf);
        },
        destroy() {
            running = false;
            cancelAnimationFrame(raf);
            resize.disconnect();
            offTheme();
        },
    };
}
