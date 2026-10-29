// The access points view: a card for each access point (its addresses
// together) with the networks it offers and the devices on it, then the
// devices shared by many (a wired network), the devices that only look for
// networks, and the quiet access points.  Reads well on a phone.
//
//   const c = apCards({ onPick: (key) => ..., linkKinds });
//   c.update(graph, findings)

import { el } from '../../core/dom.js';
import * as format from '../../core/format.js';
import { gather, unitName } from './groups.js';

const chipMax = 24;

export function apCards({ onPick = null, linkKinds }) {
    const node = el('div', { class: 'ac' });
    const kindOf = (id) => linkKinds.get(id) ?? { title: id, color: '--muted' };

    function chip(dev, kind, flags) {
        const k = kindOf(kind);
        const f = flags.get(dev.key);
        return el('button', { type: 'button', class: ['ac-chip', f && 'flag'], title: [dev.mac, ...(f ?? []).map((x) => x.title)].join('\n'),
            onclick: () => onPick?.(dev.key) },
        el('span', { class: 'ac-dot', style: { background: `var(${k.color})` } }), dev.label);
    }

    function chips(devs, kind, flags) {
        return [...devs.slice(0, chipMax).map((d) => chip(d, kind, flags)),
            devs.length > chipMax ? el('span', { class: 'muted ac-more' }, `and ${format.count(devs.length - chipMax)} more`) : null];
    }

    function card(title, side, ...body) {
        return el('article', { class: 'ac-card' }, el('header', {}, el('h3', {}, title), side ? el('span', { class: 'muted' }, side) : null), ...body);
    }

    return {
        node,
        update(graph, findings) {
            const r = gather(graph, findings);
            const out = [];
            const onHub = new Map();
            for (const e of r.edges) {
                if (!e.from.unit || e.to.unit)
                    continue;
                if (!onHub.has(e.from.id))
                    onHub.set(e.from.id, []);
                onHub.get(e.from.id).push(e);
            }
            const hubs = [...r.hubs].sort((a, b) => (onHub.get(b.id)?.reduce((s, e) => s + e.count, 0) ?? 0) -
                (onHub.get(a.id)?.reduce((s, e) => s + e.count, 0) ?? 0));
            for (const h of hubs) {
                const rows = [];
                for (const e of onHub.get(h.id) ?? []) {
                    const k = kindOf(e.kind);
                    const devs = e.to.members.filter((d) => e.members.has(d));
                    if (e.to.shared)
                        rows.push(el('div', { class: 'ac-row muted' }, el('span', {}, el('span', { class: 'ac-dot sq', style: { background: `var(${k.color})` } }),
                            ` ${format.count(devs.length)} of the ${format.count(e.to.members.length)} ${k.groupTitle ?? 'devices'} shared with other access points`)));
                    else
                        rows.push(el('div', { class: 'ac-row' }, ...chips(devs, e.kind, r.flagged)));
                }
                out.push(card(el('button', { type: 'button', class: 'link-button', title: h.members.map((m) => m.mac).join('\n'),
                    onclick: () => onPick?.(h.members[0].key) }, h.label),
                `${h.members.length > 1 ? `${h.members.length} addresses · ` : ''}${h.channels.length ? `ch ${h.channels.join(', ')}` : ''}`,
                h.names.size ? el('div', { class: 'ac-names' }, ...[...h.names].sort().map((n) => el('span', { class: 'ac-name' }, n))) : null,
                ...rows));
            }
            for (const g of r.attached.filter((x) => x.shared)) {
                const k = kindOf(g.kind);
                const hubsOf = (d) => r.edges.filter((e) => e.to === g && e.members.has(d)).length;
                const devs = [...g.members].sort((a, b) => hubsOf(b) - hubsOf(a));
                const n = r.edges.filter((e) => e.to === g).length;
                out.push(card(`${format.count(devs.length)} ${k.groupTitle ?? 'devices'}`, k.title,
                    el('p', { class: 'muted ac-note' }, `Seen behind ${format.count(n)} access points, so they share one network.  Most seen first:`),
                    el('div', { class: 'ac-row' }, ...chips(devs, g.kind, r.flagged))));
            }
            for (const s of r.seekers) {
                const k = kindOf(s.kind);
                const names = r.edges.filter((e) => e.from === s).map((e) => e.to.label).sort();
                out.push(card(`${format.count(s.members.length)} ${k.groupTitle ?? 'devices'}`, names.length ? names.slice(0, 6).join(', ') + (names.length > 6 ? '…' : '') : '',
                    el('div', { class: 'ac-row' }, ...chips(s.members, s.kind, r.flagged))));
            }
            if (r.quietHubs.length)
                out.push(card('Quiet access points', format.count(r.quietHubs.length),
                    el('p', { class: 'muted ac-note' }, 'Nothing else related to them in this window.'),
                    el('div', { class: 'ac-row' }, ...r.quietHubs.slice(0, 40).map((u) => el('button', { type: 'button', class: 'ac-chip',
                        title: u.members.map((m) => `${m.label} ${m.mac}`).join('\n'), onclick: () => onPick?.(u.members[0].key) },
                    unitName(u), u.members[0].label !== u.members[0].mac ? el('span', { class: 'muted' }, ` ${u.members[0].label}`) : null)))));
            node.replaceChildren(...(out.length ? out : [el('p', { class: 'muted' }, 'No access points heard in this window yet.')]));
        },
    };
}
