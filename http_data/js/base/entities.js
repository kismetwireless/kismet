// The "Linked devices" section of the device panel, for every phy: the
// records the server linked to this one (a Wi-Fi record and the Ethernet
// record with the same MAC address), how sure it is, and why.
//
// Shown only for linked records and for records with a possible link; the
// links come from js/core/entities.js.

import { relationshipText, wifiKindText, evidenceText, confidence, peerOf, viaList } from '../core/entityinfo.js';

const base = 'kismet.device.base';
const en = 'kismet.entity';
const ed = 'kismet.entity.edge';

const macPattern = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

export function register(kismet) {
    const { ui, api, dom, icons, format, entities } = kismet;
    const { el } = dom;
    const muted = ui.muted;

    const edgesOf = (reply) => (Array.isArray(reply?.[`${en}.edges`]) ? reply[`${en}.edges`] : []);

    // Redraw a cell only when its value changed, so links stay put between the panel's redraws
    const stable = (build) => (cell, v, rec, state) => {
        const k = JSON.stringify(v ?? null);
        if (state.k === k && cell.childNodes.length)
            return undefined;
        state.k = k;
        dom.replace(cell, build(v, rec));
        return undefined;
    };

    const deviceLink = (key, text) => el('a', { href: '#', class: 'mono', title: 'Open this device', onclick: (e) => {
        e.preventDefault();
        ui.openDevice(key);
    } }, text, ' ', icons.icon('chain'));

    // A BSSID or WDS radio: a link to its Wi-Fi device, if Kismet tracks one
    function macLink(mac) {
        if (!macPattern.test(mac))
            return el('span', { class: 'mono' }, mac);
        const a = el('a', { href: '#', class: 'mono', title: 'Open this device', onclick: async (ev) => {
            ev.preventDefault();
            let key = null;
            try {
                const devs = await api.post(`devices/by-mac/${mac}/devices.json`, { fields: [`${base}.key`, `${base}.phyname`] });
                const list = Array.isArray(devs) ? devs : [];
                key = (list.find((d) => d[`${base}.phyname`] === 'IEEE802.11') ?? list[0])?.[`${base}.key`] ?? null;
            } catch {
                key = null;
            }
            if (key) {
                ui.openDevice(key);
            } else {
                a.title = 'Kismet doesn\'t track a device with this MAC address';
                a.classList.add('muted');
            }
        } }, mac, ' ', icons.icon('chain'));
        return a;
    }

    const threshold = () => {
        const t = entities.status()?.['kismet.entity.status.min_confidence'];
        return typeof t === 'number' ? t : null;
    };

    const edgeFields = [
        { id: 'peer', title: 'Record', value: (x) => peerOf(x).key,
            draw: stable((key, x) => {
                const { record } = peerOf(x);
                if (!record)
                    return [el('span', { class: 'mono' }, x[`${ed}.macaddr`] ?? ''), ' ', muted('No longer tracked')];
                return deviceLink(key, record[`${base}.macaddr`] ?? key);
            }),
            help: 'The linked device record.  The two records stay separate; open this one to see what the other phy saw.' },
        { id: 'state', title: 'Link', value: (x) => [x[`${ed}.linked`], x[`${ed}.conflicted`], confidence(x), threshold()],
            draw: stable((v, x) => {
                const t = threshold();
                const out = [x[`${ed}.linked`] ? el('span', { class: 'badge ok entity-badge' }, 'Linked') :
                    el('span', { class: 'badge alert entity-badge' }, 'Possible link')];
                if (x[`${ed}.conflicted`])
                    out.push(el('span', { class: 'badge error entity-badge', title: 'What the wire saw contradicts this link' }, 'Conflicted'));
                if (!x[`${ed}.linked`])
                    out.push(muted(t === null ? ' below the linking threshold' : ` below the linking threshold of ${t}`));
                return out;
            }),
            help: 'Records are linked when the confidence reaches entity_link_min_confidence in kismet_wired.conf.  ' +
                'Below it they are a possible link: listed here, but not given an entity id.  A conflicted link is one the wire contradicts.' },
        { id: 'confidence', title: 'Confidence', value: confidence,
            draw: stable((c, x) => el('div', { class: ['fill-bar', 'entity-confidence', !x[`${ed}.linked`] && 'possible'],
                role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': c, title: `${c} out of 100` },
            el('span', { class: 'fill-bar-fill', style: { width: `${c}%` } }),
            el('span', { class: 'fill-bar-text' }, `${c} / 100`))),
            help: 'How sure Kismet is that the two records are one device, from the evidence below.  It never reaches 100: ' +
                'a MAC address can be cloned.' },
        { title: 'Relationship', field: `${ed}.relationship`, format: relationshipText },
        { title: 'On Wi-Fi', field: `${ed}.wifi_kind`, format: wifiKindText,
            help: 'What the Wi-Fi record is, which sets how much the shared MAC address counts for.' },
        { id: 'evidence', title: 'Evidence', field: `${ed}.evidence_names`, show: (v) => evidenceText(v).length > 0,
            draw: stable((v) => el('ul', { class: 'entity-evidence' }, evidenceText(v).map((t) => el('li', {}, t)))),
            help: 'What Kismet saw that ties the records together.  Each fact counts once.' },
        { id: 'via', title: 'Heard behind', value: viaList, show: (v) => v.length > 0,
            draw: stable((v) => el('div', { class: 'entity-via' }, v.map((m) => macLink(m)))),
            help: 'The access points (BSSIDs) or WDS bridge radios the Wi-Fi record was heard behind, newest first.' },
        { title: 'First linked', field: `${ed}.first_time`, format: (v) => format.time(v) },
        { title: 'Last confirmed', field: `${ed}.last_time`, format: (v) => format.time(v) },
    ];

    const sectionFields = [
        { id: 'entity', title: 'Entity', field: `${en}.entity_id`,
            format: (v) => (v ? String(v) : muted('Not linked; possible links only')),
            help: 'Linked records share this entity id.  It lasts one server run; device filters and rules can select ' +
                'linked records with exists(kismet.device.base.entity_id).' },
        {
            list: `${en}.edges`,
            itemTitle: (x) => {
                const { record } = peerOf(x);
                return record?.[`${base}.type`] || (record?.[`${base}.phyname`] ?? 'Linked record');
            },
            fields: edgeFields,
        },
    ];

    ui.deviceDetails.add({
        id: 'entity', title: 'Linked devices', priority: 6,
        match: (dev) => {
            // Read for the threshold and to know whether the server links at all
            entities.status();
            return dev[`${base}.entity_id`] !== undefined || edgesOf(entities.linked(dev)).length > 0;
        },
        render: (dev, node) => {
            if (!node.entityParts) {
                node.entityParts = { note: el('p', { class: 'muted' }, 'Loading...'), fields: el('div') };
                node.replaceChildren(node.entityParts.note, node.entityParts.fields);
            }
            const { note, fields } = node.entityParts;
            const reply = entities.linked(dev);
            if (reply === null)
                note.textContent = 'This server doesn\'t list its links.';
            note.hidden = !!reply;
            fields.hidden = !reply;
            if (reply)
                ui.detailFields(fields, reply, sectionFields);
        },
    });
}
