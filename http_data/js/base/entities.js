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

export function register(kismet) {
    const { ui, dom, format, entities } = kismet;
    const { el } = dom;
    const muted = ui.muted;

    const edgesOf = (reply) => (Array.isArray(reply?.[`${en}.edges`]) ? reply[`${en}.edges`] : []);

    // Redraw a cell only when its value changed, so links stay put between
    // the panel's redraws.  build() draws from the value alone, so everything
    // it shows has to be in the value.
    const stable = (build) => (cell, v, rec, state) => {
        const k = JSON.stringify(v ?? null);
        if (state.k === k && cell.childNodes.length)
            return undefined;
        state.k = k;
        dom.replace(cell, build(v));
        return undefined;
    };

    const threshold = () => {
        const t = entities.status()?.['kismet.entity.status.min_confidence'];
        return typeof t === 'number' ? t : null;
    };

    const edgeFields = [
        { id: 'peer', title: 'Record',
            value: (x) => {
                const { key, record } = peerOf(x);
                return record ? { key, mac: record[`${base}.macaddr`] ?? key } : { key: null, mac: x[`${ed}.macaddr`] ?? '' };
            },
            draw: stable(({ key, mac }) => (key ? ui.deviceLink(key, mac) :
                [el('span', { class: 'mono' }, mac), ' ', muted('No longer tracked')])),
            help: 'The linked device record.  The two records stay separate; open this one to see what the other phy saw.' },
        { id: 'state', title: 'Link', value: (x) => ({ linked: !!x[`${ed}.linked`], conflicted: !!x[`${ed}.conflicted`], t: threshold() }),
            draw: stable(({ linked, conflicted, t }) => {
                const out = [linked ? el('span', { class: 'badge ok entity-badge' }, 'Linked') :
                    el('span', { class: 'badge alert entity-badge' }, 'Possible link')];
                if (conflicted)
                    out.push(el('span', { class: 'badge error entity-badge', title: 'What the wire saw contradicts this link' }, 'Conflicted'));
                if (!linked)
                    out.push(muted(t === null ? ' below the linking threshold' : ` below the linking threshold of ${t}`));
                return out;
            }),
            help: 'Records are linked when the confidence reaches entity_link_min_confidence in kismet_wired.conf.  ' +
                'Below it they are a possible link: listed here, but not given an entity id.  A conflicted link is one the wire contradicts.' },
        { id: 'confidence', title: 'Confidence', value: (x) => ({ c: confidence(x), linked: !!x[`${ed}.linked`] }),
            draw: stable(({ c, linked }) => el('div', { class: ['fill-bar', 'entity-confidence', !linked && 'possible'],
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
            draw: stable((v) => el('div', { class: 'entity-via' }, v.map((m) => ui.macLink(m, { phy: 'IEEE802.11' })))),
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
