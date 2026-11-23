// Text for linked wired and Wi-Fi records (the server's entities): what a
// link's relationship, Wi-Fi role and evidence mean, and the linking status
// counters worth a warning.  No DOM, so it can be tested on its own;
// js/core/entities.js reads the links and js/base/entities.js draws them.

const relationships = {
    wired_same_mac: 'Same MAC address on Wi-Fi and the wire',
    wired_bridged: 'Wired host bridged onto Wi-Fi',
};

const wifiKinds = {
    client: 'Wi-Fi client',
    client_mgmt: 'Wi-Fi client, heard only in management frames',
    bridged: 'Wired host behind an access point or WDS bridge',
    ap: 'Access point',
    inferred: 'Only ever a destination on Wi-Fi',
};

const evidence = {
    radio_client: 'Sent frames as a Wi-Fi client',
    associated: 'Associated with an access point',
    radio_ap: 'Is a Wi-Fi access point',
    wds_radio: 'Is a WDS bridge radio',
    bridged_from_ds: 'An access point relayed its frames onto Wi-Fi',
    bridged_4addr: 'A WDS bridge relayed its frames',
    local_mac: 'Locally administered (randomized or virtual) MAC address',
    ip_match: 'Its Wi-Fi IPv4 address is on the wired record',
};

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const str = (v) => (typeof v === 'string' ? v : '');
// The words for a name, or the name as it came ('constructor' isn't a name we know)
const words = (table, name) => (Object.hasOwn(table, name) ? table[name] : name);

export const relationshipText = (r) => words(relationships, str(r)) || 'Unknown';
export const wifiKindText = (k) => words(wifiKinds, str(k)) || 'Unknown';

// The evidence of a link in plain words, in the server's order; a name this
// page doesn't know is shown as it came
export function evidenceText(names) {
    if (!Array.isArray(names))
        return [];
    return names.filter((n) => typeof n === 'string' && n !== '').map((n) => words(evidence, n));
}

// A link's confidence, clamped to 0-100
export const confidence = (edge) => Math.max(0, Math.min(100, Math.round(num(edge?.['kismet.entity.edge.confidence']))));

// The link's other record: { key, record } with record null once the server
// has forgotten it
export function peerOf(edge) {
    const key = str(edge?.['kismet.entity.edge.peer_key']);
    const p = edge?.['kismet.entity.edge.peer'];
    const record = Array.isArray(p) && p[0] && typeof p[0] === 'object' ? p[0] : null;
    return { key, record };
}

// BSSIDs or WDS radios a link was heard behind, newest first
export function viaList(edge) {
    const v = edge?.['kismet.entity.edge.via'];
    return Array.isArray(v) ? v.filter((m) => typeof m === 'string' && m !== '') : [];
}

// The linking counters worth telling someone about: each nonzero one as
// { id, text, help }.  Nothing when all is well.
export function statusNotes(st) {
    if (!st || typeof st !== 'object')
        return [];
    const s = (k) => num(st[`kismet.entity.status.${k}`]);
    const n = (v) => v.toLocaleString('en-US');
    const notes = [];
    if (s('index_refused'))
        notes.push({ id: 'index', text: `${n(s('index_refused'))} Ethernet MAC addresses not checked for a Wi-Fi link: ` +
            `the link index of ${n(s('index_capacity'))} was full`,
        help: 'They are found again once the index has room.  It holds twice wired_max_devices in kismet_wired.conf.' });
    if (s('refused_cap'))
        notes.push({ id: 'cap', text: `${n(s('refused_cap'))} links not kept: the limit of ${n(s('max_edges'))} links was reached`,
            help: 'Raise entity_max_edges in kismet_wired.conf.' });
    if (s('refused_per_device'))
        notes.push({ id: 'perdev', text: `${n(s('refused_per_device'))} links not kept: a record already had ` +
            `${n(s('max_edges_per_device'))} links`,
        help: 'entity_max_edges_per_device in kismet_wired.conf limits the links of one record.' });
    if (s('component_capped'))
        notes.push({ id: 'component', text: `${n(s('component_capped'))} links kept as possible links: the group of ` +
            `linked records would have passed ${n(s('max_component'))}`,
        help: 'entity_max_component in kismet_wired.conf limits how many records one entity joins.' });
    if (s('index_deferred'))
        notes.push({ id: 'deferred', text: `${n(s('index_deferred'))} MAC addresses waiting for room under the link limits`,
            help: 'They are linked once links are freed, as records are forgotten.' });
    return notes;
}

// One line on linking, or '' when the server doesn't link
export function statusSummary(st) {
    if (!st || typeof st !== 'object' || !num(st['kismet.entity.status.enabled']))
        return '';
    const s = (k) => num(st[`kismet.entity.status.${k}`]);
    const n = (v) => v.toLocaleString('en-US');
    const possible = Math.max(0, s('edges') - s('linked'));
    return `Linked to Wi-Fi: ${n(s('linked'))} ${s('linked') === 1 ? 'link' : 'links'}` +
        (possible ? `, ${n(possible)} possible` : '') +
        `, ${n(s('records'))} ${s('records') === 1 ? 'record' : 'records'} in ${n(s('entities'))} ` +
        `${s('entities') === 1 ? 'entity' : 'entities'}`;
}
