// Wi-Fi in the Insights tab: how Wi-Fi devices relate (a client and its
// access point, an access point and its network name, a device and the
// network names it looks for or answers to), and the unusual things those
// relations show.

const phy = 'IEEE802.11';
const base = 'kismet.device.base';
const ssidRec = 'dot11.device/dot11.device.last_beaconed_ssid_record';

const fields = [
    [`dot11.device/dot11.device.associated_client_map`, 'd11_clients'],
    [`${ssidRec}/dot11.advertisedssid.ssid`, 'd11_ssid'],
    [`${ssidRec}/dot11.advertisedssid.crypt_string`, 'd11_crypt'],
    [`${ssidRec}/dot11.advertisedssid.channel`, 'd11_channel'],
    [`${ssidRec}/dot11.advertisedssid.first_time`, 'd11_ssid_first'],
    [`${ssidRec}/dot11.advertisedssid.dot11s.meshid`, 'd11_meshid'],
    [`dot11.device/dot11.device.probed_ssid_map`, 'd11_probed'],
    [`dot11.device/dot11.device.responded_ssid_map`, 'd11_responded'],
    [`dot11.device/dot11.device.mbssid_transmitter`, 'd11_mbssid_tx'],
    [`dot11.device/dot11.device.karma`, 'd11_karma'],
];

// The server's karma thresholds (dot11_karma_min_matched, _min_unbeaconed),
// for the guess made when an older server has no karma detection
const karmaMinMatched = 3;
const karmaMinAnswered = 10;
// dot11.karma.reason: bit 1 answers for networks it doesn't advertise, bit 2 a beaconed pool
const karmaReasonPool = 2;

const list = (v) => (Array.isArray(v) ? v : v && typeof v === 'object' ? Object.values(v) : []);
const ssidId = (ssid) => `dot11-ssid:${ssid}`;
const meshId = (id) => `dot11-mesh:${id}`;

// A locally administered address, as phones use when they randomize
const randomized = (mac) => /^.[26AE]/i.test(mac ?? '');

function jaccard(a, b) {
    let both = 0;
    for (const x of a)
        both += b.has(x);
    const either = a.size + b.size - both;
    return either ? both / either : 0;
}

export function registerInsights(kismet) {
    const { ui, format } = kismet;
    const { insightRelations, linkKinds, insightFindings } = ui;

    linkKinds.add({ id: 'dot11-assoc', title: 'Wi-Fi client of', groupTitle: 'clients', color: '--ok', length: 46, live: true });
    linkKinds.add({ id: 'dot11-wired', title: 'Wired host behind', groupTitle: 'wired hosts', color: '--muted', style: 'dotted', length: 70, live: true });
    linkKinds.add({ id: 'dot11-advert', title: 'Advertises', color: '--accent', length: 34, names: true });
    linkKinds.add({ id: 'dot11-probe', title: 'Looks for', groupTitle: 'looking for networks', color: '--muted', style: 'dashed', length: 90 });
    linkKinds.add({ id: 'dot11-respond', title: 'Answers for', groupTitle: 'answering for networks', color: '--error', style: 'dashed', length: 70 });
    linkKinds.add({ id: 'dot11-mesh', title: 'Mesh point of', groupTitle: 'mesh points', color: '--warn', length: 40, names: true });
    // not a line: the networks one radio sends in its multiple BSSID element
    linkKinds.add({ id: 'dot11-mbssid', title: 'Multiple BSSID set', groupTitle: 'networks in its multiple BSSID set',
        short: 'MBSSID', color: '--accent' });

    insightRelations.add({
        id: 'dot11', fields,
        relate(rec, g) {
            if (rec[`${base}.phyname`] !== phy)
                return;
            const n = g.device(rec[`${base}.key`]);
            if (!n)
                return;
            const type = rec[`${base}.type`] ?? '';
            g.role(n, /AP/.test(type) ? 'ap' : /Bridged|Wired/.test(type) ? 'bridge' : /Client/.test(type) ? 'client' : 'other');
            n.karma = rec.d11_karma && typeof rec.d11_karma === 'object' && !Array.isArray(rec.d11_karma) ? rec.d11_karma : null;

            // A network listed in another access point's multiple BSSID
            // element is served by that access point's radio
            g.same(g.mac(rec.d11_mbssid_tx), n, 'dot11-mbssid');

            // The points of an 802.11s mesh beacon its mesh ID, with no network name
            const mesh = typeof rec.d11_meshid === 'string' ? rec.d11_meshid : '';
            if (mesh)
                g.link(n, g.thing(meshId(mesh), { label: mesh, kind: 'mesh', title: 'Mesh ID' }), { kind: 'dot11-mesh' });

            const ssid = rec.d11_ssid;
            if (typeof ssid === 'string') {
                n.ssid = ssid;
                n.crypt = rec.d11_crypt || '';
                if (ssid) {
                    const t = g.thing(ssidId(ssid), { label: ssid, kind: 'ssid' });
                    t.advertisers = [...(t.advertisers ?? []), n];
                    g.link(n, t, { kind: 'dot11-advert' });
                } else if (!mesh) {
                    n.label = 'Hidden network';
                }
            }

            for (const key of Object.values(rec.d11_clients && typeof rec.d11_clients === 'object' ? rec.d11_clients : {})) {
                const c = g.device(key);
                if (!c)
                    continue;
                const wired = /Bridged|Wired/.test(c.rec?.[`${base}.type`] ?? '');
                g.link(c, n, { kind: wired ? 'dot11-wired' : 'dot11-assoc' });
                (c.aps ??= []).push(n);
            }

            n.probes = new Set();
            for (const p of list(rec.d11_probed)) {
                const s = p['dot11.probedssid.ssid'];
                if (!s)
                    continue;
                n.probes.add(s);
                g.link(n, g.thing(ssidId(s), { label: s, kind: 'ssid' }), { kind: 'dot11-probe' });
            }

            n.answers = new Set();
            for (const r of list(rec.d11_responded)) {
                const s = r['dot11.advertisedssid.ssid'];
                if (!s)
                    continue;
                n.answers.add(s);
                if (s !== n.ssid)
                    g.link(n, g.thing(ssidId(s), { label: s, kind: 'ssid' }), { kind: 'dot11-respond' });
            }
        },
        after(g) {
            // An access point sends each network and band from its own address.
            // Makers vary the first byte's locally administered bits, a nibble
            // of the fourth byte, or the last byte by a few; one maker's
            // addresses alike otherwise are one box
            const boxes = new Map();
            for (const n of g.nodes.values()) {
                if (n.role !== 'ap' || !n.mac)
                    continue;
                const b = n.mac.split(':').map((x) => parseInt(x, 16));
                if (b.length !== 6 || b.some(Number.isNaN))
                    continue;
                const key = [n.rec?.[`${base}.manuf`] ?? '', b[1], b[2], b[4]].join(':');
                if (!boxes.has(key))
                    boxes.set(key, []);
                boxes.get(key).push({ n, b });
            }
            const alike = (x, y) => (x[3] === y[3] && x[4] === y[4] && Math.abs(x[5] - y[5]) <= 3) ||
                (x[4] === y[4] && x[5] === y[5] && (x[3] & 0x0f) === (y[3] & 0x0f));
            for (const list of boxes.values())
                for (let i = 0; i < list.length; i++)
                    for (let j = i + 1; j < list.length; j++)
                        if (alike(list[i].b, list[j].b))
                            g.same(list[i].n, list[j].n);
            for (const t of [...g.nodes.values()]) {
                if (t.thingKind !== 'ssid')
                    continue;
                if (!t.advertisers?.length) {
                    t.thingKind = 'ssid-sought';
                } else if (t.advertisers.length === 1 && t.degree === 1) {
                    // a name only its own access point uses: the access point's label is enough
                    t.advertisers[0].label = t.label;
                    g.drop(t);
                }
            }
        },
    });

    const names = (nodes) => nodes.map((n) => n.label).join(', ');
    const short = (arr, n = 4) => (arr.length > n ? `${arr.slice(0, n).join(', ')} and ${arr.length - n} more` : arr.join(', '));

    insightFindings.add({
        id: 'dot11-twin',
        find({ graph }) {
            const out = [];
            for (const t of graph.nodes.values()) {
                const ads = t.advertisers ?? [];
                if (t.thingKind !== 'ssid' || ads.length < 2)
                    continue;
                const kinds = new Set(ads.map((a) => a.crypt || 'unknown'));
                if (kinds.size < 2)
                    continue;
                const firsts = ads.map((a) => a.rec?.d11_ssid_first ?? 0).filter(Boolean);
                const late = firsts.length > 1 ? Math.max(...firsts) - Math.min(...firsts) : 0;
                for (const n of [...ads, t])
                    if (!n.flags.includes('twin'))
                        n.flags.push('twin');
                out.push({
                    id: `twin:${t.label}`, severity: 'high',
                    title: `"${t.label}" is advertised with different security`,
                    text: `${ads.length} access points call themselves "${t.label}": ` +
                        ads.map((a) => `${a.mac} (${a.crypt || 'unknown'}, channel ${a.rec?.d11_channel || '?'})`).join('; ') + '.  ' +
                        (late > 60 ? `One appeared ${format.duration(late)} after the first.  ` : '') +
                        'A copy of a network with weaker security is how an evil twin works: devices that know the name may join it.',
                    devices: ads.map((a) => a.key), things: [t.id],
                });
            }
            return out;
        },
    });

    // Servers with karma detection define its alert and give the verdict on
    // each access point; older ones get a guess from the names answered for.
    // Undefined until the server has said which it is.
    let serverKarma;
    let askedKarma = false;
    const askServerKarma = () => {
        if (askedKarma)
            return;
        askedKarma = true;
        kismet.api.post('alerts/definitions.json', { fields: ['kismet.alert.definition.header'] })
            .then((defs) => {
                serverKarma ??= Array.isArray(defs) && defs.some((x) => x?.['kismet.alert.definition.header'] === 'DOT11KARMA');
            })
            .catch(() => {
                askedKarma = false;
            });
    };
    const karmaCount = (k, f) => (Number.isFinite(k[`dot11.karma.${f}`]) ? k[`dot11.karma.${f}`] : 0);
    const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
    const karmaAdvice = 'An access point normally answers only for its own networks.  One that answers for the names ' +
        'devices look for may be a "karma" or "mana" attack (as a Wi-Fi Pineapple can run), trying to get them to join it.  ' +
        'An old access point serving several hidden networks from one address can look the same.';

    insightFindings.add({
        id: 'dot11-karma',
        alerts: ['DOT11KARMA'],
        find({ graph, now }) {
            const nodes = [...graph.nodes.values()];
            if (nodes.some((n) => n.karma))
                serverKarma = true;
            else if (serverKarma === undefined)
                askServerKarma();
            if (serverKarma === undefined)
                return [];

            // How many devices looked for each name, for the guess
            const probers = new Map();
            if (!serverKarma)
                for (const n of nodes)
                    for (const s of n.probes ?? [])
                        probers.set(s, (probers.get(s) ?? 0) + 1);

            const out = [];
            for (const n of nodes) {
                const other = [...(n.answers ?? [])].filter((s) => typeof s === 'string' && s !== n.ssid && !s.startsWith('DIRECT-'));
                const answered = other.length ? `  It answered as ${short(other.map((s) => `"${s}"`))}.` : '';
                let title;
                let text;
                if (serverKarma) {
                    if (!n.karma?.['dot11.karma.suspect'])
                        continue;
                    const unbeaconed = karmaCount(n.karma, 'unbeaconed_ssids');
                    const matched = karmaCount(n.karma, 'probe_matched_ssids');
                    const directed = karmaCount(n.karma, 'directed_beacons');
                    const pool = karmaCount(n.karma, 'pool_ssids');
                    const answeredPool = Math.min(karmaCount(n.karma, 'answered_pool_ssids'), pool);
                    // Why the server flagged it, as of the alert
                    const isPool = (karmaCount(n.karma, 'reason') & karmaReasonPool) !== 0;
                    // The flag stays once set; the counts are of the recent names only
                    if (isPool) {
                        // The counts are of the recent names; a pool it stopped beaconing shrinks
                        // below the server's dot11_karma_min_pool, and the counts of a BSSID
                        // gone quiet hold only until counts_until
                        const flood = karmaCount(n.karma, 'flood_ssids');
                        const until = karmaCount(n.karma, 'counts_until');
                        const fresh = !(until > 0 && Number.isFinite(now) && now > until);
                        const current = fresh && karmaCount(n.karma, 'pool_current') !== 0 && (pool > 0 || flood > 0);
                        // A pool too big for the server's lists is counted from a sample
                        const estimated = karmaCount(n.karma, 'pool_estimated') !== 0;
                        const poolCount = (one, many) =>
                            `${estimated ? 'about ' : ''}${plural(pool, one, many)}${estimated ? ' (estimated)' : ''}`;
                        // A flood of one-off names may leave no name beaconed twice to count
                        const floodText = flood ? `${pool ? ', and ' : ''}${plural(flood, 'new network name', 'new network names')} ` +
                            'within 5 seconds (a beacon flood)' : '';
                        const poolText = current ?
                            (pool ? `beaconed ${poolCount('different network', 'different networks')} from one BSSID` :
                                `flooded beacons for ${plural(flood, 'new network', 'new networks')} within 5 seconds from one BSSID`) :
                            'beaconed a pool of networks from one BSSID';
                        title = unbeaconed ?
                            `${n.mac} ${poolText} and answered for ${plural(unbeaconed, 'network', 'networks')} it doesn't advertise` :
                            `${n.mac} ${poolText}`;
                        text = (current ?
                            'Kismet saw it send broadcast beacons for ' +
                            (pool ? `${poolCount('network name', 'network names')} from one BSSID (an SSID pool)` : '') + floodText +
                            (answeredPool ? `, and answer probe requests for ${answeredPool === pool ? 'each' : answeredPool} of them` : '') :
                            'Kismet saw it send broadcast beacons for enough different network names from one BSSID ' +
                            '(an SSID pool) to flag it.  It has since stopped beaconing most of them') +
                            (unbeaconed ? `; it also answered for ${plural(unbeaconed, 'name', 'names')} it never sent in broadcast beacons` +
                                (matched ? `, ${matched === unbeaconed ? 'each' : matched} of them just probed for by devices nearby` : '') : '') +
                            '.  Most access points with several networks use a separate BSSID for each.';
                    } else {
                        title = unbeaconed ? `${n.mac} answered for ${plural(unbeaconed, 'network', 'networks')} it doesn't advertise` :
                            `${n.mac} answered for networks it didn't advertise`;
                        text = unbeaconed ?
                            `Kismet saw it answer probe requests for ${plural(unbeaconed, 'network name', 'network names')} ` +
                            'it never sent in broadcast beacons' +
                            (matched ? `; devices nearby had just probed for ${matched === unbeaconed ? 'each' : matched} of them` : '') +
                            (directed ? `; ${directed} of them only in beacons addressed to one device` : '') + '.' :
                            'Kismet saw it answer probe requests for enough network names it didn\'t send in broadcast beacons ' +
                            'to flag it.  It has since advertised them, or answered for them too long ago to count now.';
                    }
                    text += `${answered}  ${karmaAdvice}`;
                } else {
                    // The guess: names other than the one it beacons, less one
                    // for a hidden network (an old hidden name, after a rename)
                    const allowance = n.ssid === '' ? 1 : 0;
                    const matched = other.filter((s) => (probers.get(s) ?? 0) > (n.probes?.has(s) ? 1 : 0)).length;
                    if (matched - allowance < karmaMinMatched && other.length - allowance < karmaMinAnswered)
                        continue;
                    title = `${n.mac} answers for ${other.length} different networks`;
                    text = `It sent probe responses for networks other than its own` +
                        (matched ? `, ${matched} of them names other devices looked for` : '') + `.${answered}  ${karmaAdvice}  ` +
                        'This server doesn\'t check for karma itself, so this is a guess from the names it answered for.';
                }
                n.flags.push('karma');
                out.push({ id: `karma:${n.key}`, severity: 'high', title, text, devices: [n.key], things: other.map(ssidId) });
            }
            return out;
        },
    });

    insightFindings.add({
        id: 'dot11-randomized',
        find({ graph }) {
            // Devices that only look for networks, from randomized addresses,
            // grouped by how alike their lists of network names are
            const probers = [...graph.nodes.values()].filter((n) => n.probes?.size >= 2 && randomized(n.mac) && !n.aps?.length);
            const groups = [];
            for (const n of probers) {
                const g = groups.find((grp) => jaccard(grp.probes, n.probes) >= 0.75);
                if (g) {
                    g.members.push(n);
                    n.probes.forEach((s) => g.probes.add(s));
                } else {
                    groups.push({ members: [n], probes: new Set(n.probes) });
                }
            }
            return groups.filter((g) => g.members.length > 1).map((g) => {
                const sorted = [...g.probes].sort();
                return {
                    id: `randomized:${sorted.join('|')}`, severity: 'info', hull: true,
                    title: `${g.members.length} randomized addresses are probably one device`,
                    text: `Each of them looks for the same networks: ${short(sorted.map((s) => `"${s}"`), 5)}.  ` +
                        'Phones change their address to avoid being followed, but the list of networks they remember stays the same.',
                    devices: g.members.map((m) => m.key),
                };
            });
        },
    });

    insightFindings.add({
        id: 'dot11-roam',
        find({ graph }) {
            const out = [];
            for (const n of graph.nodes.values()) {
                if (n.role !== 'client' || (n.aps?.length ?? 0) < 2)
                    continue;
                const ssids = new Set(n.aps.map((a) => a.ssid).filter(Boolean));
                out.push({
                    id: `roam:${n.key}`, severity: 'info',
                    title: `${n.label} moved between ${n.aps.length} access points`,
                    text: `It was a client of ${names(n.aps)}` + (ssids.size === 1 ? `, all "${[...ssids][0]}": roaming within one network.` : '.'),
                    devices: [n.key, ...n.aps.map((a) => a.key)],
                });
            }
            return out;
        },
    });

    insightFindings.add({
        id: 'dot11-shared-wire',
        find({ graph }) {
            const out = [];
            for (const n of graph.nodes.values()) {
                if (n.role !== 'bridge' || (n.aps?.length ?? 0) < 2)
                    continue;
                const ssids = [...new Set(n.aps.map((a) => a.ssid || 'a hidden network'))];
                out.push({
                    id: `wire:${n.key}`, severity: 'info',
                    title: `One wired host is behind ${n.aps.length} access points`,
                    text: `${n.mac} is reached through ${short(ssids.map((s) => `"${s}"`))}, so they share a network behind the radios` +
                        (ssids.length > 1 ? ', whatever their names.' : '.'),
                    devices: [n.key, ...n.aps.map((a) => a.key)],
                });
            }
            return out;
        },
    });
}
