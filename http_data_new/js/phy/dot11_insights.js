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
    [`dot11.device/dot11.device.probed_ssid_map`, 'd11_probed'],
    [`dot11.device/dot11.device.responded_ssid_map`, 'd11_responded'],
];

const list = (v) => (Array.isArray(v) ? v : v && typeof v === 'object' ? Object.values(v) : []);
const ssidId = (ssid) => `dot11-ssid:${ssid}`;

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

    linkKinds.add({ id: 'dot11-assoc', title: 'Wi-Fi client of', color: '--ok', length: 46, live: true });
    linkKinds.add({ id: 'dot11-wired', title: 'Wired host behind', color: '--muted', style: 'dotted', length: 70, live: true });
    linkKinds.add({ id: 'dot11-advert', title: 'Advertises', color: '--accent', length: 34, names: true });
    linkKinds.add({ id: 'dot11-probe', title: 'Looks for', color: '--muted', style: 'dashed', length: 90 });
    linkKinds.add({ id: 'dot11-respond', title: 'Answers for', color: '--error', style: 'dashed', length: 70 });

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

            const ssid = rec.d11_ssid;
            if (typeof ssid === 'string') {
                n.ssid = ssid;
                n.crypt = rec.d11_crypt || '';
                if (ssid) {
                    const t = g.thing(ssidId(ssid), { label: ssid, kind: 'ssid' });
                    t.advertisers = [...(t.advertisers ?? []), n];
                    g.link(n, t, { kind: 'dot11-advert' });
                } else {
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

    insightFindings.add({
        id: 'dot11-karma',
        find({ graph }) {
            const out = [];
            for (const n of graph.nodes.values()) {
                const other = [...(n.answers ?? [])].filter((s) => s !== n.ssid);
                if (other.length < 2)
                    continue;
                n.flags.push('karma');
                out.push({
                    id: `karma:${n.key}`, severity: 'high',
                    title: `${n.mac} answers for ${other.length} different networks`,
                    text: `It sent probe responses as ${short(other.map((s) => `"${s}"`))}.  An access point answers for its own ` +
                        'networks; one that answers whatever name a phone asks for (a "karma" attack, as a WiFi Pineapple does) ' +
                        'is trying to get devices to join it.',
                    devices: [n.key], things: other.map(ssidId),
                });
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
