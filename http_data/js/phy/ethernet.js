// Ethernet (IEEE802.3): wired devices from Ethernet captures, with their
// VLANs, addresses, names and DHCP details, the Ethernet flows tab and the
// Ethernet VLANs window, and the "On the wire" section of a device linked to
// an Ethernet record (a Wi-Fi client, say).
//
// The server names no UI module for this phy, so js/core/modules.js loads
// this one when the server lists the IEEE802.3 phy.  The tab and the window's
// menu entry are offered only once the server has Ethernet devices.  Wired devices have
// no location, so there's no map source for them.

import { protocolNames, roleNames, tcpFlagNames, ipProtocolName, vlanLabel, vlanTagText, vlanSortKey,
    endpoint, hostNames, addresses, statusNotes, flowFilter } from './ethernetinfo.js';
import { statusNotes as entityNotes, statusSummary as entitySummary } from '../core/entityinfo.js';

const base = 'kismet.device.base';
const e = 'ethernet.device';
const phy = 'IEEE802.3';
const fl = 'ethernet.flow';
const vl = 'ethernet.vlan';

const statusSeconds = 10;
const flowPage = 200;
const deviceFlows = 100;

const macPattern = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;

const ipSources = { arp: 'ARP', dhcp: 'DHCP', dhcpv6: 'DHCPv6', traffic: 'Traffic' };
const nameSources = { dhcp_hostname: 'DHCP hostname', dhcp_fqdn: 'DHCP FQDN', dhcpv6_fqdn: 'DHCPv6 FQDN' };

export function register(kismet) {
    const { ui, api, dom, icons, format, settings } = kismet;
    const { el } = dom;
    const { dialog } = kismet.widgets.dialog;
    const { listTable, aboutView } = kismet.widgets;
    const muted = ui.muted;

    icons.define('ethernet', '<rect x="4" y="5" width="16" height="12" rx="1.5"/><path d="M9 17v3h6v-3"/>' +
        '<path d="M8 8.5v2.5M10.7 8.5v2.5M13.3 8.5v2.5M16 8.5v2.5"/>');
    icons.define('router', '<circle cx="12" cy="12" r="9"/><path d="M7.5 9.5h9M14 7l2.5 2.5L14 12"/>' +
        '<path d="M16.5 14.5h-9M10 12l-2.5 2.5L10 17"/>');

    const list = (v) => (Array.isArray(v) ? v : []);
    const isEthernet = (row) => row[`${base}.phyname`] === phy;
    const time = (v) => format.time(v);
    const counted = (v) => (typeof v === 'number' ? v.toLocaleString() : '-');

    // ---- device list -----------------------------------------------------

    ui.deviceIcons.add({
        id: 'ethernet', priority: 0,
        fields: [`${base}.phyname`, `${base}.type`],
        match: (row) => {
            if (!isEthernet(row))
                return null;
            if (row[`${base}.type`] === 'Ethernet Router')
                return icons.icon('router', 'Ethernet router');
            if (row[`${base}.type`] === 'Ethernet Server')
                return icons.icon('server', 'Ethernet server');
            return icons.icon('ethernet', 'Ethernet device');
        },
    });

    ui.phyColors.add({ id: phy, title: 'Ethernet', color: '#ffd8a8' });
    ui.deviceViews.add({ id: `phy-${phy}`, title: 'Ethernet devices', group: 'Phy types' });

    const vlanList = (vlans) => list(vlans).slice()
        .sort((a, b) => vlanSortKey(a[`${e}.vlan.tags`], a[`${e}.vlan.vid`], a[`${e}.vlan.inner_vid`]) -
            vlanSortKey(b[`${e}.vlan.tags`], b[`${e}.vlan.vid`], b[`${e}.vlan.inner_vid`]))
        .map((v) => vlanLabel(v[`${e}.vlan.tags`], v[`${e}.vlan.vid`], v[`${e}.vlan.inner_vid`]));
    // The first of a list, with how many more there are; the tooltip lists them all
    const firstOf = (items) => (items.length > 1 ? `${items[0]} +${items.length - 1}` : items[0] ?? '');
    const allOf = (items) => (items.length > 1 ? items.join('\n') : null);

    ui.deviceColumns.add({
        id: 'eth_vlans', title: 'VLANs', priority: 130, group: 'Ethernet', width: '8em', shorten: true,
        description: 'VLANs an Ethernet device sent on',
        fields: [[`${e}/${e}.vlans`, 'eth_vlans']],
        filterField: `${e}/${e}.vlans/${e}.vlan.vid`, filterKind: 'number',
        render: (row) => vlanList(row.eth_vlans).join(', '),
    });
    ui.deviceColumns.add({
        id: 'eth_ips', title: 'IP addresses', priority: 131, group: 'Ethernet', width: '13em', shorten: true,
        description: 'IPv4 and IPv6 addresses of an Ethernet device: the first, and how many more',
        fields: [[`${e}/${e}.ipv4`, 'eth_ipv4'], [`${e}/${e}.ipv6`, 'eth_ipv6']],
        render: (row) => firstOf(addresses(row.eth_ipv4, row.eth_ipv6)),
        tooltip: (row) => allOf(addresses(row.eth_ipv4, row.eth_ipv6)),
    });
    ui.deviceColumns.add({
        id: 'eth_hostname', title: 'Hostname', priority: 132, group: 'Ethernet', width: '14em', shorten: true,
        description: 'Names an Ethernet device announced for itself in DHCP or DHCPv6',
        fields: [[`${e}/${e}.names`, 'eth_names']],
        filterField: `${e}/${e}.names/${e}.name.name`,
        render: (row) => firstOf(hostNames(row.eth_names)),
        tooltip: (row) => allOf(hostNames(row.eth_names)),
    });

    // The device list's search can't look inside lists, so addresses, names
    // and VLANs are filters: ip == 192.0.2.10, hostname ~ printer, vlan == 20
    const filterHint = (id, names, fields, more = {}) => ui.filterHints.add({ id, phy, names, fields, ...more });
    filterHint('eth_ip', ['ip'], [`${e}/${e}.ipv4/${e}.ip.address`, `${e}/${e}.ipv6/${e}.ip.address`],
        { help: 'IPv4 and IPv6 addresses of Ethernet devices' });
    filterHint('eth_hostname', ['hostname'], [`${e}/${e}.names/${e}.name.name`],
        { help: 'Names Ethernet devices announced in DHCP or DHCPv6' });
    filterHint('eth_vlan', ['vlan'], [`${e}/${e}.vlans/${e}.vlan.vid`],
        { filterKind: 'number', help: 'VLAN IDs Ethernet devices sent on (the outer tag)' });
    ui.searchFields.add({
        id: 'ethernet', phy, description: 'DHCP vendor class',
        fields: [`${e}/${e}.dhcp_vendor`, `${e}/${e}.dhcpv6_vendor`],
        help: 'DHCP and DHCPv6 vendor class of Ethernet devices',
    });

    // ---- links to devices by MAC -------------------------------------------

    // Open the Ethernet device with a MAC address, if Kismet tracks one
    async function openByMac(mac) {
        if (!macPattern.test(mac))
            return false;
        const devs = await api.post(`devices/by-mac/${mac}/devices.json`, { fields: [`${base}.key`, `${base}.phyname`] });
        const dev = list(devs).find((d) => d[`${base}.phyname`] === phy) ?? list(devs)[0];
        if (!dev)
            return false;
        ui.openDevice(dev[`${base}.key`]);
        return true;
    }

    // A MAC from a flow: a link to its device for unicast addresses
    function macLink(mac) {
        if (typeof mac !== 'string' || !macPattern.test(mac) || /^(00:){5}00$/.test(mac))
            return muted('-');
        if ((parseInt(mac.slice(0, 2), 16) & 1) !== 0)
            return el('span', { class: 'mono', title: 'Broadcast or multicast address' }, mac);
        const a = el('a', { href: '#', class: 'mono eth-mac', title: 'Open this device', onclick: async (ev) => {
            ev.preventDefault();
            let found = false;
            try {
                found = await openByMac(mac);
            } catch {
                found = false;
            }
            if (!found) {
                a.title = 'Kismet doesn\'t track a device with this MAC address';
                a.classList.add('muted');
            }
        } }, mac, ' ', icons.icon('chain'));
        return a;
    }

    // ---- flows tables ------------------------------------------------------

    const flowValue = (k) => (r) => r[`${fl}.${k}`];
    const flowVlan = (r) => vlanLabel(r[`${fl}.vlan_tags`], r[`${fl}.vid`], r[`${fl}.inner_vid`]);
    const flowFlags = (r) => {
        if (r[`${fl}.proto`] !== 6)
            return '';
        const a = tcpFlagNames(r[`${fl}.tcp_flags_ab`]).join(' ');
        const b = tcpFlagNames(r[`${fl}.tcp_flags_ba`]).join(' ');
        return `${a || '-'} / ${b || '-'}`;
    };
    const flowKey = (r) => ['family', 'proto', 'addr_a', 'port_a', 'addr_b', 'port_b', 'vlan_tags', 'vid', 'inner_vid']
        .map((k) => r[`${fl}.${k}`]).join('|');

    const flowColumns = [
        { id: 'proto', title: 'Protocol', value: (r) => ipProtocolName(r[`${fl}.proto`]) },
        { id: 'a', title: 'Side A', value: (r) => endpoint(r[`${fl}.addr_a`], r[`${fl}.port_a`], r[`${fl}.proto`]) },
        { id: 'b', title: 'Side B', value: (r) => endpoint(r[`${fl}.addr_b`], r[`${fl}.port_b`], r[`${fl}.proto`]) },
        { id: 'vlan', title: 'VLAN', value: (r) => vlanSortKey(r[`${fl}.vlan_tags`], r[`${fl}.vid`], r[`${fl}.inner_vid`]),
            render: flowVlan },
        { id: 'ab', title: 'A to B', value: flowValue('bytes_ab'), align: 'right', dir: 'desc',
            render: (r) => format.size(r[`${fl}.bytes_ab`]) },
        { id: 'ba', title: 'B to A', value: flowValue('bytes_ba'), align: 'right', dir: 'desc',
            render: (r) => format.size(r[`${fl}.bytes_ba`]) },
        { id: 'packets', title: 'Packets', value: (r) => (r[`${fl}.packets_ab`] ?? 0) + (r[`${fl}.packets_ba`] ?? 0),
            align: 'right', dir: 'desc', render: (r) => counted((r[`${fl}.packets_ab`] ?? 0) + (r[`${fl}.packets_ba`] ?? 0)) },
        { id: 'mac_a', title: 'MAC A', value: flowValue('mac_a'), render: (r) => macLink(r[`${fl}.mac_a`]) },
        { id: 'mac_b', title: 'MAC B', value: flowValue('mac_b'), render: (r) => macLink(r[`${fl}.mac_b`]) },
        { id: 'last', title: 'Last seen', value: flowValue('last_time'), dir: 'desc', render: (r) => time(r[`${fl}.last_time`]) },
    ];

    // Everything about one flow, shown under the table when its row is clicked
    const flowDetail = (r, node) => ui.detailFields(node, r, [
        { title: 'Protocol', value: (x) => ipProtocolName(x[`${fl}.proto`]) },
        { title: 'Side A', value: (x) => endpoint(x[`${fl}.addr_a`], x[`${fl}.port_a`], x[`${fl}.proto`]) },
        { title: 'MAC A', field: `${fl}.mac_a`, format: macLink, help: 'The last source MAC address seen sending for side A.' },
        { title: 'Side B', value: (x) => endpoint(x[`${fl}.addr_b`], x[`${fl}.port_b`], x[`${fl}.proto`]) },
        { title: 'MAC B', field: `${fl}.mac_b`, format: macLink, help: 'The last source MAC address seen sending for side B.' },
        { title: 'Started by', field: `${fl}.initiator`, format: (v) => (v === 'a' ? 'Side A' : 'Side B'),
            help: 'The side that sent the first packet Kismet saw.  A flow already running when the capture started may have begun with the other side.' },
        { title: 'VLAN', value: flowVlan },
        { title: 'A to B', value: (x) => `${format.size(x[`${fl}.bytes_ab`])}, ${counted(x[`${fl}.packets_ab`])} packets` },
        { title: 'B to A', value: (x) => `${format.size(x[`${fl}.bytes_ba`])}, ${counted(x[`${fl}.packets_ba`])} packets` },
        { title: 'TCP flags', value: flowFlags, hideEmpty: true, help: 'TCP flags seen from side A / side B.' },
        { title: 'First seen', field: `${fl}.first_time`, format: time },
        { title: 'Last seen', field: `${fl}.last_time`, format: time },
    ]);

    // A table of flows from the server, most recent first.  query() gives the
    // filter and paging; onLoad gets the whole reply, and onDetail is called
    // when a flow's details are drawn.  fill makes it take its container's height.
    function flowTable(id, query, onLoad, onDetail, fill = false) {
        return listTable({
            id, fill,
            load: async () => {
                const r = await api.post('phy/ethernet/flows/flows.json', query());
                onLoad?.(r);
                return list(r?.[`${fl}s.flows`]);
            },
            columns: flowColumns,
            search: 'Search these flows',
            empty: 'No flows.',
            defaultSort: { column: 'last', dir: 'desc' },
            rowKey: flowKey,
            detail: (r, node) => {
                flowDetail(r, node);
                onDetail?.();
            },
            refreshSeconds: 5,
        });
    }

    // ---- server status -----------------------------------------------------

    // The status endpoint is read every statusSeconds while the page is
    // visible, to offer the flows tab and VLANs window once there are
    // Ethernet devices and to warn about devices or flows that weren't kept
    let status = null;
    const statusWatchers = new Set();
    let statusTimer = null;
    let offered = false;
    let linkBoxes = 0;

    function offerWindows(on) {
        if (on === offered)
            return;
        offered = on;
        if (on) {
            // Right after the Map tab
            ui.panes.add({ id: 'ethernet-flows', title: 'Ethernet flows', area: 'main', priority: 45,
                create: (body) => flowsPane(body) });
            ui.menuItems.add({ id: 'ethernet-vlans', title: 'Ethernet VLANs', icon: 'ethernet', onClick: () => openVlans() });
        } else {
            ui.panes.remove('ethernet-flows');
            ui.menuItems.remove('ethernet-vlans');
        }
    }

    let statusGone = false;

    async function readStatus() {
        clearTimeout(statusTimer);
        if (statusGone)
            return;
        if (document.visibilityState !== 'hidden') {
            try {
                status = await api.get('phy/ethernet/status/status.json');
                offerWindows((status?.['ethernet.status.devices'] ?? 0) > 0);
                // Linking counters only while something shows them
                if (linkBoxes)
                    await kismet.entities.refreshStatus().catch(() => null);
                for (const fn of statusWatchers)
                    fn(status);
            } catch (err) {
                // A server without the endpoint: nothing to offer, and no need to ask again
                if (err.status === 404) {
                    statusGone = true;
                    offerWindows(false);
                    return;
                }
            }
        }
        statusTimer = setTimeout(readStatus, statusSeconds * 1000);
    }
    readStatus();
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible')
            readStatus();
    });

    // Warnings from the status counters, kept up to date while shown.  With
    // links, also how many Ethernet records are linked to Wi-Fi ones and the
    // links not kept at a limit.
    function statusBox({ links = false } = {}) {
        const warnings = el('ul', { class: 'mem-insights', hidden: true });
        const summary = el('p', { class: 'muted eth-links', hidden: true });
        const node = links ? el('div', { class: 'eth-status' }, summary, warnings) : warnings;
        let shown = '';
        const draw = (st) => {
            const ent = links ? kismet.entities.status() : null;
            const notes = [...statusNotes(st), ...entityNotes(ent)];
            const line = entitySummary(ent);
            const key = JSON.stringify([notes, line]);
            if (key === shown)
                return;
            shown = key;
            warnings.replaceChildren(...notes.map((n) => el('li', { class: 'mem-insight mem-warn', title: n.help },
                el('span', {}, n.text), el('span', { class: 'muted' }, n.help))));
            warnings.hidden = !notes.length;
            summary.textContent = line;
            summary.hidden = !line;
        };
        draw(status);
        statusWatchers.add(draw);
        if (links) {
            linkBoxes++;
            // At once, not at the next status read
            kismet.entities.refreshStatus().then(() => draw(status), () => {});
        }
        return { node, destroy: () => {
            statusWatchers.delete(draw);
            if (links)
                linkBoxes--;
        } };
    }

    // ---- windows -------------------------------------------------------------

    // A window sized to its content, as far as the screen allows, until the
    // user sizes it
    function ethernetWindow({ title, body, width, onClose }) {
        const w = Math.min(width, window.innerWidth - 32);
        const h = Math.min(Math.round(window.innerHeight * 0.85), 900);
        let userSized = false;
        let fitted = h;
        const d = dialog({
            title, body, modal: false, className: 'pk-panel',
            position: { left: Math.round((window.innerWidth - w) / 2), top: 70, width: w, height: h },
            onMove: (p) => {
                if (Math.abs((p?.height ?? fitted) - fitted) > 1)
                    userSized = true;
            },
            onClose,
        });
        d.fit = () => {
            if (userSized)
                return;
            requestAnimationFrame(() => {
                if (userSized || !d.node.isConnected)
                    return;
                d.fitContent({ grow: true });
                fitted = d.node.offsetHeight;
            });
        };
        d.fit();
        return d;
    }

    const vlanAbout = [
        'The VLANs Kismet saw on Ethernet captures, from the 802.1Q tags on frames.  Untagged frames are listed as Untagged; ' +
            'VLAN 0 carries only a priority.  QinQ (stacked tags) is shown as outer/inner VLAN ID.',
        'Devices counts the source MAC addresses that sent on the VLAN.  Frames and bytes count every frame sent on it, as on the wire.',
        'On Linux, captures of the "any" interface can lose their VLAN tags, so their frames show as untagged.',
        'Linked to Wi-Fi counts the Ethernet records Kismet linked to the Wi-Fi record with the same MAC address, and the ' +
            'possible links below entity_link_min_confidence.  A linked device lists them under Linked devices.',
    ];

    let vlanWindow = null;

    function openVlans() {
        if (vlanWindow?.node.isConnected) {
            vlanWindow.raise();
            return vlanWindow;
        }

        const summary = el('span', { class: 'muted' });
        const about = aboutView({ setting: 'ethernet.vlans.about' });
        about.set(vlanAbout);
        const notes = statusBox({ links: true });
        const v = (k) => (r) => r[`${vl}.${k}`];
        let d = null;
        const table = listTable({
            id: 'ethernet-vlans',
            load: async () => {
                const rows = list(await api.get('phy/ethernet/vlans/vlans.json'));
                const tagged = rows.filter((r) => r[`${vl}.tags`] > 0).length;
                summary.textContent = `${rows.length.toLocaleString()} ${rows.length === 1 ? 'entry' : 'entries'}, ` +
                    `${tagged.toLocaleString()} tagged`;
                d?.fit();
                return rows;
            },
            columns: [
                { id: 'vlan', title: 'VLAN', value: (r) => vlanSortKey(r[`${vl}.tags`], r[`${vl}.vid`], r[`${vl}.inner_vid`]),
                    render: (r) => vlanLabel(r[`${vl}.tags`], r[`${vl}.vid`], r[`${vl}.inner_vid`]) },
                { id: 'tags', title: 'Tags', value: (r) => vlanTagText(r[`${vl}.tags`]) },
                { id: 'devices', title: 'Devices', value: v('devices'), align: 'right', dir: 'desc', render: (r) => counted(r[`${vl}.devices`]) },
                { id: 'packets', title: 'Frames', value: v('packets'), align: 'right', dir: 'desc', render: (r) => counted(r[`${vl}.packets`]) },
                { id: 'bytes', title: 'Bytes', value: v('bytes'), align: 'right', dir: 'desc', render: (r) => format.size(r[`${vl}.bytes`]) },
                { id: 'first', title: 'First seen', value: v('first_time'), dir: 'desc', render: (r) => time(r[`${vl}.first_time`]) },
                { id: 'last', title: 'Last seen', value: v('last_time'), dir: 'desc', render: (r) => time(r[`${vl}.last_time`]) },
            ],
            search: 'Search VLANs',
            empty: 'No Ethernet frames seen yet.',
            defaultSort: { column: 'vlan', dir: 'asc' },
            rowKey: (r) => `${r[`${vl}.tags`]}|${r[`${vl}.vid`]}|${r[`${vl}.inner_vid`]}`,
            detail: (r, node) => {
                const tagged = r[`${vl}.tags`] > 0 && r[`${vl}.vid`] > 0;
                const label = vlanLabel(r[`${vl}.tags`], r[`${vl}.vid`], r[`${vl}.inner_vid`]);
                dom.replace(node, el('div', { class: 'pk-bar' },
                    el('b', {}, `VLAN ${label}`),
                    tagged ? el('button', { type: 'button', onclick: () => {
                        // The window would cover the tab it switches to
                        d?.close();
                        openFlows({ vlan: String(r[`${vl}.vid`]) });
                    } },
                        `Flows on VLAN ${r[`${vl}.vid`]}`) : muted('Flows can only be picked by a tagged VLAN ID.'),
                    tagged ? muted(`Devices on it: search the device list for vlan == ${r[`${vl}.vid`]}`) : null));
                d?.fit();
            },
            refreshSeconds: 5,
        });

        const bar = el('div', { class: 'pk-bar about-anchor' }, summary, about.button);
        const body = el('div', { class: 'mem-window' }, bar, notes.node, table.node, about.node);
        d = ethernetWindow({ title: 'Ethernet VLANs', body, width: 880, onClose: () => {
            table.destroy();
            notes.destroy();
            about.destroy();
            vlanWindow = null;
        } });
        vlanWindow = d;
        return d;
    }

    const flowAbout = [
        'IP flows Kismet saw on Ethernet captures: traffic between two addresses and ports, with one protocol, on one VLAN.  ' +
            'Side A and side B are the two ends; the MACs are the last ones seen sending for each side, which for a remote ' +
            'address is usually a router.',
        'The newest flows come first, a page at a time.  Filter by a MAC address (either side), an IP address (either side) ' +
            'or a VLAN ID; the search box then searches the page shown.  Click a flow for its details.',
        'Flows are kept in memory only, never logged, and are forgotten after they go idle (wired_flow_tcp_timeout and ' +
            'wired_flow_udp_timeout in kismet_wired.conf).',
    ];

    let flowView = null;        // the flows tab, once built
    let flowPreset = null;      // a filter for the tab to start with

    // Switch to the flows tab, with a filter when one is given (from a VLAN or
    // a device).  Only Ethernet data links here, so the tab is offered at once
    // if the status read hasn't caught up yet.
    function openFlows(preset = null) {
        flowPreset = preset;
        offerWindows(true);
        // After the tab area has built a newly offered tab
        queueMicrotask(() => {
            if (flowPreset && flowView)
                flowView.setFilter(flowPreset);
            flowPreset = null;
            kismet.widgets.panes.showPane('ethernet-flows');
        });
    }

    // The Ethernet flows tab, after the Map tab
    function flowsPane(body) {
        const saved = settings.get('ethernet.flows.filter', {}) ?? {};
        const start = flowPreset ?? { mac: saved.mac ?? '', ip: saved.ip ?? '', vlan: saved.vlan ?? '' };
        flowPreset = null;

        const input = (name, placeholder, width, more = {}) => el('input', { type: 'text', name, placeholder,
            'aria-label': placeholder, spellcheck: false, autocomplete: 'off', style: { width }, ...more });
        const macInput = input('mac', 'MAC address', '12rem');
        const ipInput = input('ip', 'IP address', '14rem');
        const vlanInput = input('vlan', 'VLAN ID', '6rem', { inputmode: 'numeric' });
        const error = el('span', { class: 'error-text', hidden: true });
        const summary = el('span', { class: 'muted eth-flow-count' });
        const prev = el('button', { type: 'button', title: 'Newer flows', 'aria-label': 'Newer flows', onclick: () => page(-1) },
            icons.icon('left'));
        const next = el('button', { type: 'button', title: 'Older flows', 'aria-label': 'Older flows', onclick: () => page(1) },
            icons.icon('right'));
        const first = el('button', { type: 'button', title: 'Newest flows', 'aria-label': 'Newest flows', onclick: () => page(0) },
            icons.icon('first'));
        const notes = statusBox();
        const off = el('p', { class: 'muted', hidden: true },
            'Flow tracking is off on this server (wired_max_flows is 0 in kismet_wired.conf).');
        const about = aboutView({ setting: 'ethernet.flows.about' });
        about.set(flowAbout);

        let filter = {};
        let offset = 0;
        let total = null;

        const table = flowTable('ethernet-flows', () => ({ ...filter, start: offset, length: flowPage }), (r) => {
            total = r?.[`${fl}s.total`] ?? 0;
            // Flows expired under the page being read: go back to the last page there is
            if (offset > 0 && offset >= total) {
                offset = Math.max(0, Math.floor((total - 1) / flowPage) * flowPage);
                setTimeout(() => table.refresh(), 0);
            }
            showPage();
        }, null, true);

        function showPage() {
            const n = total ?? 0;
            const shown = Math.min(flowPage, Math.max(0, n - offset));
            const what = Object.keys(filter).length ? 'matching flows' : 'flows';
            summary.textContent = total === null ? 'Loading...' : n === 0 ? `No ${what}` :
                `${(offset + 1).toLocaleString()}-${(offset + shown).toLocaleString()} of ${n.toLocaleString()} ${what}, newest first`;
            prev.disabled = first.disabled = offset === 0;
            next.disabled = offset + flowPage >= n;
            off.hidden = (status?.['ethernet.status.max_flows'] ?? 1) !== 0;
        }

        function page(dir) {
            offset = dir === 0 ? 0 : Math.max(0, offset + dir * flowPage);
            showPage();
            table.refresh();
        }

        function apply(values) {
            const f = flowFilter(values);
            error.hidden = !f.error;
            error.textContent = f.error ?? '';
            if (f.error)
                return;
            filter = f.filter;
            settings.set('ethernet.flows.filter', { mac: macInput.value.trim(), ip: ipInput.value.trim(), vlan: vlanInput.value.trim() });
            offset = 0;
            total = null;
            showPage();
            table.refresh();
        }

        function setFilter(values) {
            macInput.value = values.mac ?? '';
            ipInput.value = values.ip ?? '';
            vlanInput.value = values.vlan ?? '';
            apply(values);
        }

        const form = el('form', { class: 'pk-bar eth-flow-filter', onsubmit: (ev) => {
            ev.preventDefault();
            apply({ mac: macInput.value, ip: ipInput.value, vlan: vlanInput.value });
        } }, macInput, ipInput, vlanInput,
        el('button', { type: 'submit', class: 'primary' }, 'Filter'),
        el('button', { type: 'button', onclick: () => setFilter({}) }, 'Clear'),
        error);
        const bar = el('div', { class: 'pk-bar about-anchor' }, first, prev, next, summary, about.button);
        body.classList.add('eth-flows-tab');
        body.append(el('div', { class: 'eth-flows-head' }, form, bar, notes.node, off), table.node, about.node);

        const statusDraw = () => showPage();
        statusWatchers.add(statusDraw);
        macInput.value = start.mac ?? '';
        ipInput.value = start.ip ?? '';
        vlanInput.value = start.vlan ?? '';
        const f = flowFilter(start);
        filter = f.filter ?? {};
        showPage();
        const view = { setFilter };
        flowView = view;

        return {
            // Fresh flows at once on returning to the tab, not at the next refresh
            show: () => table.refresh(),
            destroy() {
                table.destroy();
                notes.destroy();
                statusWatchers.delete(statusDraw);
                about.destroy();
                if (flowView === view)
                    flowView = null;
            },
        };
    }

    // ---- device details ------------------------------------------------------

    // A small table for a draw(), updated in place so a text selection
    // survives the panel's redraws.  rows(v) gives [key, cells] per row; a
    // cell is text, or { text, node() } for content built from that text.
    const smallTable = (heads, rows) => (cell, v, _rec, state) => {
        if (!state.table) {
            state.table = el('table', { class: 'ds-census' }, el('tr', {}, heads.map((h) => el('th', {}, h))));
            state.rows = new Map();
            cell.replaceChildren(el('div', { class: 'eth-table' }, state.table));
        }
        const seen = new Set();
        let at = state.table.firstChild.nextSibling;
        rows(v).forEach(([k, cells]) => {
            let key = k;
            for (let j = 1; seen.has(key); j++)
                key = `${k}#${j}`;
            seen.add(key);
            let row = state.rows.get(key);
            if (!row) {
                row = { tr: el('tr', {}, heads.map(() => el('td'))), shown: [] };
                state.rows.set(key, row);
            }
            cells.forEach((c, j) => {
                const text = c && typeof c === 'object' ? c.text : String(c ?? '');
                if (row.shown[j] === text)
                    return;
                row.shown[j] = text;
                dom.replace(row.tr.children[j], c && typeof c === 'object' ? c.node() : text);
            });
            if (row.tr !== at)
                state.table.insertBefore(row.tr, at);
            else
                at = at.nextSibling;
        });
        for (const [key, row] of state.rows) {
            if (!seen.has(key)) {
                row.tr.remove();
                state.rows.delete(key);
            }
        }
        return undefined;
    };
    const hasList = (path) => (dev) => list(kismet.api.field(dev, path)).length > 0;
    const anyOf = (...paths) => (dev) => paths.some((p) => {
        const v = kismet.api.field(dev, p);
        return typeof v === 'string' && v !== '';
    });
    const mono = (v) => el('span', { class: 'mono eth-wrap' }, v);

    // Its rows are also drawn from a linked Ethernet record, in another phy's
    // "On the wire" section
    const ethernetSection = ui.deviceDetails.add({
        id: 'ethernet', title: 'Ethernet', priority: 5,
        match: (device) => device[`${base}.phyname`] === phy && !!device[e],
        fields: [
            { title: 'Roles', field: `${e}/${e}.roles`, show: (v) => roleNames(v).length > 0, format: (v) => roleNames(v).join(', '),
                help: 'What the device was seen doing for others: handing out DHCP or DHCPv6 leases, or named as a gateway or DNS server in a DHCP reply.' },
            { title: 'Protocols', field: `${e}/${e}.protocols`, show: (v) => protocolNames(v).length > 0,
                format: (v) => protocolNames(v).join(', '), help: 'The protocols the device sent.' },
            {
                group: 'Names', show: hasList(`${e}/${e}.names`),
                help: 'Names the device announced for itself.  Anyone on the network can send any name, so they\'re claims, not proof.',
                fields: [
                    { id: 'eth_names', wide: true, field: `${e}/${e}.names`,
                        draw: smallTable(['Name', 'Source', 'First seen', 'Last seen'], (v) => list(v).map((n) => [
                            `${n[`${e}.name.source`]}|${n[`${e}.name.name`]}`, [
                                n[`${e}.name.name`] ?? '',
                                nameSources[n[`${e}.name.source`]] ?? n[`${e}.name.source`] ?? '',
                                time(n[`${e}.name.first_time`]),
                                time(n[`${e}.name.last_time`])]])) },
                ],
            },
            {
                group: 'Addresses', show: (dev) => hasList(`${e}/${e}.ipv4`)(dev) || hasList(`${e}/${e}.ipv6`)(dev),
                help: 'IP addresses the device used or was given.  ARP and DHCP addresses are always listed; addresses from the traffic it sent only when they are local, unless wired_learn_remote_ips is set.',
                fields: [
                    { id: 'eth_addresses', wide: true, value: (dev) => [...list(dev[e]?.[`${e}.ipv4`]), ...list(dev[e]?.[`${e}.ipv6`])],
                        draw: smallTable(['Address', 'Source', 'First seen', 'Last seen'], (v) => v.map((a) => {
                            const addr = a[`${e}.ip.address`] ?? '';
                            const eui = a[`${e}.ip.eui64_mac`];
                            const euiOk = typeof eui === 'string' && macPattern.test(eui);
                            return [addr, [
                                { text: JSON.stringify([addr, euiOk ? eui : null]), node: () => [mono(addr), euiOk ?
                                    el('div', { class: 'muted', title: 'The MAC address in this IPv6 address\'s interface ID isn\'t this device\'s' },
                                        `EUI-64 of ${eui}`) : null] },
                                ipSources[a[`${e}.ip.source`]] ?? a[`${e}.ip.source`] ?? '',
                                time(a[`${e}.ip.first_time`]),
                                time(a[`${e}.ip.last_time`])]];
                        })) },
                ],
            },
            {
                group: 'VLANs', show: hasList(`${e}/${e}.vlans`),
                help: 'VLANs the device sent on.  Untagged frames are listed as Untagged; QinQ is shown as outer/inner VLAN ID.',
                fields: [
                    { id: 'eth_vlans', wide: true, field: `${e}/${e}.vlans`,
                        draw: smallTable(['VLAN', 'Tags', 'Frames', 'First seen', 'Last seen'], (v) => list(v).slice()
                            .sort((a, b) => vlanSortKey(a[`${e}.vlan.tags`], a[`${e}.vlan.vid`], a[`${e}.vlan.inner_vid`]) -
                                vlanSortKey(b[`${e}.vlan.tags`], b[`${e}.vlan.vid`], b[`${e}.vlan.inner_vid`]))
                            .map((x) => {
                                const label = vlanLabel(x[`${e}.vlan.tags`], x[`${e}.vlan.vid`], x[`${e}.vlan.inner_vid`]);
                                return [`${x[`${e}.vlan.tags`]}|${label}`, [label, vlanTagText(x[`${e}.vlan.tags`]),
                                    counted(x[`${e}.vlan.packets`]), time(x[`${e}.vlan.first_time`]), time(x[`${e}.vlan.last_time`])]];
                            })) },
                ],
            },
            {
                group: 'Traffic',
                fields: [
                    { title: 'Sent', field: `${e}/${e}.tx_bytes`, format: format.size, help: 'Bytes the device sent, as on the wire.' },
                    { title: 'Received', field: `${e}/${e}.rx_bytes`, format: format.size,
                        help: 'Bytes sent to the device as a unicast destination.  Broadcast and multicast frames aren\'t counted.' },
                    { title: 'Unicast frames', field: `${e}/${e}.tx_unicast`, format: counted, help: 'Unicast frames the device sent.' },
                    { title: 'Multicast frames', field: `${e}/${e}.tx_multicast`, format: counted, help: 'Multicast frames the device sent.' },
                    { title: 'Broadcast frames', field: `${e}/${e}.tx_broadcast`, format: counted, help: 'Broadcast frames the device sent.' },
                    { title: 'Malformed frames', field: `${e}/${e}.malformed`, hideZero: true, format: (v) => el('span', { class: 'warn-text' }, counted(v)),
                        help: 'Frames from the device that couldn\'t be decoded: truncated or with bad lengths.' },
                    { title: 'Not kept', field: `${e}/${e}.list_full`, hideZero: true, format: counted,
                        help: 'VLANs, addresses or names left off this device because its list was full (16 VLANs, 8 addresses of each kind, 4 names from each source).' },
                ],
            },
            {
                group: 'DHCP', show: anyOf(`${e}/${e}.dhcp_vendor`, `${e}/${e}.dhcp_prl`, `${e}/${e}.dhcp_client_id`,
                    `${e}/${e}.dhcpv6_duid`, `${e}/${e}.dhcpv6_vendor`, `${e}/${e}.dhcpv6_oro`),
                help: 'What the device sent in its DHCP and DHCPv6 requests.  The parameter request list and vendor class often tell the operating system apart.',
                fields: [
                    { title: 'Vendor class', field: `${e}/${e}.dhcp_vendor`, hideEmpty: true, format: mono, help: 'DHCP option 60.' },
                    { title: 'Parameter request list', field: `${e}/${e}.dhcp_prl`, hideEmpty: true, format: mono,
                        help: 'DHCP option 55: the options the client asked for, in its order.  It works as a fingerprint of the client\'s DHCP software.' },
                    { title: 'Client ID', field: `${e}/${e}.dhcp_client_id`, hideEmpty: true, format: mono,
                        help: 'DHCP option 61, in hex.  Often the MAC address with a type byte in front.' },
                    { title: 'DHCPv6 DUID', field: `${e}/${e}.dhcpv6_duid`, hideEmpty: true, format: mono,
                        help: 'The DHCPv6 client\'s DUID, in hex.  It stays the same across interfaces, so it can tie one host\'s addresses together.' },
                    { title: 'DHCPv6 vendor class', field: `${e}/${e}.dhcpv6_vendor`, hideEmpty: true, format: mono },
                    { title: 'DHCPv6 option requests', field: `${e}/${e}.dhcpv6_oro`, hideEmpty: true, format: mono,
                        help: 'The DHCPv6 options the client asked for.' },
                ],
            },
            {
                group: 'Flows',
                help: `The device's newest IP flows (at most ${deviceFlows}), with either side's last MAC address its own.  The Ethernet flows tab pages through all of them.`,
                fields: [
                    { id: 'eth_flows', wide: true, field: `${base}.macaddr`,
                        draw: (cell, mac, _rec, state) => {
                            state.mac = mac;
                            if (state.table)
                                return;
                            const note = el('span', { class: 'muted' });
                            state.table = flowTable('ethernet-device-flows', () => (macPattern.test(state.mac) ?
                                { mac: state.mac, length: deviceFlows } : { mac: '00:00:00:00:00:00', length: 1 }), (r) => {
                                const n = r?.[`${fl}s.total`] ?? 0;
                                note.textContent = n > deviceFlows ? `Newest ${deviceFlows} of ${n.toLocaleString()} flows` : '';
                            });
                            cell.replaceChildren(el('div', { class: 'pk-bar' }, note,
                                el('button', { type: 'button', onclick: () => {
                                    // Close the device panel, which would cover the tab
                                    cell.closest('dialog')?.close();
                                    openFlows({ mac: state.mac });
                                } }, 'Open in Ethernet flows')),
                            state.table.node);
                        } },
                ],
            },
        ],
    });

    // ---- linked records ------------------------------------------------------

    // What the wire saw a device on another phy (a Wi-Fi client, say) do,
    // from the Ethernet record linked to it: the Ethernet section's rows, read
    // from that record, with the sensors that saw it
    const linkedEthernet = (dev) => {
        const rec = kismet.entities.peer(dev, phy)?.record;
        return rec && rec[e] ? rec : null;
    };

    const sensorRows = (seenby) => Object.values(seenby ?? {}).filter((s) => s && typeof s === 'object')
        .sort((a, b) => (b['kismet.common.seenby.last_time'] ?? 0) - (a['kismet.common.seenby.last_time'] ?? 0));

    const wireFields = [
        { id: 'eth_record', title: 'Ethernet record', field: `${base}.key`, draw: ui.recordLink({ title: 'Open the Ethernet record' }),
            help: 'The Ethernet device record linked to this one.  Open it for its own panel.' },
        { title: 'Last seen on the wire', field: `${base}.last_time`, format: time },
        ...(ethernetSection?.fields ?? []).filter((f) => f.group !== 'Flows'),
        {
            group: 'Sensors', show: (rec) => sensorRows(rec[`${base}.seenby`]).length > 0,
            help: 'The data sources that saw the device on the wire.',
            fields: [
                { id: 'eth_sensors', wide: true, field: `${base}.seenby`,
                    draw: smallTable(['Source', 'Frames', 'Last seen'], (v) => sensorRows(v).map((s) => [
                        String(s['kismet.common.seenby.uuid'] ?? ''), [
                            s['kismet.common.seenby.source']?.['kismet.datasource.name'] ?? s['kismet.common.seenby.uuid'] ?? '',
                            counted(s['kismet.common.seenby.num_packets']),
                            time(s['kismet.common.seenby.last_time'])]])) },
            ],
        },
        ...(ethernetSection?.fields ?? []).filter((f) => f.group === 'Flows'),
    ];

    ui.deviceDetails.add({
        id: 'ethernet_wire', title: 'On the wire', priority: 7,
        match: (device) => device[`${base}.phyname`] !== phy && !!linkedEthernet(device),
        render: (device, node) => {
            const rec = linkedEthernet(device);
            if (rec)
                ui.detailFields(node, rec, wireFields);
        },
    });
}
