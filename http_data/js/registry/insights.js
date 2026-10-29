// Registries for the Insights tab (js/widgets/insights/): the device graph,
// the activity rhythm, and the list of unusual things.
//
// The base code knows only devices.  A phy module adds what it knows about
// how its devices relate (a Wi-Fi client and its access point, a network
// name and the devices that advertise or look for it) and what it finds
// unusual (one network name with two kinds of security).

import { createRegistry } from './registry.js';

// How devices relate.
//   id, fields     extra device fields to read, in the form the device views take
//   relate(rec, g) called for each device record; g adds to the graph:
//     g.device(key)                  the node of a device, by device key
//     g.mac(mac)                     the node of a device by MAC, if it is in the window
//     g.thing(id, { label, kind, title })   a node that isn't a device (a network name);
//                                    the same id gives the same node
//     g.link(a, b, { kind, weight, title })  a line between two nodes; kind is a
//                                    linkKinds id
//     g.flag(node, text)             mark a node as unusual (drawn with a ring)
//     g.role(node, role)             'ap', 'client', 'probe', 'bridge', or 'other'
//     g.same(a, b)                   two device nodes are one device (an access point's
//                                    addresses for each network and band)
//     g.drop(node)                   take a node and its links out again
//   after(g)       called once after every record, for links that need them all
export const insightRelations = createRegistry('insightRelations', {
    required: ['relate'],
    defaults: { fields: [] },
});

// Kinds of line in the graph, so a phy can draw its own.
//   id, title (for the legend), style: 'solid' | 'dashed' | 'dotted',
//   color: a theme variable ('--accent'), length: the spring length in px,
//   live: true to show packets moving along it, names: true when the thing at
//   its far end names the device (so the device needs no label of its own)
//   groupTitle: what several devices at one end are called ('clients'), for
//   the Flow and Access points views
export const linkKinds = createRegistry('linkKinds', {
    required: ['title'],
    defaults: { style: 'solid', color: '--muted', length: 60, live: false },
});

// Unusual things, for the Unusual list and rings in the graph.
//   id, title, fields (as above)
//   alerts         Kismet alert headers this finding explains, so they aren't
//                  listed again as plain alerts
//   find(model) -> [{ id, severity: 'high'|'medium'|'info', title, text,
//                     devices: [keys], things: [thing ids] }]
//     model.records   the device records read
//     model.graph     the graph built from them (nodes, links)
//     model.now       server time, seconds
//     model.alerts    Kismet's alerts in the window
export const insightFindings = createRegistry('insightFindings', {
    required: ['find'],
    defaults: { fields: [] },
});

// Whole views of their own, shown as further tabs after the built-in ones.
//   id, title, priority
//   create(el, ctx) -> { update(model), show(), hide(), destroy() }
//     update gets the same model as findings, after each read (every few
//     seconds while the view shows); a view may also read what it needs itself
//     ctx.openDevice(key), ctx.api, ctx.showing() -> bool
export const insightViews = createRegistry('insightViews', {
    required: ['title', 'create'],
});
