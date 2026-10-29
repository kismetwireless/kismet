"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'MeshCore') {
        return '<i class="fa fa-circle-nodes"></i>';
    }
});

/* Highlight MeshCore devices */
kismet_ui.AddDeviceRowHighlight({
    name: "MeshCore Nodes",
    description: "MeshCore LoRa mesh nodes",
    priority: 100,
    defaultcolor: "#d2e4f7",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === 'MeshCore';
    }
});

/* Advert node types, from the MeshCore firmware ADV_TYPE_* */
var meshcore_node_types = {
    0: "None",
    1: "Companion",
    2: "Repeater",
    3: "Room server",
    4: "Sensor",
};

kismet_ui.AddDeviceDetail("meshcore", "MeshCore", 0, {
    filter: function(data) {
        return 'meshcore.node' in data;
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "meshcoreData",
            "fields": [
            {
                field: "meshcore.node/meshcore.node.name",
                title: "Name",
                empty: "<i>Unknown</i>",
                draw: function(opts) {
                    return kismet.censorString(opts['value']);
                },
                help: "Node name from the most recent signed advert.",
            },
            {
                field: "meshcore.node/meshcore.node.type",
                title: "Node Type",
                draw: function(opts) {
                    return meshcore_node_types[opts['value']] || `Unknown (${opts['value']})`;
                },
                help: "Role advertised by the node; repeaters relay traffic for other nodes, and room servers host shared message boards.",
            },
            {
                field: "meshcore.node/meshcore.node.pubkey",
                title: "Public Key",
                draw: function(opts) {
                    var keytype = data['meshcore.node']['meshcore.node.key_type'];
                    return `${keytype} <span style="font-family: monospace; word-break: break-all;">${kismet.censorString(opts['value'])}</span>`;
                },
                help: "Public key identifying the node, in base64.  Other packets refer to nodes by the first byte or bytes of this key.",
            },
            {
                field: "meshcore.node/meshcore.node.lat",
                title: "Advertised Location",
                filterOnZero: true,
                draw: function(opts) {
                    var lon = data['meshcore.node']['meshcore.node.lon'];
                    return `${kismet.censorLocation(opts['value'].toFixed(6))}, ${kismet.censorLocation(lon.toFixed(6))}`;
                },
                help: "Location the node includes in its adverts, if any.",
            },
            {
                field: "meshcore.node/meshcore.node.adverts",
                title: "Adverts",
                help: "Number of adverts with valid signatures seen from this node, including repeats relayed by other nodes.",
            },
            {
                field: "meshcore.node/meshcore.node.advert_ts",
                title: "Last Advert Time",
                filterOnZero: true,
                draw: kismet_ui.RenderTrimmedTime,
                help: "Time from the node's own clock in its last advert, which may be wrong.",
            },
            {
                field: "meshcore.node/meshcore.node.advert_hops",
                title: "Advert Hops",
                help: "Number of repeaters the most recent advert passed through before it was received.",
            },
            {
                field: "meshcore.node/meshcore.node.relayed",
                title: "Packets Relayed",
                filterOnZero: true,
                help: "Number of packets this node was seen repeating for other nodes.",
            },
            {
                field: "meshcore.node/meshcore.node.last_relayed",
                title: "Last Relayed",
                filterOnZero: true,
                draw: kismet_ui.RenderTrimmedTime,
            },
            {
                field: "meshcore.node/meshcore.node.bad_signatures",
                title: "Invalid Adverts",
                filterOnZero: true,
                help: "Adverts for this node's key that failed signature verification; these may be spoofed.",
            },
            ],
        });
    },
});
