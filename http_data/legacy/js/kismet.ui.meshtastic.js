
"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'Meshtastic') {
        return '<i class="fa fa-circle-nodes"></i>';
    }
});

/* Highlight Meshtastic devices */
kismet_ui.AddDeviceRowHighlight({
    name: "Meshtastic Nodes",
    description: "Meshtastic LoRa mesh nodes",
    priority: 100,
    defaultcolor: "#c8f7d2",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === 'Meshtastic';
    }
});

/* Meshtastic Config.DeviceConfig.Role values */
var meshtastic_roles = {
    0: "Client",
    1: "Client (mute)",
    2: "Router",
    3: "Router/Client",
    4: "Repeater",
    5: "Tracker",
    6: "Sensor",
    7: "TAK",
    8: "Client (hidden)",
    9: "Lost and found",
    10: "TAK tracker",
    11: "Router (late)",
    12: "Client (base)",
};

function meshtastic_render_uptime(sec) {
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;

    var t = `${h}h ${m}m ${s}s`;

    if (d > 0)
        t = `${d}d ${t}`;

    return t;
}

/* Telemetry is only shown once a node has reported any */
function meshtastic_has_telemetry(data) {
    var node = data['meshtastic.node'];

    if (typeof(node) === 'undefined')
        return false;

    return node['meshtastic.node.telem.battery'] > 0 ||
        node['meshtastic.node.telem.voltage'] > 0 ||
        node['meshtastic.node.telem.chan_util'] > 0 ||
        node['meshtastic.node.telem.chan_tx_util'] > 0 ||
        node['meshtastic.node.telem.uptime'] > 0;
}

kismet_ui.AddDeviceDetail("meshtastic", "Meshtastic", 0, {
    filter: function(data) {
        return 'meshtastic.node' in data;
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "meshtasticData",
            "fields": [
            {
                field: "meshtastic.node/meshtastic.node.nodeid",
                title: "Node ID",
                empty: "<i>Unknown</i>",
                draw: function(opts) {
                    return kismet.censorString(opts['value']);
                },
                help: "Meshtastic node number, derived from the hardware ID of the radio.",
            },
            {
                field: "meshtastic.node/meshtastic.node.longname",
                title: "Long Name",
                filterOnEmpty: true,
                draw: function(opts) {
                    return kismet.censorString(opts['value']);
                },
                help: "Node name, as set by the operator and advertised in the node info.",
            },
            {
                field: "meshtastic.node/meshtastic.node.shortname",
                title: "Short Name",
                filterOnEmpty: true,
                draw: function(opts) {
                    return kismet.censorString(opts['value']);
                },
                help: "Short node name shown on device screens and in the Meshtastic apps.",
            },
            {
                field: "meshtastic.node/meshtastic.node.role",
                title: "Role",
                draw: function(opts) {
                    return meshtastic_roles[opts['value']] || `Unknown (${opts['value']})`;
                },
                help: "Role the node is configured for; routers and repeaters relay traffic for other nodes.",
            },
            {
                field: "meshtastic.node/meshtastic.node.manuf",
                title: "Hardware Model",
                filterOnZero: true,
                draw: function(opts) {
                    return `${data['kismet.device.base.manuf']} (${opts['value']})`;
                },
                help: "Hardware model advertised by the node, and the raw Meshtastic model ID.",
            },
            {
                field: "meshtastic.node/meshtastic.node.licensed",
                title: "Licensed Operator",
                draw: function(opts) {
                    if (opts['value'])
                        return "Yes";
                    return "No";
                },
                help: "Licensed amateur radio operators run without encryption, as required in many countries.",
            },
            {
                field: "meshtastic.node",
                groupTitle: "Telemetry",
                id: "meshtastic_telem",
                filter: function(opts) {
                    return meshtastic_has_telemetry(opts['data']);
                },
                fields: [
                {
                    field: "meshtastic.node/meshtastic.node.telem.battery",
                    title: "Battery",
                    filterOnZero: true,
                    draw: function(opts) {
                        if (opts['value'] > 100)
                            return "External power";
                        return `${opts['value']}%`;
                    },
                    help: "Battery level reported by the node; values over 100% indicate external power.",
                },
                {
                    field: "meshtastic.node/meshtastic.node.telem.voltage",
                    title: "Voltage",
                    filterOnZero: true,
                    draw: function(opts) {
                        return `${opts['value'].toFixed(2)}V`;
                    },
                },
                {
                    field: "meshtastic.node/meshtastic.node.telem.chan_util",
                    title: "Channel Utilization",
                    filterOnZero: true,
                    draw: function(opts) {
                        return `${opts['value'].toFixed(1)}%`;
                    },
                    help: "Percentage of airtime in use on the channel, as seen by the node, including traffic from other nodes.",
                },
                {
                    field: "meshtastic.node/meshtastic.node.telem.chan_tx_util",
                    title: "TX Utilization",
                    filterOnZero: true,
                    draw: function(opts) {
                        return `${opts['value'].toFixed(1)}%`;
                    },
                    help: "Percentage of airtime the node itself spent transmitting.",
                },
                {
                    field: "meshtastic.node/meshtastic.node.telem.uptime",
                    title: "Uptime",
                    filterOnZero: true,
                    draw: function(opts) {
                        return meshtastic_render_uptime(opts['value']);
                    },
                },
                {
                    field: "meshtastic.node/meshtastic.node.telem.timestamp",
                    title: "Reported",
                    filterOnZero: true,
                    draw: kismet_ui.RenderTrimmedTime,
                    help: "Time reported by the node with its telemetry.",
                },
                ],
            },
            ],
        });
    },
});
