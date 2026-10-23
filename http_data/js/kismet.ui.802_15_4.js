"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === '802.15.4') {
        if (kismet_theme.theme === 'dark') {
            return '<img src="images/zigbee-icon-dark.svg" style="height: 1em; width: 1em; vertical-align: -0.125em;">';
        } else {
            return '<img src="images/zigbee-icon.svg" style="height: 1em; width: 1em; vertical-align: -0.125em;">';
        }
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "802.15.4/Zigbee Device",
    description: "Highlight all 802.15.4/Zigbee devices",
    priority: 100,
    defaultcolor: "#b3d1b3",
    defaultenable: false,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return ('kismet.device.base.phyname' in data && data['kismet.device.base.phyname'] == '802.15.4');
    }
});

/* Zigbee devices seen using a publicly known key, or exposing one */
kismet_ui.AddDeviceRowHighlight({
    name: "Zigbee Known Key",
    description: "Zigbee devices using a publicly known key, or sending a key in the clear",
    priority: 10,
    defaultcolor: "#ff6666",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname',
        '802154.device'
    ],
    selector: function(data) {
        if (data['kismet.device.base.phyname'] !== '802.15.4')
            return false;

        return kismet.ObjectByString(data, '802154.device/802154.device.key_state') === 2;
    }
});


kismet_ui.AddDeviceDetail("802154", "802.15.4", 0, {
    filter: function(data) {
        return data['kismet.device.base.phyname'] === "802.15.4";
    },
    draw: function(data, target) {
        target.devicedata(data, {
            id: "802154data",
            fields: [
            {
                field: "802154.device/802154.device.network_type",
                title: "Network",
                empty: "Unknown",
                help: "What the frames' payloads show: a Zigbee NWK header or beacon, Zigbee Green Power, Thread (its beacon, or MLE over 6LoWPAN), or other 6LoWPAN traffic.",
            },
            {
                field: "802154.device/802154.device.role",
                title: "Role",
                empty: "Unknown",
                help: "From its beacons: the PAN coordinator, or a router (Zigbee routers beacon).",
            },
            {
                field: "802154.device/802154.device.pan_id",
                title: "PAN ID",
                draw: function(opts) {
                    if (opts['value'] === 0xFFFF)
                        return "Unknown";
                    return "0x" + opts['value'].toString(16).padStart(4, '0');
                },
            },
            {
                field: "802154.device/802154.device.short_addr",
                title: "Short address",
                draw: function(opts) {
                    if (opts['value'] === 0xFFFF)
                        return "Unknown";
                    return "0x" + opts['value'].toString(16).padStart(4, '0');
                },
            },
            {
                field: "802154.device/802154.device.ieee_addr",
                title: "IEEE address",
                filter: function(opts) {
                    var v = kismet.ObjectByString(opts['data'], "802154.device/802154.device.ieee_addr");
                    return v && v !== "00:00:00:00:00:00";
                },
                help: "The EUI-64 a Zigbee NWK header gave for this short address.",
            },
            {
                field: "802154.device/802154.device.gpd_srcid",
                title: "GPD source ID",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "802154.device/802154.device.gpd_srcid") != 0;
                },
                draw: function(opts) {
                    return "0x" + opts['value'].toString(16).padStart(8, '0');
                },
                help: "The Zigbee Green Power source ID that names this device; it has no MAC address of its own, so Kismet tracks it under an address made from this ID.",
            },
            {
                field: "802154.device/802154.device.ext_pan_id",
                title: "Extended PAN ID",
                empty: "Unknown",
            },
            {
                field: "802154.device/802154.device.network_name",
                title: "Network name",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "802154.device/802154.device.network_name") !== "";
                },
            },
            {
                field: "802154.device/802154.device.stack_profile",
                title: "Zigbee stack profile",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "802154.device/802154.device.stack_profile") != 0;
                },
                draw: function(opts) {
                    if (opts['value'] === 2)
                        return "Zigbee PRO";
                    if (opts['value'] === 1)
                        return "Zigbee";
                    return "Profile " + opts['value'];
                },
            },
            {
                field: "802154.device/802154.device.key_status",
                title: "Key check",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "802154.device/802154.device.key_status") !== "";
                },
                draw: function(opts) {
                    var state = kismet.ObjectByString(opts['data'], "802154.device/802154.device.key_state");
                    var first = kismet.ObjectByString(opts['data'], "802154.device/802154.device.key_first_time");
                    var text = kismet.censorString(opts['value']);

                    if (state === 2) {
                        if (first > 0)
                            text += ", first seen " + new Date(first * 1000).toLocaleString();
                        return '<b style="color: #c00000;">' + text + '</b>';
                    }

                    if (state === 3)
                        return '<b style="color: #007000;">' + text + '</b>';

                    return text;
                },
                help: "What Kismet checked: each secured NWK or APS frame is checked against a table of publicly known Zigbee keys (a match needs the frame's MIC to verify, so it is never a guess), and Transport Key commands sent without APS security are looked for. \"Known key in use\" means anyone can read this network's traffic; \"No known key\" means every secured frame was checked and none matched, so the network uses a key of its own; \"Not checked yet\" means it sent encrypted frames but none that could be checked so far. \"Your key in use\" means its frames matched a key you gave Kismet (zigbee_key= in kismet_zigbee.conf or kismet_site.conf); that is no weakness, so it raises no alert.",
            },
            {
                field: "802154.device/802154.device.weak_key",
                title: "Publicly known key",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "802154.device/802154.device.weak_key") !== "";
                },
                help: "Keys anyone can know, seen in use: a Transport Key command sent without APS security (its key in the clear), APS security with a publicly known link key (ZigBeeAlliance09, the ZLL link key, the Zigbee 3.0 distributed link key and others), or NWK security with a publicly known network key (the TI Z-Stack default and others), named here. Anyone who receives these frames can decrypt the network's traffic.",
            },
            {
                field: "802154.device/802154.device.exposed_key",
                title: "Exposed key",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "802154.device/802154.device.exposed_key") !== "";
                },
                help: "The key a Transport Key command from this device carried, readable because it was sent in the clear or under a publicly known link key.",
            },
            ],
        });
    },
});
