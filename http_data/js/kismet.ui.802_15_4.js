"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === '802.15.4') {
        if (kismet_theme.theme === 'dark') {
            return '<img src="images/zigbee-icon-dark.svg" height="20px" width="20px">';
        } else {
            return '<img src="images/zigbee-icon.svg" height="20px" width="20px">';
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
            ],
        });
    },
});
