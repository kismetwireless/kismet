
"use strict";

/* Highlight zwave devices */
kismet_ui.AddDeviceRowHighlight({
    name: "Z-Wave Devices",
    description: "Z-Wave Node",
    priority: 100,
    defaultcolor: '#ffe6b3',
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === "Z-Wave";
    }
});

kismet_ui.AddDeviceDetail("zwave", "Z-Wave (Killerzee)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "Z-Wave");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "zwaveData",
            "fields": [
            {
                field: "zwave.device/zwave.device.home_id",
                title: "Home ID",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'].toString(16);
                }
            },
            {
                field: "zwave.device/zwave.device.device_id",
                title: "Device ID",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'].toString(16);
                }
            },
            ],
        });
    },
});

