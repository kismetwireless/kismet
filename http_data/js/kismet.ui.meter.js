
"use strict";

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "RF Meter Devices",
    description: "RF Power, Water, Gas Meters",
    priority: 100,
    defaultcolor: "#b3ffe6",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === "RF Meter";
    }
});

kismet_ui.AddDeviceDetail("rfmeter", "Meter (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RTLAMR");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "meterData",
            "fields": [
            {
                field: "meter.device/meter.device.meter_id",
                title: "Meter ID",
                empty: "<i>Unknown</i>"
            },
            {
                field: "meter.device/meter.device.meter_type",
                title: "Meter Type",
                empty: "<i>Unknown</i>"
            },
            {
                field: "meter.device/meter.device.consumption",
                title: "Consumption",
                empty: "<i>Unknown</i>"
            },
            ],
        });
    },
});

