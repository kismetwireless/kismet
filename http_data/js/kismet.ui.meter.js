
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
		return 'meter.device' in data;
    }
});

kismet_ui.AddDeviceDetail("rfmeter", "Meter (SDR)", 0, {
    filter: function(data) {
		return 'meter.device' in data;
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "meterData",
            "fields": [
            {
                field: "meter.device/meter.device.meter_id",
                title: "Meter ID",
                empty: "<i>Unknown</i>",
            },
            {
                field: "meter.device/meter.device.meter_type",
                title: "Meter Type",
                empty: "<i>Unknown</i>",
				help: "Type of meter (eletrical, gas, or water)",
            },
            {
                field: "meter.device/meter.device.model_vec",
                title: "Models",
                empty: "<i>Unknown</i>",
                help: "Meters may be decoded as multiple models.",
                draw: function(opts) {
                    var models = "";
                    data['meter.device']['meter.device.model_vec'].forEach(m => {
                        models = `${models}${m}<br>`
                    });

                    return models;
                },
            },
            {
                field: "meter.device/meter.device.consumption",
                title: "Consumption",
                empty: "<i>Unknown</i>",
				help: "Consumption rate (units may vary per meter type)",
            },
            ],
        });
    },
});

