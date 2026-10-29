"use strict";

/* ANT and ANT+: heart-rate straps, bike sensors, fitness equipment */

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'ANT') {
        var type = row['original_data']['kismet.device.base.type'] || '';

        if (type.indexOf('Heart rate') >= 0)
            return '<i class="fa fa-heart-pulse"></i>';
        if (type.indexOf('Bike') >= 0)
            return '<i class="fa fa-bicycle"></i>';
        if (type.indexOf('Stride') >= 0)
            return '<i class="fa fa-person-running"></i>';
        return '<i class="fa fa-wave-square"></i>';
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "ANT / ANT+ devices",
    description: "ANT and ANT+ fitness sensors and the devices that read them",
    priority: 100,
    defaultcolor: "#d9f7e3",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === 'ANT';
    }
});

function antHas(opts, f, empty) {
    var v = kismet.ObjectByString(opts['data'], "ant.device/ant.device." + f);
    return v !== undefined && v !== empty;
}

kismet_ui.AddDeviceDetail("ant", "ANT / ANT+", 0, {
    filter: function(data) {
        return data['kismet.device.base.phyname'] === "ANT";
    },
    draw: function(data, target) {
        target.devicedata(data, {
            id: "antdata",
            fields: [
            {
                field: "ant.device/ant.device.device_type_name",
                title: "Device type",
                empty: "Unknown",
                draw: function(opts) {
                    var t = kismet.ObjectByString(opts['data'], "ant.device/ant.device.device_type");
                    return (opts['value'] || "Unknown") + " (" + t + ")";
                },
                help: "The ANT+ device profile its device type names. A private network's types are its own.",
            },
            {
                field: "ant.device/ant.device.device_number",
                title: "Device number",
                help: "What a watch or head unit pairs on, with the device type and transmission type.",
            },
            {
                field: "ant.device/ant.device.network",
                title: "Network",
                draw: function(opts) {
                    var plus = kismet.ObjectByString(opts['data'], "ant.device/ant.device.ant_plus");
                    return opts['value'] + (plus ? " (ANT+)" : " (private network key)");
                },
                help: "The 2-octet address on the air, derived from the 8-octet network key; A6:C5 is ANT+.",
            },
            {
                field: "ant.device/ant.device.trans_type",
                title: "Transmission type",
                draw: function(opts) {
                    return "0x" + ("0" + opts['value'].toString(16)).slice(-2);
                },
            },
            {
                field: "ant.device/ant.device.rf_channel",
                title: "Channel",
                filter: function(opts) { return antHas(opts, "rf_channel", -1); },
                draw: function(opts) {
                    return opts['value'] + " (" + (2400 + opts['value']) + " MHz)";
                },
            },
            {
                field: "ant.device/ant.device.heart_rate",
                title: "Heart rate",
                filter: function(opts) { return antHas(opts, "heart_rate", 0); },
                draw: function(opts) {
                    return opts['value'] + " bpm";
                },
            },
            {
                field: "ant.device/ant.device.manufacturer",
                title: "Manufacturer",
                filter: function(opts) { return antHas(opts, "manufacturer_id", 0); },
                draw: function(opts) {
                    var id = kismet.ObjectByString(opts['data'], "ant.device/ant.device.manufacturer_id");
                    return (opts['value'] || "ID") + " (" + id + ")";
                },
            },
            {
                field: "ant.device/ant.device.model",
                title: "Model",
                filter: function(opts) { return antHas(opts, "model", 0); },
            },
            {
                field: "ant.device/ant.device.serial",
                title: "Serial number",
                filter: function(opts) { return antHas(opts, "serial", 0); },
            },
            {
                field: "ant.device/ant.device.sw_version",
                title: "Software version",
                filter: function(opts) { return antHas(opts, "sw_version", ""); },
            },
            {
                field: "ant.device/ant.device.battery_status",
                title: "Battery",
                filter: function(opts) { return antHas(opts, "battery_status", ""); },
            },
            {
                field: "ant.device/ant.device.pairing_seen",
                title: "Pairing",
                filter: function(opts) { return antHas(opts, "pairing_seen", 0); },
                draw: function(opts) { return "Has sent with the pairing bit set"; },
            },
            {
                field: "ant.device/ant.device.last_page",
                title: "Last data page",
                filter: function(opts) { return antHas(opts, "last_page", -1); },
            },
            {
                field: "ant.device/ant.device.last_payload",
                title: "Last payload",
            },
            ],
        });
    },
});
