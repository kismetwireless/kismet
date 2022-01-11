
kismet_ui.AddDeviceDetail("btle", "BTLE", 0, {
    filter: function(data) {
        return data['kismet.device.base.phyname'] === "BTLE";
    },
    draw: function(data, target) {
        target.devicedata(data, {
            id: "btledata",
            fields: [
            {
                field: "btle_discovery",
                title: " Discovery",
                draw: function(opts) {
                    var le = 
                        kismet.ObjectByString(opts['data'], "btle.device/btle.device.le_limited_discoverable");
                    var ge = 
                        kismet.ObjectByString(opts['data'], "btle.device/btle.device.le_general_discoverable");

                    var text = "";

                    if (le)
                        text = "Limited";

                    if (ge)
                        if (text.length == 0)
                            text = "General";
                        else
                            text += ", General";

                    if (text.length == 0)
                        return "Unknown";

                    return text;
                },
                help: "BTLE devices with limited discovery can only be detected for 30 seconds.  Devices with general discovery can be detected at any time.",
            },
            {
                field: "btle.device/btle.device.br_edr_unsupported",
                title: "BR/EDR Mode",
                draw: function(opts) {
                    if (opts['value']) 
                        return "Not supported";
                    return "Supported";
                },
                help: "Some devices support classic Bluetooth BR/EDR modes.",
            },
            {
                field: "btle.device/btle.device.simultaneous_br_edr_controller",
                title: "BR EDR Controller",
                draw: function(opts) {
                    if (opts['value']) 
                        return "Supported";
                    return "Not supported";
                },
                help: "Device supports BT classic BR/EDR modes as a controller",
            },
            {
                field: "btle.device/btle.device.simultaneous_br_edr_host",
                title: "BR EDR Host",
                draw: function(opts) {
                    if (opts['value']) 
                        return "Supported";
                    return "Not supported";
                },
                help: "Device supports BT classic BR/EDR modes as a host",
            },
            ],
        });
    },
});

