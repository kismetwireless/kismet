
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
            {
                field: "btle.device/btle.device.pdu_type",
                title: "PDU Type",
                draw: function(opts) {
                    var pdu_types = {
                        0x0: "ADV_IND (Connectable)",
                        0x1: "ADV_DIRECT_IND",
                        0x2: "ADV_NONCONN_IND (Non-connectable)",
                        0x3: "SCAN_REQ",
                        0x4: "SCAN_RSP",
                        0x5: "CONNECT_REQ",
                        0x6: "ADV_SCAN_IND (Scannable)",
                        0x7: "ADV_EXT_IND"
                    };
                    return pdu_types[opts['value']] || "Unknown (" + opts['value'] + ")";
                },
                help: "BLE advertising PDU type indicating if device is connectable",
            },
            ],
        });
    },
});

