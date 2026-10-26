
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
            {
                field: "btle.device/btle.device.tracker",
                groupTitle: "Location Tracker",
                filterOnEmpty: true,
                id: "btle_tracker",
                help: "Location tracker (item finder) advertisement.  The values are what the tracker advertises; they are not authenticated.",
                fields: [
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.type",
                    title: "Type",
                    draw: function(opts) {
                        var types = {
                            "samsung_smarttag": "Samsung SmartTag",
                            "apple_findmy": "Apple Find My",
                            "google_fmdn": "Google Find My Device network",
                            "dult": "DULT (unwanted tracking detection)",
                        };
                        return types[opts['value']] || opts['value'];
                    },
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.subtype",
                    title: "Device",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        var subtypes = {
                            "airtag": "AirTag",
                            "findmy_accessory": "Find My network accessory",
                            "airpods": "AirPods",
                        };
                        return subtypes[opts['value']] || opts['value'];
                    },
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.state_name",
                    title: "State",
                    draw: function(opts) {
                        var raw = kismet.ObjectByString(opts['data'],
                            "btle.device/btle.device.tracker/btle.device.tracker.state");
                        return opts['value'].replace(/_/g, " ") + " (" + raw + ")";
                    },
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.separated",
                    title: "Separated",
                    draw: function(opts) {
                        if (opts['value'])
                            return "Yes";
                        return "No";
                    },
                    help: "The tracker advertises that it is away from its owner.",
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.battery",
                    title: "Battery",
                    draw: function(opts) {
                        return opts['value'].replace(/_/g, " ");
                    },
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.uwb",
                    title: "UWB",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        if (opts['value'])
                            return "Supported";
                        return "Not supported";
                    },
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.aging_counter",
                    title: "Aging Counter",
                    filterOnEmpty: true,
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.privacy_id",
                    title: "Privacy ID",
                    filterOnEmpty: true,
                    help: "Rotating identifier from the advertisement.  It does not identify the owner; a separated tracker keeps it across several address changes.",
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.ephemeral_id",
                    title: "Ephemeral ID",
                    filterOnEmpty: true,
                    help: "Rotating identifier from the advertisement; it changes every 1024 seconds and does not identify the owner.",
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.network_id",
                    title: "Network ID",
                    filterOnEmpty: true,
                    help: "Finding network the tracker reports to, from its DULT advertisement.",
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.last_time",
                    title: "Last Seen",
                    draw: function(opts) {
                        return new Date(opts['value'] * 1000);
                    },
                },
                ],
            },
            ],
        });
    },
});

