
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
                field: "btle.device/btle.device.appearance_name",
                title: "Appearance",
                filterOnEmpty: true,
                help: "What the device advertises itself as (the Bluetooth appearance value).",
            },
            {
                field: "btle.device/btle.device.beacon",
                groupTitle: "Beacon",
                filterOnEmpty: true,
                id: "btle_beacon",
                help: "Identity advertised by a proximity beacon (iBeacon, AltBeacon, or Eddystone).",
                fields: [
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.type",
                    title: "Format",
                    draw: function(opts) {
                        var types = {
                            "ibeacon": "iBeacon",
                            "altbeacon": "AltBeacon",
                            "eddystone_uid": "Eddystone UID",
                            "eddystone_url": "Eddystone URL",
                        };
                        return types[opts['value']] || kismet.censorString(opts['value']);
                    },
                },
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.uuid",
                    title: "UUID",
                    filterOnEmpty: true,
                },
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.major",
                    title: "Major",
                    filterOnEmpty: true,
                },
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.minor",
                    title: "Minor",
                    filterOnEmpty: true,
                },
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.namespace",
                    title: "Namespace",
                    filterOnEmpty: true,
                },
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.instance",
                    title: "Instance",
                    filterOnEmpty: true,
                },
                {
                    field: "btle.device/btle.device.beacon/btle.device.beacon.url",
                    title: "URL",
                    filterOnEmpty: true,
                },
                ],
            },
            kismet_ui_btadv.fields("btle.device/btle.device.adv"),
            {
                field: "btle.device/btle.device.connection",
                groupTitle: "Connection",
                filterOnEmpty: true,
                id: "btle_connection",
                help: "The last connection a central made to this device, from its connection request.",
                fields: [
                {
                    field: "btle.device/btle.device.connection/btle.device.connection.central",
                    title: "Central",
                    draw: function(opts) {
                        return kismet.censorMAC(opts['value']);
                    },
                },
                {
                    field: "btle.device/btle.device.connection/btle.device.connection.interval_us",
                    title: "Interval",
                    draw: function(opts) {
                        return (opts['value'] / 1000).toFixed(2) + " ms";
                    },
                },
                {
                    field: "btle.device/btle.device.connection/btle.device.connection.latency",
                    title: "Latency",
                },
                {
                    field: "btle.device/btle.device.connection/btle.device.connection.timeout_ms",
                    title: "Timeout",
                    draw: function(opts) {
                        return opts['value'] + " ms";
                    },
                },
                ],
            },
            {
                field: "btle.device/btle.device.adv_sid",
                title: "Advertising Set",
                filterOnEmpty: true,
                help: "Extended advertising set ID.",
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
                            "tile": "Tile",
                            "chipolo": "Chipolo",
                            "pebblebee": "Pebblebee",
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
                    help: "Salted hash of the rotating identifier from the advertisement, which changes every 1024 seconds; it links advertisements within this run of Kismet only.",
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.maintained",
                    title: "Owner Nearby Recently",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        return opts['value'] ? "Yes" : "No";
                    },
                    help: "The tracker's owner connected to it within its current key period.",
                },
                {
                    field: "btle.device/btle.device.tracker/btle.device.tracker.follow_time",
                    title: "Seen Separated",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        return Math.floor(opts['value'] / 60) + " minutes";
                    },
                    help: "How long the separated tracker has been seen without a long gap; with GPS, the TRACKERFOLLOW alert is raised once it has been seen this way for 30 minutes across several places.",
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

