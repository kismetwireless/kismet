// Detail rows for the decoded advertising and EIR record, shared by the BTLE and
// Bluetooth device details; base is the path of the record, such as
// "btle.device/btle.device.adv"
export function fields(base) {
    var f = function(name) {
        return base + "/bluetooth.adv." + name;
    };

    var sub = function(rec, name) {
        return f(rec) + "/bluetooth.adv." + rec + "." + name;
    };

    var yesno = function(opts) {
        return opts['value'] ? "Yes" : "No";
    };

    var words = function(opts) {
        var s = String(opts['value']).replace(/_/g, " ");
        return kismet.sanitizeHTML(s.charAt(0).toUpperCase() + s.slice(1));
    };

    var usec = function(opts) {
        return kismet.sanitizeHTML((opts['value'] / 1000).toFixed(2) + " ms");
    };

    return {
        field: base,
        groupTitle: "Advertised Data",
        filterOnEmpty: true,
        id: "btadv_" + kismet.sanitizeId(base),
        help: "Records decoded from the advertising or extended inquiry response data.  The " +
            "values are what the device advertises; they are not authenticated.",
        fields: [
        {
            field: base + "/bluetooth.company_name",
            title: "Company",
            filterOnEmpty: true,
            help: "Company named by the manufacturer data's company ID.",
        },
        {
            field: f("service_names"),
            title: "Services",
            filterOnEmpty: true,
            draw: function(opts) {
                return kismet.sanitizeHTML(opts['value'].join(", "));
            },
        },
        {
            field: f("service_class"),
            title: "Device Kind",
            filterOnEmpty: true,
            draw: words,
            help: "Kind of device its advertised services suggest.",
        },
        {
            field: f("vehicle"),
            title: "Vehicle",
            filterOnEmpty: true,
            draw: words,
        },
        {
            field: f("device_id"),
            title: "Device ID",
            filterOnEmpty: true,
            help: "Device ID record: vendor, product and version of the device.",
            draw: function(opts) {
                var v = opts['value'];
                var vendor = v['bluetooth.company_name'] ||
                    ("0x" + v['bluetooth.adv.device_id.vendor'].toString(16).padStart(4, "0"));
                return kismet.sanitizeHTML(vendor + " (" + v['bluetooth.adv.device_id.vendor_source'] +
                    "), product 0x" + v['bluetooth.adv.device_id.product'].toString(16).padStart(4, "0") +
                    ", version " + v['bluetooth.adv.device_id.version']);
            },
        },
        {
            field: f("microsoft_device"),
            title: "Microsoft",
            filterOnEmpty: true,
            help: "Microsoft Connected Devices or Swift Pair advertisement.",
        },
        {
            field: f("swift_pair_name"),
            title: "Swift Pair Name",
            filterOnEmpty: true,
        },
        {
            field: f("fast_pair_model"),
            title: "Fast Pair Model",
            filterOnEmpty: true,
            help: "Google Fast Pair model ID, sent while the device is pairable.",
        },
        {
            field: f("matter"),
            title: "Matter",
            filterOnEmpty: true,
            help: "Matter commissioning advertisement.",
            draw: function(opts) {
                var v = opts['value'];
                var vendor = v['bluetooth.adv.matter.vendor_name'] ||
                    ("vendor 0x" + v['bluetooth.adv.matter.vendor_id'].toString(16).padStart(4, "0"));
                return kismet.sanitizeHTML(vendor + ", product 0x" +
                    v['bluetooth.adv.matter.product_id'].toString(16).padStart(4, "0") +
                    ", discriminator " + v['bluetooth.adv.matter.discriminator']);
            },
        },
        {
            field: f("sensor"),
            title: "Sensor",
            filterOnEmpty: true,
            help: "Environmental sensor readings the device broadcasts.",
            draw: function(opts) {
                var v = opts['value'];
                var p = [];
                if ('bluetooth.adv.sensor.temperature' in v)
                    p.push(v['bluetooth.adv.sensor.temperature'].toFixed(2) + " C");
                if ('bluetooth.adv.sensor.humidity' in v)
                    p.push(v['bluetooth.adv.sensor.humidity'].toFixed(1) + "% RH");
                if ('bluetooth.adv.sensor.pressure' in v)
                    p.push(v['bluetooth.adv.sensor.pressure'].toFixed(1) + " hPa");
                if ('bluetooth.adv.sensor.battery_mv' in v)
                    p.push((v['bluetooth.adv.sensor.battery_mv'] / 1000).toFixed(3) + " V");
                return kismet.sanitizeHTML(p.join(", ") + " (" + v['bluetooth.adv.sensor.source'] + ")");
            },
        },
        {
            field: f("continuity"),
            groupTitle: "Apple Continuity",
            filterOnEmpty: true,
            id: "btadv_continuity_" + kismet.sanitizeId(base),
            fields: [
            { field: sub("continuity", "messages"), title: "Messages", filterOnEmpty: true, },
            { field: sub("continuity", "activity"), title: "Activity", filterOnEmpty: true, },
            { field: sub("continuity", "wifi_on"), title: "Wi-Fi On", filterOnEmpty: true, draw: yesno, },
            { field: sub("continuity", "airdrop_receiving"), title: "AirDrop Receiving", filterOnEmpty: true,
                draw: yesno, },
            { field: sub("continuity", "nearby_action"), title: "Action", filterOnEmpty: true, },
            { field: sub("continuity", "setup_device"), title: "Setting Up", filterOnEmpty: true, },
            { field: sub("continuity", "homekit.category"), title: "HomeKit Accessory", filterOnEmpty: true, },
            { field: sub("continuity", "homekit.device_id"), title: "HomeKit ID", filterOnEmpty: true, },
            { field: sub("continuity", "homekit.paired"), title: "HomeKit Paired", filterOnEmpty: true,
                draw: yesno, },
            { field: sub("continuity", "airplay_ipv4"), title: "AirPlay Address", filterOnEmpty: true, },
            { field: sub("continuity", "airprint_address"), title: "AirPrint Address", filterOnEmpty: true, },
            { field: sub("continuity", "hotspot.network"), title: "Hotspot Network", filterOnEmpty: true, },
            { field: sub("continuity", "hotspot.signal_bars"), title: "Hotspot Signal", filterOnEmpty: true, },
            { field: sub("continuity", "hotspot.battery"), title: "Hotspot Battery", filterOnEmpty: true,
                draw: function(opts) { return opts['value'] + "%"; }, },
            ],
        },
        {
            field: f("mesh"),
            groupTitle: "Bluetooth Mesh",
            filterOnEmpty: true,
            id: "btadv_mesh_" + kismet.sanitizeId(base),
            fields: [
            { field: sub("mesh", "beacon"), title: "Beacon", filterOnEmpty: true, },
            { field: sub("mesh", "network_id"), title: "Network ID", filterOnEmpty: true, },
            { field: sub("mesh", "iv_index"), title: "IV Index", filterOnEmpty: true, },
            { field: sub("mesh", "proxy"), title: "Proxy", filterOnEmpty: true, },
            { field: sub("mesh", "device_uuid"), title: "Unprovisioned UUID", filterOnEmpty: true, },
            { field: sub("mesh", "oob_info"), title: "OOB Information", filterOnEmpty: true, },
            ],
        },
        {
            field: f("audio"),
            groupTitle: "LE Audio",
            filterOnEmpty: true,
            id: "btadv_audio_" + kismet.sanitizeId(base),
            fields: [
            { field: sub("audio", "broadcast_name"), title: "Broadcast", filterOnEmpty: true, },
            { field: sub("audio", "broadcast_id"), title: "Broadcast ID", filterOnEmpty: true, },
            { field: sub("audio", "program_info"), title: "Program", filterOnEmpty: true, },
            { field: sub("audio", "language"), title: "Language", filterOnEmpty: true, },
            { field: sub("audio", "quality"), title: "Quality", filterOnEmpty: true, },
            { field: sub("audio", "encrypted"), title: "Encrypted", filterOnEmpty: true, draw: yesno, },
            { field: sub("audio", "unicast"), title: "Unicast", filterOnEmpty: true, },
            { field: sub("audio", "sink_contexts"), title: "Sink Contexts", filterOnEmpty: true, },
            { field: sub("audio", "source_contexts"), title: "Source Contexts", filterOnEmpty: true, },
            { field: sub("audio", "set_id"), title: "Coordinated Set", filterOnEmpty: true, },
            ],
        },
        {
            field: f("indoor"),
            title: "Indoor Position",
            filterOnEmpty: true,
            help: "Location an Indoor Positioning beacon advertises.",
            draw: function(opts) {
                var v = opts['value'];
                var p = [];
                if ('bluetooth.adv.indoor.latitude' in v)
                    p.push(kismet.censorLocation(v['bluetooth.adv.indoor.latitude'].toFixed(6)) + ", " +
                        kismet.censorLocation(v['bluetooth.adv.indoor.longitude'].toFixed(6)));
                if ('bluetooth.adv.indoor.north_dm' in v)
                    p.push((v['bluetooth.adv.indoor.north_dm'] / 10) + " m N, " +
                        (v['bluetooth.adv.indoor.east_dm'] / 10) + " m E");
                if ('bluetooth.adv.indoor.floor' in v)
                    p.push("floor " + v['bluetooth.adv.indoor.floor']);
                if ('bluetooth.adv.indoor.altitude_dm' in v)
                    p.push((v['bluetooth.adv.indoor.altitude_dm'] / 10) + " m");
                return kismet.sanitizeHTML(p.join(", "));
            },
        },
        { field: f("uri"), title: "URI", filterOnEmpty: true, },
        { field: f("transports"), title: "Transports", filterOnEmpty: true, },
        { field: f("le_role"), title: "LE Role", filterOnEmpty: true, },
        { field: f("adv_interval_us"), title: "Advertising Interval", filterOnEmpty: true, draw: usec, },
        { field: f("conn_interval_min_us"), title: "Preferred Interval Min", filterOnEmpty: true, draw: usec, },
        { field: f("conn_interval_max_us"), title: "Preferred Interval Max", filterOnEmpty: true, draw: usec, },
        { field: f("le_features"), title: "LE Features", filterOnEmpty: true, },
        ],
    };
}
