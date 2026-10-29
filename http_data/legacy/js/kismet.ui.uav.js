
"use strict";

/* Open Drone ID / Remote ID enumerations (ASTM F3411) */
var remoteid_versions = ["F3411-19 (1.0)", "F3411-20 (1.1)", "F3411-22 (2.0)"];

var remoteid_ua_types = ["Undeclared", "Aeroplane", "Helicopter or multirotor",
    "Gyroplane", "Hybrid lift", "Ornithopter", "Glider", "Kite", "Free balloon",
    "Captive balloon", "Airship", "Free fall or parachute", "Rocket",
    "Tethered powered aircraft", "Ground obstacle", "Other"];

var remoteid_status = ["Undeclared", "Ground", "Airborne", "Emergency",
    "Remote ID system failure"];

var remoteid_height_types = ["Above takeoff", "Above ground"];

var remoteid_horiz_accuracy = ["Unknown", "< 18.52 km", "< 7.408 km", "< 3.704 km",
    "< 1852 m", "< 926 m", "< 555.6 m", "< 185.2 m", "< 92.6 m", "< 30 m", "< 10 m",
    "< 3 m", "< 1 m"];

var remoteid_vert_accuracy = ["Unknown", "< 150 m", "< 45 m", "< 25 m", "< 10 m",
    "< 3 m", "< 1 m"];

var remoteid_speed_accuracy = ["Unknown", "< 10 m/s", "< 3 m/s", "< 1 m/s", "< 0.3 m/s"];

var remoteid_operator_location_types = ["Takeoff", "Live GNSS", "Fixed"];

var remoteid_classification_types = ["Undeclared", "European Union"];

var remoteid_eu_categories = ["Undeclared", "Open", "Specific", "Certified"];

var remoteid_eu_classes = ["Undeclared", "Class 0", "Class 1", "Class 2", "Class 3",
    "Class 4", "Class 5", "Class 6"];

var remoteid_self_id_types = ["Text", "Emergency", "Extended status"];

var remoteid_auth_types = ["None", "UAS ID signature", "Operator ID signature",
    "Message set signature", "Network Remote ID", "Specific method"];

/* Look up an enumeration, keeping the raw value when it's out of range */
function remoteid_enum(table, value) {
    if (value >= 0 && value < table.length)
        return table[value];
    return "Unknown (" + value + ")";
}

function remoteid_enum_render(table) {
    return function(opts) {
        return remoteid_enum(table, opts['value']);
    };
}

function remoteid_height_render(opts) {
    return kismet_ui.renderHeightDistance(opts['value'], 1);
}

/* Remote ID fields are only present once a message has carried them */
function remoteid_field(name, title, extra) {
    var f = {
        field: "uav.device/uav.remoteid/uav.remoteid." + name,
        title: title,
        filterOnEmpty: true,
    };

    return Object.assign(f, extra);
}

/* Locations are 0,0 until they've been reported */
function uav_location_set(data, path) {
    var lat = kismet.ObjectByString(data, path + "/kismet.common.location.geopoint[1]");
    var lon = kismet.ObjectByString(data, path + "/kismet.common.location.geopoint[0]");

    return (typeof(lat) === 'number' && typeof(lon) === 'number' && (lat != 0 || lon != 0));
}

/* Highlight UAV devices */
kismet_ui.AddDeviceRowHighlight({
    name: "UAV/Drones",
    description: "UAV and Drone devices",
    priority: 100,
    defaultcolor: "#f49e42",
    defaultenable: true,
    fields: [
        'uav.device'
    ],
    selector: function(data) {
        return ('uav.device' in data && data['uav.device'] != 0);
    }
});

kismet_ui.AddDeviceDetail("uav", "UAV/Drone", 0, {
    filter: function(data) {
        return ('uav.device' in data && data['uav.device'] != 0);
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "uavdata",
            "fields": [
            {
                field: "uav.device/uav.manufacturer",
                title: "Manufacturer",
                empty: "<i>Unknown</i>",
                help: "The UAV manufacturer may be derived from characteristics such as MAC address and SSID, or from embedded data such as the DroneID information.",
            },
            {
                field: "uav.device/uav.model",
                title: "Model",
                filterOnEmpty: true,
                help: "The UAV model may be derived from characteristics such as MAC address and SSID, or from embedded data such as the DroneID information.",
            },
            {
                field: "uav.device/uav.serialnumber",
                title: "Serial Number",
                filterOnEmpty: true,
                help: "Serial numbers are available from UAV devices which broadcast DJI DroneID or Open Drone ID / Remote ID.",
            },
            {
                field: "uav.device/uav.match_type",
                title: "ID Method",
                empty: "<i>Unknown</i>",
                help: "Kismet can identify a UAV device by several methods; 'WifiMatch' compares the MAC address and SSID.  'DroneID' matches the DJI DroneID protocol added to packets from the device.  'Remote ID' matches the Open Drone ID / Remote ID broadcast.",
            },
            {
                field: "home_location",
                title: "Home Location",
                filter: function(opts) {
                    return uav_location_set(opts['data'], "uav.device/uav.telemetry.home_location");
                },
                render: function(opts) {
                    var loc =
                        kismet.ObjectByString(opts['data'], "uav.device/uav.telemetry.home_location/kismet.common.location.geopoint[1]") + ", " +
                        kismet.ObjectByString(opts['data'], "uav.device/uav.telemetry.home_location/kismet.common.location.geopoint[0]");

                    return loc;
                },
                help: "Last advertised <b>home</b> location.  The home location is where a UAV will return to if signal is lost or a return-to-home is received.",
            },
            {
                field: "app_location",
                title: "App Location",
                filter: function(opts) {
                    return uav_location_set(opts['data'], "uav.device/uav.telemetry.app_location");
                },
                render: function(opts) {
                    var loc =
                        kismet.ObjectByString(opts['data'], "uav.device/uav.telemetry.app_location/kismet.common.location.geopoint[1]") + ", " +
                        kismet.ObjectByString(opts['data'], "uav.device/uav.telemetry.app_location/kismet.common.location.geopoint[0]");

                    return loc;
                },
                help: "Last advertised <b>application</b> location.  This is the last-known location of the operator application.",
            },
            {
                field: "uav.device/uav.last_telemetry",
                groupTitle: "Telemetry",
                filterOnEmpty: true,
                filterOnZero: true,
                id: "last_telem",
                fields: [
                {
                    field: "uav.device/uav.last_telemetry/uav.telemetry.motor_on",
                    title: "Motor",
                    draw: function(opts) {
                        if (opts['value'])
                            return "On";
                        return "Off";
                    },
                    empty: "<i>Unknown</i>",
                    help: "The UAV device advertised that the props are currently on",
                },
                {
                    field: "uav.device/uav.last_telemetry/uav.telemetry.airborne",
                    title: "Airborne",
                    draw: function(opts) {
                        if (opts['value'])
                            return "Yes";
                        return "No";
                    },
                    empty: "<i>Unknown</i>",
                    help: "The UAV device advertised that it is airborne",
                },
                {
                    field: "uav_location",
                    title: "Last Location",
                    render: function(opts) {
                        var loc =
                            kismet.ObjectByString(opts['data'], "uav.device/uav.last_telemetry/uav.telemetry.location/kismet.common.location.geopoint[1]") + ", " +
                            kismet.ObjectByString(opts['data'], "uav.device/uav.last_telemetry/uav.telemetry.location/kismet.common.location.geopoint[0]");

                        return loc;
                    },
                    help: "Last advertised location",
                },
                {
                    field: "uav.device/uav.last_telemetry/uav.telemetry.location/kismet.common.location.alt",
                    title: "Altitude",
                    help: "Last advertised altitude",
                    filter: function(opts) {
                        return (kismet.ObjectByString(opts['data'], "uav.device/uav.last_telemetry/uav.telemetry.location/kismet.common.location.fix") >= 3);
                    },
                    draw: function(opts) {
                        return kismet_ui.renderHeightDistance(opts['value']);
                    }
                },
                {
                    field: "uav.device/uav.last_telemetry/uav.telemetry.height",
                    title: "Height",
                    draw: function(opts) {
                        return kismet_ui.renderHeightDistance(opts['value']);
                    },
                    help: "Advertised height above ground",
                },

                ],
            },
            {
                field: "uav.device/uav.remoteid",
                groupTitle: "Remote ID",
                filterOnEmpty: true,
                id: "remoteid",
                help: "Open Drone ID / Remote ID (ASTM F3411, ASD-STAN EN 4709-002) broadcast by the UAV.  Fields are only shown once the UAV has sent them.  Remote ID is not authenticated; the values are what the transmitter claims.",
                fields: [
                remoteid_field("transport", "Transport", {
                    help: "How the Remote ID broadcast was last received: Wi-Fi beacon, Wi-Fi NAN, BLE legacy or extended advertising, or Linux HCI scanning.",
                }),
                remoteid_field("protocol_version", "Protocol", {
                    draw: remoteid_enum_render(remoteid_versions),
                }),
                remoteid_field("serial_number", "Serial Number", {
                    help: "ANSI/CTA-2063-A serial number of the UA.",
                }),
                remoteid_field("registration_id", "Registration", {
                    help: "Civil aviation authority registration ID.",
                }),
                remoteid_field("utm_id", "UTM ID", {
                    help: "UUID assigned by a UTM (UAS traffic management) service.",
                }),
                remoteid_field("session_id", "Session ID", {
                    help: "Session ID, used in place of a fixed serial number by some UAs.",
                }),
                remoteid_field("ua_type", "UA Type", {
                    draw: remoteid_enum_render(remoteid_ua_types),
                }),
                remoteid_field("message_counter", "Message Counter", {
                    help: "Counter of the last Remote ID message or message pack received.",
                }),
                {
                    field: "uav.device/uav.remoteid",
                    groupTitle: "Location",
                    id: "remoteid_location",
                    filter: function(opts) {
                        return kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.status") != null;
                    },
                    fields: [
                    remoteid_field("status", "Status", {
                        draw: remoteid_enum_render(remoteid_status),
                    }),
                    remoteid_field("direction", "Direction", {
                        draw: function(opts) {
                            return opts['value'] + "&deg;";
                        },
                        help: "Direction of travel, clockwise from true north.",
                    }),
                    remoteid_field("speed_horizontal", "Ground Speed", {
                        draw: function(opts) {
                            return kismet_ui.renderSpeed(opts['value'] * 3.6, 1);
                        },
                    }),
                    remoteid_field("speed_vertical", "Vertical Speed", {
                        draw: function(opts) {
                            return kismet_ui.renderHeightDistance(opts['value'], 1) + "/s";
                        },
                        help: "Vertical speed; positive values are climbing.",
                    }),
                    remoteid_field("altitude_geo", "Geodetic Altitude", {
                        draw: remoteid_height_render,
                        help: "Altitude above the WGS-84 ellipsoid.",
                    }),
                    remoteid_field("altitude_baro", "Pressure Altitude", {
                        draw: remoteid_height_render,
                        help: "Barometric pressure altitude, referenced to standard pressure.",
                    }),
                    remoteid_field("height", "Height", {
                        draw: remoteid_height_render,
                    }),
                    remoteid_field("height_type", "Height Reference", {
                        draw: remoteid_enum_render(remoteid_height_types),
                    }),
                    remoteid_field("horiz_accuracy", "Horizontal Accuracy", {
                        draw: remoteid_enum_render(remoteid_horiz_accuracy),
                    }),
                    remoteid_field("vert_accuracy", "Vertical Accuracy", {
                        draw: remoteid_enum_render(remoteid_vert_accuracy),
                    }),
                    remoteid_field("baro_accuracy", "Pressure Altitude Accuracy", {
                        draw: remoteid_enum_render(remoteid_vert_accuracy),
                    }),
                    remoteid_field("speed_accuracy", "Speed Accuracy", {
                        draw: remoteid_enum_render(remoteid_speed_accuracy),
                    }),
                    remoteid_field("location_timestamp", "Timestamp", {
                        draw: function(opts) {
                            var m = Math.floor(opts['value'] / 60);
                            var s = opts['value'] - (m * 60);
                            return m + ":" + (s < 10 ? "0" : "") + s.toFixed(1) + " past the hour";
                        },
                        help: "Time of the location report, in minutes and seconds past the hour (UTC).",
                    }),
                    remoteid_field("timestamp_accuracy", "Timestamp Accuracy", {
                        draw: function(opts) {
                            if (opts['value'] == 0)
                                return "Unknown";
                            return (opts['value'] / 10).toFixed(1) + " s";
                        },
                    }),
                    ],
                },
                {
                    field: "uav.device/uav.remoteid",
                    groupTitle: "Operator",
                    id: "remoteid_operator",
                    filter: function(opts) {
                        var opid = kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.operator_id");

                        return kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.operator_location_type") != null ||
                            kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.self_id_type") != null ||
                            (typeof(opid) === 'string' && opid.length > 0);
                    },
                    fields: [
                    remoteid_field("operator_id", "Operator ID", {
                        help: "Operator registration ID, if the UA broadcasts one.",
                    }),
                    remoteid_field("self_id", "Description", {
                        help: "Self ID description of the flight, set by the operator.",
                    }),
                    remoteid_field("self_id_type", "Description Type", {
                        draw: remoteid_enum_render(remoteid_self_id_types),
                    }),
                    remoteid_field("operator_location_type", "Operator Location", {
                        draw: remoteid_enum_render(remoteid_operator_location_types),
                        help: "Where the operator location (shown as the App Location) comes from.  A takeoff location is also shown as the Home Location.",
                    }),
                    remoteid_field("operator_altitude", "Operator Altitude", {
                        draw: remoteid_height_render,
                    }),
                    remoteid_field("classification_type", "Classification", {
                        draw: remoteid_enum_render(remoteid_classification_types),
                    }),
                    remoteid_field("eu_category", "EU Category", {
                        filter: function(opts) {
                            return kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.classification_type") == 1;
                        },
                        draw: remoteid_enum_render(remoteid_eu_categories),
                    }),
                    remoteid_field("eu_class", "EU Class", {
                        filter: function(opts) {
                            return kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.classification_type") == 1;
                        },
                        draw: remoteid_enum_render(remoteid_eu_classes),
                    }),
                    remoteid_field("area_count", "Area Aircraft", {
                        help: "Number of aircraft in the operating area.",
                    }),
                    remoteid_field("area_radius", "Area Radius", {
                        draw: remoteid_height_render,
                    }),
                    remoteid_field("area_ceiling", "Area Ceiling", {
                        draw: remoteid_height_render,
                    }),
                    remoteid_field("area_floor", "Area Floor", {
                        draw: remoteid_height_render,
                    }),
                    remoteid_field("system_timestamp", "System Timestamp", {
                        draw: kismet_ui.RenderTrimmedTime,
                    }),
                    ],
                },
                {
                    field: "uav.device/uav.remoteid",
                    groupTitle: "Authentication",
                    id: "remoteid_auth",
                    filter: function(opts) {
                        return kismet.ObjectByString(opts['data'], "uav.device/uav.remoteid/uav.remoteid.auth_type") != null;
                    },
                    help: "Authentication data is reassembled from its pages and shown as sent; Kismet does not verify it.",
                    fields: [
                    remoteid_field("auth_type", "Type", {
                        draw: remoteid_enum_render(remoteid_auth_types),
                    }),
                    remoteid_field("auth_timestamp", "Timestamp", {
                        draw: kismet_ui.RenderTrimmedTime,
                    }),
                    remoteid_field("auth_data", "Data", {
                        draw: function(opts) {
                            return '<span style="word-break: break-all;">' + opts['value'] + '</span>';
                        },
                    }),
                    ],
                },
                ],
            }

            ],
        });
    },
});

