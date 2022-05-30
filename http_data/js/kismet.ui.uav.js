
"use strict";

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
                help: "Serial numbers are available from UAV devices which broadcast the DroneID protocol.  Currently only DJI devices advertise this protocol.",
            },
            {
                field: "uav.device/uav.match_type",
                title: "ID Method",
                empty: "<i>Unknown</i>",
                help: "Kismet can identify a UAV device by several methods; 'WifiMatch' compares the MAC address and SSID.  'DroneID' matches the DJI DroneID protocol added to packets from the device.",
            },
            {
                field: "home_location",
                title: "Home Location",
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
                    render: function(opts) {
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
                    render: function(opts) {
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
                    render: function(opts) {
                        console.log(opts['value']);
                        return kismet_ui.renderHeightDistance(opts['value']);
                    }
                },
                {
                    field: "uav.device/uav.last_telemetry/uav.telemetry.height",
                    title: "Height",
                    render: function(opts) {
                        console.log(opts['value']);
                        return kismet_ui.renderHeightDistance(opts['value']);
                    },
                    help: "Advertised height above ground",
                },

                ],
            }

            ],
        });
    },
});

