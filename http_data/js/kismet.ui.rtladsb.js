(
  typeof define === "function" ? function (m) { define("kismet-ui-rtladsb-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_rtladsb = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "RTLadsb Devices",
    description: "RTLadsb Sensor",
    priority: 50,
    //defaultcolor: "#efe0c3",
    defaultcolor: "#ffb3b3",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname',
        'rtladsb.device'
    ],
    selector: function(data) {
        var aircraft_names = [
            '^police$',
            '^depart$',
            ];

        if (data['kismet.device.base.phyname'] === 'RTLADSB') {
            for (var re of aircraft_names) {
		 if (data['rtladsb.device']['rtladsb.device.adsb']['rtladsb.device.aoperator'].match(new RegExp(re, 'i')) != null)
                    return true;
            }
        } 

        //return data['kismet.device.base.phyname'] === "RTLADSB";
    }
});

kismet_ui.AddDeviceDetail("rtladsb", "RTLADSB (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RTLADSB");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "rtladsbData",
            "fields": [
            {
                field: "rtladsb.device/rtladsb.device.common/rtladsb.device.model",
                liveupdate: true,
                title: "Model",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtladsb.device/rtladsb.device.common/rtladsb.device.id",
                liveupdate: true,
                title: "Plane ICAO",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.regid",
                liveupdate: true,
                title: "REG ID",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.mdl",
                liveupdate: true,
                title: "MDL",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.atype",
                liveupdate: true,
                title: "Aircraft Type",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.aoperator",
                liveupdate: true,
                title: "Aircraft Operator",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.callsign",
                liveupdate: true,
                title: "Callsign",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.callsign",
                id: "fa_callsign",
                liveupdate: true,
                title: "Flightaware",
                filterOnZero: true,
                filterOnEmpty: true,
                draw: function(opts) {
                    return '<a href="https://flightaware.com/live/flight/' + opts['value'] + '" target="_new">Track ' + opts['value'] + ' on FlightAware</a>';
                },
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.altitude",
                liveupdate: true,
                title: "Altitude",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.speed",
                liveupdate: true,
                title: "Speed",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.heading",
                liveupdate: true,
                title: "Heading",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.asgs",
                liveupdate: true,
                title: "Airspeed(AS) / Groundspeed (GS)",
                filterOnZero: true,
            },
            //{
            //    field: "rtladsb.device/rtladsb.device.powermeter",
            //    groupTitle: "Powermeter",
            //    id: "group_power_data",
            //    filterOnEmpty: true,
            //    fields: [
            //    {
            //        field: "rtladsb.device/rtladsb.device.powermeter/rtladsb.device.consumption",
            //        title: "Consumption",
            //        filterOnEmpty: true,
            //        render: function(opts) {
            //            return kismet_ui.renderConsumption(opts['value'], 2);
            //        }
            //    },
            //    ]
            //},

            ],
        });
    },
});

// We're done loading
exports.load_complete = 1;

return exports;

});
