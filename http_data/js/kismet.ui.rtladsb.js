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
                title: "Model",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtladsb.device/rtladsb.device.common/rtladsb.device.id",
                title: "Plane ICAO",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.regid",
                title: "REG ID",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.mdl",
                title: "MDL",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.atype",
                title: "Aircraft Type",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.aoperator",
                title: "Aircraft Operator",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.callsign",
                title: "Callsign",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.altitude",
                title: "Altitude",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.speed",
                title: "Speed",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.heading",
                title: "Heading",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.adsb/rtladsb.device.asgs",
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

console.log("kismet.ui.rtladsb.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});
