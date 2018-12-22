(
  typeof define === "function" ? function (m) { define("kismet-ui-rtlamr-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_rtlamr = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "RTLamr Devices",
    description: "RTLamr Sensor",
    priority: 100,
    defaultcolor: "#b3ffe6",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === "RTLAMR";
    }
});

kismet_ui.AddDeviceDetail("rtlamr", "RTLAMR (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RTLAMR");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "rtlamrData",
            "fields": [
            {
                field: "rtlamr.device/rtlamr.device.common/rtlamr.device.model",
                title: "Model",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtlamr.device/rtlamr.device.common/rtlamr.device.id",
                title: "Device ID",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtlamr.device/rtlamr.device.powermeter/rtlamr.device.consumption",
                title: "Current Reading",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtlamr.device/rtlamr.device.common/rtlamr.device.rtlchannel",
                title: "Channel",
                filterOnZero: true,
            },
            //{
            //    field: "rtlamr.device/rtlamr.device.powermeter",
            //    groupTitle: "Powermeter",
            //    id: "group_power_data",
            //    filterOnEmpty: true,
            //    fields: [
            //    {
            //        field: "rtlamr.device/rtlamr.device.powermeter/rtlamr.device.consumption",
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

console.log("kismet.ui.rtlamr.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});
