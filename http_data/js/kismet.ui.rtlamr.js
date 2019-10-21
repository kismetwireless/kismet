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
                field: "rtlamr.device/rtlamr.device.meter_id",
                title: "Meter ID",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtlamr.device/rtlamr.device.meter_type",
                title: "Meter Type",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtlamr.device/rtlamr.device.consumption",
                title: "Consumption",
                empty: "<i>Unknown</i>"
            },
            ],
        });
    },
});

// We're done loading
exports.load_complete = 1;

return exports;

});
