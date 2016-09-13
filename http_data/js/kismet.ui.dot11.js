(
  typeof define === "function" ? function (m) { define("kismet-ui-dot11-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_dot11 = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

/* Define some callback functions for the table */

console.log("adding device detail 'dot11'");
kismet_ui.AddDeviceDetail("dot11", "802.11 Wi-Fi", 0, {
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "dot11DeviceData",
            "fields": [
            {
                field: "dot11_device.dot11_device_last_beaconed_ssid",
                title: "Last Beaconed SSID (AP)",
                empty: "<i>None</i>"
            },
            {
                field: "dot11_device.dot11_device_last_probed_ssid",
                title: "Last Probed SSID (Client)",
                empty: "<i>None</i>"
            },
            {
                field: "dot11_device.dot11_device_num_fragments",
                title: "Fragmented Packets"
            },
            {
                field: "dot11_device.dot11_device_num_retries",
                title: "Retried Packets"
            },
            {
                field: "dot11_device.dot11_device_datasize",
                title: "Data Transferred",
                render: function(key, data, value) {
                    return kismet.HumanReadableSize(value);
                }
            },
            {
                field: "dot11_device.dot11_device_datasize_retry",
                title: "Data Transferred (Retry)",
                render: function(key, data, value) {
                    return kismet.HumanReadableSize(value);
                }
            }
            ]
        });
    }
});

console.log("kismet.ui.dot11.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});


