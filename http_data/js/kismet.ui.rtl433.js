(
  typeof define === "function" ? function (m) { define("kismet-ui-rtl433-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_rtl433 = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "WPA Handshake",
    description: "A possibly complete WPA handshake has been captured",
    priority: 10,
    defaultcolor: "yellow",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === "RTL433";
    }
});

kismet_ui.AddDeviceDetail("rtl433", "RTL-433 (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RTL433");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "rtl433Data",
            "fields": [
            {
                field: "rtl433.device/rtl433.device.common/rtl433.device.model",
                title: "Model",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtl433.device/rtl433.device.common/rtl433.device.id",
                title: "Device ID",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtl433.device/rtl433.device.common/rtl433.device.rtlchannel",
                title: "Channel",
                filterOnZero: true,
            },
            {
                field: "rtl433.device/rtl433.device.common/rtl433.device.battery",
                title: "Battery",
                filterOnEmpty: true,
            },
            {
                field: "rtl433.device/rtl433.device.thermometer",
                groupTitle: "Thermometer",
                id: "group_therm_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433.device/rtl433.device.thermometer/rtl433.device.temperature",
                    title: "Temperature",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return kismet_ui.renderTemperature(opts['value'], 2);
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.thermometer/rtl433.device.humidity",
                    title: "Humidity (%)",
                    filterOnEmpty: true,
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + "%";
                    }
                },
                ]
            },
            {
                field: "rtl433.device/rtl433.device.weatherstation",
                groupTitle: "Weather",
                id: "group_weather_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433.device/rtl433.device.weatherstation/rtl433.device.wind_dir",
                    title: "Wind Direction",
                    filterOnEmpty: true,
                    render: function(opts) {
                        var rv = opts['value'] + "&deg; (" + 
                            kismet_ui.DegToDir(opts['value']) + ")";

                        /*
                        rv += '<br>';

                        rv += '<span class="fa-stack" style="font-size: 16pt;">';
                        rv += '<i class="fa fa-stack-1x fa-circle-o" />';
                        rv += '<i class="fa fa-stack-1x fa-chevron-up" style="' +
                            '-ms-transform: rotate(' + opts['value'] + 'deg);' +
                            '-webkit-transform: rotate(' + opts['value'] + 'deg);' +
                            'transform: rotate(' + opts['value'] + 'deg);' +
                            '" />';
                        rv += '</span>';
                        */

                        return rv;
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.weatherstation/rtl433.device.wind_speed",
                    title: "Wind Speed",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return kismet_ui.renderSpeed(opts['value'], 2);
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.weatherstation/rtl433.device.wind_gust",
                    title: "Wind Gust",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return kismet_ui.renderSpeed(opts['value'], 2);
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.weatherstation/rtl433.device.rain",
                    title: "Rain",
                    filterOnEmpty: true
                },
                ]
            },

            ],
        });
    },
});

console.log("kismet.ui.rtl433.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});
