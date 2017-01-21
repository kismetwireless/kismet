(
  typeof define === "function" ? function (m) { define("kismet-ui-rtl433-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_rtl433 = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

kismet_ui.AddDeviceDetail("rtl433", "RTL-433 (SDR)", 0, {
    filter: function(data) {
        return (data['kismet_device_base_phyname'] === "RTL433");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "rtl433Data",
            "fields": [
            {
                field: "rtl433_device.rtl433_device_common.rtl433_device_model",
                title: "Model",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtl433_device.rtl433_device_common.rtl433_device_id",
                title: "Device ID",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtl433_device.rtl433_device_common.rtl433_device_rtlchannel",
                title: "Channel",
                filterOnZero: true,
            },
            {
                field: "rtl433_device.rtl433_device_common.rtl433_device_battery",
                title: "Battery",
                filterOnEmpty: true,
            },
            {
                field: "rtl433_device.rtl433_device_thermometer",
                groupTitle: "Thermometer",
                id: "group_therm_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433_device.rtl433_device_thermometer.rtl433_device_temperature",
                    title: "Temperature",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return kismet_ui_base.renderTemperature(opts['value']);
                    }
                },
                {
                    field: "rtl433_device.rtl433_device_thermometer.rtl433_device_humidity",
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
                field: "rtl433_device.rtl433_device_weatherstation",
                groupTitle: "Weather",
                id: "group_weather_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433_device.rtl433_device_weatherstation.rtl433_device_wind_dir",
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
                    field: "rtl433_device.rtl433_device_weatherstation.rtl433_device_wind_speed",
                    title: "Wind Speed",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return kismet_ui_base.renderSpeed(opts['value']);
                    }
                },
                {
                    field: "rtl433_device.rtl433_device_weatherstation.rtl433_device_wind_gust",
                    title: "Wind Gust",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return kismet_ui_base.renderSpeed(opts['value']);
                    }
                },
                {
                    field: "rtl433_device.rtl433_device_weatherstation.rtl433_device_rain",
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
