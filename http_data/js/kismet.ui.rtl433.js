
"use strict";

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "RTL433 Devices",
    description: "RTL433 Sensor",
    priority: 100,
    defaultcolor: "#ffb3cc",
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
            {
                field: "rtl433.device/rtl433.device.tpms",
                groupTitle: "Tire pressure",
                id: "group_tpms_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433.device/rtl433.device.tpms/rtl433.device.tpms.pressure_bar",
                    title: "Pressure",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " bar";
                    },
                    help: "Reported TPMS pressure in bars",
                },
                {
                    field: "rtl433.device/rtl433.device.tpms/rtl433.device.tpms.pressure_kpa",
                    title: "Pressure",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " kPa";
                    },
                    help: "Reported TPMS pressure in kPa",
                },
                ]
            },
            {
                field: "rtl433.device/rtl433.device.switch",
                groupTitle: "Switch",
                id: "group_switch_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433.device/rtl433.device.switch/rtl433.device.switch.1",
                    title: "Switch 1",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return opts['value'];
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.switch/rtl433.device.switch.2",
                    title: "Switch 2",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return opts['value'];
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.switch/rtl433.device.switch.3",
                    title: "Switch 3",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return opts['value'];
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.switch/rtl433.device.switch.4",
                    title: "Switch 4",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return opts['value'];
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.switch/rtl433.device.switch.5",
                    title: "Switch 5",
                    filterOnEmpty: true,
                    render: function(opts) {
                        return opts['value'];
                    }
                },
                ]
            },
            {
                field: "rtl433.device/rtl433.device.lightningsensor",
                groupTitle: "Lightning Sensor",
                id: "group_lightning_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "rtl433.device/rtl433.device.lightningsensor/rtl433.device.lightning_strike_count",
                    title: "Strike Count",
                    filterOnEmpty: true,
                    help: "Last reported lighting strike count (may reset arbitrarily)"
                },
                {
                    field: "rtl433.device/rtl433.device.lightningsensor/rtl433.device.lightning_storm_active",
                    title: "Storm Active",
                    filterOnEmpty: true,
                    help: "Storm currently active",
                    render: function(opts) {
                        if (opts['value'])
                            return "Active";
                        return "Inactive";
                    }
                },
                {
                    field: "rtl433.device/rtl433.device.lightningsensor/rtl433.device.lightning_rfi",
                    title: "RFI",
                    filterOnEmpty: true,
                    help: "Radio Frequency Interference from lightning activity"
                },
                {
                    field: "rtl433.device/rtl433.device.lightningsensor/rtl433.device.lightning_storm_distance",
                    title: "Storm distance",
                    filterOnEmpty: true,
                    help: "Estimated storm distance (no distance units provided)"
                },
                ]
            },

            ],
        });
    },
});

