
"use strict";

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "Sensor Devices",
    description: "RF-based Sensors",
    priority: 100,
    defaultcolor: "#ffb3cc",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === "RFSENSOR";
    }
});

kismet_ui.AddDeviceDetail("rfsensor", "RF Sensor", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RFSENSOR");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "sensorData",
            "fields": [
            {
                field: "sensor.device/sensor.device.common/sensor.device.model",
                title: "Model",
                empty: "<i>Unknown</i>",
                help: "Device model as reported by rtl_433.",
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.id",
                title: "Device ID",
				filterOnEmpty: true,
                help: "Device ID as reported in the RF protocol, if known.",
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.snr",
                title: "SNR",
				filterOnEmpty: true,
				filterOnZero: true,
                help: "Reported signal-to-noise ratio of device when dBm is not known",
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.rssi",
                title: "RSSI",
				filterOnEmpty: true,
				filterOnZero: true,
                help: "Reported RSSI signal level of device, when signal units not known.",
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.noise",
                title: "Noise",
				filterOnEmpty: true,
				filterOnZero: true,
                help: "Reported noise level of device, when signal units not known.",
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.subchannel",
                title: "Sub-Channel",
                filterOnZero: true,
                help: "Some RF devices report an additional sub-channel for identification purposes.",
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.battery",
                title: "Battery",
                filterOnEmpty: true,
                help: "Sensor batery level, if known.",
            },
            {
                field: "sensor.device/sensor.device.thermometer",
                groupTitle: "Thermometer",
                id: "group_therm_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.thermometer/sensor.device.temperature",
                    title: "Temperature",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        return kismet_ui.renderTemperature(opts['value'], 2);
                    }
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.moisturesensor",
                groupTitle: "Moisture",
                id: "group_moisture_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.moisturesensor/sensor.device.moisture",
                    title: "Moisture (%)",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        return `${opts['value']}%`;
                    }
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.weatherstation",
                groupTitle: "Weather",
                id: "group_weather_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.wind_dir",
                    title: "Wind Direction",
                    filterOnEmpty: true,
                    draw: function(opts) {
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
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.wind_speed",
                    title: "Wind Speed",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        return kismet_ui.renderSpeed(opts['value'], 2);
                    }
                },
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.wind_gust",
                    title: "Wind Gust",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        return kismet_ui.renderSpeed(opts['value'], 2);
                    }
                },
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.rain",
                    title: "Rain",
                    filterOnEmpty: true
                },
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.rain_raw",
                    title: "Rain (Raw)",
                    filterOnEmpty: true,
                    help: "Raw sensor value for rain",
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.tpms",
                groupTitle: "Tire pressure",
                id: "group_tpms_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.tpms/sensor.device.tpms.pressure_bar",
                    title: "Pressure",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " bar";
                    },
                    help: "Reported TPMS pressure in bars",
                },
                {
                    field: "sensor.device/sensor.device.tpms/sensor.device.tpms.pressure_kpa",
                    title: "Pressure",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " kPa";
                    },
                    help: "Reported TPMS pressure in kPa",
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.switch",
                groupTitle: "Switch",
                id: "group_switch_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.switch/sensor.device.switch.1",
                    title: "Switch 1",
                    filterOnEmpty: true,
                },
                {
                    field: "sensor.device/sensor.device.switch/sensor.device.switch.2",
                    title: "Switch 2",
                    filterOnEmpty: true,
                },
                {
                    field: "sensor.device/sensor.device.switch/sensor.device.switch.3",
                    title: "Switch 3",
                    filterOnEmpty: true,
                },
                {
                    field: "sensor.device/sensor.device.switch/sensor.device.switch.4",
                    title: "Switch 4",
                    filterOnEmpty: true,
                },
                {
                    field: "sensor.device/sensor.device.switch/sensor.device.switch.5",
                    title: "Switch 5",
                    filterOnEmpty: true,
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.lightningsensor",
                groupTitle: "Lightning Sensor",
                id: "group_lightning_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.lightningsensor/sensor.device.lightning_strike_count",
                    title: "Strike Count",
                    filterOnEmpty: true,
                    help: "Last reported lighting strike count (may reset arbitrarily)"
                },
                {
                    field: "sensor.device/sensor.device.lightningsensor/sensor.device.lightning_storm_active",
                    title: "Storm Active",
                    filterOnEmpty: true,
                    help: "Storm currently active",
                    draw: function(opts) {
                        if (opts['value'])
                            return "Active";
                        return "Inactive";
                    }
                },
                {
                    field: "sensor.device/sensor.device.lightningsensor/sensor.device.lightning_rfi",
                    title: "RFI",
                    filterOnEmpty: true,
                    help: "Radio Frequency Interference from lightning activity"
                },
                {
                    field: "sensor.device/sensor.device.lightningsensor/sensor.device.lightning_storm_distance",
                    title: "Storm distance",
                    filterOnEmpty: true,
                    help: "Estimated storm distance (no distance units provided)"
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.last_record",
                title: "Last record",
                filterOnEmpty: true,
                help: "Last JSON record (for debug/devel purposes)",
            },

            ],
        });
    },
});

