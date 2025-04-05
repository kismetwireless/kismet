
"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'RFSENSOR') {
        return '<i class="fa fa-gauge-high"></i>';
    }
});

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
                help: "Sensor battery data.  Different vendors use different indicators, this value may be a string such as 'OK' or may be a numerical value for presence or charge.",
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
                    liveupdate: true,
                    help: "Temperature (localized to preferred units whenever possible) reported by the sensor, as well as the past minute, hour, and day of temperature readings.  Not all sensors report temperature regularly, so the past minute of data may sometimes be empty.",
                    render: function(opts) {
                        var d =
                            '<span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(kismet_ui.renderTemperature(opts['value'], 2));


                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.thermometer']['sensor.device.temperature_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.thermometer']['sensor.device.temperature_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.thermometer']['sensor.device.temperature_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
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
                    help: "Moisture or humidity, most often in a percentage, as reported by the sensor, as well as the past minute, hour, and day of moisture readings.  Not all sensors report moisture regularly, so the past minute of data may sometimes be empty.",
                    liveupdate: true,
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 1.5em;">M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(`${opts['value']}%`);


                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.moisturesensor']['sensor.device.moisture_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.moisturesensor']['sensor.device.moisture_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.moisturesensor']['sensor.device.moisture_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
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
                    filterOnZero: true,
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
                    filterOnZero: true,
                    help: "Wind speed",
                    liveupdate: true,
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 1.5em;">M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(`${kismet_ui.renderSpeed(opts['value'], 2)}`);

                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.wind_speed_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.wind_speed_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.wind_speed_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
                },
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.wind_gust",
                    title: "Wind Gust",
                    filterOnEmpty: true,
                    filterOnZero: true,
                    help: "Wind speed (max/gust)",
                    liveupdate: true,
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 1.5em;">M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(`${kismet_ui.renderSpeed(opts['value'], 2)}`);

                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.wind_gust_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});

                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.wind_gust_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.wind_gust_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
                },
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.rain",
                    title: "Rain",
                    filterOnEmpty: true,
                    filterOnZero: true,
                    liveupdate: true,
                    help: "Rain quantity (often in mm)",
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 2em;">&Delta;M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 2em;">&Delta;H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 2em;">&Delta;D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(opts['value']);


                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.rain_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDelta});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.rain_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDelta});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.weatherstation']['sensor.device.rain_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDelta});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
                },
                {
                    field: "sensor.device/sensor.device.weatherstation/sensor.device.rain_raw",
                    title: "Rain (Raw)",
                    filterOnEmpty: true,
                    filterOnZero: true,
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
                {
                    field: "sensor.device/sensor.device.tpms/sensor.device.tpms.pressure_psi",
                    title: "Pressure",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " PSI";
                    },
                    help: "Reported TPMS pressure in PSI",
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
                    liveupdate: true,
                    help: "Last reported lighting strike count (may reset arbitrarily)",
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 2em;">&Delta;M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 2em;">&Delta;H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 2em;">&Delta;D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(opts['value']);


                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.lightningsensor']['sensor.device.lightning_strike_count_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDelta});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.lightningsensor']['sensor.device.lightning_strike_count_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDelta});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.lightningsensor']['sensor.device.lightning_strike_count_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDelta});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
                },
                {
                    field: "sensor.device/sensor.device.lightningsensor/sensor.device.lightning_storm_active",
                    title: "Storm Active",
                    filterOnEmpty: true,
                    liveupdate: true,
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
                    liveupdate: true,
                    filterOnEmpty: true,
                    help: "Radio Frequency Interference detected, often from other electronic devices."
                },
                {
                    field: "sensor.device/sensor.device.lightningsensor/sensor.device.lightning_storm_distance",
                    title: "Storm distance",
                    filterOnEmpty: true,
                    liveupdate: true,
                    help: "Estimated storm distance (no distance units provided)"
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.aqi",
                groupTitle: "Air Quality",
                id: "group_aqi_data",
                filterOnEmpty: true,
                fields: [
                {
                    field: "sensor.device/sensor.device.aqi/sensor.device.pm2_5",
                    title: "PM2.5",
                    filterOnEmpty: true,
                    help: "Estimated PM2.5 particulate matter",
                    liveupdate: true,
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 1.5em;">M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(`${opts['value']}`);


                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.aqi']['sensor.device.pm2_5_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.aqi']['sensor.device.pm2_5_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.aqi']['sensor.device.pm2_5_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
                },
                {
                    field: "sensor.device/sensor.device.aqi/sensor.device.pm10",
                    title: "PM10",
                    filterOnEmpty: true,
                    help: "Estimated PM2.5 particulate matter",
                    liveupdate: true,
                    render: function(opts) {
                        var d =
                            "<span></span><br>" +
                            '<span style="display: inline-block; width: 1.5em;">M:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">H:</span> <span></span><br>' +
                            '<span style="display: inline-block; width: 1.5em;">D:</span> <span></span><br>';

                        return d;
                    },
                    draw: function(opts) {
                        var t = $('span:eq(0)', opts['container']);
                        var m = $('span:eq(2)', opts['container']);
                        var h = $('span:eq(4)', opts['container']);
                        var d = $('span:eq(6)', opts['container']);

                        t.html(`${opts['value']}`);


                        var t_m =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.aqi']['sensor.device.pm10_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        m.sparkline(t_m,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_h =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.aqi']['sensor.device.pm10_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        h.sparkline(t_h,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });

                        var t_d =
                            kismet.RecalcRrdData2(data['sensor.device']['sensor.device.aqi']['sensor.device.pm10_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDrag, transformopt: {backfill: true}});


                        d.sparkline(t_d,
                            { type: "bar",
                                height: 14,
                                barWidth: 2,
                                chartRangeMin: 0,
                                barColor: kismet_theme.sparkline_main,
                                nullColor: kismet_theme.sparkline_main,
                                zeroColor: kismet_theme.sparkline_main,
                            });
                    },
                },
                ]
            },
            {
                field: "sensor.device/sensor.device.common/sensor.device.last_record",
                liveupdate: true,
                title: "Last record",
                filterOnEmpty: true,
                help: "Last JSON record (for debug/devel purposes)",
            },

            ],
        });
    },
});

