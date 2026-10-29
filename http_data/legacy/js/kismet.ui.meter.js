
"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'METER') {
        return '<i class="fa fa-house-chimney-user"></i>';
    }
});

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "RF Meter Devices",
    description: "RF Power, Water, Gas Meters",
    priority: 100,
    defaultcolor: "#b3ffe6",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
		return 'meter.device' in data;
    }
});

kismet_ui.AddDeviceDetail("rfmeter", "Meter (SDR)", 0, {
    filter: function(data) {
		return 'meter.device' in data;
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "meterData",
            "fields": [
            {
                field: "meter.device/meter.device.meter_id",
                title: "Meter ID",
                empty: "<i>Unknown</i>",
            },
            {
                field: "meter.device/meter.device.meter_type",
                title: "Meter Type",
                empty: "<i>Unknown</i>",
				help: "Type of meter (eletrical, gas, or water)",
            },
            {
                field: "meter.device/meter.device.model_vec",
                title: "Models",
                empty: "<i>Unknown</i>",
                help: "Meters may be decoded as multiple models.",
                draw: function(opts) {
                    var models = "";
                    data['meter.device']['meter.device.model_vec'].forEach(m => {
                        models = `${models}${m}<br>`
                    });

                    return models;
                },
            },
            {
                field: "meter.device/meter.device.consumption",
                title: "Consumption",
                empty: "<i>Unknown</i>",
				help: "Consumption rate (units may vary per meter type)",
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
                        kismet.RecalcRrdData2(data['meter.device']['meter.device.consumption_rrd'], kismet.RRD_SECOND, {transform: kismet.RrdDelta});


                    m.sparkline(t_m, 
                        { type: "bar",
                            height: 14,
                            barWidth: 2,
                            barColor: kismet_theme.sparkline_main,
                            nullColor: kismet_theme.sparkline_main,
                            zeroColor: kismet_theme.sparkline_main,
                        });

                    var t_h =
                        kismet.RecalcRrdData2(data['meter.device']['meter.device.consumption_rrd'], kismet.RRD_MINUTE, {transform: kismet.RrdDelta});


                    h.sparkline(t_h, 
                        { type: "bar",
                            height: 14,
                            barWidth: 2,
                            barColor: kismet_theme.sparkline_main,
                            nullColor: kismet_theme.sparkline_main,
                            zeroColor: kismet_theme.sparkline_main,
                        });

                    var t_d =
                        kismet.RecalcRrdData2(data['meter.device']['meter.device.consumption_rrd'], kismet.RRD_HOUR, {transform: kismet.RrdDelta});



                    d.sparkline(t_d, 
                        { type: "bar",
                            height: 14,
                            barWidth: 2,
                            barColor: kismet_theme.sparkline_main,
                            nullColor: kismet_theme.sparkline_main,
                            zeroColor: kismet_theme.sparkline_main,
                        });
                },
                liveupdate: true,
            },
            ],
        });
    },
});

