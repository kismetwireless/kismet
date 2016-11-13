// Display the channel records system from Ksimet
// 
// dragorn@kismetwireless.net
// MIT/GPL License (pick one); the web ui code is licensed more
// freely than GPL to reflect the generally MIT-licensed nature
// of the web/jquery environment
//


(function($) {
    var element = null;

    var base_options = {

    };

    var options = base_options;

    var timerid = -1;

    var devgraph_chart = null;
    var timegraph_chart = null;

    var devgraph_canvas = null;
    var timegraph_canvas = null;

    var picker = null;
    var graphtype = null;
    var coming_soon = null;

    var visible = false;

    var channeldisplay_refresh = function() {
        clearTimeout(timerid);

        if (element.is(':hidden')) {
            timerid = -1;
            return;
        }

        $.get("/channels/channels.json")
        .done(function(data) {
            var devtitles = new Array();
            var devnums = new Array();

            // Chart type from radio buttons
            var charttype = $("input[name='graphtype']:checked", graphtype).val();
            // Chart timeline from selector
            var charttime = $('select#historyrange option:selected', element).val();
            // Frequency translation from selector
            var freqtrans = $('select#k_cd_freq_selector option:selected', element).val();

            // historical line chart
            if (charttype === 'history') {
                var pointtitles = new Array();
                var datasets = new Array();
                var title = "";

                var rrd_type = kismet.RRD_SECOND;
                var rrd_data = null;

                if (charttime === 'min') {
                    title = "Past Minute";

                    for (var x = 0; x < 60; x++) {
                        if (x % 5 == 0) {
                            pointtitles.push(x);
                        } else {
                            pointtitles.push(' ');
                        }
                    }

                    rrd_type = kismet.RRD_SECOND;
                    rrd_data = "kismet_channelrec_device_rrd.kismet_common_rrd_minute_vec";

                } else if (charttime === 'hour') {
                    title = "Past Hour";

                    for (var x = 0; x < 60; x++) {
                        if (x % 5 == 0) {
                            pointtitles.push(x);
                        } else {
                            pointtitles.push(' ');
                        }
                    }

                    rrd_type = kismet.RRD_MINUTE;
                    rrd_data = "kismet_channelrec_device_rrd.kismet_common_rrd_hour_vec";

                } else /* day */ {
                    title = "Past Day";

                    for (var x = 0; x < 24; x++) {
                        pointtitles.push(x);
                    }

                    rrd_type = kismet.RRD_HOUR;
                    rrd_data = "kismet_channelrec_device_rrd.kismet_common_rrd_day_vec";

                }

                // Position in the color map
                var colorpos = 0;
                var nkeys = Object.keys(data['kismet_channeltracker_frequency_map']).length;
                for (var fk in data['kismet_channeltracker_frequency_map']) {
                    var linedata = 
                        kismet.RecalcRrdData(
                            data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_device_rrd']['kismet_common_rrd_last_time'], 
                            last_devicelist_time, 
                            rrd_type,
                            kismet.ObjectByString(
                                data['kismet_channeltracker_frequency_map'][fk], 
                                rrd_data),
                            {});

                    // Convert the freq name
                    var cfk = kismet_ui.GetConvertedChannel(freqtrans, fk);

                    var label = "";

                    if (cfk == fk) 
                        label = kismet.HumanReadableFrequency(parseInt(fk));
                    else
                        label = cfk;

                    // Rotate through the color wheel
                    var color = 255 * (colorpos / nkeys);
                    colorpos++;

                    // Build the dataset record
                    var ds = {
                        label:  label,
                        fill: false,
                        lineTension: 0.1,
                        data: linedata,
                        borderColor: "hsl(" + color + ", 100%, 50%)",
                    };

                    // Add it to the dataset
                    datasets.push(ds);
                }

                devgraph_canvas.hide();
                timegraph_canvas.show();
                coming_soon.hide();

                if (timegraph_chart == null) {
                    var device_options = {
                        type: "line",
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                yAxes: [{
                                    ticks: {
                                        beginAtZero: true,
                                    }
                                }],
                            },
                        },
                        data: {
                            labels: pointtitles,
                            datasets: datasets,
                        }
                    };

                    timegraph_chart = new Chart(timegraph_canvas, 
                        device_options);
                } else {
                    timegraph_chart.data.datasets = datasets;
                    timegraph_chart.data.labels = pointtitles;

                    timegraph_chart.update(0);
                }
            } else {
                // 'now', but default - if for some reason we didn't get a
                // value from the selector, this falls through to the bar graph
                // which is what we probably really want
                for (var fk in data['kismet_channeltracker_frequency_map']) {
                    var slot_now =
                        (data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_device_rrd']['kismet_common_rrd_last_time']) % 60;
                    var dev_now = data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_device_rrd']['kismet_common_rrd_minute_vec'][slot_now];

                    var cfk = kismet_ui.GetConvertedChannel(freqtrans, fk);

                    if (cfk == fk) 
                        devtitles.push(kismet.HumanReadableFrequency(parseInt(fk)));
                    else
                        devtitles.push(cfk);

                    devnums.push(dev_now);
                }

                devgraph_canvas.show();
                timegraph_canvas.hide();

                if (devgraph_chart == null) {
                    coming_soon.hide();

                    var device_options = {
                        type: "bar",
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                yAxes: [{
                                    ticks: {
                                        beginAtZero: true,
                                    }
                                }],
                            },
                        },
                        data: {
                            labels: devtitles,
                            datasets: [
                                {
                                    label: "Devices per Channel",
                                    backgroundColor: 'rgba(160, 160, 160, 1)',
                                    data: devnums,
                                    borderWidth: 1,
                                }
                            ],
                        }
                    };

                    devgraph_chart = new Chart(devgraph_canvas, 
                        device_options);

                } else {
                    devgraph_chart.data.datasets[0].data = devnums;
                    devgraph_chart.data.labels = devtitles;

                    devgraph_chart.update();
                }
            }

            timerid = setTimeout(channeldisplay_refresh, 5000);
        });
    };

    $.fn.channels = function(data, inopt) {
        element = $(this);

        visible = element.is(":visible");

        if (typeof(inopt) === "string") {

        } else {
            options = $.extend(base_options, inopt);
        }

        if (graphtype == null) {
            graphtype = $('<div>', {
                "id": "graphtype",
                "class": "k_cd_type",
            })
            .append(
                $('<label>', {
                    for: "gt_bar",
                })
                .text("Current")
            )
            .append($('<input>', {
                type: "radio",
                id: "gt_bar",
                name: "graphtype",
                value: "now",
                checked: "checked"
                })
            )
            .append(
                $('<label>', {
                    for: "gt_line",
                })
                .text("Historical")
            )
            .append($('<input>', {
                type: "radio",
                name: "graphtype",
                value: "history"
            })
            )
            .append(
                $('<select>', {
                    id: "historyrange",
                    class: "k_cd_hr_list"
                })
                .append(
                    $('<option>', {
                        value: "min",
                    })
                    .text("Past Minute")
                )
                .append(
                    $('<option>', {
                        value: "hour",
                    })
                    .text("Past Hour")
                )
                .append(
                    $('<option>', {
                        value: "day",
                    })
                    .text("Past Day")
                )
                .hide()
            );

            element.append(graphtype);

            graphtype.on('change', function() {
                var gt = $("input[name='graphtype']:checked", graphtype). val();
                console.log("changed graph type " + gt);

                if (gt === 'now') {
                    $("select#historyrange", graphtype).hide();
                } else {
                    $("select#historyrange", graphtype).show();
                }

                channeldisplay_refresh();
            });

        }

        if (picker == null) {
            picker = $('<div>', {
                id: "picker",
                class: "k_cd_picker",
            });

            var sel = $('<select>', {
                id: "k_cd_freq_selector",
                class: "k_cd_list",
            });

            picker.append(sel);

            var chlist = new Array();
            chlist.push("Frequency");

            chlist = chlist.concat(kismet_ui.GetChannelListKeys());

            for (var c in chlist) {
                var e = $('<option>', {
                    value: chlist[c], 
                });
                e.html(chlist[c]);

                sel.append(e);
            }

            element.append(picker);

            picker.on('change', function() {
                channeldisplay_refresh();
            });

        }

        devgraph_canvas = $('<canvas>', {
            class: "k_cd_dg",
            width: "100%",
            height: "100%",
        });

        element.append(devgraph_canvas);

        timegraph_canvas = $('<canvas>', {
            class: "k_cd_dg",
            width: "100%",
            height: "100%"
        });

        timegraph_canvas.hide();
        element.append(timegraph_canvas);

        // Add a 'coming soon' item
        if (coming_soon == null)  {
            coming_soon = $('<i>', {
                "id": "coming_soon",
            });
            coming_soon.html("Channel data loading...");
            element.append(coming_soon);
        }

        // Hook an observer to see when we become visible
        var observer = new MutationObserver(function(mutations) {
            if (element.is(":hidden") && timerid >= 0) {
                visible = false;
                clearTimeout(timerid);
            } else if (element.is(":visible") && !visible) {
                visible = true;
                channeldisplay_refresh();
            }
        });

        observer.observe(element[0], {
            attributes: true
        });

        if (visible) {
            channeldisplay_refresh();
        }

    };

}(jQuery));

