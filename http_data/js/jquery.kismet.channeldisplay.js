// Display the channel records system from Kismet
//
// Requires js-storage and jquery be loaded first
//
// dragorn@kismetwireless.net
// MIT/GPL License (pick one); the web ui code is licensed more
// freely than GPL to reflect the generally MIT-licensed nature
// of the web/jquery environment
//


(function($) {
    var local_uri_prefix = "";
    if (typeof(KISMET_URI_PREFIX) !== 'undefined')
        local_uri_prefix = KISMET_URI_PREFIX;

    var base_options = {
        url: ""
    };

    var channeldisplay_refresh = function(state) {
        clearTimeout(state.timerid);

        if (!kismet_ui.window_visible || state.element.is(':hidden')) {
            state.timerid = -1;
            return;
        }

        $.get(local_uri_prefix + state.options.url + "channels/channels.json")
        .done(function(data) {
            data = kismet.sanitizeObject(data);

            var devtitles = new Array();
            var devnums = new Array();

            // Chart type from radio buttons
            var charttype = $("input[name='graphtype']:checked", state.graphtype).val();
            // Chart timeline from selector
            var charttime = $('select#historyrange option:selected', state.element).val();
            // Frequency translation from selector
            var freqtrans = $('select#k_cd_freq_selector option:selected', state.element).val();
            // Pull from the stored value instead of the live
            var filter_string = state.storage.get('jquery.kismet.channels.filter');

            // historical line chart
            if (charttype === 'history') {
                var pointtitles = new Array();
                var datasets = new Array();
                var title = "";

                var rrd_data = null;

                if (charttime === 'min') {

                    for (var x = 60; x > 0; x--) {
                        if (x % 5 == 0) {
                            pointtitles.push(x);
                        } else {
                            pointtitles.push('');
                        }
                    }

                    rrd_type = kismet.RRD_SECOND;
                    rrd_data = "kismet.channelrec.device_rrd/kismet.common.rrd.minute_vec";
                } else if (charttime === 'hour') {

                    for (var x = 60; x > 0; x--) {
                        if (x % 5 == 0) {
                            pointtitles.push(x);
                        } else {
                            pointtitles.push('');
                        }
                    }

                    rrd_type = kismet.RRD_MINUTE;
                    rrd_data = "kismet.channelrec.device_rrd/kismet.common.rrd.hour_vec";

                } else /* day */ {

                    for (var x = 24; x > 0; x--) {
                        if (x % 4 == 0) {
                            pointtitles.push(x);
                        } else {
                            pointtitles.push('');
                        }
                    }

                    rrd_type = kismet.RRD_HOUR;
                    rrd_data = "kismet.channelrec.device.rrd/kismet.common.rrd.day_vec";

                }

                // Position in the color map
                var colorpos = 0;
                var nkeys = Object.keys(data['kismet.channeltracker.frequency_map']).length;

                var filter = $('select#gh_filter', state.element);
                filter.empty();

                if (filter_string === '' || filter_string === 'any') {
                    filter.append(
                        $('<option>', {
                            value: "",
                            selected: "selected",
                        })
                        .text("Any")
                    );
                }  else {
                    filter.append(
                        $('<option>', {
                            value: "any",
                        })
                        .text("Any")
                    );
                }

                for (var fk in data['kismet.channeltracker.frequency_map']) {
                    var linedata =
                        kismet.RecalcRrdData(
                            data['kismet.channeltracker.frequency_map'][fk]['kismet.channelrec.device_rrd']['kismet.common.rrd.last_time'],
                            data['kismet.channeltracker.frequency_map'][fk]['kismet.channelrec.device_rrd']['kismet.common.rrd.last_time'],
                            rrd_type,
                            kismet.ObjectByString(
                                data['kismet.channeltracker.frequency_map'][fk],
                                rrd_data),
                            {});

                    // Convert the freq name
                    var cfk = kismet_ui.GetConvertedChannel(freqtrans, fk);

                    var label = "";

                    if (cfk == fk)
                        label = kismet.HumanReadableFrequency(parseInt(fk));
                    else
                        label = cfk;

                    // Make a filter option
                    if (filter_string === fk) {
                        filter.append(
                            $('<option>', {
                                value: fk,
                                selected: "selected",
                            })
                            .text(label)
                        );
                    } else {
                        filter.append(
                            $('<option>', {
                                value: fk,
                            })
                            .text(label)
                        );
                    }

                    // Rotate through the color wheel
                    var color = parseInt(255 * (colorpos / nkeys));
                    colorpos++;

                    // Build the dataset record
                    var ds = {
                        stack: 'bar',
                        label:  label,
                        fill: true,
                        lineTension: 0.1,
                        data: linedata,
                        borderColor: "hsl(" + color + ", 100%, 50%)",
                        backgroundColor: "hsl(" + color + ", 100%, 50%)",
                    };

                    // Add it to the dataset if we're not filtering
                    if (filter_string === fk ||
                        filter_string === '' ||
                        filter_string === 'any') {
                            datasets.push(ds);
                    }
                }

                state.devgraph_canvas.hide();
                state.timegraph_canvas.show();
                state.coming_soon.hide();

                if (state.timegraph_chart == null) {
                    var device_options = {
                        type: "bar",
                        responsive: true,
                        options: {
                            maintainAspectRatio: false,
                            scales: {
                                yAxes: [{
                                    ticks: {
                                        beginAtZero: true,
                                    },
                                    stacked: true,
                                }],
                                xAxes: [{
                                    stacked: true,
                                }],
                            },
                            legend: {
                                labels: {
                                    boxWidth: 15,
                                    fontSize: 9,
                                    padding: 5,
                                },
                            },
                        },
                        data: {
                            labels: pointtitles,
                            datasets: datasets,
                        }
                    };

                    state.timegraph_chart = new Chart(state.timegraph_canvas,
                        device_options);
                } else {
                    state.timegraph_chart.data.datasets = datasets;
                    state.timegraph_chart.data.labels = pointtitles;

                    state.timegraph_chart.update();
                }
            } else {
                // 'now', but default - if for some reason we didn't get a
                // value from the selector, this falls through to the bar graph
                // which is what we probably really want
                for (var fk in data['kismet.channeltracker.frequency_map']) {
                    var slot_now =
                        (data['kismet.channeltracker.frequency_map'][fk]['kismet.channelrec.device_rrd']['kismet.common.rrd.last_time']) % 60;
                    var dev_now = data['kismet.channeltracker.frequency_map'][fk]['kismet.channelrec.device_rrd']['kismet.common.rrd.minute_vec'][slot_now];

                    var cfk = kismet_ui.GetConvertedChannel(freqtrans, fk);

                    if (cfk == fk)
                        devtitles.push(kismet.HumanReadableFrequency(parseInt(fk)));
                    else
                        devtitles.push(cfk);

                    devnums.push(dev_now);
                }

                state.devgraph_canvas.show();
                state.timegraph_canvas.hide();

                if (state.devgraph_chart == null) {
                    state.coming_soon.hide();

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
                                    backgroundColor: kismet_theme.graphBasicColor,
                                    data: devnums,
                                    borderWidth: 1,
                                }
                            ],
                        }
                    };

                    state.devgraph_chart = new Chart(state.devgraph_canvas,
                        device_options);

                } else {
                    state.devgraph_chart.data.datasets[0].data = devnums;
                    state.devgraph_chart.data.labels = devtitles;

                    state.devgraph_chart.update();
                }
            }

        })
        .always(function() {
            state.timerid = setTimeout(function() { channeldisplay_refresh(state); }, 5000);
        });
    };

    var update_graphtype = function(state, gt = null) {

        if (gt == null)
            gt = $("input[name='graphtype']:checked", state.graphtype).val();

        state.storage.set('jquery.kismet.channels.graphtype', gt);

        if (gt === 'now') {
            $("select#historyrange", state.graphtype).hide();
            $("select#gh_filter", state.graphtype).hide();
            $("label#gh_filter_label", state.graphtype).hide();
        } else {
            $("select#historyrange", state.graphtype).show();
            $("label#gh_filter_label", state.graphtype).show();
            $("select#gh_filter", state.graphtype).show();
        }

        charttime = $('select#historyrange option:selected', state.element).val();
        state.storage.set('jquery.kismet.channels.range', charttime);
    }

    var channels_resize = function(state) {
        console.log('resize container ', state.devgraph_container.width(), state.devgraph_container.height());

        if (state.devgraph_canvas != null)
            state.devgraph_canvas
                .prop('width', state.devgraph_container.width())
                .prop('height', state.devgraph_container.height());

        if (state.timegraph_canvas != null)
            state.timegraph_canvas
                .prop('width', state.devgraph_container.width())
                .prop('height', state.devgraph_container.height());

        if (state.devgraph_chart != null)
            state.devgraph_chart.resize();

        if (state.timegraph_chart != null)
            state.timegraph_chart.resize();

        channeldisplay_refresh(state);
    }

    $.fn.channels = function(inopt) {
        var state = {
            element: $(this),
            options: base_options,
            timerid: -1,
            devgraph_container: null,
            devgraph_chart: null,
            timegraph_chart: null,
            devgraph_canvas: null,
            timegraph_canvas: null,
            picker: null,
            graphtype: null,
            coming_soon: null,
            visible: false,
            storage: null,
            resizer: null,
            reset_size: null,
        };

        // Modeled on the datatables resize function
        state.resizer = $('<iframe/>')
            .css({
                position: 'absolute',
                top: 0,
                left: 0,
                height: '100%',
                width: '100%',
                zIndex: -1,
                border: 0
            })
        .attr('frameBorder', '0')
        .attr('src', 'about:blank');

        state.resizer[0].onload = function() {
			var body = this.contentDocument.body;
			var height = body.offsetHeight;
            var width = body.offsetWidth;
			var contentDoc = this.contentDocument;
			var defaultView = contentDoc.defaultView || contentDoc.parentWindow;

			defaultView.onresize = function () {
				var newHeight = body.clientHeight || body.offsetHeight;
				var docClientHeight = contentDoc.documentElement.clientHeight;

				var newWidth = body.clientWidth || body.offsetWidth;
				var docClientWidth = contentDoc.documentElement.clientWidth;

				if ( ! newHeight && docClientHeight ) {
					newHeight = docClientHeight;
				}

				if ( ! newWidth && docClientWidth ) {
					newWidth = docClientWidth;
				}

				if ( newHeight !== height || newWidth !== width ) {
					height = newHeight;
					width = newWidth;
                    console.log("triggered resizer", height, width);
                    channels_resize(state);
				}
			};
		};

        state.resizer
            .appendTo(state.element)
            .attr('data', 'about:blank');

        state.element.on('resize', function() {
            console.log("element resize");
            channels_resize(state);
        });

        state.element.addClass(".channels");

        state.storage = Storages.localStorage;

        var stored_gtype = "now";
        var stored_channel = "Frequency";
        var stored_range = "min";

        if (state.storage.isSet('jquery.kismet.channels.graphtype'))
            stored_gtype = state.storage.get('jquery.kismet.channels.graphtype');

        if (state.storage.isSet('jquery.kismet.channels.channeltype'))
            stored_channel = state.storage.get('jquery.kismet.channels.channeltype');

        if (state.storage.isSet('jquery.kismet.channels.range'))
            stored_range = state.storage.get('jquery.kismet.channels.range');


        if (!state.storage.isSet('jquery.kismet.channels.filter'))
            state.storage.set('jquery.kismet.channels.filter', 'any');

        state.visible = state.element.is(":visible");

        if (typeof(inopt) === "string") {

        } else {
            state.options = $.extend(base_options, inopt);
        }

        var banner = $('div.k_cd_banner', state.element);
        if (banner.length == 0) {
            banner = $('<div>', {
                id: "banner",
                class: "k_cd_banner"
            });

            state.element.append(banner);
        }

        if (state.graphtype == null) {
            state.graphtype = $('<div>', {
                "id": "graphtype",
                "class": "k_cd_type",
            })
            .append(
                $('<label>', {
                    for: "gt_bar",
                })
                .text("Current")
                .tooltipster({ content: 'Realtime devices-per-channel'})
            )
            .append($('<input>', {
                type: "radio",
                id: "gt_bar",
                name: "graphtype",
                value: "now",
                })
            )
            .append(
                $('<label>', {
                    for: "gt_line",
                })
                .text("Historical")
                .tooltipster({ content: 'Historical RRD device records'})
            )
            .append($('<input>', {
                type: "radio",
                id: "gt_line",
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
                        id: "hr_min",
                        value: "min",
                    })
                    .text("Past Minute")
                )
                .append(
                    $('<option>', {
                        id: "hr_hour",
                        value: "hour",
                    })
                    .text("Past Hour")
                )
                .append(
                    $('<option>', {
                        id: "hr_day",
                        value: "day",
                    })
                    .text("Past Day")
                )
                .hide()
            )
            .append(
                $('<label>', {
                    id: "gh_filter_label",
                    for: "gh_filter",
                })
                .text("Filter")
                .append(
                    $('<select>', {
                        id: "gh_filter"
                    })
                    .append(
                        $('<option>', {
                            id: "any",
                            value: "any",
                            selected: "selected",
                        })
                        .text("Any")
                    )
                )
                .hide()
            );

            // Select time range from stored value
            $('option#hr_' + stored_range, state.graphtype).attr('selected', 'selected');

            // Select graph type from stored value
            if (stored_gtype == 'now') {
                $('input#gt_bar', state.graphtype).attr('checked', 'checked');
            } else {
                $('input#gt_line', state.graphtype).attr('checked', 'checked');
            }

            banner.append(state.graphtype);

            update_graphtype(state, stored_gtype);

            state.graphtype.on('change', function() {
                update_graphtype(state);
                channeldisplay_refresh(state);
            });

            $('select#gh_filter', state.graphtype).on('change', function() {
                var filter_string = $('select#gh_filter option:selected', state.element).val();
                state.storage.set('jquery.kismet.channels.filter', filter_string);
                channeldisplay_refresh(state);
            });

        }

        if (state.picker == null) {
            state.picker = $('<div>', {
                id: "picker",
                class: "k_cd_picker",
            });

            var sel = $('<select>', {
                id: "k_cd_freq_selector",
                class: "k_cd_list",
            });

            state.picker.append(sel);

            var chlist = new Array();
            chlist.push("Frequency");

            chlist = chlist.concat(kismet_ui.GetChannelListKeys());

            for (var c in chlist) {
                var e = $('<option>', {
                    value: chlist[c],
                }).html(chlist[c]);

                if (chlist[c] === stored_channel)
                    e.attr("selected", "selected");

                sel.append(e);
            }

            banner.append(state.picker);

            state.picker.on('change', function() {
                var freqtrans =
                    $('select#k_cd_freq_selector option:selected', state.element).val();

                state.storage.set('jquery.kismet.channels.channeltype', freqtrans);

                channeldisplay_refresh(state);
            });

        }

        if (state.devgraph_container == null) {
            state.devgraph_container =
                $('<div>', {
                    class: "k_cd_container"
                });

            state.devgraph_canvas = $('<canvas>', {
                class: "k_cd_dg",
            });

            state.devgraph_container.append(state.devgraph_canvas);

            state.timegraph_canvas = $('<canvas>', {
                class: "k_cd_dg",
            });

            state.timegraph_canvas.hide();
            state.devgraph_container.append(state.timegraph_canvas);

            state.element.append(state.devgraph_container);
        }

        // Add a 'coming soon' item
        if (state.coming_soon == null)  {
            state.coming_soon = $('<i>', {
                "id": "coming_soon",
            });
            state.coming_soon.html("Channel data loading...");
            state.element.append(state.coming_soon);
        }

        // Hook an observer to see when we become visible
        var observer = new MutationObserver(function(mutations) {
            if (state.element.is(":hidden") && state.timerid >= 0) {
                state.visible = false;
                clearTimeout(state.timerid);
            } else if (state.element.is(":visible") && !state.visible) {
                state.visible = true;
                channeldisplay_refresh(state);
            }
        });

        observer.observe(state.element[0], {
            attributes: true
        });

        if (state.visible) {
            channeldisplay_refresh(state);
        }
    };

}(jQuery));

