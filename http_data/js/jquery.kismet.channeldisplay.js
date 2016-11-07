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
    var picker = null;
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
            var maxdev = 0;

            var freqtrans = $('select#k_cd_freq_selector option:selected', element).val();

            for (var fk in data['kismet_channeltracker_frequency_map']) {
                var slot_now =
                    (data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_device_rrd']['kismet_common_rrd_last_time'] - 1) % 60;
                var dev_now = data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_device_rrd']['kismet_common_rrd_minute_vec'][slot_now];

                cfk = kismet_ui.GetConvertedChannel(freqtrans, fk);

                if (cfk == fk) 
                    devtitles.push(kismet.HumanReadableFrequency(parseInt(fk)));
                else
                    devtitles.push(cfk);

                // devnums.push(dev_now + Math.random() * 100);
                devnums.push(dev_now);

                if (maxdev < dev_now)
                    maxdev = dev_now;
            }

            if (maxdev == 0)
                maxdev = 5;

            if (devgraph_chart == null) {
                coming_soon.hide();

                var device_options = {
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
                    type: "bar",
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

                devgraph_chart = new Chart($('.k_cd_dg', element), device_options);

            } else {
                devgraph_chart.data.datasets[0].data = devnums;
                devgraph_chart.data.labels = devtitles;

                devgraph_chart.update();
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

        if (picker == null) {
            picker = $('<div>', {
                "id": "picker",
                "class": "k_cd_picker",
            });

            var sel = $('<select>', {
                "id": "k_cd_freq_selector",
                class: "k_cd_list",
            });

            picker.append(sel);

            var chlist = new Array();
            chlist.push("Frequency");

            chlist = chlist.concat(kismet_ui.GetChannelListKeys());

            for (var c in chlist) {
                var e = $('<option>', {
                    "value": chlist[c], 
                });
                e.html(chlist[c]);

                sel.append(e);
            }

            element.append(picker);
        }

        picker.on('change', function() {
            channeldisplay_refresh();
        });

        devgraph_canvas = $('<canvas>', {
            "class": "k_cd_dg",
            "width": "100%",
            "height": "100%",
        });

        element.append(devgraph_canvas);

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

