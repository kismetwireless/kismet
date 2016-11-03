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

    var channeldisplay_refresh = function() {
        $.get("/channels/channels.json")
        .done(function(data) {
            var devtitles = new Array();
            var devnums = new Array();
            var maxdev = 0;

            for (var fk in data['kismet_channeltracker_frequency_map']) {
                var slot_now =
                    data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_packets_rrd']['kismet_common_rrd_last_time'] % 60;
                var dev_now = data['kismet_channeltracker_frequency_map'][fk]['kismet_channelrec_packets_rrd']['kismet_common_rrd_minute_vec'][slot_now];

                devtitles.push(kismet.HumanReadableFrequency(parseInt(fk)));
                // devnums.push(dev_now + Math.random() * 100);
                devnums.push(dev_now);

                if (dev_now > maxdev)
                    maxdev = dev_now;
            }

            if (maxdev == 0)
                maxdev = 5;

            if (devgraph_chart == null) {
                element.html("");

                devgraph_canvas = $('<canvas>', {
                    "class": "k_cd_dg",
                    "width": "100%",
                    "height": "100%",

                });

                element.append(devgraph_canvas);

                var device_options = {
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            yAxes: [{
                                ticks: {
                                    max: parseInt(maxdev * 1.25),
                                    min: 0,
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

            timerid = setTimeout(channeldisplay_refresh, 1000);
        });
    };

    $.fn.channels = function(data, inopt) {
        element = $(this);

        element.bind('resize', function(e) {
            console.log("channels div resize");
        });

        if (typeof(inopt) === "string") {

        } else {
            options = $.extend(base_options, inopt);
        }

        channeldisplay_refresh();
    };

}(jQuery));

