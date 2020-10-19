// Packet rate widget
//
// Requires js-storage, jquery, and sparkline be loaded prior
//
// dragorn@kismetwireless.net
// MIT/GPL License (pick one); the web ui code is licensed more
// freely than GPL to reflect the generally MIT-licensed nature
// of the web/jquery environment
//

(function ($) {
    var local_uri_prefix = "";
    if (typeof(KISMET_URI_PREFIX) !== 'undefined')
        local_uri_prefix = KISMET_URI_PREFIX;

    var base_options = {
        use_color: true,
    };

    var options = base_options;

    var timerid = -1;

    var element = null;

    var dialog = null;

    var click = null;

    var packetgraph = null;

    var popup_content =
	    $('<div>', {
            style: 'padding: 2px; border: 0px;'
        })
        .append(
            $('<div>', {
                id: 'status',
                style: 'padding-bottom: 2px;'
            })
        )
        .append(
            $('<table>', {
                id: "statustable",
                style: "border: 0px !important; width: 100%;",
            })
            .append(
                $('<tr>')
                .append(
                    $('<td>').html('Total Packets')
                )
                .append(
                    $('<td>', {
                        id: 'rate'
                    }).html("n/a")
                )
            )
            .append(
                $('<tr>')
                .append(
                    $('<td>').html('Duplicates')
                )
                .append(
                    $('<td>', {
                        id: 'dupe'
                    }).html("n/a")
                )
            )
            .append(
                $('<tr>')
                .append(
                    $('<td>').html('Packet queue backlog')
                )
                .append(
                    $('<td>', {
                        id: 'queue'
                    }).html("n/a")
                )
            )
            .append(
                $('<tr>')
                .append(
                    $('<td>').html('Dropped queue')
                )
                .append(
                    $('<td>', {
                        id: 'drop'
                    }).html("n/a")
                )
            )
            .append(
                $('<tr>')
                .append(
                    $('<td>').html('Errors')
                )
                .append(
                    $('<td>', {
                        id: 'error'
                    }).html("n/a")
                )
            )
        );

    // Close the alert panel if we click outside it
    var close_dialog_outside = function(e) {
        if (e == null ||
            (e != null && $(e.target).closest('#packetdialog').length == 0)) {

            if (dialog != null) {
                dialog.remove();
                dialog = null;
            }

            // Remove the handler
            $('body').off('click', close_dialog_outside);

            // Don't pass the click on
            e.stopImmediatePropagation();
        }
    }

    var open_dialog = function(e) {
        if (dialog != null) {
            close_dialog_outside(e);

            e.stopImmediatePropagation();
            return;
        }

        var fullscreen = false;

        var nominal_w = 400;
        //var nominal_h = ($(window).height() / 3) * 2;
        var nominal_h = 120;

        var pos = { };

        if ($(window).width() < 450) {
            nominal_w = $(window).width() - 5;
            nominal_h = $(window).height() - 5;

            pos = {
                "my": "left-top",
                "at": "left-top",
                "of": "window",
                "offsetX": 2,
                "offsetY": 2,
                "autoposition": "RIGHT"
            };

            fullscreen = true;
        } else {
            // Position under the element
            var off_y = (nominal_h / 2) + (element.outerHeight() / 2) + 3;

            // left-ish of the icon
            var off_x = (nominal_w / 5) * 2;
            off_x *= -1;

            // Where the outer border lands
            var outerborder = off_x + (nominal_w / 2);

            pos = {
                of: element,
                offsetY: off_y,
                offsetX: off_x
            };

            fullscreen = false;
        }

        if (fullscreen)
            $('.kg-header-close', popup_content).show();

        dialog = $.jsPanel({
            id: "packetdialog",
            headerRemove: true,
            position: pos,
            contentSize: {
                width: nominal_w,
                height: nominal_h
            },
            content: popup_content,
        });

        $("body").on("click", close_dialog_outside);

        e.stopImmediatePropagation();
    }

    /*
    var packet_refresh = function() {
        if (kismet_ui.window_visible) {
            $.get(local_uri_prefix + "packetchain/packet_stats.json")
            .done(function(data) {
                data = kismet.sanitizeObject(data);

                try {
                    var rate_rrd =
                        kismet.RecalcRrdData2(data['kismet.packetchain.packets_rrd'], kismet.RRD_SECOND, {
                                transform: function(data, opt) {
                                    var slices = 3;
                                    var peak = 0;
                                    var ret = new Array();

                                    for (var ri = 0; ri < data.length; ri++) {
                                        peak = Math.max(peak, data[ri]);

                                        if ((ri % slices) == (slices - 1)) {
                                            ret.push(peak);
                                            peak = 0;
                                        }
                                    }

                                    return ret;
                                }
                            });

                    var error_rrd =
                        kismet.RecalcRrdData2(
                            data['kismet.packetchain.error_packets_rrd'], kismet.RRD_SECOND, {
                                transform: function(data, opt) {
                                    var slices = 3;
                                    var peak = 0;
                                    var ret = new Array();

                                    for (var ri = 0; ri < data.length; ri++) {
                                        peak = Math.max(peak, data[ri]);

                                        if ((ri % slices) == (slices - 1)) {
                                            ret.push(peak);
                                            peak = 0;
                                        }
                                    }

                                    return ret;
                                }
                            });

                    var dupe_rrd =
                        kismet.RecalcRrdData2(
                            data['kismet.packetchain.dupe_packets_rrd'], kismet.RRD_SECOND, {
                                transform: function(data, opt) {
                                    var slices = 3;
                                    var peak = 0;
                                    var ret = new Array();

                                    for (var ri = 0; ri < data.length; ri++) {
                                        peak = Math.max(peak, data[ri]);

                                        if ((ri % slices) == (slices - 1)) {
                                            ret.push(peak);
                                            peak = 0;
                                        }
                                    }

                                    return ret;
                                }
                            });

                    var queue_rrd =
                        kismet.RecalcRrdData2(
                            data['kismet.packetchain.queued_packets_rrd'], kismet.RRD_SECOND, {
                                transform: function(data, opt) {
                                    var slices = 3;
                                    var peak = 0;
                                    var ret = new Array();

                                    for (var ri = 0; ri < data.length; ri++) {
                                        peak = Math.max(peak, data[ri]);

                                        if ((ri % slices) == (slices - 1)) {
                                            ret.push(peak);
                                            peak = 0;
                                        }
                                    }

                                    return ret;
                                }
                            });

                    var drop_rrd =
                        kismet.RecalcRrdData2(
                            data['kismet.packetchain.dropped_packets_rrd'], kismet.RRD_SECOND, {
                                transform: function(data, opt) {
                                    var slices = 3;
                                    var peak = 0;
                                    var ret = new Array();

                                    for (var ri = 0; ri < data.length; ri++) {
                                        peak = Math.max(peak, data[ri]);

                                        if ((ri % slices) == (slices - 1)) {
                                            ret.push(peak);
                                            peak = 0;
                                        }
                                    }

                                    return ret;
                                }
                            });

                    var combo_rrd = [];

                    for (var i = 0; i < rate_rrd.length; i++) {
                        combo_rrd.push([rate_rrd[i], dupe_rrd[i]]);
                    }
                    

                    packetgraph.sparkline(combo_rrd, {
                        type: "bar", 
                        height: 12, 
                    });

                    $('#rate', popup_content).sparkline(rate_rrd, {
                        type: "bar",
                        height: 12,
                    });

                    $('#error', popup_content).sparkline(error_rrd, {
                        type: "bar",
                        height: 12,
                    });

                    $('#dupe', popup_content).sparkline(dupe_rrd, {
                        type: "bar",
                        height: 12,
                    });

                    $('#queue', popup_content).sparkline(queue_rrd, {
                        type: "bar",
                        height: 12,
                    });

                    $('#drop', popup_content).sparkline(drop_rrd, {
                        type: "bar",
                        height: 12,
                    });

                } catch (error) {

                }

            })
            .always(function() {
                timerid = setTimeout(packet_refresh, 1000);
            });
        } else {
            timerid = setTimeout(packet_refresh, 1000);
        }
    }
    */

    $.fn.packetrate = function(data, inopt) {
        // Get the stored value if one exists
        storage = Storages.localStorage;

        element = $(this);

        element.addClass('kg-top-icon');

        options = $.extend(base_options, inopt);

        packetgraph = $('div.icon', this);
        if (packetgraph.length == 0) {
            packetgraph = $('<div>', {
                class: "icon",
                width: "100px",
                height: "10px",
            });
        }

        click = $('a.packetbutton', this);

        if (click.length != 0) {
            click.empty();
        }

        click = $('<a>', {
            href: "#",
            class: "packetbutton"
        })
        .on('click', open_dialog);

        click.append(packetgraph);
        element.append(click);

        packetgraph.sparkline([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], {
            type: "bar", 
            height: 12, 
            width: 100,
        });


        element.tooltipster({
            maxWidth: 450
        });

        kismet_ui_base.SubscribeEventbus("PACKETCHAIN_STATS", [], function(data) {
            data = kismet.sanitizeObject(data);

            try {
                var rate_rrd =
                    kismet.RecalcRrdData2(data['kismet.packetchain.packets_rrd'], kismet.RRD_SECOND, {
                        transform: function(data, opt) {
                            var slices = 3;
                            var peak = 0;
                            var ret = new Array();

                            for (var ri = 0; ri < data.length; ri++) {
                                peak = Math.max(peak, data[ri]);

                                if ((ri % slices) == (slices - 1)) {
                                    ret.push(peak);
                                    peak = 0;
                                }
                            }

                            return ret;
                        }
                    });

                var error_rrd =
                    kismet.RecalcRrdData2(
                        data['kismet.packetchain.error_packets_rrd'], kismet.RRD_SECOND, {
                            transform: function(data, opt) {
                                var slices = 3;
                                var peak = 0;
                                var ret = new Array();

                                for (var ri = 0; ri < data.length; ri++) {
                                    peak = Math.max(peak, data[ri]);

                                    if ((ri % slices) == (slices - 1)) {
                                        ret.push(peak);
                                        peak = 0;
                                    }
                                }

                                return ret;
                            }
                        });

                var dupe_rrd =
                    kismet.RecalcRrdData2(
                        data['kismet.packetchain.dupe_packets_rrd'], kismet.RRD_SECOND, {
                            transform: function(data, opt) {
                                var slices = 3;
                                var peak = 0;
                                var ret = new Array();

                                for (var ri = 0; ri < data.length; ri++) {
                                    peak = Math.max(peak, data[ri]);

                                    if ((ri % slices) == (slices - 1)) {
                                        ret.push(peak);
                                        peak = 0;
                                    }
                                }

                                return ret;
                            }
                        });

                var queue_rrd =
                    kismet.RecalcRrdData2(
                        data['kismet.packetchain.queued_packets_rrd'], kismet.RRD_SECOND, {
                            transform: function(data, opt) {
                                var slices = 3;
                                var peak = 0;
                                var ret = new Array();

                                for (var ri = 0; ri < data.length; ri++) {
                                    peak = Math.max(peak, data[ri]);

                                    if ((ri % slices) == (slices - 1)) {
                                        ret.push(peak);
                                        peak = 0;
                                    }
                                }

                                return ret;
                            }
                        });

                var drop_rrd =
                    kismet.RecalcRrdData2(
                        data['kismet.packetchain.dropped_packets_rrd'], kismet.RRD_SECOND, {
                            transform: function(data, opt) {
                                var slices = 3;
                                var peak = 0;
                                var ret = new Array();

                                for (var ri = 0; ri < data.length; ri++) {
                                    peak = Math.max(peak, data[ri]);

                                    if ((ri % slices) == (slices - 1)) {
                                        ret.push(peak);
                                        peak = 0;
                                    }
                                }

                                return ret;
                            }
                        });

                var combo_rrd = [];

                for (var i = 0; i < rate_rrd.length; i++) {
                    combo_rrd.push([rate_rrd[i], dupe_rrd[i]]);
                }


                packetgraph.sparkline(combo_rrd, {
                    type: "bar", 
                    height: 12, 
                });

                $('#rate', popup_content).sparkline(rate_rrd, {
                    type: "bar",
                    height: 12,
                });

                $('#error', popup_content).sparkline(error_rrd, {
                    type: "bar",
                    height: 12,
                });

                $('#dupe', popup_content).sparkline(dupe_rrd, {
                    type: "bar",
                    height: 12,
                });

                $('#queue', popup_content).sparkline(queue_rrd, {
                    type: "bar",
                    height: 12,
                });

                $('#drop', popup_content).sparkline(drop_rrd, {
                    type: "bar",
                    height: 12,
                });

            } catch (error) {

            }

        });
    };

}(jQuery));
