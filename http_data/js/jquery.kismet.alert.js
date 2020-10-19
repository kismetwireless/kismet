// Alert icon and window
//
// Requires js-storage and jquery be loaded prior
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
        max_backlog: 50,
    };

    var options = base_options;

    var timerid = -1;

    var element = null;

    var alerticon = null;
    var alertbg = null;
    var alertnum = null;

    var alertclick = null;

    // Last time from the server
    var last_time = 0;

    // Last time we closed the alert window
    var last_closed_time = 0;

    var dialog = null;

    var alert_list = new Array();

    var storage = null;

    function update_tooltips() {
        var num_new = 0;

        var new_plural = 's';
        var total_plural = 's';

        for (var x = 0; x < alert_list.length; x++) {
            if (alert_list[x]['kismet.alert.timestamp'] <= last_closed_time) {
                break;
            }

            num_new++;
        }

        var num_total = alert_list.length - num_new;

        if (num_new <= 1)
            new_plural = '';

        if (num_total <= 1)
            total_plural = '';

        if (num_new == 0) {
            if (num_total == 0) {
                element.tooltipster('content', 'No alerts');
            } else {
                element.tooltipster('content', num_total + ' old alert' + total_plural);
            }
        } else {
            if (num_total == 0) {
                element.tooltipster('content', num_new + ' alert' + new_plural);
            } else {
                element.tooltipster('content', num_new + ' alert' + new_plural + ' ' + num_total + ' old alert' + total_plural);
            }
        }
    }

    // Close the alert panel if we click outside it
    var close_dialog_outside = function(e) {
        if (e == null ||
            (e != null && $(e.target).closest('#alertdialog').length == 0)) {

            // Remember the time
            last_closed_time = last_time;

            storage.set('jquery.kismet.alert.last_closed', last_closed_time);

            if (dialog != null) {
                dialog.remove();
                dialog = null;
            }

            // Un-flag the alert button
            alertbg.removeClass('ka-top-bg-alert');

            // Remove the handler
            $('body').off('click', close_dialog_outside);

            update_tooltips();

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
        var nominal_h = ($(window).height() / 3) * 2;

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


        // Make the list of alerts
        var listholder = $('<div>', {
            class: "ka-alert-list",
            id: "ka-alert-list"
        });

        for (var x = 0; x < options.max_backlog; x++) {
            var d = $('<div>', {
                class: "ka-alert-line"
            });
            listholder.append(d);
        }

        var alert_popup_content = 
            $('<div>', {
                class: "ka-dialog-content"
            })
            .append(
                $('<div>', {
                    class: "ka-dialog-header"
                })
                .append(
                    $('<i>', {
                        class: "fa fa-bell ka-header-icon"
                    })
                )
                .append(
                    $('<b>', {
                        class: "ka-header-text"
                    }).text('Alerts')
                )
                .append(
                    $('<a>', {
                        href: "#"
                    })
                    .on('click', function() {
                        close_dialog_outside(null);
                    })
                    .append(
                        $('<span>', {
                            class: "ka-header-close jsglyph jsglyph-close"
                        })
                        .hide()
                    )
                )
            )
            .append(
                $('<div>', {
                    class: "ka-dialog-main"
                })
                .append(
                    $('<div>', {
                        class: "ka-dialog-center",
                        id: "ka-dialog-none"
                    })
                    .append(
                        $('<span>', {
                            class: "fa fa-bell-slash ka-big-icon"
                        })
                    )
                    .append(
                        $('<span>', {
                            class: "ka-dialog-center ka-no-text"
                        })
                        .text("No alerts to show!")
                    )
                )
                .append(listholder)
            )
            .append(
                $('<div>', {
                    class: "ka-dialog-footer"
                })
                .append(
                    $('<span>', {
                        class: "ka-bottom-text"
                    })
                    .append(
                        $('<a>', {
                            href: '#',
                            id: 'ka-alert-show-all'
                        })
                        .on('click', function() {
                            populate_alert_content(alert_popup_content, true);
                        })
                        .text("No previous alerts")
                    )
                )
            );


        if (fullscreen)
            $('.ka-header-close', alert_popup_content).show();

        populate_alert_content(alert_popup_content);

        dialog = $.jsPanel({
            id: "alertdialog",
            headerRemove: true,
            position: pos,
            contentSize: {
                width: nominal_w,
                height: nominal_h
            },
            content: alert_popup_content,
        });

        $("body").on("click", close_dialog_outside);

        e.stopImmediatePropagation();
    }

    var merge_alerts = function(alerts) {
        alertbg.addClass('ka-top-bg-alert');

        $.merge(alerts, alert_list);
        alert_list = alerts.slice(0, options.max_backlog);

        // Is the dialog showing?  Update it if it is
        if (dialog != null) {
            populate_alert_content(dialog.content);
        }

        update_tooltips();
    }

    var alert_refresh = function(fetchtime = last_time) {
        $.get(local_uri_prefix + "alerts/wrapped/last-time/" + fetchtime + "/alerts.json")
            .done(function(data) {
                data = kismet.sanitizeObject(data);

                // Reverse, combine in the data var, slice and assign to the alert list
                data['kismet.alert.list'].reverse();
                merge_alerts(data['kismet.alert.list']);
            })
    }

    var populate_alert_content = function(c, showall = false) {
        var divs = $('div.ka-alert-line', c);

        if (showall) {
            last_closed_time = 0;
            storage.set('jquery.kismet.alert.last_closed', last_closed_time);
        }

        // If the top alert is older (or equal) to the last time we closed the
        // alert popup, then we don't have any new alerts
        if (alert_list.length == 0) {
            $('div#ka-dialog-none', c).show();
            $('div#ka-alert-list', c).hide();
            $('a#ka-alert-show-all', c).text("No alerts...");
            return;
        } 
       
        // Are we showing all alerts, or do we have new ones?
        if (alert_list.length > 0 &&
                alert_list[0]['kismet.alert.timestamp'] > last_closed_time) {
            $('div#ka-dialog-none', c).hide();
            $('div#ka-alert-list', c).show();

            // Set the txt at the bottom to something sane
            $('a#ka-alert-show-all', c).text("Showing all alerts...");

            // Clear all the divs
            divs.empty();
            divs.hide();

            for (var x = 0; x < alert_list.length; x++) {
                // Stop when we get to old ones
                if (alert_list[x]['kismet.alert.timestamp'] <= last_closed_time) {
                    // Set the text to 'show all'
                    $('a#ka-alert-show-all', c).text("Show all previous alerts...");
                    break;
                }

                var d = divs.eq(x);

                var ds = (new Date(alert_list[x]['kismet.alert.timestamp'] * 1000).toString()).substring(4, 25);

                // Build the content of each alert line
                d.append(
                    $('<div>', {
                        class: "ka-alert-line-header"
                    })
                    .append(
                        $('<i>', {
                            class: "fa fa-bell ka-alert-line-icon"
                        })
                    )
                    .append(
                        $('<span>', {
                            class: "ka-alert-line-date"
                        })
                        .html(ds)
                    )
                    .append(
                        $('<span>', {
                            class: "ka-alert-line-type"
                        })
                        .html(kismet.censorMAC(alert_list[x]['kismet.alert.header']))
                    )
                    .append(
                        $('<div>', {
                            class: "ka-alert-line-text"
                        })
                        .html(kismet.censorMAC(alert_list[x]['kismet.alert.text']))
                    )
                    .append(
                        $('<div>', {
                            class: "ka-alert-line-footer"
                        })
                        .append(
                            $('<span>', {
                                class: "ka-alert-line-address"
                            })
                            .html(kismet_ui_base.renderMac(alert_list[x]['kismet.alert.source_mac']))
                        )
                        .append(
                            $('<i>', {
                                class: "fa fa-arrow-right ka-alert-line-arrow"
                            })
                        )
                        .append(
                            $('<span>', {
                                class: "ka-alert-line-address"
                            })
                            .html(kismet_ui_base.renderMac(alert_list[x]['kismet.alert.dest_mac']))
                        )
                    )
                );

                d.show();

            }

        } else {
            $('div#ka-dialog-none', c).show();
            $('div#ka-alert-list', c).hide();
            divs.empty();
            $('a#ka-alert-show-all', c).text("Show all previous alerts...");
        }
    }

    $.fn.alert = function(data, inopt) {
        // Get the stored value if one exists
        storage = Storages.localStorage;

        if (storage.isSet('jquery.kismet.alert.last_closed'))
            last_closed_time = storage.get('jquery.kismet.alert.last_closed');

        element = $(this);

        element.addClass('ka-top-icon');

        options = $.extend(base_options, inopt);

        alertbg = $('i.background', this);
        if (alertbg.length == 0) {
            alertbg = $('<i>', {
                class: "background fa fa-square fa-stack-2x ka-top-bg-normal"
            });
        }

        alerticon = $('i.icon', this);
        if (alerticon.length == 0) {
            alerticon = $('<i>', {
                class: "icon fa fa-bell fa-inverse fa-stack-1x"
            });
        }

        alertnum = $('span.number', this);
        if (alertnum.length == 0) {
            alertnum = $('<span>', {
                class: "number fa fa-stack-1x"
            });
        }

        // Make the headerbar icon
        var alertholder = $('span.fa-stack', this);

        if (alertholder.length != 0) {
            alertholder.empty();
        } else {
            alertholder = $('<span>', {
                class: "fa-stack"
            });
        }

        alertholder.append(alertbg);
        alertholder.append(alerticon);
        alertholder.append(alertnum);

        // Build the wrapper around the header button

        alertclick = $('a.alertbutton', this);

        if (alertclick.length != 0) {
            alertclick.empty();
        }

        alertclick = $('<a>', {
            href: "#",
            class: "alertbutton"
        })
        .on('click', open_dialog);

        alertclick.append(alertholder);
        element.append(alertclick);

        element.tooltipster({
            maxWidth: 450
        });

        alert_refresh(0);

        kismet_ui_base.SubscribeEventbus("ALERT", [], function(data) {
            data = kismet.sanitizeObject(data);
            merge_alerts([data]);
        });
    };

}(jQuery));
