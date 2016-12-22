// Alert icon and window
//
// dragorn@kismetwireless.net
// MIT/GPL License (pick one); the web ui code is licensed more
// freely than GPL to reflect the generally MIT-licensed nature
// of the web/jquery environment
//

(function ($) {
    var base_options = { 
        use_color: true,
    };

    var options = base_options;

    var timerid = -1;

    var element = null;

    var alerticon = null;
    var alertbg = null;
    var alertnum = null;

    var last_time = 0;

    var dialog = null;

    // Close the alert panel if we click outside it
    var close_dialog_outside = function(e) {
        if ($(e.target).closest('#alertdialog').length == 0) {
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

    var alert_refresh = function() {
        $.get("/alerts/last-time/" + last_time + "/alerts.json")
        .done(function(data) {

        })
        .always(function() {
            timerid = setTimeout(alert_refresh, 1000);
        });

    }

    $.fn.alert = function(data, inopt) {
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

        var link = $('a.alertbutton', this);

        if (link.length != 0) {
            link.empty();
        } else {
            link = $('<a>', {
                href: "#",
                class: "alertbutton"
            })
            .on('click', function(e) {
                if (dialog != null) {
                    e.stopImmediatePropagation();
                    return;
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
                    )
                    .append(
                        $('<div>', {
                            class: "ka-dialog-footer"
                        })
                        .append(
                            $('<span>', {
                                class: "ka-bottom-text"
                            })
                            .text("No previous alerts")
                        )
                    );

                var nominal_w = 400;
                var nominal_h = ($(window).height() / 3) * 2;

                // Position under the element
                var off_y = (nominal_h / 2) + (element.outerHeight() / 2) + 3;

                // left-ish of the icon
                var off_x = (nominal_w / 3);
                off_x *= -1;

                // Where the outer border lands
                var outerborder = off_x + (nominal_w / 2);

                dialog = $.jsPanel({
                    id: "alertdialog",
                    headerRemove: true,
                    position: {
                        of: element,
                        offsetY: off_y,
                        offsetX: off_x
                    },
                    contentSize: {
                        width: nominal_w,
                        height: nominal_h
                    },
                    content: alert_popup_content,
                });

                $("body").on("click", close_dialog_outside);

                e.stopImmediatePropagation();
            });
        }

        link.append(alertholder);
        element.append(link);

        alert_refresh();
    };

}(jQuery));
