// GPS status and window
//
// Requires js-storage and jquery be loaded prior
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

    var gpsicon = null;

    var gpsclick = null;

    // Last time from the server
    var last_time = 0;

    var dialog = null;

    var last_gps = null;

    // Close the alert panel if we click outside it
    var close_dialog_outside = function(e) {
        if (e == null ||
            (e != null && $(e.target).closest('#gpsdialog').length == 0)) {

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

        var gps_popup_content

        if (fullscreen)
            $('.kg-header-close', gps_popup_content).show();

        dialog = $.jsPanel({
            id: "gpsdialog",
            headerRemove: true,
            position: pos,
            contentSize: {
                width: nominal_w,
                height: nominal_h
            },
            content: gps_popup_content,
        });

        $("body").on("click", close_dialog_outside);

        e.stopImmediatePropagation();
    }

    var gps_refresh = function() {
        $.get("/gps/location.json")
        .done(function(data) {
            last_gps = data;

            if (last_gps == null ||
                (last_gps != null && last_gps['kismet.common.location.valid'] == 0) ||
                (last_gps != null && last_gps['kismet.common.location.fix'] < 2)) {
                gpsicon.removeClass('kg-icon-3d');
                gpsicon.removeClass('kg-icon-2d');
                element.tooltipster('content', 'GPS connection lost...');
                return;
            } else if (last_gps['kismet.common.location.fix'] == 2) {
                gpsicon.removeClass('kg-icon-3d');
                gpsicon.addClass('kg-icon-2d');
                element.tooltipster('content', '2d GPS location');
            } else if (last_gps['kismet.common.location.fix'] == 3) {
                gpsicon.removeClass('kg-icon-2d');
                gpsicon.addClass('kg-icon-3d');
                element.tooltipster('content', '3d GPS location');
            }
        })
        .always(function() {
            timerid = setTimeout(gps_refresh, 1000);
        });
    }

    $.fn.gps = function(data, inopt) {
        // Get the stored value if one exists
        storage = Storages.localStorage;

        element = $(this);

        element.addClass('kg-top-icon');

        options = $.extend(base_options, inopt);

        gpsicon = $('i.icon', this);
        if (gpsicon.length == 0) {
            gpsicon = $('<i>', {
                class: "icon fa fa-crosshairs kg-icon-base"
            });
        }

        gpsclick = $('a.gpsbutton', this);

        if (gpsclick.length != 0) {
            gpsclick.empty();
        }

        gpsclick = $('<a>', {
            href: "#",
            class: "gpsbutton"
        })
        .on('click', open_dialog);

        gpsclick.append(gpsicon);
        element.append(gpsclick);

        element.tooltipster({
            maxWidth: 450
        });

        gps_refresh();
    };

}(jQuery));
