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
    var local_uri_prefix = "";
    if (typeof(KISMET_URI_PREFIX) !== 'undefined')
        local_uri_prefix = KISMET_URI_PREFIX;

    var base_options = {
        use_color: true,
    };

    var options = base_options;

    var timerid = -1;

    var element = null;

    var gpsicon = null;

    var gpstext = null;
    var gpslat = null;
    var gpslon = null;
    var gpsx = null;

    var gpsclick = null;

    // Last time from the server
    var last_time = 0;

    var dialog = null;

    var last_gps = null;

    var gps_popup_content =
	    $('<div>', {
            style: 'padding: 2px;'
        })
            .append(
                $('<div>', {
                    id: 'gpsstatus',
                    style: 'padding-bottom: 2px;'
                })
            )
            .append(
                $('<table>', {
                    id: "gpsstatustable"
                })
                .append(
                    $('<tr>')
                    .append(
                        $('<td>').html('Time')
                    )
                    .append(
                        $('<td>', {
                            id: 'time'
                        }).html("n/a")
                    )
                )
                .append(
                    $('<tr>')
                    .append(
                        $('<td>').html('Location')
                    )
                    .append(
                        $('<td>', {
                            id: 'location'
                        }).html("n/a")
                    )
                )
                .append(
                    $('<tr>')
                    .append(
                        $('<td>').html('Speed')
                    )
                    .append(
                        $('<td>', {
                            id: 'speed'
                        }).html("n/a")
                    )
                )
                .append(
                    $('<tr>')
                    .append(
                        $('<td>').html('Heading')
                    )
                    .append(
                        $('<td>', {
                            id: 'heading'
                        }).html("n/a")
                    )
                )
                .append(
                    $('<tr>')
                    .append(
                        $('<td>').html('Altitude')
                    )
                    .append(
                        $('<td>', {
                            id: 'altitude'
                        }).html("n/a")
                    )
                )
            );

    // Close the alert panel if we click outside it
    var close_dialog_outside = function(e) {
        if (e == null ||
            (e != null && $(e.target).closest('#gpsdialog').length == 0)) {

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

        if (last_gps == null ||
            (last_gps != null &&
                (last_gps['kismet.common.location.fix'] < 2))) {
                    $('#gpsstatus', gps_popup_content).html('No GPS available');
                    $('#time', gps_popup_content).html('n/a');
                    $('#location', gps_popup_content).html('n/a');
                    $('#speed', gps_popup_content).html('n/a');
                    $('#heading', gps_popup_content).html('n/a');
                    $('#altitude', gps_popup_content).html('n/a');
                }

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

    var gps_refresh = function(data) {
        if (kismet.getStorage('kismet.ui.gps.icon') === 'False') {
            gpsicon.hide();
        } else {
            gpsicon.show();
        }

        if (kismet.getStorage('kismet.ui.gps.text') === 'False') {
            gpstext.hide();
        } else {
            gpstext.show();
        }

        if (kismet.getStorage('kismet.ui.gps.stack', true)) {
            gpstext.removeClass('gps-side-by-side');
            gpstext.addClass('gps-dual-stack');
            gpsx.hide();
        } else {
            gpstext.addClass('gps-side-by-side');
            gpstext.removeClass('gps-dual-stack');
            gpsx.show();
        }

        data = kismet.sanitizeObject(data);

        last_gps = data;

        var d = "Unknown"
        try {
            d = new Date(last_gps['kismet.common.location.time_sec']*1000).toISOString();
        } catch (e) {
            ;
        }

        if (last_gps?.['kismet.common.location.fix'] >= 2) {
            if (last_gps['kismet.common.location.fix'] == 2) {
                $('#gpsstatus', gps_popup_content).html('GPS locked (2d)');
                $('#altitude', gps_popup_content).html('n/a');
            } else {
                $('#gpsstatus', gps_popup_content).html('GPS locked (3d)');
                $('#altitude', gps_popup_content).html(kismet_ui.renderDistance(last_gps['kismet.common.location.alt'] / 1000, 0));
            }

            $('#time', gps_popup_content).html(d);
            $('#location', gps_popup_content).html(last_gps['kismet.common.location.geopoint'][1] + " x " + last_gps['kismet.common.location.geopoint'][0]);
            $('#speed', gps_popup_content).html(kismet_ui.renderSpeed(last_gps['kismet.common.location.speed']));
            $('#heading', gps_popup_content).html(last_gps['kismet.common.location.heading']);
        } else {
            $('#gpsstatus', gps_popup_content).html('No GPS available');
            $('#time', gps_popup_content).html('n/a');
            $('#location', gps_popup_content).html('n/a');
            $('#speed', gps_popup_content).html('n/a');
            $('#heading', gps_popup_content).html('n/a');
            $('#altitude', gps_popup_content).html('n/a');
        }

        if (last_gps == null ||
            (last_gps != null && last_gps['kismet.common.location.fix'] < 2)) {
            gpsicon.removeClass('kg-icon-3d');
            gpsicon.removeClass('kg-icon-2d');
            element.tooltipster('content', 'GPS connection lost...');

            gpstext.addClass('gpstext_lost');
            gpslat.html(0);
            gpslon.html(0);

            return;
        } else if (last_gps['kismet.common.location.fix'] == 2) {
            gpsicon.removeClass('kg-icon-3d');
            gpsicon.addClass('kg-icon-2d');
            element.tooltipster('content', 'GPS fix' +  last_gps['kismet.common.location.geopoint'][1] + ' x ' +
                last_gps['kismet.common.location.geopoint'][0]);

            gpstext.removeClass('gpstext_lost');
            gpslat.html(kismet.censorLocation[last_gps['kismet.common.location.geopoint'][1]]);
            gpslon.html(kismet.censorLocation[last_gps['kismet.common.location.geopoint'][0]]);

            // gpstext.html(kismet.censorLocation(last_gps['kismet.common.location.geopoint'][1]) + " x " + kismet.censorLocation(last_gps['kismet.common.location.geopoint'][0]));
        } else if (last_gps['kismet.common.location.fix'] == 3) {
            gpsicon.removeClass('kg-icon-2d');
            gpsicon.addClass('kg-icon-3d');
            element.tooltipster('content', 'GPS fix ' +
                last_gps['kismet.common.location.geopoint'][1] + ' x ' +
                last_gps['kismet.common.location.geopoint'][0] + ' ' +
                kismet_ui.renderDistance(last_gps['kismet.common.location.alt'] / 1000, 0));

            gpstext.removeClass('gpstext_lost');
            gpslat.html(kismet.censorLocation(last_gps['kismet.common.location.geopoint'][1]));
            gpslon.html(kismet.censorLocation(last_gps['kismet.common.location.geopoint'][0]));
        }
    }

    $.fn.gps = function(data, inopt) {
        // Get the stored value if one exists
        storage = Storages.localStorage;

        element = $(this);

        element.addClass('kg-top-icon');

        options = $.extend(base_options, inopt);

        let holder=$('<div class="gps-side-by-side"></div>');

        gpsicon = $('i.icon', this);
        if (gpsicon.length == 0) {
            gpsicon = $('<i>', {
                class: "icon fa fa-crosshairs kg-icon-base"
            });
        }

        gpstext = $('#gps-topbar-text-holder', this);
        if (gpstext.length == 0) {
            gpstext = $('<div id="#gps-topbar-text-holder" class="gpstext"></div>');
        }

        gpslat = $('#gps-toolbar-lat', this);
        if (gpslat.length == 0) {
            gpslat = $('<div id="gps-toolbar-lat">Unknown</div>');
            gpstext.append(gpslat);
        }

        gpsx = $('#gps-toolbar-x', this);
        if (gpsx.length == 0) {
            gpsx = $('<div id="gps-toolbar-x" class="gps-toolbar-x">x</div>');
            gpstext.append(gpsx);
        }

        gpslon = $('#gps-toolbar-lon', this);
        if (gpslon.length == 0) {
            gpslon = $('<div id="gps-toolbar-lon">Unknown</div>');
            gpstext.append(gpslon);
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

        if (kismet.getStorage('kismet.ui.gps.icon') === 'False') {
            gpsicon.hide();
        }

        if (kismet.getStorage('kismet.ui.gps.text') === 'False') {
            gpstext.hide();
        }

        if (kismet.getStorage('kismet.ui.gps.stack', true)) {
            gpstext.removeClass('gps-side-by-side');
            gpstext.addClass('gps-dual-stack');
            gpsx.hide();
        } else {
            gpstext.addClass('gps-side-by-side');
            gpstext.removeClass('gps-dual-stack');
            gpsx.show();
        }

        gpsclick.append(gpstext);
        gpsclick.append(gpsicon);

        holder.append(gpsclick);
        element.append(holder);

        element.tooltipster({
            maxWidth: 450
        });

        $.get(local_uri_prefix + "gps/location.json")
            .done(function(data) {
                gps_refresh(data);
            });

        kismet_ui_base.SubscribeEventbus("GPS_LOCATION", [], function(data) {
            gps_refresh(data);
        });
    };

}(jQuery));
