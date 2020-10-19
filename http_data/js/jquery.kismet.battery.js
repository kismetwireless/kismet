// Display the battery status
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

    var timetext;
    var baticon;
    var batoverlay;

    var batinfo_refresh = function(data) {
        data = kismet.sanitizeObject(data);

        baticon.removeClass("fa-refresh");
        baticon.removeClass("fa-spin");
        baticon.removeClass("fa-battery-0");
        baticon.removeClass("fa-battery-1");
        baticon.removeClass("fa-battery-2");
        baticon.removeClass("fa-battery-3");
        baticon.removeClass("fa-battery-4");
        baticon.removeClass("fa-plug");

        var p = data['kismet.system.battery.percentage'];
        var c = data['kismet.system.battery.charging'];
        var a = data['kismet.system.battery.ac'];

        if (c === 'charging') {
            timetext.text("Charging " + p + "% ");
            timetext.show();

            batoverlay.show();
            batoverlay.addClass("battery-blink");

            if (p < 25)
                baticon.addClass("fa-battery-0");
            else if (p < 50)
                baticon.addClass("fa-battery-1");
            else if (p < 75)
                baticon.addClass("fa-battery-2");
            else if (p < 90)
                baticon.addClass("fa-battery-3");
            else
                baticon.addClass("fa-battery-4");
        } else if (c === 'discharging') {
            batoverlay.hide();

            if (p < 25)
                baticon.addClass("fa-battery-0");
            else if (p < 50)
                baticon.addClass("fa-battery-1");
            else if (p < 75)
                baticon.addClass("fa-battery-2");
            else if (p < 90)
                baticon.addClass("fa-battery-3");
            else
                baticon.addClass("fa-battery-4");

            var s = data['kismet.system.battery.remaining'];

            if (s > 0) {
                var h = Math.floor(s / 3600);
                s -= 3600 * h;
                var m = Math.floor(s / 60);
                s -= 60 * m;

                if (m < 10)
                    m = '0' + m

                timetext.text(p + "% " + h + "h " + m + "m");
            } else {
                timetext.text(p + "%");
            }

            timetext.show();
        } else if (a == 1 && p == 0) {
            timetext.hide();
            baticon.addClass("fa-plug");
            batoverlay.hide();
        } else if (c === 'charged') {
            batoverlay.show();
            batoverlay.removeClass("battery-blink")
            baticon.addClass("fa-battery-4");
            timetext.text("Charged");
            timetext.show();
        } else {
            timetext.text("Unknown");
            timetext.show();
            baticon.addClass("fa-battery-0");
            batoverlay.hide();
        }

    };

    $.fn.battery = function(data, inopt) {
        element = $(this);

        options = $.extend(base_options, inopt);

        // Build the text and hide it
        timetext = $('span.battime', this);
        if (timetext.length == 0) {
            timetext = $('<span>', {
                class: "battime"
            }).text("00:00:00");

            element.append(timetext);
            timetext.hide();
        }

        // Build the icon, set as a spinner first
        var batholder = $('span.batholder-stack', this);

        if (batholder.length == 0) {
            batholder = $('<span>', {
                class: "fa-stack batholder-stack"
            });

            baticon = $('<i>', {
                class: "batpower fa fa-stack-1x fa-refresh fa-spin",
            });

            batholder.append(baticon);

            batoverlay = $('<i>', {
                class: "batpoweroverlay fa fa-stack-1x fa-bolt fa-inverse"
            });
            batholder.append(batoverlay);
            batoverlay.hide();

            element.append(batholder);
        }

        $.get(local_uri_prefix + "system/status.json")
        .done(function(data) {
            batinfo_refresh(data);
        });

        kismet_ui_base.SubscribeEventbus("BATTERY", [], function(data) {
            batinfo_refresh(data);
        });
    };

}(jQuery));
