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

        element.addClass('kis_alert_icon');

        options = $.extend(base_options, inopt);

        alertbg = $('i.background', this);
        if (alertbg.length == 0) {
            alertbg = $('<i>', {
                class: "background fa fa-square fa-stack-2x kis_alert_bg_normal"
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
                class: "number fa fa-fw fa-inverse"
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
        //alertholder.append(alertnum);

        element.append(alertholder);

        alert_refresh();
    };

}(jQuery));
