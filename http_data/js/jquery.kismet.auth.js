// Auth check
//
// Requires jquery be loaded prior
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

    var lockicon = null;

    var dialog = null;

    var open_dialog = function(e) {

    }

    var tooltip_locked = 
        $('<div>', { })
        .append(
            $('<p>', { })
            .html('Not currently logged in.  Some functions will be unavailable to you, such as downloading packet captures, changing the configuration of data sources, or other server configuration options.')
        );

    var tooltip_unlocked =
        $('<div>', {})
        .append(
            $('<p>', {})
            .html('Successfully logged in to Kismet')
        );

    var login_refresh = function() {
        kismet_ui_base.LoginCheck(function(success) {
            element.removeClass('fa-unlock-alt');
            element.removeClass('fa-lock');

            if (success) {
                element.addClass('fa-unlock-alt');
                element.tooltipster('content', tooltip_unlocked);
            } else {
                element.addClass('fa-lock');
                element.tooltipster('content', tooltip_locked);
            }

            timerid = setTimeout(login_refresh, 10000);
        });
    }


    $.fn.loginwatcher = function(data, inopt) {
        element = $(this);

        element.addClass('fa');
        element.addClass('fa-lock');
        element.addClass('k-lw-icon');
        element.tooltipster({
            content: tooltip_locked,
            maxWidth: 450
        });

        options = $.extend(base_options, inopt);

        login_refresh();
    };

}(jQuery));
