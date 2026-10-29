// Display the messagebus message system from Kismet
//
// dragorn@kismetwireless.net
// MIT/GPL License (pick one); the web ui code is licensed more
// freely than GPL to reflect the generally MIT-licensed nature
// of the web/jquery environment

// Options:
// use_color (bool) (true) - Colorize messages
// scroll (bool) (true) - Make scrollable
// max_messages (int) (30) - Maximum messages to show
// old_time (int) (30) - How long before a message is considered 'old'
// class_debug (string) (messagebus_debug) - Display class applied to debug msgs
// class_info (string) (messagebus_info) - Display class applied to info msgs
// class_error (string) (messagebus_error) - Display class applied to error msgs
// class_alert (string) (messagebus_alert) - Display class applied to alert msgs
// class_fatal (string) (messagebus_fatal) - Display class applied to fatal msgs
// class_old (string) (messagebus_old) - Display class applied to old msgs
//

(function ($) {
    var local_uri_prefix = "";
    if (typeof(KISMET_URI_PREFIX) !== 'undefined')
        local_uri_prefix = KISMET_URI_PREFIX;

    // Message flags
    var MSGFLAG_NONE = 0;
    var MSGFLAG_DEBUG = 1;
    var MSGFLAG_INFO = 2;
    var MSGFLAG_ERROR = 4;
    var MSGFLAG_ALERT = 8;
    var MSGFLAG_FATAL = 16;

    var base_options = { 
        use_color: true,
        scroll: true,
        max_messages: 30,
        class_debug: "messagebus_debug",
        class_info: "messagebus_info",
        class_error: "messagebus_error",
        class_alert: "messagebus_alert",
        class_fatal: "messagebus_fatal",
        class_old: "messagebus_old",
    };

    var merge_messages = function(state, messages) {
        var divs = $('div.messagebus_message', state['element']);

        $.merge(messages, state['message_list']);

        state['message_list'] = messages.slice(0, state['options'].max_messages);

        for (var x = 0; x < state['message_list'].length; x++) {
            var d = divs.eq(x);

            // Compute trimmed date
            var ds = (new Date(state['message_list'][x]['kismet.messagebus.message_time'] * 1000).toString()).substring(4, 25);

            /*
            var pse = $('<p>').text(ds);
            var ce = $('<span>').html(kismet.sanitizeHTML(kismet.censorMAC(state['message_list'][x]['kismet.messagebus.message_string'])));

            d.empty();
            d.append(pse);
            d.append(ce);
            */

            d.html(`<p>${ds}</p> ${kismet.censorMAC(state['message_list'][x]['kismet.messagebus.message_string'])}`);

            // Remove all flagged clases
            d.removeClass("messagebus_debug");
            d.removeClass("messagebus_info");
            d.removeClass("messagebus_error");
            d.removeClass("messagebus_alert");
            d.removeClass("messagebus_fatal");

            var f = state['message_list'][x]['kismet.messagebus.message_flags'];

            if (f & MSGFLAG_FATAL) {
                d.addClass("messagebus_fatal");
            } else if (f & MSGFLAG_ALERT) {
                d.addClass("messagebus_alert");
            } else if (f & MSGFLAG_ERROR) {
                d.addClass("messagebus_error");
            } else if (f & MSGFLAG_INFO) {
                d.addClass("messagebus_info");
            } else if (f & MSGFLAG_DEBUG) {
                d.addClass("messagebus_debug");
            }
        }
    }

    var messagebus_refresh = function(state) {
        $.get(local_uri_prefix + "messagebus/last-time/" + 
            state['last_msg_time'] + "/messages.json")
            .done(function(data) {
                data['kismet.messagebus.list'].reverse();

                merge_messages(state, kismet.sanitizeObject(data['kismet.messagebus.list']));
            })
    }

    $.fn.messagebus = function(inopt) {
        var state = {
            element: $(this),
            options: base_options,
            last_msg_time: 0,
            message_list: [],
            timerid: -1,
        };

        state['element'].empty();

        state['element'].addClass('messagebus');

        state['options'] = $.extend(base_options, inopt);

        // Fill the div with placeholders for as many messages as we need
        var ndiv = $('div.messagebus_message', state['element']).length;

        if (ndiv < state['options'].max_messages) {
            for (var x = ndiv; x < state['options'].max_messages; x++) {
                var d = $('<div>', { class: "messagebus_message" });
                state['element'].append(d);
            }
        } else if (ndiv > state['options'].max_messages) {
            var nremoved = 0;
            $('div.messagebus_message', state['element']).each(function() {
                if (ndiv - nremoved <= state['options'].max_messages) {
                    return;
                }

                $(this).remove();
                nremoved++;
            });
        }

        messagebus_refresh(state);

        kismet_ui_base.SubscribeEventbus("MESSAGE", [], function(data) {
            data = kismet.sanitizeObject(data);
            merge_messages(state, [data]);
        });

    };

}(jQuery));
