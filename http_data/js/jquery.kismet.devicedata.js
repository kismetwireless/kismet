// Map a json struct into a simple table

/* Fields is an array, processed in order, of:
    {
        "field", "..." // Field spec
        "title", "..." // title text
        "render", function(key, data) {}  // Optional function for rendering that should return html
    }
*/

(function ($) {
    $.fn.devicedata = function(data, options) {
        var settings = $.extend({
            "stripe": true,
            "fields": {},
        }, options);

        var subtable = $('table #kismetDeviceData', this);

        // Do we need to make a table to hold our stuff?
        if (subtable.length == 0) {
            subtable = $('<table />', {
                    "id": "kismetDeviceData"
                });
            this.append(subtable);
        }

        settings.fields.forEach(function(v, index, array) {
            var drow = $('#' + v['field'], subtable);

            if (drow.length == 0) {
                drow = $('<tr />', {
                    "id": v['field']
                });
                drow.append('<td /><td />');

                subtable.append(drow);
            } else {
                console.log("existing row?");
            }

            console.log(drow);

            $('td:eq(0)', drow).html(v['title']);

            // Do we have a function for rendering this?
            if ('render' in v && typeof(v['render']) == "function") {
                $('td:eq(1)', drow).html(v['render'](v['field'], data));
            } else {
                $('td:eq(1)', drow).html(data[v['field']]);
            }

        });

    };
}(jQuery));
