// Map a json struct into a simple table

/* Fields is an array, processed in order, of:
    {
        "field": "..." // Field spec
        "title": "..." // title text
        "groupTitle": "..." // This will be a sub-group, which is a new
            table made from this keys id, fields, etc records
        // Optional function for rendering that should return html, taking
        // the original key, data, and resolved value
        "render": function(key, data, value) {}  
        "emtpy": "..." // Text to be substituted when there is no value
        // Optional function for filtering if we display this entity, returns
        // boolean for display
        "filter": function(key, data, value) {}
    }
*/

(function ($) {
    $.fn.devicedata = function(data, options) {
        var settings = $.extend({
            "stripe": true,
            "id": "kismetDeviceData",
            "fields": [],
            "filter": null,
        }, options);

        var subtable = $('table #kismetDeviceData', this);

        // Do we need to make a table to hold our stuff?
        if (subtable.length == 0) {
            subtable = $('<table />', {
                    "id": settings['id'],
                    "border": settings['border'],
                    "class": "kismet_devicedata"
                });
            this.append(subtable);
        }

        settings.fields.forEach(function(v, index, array) {
            // Do we have a function for rendering this?
            var d = kismet.ObjectByString(data, v['field']);

            if ('filter' in v && typeof(v['filter']) === 'function') {
                if (!(v['filter'](v['field'], data, d))) {
                    return;
                }
            }

            // Find the row if it exists
            var drow = $('#' + v['field'], subtable);

            // Do we have a sub-group?
            if ('groupTitle' in v) {
                if (drow.length == 0) {
                    drow = $('<tr />', {
                        "id": v['field']
                    });

                    drow.append($('<td />', {
                        "colspan": 2
                    }));

                    subtable.append(drow);
                }

                var cell = $('td:eq(0)', drow);

                cell.append($('<b />', {
                        'html': v['groupTitle']
                }));

                cell.append($('<br />'));
                cell.append($('<div />'));

                var contentdiv = $('div', cell);

                // Recursively fill in the div with the sub-settings
                contentdiv.devicedata(data, v);

                return;

            }

            // Standard row
            if (drow.length == 0) {
                drow = $('<tr />', {
                    "id": v['field']
                });
                drow.append($('<td /><td />'));

                subtable.append(drow);
            } else {
                console.log("existing row?");
            }

            $('td:eq(0)', drow).html(v['title']);

            if ('render' in v && typeof(v['render']) === 'function') {
                $('td:eq(1)', drow).html(v['render'](v['field'], data, d));
            } else {
                if ('empty' in v && typeof(d) === 'undefined' ||
                        (typeof(d) !== 'undefined' && d.length == 0)) {
                    $('td:eq(1)', drow).html(v['empty'])
                } else {
                    $('td:eq(1)', drow).html(d);
                }
            }

        });

    };
}(jQuery));
