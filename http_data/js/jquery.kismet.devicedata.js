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
            "span": false,
        }, options);

        var subtable = $('table #' + settings['id'], this);

        // Do we need to make a table to hold our stuff?
        if (subtable.length == 0) {
            subtable = $('<table />', {
                    "id": settings['id'],
                    "class": "kismet_devicedata"
                });
            this.append(subtable);
            console.log(subtable);
        }

        settings.fields.forEach(function(v, index, array) {
            var id = v['field'].replace(/[.\[\]\(\)]/g, '_');

            // Do we have a function for rendering this?
            var d = kismet.ObjectByString(data, v['field']);

            if ('filter' in v && typeof(v['filter']) === 'function') {
                if (!(v['filter'](v['field'], data, d))) {
                    return;
                }
            }

            // Find the row if it exists
            var drow = $('#tr_' + id, subtable);

            // Do we have a sub-group?
            if ('groupTitle' in v) {
                if (drow.length == 0) {
                    drow = $('<tr />', {
                        "id": "tr_" + id
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
                    "id": "tr_" + id,
                });

                if (v["span"]) {
                    drow.append($('<td />', {
                        "colspan": 2,
                        "class": "span"
                    }));
                } else {
                    drow.append($('<td /><td />'));
                }

                subtable.append(drow);
            } else {
                console.log("existing row?");
            }

            var td;

            if (v["span"]) {
                td = $('td:eq(0)', drow);
            } else {
                $('td:eq(0)', drow).html(v['title']);
                td = $('td:eq(1)', drow);
            }

            if ('render' in v && typeof(v['render']) === 'function') {
                td.html(v['render'](v['field'], data, d));
            } else {
                if ('empty' in v && typeof(d) === 'undefined' ||
                        (typeof(d) !== 'undefined' && d.length == 0)) {
                    td.html(v['empty']);
                } else {
                    td.html(d);
                }
            }

            // Apply the draw function after the row is created
            if ('draw' in v && typeof(v.draw) === 'function') 
                v.draw(v['field'], data, kismet.ObjectByString(data, v['field']), td);

        });

        /*
        var drawloop = function(settings, container) {
            settings.fields.forEach(function(v, index, array) {
                var id = v['field'].replace(/[.\[\]\(\)]/g, '_');

                // Find the row if it exists
                var drow = $('#' + id, container);

                // Skip any we can't find
                if (drow.length == 0)
                    return;

                if ('draw' in v && typeof(v.draw) === 'function') 
                    v.draw(v['field'], data, kismet.ObjectByString(data, v['field']), drow);

                if ('fields' in v) {
                    console.log("Looking for #" + settings["id"]);
                    console.log(container);

                    var subtable = $('table #' + settings["id"], container);

                    console.log(subtable);

                    // Bail if we can't find the subtable
                    if (subtable.length == 0) {
                        console.log("Failed to find table in draw");
                        return;
                    }

                    drawloop(v, subtable);
                }
            });
        }

        // Initiate a recursive loop calling the draw function
        drawloop(settings, this);
        */

    };
}(jQuery));
