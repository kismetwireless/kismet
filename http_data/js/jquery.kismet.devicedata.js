// Map a json struct into a simple table

/* Fields is an array, processed in order, of:
    {
        "field": "..." // Field spec
        "title": "..." // title text

        // Optional function for filtering if we display this entity, returns
        // boolean for display
        "filter": function(key, data, value) { return bool }

        Subgroups (nested table of a subset of fields)

        // Indicates we have a subgroup.  Title is string, or function
        // returning a string
        "groupTitle": string | function(key, data, value)
        "fields": [...] // Additional nested fields w/in the subgroup

        Iterative groups (vectors and dictionaries of multiple values,
        the fields group is applied to each index
        "groupIterate": boolean // Do we iterate over an index of the field
        and apply fields to each?
        "iterateTitle": string|function(key, data, value, index) // Fixed string
        or optional function for each index
        "fields": [...] // Additional nested fields which will be indexed 
        and grouped.

        When using iterator groups, field references should be based on the 
        inner fields, ie a top-level array field of foo.bar.array containing
        foo.bar.array[x].val1, foo.bar.array[x].val2, the sub group of 
        fields should reference fields as 'val1' and 'val2' to get automatically
        indexed by reference

        // Optional string or function for rendering that should return html, taking
        // the original key, data, and resolved value
        "render": string | function(key, data, value) {}  

        // Optional function for

        "emtpy": "..." | function(key, data, value) 
        // Text to be substituted when there is no value
        
    }
*/

(function ($) {
    $.fn.devicedata = function(data, options) {
        var settings = $.extend({
            "stripe": true,
            "id": "kismetDeviceData",
            "fields": [],
            "span": false,
            "baseobject": "",
        }, options);

        var subtable = $('table #' + settings['id'], this);

        // Do we need to make a table to hold our stuff?
        if (subtable.length == 0) {
            subtable = $('<table />', {
                    "id": settings['id'],
                    "class": "kismet_devicedata"
                });
            this.append(subtable);
        } else {
            subtable.empty();
        }

        settings.fields.forEach(function(v, index, array) {
            var id = (settings.baseobject + v['field']).replace(/[.\[\]\(\)]/g, '_');

            // Do we have a function for rendering this?
            var d = kismet.ObjectByString(data, settings.baseobject + v['field']);

            if ('filter' in v && typeof(v['filter']) === 'function') {
                if (!(v['filter'](v['field'], data, d))) {
                    return;
                }
            }

            // Do we have a sub-group or group list?
            if ('groupTitle' in v) {
                var drow = $('<tr />', {
                    "id": "tr_" + id
                });

                subtable.append(drow);

                drow.append($('<td />', {
                    "colspan": 2
                }));

                var cell = $('td:eq(0)', drow);

                var gt = "";

                if (typeof(v['groupTitle']) === 'string')
                    gt = v['groupTitle'];
                else if (typeof(v['groupTitle']) === 'function')
                    gt = v['groupTitle'](v['field'], data, d);

                cell.append($('<b class="devicedata_subgroup_header">' + gt + '</b>'));

                cell.append($('<br />'));
                cell.append($('<div />'));

                var contentdiv = $('div', cell);

                // Recursively fill in the div with the sub-settings
                contentdiv.devicedata(data, v);

                return;
            }

            // Iterative group
            if ('groupIterate' in v && v['groupIterate'] == true) {
                for (var idx in d) {
                    // If we have a title, make a span row for it
                    if ('iterateTitle' in v) {
                        var subid = (id + '[' + idx + ']').replace(/[.\[\]\(\)]/g, '_');

                        var drow = $('<tr />', {
                            "id": "tr_" + subid
                        });

                        subtable.append(drow);

                        drow.append($('<td />', {
                            "colspan": 2
                        }));

                        var cell = $('td:eq(0)', drow);

                        var it = "";

                        if (typeof(v['iterateTitle']) === 'string')
                            it = v['iterateTitle'];
                        else if (typeof(v['iterateTitle']) === 'function')
                            it = v['iterateTitle'](v['field'], data, d, idx);
                        
                        cell.append($('<b class="devicedata_subgroup_header">' + it + '</b>'));

                        cell.append($('<br />'));
                    }

                    cell.append($('<div />'));

                    var contentdiv = $('div', cell);

                    // index the subobject
                    v['baseobject'] = v['field'] + '[' + idx + ']' + '.';
                    
                    contentdiv.devicedata(data, v);
                }
            }

            // Standard row
            var drow = $('<tr />', {
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

            var td;

            if (v["span"]) {
                td = $('td:eq(0)', drow);
            } else {
                $('td:eq(0)', drow).html(v['title']);
                td = $('td:eq(1)', drow);
            }

            if ('render' in v) {
                if (typeof(v['render']) === 'function') {
                    td.html(v['render'](v['field'], data, d));
                } else if (typeof(v['render']) === 'string') {
                    td.html(v['render']);
                }
            } else {
                if ('empty' in v && 
                        (typeof(d) === 'undefined' ||
                        (typeof(d) !== 'undefined' && d.length == 0))) {
                    if (typeof(v['empty']) === 'string')
                        td.html(v['empty']);
                    else if (typeof(v['empty']) === 'function')
                        td.html(v['empty'](v['field'], data, d));
                } else if ('zero' in v &&
                        (typeof(d) === 'undefined' ||
                         (typeof(d) === 'number' && d == 0))) {
                    if (typeof(v['zero']) === 'string')
                        td.html(v['zero']);
                    else if (typeof(v['zero']) === 'function')
                        td.html(v['zero'](v['field'], data, d));
                } else {
                    td.html(d);
                }
            }

            // Apply the draw function after the row is created
            if ('draw' in v && typeof(v.draw) === 'function') 
                v.draw(v['field'], data, kismet.ObjectByString(data, v['field']), td);

        });
    };
}(jQuery));
