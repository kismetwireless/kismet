// Map a json struct into a simple table

/* Fields is an array, processed in order, of:
    {
        "field": "..." // Field spec
        "title": "..." // title text

        // Options will contain AT LEAST
        // 'key' - current field key
        // 'data' - current data
        // 'value' - resolved value
        // 'basekey' - string key of base in an iteration
        // 'base' - resolved object base
        // and may also include
        // 'index' - iteration index
        // 'container' - parent container for draw functions

        // Optional function for filtering if we display this entity, returns
        // boolean for display.  
        "filter": function(opts) { return bool }

        // Optional shortcut filters for common filtering options
        "filterOnEmpty": boolean // Filter this row if the value does not exist,
        or exists, is a string, and is empty ('')
        "filterOnZero": boolean // Filter this row if the value does not exist,
        or exists, is a number, and is equal to 0

        Subgroups (nested table of a subset of fields)

        // Indicates we have a subgroup.  Title is string, or function
        // returning a string
        "groupTitle": string | function(opts)
        "fields": [...] // Additional nested fields w/in the subgroup

        Iterative groups (vectors and dictionaries of multiple values,
        the fields group is applied to each index
        "groupIterate": boolean // Do we iterate over an index of the field
        and apply fields to each?
        "iterateTitle": string|function(opts) // Fixed string
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
        "render": string | function(opts) {}  

        // Optional function for

        "emtpy": string | function(opts) 
        // Text to be substituted when there is no value
        
    }
*/

(function ($) {
    $.fn.devicedata = function(data, options) {
        var settings = $.extend({
            "stripe": true,
            "id": "kismetDeviceData",
            "fields": [],
            "baseobject": "",
        }, options);

        var subtable = $('table #' + settings['id'], this);

        // Do we need to make a table to hold our stuff?
        if (subtable.length == 0) {
            subtable = $('<table />', {
                    "id": settings['id'],
                    "class": "kismet_devicedata",
                    "width": "100%",
                });
            this.append(subtable);
        } else {
            subtable.empty();
        }

        settings.fields.forEach(function(v, index, array) {
            var id = (settings.baseobject + v['field']).replace(/[.\[\]\(\)]/g, '_');

            // Do we have a function for rendering this?
            var d = kismet.ObjectByString(data, settings.baseobject + v['field']);

            var callopts = {
                key: v['field'],
                basekey: settings.baseobject,
                base: kismet.ObjectByString(data, settings.baseobject),
                data: data,
                value: d
            };

            if ('index' in settings) {
                callopts['index'] = settings['index'];
            }

            if ('filter' in v && typeof(v['filter']) === 'function') {
                if (!(v['filter'](callopts))) {
                    return;
                }
            }

            if ('filterOnEmpty' in v && v['filterOnEmpty'] && 
                    (typeof(d) === 'undefined' ||
                     (typeof(d) === 'string' && d.length == 0))) {
                return;
            }

            if ('filterOnZero' in v && v['filterOnZero'] &&
                    (typeof(d) === 'undefined' ||
                     (typeof(d) === 'number' && d == 0))) {
                return;
            }

            // Do we have a sub-group or group list?
            if ('groupTitle' in v) {
                var drow = $('<tr class="kismet_devicedata_grouptitle" />', {
                    "id": "tr_" + id
                });

                subtable.append(drow);

                drow.append($('<td />', {
                    "class": "kismet_devicedata_span",
                    "colspan": 2
                }));

                var cell = $('td:eq(0)', drow);

                var gt = "";

                if (typeof(v['groupTitle']) === 'string')
                    gt = v['groupTitle'];
                else if (typeof(v['groupTitle']) === 'function')
                    gt = v['groupTitle'](callopts);

                cell.append($('<b class="devicedata_subgroup_header">' + gt + '</b>'));

                cell.append($('<br />'));
                cell.append($('<div />'));

                var contentdiv = $('div', cell);

                // Recursively fill in the div with the sub-settings
                contentdiv.devicedata(data, v);

                // Apply the draw function after the subgroup is created
                if ('draw' in v && typeof(v.draw) === 'function') {
                    callopts['container'] = cell;

                    v.draw(callopts);
                }

                return;
            }

            // Iterative group
            if ('groupIterate' in v && v['groupIterate'] == true) {
                for (var idx in d) {
                    callopts['index'] = idx;
                    callopts['basekey'] = v['field'] + '[' + idx + ']' + '.';
                    callopts['base'] = kismet.ObjectByString(data, callopts['basekey']);

                    // If we have a title, make a span row for it
                    if ('iterateTitle' in v) {
                        var subid = (id + '[' + idx + ']').replace(/[.\[\]\(\)]/g, '_');

                        var drow = $('<tr class="kismet_devicedata_groupdata" />', {
                            "id": "tr_" + subid
                        });

                        subtable.append(drow);

                        drow.append($('<td />', {
                            "class": "kismet_devicedata_span",
                            "colspan": 2
                        }));

                        var cell = $('td:eq(0)', drow);

                        var it = "";

                        if (typeof(v['iterateTitle']) === 'string')
                            it = v['iterateTitle'];
                        else if (typeof(v['iterateTitle']) === 'function')
                            it = v['iterateTitle'](callopts);

                        cell.append($('<b class="devicedata_subgroup_header">' + it + '</b>'));

                        cell.append($('<br />'));
                    }

                    cell.append($('<div />'));

                    var contentdiv = $('div', cell);

                    // index the subobject
                    v['baseobject'] = v['field'] + '[' + idx + ']' + '.';
                    v['index'] = idx;

                    contentdiv.devicedata(data, v);

                    // Apply the draw function after the iterative group is processed
                    if ('draw' in v && typeof(v.draw) === 'function') {
                        callopts['container'] = cell;

                        v.draw(callopts);
                    }

                }

                return;
            }

            // Standard row
            var drow = $('<tr />', {
                "id": "tr_" + id,
            });

            if (v["span"]) {
                drow.append($('<td />', {
                    "colspan": 2,
                    "class": "kismet_devicedata_span"
                }));
            } else {
                drow.html('<td class="kismet_devicedata_td_title" /><td class="kismet_devicedata_td_content" />');
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
                    td.html(v['render'](callopts));
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
                        td.html(v['empty'](callopts));
                } else if ('zero' in v &&
                        (typeof(d) === 'undefined' ||
                         (typeof(d) === 'number' && d == 0))) {
                    if (typeof(v['zero']) === 'string')
                        td.html(v['zero']);
                    else if (typeof(v['zero']) === 'function')
                        td.html(v['zero'](callopts));
                } else {
                    td.html(d);
                }
            }

            // Apply the draw function after the row is created
            if ('draw' in v && typeof(v.draw) === 'function') {
                callopts['container'] = td;

                v.draw(callopts);
            }
        }
        );
    };
}(jQuery));
