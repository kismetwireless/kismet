// Map a json struct into a simple table

/* Fields is an array, processed in order, of:
    {
        "field": "..." // Field spec
        "title": "..." // title text

        "help": "..." // Help / explanatory text

        Options will contain AT LEAST
        'key' - current field key
        'data' - current data
        'value' - resolved value
        'basekey' - string key of base in an iteration
        'base' - resolved object base
        and may also include
        'index' - iteration index
        'container' - parent container for draw functions
        'sanitize' - sanitize HTML of content, default true

        Optional function for filtering if we display this entity, returns
        boolean for display.  
        "filter": function(opts) { return bool }

        Optional shortcut filters for common filtering options
        "filterOnEmpty": boolean // Filter this row if the value does not exist,
        or exists, is a string, and is empty ('')
        "filterOnZero": boolean // Filter this row if the value does not exist,
        or exists, is a number, and is equal to 0

        Subgroups (nested table of a subset of fields)

        Indicates we have a subgroup.  Title is string, or function
        returning a string
        "groupTitle": string | function(opts)
        "fields": [...] // Additional nested fields w/in the subgroup

        Iterative groups (vectors and dictionaries of multiple values,
        the fields group is applied to each index
        "groupIterate": boolean // Do we iterate over an index of the field
        and apply fields to each?
        "iterateTitle": string|function(opts) // Fixed string
        or optional function for each index
        each index.
        "fields": [...] // Additional nested fields which will be indexed 
        and grouped.

        When using iterator groups, field references should be based on the 
        inner fields, ie a top-level array field of foo.bar.array containing
        foo.bar.array[x].val1, foo.bar.array[x].val2, the sub group of 
        fields should reference fields as 'val1' and 'val2' to get automatically
        indexed by reference

        // A storage object passed to render and draw in opts['storage'], for 
        // holding js-scope variables
        "storage": {}

        // Perform live updates on this field by calling draw() when new data is
        // available
        "liveupdate": bool

        // Optional string or function for rendering that should return html, taking
        // the original key, data, and resolved value; this is used to create any 
        // necessary wrapper objects.
        "render": string | function(opts) {}  

        // Optional function for drawing data, called repeatedly as data is updated; 
        // This function can return nothing and manipulate only the content it is
        // given, or it can return a string or object which replaces the current 
        // content of the cell
        "draw": function(opts) {}

        // Optional function for

        "emtpy": string | function(opts) 
        Text to be substituted when there is no value
    }
*/

(function ($) {
    function showitemhelp(item, title) {
        var h = $(window).height() / 3;
        var w = $(window).width() / 2;

        if (w < 450) 
            w = $(window).width() - 5;

        if (h < 200)
            h = $(window).height() - 5;

        $.jsPanel({
                id: "item-help",
                headerTitle: title,
                headerControls: {
                    controls: 'closeonly',
                    iconfont: 'jsglyph',
                },
                paneltype: 'modal',
                content: '<div style="padding: 10px;"><h3>' + title + '</h3><p>' + item['help'],
            })
            .resize({
                width: w,
                height: h
            })
            .reposition({
                my: 'center',
                at: 'center',
                of: 'window'
            });
    }

    function make_help_func(item, title) {
        return function() { showitemhelp(item, title); };
    }

    $.fn.devicedata = function(data, options) {
        var settings = $.extend({
            "stripe": true,
            "id": "kismetDeviceData",
            "fields": [],
            "baseobject": "",
            "sanitize": true,
            "storage": {},
        }, options);

        var subtable = $('table.kismet_devicedata#' + kismet.sanitizeId(settings['id']), this);

        // Do we need to make a table to hold our stuff?
        if (subtable.length == 0) {
            subtable = $('<table />', {
                    "id": kismet.sanitizeId(settings['id']),
                    "class": "kismet_devicedata",
                    "width": "100%",
                });
            this.append(subtable);
        }

        settings.fields.forEach(function(v, index, array) {
            var id;
            var liveupdate = false;

            if ('id' in v)
                id = kismet.sanitizeId(settings.baseobject + v['id']);
            else
                id = kismet.sanitizeId(settings.baseobject + v['field']);

            if ('liveupdate' in v)
                liveupdate = v['liveupdate'];

            // Do we have a function for rendering this?
            var d = kismet.ObjectByString(data, settings.baseobject + v['field']);

            var callopts = {
                key: v['field'],
                basekey: settings.baseobject,
                base: kismet.ObjectByString(data, settings.baseobject),
                data: data,
                value: d,
                id: id,
                storage: settings['storage']
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
                     (typeof(d) === 'number' && d == 0) ||
                     typeof(d) === 'string' && d === '0')) {
                return;
            }

            // Do we have a sub-group or group list?
            if ('groupTitle' in v) {
                var drow = $('tr.kismet_devicedata_grouptitle#tr_' + id, subtable);

                if (drow.length == 0) {
                    drow = $('<tr>', {
                        class: 'kismet_devicedata_grouptitle',
                        id: 'tr_' + id
                    });

                    subtable.append(drow);

                    var cell = $('<td>', {
                        class: 'kismet_devicedata_span',
                        colspan: 2
                    });

                    drow.append(cell);

                    var contentdiv = $('<div>', {
                        id: 'cd_' + id
                    });

                    callopts['container'] = contentdiv;
                    callopts['cell'] = cell;
                    callopts['containerid'] = 'cd_' + id;

                    var gt = "";

                    if (typeof(v['groupTitle']) === 'string')
                        gt = v['groupTitle'];
                    else if (typeof(v['groupTitle']) === 'function')
                        gt = v['groupTitle'](callopts);

                    cell.append($('<b class="devicedata_subgroup_header">' + gt + '</b>'));

                    if ('help' in v && v['help']) {
                        fn = make_help_func(v, gt);

                        cell.append($('<i>', {
                            class: 'k_dd_td_help pseudolink fa fa-question-circle'
                        })
                            .on('click', fn)
                        );

                    }

                    cell.append($('<br>'));

                    cell.append(contentdiv);

                    if ('render' in v && typeof(v.render) === 'function') {
                        contentdiv.html(v.render(callopts));
                    }
                } else if (!liveupdate) {
                    var contentdiv = $('div#cd_' + id, drow);

                    if ('groupField' in v) {
                        if (typeof(v['groupField']) === 'string')
                            v['baseobject'] = settings.baseobject + v['groupField'] + "/";
                    }
                    contentdiv.devicedata(data, v);
                    return;
                }

                var cell = $('td', drow);
                var contentdiv = $('div#cd_' + id, drow);

                callopts['container'] = cell;
                callopts['cell'] = cell;
                callopts['containerid'] = 'cd_' + id;

                // Recursively fill in the div with the sub-settings
                if ('groupField' in v) {
                    if (typeof(v['groupField']) === 'string')
                        v['baseobject'] = settings.baseobject + v['groupField'] + "/";
                }

                contentdiv.devicedata(data, v);

                // Apply the draw function after the subgroup is created
                if ('draw' in v && typeof(v.draw) === 'function') {
                    var r = v.draw(callopts);

                    if (typeof(r) !== 'undefined' && typeof(r) !== 'none') 
                        cell.html(r);
                }

                return;
            }

            // Iterative group
            if ('groupIterate' in v && v['groupIterate'] == true) {
                for (var idx in d) {
                    // index the subobject
                    v['baseobject'] = `${v['field']}[${idx}]/`;
                    v['index'] = idx;

                    callopts['index'] = idx;
                    callopts['basekey'] = `${v['field']}[${idx}]/`;
                    callopts['base'] = kismet.ObjectByString(data, callopts['basekey']);

                    var subid = kismet.sanitizeId(`${id}[${idx}]`);
                    callopts['id'] = subid;

                    var drow = $('tr.kismet_devicedata_groupdata#tr_' + subid, subtable);

                    if (drow.length == 0) {
                        drow = $('<tr>', {
                            class: 'kismet_devicedata_groupdata',
                            id: 'tr_' + subid
                        });

                        subtable.append(drow);

                        var cell = $('<td>', {
                            class: 'kismet_devicedata_span', 
                            colspan: 2
                        });

                        drow.append(cell);

                        // Make the content div for it all the time
                        var contentdiv = $('<div>', {
                            id: 'cd_' + subid
                        });

                        callopts['container'] = contentdiv;
                        callopts['cell'] = cell;
                        callopts['containerid'] = 'cd_' + subid;

                        // If we have a title, make a span row for it
                        if ('iterateTitle' in v) {
                            // console.log('iteratetitle', subid);

                            var title_span = $('<span>');
                            callopts['title'] = title_span;

                            if (typeof(v['iterateTitle']) === 'string')
                                title_span.html(v['iterateTitle']);
                            else if (typeof(v['iterateTitle']) === 'function')
                                title_span.html(it = v['iterateTitle'](callopts));

                            cell.append($('<b>', {
                                'class': 'devicedata_subgroup_header'
                            }).append(title_span))

                            cell.append($('<br />'));
                        }

                        cell.append(contentdiv);

                        if ('render' in v && typeof(v.render) === 'function') {
                            contentdiv.html(v.render(callopts));
                        }
                    } else if (!liveupdate) {
                        var contentdiv = $('div#cd_' + subid, drow);
                        contentdiv.devicedata(data, v);

                        return;
                    }

                    var cell = $('td', drow);
                    var contentdiv = $('div#cd_' + subid, drow);

                    callopts['cell'] = cell;
                    callopts['container'] = contentdiv;
                    callopts['containerid'] = 'cd_' + subid;

                    contentdiv.devicedata(data, v);

                    // Apply the draw function after the iterative group is processed
                    if ('draw' in v && typeof(v.draw) === 'function') {
                        var r = v.draw(callopts);

                        if (typeof(r) !== 'undefined' && typeof(r) !== 'none') 
                            contentdiv.html(r);
                    }
                }

                return;
            }

            // Standard row
            var drow = $('tr.kismet_devicedata_groupdata#tr_' + id, subtable);

            if (drow.length == 0) {
                drow = $('<tr>', {
                    class: 'kismet_devicedata_groupdata',
                    id: 'tr_' + id
                });

                var td;

                if (v["span"]) {
                    td = $('<td>', {
                        colspan: 2,
                        class: 'kismet_devicedata_span kismet_devicedata_td_content'
                    });
                    drow.append(td);
                } else {
                    var title = $('<td>', {
                        class: 'kismet_devicedata_td_title'
                    });
                    var content = $('<td>', {
                        class: 'kismet_devicedata_td_content'
                    });

                    td = content;

                    drow.append(title);
                    drow.append(content);

                    title.html(v['title']);

                    if (v['help']) {
                        fn = make_help_func(v, v['title']);

                        title.append($('<i>', {
                            class: 'k_dd_td_help pseudolink fa fa-question-circle'
                        })
                            .on('click', fn)
                        );

                    }
                }

                if ('render' in v) {
                    if (typeof(v['render']) === 'function') {
                        td.html(v['render'](callopts));
                    } else if (typeof(v['render']) === 'string') {
                        td.html(v['render']);
                    }

                }

                subtable.append(drow);
            } else if (!liveupdate) {
                return;
            }

            var td = $('td.kismet_devicedata_td_content', drow);

            // Apply the draw function after the row is created
            if ('draw' in v && typeof(v.draw) === 'function') {
                callopts['container'] = td;
                var r = v.draw(callopts);

                if (typeof(r) !== 'undefined' && typeof(r) !== 'none') 
                    td.html(r);
            } else if ('empty' in v && 
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
        );
    };
}(jQuery));
