(
  typeof define === "function" ? function (m) { define("kismet-ui-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui = m(); }
)(function () {

"use strict";

var local_uri_prefix = "";
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

var exports = {};

exports.window_visible = true;

// Load spectrum css and js
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/spectrum.css'
    });
$('<script>')
    .appendTo('head')
    .attr({
        type: 'text/javascript',
        src: local_uri_prefix + 'js/spectrum.js'
    });


exports.last_timestamp = 0;

// Set panels to close on escape system-wide
jsPanel.closeOnEscape = true;

var device_dt = null;

var DeviceViews = [
    {
        name: "All devices",
        view: "all",
        priority: -100000,
        group: "none"
    },
];

/* Add a view option that the user can pick for the main device table;
 * view is expected to be a component of the /devices/views/ api
 */
exports.AddDeviceView = function(name, view, priority, group = 'none') {
    DeviceViews.push({name: name, view: view, priority: priority, group: group});
}

exports.BuildDeviceViewSelector = function(element) {
    var grouped_views = [];

    // Pre-sort the array so that as we build our nested stuff we do it in order
    DeviceViews.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (b.priority > a.priority)
            return 1;

        return 0;
    });

    // This isn't efficient but happens rarely, so who cares
    for (var i in DeviceViews) {
        if (DeviceViews[i]['group'] == 'none') {
            // If there's no group, immediately add it to the grouped view
            grouped_views.push(DeviceViews[i]);
        } else {
            // Otherwise look for the group already in the view
            var existing_g = -1;
            for (var g in grouped_views) {
                if (Array.isArray(grouped_views[g])) {
                    if (grouped_views[g][0]['group'] == DeviceViews[i]['group']) {
                        existing_g = g;
                        break;
                    }
                }
            }

            // Make a new sub-array if we don't exist, otherwise append to the existing array
            if (existing_g == -1) {
                grouped_views.push([DeviceViews[i]]);
            } else {
                grouped_views[existing_g].push(DeviceViews[i]);
            }
        }
    }

    var selector = 
        $('<select>', {
            name: 'devices_views_select',
            id: 'devices_views_select'
        });

    for (var i in grouped_views) {
        if (!Array.isArray(grouped_views[i])) {
            selector.append(
                $('<option>', {
                    value: grouped_views[i]['view']
                }).html(grouped_views[i]['name'])
            );
        } else {
            var optgroup =
                $('<optgroup>', {
                    label: grouped_views[i][0]['group']
                });

            for (var og in grouped_views[i]) {
                optgroup.append(
                    $('<option>', {
                        value: grouped_views[i][og]['view']
                    }).html(grouped_views[i][og]['name'])
                );
            }

            selector.append(optgroup);
        }
    }

    var selected_option = kismet.getStorage('kismet.ui.deviceview.selected', 'all');
    $('option[value="' + selected_option + '"]', selector).prop("selected", "selected");

    selector.on("selectmenuselect", function(evt, elem) {
        kismet.putStorage('kismet.ui.deviceview.selected', elem.item.value);

        if (device_dt != null) {
            device_dt.ajax.url(local_uri_prefix + "devices/views/" + elem.item.value + "/devices.json");
        }
    });

    element.empty().append(selector);

    selector.selectmenu()
        .selectmenu("menuWidget")
        .addClass("selectoroverflow");
}

// Local maps of views for phys and datasources we've already added
var existing_views = {};
var view_list_updater_tid = 0;

function deviceview_selector_dynamic_update() {
    clearTimeout(view_list_updater_tid);
    view_list_updater_tid = setTimeout(deviceview_selector_dynamic_update, 5000);

    if (!exports.window_visible)
        return;

    var ds_priority = -5000;
    var phy_priority = -1000;

    $.get(local_uri_prefix + "devices/views/all_views.json")
        .done(function(data) {
            var ds_promises = [];

            var f_datasource_closure = function(uuid) {
                var ds_promise = $.Deferred();

                $.get(local_uri_prefix + "datasource/by-uuid/" + uuid + "/source.json")
                .done(function(dsdata) {
                    var dsdata = kismet.sanitizeObject(dsdata);
                    var synth_view = 'seenby-' + dsdata['kismet.datasource.uuid'];

                    existing_views[synth_view] = 1;

                    exports.AddDeviceView(dsdata['kismet.datasource.name'], synth_view, ds_priority, 'Datasources');
                    ds_priority = ds_priority - 1;
                })
                .always(function() {
                    ds_promise.resolve();
                });

                return ds_promise.promise();
            };

            data = kismet.sanitizeObject(data);

            for (var v in data) {
                if (data[v]['kismet.devices.view.id'] in existing_views)
                    continue;

                if (data[v]['kismet.devices.view.id'].substr(0, 7) === 'seenby-') {
                    var uuid = data[v]['kismet.devices.view.id'].substr(7);
                    ds_promises.push(f_datasource_closure(uuid));
                    // ds_promises.push($.get(local_uri_prefix + "datasource/by-uuid/" + uuid + "/source.json"));
                }

                if (data[v]['kismet.devices.view.id'].substr(0, 4) === 'phy-') {
                    existing_views[data[v]['kismet.devices.view.id']] = 1;
                    exports.AddDeviceView(data[v]['kismet.devices.view.description'], data[v]['kismet.devices.view.id'], phy_priority, 'Phy types');
                    phy_priority = phy_priority - 1;
                }
            }

            // Complete all the DS queries
            $.when(ds_promises).then(function(pi) {
                ;
            })
            .done(function() {
                // Skip generating this round if the menu is open
                if ($("div.viewselector > .ui-selectmenu-button").hasClass("ui-selectmenu-button-open")) {
                    ;
                } else {
                    exports.BuildDeviceViewSelector($('div.viewselector'));
                }
            });
        });
}
deviceview_selector_dynamic_update();

// List of datatable columns we have available
var DeviceColumns = new Array();

// Device row highlights, consisting of fields, function, name, and color
var DeviceRowHighlights = new Array();

/* Add a jquery datatable column that the user can pick from, with various
 * options:
 *
 * sTitle: datatable column title
 * name: datatable 'name' field (optional)
 * field: Kismet field path, array pair of field path and name, array of fields,
 *  or a function returning one of the above.
 * fields: Multiple fields.  When multiple fields are defined, ONE field MUST be defined in the
 *  'field' parameter.  Additional multiple fields may be defined in this parameter.
 * renderfunc: string name of datatable render function, taking DT arguments
 *  (data, type, row, meta), (optional)
 * drawfunc: string name of a draw function, taking arguments:
 *  dyncolumn - The dynamic column (this)
 *  datatable - A DataTable() object of the table we're operating on
 *  row - The row we're operating on, which should be visible
 *  This will be called during the drawCallback
 *  stage of the table, on visible rows. (optional)
 */
exports.AddDeviceColumn = function(id, options) {
    var coldef = {
        kismetId: id,
        sTitle: options.sTitle,
        field: null,
        fields: null,
    };

    if ('field' in options) {
        coldef.field = options.field;
    }

    if ('fields' in options) {
        coldef.fields = options.fields;
    }

    if ('description' in options) {
        coldef.description = options.description;
    }

    if ('name' in options) {
        coldef.name = options.name;
    }

    if ('orderable' in options) {
        coldef.bSortable = options.orderable;
    }

    if ('visible' in options) {
        coldef.bVisible = options.visible;
    } else {
        coldef.bVisible = true;
    }

    if ('selectable' in options) {
        coldef.user_selectable = options.selectable;
    } else {
        coldef.user_selectable = true;
    }

    if ('searchable' in options) {
        coldef.bSearchable = options.searchable;
    }

    if ('width' in options)
        coldef.width = options.width;

    if ('sClass' in options)
        coldef.sClass = options.sClass;

    var f;
    if (typeof(coldef.field) === 'string') {
        var fs = coldef.field.split("/");
        f = fs[fs.length - 1];
    } else if (Array.isArray(coldef.field)) {
        f = coldef.field[1];
    }

    // Bypass datatable/jquery pathing
    coldef.mData = function(row, type, set) {
        return kismet.ObjectByString(row, f);
    }

    // Datatable render function
    if ('renderfunc' in options) {
        coldef.mRender = options.renderfunc;
    }

    // Set an arbitrary draw hook we call ourselves during the draw loop later
    if ('drawfunc' in options) {
        coldef.kismetdrawfunc = options.drawfunc;
    }

    DeviceColumns.push(coldef);
}

/* Add a row highlighter for coloring rows; expects an options dictionary containing:
 * name: Simple name
 * description: Longer description
 * priority: Priority for assigning color
 * defaultcolor: rgb default color
 * defaultenable: optional bool, should be turned on by default
 * fields: *array* of field definitions, each of which may be a single or two-element
 *  field definition/path.  A *single* field must still be represented as an array,
 *  ie, ['some.field.def'].  Multiple fields and complex fields could be represented
 *  as ['some.field.def', 'some.second.field', ['some.complex/field.path', 'field.foo']]
 * selector: function(data) returning true for color or false for ignore
 */
exports.AddDeviceRowHighlight = function(options) {

    // Load enable preference
    var storedenable =
        kismet.getStorage('kismet.rowhighlight.enable' + options.name, 'NONE');

    if (storedenable === 'NONE') {
        if ('defaultenable' in options) {
            options['enable'] = options['defaultenable'];
        } else {
            options['enable'] = true;
        }
    } else {
        options['enable'] = storedenable;
    }

    // Load color preference
    var storedcolor =
        kismet.getStorage('kismet.rowhighlight.color' + options.name, 'NONE');

    if (storedcolor !== 'NONE') {
        options['color'] = storedcolor;
    } else {
        options['color'] = options['defaultcolor'];
    }

    DeviceRowHighlights.push(options);

    DeviceRowHighlights.sort(function(a, b) {
        if (a.priority < b.priority)
            return -1;
        if (b.priority > a.priority)
            return 1;

        return 0;
    });
}

/* Return columns from the selected list of column IDs */
exports.GetDeviceColumns = function(showall = false) {
    var ret = new Array();

    var order = kismet.getStorage('kismet.datatable.columns', []);

    // If we don't have an order saved
    if (order.length == 0) {
        // Sort invisible columns to the end
        for (var i in DeviceColumns) {
            if (!DeviceColumns[i].bVisible)
                continue;
            ret.push(DeviceColumns[i]);
        }
        for (var i in DeviceColumns) {
            if (DeviceColumns[i].bVisible)
                continue;
            ret.push(DeviceColumns[i]);
        }
        return ret;
    }

    // Otherwise look for all the columns we have enabled
    for (var oi in order) {
        var o = order[oi];

        if (!o.enable)
            continue;

        // Find the column that matches the ID in the master list of columns
        var dc = DeviceColumns.find(function(e, i, a) {
            if (e.kismetId === o.id)
                return true;
            return false;
        });

        if (dc != undefined && dc.user_selectable) {
            dc.bVisible = true;
            ret.push(dc);
        }
    }

    // If we didn't find anything, default to the normal behavior - something is wrong
    if (ret.length == 0) {
        // Sort invisible columsn to the end
        for (var i in DeviceColumns) {
            if (!DeviceColumns[i].bVisible)
                continue;
            ret.push(DeviceColumns[i]);
        }
        for (var i in DeviceColumns) {
            if (DeviceColumns[i].bVisible)
                continue;
            ret.push(DeviceColumns[i]);
        }
        return ret;
    }

    // If we're showing everything, find any other columns we don't have selected,
    // now that we've added the visible ones in the right order.
    if (showall) {
        for (var dci in DeviceColumns) {
            var dc = DeviceColumns[dci];

            /*
            if (!dc.user_selectable)
                continue;
                */

            var rc = ret.find(function(e, i, a) {
                if (e.kismetId === dc.kismetId)
                    return true;
                return false;
            });

            if (rc == undefined) {
                dc.bVisible = false;
                ret.push(dc);
            }
        }

        // Return the list w/out adding the non-user-selectable stuff
        return ret;
    }

    // Then append all the columns the user can't select because we need them for
    // fetching data or providing hidden sorting
    for (var dci in DeviceColumns) {
        if (!DeviceColumns[dci].user_selectable) {
            ret.push(DeviceColumns[dci]);
        }
    }

    return ret;
}

// Generate a map of column number to field array so we can tell Kismet what fields
// are in what column for sorting
exports.GetDeviceColumnMap = function(columns) {
    var ret = {};

    for (var ci in columns) {
        var fields = new Array();

        if ('field' in columns[ci]) 
            fields.push(columns[ci]['field']);

        if ('fields' in columns[ci])
            fields.push.apply(fields, columns[ci]['fields']);

        ret[ci] = fields;
    }

    return ret;
}


/* Return field arrays for the device list; aggregates fields from device columns,
 * widget columns, and color highlight columns.
 */
exports.GetDeviceFields = function(selected) {
    var rawret = new Array();
    var cols = exports.GetDeviceColumns();

    for (var i in cols) {
        if ('field' in cols[i] && cols[i]['field'] != null) 
            rawret.push(cols[i]['field']);

        if ('fields' in cols[i] && cols[i]['fields'] != null) 
            rawret.push.apply(rawret, cols[i]['fields']);
    }

    for (var i in DeviceRowHighlights) {
        rawret.push.apply(rawret, DeviceRowHighlights[i]['fields']);
    }

    // De-dupe the list of fields/field aliases
    var ret = rawret.filter(function(item, pos, self) {
        return self.indexOf(item) == pos;
    });

    return ret;
}

exports.AddDetail = function(container, id, title, pos, options) {
    var settings = $.extend({
        "filter": null,
        "render": null,
        "draw": null
    }, options);

    var det = {
        id: id,
        title: title,
        position: pos,
        options: settings
    };

    container.push(det);

    container.sort(function(a, b) {
        return a.position - b.position;
    });
}

exports.DetailWindow = function(key, title, options, window_cb, close_cb) {
    // Generate a unique ID for this dialog
    var dialogid = "detaildialog" + key;
    var dialogmatch = '#' + dialogid;

    if (jsPanel.activePanels.list.indexOf(dialogid) != -1) {
        jsPanel.activePanels.getPanel(dialogid).front();
        return;
    }

    var h = $(window).height() - 5;

    // If we're on a wide-screen browser, try to split it into 3 details windows
    var w = ($(window).width() / 3) - 10;

    // If we can't, split it into 2.  This seems to look better when people
    // don't run full-size browser windows.
    if (w < 450) {
        w = ($(window).width() / 2) - 5;
    }

    // Finally make it full-width if we're still narrow
    if (w < 450) {
        w = $(window).width() - 5;
    }

    var panel = $.jsPanel({
        theme: 'dark',

        id: dialogid,
        headerTitle: title,

        headerControls: {
            iconfont: 'jsglyph',
            controls: 'closeonly',
        },

        position: {
            "my": "left-top",
            "at": "left-top",
            "of": "window",
            "offsetX": 2,
            "offsetY": 2,
            "autoposition": "RIGHT"
        },

        resizable: {
            minWidth: 450,
            minHeight: 400,
            stop: function(event, ui) {
                $('div#accordion', ui.element).accordion("refresh");
            }
        },

        onmaximized: function() {
            $('div#accordion', this.content).accordion("refresh");
        },

        onnormalized: function() {
            $('div#accordion', this.content).accordion("refresh");
        },

        onclosed: function() {
            close_cb(this, options);
        },

        callback: function() {
            window_cb(this, options);
        },
    }).resize({
        width: w,
        height: h,
        callback: function(panel) {
            $('div#accordion', this.content).accordion("refresh");
        },
    });

    // Did we creep off the screen in our autopositioning?  Put this panel in
    // the left if so (or if it's a single-panel situation like mobile, just
    // put it front and center)
    if (panel.offset().left + panel.width() > $(window).width()) {
        panel.reposition({
            "my": "left-top",
            "at": "left-top",
            "of": "window",
            "offsetX": 2,
            "offsetY": 2,
        });
    }

}

exports.DeviceDetails = new Array();

/* Register a device detail accordion panel, taking an id for the panel
 * content, a title presented to the user, a position in the list, and
 * options.  Because details are directly rendered all the time and
 * can't be moved around / saved as configs like columns can, callbacks
 * are just direct functions here.
 *
 * filter and render take one argument, the data to be shown
 * filter: function(data) {
 *  return false;
 * }
 *
 * render: function(data) {
 *  return "Some content";
 * }
 *
 * draw takes the device data and a container element as an argument:
 * draw: function(data, element) {
 *  e.append("hi");
 * }
 * */
exports.AddDeviceDetail = function(id, title, pos, options) {
    exports.AddDetail(exports.DeviceDetails, id, title, pos, options);
}

exports.GetDeviceDetails = function() {
    return exports.DeviceDetails;
}

exports.DeviceDetailWindow = function(key) {
    exports.DetailWindow(key, "Device Details", 
        {
            storage: {}
        },

        function(panel, options) {
            var content = panel.content;

            panel.active = true;

            window['storage_devlist_' + key] = {};

            window['storage_devlist_' + key]['foobar'] = 'bar';

            panel.updater = function() {
                if (exports.window_visible) {
                    $.get(local_uri_prefix + "devices/by-key/" + key + "/device.json")
                        .done(function(fulldata) {
                            fulldata = kismet.sanitizeObject(fulldata);

                            panel.headerTitle("Device: " + kismet.censorMAC(fulldata['kismet.device.base.commonname']));

                            var accordion = $('div#accordion', content);

                            if (accordion.length == 0) {
                                accordion = $('<div />', {
                                    id: 'accordion'
                                });

                                content.append(accordion);
                            }

                            var detailslist = kismet_ui.GetDeviceDetails();

                            for (var dii in detailslist) {
                                var di = detailslist[dii];

                                // Do we skip?
                                if ('filter' in di.options &&
                                    typeof(di.options.filter) === 'function') {
                                    if (di.options.filter(fulldata) == false) {
                                        continue;
                                    }
                                }

                                var vheader = $('h3#header_' + di.id, accordion);

                                if (vheader.length == 0) {
                                    vheader = $('<h3>', {
                                        id: "header_" + di.id,
                                    })
                                        .html(di.title);

                                    accordion.append(vheader);
                                }

                                var vcontent = $('div#' + di.id, accordion);

                                if (vcontent.length == 0) {
                                    vcontent = $('<div>', {
                                        id: di.id,
                                    });
                                    accordion.append(vcontent);
                                }

                                // Do we have pre-rendered content?
                                if ('render' in di.options &&
                                    typeof(di.options.render) === 'function') {
                                    vcontent.html(di.options.render(fulldata));
                                }

                                if ('draw' in di.options &&
                                    typeof(di.options.draw) === 'function') {
                                    di.options.draw(fulldata, vcontent, options, 'storage_devlist_' + key);
                                }

                                if ('finalize' in di.options &&
                                    typeof(di.options.finalize) === 'function') {
                                    di.options.finalize(fulldata, vcontent, options, 'storage_devlist_' + key);
                                }
                            }
                            accordion.accordion({ heightStyle: 'fill' });
                        })
                        .fail(function(jqxhr, texterror) {
                            content.html("<div style=\"padding: 10px;\"><h1>Oops!</h1><p>An error occurred loading device details for key <code>" + key + 
                                "</code>: HTTP code <code>" + jqxhr.status + "</code>, " + texterror + "</div>");
                        })
                        .always(function() {
                            panel.timerid = setTimeout(function() { panel.updater(); }, 1000);
                        })
                } else {
                    panel.timerid = setTimeout(function() { panel.updater(); }, 1000);
                }

            };

            panel.updater();

            new ClipboardJS('.copyuri');
        },

        function(panel, options) {
            clearTimeout(panel.timerid);
            panel.active = false;
            window['storage_devlist_' + key] = {};
        });

};

exports.RenderTrimmedTime = function(opts) {
    return (new Date(opts['value'] * 1000).toString()).substring(4, 25);
}

exports.RenderHumanSize = function(opts) {
    return kismet.HumanReadableSize(opts['value']);
};

// Central location to register channel conversion lists.  Conversion can
// be a function or a fixed dictionary.
exports.freq_channel_list = { };
exports.human_freq_channel_list = { };

exports.AddChannelList = function(phyname, humanname, channellist) {
    exports.freq_channel_list[phyname] = channellist;
    exports.human_freq_channel_list[humanname] = channellist;
}

// Get a list of human frequency conversions
exports.GetChannelListKeys = function() {
    return Object.keys(exports.human_freq_channel_list);
}

// Get a converted channel name, or the raw frequency if we can't help
exports.GetConvertedChannel = function(humanname, frequency) {
    if (humanname in exports.human_freq_channel_list) {
        var conv = exports.human_freq_channel_list[humanname];

        if (typeof(conv) === "function") {
            // Call the conversion function if one exists
            return conv(frequency);
        } else if (frequency in conv) {
            // Return the mapped value
            return conv[frequency];
        }
    }

    // Return the frequency if we couldn't figure out what to do
    return frequency;
}

// Get a converted channel name, or the raw frequency if we can't help
exports.GetPhyConvertedChannel = function(phyname, frequency) {
    if (phyname in exports.freq_channel_list) {
        var conv = exports.freq_channel_list[phyname];

        if (typeof(conv) === "function") {
            // Call the conversion function if one exists
            return conv(frequency);
        } else if (frequency in conv) {
            // Return the mapped value
            return conv[frequency];
        }
    }

    // Return the frequency if we couldn't figure out what to do
    return kismet.HumanReadableFrequency(frequency);
}

exports.connection_error = 0;
exports.connection_error_panel = null;

exports.HealthCheck = function() {
    var timerid;

    if (exports.window_visible) {
        $.get(local_uri_prefix + "system/status.json")
            .done(function(data) {
                data = kismet.sanitizeObject(data);

                if (exports.connection_error && exports.connection_error_panel) {
                    try {
                        exports.connection_error_panel.close();
                        exports.connection_error_panel = null;
                    } catch (e) {
                        ;
                    }
                }

                exports.connection_error = 0;

                exports.last_timestamp = data['kismet.system.timestamp.sec'];
            })
            .fail(function() {
                if (exports.connection_error >= 3 && exports.connection_error_panel == null) {
                    exports.connection_error_panel = $.jsPanel({
                        theme: 'dark',
                        id: "connection-alert",
                        headerTitle: 'Cannot Connect to Kismet',
                        headerControls: {
                            controls: 'none',
                            iconfont: 'jsglyph',
                        },
                        contentSize: "auto auto",
                        paneltype: 'modal',
                        content: '<div style="padding: 10px;"><h3><i class="fa fa-exclamation-triangle" style="color: red;" /> Sorry!</h3><p>Cannot connect to the Kismet webserver.  Make sure Kismet is still running on this host!<p><i class="fa fa-refresh fa-spin" style="margin-right: 5px" /> Connecting to the Kismet server...</div>',
                    });
                }

                exports.connection_error++;
            })
            .always(function() {
                if (exports.connection_error)
                    timerid = setTimeout(exports.HealthCheck, 1000);
                else
                    timerid = setTimeout(exports.HealthCheck, 5000);
            }); 
    } else {
        if (exports.connection_error)
            timerid = setTimeout(exports.HealthCheck, 1000);
        else
            timerid = setTimeout(exports.HealthCheck, 5000);
    }

}


exports.DegToDir = function(deg) {
    var directions = [
        "N", "NNE", "NE", "ENE",
        "E", "ESE", "SE", "SSE",
        "S", "SSW", "SW", "WSW",
        "W", "WNW", "NW", "NNW"
    ];

    var degrees = [
        0, 23, 45, 68,
        90, 113, 135, 158,
        180, 203, 225, 248,
        270, 293, 315, 338
    ];

    for (var p = 1; p < degrees.length; p++) {
        if (deg < degrees[p])
            return directions[p - 1];
    }

    return directions[directions.length - 1];
}

// Use our settings to make some conversion functions for distance and temperature
exports.renderDistance = function(k, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.distance') === 'metric' ||
            kismet.getStorage('kismet.base.unit.distance') === '') {
        if (k < 1) {
            return (k * 1000).toFixed(precision) + ' m';
        }

        return k.toFixed(precision) + ' km';
    } else {
        var m = (k * 0.621371);

        if (m < 1) {
            return (5280 * m).toFixed(precision) + ' feet';
        }
        return (k * 0.621371).toFixed(precision) + ' miles';
    }
}

// Use our settings to make some conversion functions for distance and temperature
exports.renderHeightDistance = function(m, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.distance') === 'metric' ||
            kismet.getStorage('kismet.base.unit.distance') === '') {
        if (m < 1000) {
            return m.toFixed(precision) + ' m';
        }

        return (m / 1000).toFixed(precision) + ' km';
    } else {
        var f = (m * 3.2808399);

        if (f < 5280) {
            return f.toFixed(precision) + ' feet';
        }
        return (f / 5280).toFixed(precision) + ' miles';
    }
}

exports.renderSpeed = function(kph, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.speed') === 'metric' ||
            kismet.getStorage('kismet.base.unit.speed') === '') {
        return kph.toFixed(precision) + ' KPH';
    } else {
        return (kph * 0.621371).toFixed(precision) + ' MPH';
    }
}

exports.renderTemperature = function(c, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.temp') === 'celsius' ||
            kismet.getStorage('kismet.base.unit.temp') === '') {
        return c.toFixed(precision) + '&deg; C';
    } else {
        return (c * (9/5) + 32).toFixed(precision) + '&deg; F';
    }
}

var deviceTid;

var devicetableElement = null;

function ScheduleDeviceSummary() {
    try {
        if (exports.window_visible && devicetableElement.is(":visible")) {

            var dt = devicetableElement.DataTable();

            // Save the state.  We can't use proper state saving because it seems to break
            // the table position
            kismet.putStorage('kismet.base.devicetable.order', JSON.stringify(dt.order()));
            kismet.putStorage('kismet.base.devicetable.search', JSON.stringify(dt.search()));

            dt.ajax.reload(function(d) { }, false);
        }

    } catch (error) {
        console.log(error);
    }
    
    // Set our timer outside of the datatable callback so that we get called even
    // if the ajax load fails
    deviceTid = setTimeout(ScheduleDeviceSummary, 2000);

    return;
}

function CancelDeviceSummary() {
    clearTimeout(deviceTid);
}

/* Create the device table */
exports.CreateDeviceTable = function(element) {
    devicetableElement = element;
    // var statuselement = $('#' + element.attr('id') + '_status');

    var dt = exports.InitializeDeviceTable(element);

    dt.draw(false);

    // Start the auto-updating
    ScheduleDeviceSummary();
}

exports.InitializeDeviceTable = function(element) {
    // var statuselement = $('#' + element.attr('id') + '_status');

    /* Make the fields list json and set the wrapper object to aData to make the DT happy */
    var cols = exports.GetDeviceColumns();
    var colmap = exports.GetDeviceColumnMap(cols);
    var fields = exports.GetDeviceFields();

    var json = {
        fields: fields,
        colmap: colmap,
        datatable: true,
    };

    if ($.fn.dataTable.isDataTable(element)) {
        element.DataTable().destroy();
        element.empty();
    }

    element
        .on('xhr.dt', function (e, settings, json, xhr) {
            json = kismet.sanitizeObject(json);

            /*
            if (json['recordsFiltered'] != json['recordsTotal'])
                statuselement.html(json['recordsTotal'] + " devices (" + json['recordsFiltered'] + " shown after filter)");
            else
                statuselement.html(json['recordsTotal'] + " devices");
                */
        } )
        .DataTable( {

        destroy: true,

        scrollResize: true,
        // scrollY: 200,
        scrollX: "100%",

        pageResize: true,
        serverSide: true,
        processing: true,

        // stateSave: true,

        dom: '<"viewselector">ftip',

        deferRender: true,
        lengthChange: false,

            /*
        scroller: {
            loadingIndicator: true,
        },
        */

        // Create a complex post to get our summary fields only
        ajax: {
            url: local_uri_prefix + "devices/views/" + kismet.getStorage('kismet.ui.deviceview.selected', 'all') + "/devices.json",
            data: {
                json: JSON.stringify(json)
            },
            error: function(jqxhr, status, error) {
                // Catch missing views and reset
                if (jqxhr.status == 404) {
                    device_dt.ajax.url(local_uri_prefix + "devices/views/all/devices.json");
                    kismet.putStorage('kismet.ui.deviceview.selected', 'all');
                    exports.BuildDeviceViewSelector($('div.viewselector'));
                }
            },
            method: "POST",
            timeout: 5000,
        },

        // Get our dynamic columns
        columns: cols,

        columnDefs: [
            { className: "dt_td", targets: "_all" },
        ],

        order:
            [ [ 0, "desc" ] ],

        // Map our ID into the row
        createdRow : function( row, data, index ) {
            row.id = data['kismet.device.base.key'];
        },

        // Opportunistic draw on new rows
        drawCallback: function( settings ) {
            var dt = this.api();

            dt.rows({
                page: 'current'
            }).every(function(rowIdx, tableLoop, rowLoop) {
                for (var c in DeviceColumns) {
                    var col = DeviceColumns[c];

                    if (!('kismetdrawfunc' in col)) {
                        continue;
                    }

                    // Call the draw callback if one exists
                    try {
                        col.kismetdrawfunc(col, dt, this);
                    } catch (error) {
                        ;
                    }
                }

                for (var r in DeviceRowHighlights) {
                    try {
                        var rowh = DeviceRowHighlights[r];

                        if (rowh['enable']) {
                            if (rowh['selector'](this.data())) {
                                $('td', this.node()).css('background-color', rowh['color']);
                                break;
                            }
                        }
                    } catch (error) {
                        ;
                    }
                }
            }
            );
        }

    });

    device_dt = element.DataTable();
    // var dt_base_height = element.height();

    try { 
        device_dt.stateRestore.state.add("AJAX");
    } catch (_err) { }
    
    // $('div.viewselector').html("View picker");
    exports.BuildDeviceViewSelector($('div.viewselector'));

    // Restore the order
    var saved_order = kismet.getStorage('kismet.base.devicetable.order', "");
    if (saved_order !== "")
        device_dt.order(JSON.parse(saved_order));

    // Restore the search
    var saved_search = kismet.getStorage('kismet.base.devicetable.search', "");
    if (saved_search !== "")
        device_dt.search(JSON.parse(saved_search));

    // Set an onclick handler to spawn the device details dialog
    $('tbody', element).on('click', 'tr', function () {
        kismet_ui.DeviceDetailWindow(this.id);

        // Use the ID above we insert in the row creation, instead of looking in the
        // device list data
        // Fetch the data of the row that got clicked
        // var device_dt = element.DataTable();
        // var data = device_dt.row( this ).data();
        // var key = data['kismet.device.base.key'];
        // kismet_ui.DeviceDetailWindow(key);
    } );

    $('tbody', element)
        .on( 'mouseenter', 'td', function () {
            try {
                var device_dt = element.DataTable();

                if (typeof(device_dt.cell(this).index()) === 'Undefined')
                    return;

                var colIdx = device_dt.cell(this).index().column;
                var rowIdx = device_dt.cell(this).index().row;

                // Remove from all cells
                $(device_dt.cells().nodes()).removeClass('kismet-highlight');
                // Highlight the td in this row
                $('td', device_dt.row(rowIdx).nodes()).addClass('kismet-highlight');
            } catch (e) {

            }
        } );


    return device_dt;
}

exports.ResizeDeviceTable = function(element) {
    // console.log(element.height());
    // exports.ResetDeviceTable(element);
}

exports.ResetDeviceTable = function(element) {
    CancelDeviceSummary();

    exports.InitializeDeviceTable(element);

    ScheduleDeviceSummary();
}

kismet_ui_settings.AddSettingsPane({
    id: 'core_devicelist_columns',
    listTitle: 'Device List Columns',
    create: function(elem) {

        var rowcontainer =
            $('<div>', {
                id: 'k-c-p-rowcontainer'
            });

        var cols = exports.GetDeviceColumns(true);

        for (var ci in cols) {
            var c = cols[ci];

            if (! c.user_selectable)
                continue;

            var crow =
                $('<div>', {
                    class: 'k-c-p-column',
                    id: c.kismetId,
                })
                .append(
                    $('<i>', {
                        class: 'k-c-p-c-mover fa fa-arrows-v'
                    })
                )
                .append(
                    $('<div>', {
                        class: 'k-c-p-c-enable',
                    })
                    .append(
                        $('<input>', {
                            type: 'checkbox',
                            id: 'k-c-p-c-enable'
                        })
                        .on('change', function() {
                            kismet_ui_settings.SettingsModified();
                            })
                    )
                )
                .append(
                    $('<div>', {
                        class: 'k-c-p-c-name',
                    })
                    .text(c.description)
                )
                .append(
                    $('<div>', {
                        class: 'k-c-p-c-title',
                    })
                    .text(c.sTitle)
                )
                .append(
                    $('<div>', {
                        class: 'k-c-p-c-notes',
                        id: 'k-c-p-c-notes',
                    })
                );

            var notes = new Array;

            if (c.bVisible != false) {
                $('#k-c-p-c-enable', crow).prop('checked', true);
            }

            if (c.bSortable != false) {
                notes.push("sortable");
            }

            if (c.bSearchable != false) {
                notes.push("searchable");
            }

            $('#k-c-p-c-notes', crow).html(notes.join(", "));

            rowcontainer.append(crow);
        }

        elem.append(
            $('<div>', { })
            .append(
                $('<p>', { })
                .html('Drag and drop columns to re-order the device display table.  Columns may also be shown or hidden individually.')
            )
        )
        .append(
            $('<div>', {
                class: 'k-c-p-header',
            })
            .append(
                $('<i>', {
                    class: 'k-c-p-c-mover fa fa-arrows-v',
                    style: 'color: transparent !important',
                })
            )
            .append(
                $('<div>', {
                    class: 'k-c-p-c-enable',
                })
                .append(
                    $('<i>', {
                        class: 'fa fa-eye'
                    })
                )
            )
            .append(
                $('<div>', {
                    class: 'k-c-p-c-name',
                })
                .html('<i>Column</i>')
            )
            .append(
                $('<div>', {
                    class: 'k-c-p-c-title',
                })
                .html('<i>Title</i>')
            )
            .append(
                $('<div>', {
                    class: 'k-c-p-c-notes',
                })
                .html('<i>Info</i>')
            )
        );

        elem.append(rowcontainer);

        rowcontainer.sortable({
            change: function(event, ui) {
                kismet_ui_settings.SettingsModified();
            }
        });


    },
    save: function(elem) {
        // Generate a config array of objects which defines the user config for
        // the datatable; save it; then kick the datatable redraw
        var col_defs = new Array();

        $('.k-c-p-column', elem).each(function(i, e) {
            col_defs.push({
                id: $(this).attr('id'),
                enable: $('#k-c-p-c-enable', $(this)).is(':checked')
            });
        });

        kismet.putStorage('kismet.datatable.columns', col_defs);
        exports.ResetDeviceTable(devicetableElement);
    },
});

// Add the row highlighting
kismet_ui_settings.AddSettingsPane({
    id: 'core_device_row_highlights',
    listTitle: 'Device Row Highlighting',
    create: function(elem) {
        elem.append(
            $('<form>', {
                id: 'form'
            })
            .append(
                $('<fieldset>', {
                    id: 'fs_devicerows'
                })
                .append(
                    $('<legend>', {})
                    .html('Device Row Highlights')
                )
                .append(
                    $('<table>', {
                        id: "devicerow_table",
                        width: "100%",
                    })
                    .append(
                        $('<tr>', {})
                        .append(
                            $('<th>')
                        )
                        .append(
                            $('<th>')
                            .html("Name")
                        )
                        .append(
                            $('<th>')
                            .html("Color")
                        )
                        .append(
                            $('<th>')
                            .html("Description")
                        )
                    )
                )
            )
        );

        $('#form', elem).on('change', function() {
            kismet_ui_settings.SettingsModified();
        });

        for (var ri in DeviceRowHighlights) {
            var rh = DeviceRowHighlights[ri];

            var row =
                $('<tr>')
                .attr('hlname', rh['name'])
                .append(
                    $('<td>')
                    .append(
                        $('<input>', {
                            type: "checkbox",
                            class: "k-dt-enable",
                        })
                    )
                )
                .append(
                    $('<td>')
                    .html(rh['name'])
                )
                .append(
                    $('<td>')
                    .append(
                        $('<input>', {
                            type: "text",
                            value: rh['color'],
                            class: "k-dt-colorwidget"
                        })
                    )
                )
                .append(
                    $('<td>')
                    .html(rh['description'])
                );

            $('#devicerow_table', elem).append(row);

            if (rh['enable']) {
                $('.k-dt-enable', row).prop('checked', true);
            }

            $(".k-dt-colorwidget", row).spectrum({
                showInitial: true,
                preferredFormat: "rgb",
            });

        }
    },
    save: function(elem) {
        $('tr', elem).each(function() {
            kismet.putStorage('kismet.rowhighlight.color' + $(this).attr('hlname'), $('.k-dt-colorwidget', $(this)).val());

            kismet.putStorage('kismet.rowhighlight.enable' + $(this).attr('hlname'), $('.k-dt-enable', $(this)).is(':checked'));

            for (var ri in DeviceRowHighlights) {
                if (DeviceRowHighlights[ri]['name'] === $(this).attr('hlname')) {
                    DeviceRowHighlights[ri]['color'] = $('.k-dt-colorwidget', $(this)).val();
                    DeviceRowHighlights[ri]['enable'] = $('.k-dt-enable', $(this)).is(':checked');
                }
            }
        });
    },
});

return exports;

});
