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
 * fields: Multiple fields
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
        if ('field' in cols[i]) {
            rawret.push(cols[i]['field']);
        }

        if ('fields' in cols[i]) {
            rawret.push.apply(rawret, cols[i]['fields']);
        }
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

    exports.DeviceDetails.push(det);

    exports.DeviceDetails.sort(function(a, b) {
        return a.position - b.position;
    });
}

exports.GetDeviceDetails = function() {
    return exports.DeviceDetails;
}

exports.DeviceDetailWindow = function(key) {
    // Generate a unique ID for this dialog
    var dialogid = "devicedialog" + key;
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
        id: dialogid,
        headerTitle: 'Device Details',

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
            maxWidth: 600,
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

        callback: function() {
            var panel = this;
            var content = this.content;

            $.get(local_uri_prefix + "devices/by-key/" + key + "/device.json")
                .done(function(fulldata) {
                    fulldata = kismet.sanitizeObject(fulldata);

                    panel.headerTitle(fulldata['kismet_device_base_name']);

                    var accordion = $('<div />', {
                        id: 'accordion'
                    });

                    content.append(accordion);

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

                        var vheader = $('<h3 />', {
                            id: "header" + di.id,
                            html: di.title
                        });

                        var vcontent = $('<div />', {
                            id: di.id,
                            //class: 'autosize'
                        });

                        // Do we have pre-rendered content?
                        if ('render' in di.options &&
                                typeof(di.options.render) === 'function') {
                            vcontent.html(di.options.render(fulldata));
                        }

                        accordion.append(vheader);
                        accordion.append(vcontent);

                        if ('draw' in di.options &&
                                typeof(di.options.draw) === 'function') {
                            di.options.draw(fulldata, vcontent);
                        }
                    }
                    accordion.accordion({ heightStyle: 'fill' });
                })
            .fail(function(jqxhr, texterror) {
                content.html("<div style=\"padding: 10px;\"><h1>Oops!</h1><p>An error occurred loading device details for key <code>" + key + 
                        "</code>: HTTP code <code>" + jqxhr.status + "</code>, " + texterror + "</div>");
            });
        }
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

exports.connection_error = false;
exports.connection_error_panel = null;

exports.HealthCheck = function() {
    var timerid;

    $.get(local_uri_prefix + "system/status.json")
    .done(function(data) {
        data = kismet.sanitizeObject(data);

        if (exports.connection_error) {
            exports.connection_error_panel.close();
        }

        exports.connection_error = false;

        exports.last_timestamp = data['kismet.system.timestamp.sec'];
    })
    .fail(function() {
        if (!exports.connection_error) {
            exports.connection_error_panel = $.jsPanel({
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

        exports.connection_error = true;
    })
    .always(function() {
        if (exports.connection_error)
            timerid = setTimeout(exports.HealthCheck, 1000);
        else
            timerid = setTimeout(exports.HealthCheck, 5000);
    });

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
    if (kismet.getStorage('kismet.base.unit.temp') === 'celcius' ||
            kismet.getStorage('kismet.base.unit.temp') === '') {
        return c.toFixed(precision) + '&deg; C';
    } else {
        return (c * (9/5) + 32).toFixed(precision) + '&deg; F';
    }
}

var deviceTid;

function ScheduleDeviceSummary() {
    var dt = $('#devices').DataTable();

    // Save the state.  We can't use proper state saving because it seems to break
    // the table position
    kismet.putStorage('kismet.base.devicetable.order', JSON.stringify(dt.order()));
    kismet.putStorage('kismet.base.devicetable.search', JSON.stringify(dt.search()));

    // Snapshot where we are, because the 'don't reset page' in ajax.reload
    // DOES still reset the scroll position
    var prev_pos = {
        'top': $(dt.settings()[0].nScrollBody).scrollTop(),
        'left': $(dt.settings()[0].nScrollBody).scrollLeft()
    };
    dt.ajax.reload(function(d) {
            // Restore our scroll position
            $(dt.settings()[0].nScrollBody).scrollTop( prev_pos.top );
            $(dt.settings()[0].nScrollBody).scrollLeft( prev_pos.left );
        }, false);
    
    // Set our timer outside of the datatable callback so that we get called even
    // if the ajax load fails
    deviceTid = setTimeout(ScheduleDeviceSummary, 2000);

    return;
}

function CancelDeviceSummary() {
    clearTimeout(deviceTid);
}

var devicetableElement = null;

/* Create the device table */
exports.CreateDeviceTable = function(element, statuselement) {
    devicetableElement = element;

    var dt = exports.InitializeDeviceTable(element, statuselement);

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
            var device_dt = element.DataTable();

            if (typeof(device_dt.cell(this).index()) === 'Undefined')
                return;

            var colIdx = device_dt.cell(this).index().column;
            var rowIdx = device_dt.cell(this).index().row;

            // Remove from all cells
            $(device_dt.cells().nodes()).removeClass('kismet-highlight');
            // Highlight the td in this row
            $('td', device_dt.row(rowIdx).nodes()).addClass('kismet-highlight');
        } );

    dt.draw(false);

    // Start the auto-updating
    ScheduleDeviceSummary();
}

exports.InitializeDeviceTable = function(element, statuselement) {
    /* Make the fields list json and set the wrapper object to aData to make the DT happy */
    var cols = exports.GetDeviceColumns();
    var colmap = exports.GetDeviceColumnMap(cols);

    var fields = exports.GetDeviceFields();

    var json = {
        fields: fields,
        colmap: colmap,
        datatable: true,
    };
    var postdata = "json=" + JSON.stringify(json);

    element
        .on('xhr.dt', function (e, settings, json, xhr) {
            json = kismet.sanitizeObject(json);

            if (json['recordsFiltered'] != json['recordsTotal'])
                statuselement.html(json['recordsTotal'] + " devices (" + json['recordsFiltered'] + " shown after filter)");
            else
                statuselement.html(json['recordsTotal'] + " devices");
        } )
        .DataTable( {

        destroy: true,

        scrollResize: true,
        scrollY: 200,

        serverSide: true,
        processing: true,

        dom: 'ft',

        deferRender: true,
        lengthChange: false,

        scroller: {
            loadingIndicator: true,
        },

        // Create a complex post to get our summary fields only
        ajax: {
            url: "devices/summary/devices.json",
            data: {
                json: JSON.stringify(json)
            },
            method: "POST",
            timeout: 5000,
        },

        // Get our dynamic columns
        columns: cols,

        order:
            [ [ 0, "desc" ] ],

        // Map our ID into the row
        createdRow : function( row, data, index ) {
            row.id = data['kismet.device.base.key'];
        },

        // Opportunistic draw on new rows
        drawCallback: function( settings ) {
            var dt = this.api();

            console.log(dt.rows().length);

            dt.rows({
                page: 'current'
            }).every(function(rowIdx, tableLoop, rowLoop) {
                for (var c in DeviceColumns) {
                    var col = DeviceColumns[c];

                    if (!('kismetdrawfunc' in col)) {
                        continue;
                    }

                    // Call the draw callback if one exists
                    col.kismetdrawfunc(col, dt, this);
                }

                for (var r in DeviceRowHighlights) {
                    var rowh = DeviceRowHighlights[r];

                    if (rowh['enable']) {
                        if (rowh['selector'](this.data())) {
                            $('td', this.node()).css('background-color', rowh['color']);
                            break;
                        }
                    }
                }
            }
            );
        }

    });

    var device_dt = element.DataTable();
    // var dt_base_height = element.height();

    // Restore the order
    var saved_order = kismet.getStorage('kismet.base.devicetable.order', "");
    if (saved_order !== "")
        device_dt.order(JSON.parse(saved_order));

    // Restore the search
    var saved_search = kismet.getStorage('kismet.base.devicetable.search', "");
    if (saved_search !== "")
        device_dt.search(JSON.parse(saved_search));

    return device_dt;
}

exports.ResizeDeviceTable = function(element) {
    // console.log(element.height());
    // exports.ResetDeviceTable(element);
}

exports.ResetDeviceTable = function(element) {
    devicetableElement = element;

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
