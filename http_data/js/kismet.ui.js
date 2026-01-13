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

    var insert_selector = false;
    var selector = $('#devices_views_select', element);
    if (selector.length == 0) {
        selector = $('<select>', {
            name: 'devices_views_select',
            id: 'devices_views_select',
        });
        insert_selector = true;
    } else {
        selector.empty();
    }

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

    if (insert_selector) {
        element.append(selector);
    }

    try {
        selector.selectmenu('refresh');
    } catch (e) {
        selector.selectmenu()
            .selectmenu("menuWidget")
            .addClass("selectoroverflow");

        selector.on("selectmenuselect", function(evt, elem) {
            kismet.putStorage('kismet.ui.deviceview.selected', elem.item.value);
            ScheduleDeviceSummary();
        });
    }

}

// Local maps of views for phys and datasources we've already added
var existing_views = {};
var view_list_updater_tid = 0;

function ScheduleDeviceViewListUpdate() {
    clearTimeout(view_list_updater_tid);
    view_list_updater_tid = setTimeout(ScheduleDeviceViewListUpdate, 5000);

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

                if (data[v]['kismet.devices.view.indexed'] == false)
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
                    exports.BuildDeviceViewSelector($('span#device_view_holder'));
                }
            });
        });
}

ScheduleDeviceViewListUpdate();

// List of datatable columns we have available
var DeviceColumns = new Array();

// Device row highlights, consisting of fields, function, name, and color
var DeviceRowHighlights = new Array();

/* Add a column to the device list which is called by the table renderer
 *
 * The formatter should return an object, and is given the cell content and
 * row content.
 *
 * Formatters define the columns they pull - multiple fields can be added as
 * invisible helpers for the current column.
 *
 * Required options:
 * 'title': Column title
 * 'description': Description for column picker
 * 'field': Primary field (as single field or Kismet alias array)
 *
 * Optional style options:
 * 'width': Percentage of total column, or pixel width
 * 'alignment': Text alignment ('leftl', 'center', 'right')
 * 'sortable': boolean value to enable sorting on this field
 *
 * Optional functional options:
 * 'searchable': Field is included in searches
 * 'fields': Array of optional fields (as single or Kismet alias array); additional fields are used
 *           by some column renderers to process additional information or to ensure that additional
 *           fields are available; for example the 'channel' column utilizes additional fields to ensure
 *           the presence of the frequency and phyname fields required to render channels intelligently
 *           if the basic info is not available.
 * 'sortfield': Field used for sorting on this column; by default, this is the field passed
 *              as 'field'
 * 'render': Render function that accepts field data, row data, raw cell, an onrender callback
 *           for manipulating the cell once the dom has rendered, and optional parameter
 *           data, and returns a formatted result.
 * 'auxdata': Optional parameter data passed to the render function
*/

var device_columnlist2 = new Map();
var device_columnlist_hidden = new Map();

exports.AddDeviceColumn = (id, options) => {
    var coldef = {
        'kismetId': id,
        'title': options.title,
        'description': options.description,
        'field': null,
        'fields': null,
        'sortfield': null,
        'render': null,
        'auxdata': null,
        'mutate': null,
        'auxmdata': null,
        'sortable': false,
        'searchable': false,
        'width': null,
        'alignment': null,
    };

    if ('field' in options)
        coldef['field'] = options['field'];

    if ('fields' in options)
        coldef['fields'] = options['fields'];

    if ('sortfield' in options) {
        coldef['sortfield'] = options['sortfield'];
    } else {
        coldef['sortfield'] = coldef['field'];
    }

    if ('width' in options) {
        coldef['width'] = options['width'];
    }

    if ('alignment' in options) {
        coldef['alignment'] = options['alignment'];
    }

    if ('render' in options) {
        coldef['render'] = options['render'];
    } else {
        coldef['render'] = (data, rowdata, cell, auxdata) => {
            return data;
        }
    }

    if ('auxdata' in options)
        coldef['auxdata'] = options['auxdata'];

    if ('sortable' in options)
        coldef['sortable'] = options['sortable'];

    device_columnlist2.set(id, coldef);
}

/* Add a hidden device column that is used for other utility, but not specifically displayed;
 * for instance the device key column must always be present.
 *
 * Required elements in the column definition:
 * 'field': Field definition, either string, path, or Kismet simplification array
 * 'searchable': Boolean, field is included in searches
 *
 * */
exports.AddHiddenDeviceColumn = (coldef) => {
    var f;

    if (typeof(coldef['field']) === 'string') {
        var fs = coldef['field'].split("/");
        f = fs[fs.length - 1];
    } else if (Array.isArray(coldef['field'])) {
        f = coldef['field'][1];
    }

    device_columnlist_hidden.set(f, coldef);
}

/* Always add the device key */
exports.AddHiddenDeviceColumn({'field': "kismet.device.base.key"});

var devicelistIconMatch = [];

/* Add an icon matcher; return a html string for the icon (font-awesome or self-embedded svg)
 * that is used in the menu/icon column.  Return null if not matched.
 *
 * Matcher function
 */
exports.AddDeviceIcon = (matcher) => {
    devicelistIconMatch.push(matcher);
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

            panel.updater = function() {
                if (exports.window_visible) {
                    $.get(local_uri_prefix + "devices/by-key/" + key + "/device.json")
                        .done(function(fulldata) {
                            if (!panel.active) {
                                return;
                            }

                            fulldata = kismet.sanitizeObject(fulldata);

                            panel.headerTitle("Device: " + kismet.censorString(fulldata['kismet.device.base.commonname']));

                            var accordion = $('div#accordion', content);

                            if (accordion.length == 0) {
                                accordion = $('<div></div>', {
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
                            if (panel.active) {
                                panel.timerid = setTimeout(function() { panel.updater(); }, 1000);
                            }
                        })
                } else {
                    if (panel.active) {
                        panel.timerid = setTimeout(function() { panel.updater(); }, 1000);
                    }
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
                        content: '<div style="padding: 10px;"><h3><i class="fa fa-exclamation-triangle" style="color: red;"></i> Sorry!</h3><p>Cannot connect to the Kismet webserver.  Make sure Kismet is still running on this host!<p><i class="fa fa-refresh fa-spin" style="margin-right: 5px"></i> Connecting to the Kismet server...</div>',
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

/* Generate the list of fields we request from the server */
function GenerateDeviceFieldList2() {
    var retcols = new Map();

    for (const [k, v] of device_columnlist_hidden) {
        if (typeof(v['field']) === 'string') {
            retcols.set(v, v['field']);
        } else if (Array.isArray(v['field'])) {
            retcols.set(v['field'][1], v);
        }
    };

    for (const [k, c] of device_columnlist2) {
        /*
        if (devicetable_prefs['columns'].length > 0 &&
            !devicetable_prefs['columns'].includes(c['kismetId']))
            continue;
            */

        if (c['field'] != null) {
            if (typeof(c['field']) === 'string') {
                retcols.set(c['field'], c['field']);
            } else if (Array.isArray(c['field'])) {
                retcols.set(c['field'][1], c['field']);
            }
        }

        if (c['fields'] != null) {
            for (const cf of c['fields']) {
                if (typeof(cf) === 'string') {
                    retcols.set(cf, cf);
                } else if (Array.isArray(cf)) {
                    retcols.set(cf[1], cf);
                }

            }
        }
    }

    for (var i in DeviceRowHighlights) {
        for (var f in DeviceRowHighlights[i]['fields']) {
            retcols.set(DeviceRowHighlights[i]['fields'][f],
                DeviceRowHighlights[i]['fields'][f]);
        }
    }

    var ret = [];

    for (const [k, v] of retcols) {
        ret.push(v);
    };

    return ret;
}

/* Generate a single column for the devicelist tabulator format */
function GenerateDeviceTabulatorColumn(c) {
    var col = {
        'field': c['kismetId'],
        'title': c['title'],
        'formatter': (cell, params, onrender) => {
            try {
                return c['render'](cell.getValue(), cell.getRow().getData(), cell, onrender, c['auxdata']);
            } catch (e) {
                return cell.getValue();
            }
        },
        'headerSort': c['sortable'],
        'headerContextMenu':  [ {
            'label': "Hide Column",
            'action': function(e, column) {
                devicetable_prefs['columns'] = devicetable_prefs['columns'].filter(c => {
                    return c !== column.getField();
                });
                SaveDeviceTablePrefs();

                deviceTabulator.deleteColumn(column.getField())
                .then(col => {
                    ScheduleDeviceSummary();
                });
            }
        }, ],
    };

    var colsettings = {};
    if (c['kismetId'] in devicetable_prefs['colsettings']) {
        colsettings = devicetable_prefs['colsettings'][c['kismetId']];
    }

    if ('width' in colsettings) {
        col['width'] = colsettings['width'];
    } else if (c['width'] != null) {
        col['width'] = c['width'];
    }

    if (c['alignment'] != null)
        col['hozAlign'] = c['alignment'];

    return col;
}

/* Generate the columns for the devicelist tabulator format */
function GenerateDeviceColumns2() {
    var columns = [];

    var columnlist = [];
    if (devicetable_prefs['columns'].length == 0) {
        for (const [k, v] of device_columnlist2) {
            columnlist.push(k);
        }
    } else {
        columnlist = devicetable_prefs['columns'];
    }

    for (const k of columnlist) {
        if (!device_columnlist2.has(k)) {
            // console.log("could not find ", k);
            continue;
        }

        const c = device_columnlist2.get(k);

        columns.push(GenerateDeviceTabulatorColumn(c));
    }

    columns.unshift({
        'title': "",
        'width': '1px',
        'headerSort': false,
        'frozen': true,
        'hozAlign': 'center',
        'formatter': (cell, params, onrender) => {
            // return c['render'](cell.getValue(), cell.getRow().getData(), cell, onrender, c['auxdata']);
            for (const i of devicelistIconMatch) {
                try {
                    var icn = i(cell.getRow().getData());
                    if (icn != null) {
                        return icn;
                    }
                } catch (e) {
                    ;
                }
            }

            return '<i class="fa fa-question"></i>';
        },
        'headerMenu': () => {
            var colsub = [];
            var columns = deviceTabulator.getColumns();
            for (const [k, v] of device_columnlist2) {
                if (columns.filter(c => { return c.getField() === k; }).length > 0) {
                    continue;
                }

                colsub.push({
                    'label': v['title'],
                    'action': () => {
                        devicetable_prefs['columns'].push(v['kismetId']);
                        SaveDeviceTablePrefs();

                        const c = device_columnlist2.get(v['kismetId']);

                        deviceTabulator.addColumn(GenerateDeviceTabulatorColumn(c))
                        .then(col => {
                            ScheduleDeviceSummary();
                        });

                    }
                });
            }

            var delsub = [];
            for (const [k, v] of device_columnlist2) {
                if (columns.filter(c => { return c.getField() === k; }).length == 0) {
                    continue;
                }

                delsub.push({
                    'label': v['title'],
                    'action': () => {
                        devicetable_prefs['columns'] = devicetable_prefs['columns'].filter(c => {
                            return c !== v['kismetId'];
                        });
                        SaveDeviceTablePrefs();

                        deviceTabulator.deleteColumn(v['kismetId'])
                            .then(col => {
                                ScheduleDeviceSummary();
                            });
                    }
                });
            }

            if (colsub.length == 0) {
                colsub.push({
                    'label': '<i>All columns visible</i>',
                    'disabled': true,
                });
            }

            return [
                {
                    'label': "Add Column",
                    menu: colsub,
                },
                {
                    'label': "Remove Column",
                    menu: delsub,
                },
            ];
        },
    });


    return columns;
}

exports.PrepDeviceTable = function(element) {
    devicetableHolder2 = element;
}

/* Create the device table */
exports.CreateDeviceTable = function(element) {
    element.ready(function() {
        exports.InitializeDeviceTable(element);
    });
}

var deviceTid2 = -1;

var devicetableHolder2 = null;
var devicetableElement2 = null;
var deviceTabulator = null;
var deviceTablePage = 0;
var deviceTableTotal = 0;
var deviceTableTotalPages = 0;
var deviceTableRefreshBlock = false;
var deviceTableRefreshing = false;

function ScheduleDeviceSummary() {
    if (deviceTid2 != -1)
        clearTimeout(deviceTid2);

    deviceTid2 = setTimeout(ScheduleDeviceSummary, 1000);

    try {
        if (!deviceTableRefreshing && deviceTabulator != null && exports.window_visible && devicetableElement2.is(":visible")) {

            deviceTableRefreshing = true;

            var pageSize = deviceTabulator.getPageSize();
            if (pageSize == 0) {
                throw new Error("Page size 0");
            }

            if (deviceTableRefreshBlock) {
                throw new Error("refresh blocked");
            }

            var colparams = JSON.stringify({'fields': GenerateDeviceFieldList2()});

            var postdata = {
                "json": colparams,
                "page": deviceTablePage,
                "length": pageSize,
            }

            if (device_columnlist2.has(devicetable_prefs['sort']['column'])) {
                var f = device_columnlist2.get(devicetable_prefs['sort']['column']);
                if (f['sortfield'] != null) {
                    if (typeof(f['sortfield']) === 'string') {
                        postdata["sort"] = f['sortfield'];
                    } else if (Array.isArray(f['sortfield'])) {
                        postdata["sort"] = f['sortfield'][0];
                    }
                } else {
                    if (typeof(f['field']) === 'string') {
                        postdata["sort"] = f['sortfield'];
                    } else if (Array.isArray(f['field'])) {
                        postdata["sort"] = f['field'][0];
                    }
                }

                postdata["sort_dir"] = devicetable_prefs['sort']['dir'];
            }

            var searchterm = kismet.getStorage('kismet.ui.deviceview.search', "");
            if (searchterm.length > 0) {
                postdata["search"] = searchterm;
            }

            var viewname = kismet.getStorage('kismet.ui.deviceview.selected', 'all');

            $.post(local_uri_prefix + `devices/views/${viewname}/devices.json`, postdata,
                function(data) {
                    if (data === undefined) {
                        return;
                    }

                    deviceTableTotal = data["last_row"];
                    deviceTableTotalPages = data["last_page"];

                    // Sanitize the data
                    if (!'data' in data) {
                        throw new Error("Missing data in response");
                    }
                    var rdata = kismet.sanitizeObject(data["data"]);

                    // Permute the data based on the field list and assign the fields to the ID names
                    var procdata = [];

                    for (const d of rdata) {
                        var md = {};

                        md['original_data'] = d;

                        md['device_key'] = d['kismet.device.base.key'];

                        for (const [k, c] of device_columnlist2) {
                            if (typeof(c['field']) === 'string') {
                                var fs = c['field'].split("/");
                                var fn = fs[fs.length - 1];
                                if (fn in d)
                                    md[c['kismetId']] = d[fn];
                            } else if (Array.isArray(c['field'])) {
                                if (c['field'][1] in d)
                                    md[c['kismetId']] = d[c['field'][1]];
                            }

                            if (c['fields'] != null) {
                                for (const cf of c['fields']) {
                                    if (typeof(cf) === 'string') {
                                        var fs = cf.split("/");
                                        var fn = fs[fs.length - 1];
                                        if (fn in d)
                                            md[fn] = d[fn];
                                    } else if (Array.isArray(cf)) {
                                        if (fn[1] in d)
                                            md[fn[1]] = d[fn[1]]
                                    }

                                }
                            }

                        }

                        procdata.push(md);
                    }

                    // deviceTabulator.replaceData(data["data"]);
                    deviceTabulator.replaceData(procdata);

                    var paginator = $('#devices-table2 .tabulator-paginator');
                    paginator.empty();

                    var firstpage =
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'First',
                        }).html("First")
                    .on('click', function() {
                        deviceTablePage = 0;
                        return ScheduleDeviceSummary();
                    });
                    if (deviceTablePage == 0) {
                        firstpage.attr('disabled', 'disabled');
                    }
                    paginator.append(firstpage);

                    var prevpage =
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'Prev',
                        }).html("Prev")
                    .on('click', function() {
                        deviceTablePage = deviceTablePage - 1;
                        return ScheduleDeviceSummary();
                    });
                    if (deviceTablePage <= 0) {
                        prevpage.attr('disabled', 'disabled');
                    }
                    paginator.append(prevpage);

                    var gen_closure = (pg, pgn) => {
                        pg.on('click', () => {
                            deviceTablePage = pgn;
                            return ScheduleDeviceSummary();
                        });
                    }

                    var fp = deviceTablePage - 1;
                    if (fp <= 1)
                        fp = 1;
                    var lp = fp + 4;
                    if (lp > deviceTableTotalPages)
                        lp = deviceTableTotalPages;
                    for (let p = fp; p <= lp; p++) {
                        var ppage =
                            $('<button>', {
                                'class': 'tabulator-page',
                                'type': 'button',
                                'role': 'button',
                                'aria-label': `${p}`,
                            }).html(`${p}`);
                        gen_closure(ppage, p - 1);
                        if (deviceTablePage == p - 1) {
                            ppage.attr('disabled', 'disabled');
                        }
                        paginator.append(ppage);
                    }

                    var nextpage =
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'Next',
                        }).html("Next")
                    .on('click', function() {
                        deviceTablePage = deviceTablePage + 1;
                        return ScheduleDeviceSummary();
                    });
                    if (deviceTablePage >= deviceTableTotalPages - 1) {
                        nextpage.attr('disabled', 'disabled');
                    }
                    paginator.append(nextpage);

                    var lastpage =
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'Last',
                        }).html("Last")
                    .on('click', function() {
                        deviceTablePage = deviceTableTotalPages - 1;
                        return ScheduleDeviceSummary();
                    });
                    if (deviceTablePage >= deviceTableTotalPages - 1) {
                        lastpage.attr('disabled', 'disabled');
                    }
                    paginator.append(lastpage);
                },
                "json")
                .always(() => {
                    deviceTableRefreshing = false;
                });

            /*
            var dt = devicetableElement.DataTable();

            // Save the state.  We can't use proper state saving because it seems to break
            // the table position
            kismet.putStorage('kismet.base.devicetable.order', JSON.stringify(dt.order()));
            kismet.putStorage('kismet.base.devicetable.search', JSON.stringify(dt.search()));

            dt.ajax.reload(function(d) { }, false);
            */
        }

    } catch (error) {
        // console.log(error);
        deviceTableRefreshing = false;
    }

    return;
}

function CancelDeviceSummary() {
    clearTimeout(deviceTid2);
}

var devicetable_prefs = {};

function LoadDeviceTablePrefs() {
    devicetable_prefs = kismet.getStorage('kismet.ui.devicetable.prefs', {
        "columns": ["commonname", "type", "crypt", "last_time", "packet_rrd",
            "signal", "channel", "manuf", "wifi_clients", "wifi_bss_uptime",
            "wifi_qbss_usage"],
        "colsettings": {},
        "sort": {
            "column": "last_time",
            "dir": "asc",
        },
    });

    devicetable_prefs = $.extend({
        "columns": [],
        "colsettings": {},
        "sort": {
            "column": "",
            "dir": "asc",
        },
    }, devicetable_prefs);
}

function SaveDeviceTablePrefs() {
    kismet.putStorage('kismet.ui.devicetable.prefs', devicetable_prefs);
}

exports.HideDeviceTab = function() {
    $('#center-device-extras').hide();
}

exports.ShowDeviceTab = function() {
    exports.InitializeDeviceTable(devicetableHolder2);
    $('#center-device-extras').show();
}

exports.InitializeDeviceTable = function(element) {
    LoadDeviceTablePrefs();

    devicetableHolder2 = element;

    var searchterm = kismet.getStorage('kismet.ui.deviceview.search', "");

    if ($('#center-device-extras').length == 0) {
        var devviewmenu = $(`<form action="#"><span id="device_view_holder"></span></form><input class="device_search" type="search" id="device_search" placeholder="Filter..." value="${searchterm}"></input>`);
        $('#centerpane-tabs').append($('<div id="center-device-extras" style="position: absolute; right: 10px; top: 5px; height: 30px; display: flex;">').append(devviewmenu));
        exports.BuildDeviceViewSelector($('span#device_view_holder'));

        $('#device_search').on('keydown', (evt) => {
            var code = evt.charCode || evt.keyCode;
            if (code == 27) {
                $('#device_search').val('');
            }
        });

        $('#device_search').on('input change keyup copy paste cut', $.debounce(300, () => {
            var searchterm = $('#device_search').val();
            kismet.putStorage('kismet.ui.deviceview.search', searchterm);
            ScheduleDeviceSummary();
        }));
    }

    if ($('#devices-table2', element).length == 0) {
        devicetableElement2 =
            $('<div>', {
                id: 'devices-table2',
                'cell-spacing': 0,
                width: '100%',
                height: '100%',
            });

        element.append(devicetableElement2);
    }

    deviceTabulator = new Tabulator('#devices-table2', {
        // This looks really bad on small screens
        // layout: 'fitColumns',

        movableColumns: true,
        columns: GenerateDeviceColumns2(),

        // No loading animation/text
        dataLoader: false,

        // Server-side filtering and sorting
        sortMode: "remote",
        filterMode: "remote",

        // Server-side pagination
        pagination: true,
        paginationMode: "remote",

        // Override the pagination system to use our local counters, more occurs in
        // the update timer loop to replace pagination
        paginationCounter: function(pageSize, currentRow, currentPage, totalRows, totalPages) {
            if (deviceTableTotal == 0) {
                return "Loading..."
            }

            var frow = pageSize * deviceTablePage;
            if (frow == 0)
                frow = 1;

            var lrow = frow + pageSize;
            if (lrow > deviceTableTotal)
                lrow = deviceTableTotal;

            return `Showing rows ${frow} - ${lrow} of ${deviceTableTotal}`;
        },

        rowFormatter: function(row) {
            for (const ri of DeviceRowHighlights) {
                if (!ri['enable'])
                    continue;

                try {
                    if (ri['selector'](row.getData()['original_data'])) {
                        row.getElement().style.backgroundColor = ri['color'];
                    }
                } catch (e) {
                    ;
                }
            }
        },

        initialSort: [{
            "column": devicetable_prefs["sort"]["column"],
            "dir": devicetable_prefs["sort"]["dir"],
        }],

    });

    // Get sort events to hijack for the custom query
    deviceTabulator.on("dataSorted", (sorters) => {
        if (sorters.length == 0)
            return;

        var mut = false;
        if (sorters[0].field != devicetable_prefs['sort']['column']) {
            devicetable_prefs['sort']['column'] = sorters[0].field;
            mut = true;
        }

        if (sorters[0].dir != devicetable_prefs['sort']['dir']) {
            devicetable_prefs['sort']['dir'] = sorters[0].dir;
            mut = true;
        }

        if (mut) {
            SaveDeviceTablePrefs();
            ScheduleDeviceSummary();
        }
    });

    // Disable refresh while a menu is open
    deviceTabulator.on("menuOpened", function(component){
        deviceTableRefreshBlock = true;
    });

    // Reenable refresh when menu is closed
    deviceTabulator.on("menuClosed", function(component){
        deviceTableRefreshBlock = false;
    });


    // Handle row clicks
    deviceTabulator.on("rowClick", (e, row) => {
        kismet_ui.DeviceDetailWindow(row.getData()['device_key']);
    });

    deviceTabulator.on("columnMoved", function(column, columns){
        var cols = [];

        for (const c of columns) {
            cols.push(c.getField());
        }

        devicetable_prefs['columns'] = cols;

        SaveDeviceTablePrefs();

    });

    deviceTabulator.on("columnResized", function(column){
        if (column.getField() in devicetable_prefs['colsettings']) {
            devicetable_prefs['colsettings'][column.getField()]['width'] = column.getWidth();
        } else {
            devicetable_prefs['colsettings'][column.getField()] = {
                'width': column.getWidth(),
            }
        }

        SaveDeviceTablePrefs();
    });

    deviceTabulator.on("tableBuilt", function() {
        ScheduleDeviceSummary();
    });
}

return exports;

});
