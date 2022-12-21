(
  typeof define === "function" ? function (m) { define("kismet-ui-dot11-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_alerts = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

exports.load_complete = 0;

function severity_to_string(sev) {
    switch (sev) {
        case 0:
            return "INFO";
        case 5:
            return "LOW";
        case 10:
            return "MEDIUM";
        case 15:
            return "HIGH";
        case 20:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

function severity_to_color(sev) {
    if (kismet_theme.theme === 'dark') { 
        switch (sev) {
            case 0:
                return ["#015761", "#FFFFFF"];
            case 5:
                return ["#5f6100", "#FFFFFF"];
            case 10:
                return ["#706500", "#FFFFFF"];
            case 15:
                return ["#B9770E", "#FFFFFF"];
            case 20:
                return ["#5c010a", "#FFFFFF"];
            default:
                return ["UNKNOWN", "#FFFFFF"];
        }
    } else { 
        switch (sev) {
            case 0:
                return ["#03e3fc", "#000000"];
            case 5:
                return ["#fbff00", "#000000"];
            case 10:
                return ["#fce303", "#000000"];
            case 15:
                return ["#fcba03", "#000000"];
            case 20:
                return ["#fc031c", "#000000"];
            default:
                return ["UNKNOWN", "#000000"];
        }
    }

}

var alertTid = -1;
var alert_element;
var alert_status_element;
var AlertColumns = new Array();

exports.AddAlertColumn = function(id, options) {
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

    if ('width' in options) {
        coldef.width = options.width;
    }

    var f;
    if (typeof(coldef.field) === 'string') {
        var fs = coldef.field.split('/');
        f = fs[fs.length - 1];
    } else if (Array.isArray(coldef.field)) {
        f = coldef.field[1];
    }

    coldef.mData = function(row, type, set) {
        return kismet.ObjectByString(row, f);
    }

    if ('renderfunc' in options) {
        coldef.mRender = options.renderfunc;
    }

    if ('drawfunc' in options) {
        coldef.kismetdrawfunc = options.drawfunc;
    }

    AlertColumns.push(coldef);
}

exports.GetAlertColumns = function(showall = false) {
    var ret = new Array();

    var order = kismet.getStorage('kismet.alerttable.columns', []);

    if (order.length == 0) {
        // sort invisible columns to the end
        for (var i in AlertColumns) {
            if (!AlertColumns[i].bVisible)
                continue;
            ret.push(AlertColumns[i]);
        }

        for (var i in AlertColumns) {
            if (AlertColumns[i].bVisible)
                continue;
            ret.push(AlertColumns[i]);
        }

        return ret;
    }

    for (var oi in order) {
        var o = order[oi];

        if (!o.enable)
            continue;

        var sc = AlertColumns.find(function(e, i, a) {
            if (e.kismetId === o.id)
                return true;
            return false;
        });

        if (sc != undefined && sc.user_selectable) {
            sc.bVisible = true;
            ret.push(sc);
        }
    }

    // Fallback if no columns were selected somehow
    if (ret.length == 0) {
        // sort invisible columns to the end
        for (var i in AlertColumns) {
            if (!AlertColumns[i].bVisible)
                continue;
            ret.push(AlertColumns[i]);
        }

        for (var i in AlertColumns) {
            if (AlertColumns[i].bVisible)
                continue;
            ret.push(AlertColumns[i]);
        }

        return ret;
    }

    if (showall) {
        for (var sci in AlertColumns) {
            var sc = AlertColumns[sci];

            var rc = ret.find(function(e, i, a) {
                if (e.kismetId === sc.kismetId)
                    return true;
                return false;
            });

            if (rc == undefined) {
                sc.bVisible = false;
                ret.push(sc);
            }
        }

        return ret;
    }

    for (var sci in AlertColumns) {
        if (!AlertColumns[sci].user_selectable) {
            ret.push(AlertColumns[sci]);
        }
    }

    return ret;
}

exports.GetAlertColumnMap = function(columns) {
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

exports.GetAlertFields = function(selected) {
    var rawret = new Array();
    var cols = exports.GetAlertColumns();

    for (var i in cols) {
        if ('field' in cols[i])
            rawret.push(cols[i]['field']);

        if ('fields' in cols[i])
            rawret.push.apply(rawret, cols[i]['fields']);
    }

    // de-dupe
    var ret = rawret.filter(function(item, pos, self) {
        return self.indexOf(item) == pos;
    });

    return ret;
}


function ScheduleAlertSummary() {
    try {
        if (kismet_ui.window_visible && alert_element.is(":visible")) {
            var dt = alert_element.DataTable();

            // Save the state.  We can't use proper state saving because it seems to break
            // the table position
            kismet.putStorage('kismet.base.alerttable.order', JSON.stringify(dt.order()));
            kismet.putStorage('kismet.base.alertttable.search', JSON.stringify(dt.search()));

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
        }

    } catch (error) {
        ;
    }
    
    // Set our timer outside of the datatable callback so that we get called even
    // if the ajax load fails
    alertTid = setTimeout(ScheduleAlertSummary, 2000);
}

function InitializeAlertTable() {
    var cols = exports.GetAlertColumns();
    var colmap = exports.GetAlertColumnMap(cols);
    var fields = exports.GetAlertFields();

    var json = {
        fields: fields,
        colmap: colmap,
        datatable: true,
    };

    if ($.fn.dataTable.isDataTable(alert_element)) {
        alert_element.DataTable().destroy();
        alert_element.empty();
    }

    alert_element
        .on('xhr.dt', function(e, settings, json, xhr) {
            json = kismet.sanitizeObject(json);

            try {
                if (json['recordsFiltered'] != json['recordsTotal'])
                    alert_status_element.html(`${json['recordsTotal']} alerts (${json['recordsFiltered']} shown after filter)`);
                else
                    alert_status_element.html(`${json['recordsTotal']} alerts`);
            } catch (error) {
                ;
            }
        })
        .DataTable({
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
            ajax: {
                url: local_uri_prefix + "alerts/alerts_view.json",
                data: {
                    json: JSON.stringify(json)
                },
                method: 'POST',
                timeout: 5000,
            },
            columns: cols,
            order: [ [ 0, "desc" ] ],
            createdRow: function(row, data, index) {
                row.id = data['kismet.alert.hash'];
            },
            drawCallback: function(settings) {
                var dt = this.api();

                dt.rows({
                    page: 'current'
                }).every(function(rowIdx, tableLoop, rowLoop) {
                    for (var c in AlertColumns) {
                        var col = AlertColumns[c];

                        if (!('kismetdrawfunc') in col)
                            continue;

                        try {
                            col.kismetdrawfunc(col, dt, this);
                        } catch (error) {
                            ;
                        }
                    }

                    $('td', this.node()).css('background-color', severity_to_color(this.data()['kismet.alert.severity'])[0]);
                    $('td', this.node()).css('color', severity_to_color(this.data()['kismet.alert.severity'])[1]);
                });
            },
        });

    var alert_dt = alert_element.DataTable();

    // Restore the order
    var saved_order = kismet.getStorage('kismet.base.alerttable.order', "");
    if (saved_order !== "")
        alert_dt.order(JSON.parse(saved_order));

    // Restore the search
    var saved_search = kismet.getStorage('kismet.base.alerttable.search', "");
    if (saved_search !== "")
        alert_dt.search(JSON.parse(saved_search));

    // Set an onclick handler to spawn the device details dialog
    $('tbody', alert_element).on('click', 'tr', function () {
        exports.AlertDetailWindow(this.id);
    } );

    $('tbody', alert_element)
        .on( 'mouseenter', 'td', function () {
            var alert_dt = alert_element.DataTable();

            if (typeof(alert_dt.cell(this).index()) === 'undefined')
                return;

            var colIdx = alert_dt.cell(this).index().column;
            var rowIdx = alert_dt.cell(this).index().row;

            // Remove from all cells
            $(alert_dt.cells().nodes()).removeClass('kismet-highlight');
            // Highlight the td in this row
            $('td', alert_dt.row(rowIdx).nodes()).addClass('kismet-highlight');
        } );

    return alert_dt;
}

kismet_ui_tabpane.AddTab({
    id: 'tab_alerts',
    tabTitle: 'Alerts',
    createCallback: function(div) {
        div.append(
            $('<div>', {
                class: 'resize_wrapper',
            })
            .append(
                $('<table>', {
                    id: 'alerts_dt',
                    class: 'stripe hover nowrap',
                    'cell-spacing': 0,
                    width: '100%',
                })
            )
        ).append(
            $('<div>', {
                id: 'alerts_status',
                style: 'padding-bottom: 10px;',
            })
        );

        alert_element = $('#alerts_dt', div);
        alert_status_element = $('#alerts_status', div);

        InitializeAlertTable();
        ScheduleAlertSummary();
    },
    priority: -1001,
}, 'center');

exports.AddAlertColumn('col_header', {
    sTitle: 'Type',
    field: 'kismet.alert.header',
    name: 'Alert type',
});

exports.AddAlertColumn('col_class', {
    sTitle: 'Class',
    field: 'kismet.alert.class',
    name: 'Class',
});

exports.AddAlertColumn('col_severity', {
    sTitle: 'Severity',
    field: 'kismet.alert.severity',
    name: 'Severity',
    renderfunc: function(d, t, r, m) {
        return severity_to_string(d);
    }
});

exports.AddAlertColumn('col_time', {
    sTitle: 'Time',
    field: 'kismet.alert.timestamp',
    name: 'Timestamp',
    renderfunc: function(d, t, r, m) {
        return kismet_ui_base.renderLastTime(d, t, r, m);
    }
});

exports.AddAlertColumn('col_tx', {
    sTitle: 'Transmitter',
    field: 'kismet.alert.transmitter_mac',
    name: 'Transmitter MAC',
    renderfunc: function(d, t, r, m) {
        if (d === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        return kismet.censorMAC(d);
    }
});

exports.AddAlertColumn('col_sx', {
    sTitle: 'Source',
    field: 'kismet.alert.source_mac',
    name: 'Source MAC',
    renderfunc: function(d, t, r, m) {
        if (d === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        return kismet.censorMAC(d);
    }
});

exports.AddAlertColumn('col_dx', {
    sTitle: 'Destination',
    field: 'kismet.alert.dest_mac',
    name: 'Destination MAC',
    renderfunc: function(d, t, r, m) {
        if (d === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        if (d === "FF:FF:FF:FF:FF:FF")
            return "<i>all</i>";

        return kismet.censorMAC(d);
    }
});

exports.AddAlertColumn('content', {
    sTitle: 'Alert',
    field: 'kismet.alert.text',
    name: 'Alert content',
    renderfunc: function(d, t, r, m) {
        return kismet.censorMAC(d);
    }
});

exports.AddAlertColumn('hash_hidden', {
    sTitle: 'Hash key',
    field: 'kismet.alert.hash',
    searchable: false,
    visible: false,
    orderable: false,
});

exports.AlertDetails = new Array();

exports.AddAlertDetail = function(id, title, pos, options) {
    kismet_ui.AddDetail(exports.AlertDetails, id, title, pos, options);
}

exports.AlertDetailWindow = function(key) {
    kismet_ui.DetailWindow(key, "Alert Details", 
        {
            storage: {},
        },

        function(panel, options) {
            var content = panel.content;

            panel.active = true;

            window['storage_detail_' + key] = {};
            window['storage_detail_' + key]['foobar'] = 'bar';

            panel.updater = function() {
                if (kismet_ui.window_visible) {
                    $.get(local_uri_prefix + "alerts/by-id/" + key + "/alert.json")
                        .done(function(fulldata) {
                            fulldata = kismet.sanitizeObject(fulldata);

                            $('.loadoops', panel.content).hide();

                            panel.headerTitle(`Alert: ${fulldata['kismet.alert.header']}`);

                            var accordion = $('div#accordion', content);

                            if (accordion.length == 0) {
                                accordion = $('<div />', {
                                    id: 'accordion'
                                });

                                content.append(accordion);
                            }

                            var detailslist = exports.AlertDetails;

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

                                if ('draw' in di.options && typeof(di.options.draw) === 'function') {
                                    di.options.draw(fulldata, vcontent, options, 'storage_alert_' + key);
                                }

                                if ('finalize' in di.options &&
                                    typeof(di.options.finalize) === 'function') {
                                    di.options.finalize(fulldata, vcontent, options, 'storage_alert_' + key);
                                }
                            }
                            accordion.accordion({ heightStyle: 'fill' });
                        })
                        .fail(function(jqxhr, texterror) {
                            content.html("<div class=\"loadoops\" style=\"padding: 10px;\"><h1>Oops!</h1><p>An error occurred loading alert details for key <code>" + key + 
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
        },

        function(panel, options) {
            clearTimeout(panel.timerid);
            panel.active = false;
            window['storage_alert_' + key] = {};
        });
};

exports.AddAlertDetail("alert", "Alert", 0, {
    draw: function(data, target, options, storage) {
        target.devicedata(data, {
            id: "alertdetails",
            fields: [
                {
                    field: 'kismet.alert.header',
                    title: 'Alert',
                    liveupdate: false,
                    help: 'Alert type / identifier; each alert has a unique type name.',
                },
                {
                    field: 'kismet.alert.class',
                    title: 'Class',
                    liveupdate: false,
                    help: 'Each alert has a class, such as spoofing, denial of service, known exploit, etc.',
                },
                {
                    field: 'kismet.alert.severity',
                    title: 'Severity',
                    liveupdate: false,
                    draw: function(opts) {
                        return severity_to_string(opts['value']);
                    },
                    help: 'General severity of alert; in increasing severity, alerts are categorized as info, low, medium, high, and critical.',
                },
                {
                    field: 'kismet.alert.timestamp',
                    title: 'Time',
                    liveupdate: false,
                    draw: function(opts) {
                        console.log(Math.floor(opts['value']));
                        return kismet_ui.RenderTrimmedTime({'value': Math.floor(opts['value'])});
                    }
                },
                {
                    field: 'kismet.alert.location/kismet.common.location.geopoint',
                    filter: function(opts) {
                        try { 
                            return opts['data']['kismet.alert.location']['kismet.common.location.fix'] >= 2;
                        } catch (_error) {
                            return false;
                        }
                    },
                    title: 'Location',
                    draw: function(opts) {
                        try {
                            if (opts['value'][1] == 0 || opts['value'][0] == 0)
                                return "<i>Unknown</i>";

                            return kismet.censorLocation(opts['value'][1]) + ", " + kismet.censorLocation(opts['value'][0]);
                        } catch (error) {
                            return "<i>Unknown</i>";
                        }
                    },
                    help: 'Location where alert occurred, either as the location of the Kismet server at the time of the alert or as the location of the packet, if per-packet location was available.',
                },
                {
                    field: 'kismet.alert.text',
                    title: 'Alert content',
                    draw: function(opts) {
                        return kismet.censorMAC(opts['value']);
                    },
                    help: 'Human-readable alert content',
                },
                {
                    groupTitle: 'Addresses',
                    id: 'addresses',
                    filter: function(opts) {
                        return opts['data']['kismet.alert.transmitter_mac'] != '00:00:00:00:00:00' ||
                            opts['data']['kismet.alert.source_mac'] != '00:00:00:00:00:00' ||
                            opts['data']['kismet.alert.dest_mac'] != '00:00:00:00:00:00';
                    },
                    fields: [
                        {
                            field: 'kismet.alert.source_mac',
                            title: 'Source',
                            filter: function(opts) {
                                return opts['value'] !== '00:00:00:00:00:00';
                            },
                            draw: function(opts) {
                                return kismet.censorMAC(opts['value']);
                            },
                            help: 'MAC address of the source of the packet triggering this alert.',
                        },
                        {
                            field: 'kismet.alert.transmitter_mac',
                            title: 'Transmitter',
                            filter: function(opts) {
                                return opts['value'] !== '00:00:00:00:00:00' &&
                                    opts['data']['kismet.alert.source_mac'] !== opts['value'];
                            },
                            draw: function(opts) {
                                return kismet.censorMAC(opts['value']);
                            },
                            help: 'MAC address of the transmitter of the packet triggering this alert, if not the same as the source.  On Wi-Fi this is typically the BSSID of the AP',
                        },
                        {
                            field: 'kismet.alert.dest_mac',
                            title: 'Destination',
                            filter: function(opts) {
                                return opts['value'] !== '00:00:00:00:00:00';
                            },
                            draw: function(opts) {
                                if (opts['value'] === 'FF:FF:FF:FF:FF:FF')
                                    return '<i>All / Broadcast</i>'
                                return kismet.censorMAC(opts['value']);
                            },
                            help: 'MAC address of the destionation the packet triggering this alert.',
                        },
                    ]
                },
            ]
        })
    }
});

exports.AddAlertDetail("devel", "Dev/Debug Options", 10000, {
    render: function(data) {
        return 'Alert JSON: <a href="alerts/by-id/' + data['kismet.alert.hash'] + '/alert.prettyjson" target="_new">link</a><br />';
    }});

exports.load_complete = 1;

return exports;

});
