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

var alert_columnlist = new Map();
var alert_columnlist_hidden = new Map();

var AddAlertColumn = (id, options) => {
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

    alert_columnlist.set(id, coldef);
}

var AddHiddenAlertColumn = (coldef) => {
    var f;

    if (typeof(coldef['field']) === 'string') {
        var fs = coldef['field'].split("/");
        f = fs[fs.length - 1];
    } else if (Array.isArray(coldef['field'])) {
        f = coldef['field'][1];
    }

    alert_columnlist_hidden.set(f, coldef);
}

function GenerateAlertFieldList() {
    var retcols = new Map();

    for (const [k, v] of alert_columnlist_hidden) {
        if (typeof(v['field']) === 'string') {
            retcols.set(v, v['field']);
        } else if (Array.isArray(v['field'])) {
            retcols.set(v['field'][1], v);
        }
    };

    for (const [k, c] of alert_columnlist) {
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

    var ret = [];

    for (const [k, v] of retcols) {
        ret.push(v);
    };

    return ret;
}

function GenerateAlertTabulatorColumn(c) {
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
        /* Don't allow hiding alert columns
        'headerContextMenu':  [ {
            'label': "Hide Column",
            'action': function(e, column) {
                alerttable_prefs['columns'] = alerttable_prefs['columns'].filter(c => {
                    return c !== column.getField();
                });
                SaveAlertTablePrefs();

                alertTabulator.deleteColumn(column.getField())
                .then(col => {
                    ScheduleAlertSummary();
                });
            }
        }, ],
        */
    };

    var colsettings = {};
    if (c['kismetId'] in alerttable_prefs['colsettings']) {
        colsettings = alerttable_prefs['colsettings'][c['kismetId']];
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
function GenerateAlertColumns() {
    var columns = [];

    var columnlist = [];
    if (alerttable_prefs['columns'].length == 0) {
        for (const [k, v] of alert_columnlist) {
            columnlist.push(k);
        }
    } else {
        columnlist = alerttable_prefs['columns'];
    }

    for (const k of columnlist) {
        if (!alert_columnlist.has(k)) {
            continue;
        }

        const c = alert_columnlist.get(k);

        columns.push(GenerateAlertTabulatorColumn(c));
    }

    return columns;
}

var alertTid = -1;

var alerttableHolder = null;
var alerttableElement = null;
var alertTabulator = null;
var alertTablePage = 0;
var alertTableTotal = 0;
var alertTableTotalPages = 0;
var alertTableRefreshBlock = false;
var alerttable_prefs = {};
var alertTableRefreshing = false;

var CreateAlertTable = function(element) {
    element.ready(function() { 
        InitializeAlertTable(element);
    });
}

function ScheduleAlertSummary() {
    if (alertTid != -1)
        clearTimeout(alertTid);

    alertTid = setTimeout(ScheduleAlertSummary, 1000);

    try {
        if (!alertTableRefreshing && alertTabulator != null && kismet_ui.window_visible && alerttableElement.is(":visible")) {
            alertTableRefreshing = true;

            var pageSize = alertTabulator.getPageSize();
            if (pageSize == 0) {
                throw new Error("Page size 0");
            }

            if (alertTableRefreshBlock) {
                throw new Error("refresh blocked");
            }

            var colparams = JSON.stringify({'fields': GenerateAlertFieldList()});

            var postdata = {
                "json": colparams,
                "page": alertTablePage,
                "length": pageSize,
            }

            if (alert_columnlist.has(alerttable_prefs['sort']['column'])) {
                var f = alert_columnlist.get(alerttable_prefs['sort']['column']);
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

                postdata["sort_dir"] = alerttable_prefs['sort']['dir'];
            }

            var searchterm = kismet.getStorage('kismet.ui.alertview.search', "");
            if (searchterm.length > 0) {
                postdata["search"] = searchterm;
            }

            $.post(local_uri_prefix + `alerts/alerts_view.json`, postdata, 
                function(data) { 
                    alertTableTotal = data["last_row"];
                    alertTableTotalPages = data["last_page"];

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

                        md['alert_key'] = d['kismet.alert.hash'];

                        for (const [k, c] of alert_columnlist) {
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

                    alertTabulator.replaceData(procdata);

                    var paginator = $('#alert-table .tabulator-paginator');
                    paginator.empty();

                    var firstpage = 
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'First',
                        }).html("First")
                    .on('click', function() {
                        alertTablePage = 0;
                        return ScheduleAlertSummary();
                    });
                    if (alertTablePage == 0) {
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
                        alertTablePage = alertTablePage - 1;
                        return ScheduleAlertSummary();
                    });
                    if (alertTablePage < 1) {
                        prevpage.attr('disabled', 'disabled');
                    }
                    paginator.append(prevpage);

                    var gen_closure = (pg, pgn) => {
                        pg.on('click', () => {
                            alertTablePage = pgn;
                            return ScheduleAlertSummary();
                        });
                    }

                    var fp = alertTablePage - 1;
                    if (fp <= 1)
                        fp = 1;
                    var lp = fp + 4;
                    if (lp > alertTableTotalPages)
                        lp = alertTableTotalPages;
                    for (let p = fp; p <= lp; p++) {
                        var ppage = 
                            $('<button>', {
                                'class': 'tabulator-page',
                                'type': 'button',
                                'role': 'button',
                                'aria-label': `${p}`,
                            }).html(`${p}`);
                        gen_closure(ppage, p - 1);
                        if (alertTablePage == p - 1) {
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
                        alertTablePage = alertTablePage + 1;
                        return ScheduleAlertSummary();
                    });
                    if (alertTablePage >= alertTableTotalPages - 1) {
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
                        alertTablePage = alertTableTotalPages - 1;
                        return ScheduleAlertSummary();
                    });
                    if (alertTablePage >= alertTableTotalPages - 1) {
                        lastpage.attr('disabled', 'disabled');
                    }
                    paginator.append(lastpage);
                },
                "json")
                .always(() => {
                    alertTableRefreshing = false;
                });
        }

    } catch (error) {
        alertTableRefreshing = false;
    }
    
    return;
}

function CancelAlertSummary() {
    clearTimeout(alertTid);
}

function LoadAlertTablePrefs() {
    alerttable_prefs = kismet.getStorage('kismet.ui.alerttable.prefs', {
        "columns": [],
        "colsettings": {},
        "sort": {
            "column": "",
            "dir": "asc",
        },
    });

    alerttable_prefs = $.extend({
        "columns": [],
        "colsettings": {},
        "sort": {
            "column": "",
            "dir": "asc",
        }, 
    }, alerttable_prefs);
}

function SaveAlertTablePrefs() {
    kismet.putStorage('kismet.ui.alerttable.prefs', alerttable_prefs);
}

var InitializeAlertTable = function(element) {
    LoadAlertTablePrefs();

    alerttableHolder = element;

    var searchterm = kismet.getStorage('kismet.ui.alertview.search', "");

    if ($('#center-alert-extras').length == 0) {
        var alertviewmenu = $(`<input class="alert_search" type="search" id="alert_search" placeholder="Filter..." value="${searchterm}"></input>`);
        $('#centerpane-tabs').append($('<div id="center-alert-extras" style="position: absolute; right: 10px; top: 5px; height: 30px; display: flex;">').append(alertviewmenu));

        $('#alert_search').on('keydown', (evt) => {
            var code = evt.charCode || evt.keyCode;
            if (code == 27) {
                $('#alert_search').val('');
            }
        });

        $('#alert_search').on('keyup', $.debounce(300, () => {
            var searchterm = $('#alert_search').val();
            kismet.putStorage('kismet.ui.alertview.search', searchterm);
            ScheduleAlertSummary();
        }));
    }

    if ($('#alert-table', element).length == 0) { 
        alerttableElement =
            $('<div>', {
                id: 'alert-table',
                'cell-spacing': 0,
                width: '100%',
                height: '100%',
            });

        element.append(alerttableElement);
    }

    alertTabulator = new Tabulator('#alert-table', {
        layout: 'fitDataStretch',

        movableColumns: true,
        columns: GenerateAlertColumns(),

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
            if (alertTableTotal == 0) {
                return "Loading..."
            }

            var frow = pageSize * alertTablePage;
            if (frow == 0)
                frow = 1;

            var lrow = frow + pageSize;
            if (lrow > alertTableTotal) 
                lrow = alertTableTotal;

            return `Showing rows ${frow} - ${lrow} of ${alertTableTotal}`;
        },

        rowFormatter: function(row) {
            var colors = severity_to_color(row.getData()['original_data']['kismet.alert.severity']);
            row.getElement().style.backgroundColor = colors[0];
            row.getElement().style.cOlor = colors[1];
        },

        initialSort: [{
            "column": alerttable_prefs["sort"]["column"],
            "dir": alerttable_prefs["sort"]["dir"],
        }],

    });

    // Get sort events to hijack for the custom query
    alertTabulator.on("dataSorted", (sorters) => {
        if (sorters.length == 0)
            return;

        var mut = false;
        if (sorters[0].field != alerttable_prefs['sort']['column']) {
            alerttable_prefs['sort']['column'] = sorters[0].field;
            mut = true;
        }

        if (sorters[0].dir != alerttable_prefs['sort']['dir']) {
            alerttable_prefs['sort']['dir'] = sorters[0].dir;
            mut = true;
        }

        if (mut) {
            SaveAlertTablePrefs();
            ScheduleAlertSummary();
        }
    });

    // Disable refresh while a menu is open
    alertTabulator.on("menuOpened", function(component){
        alertTableRefreshBlock = true;
    });

    // Reenable refresh when menu is closed
    alertTabulator.on("menuClosed", function(component){
        alertTableRefreshBlock = false;
    });


    // Handle row clicks
    alertTabulator.on("rowClick", (e, row) => {
        exports.AlertDetailWindow(row.getData()['alert_key']);
    });

    alertTabulator.on("columnMoved", function(column, columns){
        var cols = [];

        for (const c of columns) {
            cols.push(c.getField());
        }

        alerttable_prefs['columns'] = cols;
       
        SaveAlertTablePrefs();

    });

    alertTabulator.on("columnResized", function(column){
        if (column.getField() in alerttable_prefs['colsettings']) {
            alerttable_prefs['colsettings'][column.getField()]['width'] = column.getWidth();
        } else {
            alerttable_prefs['colsettings'][column.getField()] = {
                'width': column.getWidth(),
            }
        }

        SaveAlertTablePrefs();
    });

    alertTabulator.on("tableBuilt", function() {
        ScheduleAlertSummary();
    });
}

kismet_ui_tabpane.AddTab({
    id: 'tab_alerts',
    tabTitle: 'Alerts',
    createCallback: function(div) {
        // InitializeAlertTable(div);
        alerttableHolder = div;
    },
    activateCallback: function() {
        alerttableHolder.ready(() => {
            InitializeAlertTable(alerttableHolder);
            $('#center-alert-extras').show();
        });
    },
    deactivateCallback: function() {
        $('#center-alert-extras').hide();
    },
    priority: -1001,
}, 'center');

AddAlertColumn('header', {
    'title': 'Type',
    'description': 'Alert type',
    'field': 'kismet.alert.header',
    'sortable': true,
    'searchable': true,
});

AddAlertColumn('class', {
    'title': 'Class',
    'description': 'Alert class',
    'field': 'kismet.alert.class',
    'sortable': true,
    'searchable': true,
});

AddAlertColumn('severity', {
    'title': 'Severity',
    'description': 'Alert severity',
    'field': 'kismet.alert.severity',
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        return severity_to_string(data);
    },
});

AddAlertColumn('time', {
    'title': 'Time',
    'description': 'Alert timestamp',
    'field': 'kismet.alert.timestamp',
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        return (new Date(data * 1000).toString()).substring(4, 25);
    },
});

AddAlertColumn('txaddr', {
    'title': 'Transmitter',
    'description': 'Transmitter MAC',
    'field': 'kismet.alert.transmitter_mac',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        return kismet.censorMAC(data);
    },
});

AddAlertColumn('sxaddr', {
    'title': 'Source',
    'description': 'Source MAC',
    'field': 'kismet.alert.source_mac',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        return kismet.censorMAC(data);
    },
});

AddAlertColumn('dxaddr', {
    'title': 'Destination',
    'description': 'Destination MAC',
    'field': 'kismet.alert.dest_mac',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        return kismet.censorMAC(data);
    },
});

AddAlertColumn('text', {
    'title': 'Alert',
    'description': 'Alert content',
    'field': 'kismet.alert.text',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data === "00:00:00:00:00:00")
            return "<i>n/a</i>";
        return kismet.censorMAC(data);
    },
});

AddHiddenAlertColumn({'field': 'kismet.alert.hash'});

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
                                accordion = $('<div>', {
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
        return 'Alert JSON: <a href="alerts/by-id/' + data['kismet.alert.hash'] + '/alert.prettyjson" target="_new">link</a><br>';
    }});

exports.load_complete = 1;

return exports;

});
