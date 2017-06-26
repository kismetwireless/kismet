(
  typeof define === "function" ? function (m) { define("kismet-ui-datasource-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_datasources = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: '/css/kismet.ui.datasources.css'
    });


/* Sidebar:  Channel coverage
 *
 * The channel coverage looks at the data sources and plots a moving graph
 * of all channels and how they're covered; it reflects how the pattern will
 * work, but not, necessarily, reality itself.
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'datasource_channel_coverage',
    listTitle: '<i class="fa fa-bar-chart-o"></i> Estimated Channel Coverage',
    clickCallback: function() {
        exports.ChannelCoverage();
    },
});

var channelcoverage_backend_tid;
var channelcoverage_display_tid;
var channelcoverage_panel = null;
var channelcoverage_chart = null;
var cc_uuid_pos_map = {};

exports.ChannelCoverage = function() {
    var w = $(window).width() * 0.85;
    var h = $(window).height() * 0.50;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    channelcoverage_chart = null;

    channelcoverage_panel = $.jsPanel({
        id: 'channelcoverage',
        headerTitle: '<i class="fa fa-bar-chart-o" /> Estimated Channel Coverage',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: '<canvas id="k-cc-canvas" style="k-cc-canvas" />',
        onclosed: function() {
            clearTimeout(channelcoverage_backend_tid);
            clearTimeout(channelcoverage_display_tid);
        }
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offy,
    });

    channelcoverage_backend_refresh();
    channelcoverage_display_refresh();
}

function channelcoverage_backend_refresh() {
    clearTimeout(channelcoverage_backend_tid);

    if (channelcoverage_panel == null)
        return;

    if (channelcoverage_panel.is(':hidden'))
        return;

    $.get("/datasource/all_sources.json")
    .done(function(data) {
        // Build a list of all devices we haven't seen before and set their 
        // initial positions to match
        for (var di = 0; di < data.length; di++) {
            if (!(data[di]['kismet.datasource.uuid'] in cc_uuid_pos_map)) {
                cc_uuid_pos_map[data[di]['kismet.datasource.uuid']] = {
                    uuid: data[di]['kismet.datasource.uuid'],
                    name: data[di]['kismet.datasource.name'],
                    interface: data[di]['kismet.datasource.interface'],
                    hopping: data[di]['kismet.datasource.hopping'],
                    channel: data[di]['kismet.datasource.channel'],
                    channels: data[di]['kismet.datasource.hop_channels'],
                    offset: data[di]['kismet.datasource.hop_offset'],
                    position: data[di]['kismet.datasource.hop_offset'],
                    skip: data[di]['kismet.datasource.hop_shuffle_skip'],
                };
            } else if (data[di]['kismet.datasource.running'] == 0) {
                delete cc_uuid_pos_map[data[di]['kismet.datasource.uuid']];
            }
        }
    })
    .always(function() {
        channelcoverage_backend_tid = setTimeout(channelcoverage_backend_refresh, 5000);
    });
}

function channelcoverage_display_refresh() {
    clearTimeout(channelcoverage_display_tid);

    if (channelcoverage_panel == null)
        return;

    if (channelcoverage_panel.is(':hidden'))
        return;

    // Now we know all the sources; make a list of all channels and figure
    // out if we're on any of them; each entry in total_channel_list contains
    // an array of UUIDs on this channel in this sequence
    var total_channel_list = {}

    for (var du in cc_uuid_pos_map) {
        var d = cc_uuid_pos_map[du];

        if (d['hopping']) {
            for (var ci = 0; ci < d['channels'].length; ci++) {
                var chan = d['channels'][ci];
                if (!(chan in total_channel_list)) {
                    total_channel_list[chan] = [ ];
                }

                if ((d['position'] % d['channels'].length) == ci) {
                    total_channel_list[chan].push(du);
                }
            }

            // Increment the virtual channel position for the graph
            if (d['skip'] == 0) {
                d['position'] = d['position'] + 1;
            } else {
                d['position'] = d['position'] + d['skip'];
            }
        } else {
            // Non-hopping sources are always on their channel
            var chan = d['channel'];

            if (!(chan in total_channel_list)) {
                total_channel_list[chan] = [ du ];
            } else {
                total_channel_list[chan].push(du);
            }
        }
    }

    // Create the channel index for the x-axis
    var chantitles = new Array();
    for (var ci in total_channel_list) {
        chantitles.push(ci);
    }	

    // Perform a natural
    var ncollator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});
    chantitles.sort(ncollator.compare);

    // Create the source datasets for the graph, covering all channels and
    // highlighting the channels we have a UUID in
    var source_datasets = []

    var ndev = 0;

    for (var du in cc_uuid_pos_map) {
        var d = cc_uuid_pos_map[du];

        var dset = [];

        for (var ci in chantitles) {
            var clist = total_channel_list[chantitles[ci]];

            if (clist.indexOf(du) < 0) {
                dset.push(0);
            } else {
                dset.push(1);
            }
        }

        var color = "hsl(" + parseInt(255 * (ndev / Object.keys(cc_uuid_pos_map).length)) + ", 100%, 50%)";

        source_datasets.push({
            label: d['name'],
            data: dset,
            borderColor: color,
            backgroundColor: color,
        });

	ndev++;

    }

    if (channelcoverage_chart == null) {
        var canvas = $('#k-cc-canvas', channelcoverage_panel.content);

        var bp = 5.0;

        if (chantitles.length < 14)
            bp = 2;

        channelcoverage_chart = new Chart(canvas, {
            type: "bar",
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    xAxes: [{ barPercentage: bp, }],
                },
            },
            data: {
                labels: chantitles,
                datasets: source_datasets,
            },
        });
    } else {
        channelcoverage_chart.data.datasets = source_datasets;
        channelcoverage_chart.data.labels = chantitles;
        channelcoverage_chart.update(0);
    }

    channelcoverage_display_tid = setTimeout(channelcoverage_display_refresh, 500);
}

/* Sidebar:  Data sources
 *
 * Combination of available data sources & current ones
 *
 */

kismet_ui_sidebar.AddSidebarItem({
    id: 'datasource_sources',
    listTitle: '<i class="fa fa-cogs"></i> Data Sources',
    priority: -500,
    clickCallback: function() {
        exports.DataSources();
    },
});

var datasource_list_tid;
var datasource_source_tid;
var datasource_panel = null;
var datasource_table = null;

var kismet_sources = new Array();

function PopulateExpanded(row) {
    var data = row.data();

    var enclosing_width = $(row.node()).innerWidth() - 50;

    var expanded = 
        $('<div>', {
            class: 'k-ds-details',
            style: 'max-width: ' + enclosing_width + 'px;',
        });

    if (kismet.ObjectByString(data, 'kismet.datasource.error')) {
        expanded.append(
            $('<div>', { 
                style: 'padding-bottom: 10px;',
            })
            .append(
                $('<i>', {
                    class: 'fa fa-minus-circle k-ds-error',
                })
            )
            .append(
                $('<span>', { 
                    style: 'padding-left: 10px;',
                })
                .html(kismet.ObjectByString(data, 'kismet.datasource.error_reason') + ' (' + kismet.ObjectByString(data, 'kismet.datasource.retry_attempts') + ' consecutive errors)')
            )
        )
    }

    var driver = kismet.ObjectByString(data, 'kismet.datasource.type_driver');
    if (driver != 0) {
        expanded.append(
            $('<div>', {
                style: 'padding-bottom: 5px; word-wrap: break-word;',     
            })
            .append(
                $('<p>', { })
                .html('Datasource: ' + driver['kismet.datasource.driver.type'])
            )
            .append(
                $('<p>', { })
                .html(driver['kismet.datasource.driver.description'])
            )
        );
    }

    expanded.append(
        $('<div>', {
            style: 'padding-bottom: 5px;',
        })
        .append(
            $('<p>', { })
            .html('UUID: ' + kismet.ObjectByString(data, 'kismet.datasource.uuid'))
        )
    );

    var channels = kismet.ObjectByString(data, 'kismet.datasource.channels');
    if (channels != 0 && channels.length > 1) {
        var chantext = "";
        for (var ci in channels) {
            chantext += channels[ci];

            if (ci < channels.length - 1)
                chantext += ", ";
        }

        expanded.append(
            $('<div>', { 
                style: 'padding-bottom: 5px;',
            })
            .append(
                $('<p>', { 
                    style: 'word-break: break-word; white-space: normal;',
                })
                .html("Channels: " + chantext)
            )
        );
    }


    return expanded;
}

exports.DataSources = function() {
    var w = $(window).width() * 0.85;
    var h = $(window).height() * 0.75;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    var cols = [
        {
            name: 'gadgets',
            sTitle: '',
            mData: '',
            mDraw: function(column, table, row) {
                var rid = table.column(column.name + ':name').index();
                var match = "td:eq(" + rid + ")";

                var data = row.data();

                var gadgets = $('<div>', {});

                var chev = 'fa-plus-square-o';

                if (row.child.isShown()) {
                    chev = 'fa-minus-square-o';
                }

                var g = 
                    $('<i>', {
                        class: 'fa ' + chev,
                        id: 'expander',
                        style: 'padding-right: 5px;',
                    });
                gadgets.append(g);

                var warn = kismet.ObjectByString(data, 'kismet.datasource.warning');
                if (warn.length != 0) {
                    var g = 
                        $('<i>', {
                            class: 'fa fa-exclamation-triangle k-ds-warning',
                        })
                        .tooltipster({ content: warn });

                    gadgets.append(g);
                }

                if (kismet.ObjectByString(data, 'kismet.datasource.running') == 0) {
                    var g =
                        $('<i>', {
                            class: 'fa fa-minus-circle k-ds-error',
                        })
                        .tooltipster({ content: kismet.ObjectByString(data, 'kismet.datasource.error_reason')});

                    gadgets.append(g);
                }

                $(match, row.node()).empty();
                $(match, row.node()).append(gadgets);
            },
            orderable: false,
            searchable: false,
        },
        {
            name: 'sourcename',
            sTitle: 'Source',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.name');
            },
        },
        {
            name: 'interface',
            sTitle: 'Interface',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.capture_interface');
            },
        },
        {
            name: 'type',
            sTitle: 'Type',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.type_driver/kismet.datasource.driver.type');
            },
        },
        {
            name: 'chanhop',
            sTitle: 'Hop',
            width: '8em',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.hopping');
            },
            mRender: function(data, type, row, meta) {
                if (data === 1)
                    return 'Hopping';
                return 'Locked';
            },
            className: 'dt-right',
        },
        {
            name: 'hoprate',
            sTitle: 'Hop Rate',
            width: '8em',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.hop_rate');
            },
            mRender: function(data, type, row, meta) {
                if (kismet.ObjectByString(row, 'kismet.datasource.hopping')) {
                    if (data >= 1) {
                        return data + '/sec';
                    } else {
                        return (data * 6) + '/min';
                    }
                }
                return 'Hopping';
            },
            className: 'dt-right',
        },
        {
            name: 'numchannels',
            sTitle: '# Channels',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.channels').length;
            },
            className: 'dt-right',
        },
        {
            name: 'channel',
            sTitle: 'Channel',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.channel');
            },
            mRender: function(data, type, row, meta) {
                if (!kismet.ObjectByString(row, 'kismet.datasource.hopping')) {
                    return data;
                }
                return 'n/a';
            },
            className: 'dt-right',
        },
        {
            name: 'packets',
            sTitle: 'Packets',
            mData: function(row, type, set) {
                return kismet.ObjectByString(row, 'kismet.datasource.num_packets');
            },
            className: 'dt-right',
        },
        {
            name: 'packetsrrd',
            sTitle: '',
            mData: '',
            mRender: function(data, type, row, meta) {
                return '<i>Preparing graph...</i>';
            },
            mDraw: function(column, table, row) {
                var rid = table.column(column.name + ':name').index();
                var match = "td:eq(" + rid + ")";

                var data = row.data();

                if (typeof(data['kismet.datasource.packets_rrd']) === 'undefined')
                    return;

                if (data['kismet.datasource.packets_rrd'] == 0)
                    return;

                var simple_rrd =
                    kismet.RecalcRrdData(
                        data['kismet.datasource.packets_rrd'],
                        data['kismet.datasource.packets_rrd']['kismet.common.rrd.last_time'],
                        kismet.RRD_SECOND,
                        data['kismet.datasource.packets_rrd']['kismet.common.rrd.minute_vec'], {
                            transform: function(data, opt) {
                                var slices = 3;
                                var peak = 0;
                                var ret = new Array();

                                for (var ri = 0; ri < data.length; ri++) {
                                    peak = Math.max(peak, data[ri]);

                                    if ((ri % slices) == (slices - 1)) {
                                        ret.push(peak);
                                        peak = 0;
                                    }
                                }

                                return ret;
                            }
                        });

                // Render the sparkline
                $(match, row.node()).sparkline(simple_rrd,
                    { type: "bar",
                        width: 100,
                        height: 12,
                        barColor: '#000000',
                        nullColor: '#000000',
                        zeroColor: '#000000'
                    });

            },
            orderable: false,
            searchable: false,
        },
        
    ]

    var content = 
        $('<div>', { 
            class: 'k-ds-tablediv',
        })
        .append(
            $('<table>', {
                width: '100%',
                id: 'sourcetable',
                class: 'k-ds-dstable nowrap',
            })
        );
        
    datasource_table = $('#sourcetable', content)
        .DataTable( {
            dom: 'ft',

            aoColumns: cols,

            data: kismet_sources,

            scrollY: '100px',
            scrollResize: true,
            paging: false,

            createdRow: function(row, data, index) {
                // console.log("Created row", data['kismet.datasource.source_number']);
                row.id = data['kismet.datasource.source_number'];
            },

            drawCallback: function( settings ) {
                var dt = this.api();

                dt.rows({
                    page: 'current'
                }).every(function(rowIdx, tableLoop, rowLoop) {
                    for (var c in cols) {
                        var col = cols[c];

                        if (!('mDraw' in col)) {
                            continue;
                        }

                        // Call the draw callback if one exists
                        col.mDraw(col, dt, this);
                    }

                });
            },
        })
        .draw(false);

    $('tbody', content).on('click', 'tr', function() {
        var row = datasource_table.row($(this));

        if (row.child.isShown()) {
            row.child.hide();
            $(this).removeClass('shown');
            $('#expander', $(this)).removeClass('fa-chevron-down');
            $('#expander', $(this)).addClass('fa-chevron-right');
        } else {
            var expanded = PopulateExpanded(row);
            row.child(expanded).show();
            $(this).addClass('shown');
            $('#expander', $(this)).addClass('fa-chevron-down');
            $('#expander', $(this)).removeClass('fa-chevron-right');
        }

    });

    datasource_panel = $.jsPanel({
        id: 'datasources',
        headerTitle: '<i class="fa fa-cogs" /> Data Sources',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: content,

        onresized: function() {
            var dt_base_height = this.content.height();
            var dt_base_width = this.content.width();

            // console.log(dt_base_height);

            if (datasource_table != null && dt_base_height != null) {
                $('div.dataTables_scrollBody', content).height(dt_base_height - 100);
                datasource_table.draw(false);
            }

        },

        onclosed: function() {
            clearTimeout(datasource_list_tid);
        }
    })
    .on('resize', function() {
       var dt_base_height = datasource_panel.content.height();
       var dt_base_width = datasource_panel.content.width();

       if (datasource_table != null && dt_base_height != null) {
           $('div.dataTables_scrollBody', content).height(dt_base_height - 100);
           datasource_table.draw(false);
       }
    })
    .resize({
        width: w,
        height: h
    })
    .reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offy,
    })
    .contentResize();

    datasource_source_refresh(function(data) {
        var scrollPos = $(".dataTables_scrollBody", content).scrollTop();

        for (var d in kismet_sources) {
            var s = kismet_sources[d];

            // console.log("Looking at source ", s['kismet.datasource.source_number']);

            var row = datasource_table.row('#' + s['kismet.datasource.source_number']);

            if (typeof(row.data()) === 'undefined') {
                console.log("Undefined row", s['kismet.datasource.source_number']);
                datasource_table.row.add(s);
            } else {
                row.data(s);

                if (row.child.isShown()) {
                    var expanded = PopulateExpanded(row);
                    row.child(expanded).show();
                }
            }
        }

        datasource_table.draw(false);
        $(".dataTables_scrollBody", content).scrollTop(scrollPos);
    });
}

/* Get the list of active sources */
function datasource_source_refresh(cb) {
    clearTimeout(datasource_list_tid);

    $.get("/datasource/all_sources.json")
    .done(function(data) {
        kismet_sources = data;
        cb(data);
    })
    .always(function() {
        datasource_list_tid = setTimeout(function() {
            datasource_source_refresh(cb)
        }, 1000);
    });
}


function datasource_list_refresh() {
    clearTimeout(datasource_list_tid);

    if (datasource_panel == null)
        return;

    if (datasource_panel.is(':hidden'))
        return;

    $.ajax({
        url: "/datasource/list_interfaces.json", 

        error: function(jqXHR, textStatus, errorThrown) {
            datasource_panel.content.html("Error: " + textStatus);
        },

    })
    .done(function(data) {
        // Build a list of all devices we haven't seen before and set their 
        // initial positions to match
        var content = datasource_panel.content;

        for (var ld = 0; ld < data.length; ld++) {
            var d = data[ld];

            content.append(
                $('<p>')
                .append(
                    $('<b>')
                    .text(d['kismet.datasource.probed.interface'])
                )
            );
        }
    });
};

// We're done loading
exports.load_complete = 1;

return exports;

});
