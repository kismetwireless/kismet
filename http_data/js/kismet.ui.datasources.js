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
    listTitle: '<i class="fa fa-bar-chart-o"></i> Channel Coverage',
    clickCallback: function() {
        exports.ChannelCoverage();
    },
});

var channelcoverage_backend_tid;
var channelcoverage_display_tid;
var channelcoverage_panel = null;
var channelcoverage_canvas = null;
var channelhop_canvas = null;
var channelcoverage_chart = null;
var channelhop_chart = null;
var cc_uuid_pos_map = {};

exports.ChannelCoverage = function() {
    var w = $(window).width() * 0.85;
    var h = $(window).height() * 0.75;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    channelcoverage_chart = null;
    channelhop_chart = null;

    var content =
        $('<div>', {
            id: "k-cc-main",
            class: "k-cc-main",
        })
        .append(
            $('<ul>', {
                id: "k-cc-tab-ul"
            })
            .append(
                $('<li>', { })
                .append(
                    $('<a>', {
                        href: '#k-cc-tab-coverage'
                    })
                    .html("Channel Coverage")
                )
            )
            .append(
                $('<li>', { })
                .append(
                    $('<a>', {
                        href: '#k-cc-tab-estimate'
                    })
                    .html("Estimated Hopping")
                )
            )
        )
        .append(
            $('<div>', {
                id: 'k-cc-tab-coverage',
                class: 'k-cc-canvas'
            })
            .append(
                $('<canvas>', {
                    id: 'k-cc-cover-canvas',
                    class: 'k-cc-canvas'
                })
            )
        )
        .append(
            $('<div>', {
                id: 'k-cc-tab-estimate',
                class: 'k-cc-canvas'
            })
            .append(
                $('<canvas>', {
                    id: 'k-cc-canvas',
                    class: 'k-cc-canvas'
                })
            )
        );

    channelcoverage_panel = $.jsPanel({
        id: 'channelcoverage',
        headerTitle: '<i class="fa fa-bar-chart-o" /> Channel Coverage',
        headerControls: {
            iconfont: 'jsglyph',
            minimize: 'remove',
            smallify: 'remove',
        },
        content: content,
        onclosed: function() {
            clearTimeout(channelcoverage_backend_tid);
            clearTimeout(channelcoverage_display_tid);
            channelhop_chart = null;
            channelhop_canvas = null;
            channelcoverage_canvas = null;
            channelcoverage_chart = null;
        },
        onresized: resize_channelcoverage,
        onmaximized: resize_channelcoverage,
        onnormalized: resize_channelcoverage,
    })
    .on('resize', function() {
        resize_channelcoverage();
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offy,
    });

    content.tabs({
        heightStyle: 'fill'
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
            if (data[di]['kismet.datasource.running'] == 0) {
                if ((data[di]['kismet.datasource.uuid'] in cc_uuid_pos_map)) {
                   delete cc_uuid_pos_map[data[di]['kismet.datasource.uuid']];
                }
            } else if (!(data[di]['kismet.datasource.uuid'] in cc_uuid_pos_map)) {
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
            } 

        }
    })
    .always(function() {
        channelcoverage_backend_tid = setTimeout(channelcoverage_backend_refresh, 5000);
    });
}

function resize_channelcoverage() {
    if (channelcoverage_panel == null)
        return;

    var container = $('#k-cc-main', channelcoverage_panel.content);

    var tabs = $('#k-cc-tab-ul', container);

    var w = container.width();
    var h = container.height() - tabs.outerHeight();

    $('#k-cc-tab-estimate', container)
        .css('width', w)
        .css('height', h);

    if (channelhop_canvas != null) {
        channelhop_canvas
            .css('width', w)
            .css('height', h);

        if (channelhop_chart != null)
             channelhop_chart.resize();
    }

    $('#k-cc-tab-coverage', container)
        .css('width', w)
        .css('height', h);

    if (channelcoverage_canvas != null) {
        channelcoverage_canvas
            .css('width', w)
            .css('height', h);

        if (channelcoverage_chart != null)
             channelcoverage_chart.resize();
    }

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

    // Create the channel index for the x-axis, used in both the hopping and the coverage
    // graphs
    var chantitles = new Array();
    for (var ci in total_channel_list) {
        chantitles.push(ci);
    }

    // Perform a natural sort on it to get it in order
    var ncollator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});
    chantitles.sort(ncollator.compare);

    // Create the source datasets for the animated estimated hopping graph, covering all 
    // channels and highlighting the channels we have a UUID in
    var source_datasets = new Array()

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

    // Create the source list for the Y axis of the coverage graph; we make an intermediary
    // which is sorted by name but includes UUID, then assemble the final one
    var sourcetitles_tmp = new Array();
    var sourcetitles = new Array();

    for (var ci in cc_uuid_pos_map) {
        sourcetitles_tmp.push({
            name: cc_uuid_pos_map[ci].name,
            uuid: ci
        });
    }

    sourcetitles_tmp.sort(function(a, b) {
        return a.name.localeCompare(b.name);
    });

    // Build the titles
    for (var si in sourcetitles_tmp) {
        sourcetitles.push(sourcetitles_tmp[si].name);
    }

    var bubble_dataset = new Array();

    // Build the bubble data
    ndev = 0;
    for (var si in sourcetitles_tmp) {
        var d = cc_uuid_pos_map[sourcetitles_tmp[si].uuid];
        var ds = new Array;

        if (d.hopping) {
            for (var ci in d.channels) {
                var c = d.channels[ci];

                var cp = chantitles.indexOf(c);

                if (cp < 0)
                    continue;

                ds.push({
                    x: cp,
                    y: si,
                    r: 5
                });
            }
        } else {
            var cp = chantitles.indexOf(d.channel);
            if (cp >= 0) {
                ds.push({
                    x: cp,
                    y: si,
                    r: 5
                });
            }
        }

        var color = "hsl(" + parseInt(255 * (ndev / Object.keys(cc_uuid_pos_map).length)) + ", 100%, 50%)";

        bubble_dataset.push({
            label: d.name,
            data: ds,
            borderColor: color,
            backgroundColor: color,
        });

        ndev++;

    }

    if (channelhop_canvas == null) {
        channelhop_canvas = $('#k-cc-canvas', channelcoverage_panel.content);

        var bp = 5.0;

        if (chantitles.length < 14)
            bp = 2;

        channelhop_chart = new Chart(channelhop_canvas, {
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
        channelhop_chart.data.datasets = source_datasets;
        channelhop_chart.data.labels = chantitles;
        channelhop_chart.update(0);
    }

    if (channelcoverage_canvas == null && sourcetitles.length != 0) {
        channelcoverage_canvas = $('#k-cc-cover-canvas', channelcoverage_panel.content);

        channelcoverage_chart = new Chart(channelcoverage_canvas, {
            type: 'bubble',
            options: {
                title: {
                    display: true,
                    text: 'Per-Source Channel Coverage',
                },
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    xAxes: [{
                        ticks: {
                            autoSkip: false,
                            stepSize: 1,
                            callback: function(value, index, values) {
                                return chantitles[value];
                            },
                            min: 0,
                            max: chantitles.length,
                            position: 'bottom',
                            type: 'linear',
                        }
                    }],
                    yAxes: [{
                        ticks: {
                            autoSkip: false,
                            stepSize: 1,
                            callback: function(value, index, values) {
                                return sourcetitles[value];
                            },
                            min: 0,
                            max: sourcetitles.length,
                            position: 'left',
                            type: 'linear',
                        },
                    }],
                },
            },
            data: {
                labels: chantitles,
                yLabels: sourcetitles,
                datasets: bubble_dataset,
            },
        });
    } else if (sourcetitles.length != 0) {
        channelcoverage_chart.data.datasets = bubble_dataset;

        channelcoverage_chart.data.labels = chantitles;
        channelcoverage_chart.data.yLabels = sourcetitles;

        channelcoverage_chart.options.scales.xAxes[0].ticks.min = 0; 
        channelcoverage_chart.options.scales.xAxes[0].ticks.max = chantitles.length; 

        channelcoverage_chart.options.scales.yAxes[0].ticks.min = 0; 
        channelcoverage_chart.options.scales.yAxes[0].ticks.max = sourcetitles.length; 

        channelcoverage_chart.update(0);
    }

    channelcoverage_display_tid = setTimeout(channelcoverage_display_refresh, 500);
}

/* Sidebar:  Data sources (new)
 *
 * Data source management panel
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'datasource_sources2',
    listTitle: '<i class="fa fa-cogs"></i> Data Sources (new)',
    priority: -500,
    clickCallback: function() {
        exports.DataSources2();
    },
});

function update_datasource2(data, state) {
    var set_row = function(sdiv, id, title, content) {
        var r = $('tr#' + id, sdiv);

        if (r.length == 0) {
            r = $('<tr>', { id: id })
            .append($('<td>'))
            .append($('<td>'));

            $('.k-ds-table', sdiv).append(r);
        }

        $('td:eq(0)', r).html(title);
        $('td:eq(1)', r).html(content);
    }

    // Clean up missing probed interfaces
    $('.interface', state['content']).each(function(i) {
        var found = false;

        for (var intf of state['kismet_interfaces']) {
            if ($(this).attr('id') === intf['kismet.datasource.probed.interface']) {
                found = true;
                break;
            }
        }

        if (!found) {
            console.log("didn't find", $(this).attr('id'));
            $(this).remove();
        }
    });
    

    for (var intf of state['kismet_interfaces']) {
        // Remove probed interfaces we don't have anymore
        if (intf['kismet.datasource.probed.in_use_uuid'] !== '00000000-0000-0000-0000-000000000000') {
            $('#' + intf['kismet.datasource.probed.interface'], state['content']).remove();
            continue;
        }

        var idiv = $('#' + intf['kismet.datasource.probed.interface'], state['content']);

        if (idiv.length == 0) {
            idiv = $('<div>', {
                id: intf['kismet.datasource.probed.interface'],
                class: 'accordion interface',
                })
            .append(
                $('<h3>', {
                    id: 'header',
                    class: 'k-ds-source',
                    html: "Available Source: " + intf['kismet.datasource.probed.interface'] + ' (' + intf['kismet.datasource.type_driver']['kismet.datasource.driver.type'] + ')',
                })
            ).append(
                $('<div>', {
                    id: 'content',
                    class: 'k-ds-content',
                })
            );

            var table = $('<table>', {
                class: 'k-ds-table'
                });

            $('#content', idiv).append(table);

            idiv.accordion({ collapsible: true, active: false });

            state['content'].append(idiv);
        }

        set_row(idiv, 'interface', '<b>Interface</b>', intf['kismet.datasource.probed.interface']);
        set_row(idiv, 'driver', '<b>Capture Driver</b>', intf['kismet.datasource.type_driver']['kismet.datasource.driver.type']);
        set_row(idiv, 'description', '<b>Type</b>', intf['kismet.datasource.type_driver']['kismet.datasource.driver.description']);

        idiv.accordion("refresh");
    }

    for (var source of state['kismet_sources']) {
        var sdiv = $('#' + source['kismet.datasource.uuid'], state['content']);

        if (sdiv.length == 0) {
            sdiv = $('<div>', {
                id: source['kismet.datasource.uuid'],
                class: 'accordion source',
                })
            .append(
                $('<h3>', {
                    id: 'header',
                    class: 'k-ds-source',
                    html: source['kismet.datasource.name'],
                })
                .append(
                    $('<span>', {
                        id: 'rrd',
                        class: 'k-ds-rrd',
                    })
                )
            ).append(
                $('<div>', {
                    id: 'content',
                    class: 'k-ds-content',
                })
            );

            var table = $('<table>', {
                class: 'k-ds-table'
                });

            $('#content', sdiv).append(table);

            sdiv.accordion({ collapsible: true, active: false });

            state['content'].append(sdiv);
        }

        if (typeof(source['kismet.datasource.packets_rrd']) !== 'undefined' &&
                source['kismet.datasource.packets_rrd'] != 0) {

            var simple_rrd =
                kismet.RecalcRrdData(
                    source['kismet.datasource.packets_rrd'],
                    source['kismet.datasource.packets_rrd']['kismet.common.rrd.last_time'],
                    kismet.RRD_SECOND,
                    source['kismet.datasource.packets_rrd']['kismet.common.rrd.minute_vec'], {
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
            $('#rrd', sdiv).sparkline(simple_rrd, { 
                type: "bar",
                width: 100,
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
                });
        }

        // $('#content', sdiv).html(source['kismet.datasource.type_driver']['kismet.datasource.driver.type']);
        
        var s = source['kismet.datasource.interface'];
        if (source['kismet.datasource.interface'] !==
                source['kismet.datasource.capture_interface']) {
            s = s + "(" + source['kismet.datasource.capture_interface'] + ")";
        }

        set_row(sdiv, 'interface', '<b>Interface</b>', s);
        set_row(sdiv, 'uuid', '<b>UUID</b>', source['kismet.datasource.uuid']);
        set_row(sdiv, 'packets', '<b>Packets</b>', source['kismet.datasource.num_packets']);

        sdiv.accordion("refresh");
    }
}

exports.DataSources2 = function() {
    var w = $(window).width() * 0.95;
    var h = $(window).height() * 0.75;
    var offy = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offy = 0;
    }

    var state = {};

    var content = 
        $('<div>', { 
            class: 'k-ds-tablediv',
        })
        
    datasource_panel = $.jsPanel({
        id: 'datasources',
        headerTitle: '<i class="fa fa-cogs" /> Data Sources',
        headerControls: {
            iconfont: 'jsglyph',
            minimize: 'remove',
            smallify: 'remove',
        },
        content: content,

        resizable: {
            stop: function(event, ui) {
                $('div.accordion', ui.element).accordion("refresh");
            }
        },

        onmaximized: function() {
            $('div.accordion', this.content).accordion("refresh");
        },

        onnormalized: function() {
            $('div.accordion', this.content).accordion("refresh");
        },

        onclosed: function() {
            clearTimeout(state['datasource_list_tid']);
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

    state["panel"] = datasource_panel;
    state["content"] = content;
    state["kismet_sources"] = [];
    state["kismet_interfaces"] = [];

    datasource_source_refresh(state, function(data) { 
            update_datasource2(data, state);
        });
    datasource_interface_refresh(state, function(data) { 
            update_datasource2(data, state);
        });
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

function datasourcepanel_resize(element) {
    var dt_base_height = element.content.height();
    var dt_base_width = element.content.width();
    
    if (datasource_table != null && dt_base_height != null) {
        $('div.dataTables_scrollBody', element.content).height(dt_base_height - 100);
        datasource_table.draw(false);
    }
}

exports.DataSources = function() {
    var w = $(window).width() * 0.95;
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

            order: [[ 1, "desc" ]],

            scrollY: '100px',
            scrollResize: true,
            paging: false,

            createdRow: function(row, data, index) {
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

    var state = {}

    datasource_panel = $.jsPanel({
        id: 'datasources',
        headerTitle: '<i class="fa fa-cogs" /> Data Sources',
        headerControls: {
            iconfont: 'jsglyph',
            minimize: 'remove',
            smallify: 'remove',
        },
        content: content,

        onresized: function() {
            datasourcepanel_resize(this);
        },
        onmaximized: function() {
            datasourcepanel_resize(this);
        },
        onnormalized: function() {
            datasourcepanel_resize(this);
        },

        onclosed: function() {
            clearTimeout(state['datasource_list_tid']);
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

    datasource_source_refresh(state, function(data) {
        var scrollPos = $(".dataTables_scrollBody", content).scrollTop();

        for (var s of state['kismet_sources']) {
            var row = datasource_table.row('#' + s['kismet.datasource.source_number']);

            if (typeof(row.data()) === 'undefined') {
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
function datasource_source_refresh(state, cb) {
    if ('datasource_get_tid' in state)
        clearTimeout(state['datasource_get_tid']);

    $.get("/datasource/all_sources.json")
    .done(function(data) {
        state['kismet_sources'] = data;
        cb(data);
    })
    .always(function() {
        state['datasource_get_tid'] = setTimeout(function() {
            datasource_source_refresh(state, cb)
        }, 1000);
    });
}

/* Get the list of potential interfaces */
function datasource_interface_refresh(state, cb) {
    if ('datasource_interface_tid' in state) 
        clearTimeout(state['datasource_interface_tid']);

    $.get("/datasource/list_interfaces.json")
    .done(function(data) {
        state['kismet_interfaces'] = data;
        cb(data);
    })
    .always(function() {
        state['datasource_interface_tid'] = setTimeout(function() {
            datasource_interface_refresh(state, cb)
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
