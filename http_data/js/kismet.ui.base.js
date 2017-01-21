(
  typeof define === "function" ? function (m) { define("kismet-ui-base-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_base = m(); }
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
        href: '/css/kismet.ui.base.css'
    });

/* Define some callback functions for the table */

exports.renderLastTime = function(data, type, row, meta) {
    return (new Date(data * 1000).toString()).substring(4, 25);
}

exports.renderDataSize = function(data, type, row, meta) {
    if (type === 'display')
        return kismet.HumanReadableSize(data);
    
    return data;
}

exports.renderMac = function(data, type, row, meta) {
    if (typeof(data) === 'undefined') {
        return "<i>n/a</i>";
    }

    return data.split('/')[0];
}

exports.renderSignal = function(data, type, row, meta) {
    if (data == 0)
        return "<i>n/a</i>"
    return data;
}

exports.renderChannel = function(data, type, row, meta) {
    if (data == 0)
        return "<i>n/a</i>"
    return data;
}

exports.renderPackets = function(data, type, row, meta) {
    return "<i>Preparing graph</i>";
}

exports.drawPackets = function(dyncolumn, table, row) {
    // Find the column
    var rid = table.column(dyncolumn.name + ':name').index();
    var match = "td:eq(" + rid + ")";

    var data = row.data();

    // Simplify the RRD so that the bars are thicker in the graph, which
    // I think looks better.  We do this with a transform function on the
    // RRD function, and we take the peak value of each triplet of samples
    // because it seems to be more stable, visually
    var simple_rrd = kismet.RecalcRrdData(data.kismet_device_base_packets_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_SECOND, data["kismet_device_base_packets_rrd"]["kismet_common_rrd_minute_vec"], {
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
        }});

    // Render the sparkline
    $(match, row.node()).sparkline(simple_rrd,
        { type: "bar",
            width: 100,
            height: 12,
            barColor: '#000000',
            nullColor: '#000000',
            zeroColor: '#000000'
        });
}

console.log("kismet.ui.base.js adding device columns");

// Define the basic columns
kismet_ui.AddDeviceColumn('column_name', {
    sTitle: 'Name',
    mData: 'kismet_device_base_name'
});

kismet_ui.AddDeviceColumn('column_type', {
    sTitle: 'Type',
    mData: 'kismet_device_base_type'
});

kismet_ui.AddDeviceColumn('column_phy', {
    sTitle: 'Phy',
    mData: 'kismet_device_base_phyname'
});

kismet_ui.AddDeviceColumn('column_signal', { 
    sTitle: 'Signal', 
    mData: 'kismet_device_base_signal.kismet_common_signal_last_signal_dbm',
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderSignal'
});

kismet_ui.AddDeviceColumn('column_channel', {
    sTitle: 'Channel',
    mData: 'kismet_device_base_channel',
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderChannel'
});

kismet_ui.AddDeviceColumn('column_time', {
    sTitle: 'Last Seen',
    mData: 'kismet_device_base_last_time',
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderLastTime'
});

kismet_ui.AddDeviceColumn('column_datasize', {
    sTitle: 'Data',
    mData: 'kismet_device_base_datasize',
    bUseRendered: false,
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderDataSize'
});

kismet_ui.AddDeviceColumn('column_packet_rrd', {
    sTitle: 'Packets',
    mData: null,
    name: 'packets',
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderPackets',
    drawfunc: 'drawPackets',
    orderable: false,
    searchable: false,
});

// Hidden row for mac address, searchable
kismet_ui.AddDeviceColumn('column_device_mac_hidden', {
    sTitle: 'MAC',
    mData: 'kismet_device_base_macaddr',
    searchable: true,
    orderable: false,
    visible: false,
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderMac'
});

// Add the (quite complex) device details.
// It has a priority of -1000 because we want it to always come first.
//
// There is no filter function because we always have base device
// details
//
// There is no render function because we immediately fill it during draw.
//
// The draw function will populate the kismet devicedata when pinged
console.log("adding device detail 'base'");
kismet_ui.AddDeviceDetail("base", "Device Info", -1000, {
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "genericDeviceData",
            "fields": [
            {
                field: "kismet_device_base_name",
                title: "Name",
                empty: "<i>None</i>"
            },
            {
                field: "kismet_device_base_macaddr",
                title: "MAC Address",
                render: function(opts) {
                    // Split out the mac from the mask
                    return opts['value'].split('/')[0];
                }
            },
            {
                field: "kismet_device_base_manuf",
                title: "Manufacturer",
                empty: "<i>Unknown</i>"
            },
            {
                field: "kismet_device_base_type",
                title: "Type",
                empty: "<i>Unknown</i>"
            },
            {
                field: "kismet_device_base_first_time",
                title: "First Seen",
                render: function(opts) {
                    return new Date(opts['value'] * 1000);
                }
            },
            {
                field: "kismet_device_base_last_time",
                title: "Last Seen",
                render: function(opts) {
                    return new Date(opts['value'] * 1000);
                }
            },
            {
                field: "group_frequency",
                groupTitle: "Frequencies",
                id: "group_frequency",

                fields: [
                {
                    field: "kismet_device_base_channel",
                    title: "Channel",
                    empty: "<i>None Advertised</i>"
                },
                {
                    field: "kismet_device_base_frequency",
                    title: "Main Frequency",
                    render: function(opts) {
                        return kismet.HumanReadableFrequency(opts['value']);
                    }
                },
                {
                    field: "frequency_map",
                    span: true,
                    render: function(opts) {
                        return '<center>Packet Frequency Distribution</center><div class="freqbar" id="' + opts['key'] + '" />';
                    },
                    draw: function(opts) {
                        var bardiv = $('div', opts['container']);

                        // Make an array morris likes using our whole data record
                        var moddata = new Array();

                        for (var fk in opts['data'].kismet_device_base_freq_khz_map) {
                            moddata.push({
                                y: kismet.HumanReadableFrequency(parseInt(fk)),
                                c: opts['data'].kismet_device_base_freq_khz_map[fk]
                            });
                        }

                        Morris.Bar({
                            element: bardiv,
                            data: moddata,
                            xkey: 'y',
                            ykeys: ['c'],
                            labels: ['Packets'],
                            hideHover: 'auto'
                        });
                    }
                },
                ]
            },
            {
                field: "group_signal_data",
                groupTitle: "Signal",
                id: "group_signal_data",

                filter: function(opts) {
                    var db = kismet.ObjectByString(opts['data'], "kismet_device_base_signal.kismet_common_signal_last_signal_dbm");
                    var rssi = kismet.ObjectByString(opts['data'], "kismet_device_base_signal.kismet_common_signal_last_signal_rssi");

                    if (db == 0 && rssi == 0)
                        return false;

                    return true;
                },

                fields: [
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_last_signal_dbm",
                    title: "Latest Signal",
                    render: function(opts) {
                        return opts['value'] + " dBm";
                    },
                    filterOnZero: true,
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_last_signal_rssi",
                    title: "Latest Signal",
                    render: function(opts) {
                        return opts['value'] + " RSSI";
                    },
                    filterOnZero: true,
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_last_noise_dbm",
                    title: "Latest Noise",
                    render: function(opts) {
                        return opts['value'] + " dBm";
                    },
                    filterOnZero: true,
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_last_noise_rssi",
                    title: "Latest Noise",
                    render: function(opts) {
                        return opts['value'] + " RSSI";
                    },
                    filterOnZero: true,
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_min_signal_dbm",
                    title: "Min. Signal",
                    render: function(opts) {
                        return opts['value'] + " dBm";
                    },
                    filterOnZero: true,
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_min_signal_rssi",
                    title: "Min. Signal",
                    render: function(opts) {
                        return opts['value'] + " RSSI";
                    },
                    filterOnZero: true,
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_max_signal_dbm",
                    title: "Max. Signal",
                    render: function(opts) {
                        return opts['value'] + " dBm";
                    },
                    filterOnZero: true,
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_max_signal_rssi",
                    title: "Max. Signal",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " RSSI";
                    },
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_min_noise_dbm",
                    title: "Min. Noise",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " dBm";
                    },
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_min_noise_rssi",
                    title: "Min. Noise",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " RSSI";
                    },
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_max_noise_dbm",
                    title: "Max. Noise",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " dBm";
                    },
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_max_noise_rssi",
                    title: "Max. Noise",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " RSSI";
                    },
                },
                { // Pseudo-field of aggregated location, only show when the location is valid
                    field: "kismet_device_base_signal.kismet_common_signal_peak_loc",
                    title: "Peak Location",
                    filter: function(opts) {
                        return kismet.ObjectByString(opts['data'], "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_valid") == 1;
                    },
                    render: function(opts) {
                        var loc = 
                            kismet.ObjectByString(opts['data'], "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_lat") + ", " + 
                            kismet.ObjectByString(opts['data'], "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_lon");

                        return loc;
                    },
                },

                ],
            },
            {
                field: "group_packet_counts",
                groupTitle: "Packets",
                id: "group_packet_counts",

                fields: [
                {
                    field: "graph_field_overall",
                    span: true,
                    render: function(opts) {
                        return '<div class="donut" id="' + opts['key'] + '" />';
                    },
                    draw: function(opts) {
                        var donutdiv = $('div', opts['container']);

                        // Make an array morris likes using our whole data record
                        var moddata = [
                        { label: "LLC/Management", value: opts['data'].kismet_device_base_packets_llc },
                        { label: "Data", value: opts['data'].kismet_device_base_packets_data }
                        ];

                        if (opts['data'].kismet_device_base_packets_error != 0)
                            moddata.push({ label: "Error", value: opts['data'].kismet_device_base_packets_error });

                        Morris.Donut({
                            element: donutdiv,
                            data: moddata
                        });
                    }
                },
                {
                    field: "kismet_device_base_packets_total",
                    title: "Total Packets"
                },
                {
                    field: "kismet_device_base_packets_llc",
                    title: "LLC/Management"
                },
                {
                    field: "kismet_device_base_packets_error",
                    title: "Error/Invalid"
                },
                {
                    field: "kismet_device_base_packets_data",
                    title: "Data"
                },
                {
                    field: "kismet_device_base_packets_crypt",
                    title: "Encrypted"
                },
                {
                    field: "kismet_device_base_packets_filtered",
                    title: "Filtered"
                },
                {
                    field: "kismet_device_base_datasize",
                    title: "Data Transferred",
                    render: function(opts) {
                        return kismet.HumanReadableSize(opts['value']);
                    }
                }


                ]
            },

            {
                // Location is its own group
                groupTitle: "Avg. Location",
                // Spoofed field for ID purposes
                field: "group_avg_location",
                // Sub-table ID
                id: "group_avg_location",

                // Don't show location if we don't know it
                filter: function(opts) {
                    return (kismet.ObjectByString(opts['data'], "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_valid") == 1);
                },

                // Fields in subgroup
                fields: [
                { 
                    field: "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_lat",
                    title: "Latitude"
                },
                {
                    field: "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_lon",
                    title: "Longitude"
                },
                {
                    field: "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_alt",
                    title: "Altitude (meters)",
                    filter: function(opts) {
                        return (kismet.ObjectByString(opts['data'], "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_fix") >= 3);
                    }

                }
                ],
            }
            ]
        });
    }
});

kismet_ui.AddDeviceDetail("packets", "Packet Graphs", 10, {
    render: function(data) {
        // Make 3 divs for s, m, h RRD
        return '<b>Packet Rates</b><br /><br />' +
            'Packets per second (last minute)<br /><div /><br />' + 
            'Packets per minute (last hour)<br /><div /><br />' + 
            'Packets per hour (last day)<br /><div />' +
            '<br /><b>Data</b><br /><br />' + 
            'Data per second (last minute)<br /><div /><br />' + 
            'Data per minute (last hour)<br /><div /><br />' + 
            'Data per hour (last day)<br /><div />';
    },
    draw: function(data, target) {
        var m = $('div:eq(0)', target);
        var h = $('div:eq(1)', target);
        var d = $('div:eq(2)', target);

        var dm = $('div:eq(3)', target);
        var dh = $('div:eq(4)', target);
        var dd = $('div:eq(5)', target);

        var mdata = kismet.RecalcRrdData(data.kismet_device_base_packets_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_SECOND, data["kismet_device_base_packets_rrd"]["kismet_common_rrd_minute_vec"], {});
        var hdata = kismet.RecalcRrdData(data.kismet_device_base_packets_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_MINUTE, data["kismet_device_base_packets_rrd"]["kismet_common_rrd_hour_vec"], {});
        var ddata = kismet.RecalcRrdData(data.kismet_device_base_packets_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_HOUR, data["kismet_device_base_packets_rrd"]["kismet_common_rrd_day_vec"], {});

        var dmdata = kismet.RecalcRrdData(data.kismet_device_base_datasize_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_SECOND, data["kismet_device_base_datasize_rrd"]["kismet_common_rrd_minute_vec"], {});
        var dhdata = kismet.RecalcRrdData(data.kismet_device_base_datasize_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_MINUTE, data["kismet_device_base_datasize_rrd"]["kismet_common_rrd_hour_vec"], {});
        var dddata = kismet.RecalcRrdData(data.kismet_device_base_datasize_rrd.kismet_common_rrd_last_time, last_devicelist_time, kismet.RRD_HOUR, data["kismet_device_base_datasize_rrd"]["kismet_common_rrd_day_vec"], {});

        m.sparkline(mdata, { type: "bar",
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
        h.sparkline(hdata,
            { type: "bar",
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
        d.sparkline(ddata,
            { type: "bar",
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });

        dm.sparkline(dmdata,
            { type: "bar",
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
        dh.sparkline(dhdata,
            { type: "bar",
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
        dd.sparkline(dddata,
            { type: "bar",
                height: 12,
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
    }
});

kismet_ui.AddDeviceDetail("seenby", "Seen By", 900, {
    filter: function(data) {
        return (Object.keys(data.kismet_device_base_seenby).length > 1);
    },
    draw: function(data, target) {
        target.devicedata(data, {
            id: "seenbyDeviceData",

            fields: [
            {
                field: "kismet_device_base_seenby",
                id: "seenby_group",
                groupIterate: true,
                iterateTitle: function(opts) {
                    return opts['value'][opts['index']].kismet_common_seenby_uuid;
                },
                fields: [
                {
                    field: "kismet_common_seenby_uuid",
                    title: "UUID",
                    empty: "<i>None</i>"
                },
                {
                    field: "kismet_common_seenby_first_time",
                    title: "First Seen",
                    render: function(opts) {
                        return new Date(opts['value'] * 1000);
                    }
                },
                {
                    field: "kismet_common_seenby_last_time",
                    title: "Last Seen",
                    render: function(opts) {
                        return new Date(opts['value'] * 1000);
                    }
                },
                ]
            }]
        });
    },
});

kismet_ui.AddDeviceDetail("devel", "Dev/Debug Options", 10000, {
    render: function(data) {
        return 'Device JSON: <a href="/devices/by-key/' + data.kismet_device_base_key + '/device.json" target="_new">link</a><br />';
    }});

/* Sidebar:  Memory monitor
 *
 * The memory monitor looks at system_status and plots the amount of 
 * ram vs number of tracked devices from the RRD
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'memory_sidebar',
    listTitle: '<i class="fa fa-tasks"></i> Memory Monitor',
    cbmodule: 'kismet_ui_base',
    clickCallback: 'MemoryMonitor'
});

var memoryupdate_tid;
var memory_panel = null;
var memory_chart = null;

exports.MemoryMonitor = function() {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.5;

    memory_chart = null;
        
    memory_panel = $.jsPanel({
        id: 'memory',
        headerTitle: '<i class="fa fa-tasks" /> Memory use',
        headerControls: {
            controls: 'closeonly'
        },
        content: '<canvas id="k-mm-canvas" style="k-mm-canvas" />',
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: 20
    });

    memorydisplay_refresh();
}

var memorydisplay_refresh = function() {
    clearTimeout(memoryupdate_tid);

    if (memory_panel == null)
        return;

    if (memory_panel.is(':hidden'))
        return;

    $.get("/system/status.json")
    .done(function(data) {
        // Common rrd type and source field
        var rrdtype = kismet.RRD_MINUTE;
        var rrddata = 'kismet_common_rrd_hour_vec';

        // Common point titles
        var pointtitles = new Array();

        for (var x = 0; x < 60; x++) {
            if (x % 5 == 0) {
                pointtitles.push(x);
            } else {
                pointtitles.push(' ');
            }
        }

        var mem_linedata =
            kismet.RecalcRrdData(
                data['kismet_system_memory_rrd']['kismet_common_rrd_last_time'],
                data['kismet_system_timestamp_sec'],
                rrdtype,
                data['kismet_system_memory_rrd'][rrddata]);

        for (var p in mem_linedata) {
            mem_linedata[p] = Math.round(mem_linedata[p] / 1024);
        }

        var dev_linedata =
            kismet.RecalcRrdData(
                data['kismet_system_devices_rrd']['kismet_common_rrd_last_time'],
                data['kismet_system_timestamp_sec'],
                rrdtype,
                data['kismet_system_devices_rrd'][rrddata]);

        var datasets = [
            {
                label: 'Memory (MB)',
                fill: 'false',
                yAxisID: 'mem-axis',
		borderColor: 'black',
                backgroundColor: 'transparent',
                data: mem_linedata,
            },
            {
                label: 'Devices',
                fill: 'false',
                yAxisID: 'dev-axis',
		borderColor: 'blue',
                backgroundColor: 'rgba(100, 100, 255, 0.33)',
                data: dev_linedata,
            }
        ];

        if (memory_chart == null) {
            var canvas = $('#k-mm-canvas', memory_panel.content);

            console.log(canvas);

            memory_chart = new Chart(canvas, {
                type: 'line',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        yAxes: [
                            {
                                position: "left",
                                "id": "mem-axis",
                                ticks: {
                                    beginAtZero: true,
                                }
                            }, {
                                position: "right",
                                "id": "dev-axis",
                                ticks: {
                                    beginAtZero: true,
                                }
                            }
                        ]
                    },
                },
                data: {
                    labels: pointtitles,
                    datasets: datasets
                }
            });
        
        } else {
            memory_chart.data.datasets = datasets;
            memory_chart.data.labels = pointtitles;
            memory_chart.update(0);
        }
    })
    .always(function() {
        memoryupdate_tid = setTimeout(memorydisplay_refresh, 5000);
    });
};

// Settings options
exports.SettingsUnitsPane = function(elem) {
    elem.append(
        $('<form>', { })
        .append(
            $('<fieldset>', { 
                id: 'set_distance',
            })
            .append(
                $('<legend>', { })
                .html("Distance")
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'dst_metric',
                    name: 'distance',
                    value: 'metric',
                })
            )
            .append(
                $('<label>', {
                    for: 'dst_metric',
                })
                .html('Metric')
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'dst_imperial',
                    name: 'distance',
                    value: 'imperial',
                })
            )
            .append(
                $('<label>', {
                    for: 'dst_imperial',
                })
                .html('Imperial')
            )
        )
        .append(
            $('<br>', { })
        )
        .append(
            $('<fieldset>', {
                id: 'set_speed'
            })
            .append(
                $('<legend>', { })
                .html("Speed")
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'spd_metric',
                    name: 'speed',
                })
            )
            .append(
                $('<label>', {
                    for: 'spd_metric',
                })
                .html('Metric')
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'spd_imperial',
                    name: 'speed',
                })
            )
            .append(
                $('<label>', {
                    for: 'spd_imperial',
                })
                .html('Imperial')
            )
        )
        .append(
            $('<br>', { })
        )
        .append(
            $('<fieldset>', {
                id: 'set_temp'
            })
            .append(
                $('<legend>', { })
                .html("Temperature")
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'temp_celcius',
                    name: 'temp',
                })
            )
            .append(
                $('<label>', {
                    for: 'temp_celcius',
                })
                .html('Celcius')
            )
            .append(
                $('<input>', {
                    type: 'radio',
                    id: 'temp_farenheit',
                    name: 'temp',
                })
            )
            .append(
                $('<label>', {
                    for: 'temp_farenheit',
                })
                .html('Farenheit')
            )
        )
    );

    $('#set_distance', elem)
        .controlgroup()
        .on('change', function() {
            var dist = $("input[name='distance']:checked", elem).val();
            kismet.putStorage('kismet.base.unit.distance', dist);
        });

    $('#set_speed', elem)
        .controlgroup()
        .on('change', function() {
            var spd = $("input[name='speed']:checked", elem).val();
            kismet.putStorage('kismet.base.unit.speed', spd);
        });
    $('#set_temp', elem)
        .controlgroup()
        .on('change', function() {
            var tmp = $("input[name='temp']:checked", elem).val();
            kismet.putStorage('kismet.base.unit.temp', tmp);
        });

    exports.SettingsUnitsReset(elem);

}

exports.SettingsUnitsReset = function(elem) {
    if (kismet.getStorage('kismet.base.unit.distance', 'metric') === 'metric') {
        $('#dst_metric', elem).attr('checked', 'checked');
    } else {
        $('#dst_imperial', elem).attr('checked', 'checked');
    }

    if (kismet.getStorage('kismet.base.unit.speed', 'metric') === 'metric') {
        $('#spd_metric', elem).attr('checked', 'checked');
    } else {
        $('#spd_imperial', elem).attr('checked', 'checked');
    }

    if (kismet.getStorage('kismet.base.unit.temp', 'celcius') === 'celcius') {
        $('#temp_celcius', elem).attr('checked', 'checked');
    } else {
        $('#temp_farenheit', elem).attr('checked', 'checked');
    }

    $('#set_distance', elem).controlgroup('refresh');
    $('#set_speed', elem).controlgroup('refresh');
    $('#set_temp', elem).controlgroup('refresh');


}

exports.SettingsUnitsSave = function(elem) {
    return true;
}

kismet_ui_settings.AddSettingsPane({
    listTitle: 'Units &amp; Measurements',
    cbmodule: 'kismet_ui_base',
    create: 'SettingsUnitsPane',
    reset: 'SettingsUnitsReset',
    save: 'SettingsUnitsSave'
});

console.log("kismet.ui.base.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});


