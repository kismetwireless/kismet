(
  typeof define === "function" ? function (m) { define("kismet-ui-base-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_base = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

/* Define some callback functions for the table */

exports.renderLastTime = function(data, type, row, meta) {
    return (new Date(data * 1000).toString()).substring(4, 25);
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
    // I think looks better
    var avg = 0;
    var secs_avg = 3;

    var simple_rrd = [];
    var rrd_len = data["kismet_device_base_packets_rrd"]["kismet_common_rrd_minute_vec"].length;
    var startsec = data["kismet_device_base_packets_rrd"]["kismet_common_rrd_last_time"];
    var startslot = data["kismet_device_base_packets_rrd"]["kismet_common_rrd_last_time"] % 60;

    if (last_devicelist_time - startsec > 60) {
        for (var ri = 0; ri < (rrd_len / secs_avg); ri++) {
            simple_rrd.push(0);
        }
    } else {
        // Skip ahead by the number of seconds since the last time 
        var sec_offt = Math.max(0, last_devicelist_time - startsec);

        // Clobber some seconds
        for (var ri = 0; ri < sec_offt; ri++) {
            data["kismet_device_base_packets_rrd"]["kismet_common_rrd_minute_vec"][(startslot + ri) % rrd_len] = 0;
        }

        // And advance the start
        startslot = (startslot + sec_offt) % 60;

        for (var ri = 0; ri < rrd_len; ri++) {
            avg += data["kismet_device_base_packets_rrd"]["kismet_common_rrd_minute_vec"][(startslot + ri) % rrd_len];

            if ((ri % secs_avg) == (secs_avg - 1)) {
                simple_rrd.push(Math.round(avg / secs_avg));
                avg = 0;
            }
        }
    }

    // Render the sparkline
    $(match, row.node()).sparkline(simple_rrd,
        { type: "bar",
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
    mData: 'kismet_device_base_signal.kismet_common_signal_last_signal_dbm' 
});

kismet_ui.AddDeviceColumn('column_channel', {
    sTitle: 'Channel',
    mData: 'kismet_device_base_channel'
});

kismet_ui.AddDeviceColumn('column_time', {
    sTitle: 'Last Seen',
    mData: 'kismet_device_base_last_time',
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderLastTime'
});

kismet_ui.AddDeviceColumn('column_packet_rrd', {
    sTitle: 'Packets',
    mData: null,
    name: 'packets',
    cbmodule: 'kismet_ui_base',
    renderfunc: 'renderPackets',
    drawfunc: 'drawPackets'
});

console.log("kismet.ui.base.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});


