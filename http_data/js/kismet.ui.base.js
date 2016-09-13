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
                render: function(key, data, value) {
                    // Split out the mac from the mask
                    return value.split('/')[0];
                }
            },
            {
                field: "kismet_device_base_type",
                title: "Type",
                empty: "Unknown"
            },
            {
                field: "kismet_device_base_first_time",
                title: "First Seen",
                render: function(key, data, value) {
                    return new Date(value * 1000);
                }
            },
            {
                field: "kismet_device_base_last_time",
                title: "Last Seen",
                render: function(key, data, value) {
                    return new Date(value * 1000);
                }
            },
            {
                field: "group_signal_data",
                groupTitle: "Signal",
                id: "group_signal_data",

                fields: [
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_last_signal_dbm",
                    title: "Latest Signal",
                    render: function(key, data, value) {
                        return value + " dBm";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_last_signal_rssi",
                    title: "Latest Signal",
                    render: function(key, data, value) {
                        return value + " RSSI";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_last_noise_dbm",
                    title: "Latest Noise",
                    render: function(key, data, value) {
                        return value + " dBm";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_last_noise_rssi",
                    title: "Latest Noise",
                    render: function(key, data, value) {
                        return value + " RSSI";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_min_signal_dbm",
                    title: "Min. Signal",
                    render: function(key, data, value) {
                        return value + " dBm";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_min_signal_rssi",
                    title: "Min. Signal",
                    render: function(key, data, value) {
                        return value + " RSSI";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_max_signal_dbm",
                    title: "Max. Signal",
                    render: function(key, data, value) {
                        return value + " dBm";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_max_signal_rssi",
                    title: "Max. Signal",
                    render: function(key, data, value) {
                        return value + " RSSI";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_min_noise_dbm",
                    title: "Min. Noise",
                    render: function(key, data, value) {
                        return value + " dBm";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_min_noise_rssi",
                    title: "Min. Noise",
                    render: function(key, data, value) {
                        return value + " RSSI";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when dbm
                    field: "kismet_device_base_signal.kismet_common_signal_max_noise_dbm",
                    title: "Max. Noise",
                    render: function(key, data, value) {
                        return value + " dBm";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Only show when rssi
                    field: "kismet_device_base_signal.kismet_common_signal_max_noise_rssi",
                    title: "Max. Noise",
                    render: function(key, data, value) {
                        return value + " RSSI";
                    },
                    filter: function(key, data, value) {
                        return (value != 0);
                    }
                },
                { // Pseudo-field of aggregated location, only show when the location is valid
                    field: "kismet_device_base_signal.kismet_common_signal_peak_loc",
                    title: "Peak Location",
                    filter: function(key, data, value) {
                        return kismet.ObjectByString(data, "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_valid") == 1;
                    },
                    render: function(key, data, value) {
                        var loc = 
                            kismet.ObjectByString(data, "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_lat") + ", " + 
                            kismet.ObjectByString(data, "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_lon");

                        /*
                           if (kismet.ObjectByString(data, "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_fix") >= 3) {
                           loc += " " + kismet.ObjectByString(data, "kismet_device_base_signal.kismet_common_signal_peak_loc.kismet_common_location_alt") + " (M)";
                           }
                           */

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
                    render: function(key, data, value) {
                        return kismet.HumanReadableSize(value);
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
                filter: function(key, data, value) {
                    return (kismet.ObjectByString(data, "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_valid") == 1);
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
                    filter: function(key, data, value) {
                        return (kismet.ObjectByString(data, "kismet_device_base_location.kismet_common_location_avg_loc.kismet_common_location_fix") >= 3);
                    }

                }
                ],
            }
            ]
        });
    }
});

kismet_ui.AddDeviceDetail("packets", "Packet Rates", 10, {
    render: function(data) {
        // Make 3 divs for s, m, h RRD
        return '<div /><br /><div /><br /><div />';
    },
    draw: function(data, target) {
        var m = $('div:eq(0)', target);
        var h = $('div:eq(1)', target);
        var d = $('div:eq(2)', target);

        m.sparkline(data.kismet_device_base_packets_rrd.kismet_common_rrd_minute_vec,
            { type: "bar",
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
        h.sparkline(data.kismet_device_base_packets_rrd.kismet_common_rrd_hour_vec,
            { type: "bar",
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
        d.sparkline(data.kismet_device_base_packets_rrd.kismet_common_rrd_day_vec,
            { type: "bar",
                barColor: '#000000',
                nullColor: '#000000',
                zeroColor: '#000000'
            });
    }
});

console.log("kismet.ui.base.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});


