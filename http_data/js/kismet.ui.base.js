(
  typeof define === "function" ? function (m) { define("kismet-ui-base-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_base = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = "";
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Flag we're still loading
exports.load_complete = 0;

/* Fetch the system user */
$.get(local_uri_prefix + "system/user_status.json")
.done(function(data) {
    exports.system_user = data['kismet.system.user'];
})
.fail(function() {
    exports.system_user = "[unknown]";
});

// Load our css
$('<link>')
    .appendTo('head')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.ui.base.css'
    });

/* Call from index to set the required ajax parameters universally */
exports.ConfigureAjax = function() {
    $.ajaxSetup({
        beforeSend: function (xhr) {
            var user = kismet.getStorage('kismet.base.login.username', 'kismet');
            var pw =  kismet.getStorage('kismet.base.login.password', '');

            xhr.setRequestHeader ("Authorization", "Basic " + btoa(user + ":" + pw));
        },

        /*
        dataFilter: function(data, type) {
            try {
                var json = JSON.parse(data);
                var sjson = kismet.sanitizeObject(json);
                console.log(JSON.stringify(sjson));
                return JSON.stringify(sjson);
            } catch {
                return data;
            }
        },
        */
    });
}

exports.ConfigureAjax();

var eventbus_ws_listeners = [];

exports.eventbus_ws = null;

exports.SubscribeEventbus = function(topic, fields, callback) {
    var sub = {
        "topic": topic,
        "callback": callback
    }

    if (fields.length > 0)
        sub["fields"] = fields;

    eventbus_ws_listeners.push(sub);

    if (exports.eventbus_ws != null && exports.eventbus_ws.readyState == 1) {
        var sub_req = {
            "SUBSCRIBE": sub["topic"],
        };

        if ("fields" in sub)
            sub_req["fields"] = sub["fields"]

        exports.eventbus_ws.send(JSON.stringify(sub_req));
    }
}

exports.OpenEventbusWs = function() {
    var proto = "";

    if (document.location.protocol == "https:")
        proto = "wss"
    else
        proto = "ws"

    var user = kismet.getStorage('kismet.base.login.username', 'kismet');
    var pw =  kismet.getStorage('kismet.base.login.password', '');

    var host = new URL(document.URL);

    var ws_url = `${proto}://${host.host}/${KISMET_PROXY_PREFIX}eventbus/events.ws?user=${encodeURIComponent(user)}&password=${encodeURIComponent(pw)}`

    exports.eventbus_ws = new WebSocket(ws_url);

    exports.eventbus_ws.onclose = function(event) {
        setTimeout(function() { exports.OpenEventbusWs(); }, 500);
    };

    exports.eventbus_ws.onmessage = function(event) {
        try {
            var json = JSON.parse(event.data);

            for (var x in json) {
                for (var sub of eventbus_ws_listeners) {
                    if (sub["topic"] === x) {
                        sub["callback"](json[x]);
                    }
                }
            }
        } catch (e) {
            console.log(e);
        }
    }

    exports.eventbus_ws.onopen = function(event) {
        for (var sub of eventbus_ws_listeners) {
            var sub_req = {
                "SUBSCRIBE": sub["topic"],
            };

            if ("fields" in sub)
                sub_req["fields"] = sub["fields"]

            exports.eventbus_ws.send(JSON.stringify(sub_req));
        }
    }
};

exports.SubscribeEventbus("TIMESTAMP", [], function(data) {
    data = kismet.sanitizeObject(data);
    kismet.timestamp_sec = data['kismet.system.timestamp.sec'];
    kismet.timestamp_usec = data['kismet.system.timestamp.usec'];
});

exports.renderUsecTime = function(data) {
    if (data == 0)
        return "<i>n/a</i>";

    var data_sec = data / 1000000;

    var days = Math.floor(data_sec / 86400);
    var hours = Math.floor((data_sec / 3600) % 24);
    var minutes = Math.floor((data_sec / 60) % 60);
    var seconds = Math.floor(data_sec % 60);

    var ret = "";

    if (days > 0)
        ret = ret + days + "d ";
    if (hours > 0 || days > 0)
        ret = ret + hours + "h ";
    if (minutes > 0 || hours > 0 || days > 0)
        ret = ret + minutes + "m ";
    ret = ret + seconds + "s";

    return ret;
}

kismet_ui.AddDeviceColumn("commonname", {
    'title': 'Name',
    'description': 'Device name',
    'field': 'kismet.device.base.commonname',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        data = kismet.censorMAC(data);
        return kismet.censorString(data);
    },
});

kismet_ui.AddDeviceColumn("type", {
    'title': 'Type',
    'description': 'Device type',
    'field': 'kismet.device.base.type',
    'sortable': true,
    'searchable': true,
});

kismet_ui.AddDeviceColumn("crypt", {
    'title': 'Encryption',
    'description': 'Advertised encryption information',
    'field': 'kismet.device.base.crypt',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data.length == 0)
            return "<i>n/a</i>";
        return data;
    },
});

kismet_ui.AddDeviceColumn("first_time", {
    'title': 'First Seen',
    'description': 'First seen timestamp',
    'field': 'kismet.device.base.first_time',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        return (new Date(data * 1000).toString()).substring(4, 25);
    }
});

kismet_ui.AddDeviceColumn("last_time", {
    'title': 'Last Seen',
    'description': 'Last active timestamp',
    'field': 'kismet.device.base.last_time',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        return (new Date(data * 1000).toString()).substring(4, 25);
    },
});

kismet_ui.AddDeviceColumn("signal", {
    'title': 'Signal',
    'description': 'Last observed signal',
    'field': ['kismet.device.base.signal/kismet.common.signal.last_signal', 'device_last_signal'],
    'sortable': true,
    'alignment': 'right',
    'render': (data, row, cell, onrender, aux) => {
        if (data == 0)
            return "<i>n/a</i>"
        return data;
    },
});

kismet_ui.AddDeviceColumn("channel", {
    'title': 'Channel',
    'description': 'Last observed chanel',
    'field': 'kismet.device.base.channel',
    'fields': ['kismet.device.base.frequency', 'kismet.device.base.phyname'],
    'sortable': true,
    'alignment': 'right',
    'render': (data, row, cell, onrender, aux) => {
        if (data != 0) {
            return data
        } else if ('kismet.device.base.phyname' in row && 'kismet.device.base.frequency' in row &&
            row['kismet.device.base_frequency'] != 0) {
                return kismet_ui.GetPhyConvertedChannel(row['kismet.device.base.phyname'], row['kismet.device.base.frequency']);
        } else {
            return "<i>n/a</i>";
        }
    }
});

kismet_ui.AddDeviceColumn("datasize", {
    'title': 'Data',
    'description': 'Data seen',
    'field': 'kismet.device.base.datasize',
    'sortable': true,
    'alignment': 'right',
    'render': (data, row, cell, onrender, aux) => {
        return kismet.HumanReadableSize(data);
    },
});

kismet_ui.AddDeviceColumn("macaddr", {
    'title': 'Address',
    'description': 'Device address (typically MAC address)',
    'field': 'kismet.device.base.macaddr',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        return kismet.censorMAC(data);
    },
});

kismet_ui.AddDeviceColumn("manuf", {
    'title': 'Manufacturer',
    'desscription': 'Device manufacturer',
    'field': 'kismet.device.base.manuf',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onerender, aux) => {
        return (data.length > 32) ? data.substr(0, 31) + '&hellip;' : data;
    },
});

kismet_ui.AddDeviceColumn("packet_rrd", {
    'title': 'Packets',
    'description': 'Packet history graph',
    'field': ['kismet.device.base.packets.rrd', 'packet_rrd'],
    'sortable': true,
    'sortfield': 'kismet.device.base.packets.rrd/kismet.common.rrd.last_value',
    'render': (data, row, cell, onrender, aux) => {
        // Simplify the RRD so that the bars are thicker in the graph, which
        // I think looks better.  We do this with a transform function on the
        // RRD function, and we take the peak value of each triplet of samples
        // because it seems to be more stable, visually
        //
        // We use the aliased field names we extracted from just the minute
        // component of the per-device packet RRD
        var simple_rrd =
            kismet.RecalcRrdData2(data, kismet.RRD_SECOND, {
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

        onrender(() => {
            $(cell.getElement()).sparkline(simple_rrd,
                { type: "bar",
                    width: "100px",
                    height: 12,
                    barColor: kismet_theme.sparkline_main,
                    nullColor: kismet_theme.sparkline_main,
                    zeroColor: kismet_theme.sparkline_main,
                });
        });

    }
});

kismet_ui.AddDeviceColumn("packets", {
    'title': 'Total packets',
    'desscription': 'Total packets',
    'field': 'kismet.device.base.packets.total',
    'sortable': true,
    'searchable': false,
});

kismet_ui.AddDeviceColumn("seenbycount", {
    'title': 'Seen by #',
    'description': '# of datasources which have seen this device',
    'field': 'kismet.device.base.seenby',
    'sortable': true,
    'searchable': false,
    'render': (data, row, cell, onrender, aux) => {
        onrender(() => {
            $(cell.getElement()).html(`${row['seenbycount'].length}`);
        });
    },
});

kismet_ui.AddHiddenDeviceColumn({'field': 'kismet.device.base.phyname', 'searchable': true});
kismet_ui.AddHiddenDeviceColumn({'field': 'kismet.device.base.macaddr', 'searchable': true});

// Add the (quite complex) device details.
// It has a priority of -1000 because we want it to always come first.
//
// There is no filter function because we always have base device
// details
//
// There is no render function because we immediately fill it during draw.
//
// The draw function will populate the kismet devicedata when pinged
kismet_ui.AddDeviceDetail("base", "Device Info", -1000, {
    draw: function(data, target, options, storage) {
        target.devicedata(data, {
            "id": "genericDeviceData",
            "fields": [
            {
                field: "kismet.device.base.name",
                title: "Name",
                help: "Device name, derived from device characteristics or set as a custom name by the user.",
                draw: function(opts) {
                    var name = opts['data']['kismet.device.base.username'];

                    if (typeof(name) != 'undefined' && name != "") {
                        name = kismet.censorString(name);
                    }

                    if (typeof(name) == 'undefined' || name == "") {
                        name = opts['data']['kismet.device.base.commonname'];
                        name = kismet.censorString(name);
                    }

                    if (typeof(name) == 'undefined' || name == "") {
                        name = opts['data']['kismet.device.base.macaddr'];
                        name = kismet.censorMAC(name);
                    }


                    var nameobj =
                        $('<a>', {
                            'href': '#'
                        })
                        .html(name);

                    nameobj.editable({
                        type: 'text',
                        mode: 'inline',
                        success: function(response, newvalue) {
                            var jscmd = {
                                "username": newvalue
                            };
                            var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));
                            $.post(local_uri_prefix + "devices/by-key/" + opts['data']['kismet.device.base.key'] + "/set_name.cmd", postdata, "json");
                        }
                    });

                    var container =
                        $('<span>');
                    container.append(nameobj);
                    container.append(
                        $('<i>', {
                            'class': 'copyuri pseudolink fa fa-copy',
                            'style': 'padding-left: 5px;',
                            'data-clipboard-text': `${name}`,
                        })
                    );

                    return container;
                }
            },

            {
                field: "kismet.device.base.tags/notes",
                title: "Notes",
                help: "Abritrary notes",
                draw: function(opts) {
                    var notes = "";

                    if ('kismet.device.base.tags' in opts['data'])
                        notes = opts['data']['kismet.device.base.tags']['notes'];

                    if (notes == null)
                        notes = "";

                    var notesobj =
                        $('<a>', {
                            'href': '#',
                            'data-type': 'textarea',
                        })
                        .html(notes.convertNewlines());

                    notesobj.editable({
                        type: 'text',
                        mode: 'inline',
                        success: function(response, newvalue) {
                            var jscmd = {
                                "tagname": "notes",
                                "tagvalue": newvalue.escapeSpecialChars(),
                            };
                            var postdata = "json=" + encodeURIComponent(JSON.stringify(jscmd));
                            $.post(local_uri_prefix + "devices/by-key/" + opts['data']['kismet.device.base.key'] + "/set_tag.cmd", postdata, "json");
                        }
                    });

                    return notesobj;
                }
            },


            {
                field: "kismet.device.base.macaddr",
                title: "MAC Address",
                help: "Unique per-phy address of the transmitting device, when available.  Not all phy types provide MAC addresses, however most do.",
                draw: function(opts) {
                    var mac = kismet.censorMAC(opts['value']);

                    var container =
                        $('<span>');
                    container.append(
                        $('<span>').html(mac)
                    );
                    container.append(
                        $('<i>', {
                            'class': 'copyuri pseudolink fa fa-copy',
                            'style': 'padding-left: 5px;',
                            'data-clipboard-text': `${mac}`,
                        })
                    );

                    return container;
                }
            },
            {
                field: "kismet.device.base.manuf",
                title: "Manufacturer",
                empty: "<i>Unknown</i>",
                help: "Manufacturer of the device, derived from the MAC address.  Manufacturers are registered with the IEEE and resolved in the files specified in kismet.conf under 'manuf='",
            },
            {
                field: "kismet.device.base.type",
                liveupdate: true,
                title: "Type",
                empty: "<i>Unknown</i>"
            },
            {
                field: "kismet.device.base.first_time",
                liveupdate: true,
                title: "First Seen",
                draw: function(opts) {
                    return new Date(opts['value'] * 1000);
                }
            },
            {
                field: "kismet.device.base.last_time",
                liveupdate: true,
                title: "Last Seen",
                draw: function(opts) {
                    return new Date(opts['value'] * 1000);
                }
            },
            {
                field: "group_frequency",
                groupTitle: "Frequencies",
                id: "group_frequency",
                liveupdate: true,

                fields: [
                {
                    field: "kismet.device.base.channel",
                    title: "Channel",
                    empty: "<i>None Advertised</i>",
                    help: "The phy-specific channel of the device, if known.  The advertised channel defines a specific, known channel, which is not affected by channel overlap.  Not all phy types advertise fixed channels, and not all device types have fixed channels.  If an advertised channel is not available, the primary frequency is used.",
                },
                {
                    field: "kismet.device.base.frequency",
                    title: "Main Frequency",
                    help: "The primary frequency of the device, if known.  Not all phy types advertise a fixed frequency in packets.",
                    draw: function(opts) {
                        return kismet.HumanReadableFrequency(opts['value']);
                    },
                    filterOnZero: true,
                },
                {
                    field: "frequency_map",
                    span: true,
                    liveupdate: true,
                    filter: function(opts) {
                        try {
                            return (Object.keys(opts['data']['kismet.device.base.freq_khz_map']).length >= 1);
                        } catch (error) {
                            return 0;
                        }
                    },
                    render: function(opts) {
                        var d =
                            $('<div>', {
                                style: 'display: flex; justify-content: center; align-items: center; height: 250px',
                            })
                            .append(
                                $('<canvas>', {
                                    id: 'freqdist',
                                    style: 'margin: 0 auto;'
                                })
                            );

                        return d;

                    },
                    draw: function(opts) {
                        var legend = new Array();
                        var data = new Array();

                        for (var fk in opts['data']['kismet.device.base.freq_khz_map']) {
                            legend.push(kismet.HumanReadableFrequency(parseInt(fk)));
                            data.push(opts['data']['kismet.device.base.freq_khz_map'][fk]);
                        }

                        var barChartData = {
                            labels: legend,

                            datasets: [{
                                label: 'Dataset 1',
                                backgroundColor: 'rgba(46, 99, 162, 1)',
                                borderWidth: 0,
                                data: data,
                            }]

                        };

                        if ('freqchart' in window[storage]) {
                            window[storage].freqchart.data.labels = legend;
                            window[storage].freqchart.data.datasets[0].data = data;
                            window[storage].freqchart.update('none');
                        } else {
                            window[storage].freqchart =
                                new Chart($('canvas', opts['container']), {
                                    type: 'bar',
                                    data: barChartData,
                                    options: {
                                        maintainAspectRatio: false,
                                        animation: false,
                                        plugins: {
                                            legend: {
                                                display: false,
                                            },
                                            title: {
                                                display: true,
                                                text: 'Packet frequency distribution'
                                            }
                                        }
                                    }
                                });

                            window[storage].freqchart.update('none');
                        }
                    }
                },
                ]
            },
            {
                field: "group_signal_data",
                groupTitle: "Signal",
                id: "group_signal_data",

                filter: function(opts) {
                    var db = kismet.ObjectByString(opts['data'], "kismet.device.base.signal/kismet.common.signal.last_signal");

                    if (db == 0)
                        return false;

                    return true;
                },

                fields: [
                {
                    field: "kismet.device.base.signal/kismet.common.signal.signal_rrd",
                    filterOnZero: true,
                    title: "Monitor Signal",

                    render: function(opts) {
                        return '<div class="monitor pseudolink">Monitor</div>';
                    },
                    draw: function(opts) {
                        $('div.monitor', opts['container'])
                        .on('click', function() {
                            exports.DeviceSignalDetails(opts['data']['kismet.device.base.key']);
                        });
                    },

                    /* RRD - come back to this later
                    render: function(opts) {
                        return '<div class="rrd" id="' + opts['key'] + '" />';
                    },
                    draw: function(opts) {
                        var rrdiv = $('div', opts['container']);

                        var rrdata = kismet.RecalcRrdData(opts['data']['kismet.device.base.signal']['kismet.common.signal.signal_rrd']['kismet.common.rrd.last_time'], last_devicelist_time, kismet.RRD_MINUTE, opts['data']['kismet.device.base.signal']['kismet.common.signal.signal_rrd']['kismet.common.rrd.minute_vec'], {});

                        // We assume the 'best' a signal can usefully be is -20dbm,
                        // that means we're right on top of it.
                        // We can assume that -100dbm is a sane floor value for
                        // the weakest signal.
                        // If a signal is 0 it means we haven't seen it at all so
                        // just ignore that data point
                        // We turn signals into a 'useful' graph by clamping to
                        // -100 and -20 and then scaling it as a positive number.
                        var moddata = new Array();

                        for (var x = 0; x < rrdata.length; x++) {
                            var d = rrdata[x];

                            if (d == 0)
                                moddata.push(0);

                            if (d < -100)
                                d = -100;

                            if (d > -20)
                                d = -20;

                            // Normalize to 0-80
                            d = (d * -1) - 20;

                            // Reverse (weaker is worse), get as percentage
                            var rs = (80 - d) / 80;

                            moddata.push(100*rs);
                        }

                        rrdiv.sparkline(moddata, { type: "bar",
                            height: 12,
                            barColor: kismet_theme.sparkline_main,
                            nullColor: kismet_theme.sparkline_main,
                            zeroColor: kismet_theme.sparkline_main,
                        });

                    }
                    */

                },
                {
                    field: "kismet.device.base.signal/kismet.common.signal.last_signal",
                    liveupdate: true,
                    title: "Latest Signal",
                    help: "Most recent signal level seen.  Signal levels may vary significantly depending on the data rates used by the device, and often, wireless drivers and devices cannot report strictly accurate signal levels.",
                    draw: function(opts) {
                        return opts['value'] + " " + data["kismet.device.base.signal"]["kismet.common.signal.type"];
                    },
                    filterOnZero: true,
                },
                {
                    field: "kismet.device.base.signal/kismet.common.signal.last_noise",
                    liveupdate: true,
                    title: "Latest Noise",
                    help: "Most recent noise level seen.  Few drivers can report noise levels.",
                    draw: function(opts) {
                        return opts['value'] + " " + data["kismet.device.base.signal"]["kismet.common.signal.type"];
                    },
                    filterOnZero: true,
                },
                {
                    field: "kismet.device.base.signal/kismet.common.signal.min_signal",
                    liveupdate: true,
                    title: "Min. Signal",
                    help: "Weakest signal level seen.  Signal levels may vary significantly depending on the data rates used by the device, and often, wireless drivers and devices cannot report strictly accurate signal levels.",
                    draw: function(opts) {
                        return opts['value'] + " " + data["kismet.device.base.signal"]["kismet.common.signal.type"];
                    },
                    filterOnZero: true,
                },

                {
                    field: "kismet.device.base.signal/kismet.common.signal.max_signal",
                    liveupdate: true,
                    title: "Max. Signal",
                    help: "Strongest signal level seen.  Signal levels may vary significantly depending on the data rates used by the device, and often, wireless drivers and devices cannot report strictly accurate signal levels.",
                    draw: function(opts) {
                        return opts['value'] + " " + data["kismet.device.base.signal"]["kismet.common.signal.type"];
                    },
                    filterOnZero: true,
                },
                {
                    field: "kismet.device.base.signal/kismet.common.signal.min_noise",
                    liveupdate: true,
                    title: "Min. Noise",
                    filterOnZero: true,
                    help: "Least amount of interference or noise seen.  Most capture drivers are not capable of measuring noise levels.",
                    draw: function(opts) {
                        return opts['value'] + " " + data["kismet.device.base.signal"]["kismet.common.signal.type"];
                    },
                },
                {
                    field: "kismet.device.base.signal/kismet.common.signal.max_noise",
                    liveupdate: true,
                    title: "Max. Noise",
                    filterOnZero: true,
                    help: "Largest amount of interference or noise seen.  Most capture drivers are not capable of measuring noise levels.",
                    draw: function(opts) {
                        return opts['value'] + " " + data["kismet.device.base.signal"]["kismet.common.signal.type"];
                    },
                },
                { // Pseudo-field of aggregated location, only show when the location is valid
                    field: "kismet.device.base.signal/kismet.common.signal.peak_loc",
                    liveupdate: true,
                    title: "Peak Location",
                    help: "When a GPS location is available, the peak location is the coordinates at which the strongest signal level was recorded for this device.",
                    filter: function(opts) {
                        return kismet.ObjectByString(opts['data'], "kismet.device.base.signal/kismet.common.signal.peak_loc/kismet.common.location.fix") >= 2;
                    },
                    draw: function(opts) {
                        var loc =
                            kismet.censorLocation(kismet.ObjectByString(opts['data'], "kismet.device.base.signal/kismet.common.signal.peak_loc/kismet.common.location.geopoint[1]")) + ", " +
                            kismet.censorLocation(kismet.ObjectByString(opts['data'], "kismet.device.base.signal/kismet.common.signal.peak_loc/kismet.common.location.geopoint[0]"));

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
                    liveupdate: true,
                    render: function(opts) {
                        const d =
                            $('<div>', {
                                style: 'display: flex;'
                            })
                            .append(
                                $('<div>', {
                                    style: 'width: 50%; height: 200px; display: flex; justify-content: center; flex-direction: column; align-items: center; height: 250px',
                                })
                                .append('<div><b><center>Packet Types</center></b></div>')
                                .append(
                                    $('<div>')
                                    .append(
                                        $('<canvas>', {
                                            id: 'packetdonut',
                                            style: 'margin: 0 auto; width: 200px; height: 200px;'
                                        })
                                    )
                                )
                            )
                            .append(
                                $('<div>', {
                                    style: 'width: 50%; height: 200px; display: flex; justify-content: center; flex-direction: column; align-items: center; height: 250px',
                                })
                                .append('<div><b><center>Direction</center></b></div>')
                                .append(
                                    $('<div>')
                                    .append(
                                        $('<canvas>', {
                                            id: 'txrxdonut',
                                            style: 'margin: 0 auto; width: 200px; height: 200px;'
                                        })
                                    )
                                )
                            );


                        return d;
                    },
                    draw: function(opts) {
                        var data = [
                            opts['data']['kismet.device.base.packets.llc'],
                            opts['data']['kismet.device.base.packets.data'],
                        ];

                        var txrxdata = [
                            opts['data']['kismet.device.base.packets.tx_total'],
                            opts['data']['kismet.device.base.packets.rx_total'],
                        ];

                        if ('packetdonut' in window[storage]) {
                            window[storage].packetdonut.data.datasets[0].data = data;
                            window[storage].packetdonut.update('none');
                        } else {
                            var legend = ['LLC/Management', 'Data'];
                            var colors = [
                                'rgba(46, 99, 162, 1)',
                                'rgba(96, 149, 212, 1)',
                            ];

                            var barChartData = {
                                labels: legend,

                                datasets: [{
                                    label: 'Dataset 1',
                                    backgroundColor: colors,
                                    borderWidth: 0,
                                    data: data,
                                }],
                            };

                            window[storage].packetdonut =
                                new Chart($('#packetdonut', opts['container']), {
                                    type: 'doughnut',
                                    data: barChartData,
                                    options: {
                                        global: {
                                            maintainAspectRatio: false,
                                        },
                                        animation: false,
                                        legend: {
                                            display: true,
                                        },
                                        title: {
                                            display: true,
                                            text: 'Packet Types'
                                        },
                                        height: '200px',
                                    }
                                });

                            window[storage].packetdonut.render();
                        }

                        if ('txrxdonut' in window[storage]) {
                            window[storage].txrxdonut.data.datasets[0].data = txrxdata;
                            window[storage].txrxdonut.update('none');
                        } else {
                            var txrxlegend = ['Transmit', 'Receive'];
                            var txrxcolors = [
                                'rgba(46, 99, 162, 1)',
                                'rgba(96, 149, 212, 1)',
                            ];

                            var txrxbarChartData = {
                                labels: txrxlegend,

                                datasets: [{
                                    label: 'Dataset 1',
                                    backgroundColor: txrxcolors,
                                    borderWidth: 0,
                                    data: txrxdata,
                                }],
                            };

                            window[storage].txrxdonut =
                                new Chart($('#txrxdonut', opts['container']), {
                                    type: 'doughnut',
                                    data: txrxbarChartData,
                                    options: {
                                        global: {
                                            maintainAspectRatio: false,
                                        },
                                        animation: false,
                                        legend: {
                                            display: true,
                                        },
                                        title: {
                                            display: true,
                                            text: 'Tx/Rx'
                                        },
                                        height: '200px',
                                    }
                                });

                            window[storage].txrxdonut.render();
                        }
                    },
                },
                {
                    field: "kismet.device.base.packets.total",
                    liveupdate: true,
                    title: "Total Packets",
                    help: "Count of all packets of all types",
                },
                {
                    field: "kismet.device.base.packets.rx_total",
                    liveupdate: true,
                    title: "Rx Packets",
                    help: "Count of all packets of all types addressed to this device",
                },
                {
                    field: "kismet.device.base.packets.tx_total",
                    liveupdate: true,
                    title: "Tx Packets",
                    help: "Count of all packets of all types sent from this device",
                },
                {
                    field: "kismet.device.base.packets.llc",
                    liveupdate: true,
                    title: "LLC/Management",
                    help: "LLC (Link Layer Control) and Management packets are typically used for controlling and defining wireless networks.  Typically they do not carry data.",
                },
                {
                    field: "kismet.device.base.packets.error",
                    liveupdate: true,
                    title: "Error/Invalid",
                    help: "Error and invalid packets indicate a packet was received and was partially processable, but was damaged or incorrect in some way.  Most error packets are dropped completely as it is not possible to associate them with a specific device.",
                },
                {
                    field: "kismet.device.base.packets.data",
                    liveupdate: true,
                    title: "Data",
                    help: "Data frames carry messages and content for the device.",
                },
                {
                    field: "kismet.device.base.packets.crypt",
                    liveupdate: true,
                    title: "Encrypted",
                    help: "Some data frames can be identified by Kismet as carrying encryption, either by the contents or by packet flags, depending on the phy type",
                },
                {
                    field: "kismet.device.base.packets.filtered",
                    liveupdate: true,
                    title: "Filtered",
                    help: "Filtered packets are ignored by Kismet",
                },
                {
                    field: "kismet.device.base.datasize",
                    liveupdate: true,
                    title: "Data Transferred",
                    help: "Amount of data transferred",
                    draw: function(opts) {
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
                    return (kismet.ObjectByString(opts['data'], "kismet.device.base.location/kismet.common.location.avg_loc/kismet.common.location.fix") >= 2);
                },

                // Fields in subgroup
                fields: [
                {
                    field: "kismet.device.base.location/kismet.common.location.avg_loc/kismet.common.location.geopoint",
                    title: "Location",
                    draw: function(opts) {
                        try {
                            if (opts['value'][1] == 0 || opts['value'][0] == 0)
                                return "<i>Unknown</i>";

                            return kismet.censorLocation(opts['value'][1]) + ", " + kismet.censorLocation(opts['value'][0]);
                        } catch (error) {
                            return "<i>Unknown</i>";
                        }
                    }
                },
                {
                    field: "kismet.device.base.location/kismet.common.location.avg_loc/kismet.common.location.alt",
                    title: "Altitude",
                    filter: function(opts) {
                        return (kismet.ObjectByString(opts['data'], "kismet.device.base.location/kismet.common.location.avg_loc/kismet.common.location.fix") >= 3);
                    },
                    draw: function(opts) {
                        try {
                            return kismet_ui.renderHeightDistance(opts['value']);
                        } catch (error) {
                            return "<i>Unknown</i>";
                        }
                    },
                }
                ],
            }
            ]
        }, storage);
    }
});

kismet_ui.AddDeviceDetail("packets", "Packet Graphs", 10, {
    render: function(data) {
        // Make 3 divs for s, m, h RRD
        var ret =
            '<b>Packet Rates</b><br><br>' +
            'Packets per second (last minute) (Tx/Rx)<br><div></div><br>' +
            'Packets per minute (last hour) (Tx/Rx)<br><div></div><br>' +
            'Packets per hour (last day) (Tx/Rx)<br><div></div>';

        if ('kismet.device.base.datasize.rrd' in data)
            ret += '<br><b>Data</b><br><br>' +
            'Data per second (last minute)<br><div></div><br>' +
            'Data per minute (last hour)<br><div></div><br>' +
            'Data per hour (last day)<br><div></div>';

        return ret;
    },
    draw: function(data, target) {
        var m = $('div:eq(0)', target);
        var h = $('div:eq(1)', target);
        var d = $('div:eq(2)', target);

        var dm = $('div:eq(3)', target);
        var dh = $('div:eq(4)', target);
        var dd = $('div:eq(5)', target);

        var mdata_tx = [];
        var hdata_tx = [];
        var ddata_tx = [];
        var mdata_rx = [];
        var hdata_rx = [];
        var ddata_rx = [];

        var mdata_combo = [];
        var hdata_combo = [];
        var ddata_combo = [];

        if (('kismet.device.base.packets.rrd' in data)) {
            mdata_tx = kismet.RecalcRrdData2(data['kismet.device.base.tx_packets.rrd'], kismet.RRD_SECOND);
            hdata_tx = kismet.RecalcRrdData2(data['kismet.device.base.tx_packets.rrd'], kismet.RRD_MINUTE);
            ddata_tx = kismet.RecalcRrdData2(data['kismet.device.base.tx_packets.rrd'], kismet.RRD_HOUR);

            mdata_rx = kismet.RecalcRrdData2(data['kismet.device.base.rx_packets.rrd'], kismet.RRD_SECOND);
            hdata_rx = kismet.RecalcRrdData2(data['kismet.device.base.rx_packets.rrd'], kismet.RRD_MINUTE);
            ddata_rx = kismet.RecalcRrdData2(data['kismet.device.base.rx_packets.rrd'], kismet.RRD_HOUR);

            for (var i = 0; i < mdata_tx.length; i++) {
                mdata_combo.push([mdata_tx[i], mdata_rx[i] * -1]);
            }

            for (var i = 0; i < hdata_tx.length; i++) {
                hdata_combo.push([hdata_tx[i], hdata_rx[i] * -1]);
            }

            for (var i = 0; i < ddata_tx.length; i++) {
                ddata_combo.push([ddata_tx[i], ddata_rx[i] * -1]);
            }


            m.sparkline(mdata_combo,
                { type: "bar",
                    height: 18,
                    barWidth: 7,
                    barColor: kismet_theme.sparkline_main,
                    nullColor: kismet_theme.sparkline_main,
                    zeroColor: kismet_theme.sparkline_main,
                    stackedBarColor: [
                        'rgba(46, 99, 162, 1)',
                        'rgba(96, 149, 212, 1)',
                    ],
                });

            h.sparkline(hdata_combo,
                { type: "bar",
                    height: 18,
                    barWidth: 7,
                    barColor: kismet_theme.sparkline_main,
                    nullColor: kismet_theme.sparkline_main,
                    zeroColor: kismet_theme.sparkline_main,
                    stackedBarColor: [
                        'rgba(46, 99, 162, 1)',
                        'rgba(96, 149, 212, 1)',
                    ],
                });

            d.sparkline(ddata_combo,
                { type: "bar",
                    height: 18,
                    barWidth: 7,
                    barColor: kismet_theme.sparkline_main,
                    nullColor: kismet_theme.sparkline_main,
                    zeroColor: kismet_theme.sparkline_main,
                    stackedBarColor: [
                        'rgba(46, 99, 162, 1)',
                        'rgba(96, 149, 212, 1)',
                    ],
                });
        } else {
            m.html("<i>No packet data available</i>");
            h.html("<i>No packet data available</i>");
            d.html("<i>No packet data available</i>");
        }


        if ('kismet.device.base.datasize.rrd' in data) {
            var dmdata = kismet.RecalcRrdData2(data['kismet.device.base.datasize.rrd'], kismet.RRD_SECOND);
            var dhdata = kismet.RecalcRrdData2(data['kismet.device.base.datasize.rrd'], kismet.RRD_MINUTE);
            var dddata = kismet.RecalcRrdData2(data['kismet.device.base.datasize.rrd'], kismet.RRD_HOUR);

        dm.sparkline(dmdata,
            { type: "bar",
                height: 18,
                barWidth: 7,
                barColor: 'rgba(46, 99, 162, 1)',
                nullColor: kismet_theme.sparkline_main,
                zeroColor: kismet_theme.sparkline_main,
            });
        dh.sparkline(dhdata,
            { type: "bar",
                height: 18,
                barWidth: 7,
                barColor: 'rgba(46, 99, 162, 1)',
                nullColor: kismet_theme.sparkline_main,
                zeroColor: kismet_theme.sparkline_main,
            });
        dd.sparkline(dddata,
            { type: "bar",
                height: 18,
                barWidth: 7,
                barColor: 'rgba(46, 99, 162, 1)',
                nullColor: kismet_theme.sparkline_main,
                zeroColor: kismet_theme.sparkline_main,
            });
        }

    }
});

kismet_ui.AddDeviceDetail("seenby", "Seen By", 900, {
    filter: function(data) {
        return (Object.keys(data['kismet.device.base.seenby']).length > 0);
    },
    draw: function(data, target, options, storage) {
        target.devicedata(data, {
            id: "seenbyDeviceData",

            fields: [
            {
                field: "kismet.device.base.seenby",
                id: "seenby_group",
                groupIterate: true,
                iterateTitle: function(opts) {
                    var this_name = opts['value'][opts['index']]['kismet.common.seenby.source']['kismet.datasource.name'];
                    var this_uuid = opts['value'][opts['index']]['kismet.common.seenby.uuid'];
					return `${this_name} (${this_uuid})`;
                },
                fields: [
                {
                    field: "kismet.common.seenby.uuid",
                    title: "UUID",
                    empty: "<i>Unknown</i>"
                },
                {
                    field: "kismet.common.seenby.source/kismet.datasource.name",
                    title: "Name",
                    empty: "<i>Unknown</i>"
                },
                {
                    field: "kismet.common.seenby.source/kismet.datasource.hardware",
                    title: "Hardware",
                    empty: "<i>Unknown</i>"
                },
                {
                    field: "kismet.common.seenby.source/kismet.datasource.interface",
                    title: "Interface",
                    empty: "<i>Unknown</i>"
                },
                {
                    field: "kismet.common.seenby.first_time",
                    title: "First Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "kismet.common.seenby.last_time",
                    title: "Last Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },
				{
					field: "kismet.common.seenby.num_packets",
					title: "Packets",
					empty: "0",
				},
                ]
            }]
        });
    },
});

kismet_ui.AddDeviceDetail("devel", "Dev/Debug Options", 10000, {
    render: function(data) {
        return 'Device JSON: <a href="devices/by-key/' + data['kismet.device.base.key'] + '/device.prettyjson" target="_new">link</a><br>';
    }});

/* Sidebar:  Memory monitor
 *
 * The memory monitor looks at system_status and plots the amount of
 * ram vs number of tracked devices from the RRD
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'memory_sidebar',
    listTitle: '<i class="fa fa-tasks"></i> Memory Monitor',
    clickCallback: function() {
        exports.MemoryMonitor();
    },
});

/*
kismet_ui_sidebar.AddSidebarItem({
    id: 'pcap_sidebar',
    priority: 10000,
    listTitle: '<i class="fa fa-download"></i> Download Pcap-NG',
    clickCallback: function() {
        location.href = "datasource/pcap/all_sources.pcapng";
    },
});
*/

var memoryupdate_tid;
var memory_panel = null;
var memory_chart = null;

exports.MemoryMonitor = function() {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.5;
    var offty = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offty = 0;
    }

    memory_chart = null;


/*
    var content =
        $('<div>', {
            'style': 'width: 100%; height: 100%;'
        })
        .append(
            $('<div>', {
                "style": "position: absolute; top: 0px; right: 10px; float: right;"
            })
            .append(
                $('<span>', {
                    'id': 'k_mm_devs',
                    'class': 'padded',
                }).html('#devices')
            )
            .append(
                $('<span>', {
                    'id': 'k_mm_ram',
                    'class': 'padded',
                }).html('#ram')
            )
        )
        .append(
            $('<canvas>', {
                'id': 'k-mm-canvas',
                'style': 'k-mm-canvas'
            })
        );
*/

	var content =
		$('<div class="k-mem-contentdiv">')
		.append(
			$('<div id="mem-tabs" class="tabs-min">')
		);

    memory_panel = $.jsPanel({
        id: 'memory',
        headerTitle: '<i class="fa fa-tasks"></i> Memory use',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: content,
        onclosed: function() {
            clearTimeout(memoryupdate_tid);
        },
        resizable: {
            stop: function(event, ui) {
                let tabs = $('#mem-tabs', this.content);
                try {
                    tabs.tabs('refresh');
                } catch (e) { }
            }
        },
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty
    })
    .front();

	kismet_ui_tabpane.AddTab({
		id: 'memtotals',
		tabTitle: 'Overall Memory',
		createCallback: f_mem_memory,
		priority: -5000,
	}, 'mem-tabs');

	kismet_ui_tabpane.AddTab({
		id: 'stats',
		tabTitle: 'Memory Statistics',
		createCallback: f_mem_stats,
		priority: -4000,
	}, 'mem-tabs');

	kismet_ui_tabpane.MakeTabPane($('#mem-tabs', content), 'mem-tabs');

    memorydisplay_refresh();
}

var f_mem_memory = function(div) {
    var content =
        $('<div>', {
            'style': 'width: 100%; height: 100%;'
        })
        .append(
            $('<div>', {
                "style": "position: absolute; top: 0px; right: 10px; float: right;"
            })
            .append(
                $('<span>', {
                    'id': 'k_mm_devs',
                    'class': 'padded',
                }).html('#devices')
            )
            .append(
                $('<span>', {
                    'id': 'k_mm_ram',
                    'class': 'padded',
                }).html('#ram')
            )
        )
        .append(
            $('<canvas>', {
                'id': 'k-mm-canvas',
                'style': 'k-mm-canvas'
            })
        );

	div.append(content);

	memory_panel.mem_content = div;
}

var f_mem_stats = function(div) {
    var content =
        $('<div>', {
            'style': 'width: 100%; height: 100%; padding: 10px;'
		});

	content.append(
		$('<div>', { 'class': 'fakerow'})
		.append(
			$('<div>', { 'class': 'cellleft' }).html("Total fields")
		)
		.append(
			$('<div>', { 'class': 'cellleft', 'id': 'memfieldcount' })
		)
	);

	content.append(
		$('<div>', { 'class': 'fakerow'})
		.append(
			$('<div>', { 'class': 'cellleft' }).html("Total Components")
		)
		.append(
			$('<div>', { 'class': 'cellleft', 'id': 'memcomponentcount' })
		)
	);

	content.append($('<div style="padding: 5px;">'));

	content.append(
		$('<div>', { 'class': 'fakerow'})
		.append(
			$('<div>', { 'class': 'cellleft' }).html("Web connections")
		)
		.append(
			$('<div>', { 'class': 'cellleft', 'id': 'memwebcmp' })
		)
	);

	content.append($('<div style="padding: 5px;">'));

	content.append(
		$('<div>', { 'class': 'fakerow'})
		.append(
			$('<div>', { 'class': 'cellleft' }).html("String Cache #")
		)
		.append(
			$('<div>', { 'class': 'cellleft', 'id': 'memstrcache' })
		)
	);

	div.append(content);

	memory_panel.status_content = div;
}

function memorydisplay_refresh() {
    clearTimeout(memoryupdate_tid);

    if (memory_panel == null)
        return;

    if (memory_panel.is(':hidden'))
        return;

    $.get(local_uri_prefix + "system/status.json")
    .done(function(data) {

		$('#memfieldcount', memory_panel.status_content).html(kismet.sanitizeHTML(data['kismet.system.num_fields']));
		$('#memcomponentcount', memory_panel.status_content).html(kismet.sanitizeHTML(data['kismet.system.num_components']));

		$('#memwebcmp', memory_panel.status_content).html(kismet.sanitizeHTML(data['kismet.system.num_http_connections']));

		$('#memstrcache', memory_panel.status_content).html(kismet.sanitizeHTML(data['kismet.system.string_cache_size']));

        // Common rrd type and source field
        var rrdtype = kismet.RRD_MINUTE;
        var rrddata = 'kismet.common.rrd.hour_vec';

        // Common point titles
        var pointtitles = new Array();

        for (var x = 60; x > 0; x--) {
            if (x % 5 == 0) {
                pointtitles.push(x + 'm');
            } else {
                pointtitles.push(' ');
            }
        }

        var mem_linedata =
            kismet.RecalcRrdData2(data['kismet.system.memory.rrd'], rrdtype);

        for (var p in mem_linedata) {
            mem_linedata[p] = Math.round(mem_linedata[p] / 1024);
        }

        var dev_linedata =
            kismet.RecalcRrdData2(data['kismet.system.devices.rrd'], rrdtype);

        $('#k_mm_devs', memory_panel.mem_content).html(`${Math.trunc(dev_linedata[dev_linedata.length - 1])} devices`);
        $('#k_mm_ram', memory_panel.mem_content).html(`${mem_linedata[mem_linedata.length - 1]} MB`);

        let graph_step = kismet.getStorage('kismet.ui.graph.stepped', false);

        if (memory_chart == null) {
            var datasets = [
                {
                    label: 'Memory (MB)',
                    fill: 'false',
                    // yAxisID: 'mem-axis',
                    borderColor: kismet_theme.sparkline_multi_a,
                    backgroundColor: 'transparent',
                    data: mem_linedata,
                    stepped: graph_step,
                },
                {
                    label: 'Devices',
                    fill: 'false',
                    // yAxisID: 'dev-axis',
                    borderColor: kismet_theme.sparkline_multi_b,
                    backgroundColor: 'rgba(100, 100, 255, 0.33)',
                    data: dev_linedata,
                    stepped: graph_step,
                }
            ];

            var canvas = $('#k-mm-canvas', memory_panel.content);

            memory_chart = new Chart(canvas, {
                type: 'line',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            position: "left",
                            "id": "mem-axis",
                            ticks: {
                                beginAtZero: true,
                            }
                        },
                    },
                },
                data: {
                    labels: pointtitles,
                    datasets: datasets
                }
            });

        } else {
            memory_chart.data.datasets[0].data = mem_linedata;
            memory_chart.data.datasets[1].data = dev_linedata;
            // memory_chart.data.datasets = datasets;
            memory_chart.data.labels = pointtitles;
            memory_chart.update('none');
        }
    })
    .always(function() {
        memoryupdate_tid = setTimeout(memorydisplay_refresh, 5000);
    });
};


/* Sidebar:  Packet queue display
 *
 * Packet queue display graphs the amount of packets in the queue, the amount dropped,
 * the # of duplicates, and so on
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'packetqueue_sidebar',
    listTitle: '<i class="fa fa-area-chart"></i> Packet Rates',
    clickCallback: function() {
        exports.PacketQueueMonitor();
    },
});

var packetqueueupdate_tid;
var packetqueue_panel = null;

exports.PacketQueueMonitor = function() {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.5;
    var offty = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offty = 0;
    }

    var content =
        $('<div class="k-pqm-contentdiv">')
        .append(
            $('<div id="pqm-tabs" class="tabs-min">')
        );

    packetqueue_panel = $.jsPanel({
        id: 'packetqueue',
        headerTitle: '<i class="fa fa-area-chart"></i> Packet Rates',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        content: content,
        onclosed: function() {
            clearTimeout(packetqueue_panel.packetqueueupdate_tid);
        },
        resizable: {
            stop: function(event, ui) {
                let tabs = $('#pqm-tabs', this.content);
                try {
                    tabs.tabs('refresh');
                } catch (e) { console.log(e); }
            }
        },
    }).resize({
        width: w,
        height: h,
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty,
    })
    .front();

    packetqueue_panel.packetqueue_chart = null;
    packetqueue_panel.datasource_chart = null;

    var f_pqm_packetqueue = function(div) {
        packetqueue_panel.pq_content = div;

        packetqueue_panel.pq_content.append(
            $('<div>', {
                style: 'width: 100%; height: 95%',
            })
                .append(
                    $('<canvas>', {
                        id: 'pq-canvas',
                        style: 'margin: 10px;',
                    })
                )
        );
    };

    var f_pqm_ds = function(div) {
        packetqueue_panel.ds_content = div;

        packetqueue_panel.ds_content.append(
            $('<div>', {
                "style": "position: absolute; top: 0px; right: 10px; float: right;"
            })
                .append(
                    $('<select>', {
                        "id": "pq_ds_type",
                    })
                        .append(
                            $('<option>', {
                                "value": "pps",
                                "selected": "selected",
                            }).text("Packets")
                        )
                        .append(
                            $('<option>', {
                                "value": "bps",
                            }).text("Data (kB)")
                        )
                )
                .append(
                    $('<select>', {
                        "id": "pq_ds_range",
                    })
                        .append(
                            $('<option>', {
                                "value": "second",
                                "selected": "selected",
                            }).text("Past Minute")
                        )
                        .append(
                            $('<option>', {
                                "value": "hour",
                            }).text("Past Hour")
                        )
                        .append(
                            $('<option>', {
                                "value": "day",
                            }).text("Past Day")
                        )
                )
        ).append(
            $('<div>', {
                style: 'width: 100%; height: 100%;'
            })
                .append(
                    $('<canvas>', {
                        "id": "dsg-canvas",
                    })
                )
        );

    };

    kismet_ui_tabpane.AddTab({
        id: 'packetqueue',
        tabTitle: 'Processing Queue',
        createCallback: f_pqm_packetqueue,
        priority: -1001
    }, 'pqm-tabs');

    kismet_ui_tabpane.AddTab({
        id: 'datasources-graph',
        tabTitle: 'Per Datasource',
        createCallback: f_pqm_ds,
        priority: -1000
    }, 'pqm-tabs');

    kismet_ui_tabpane.MakeTabPane($('#pqm-tabs', content), 'pqm-tabs');

    packetqueuedisplay_refresh();
    datasourcepackets_refresh();
}

function packetqueuedisplay_refresh() {
    if (packetqueue_panel == null)
        return;

    clearTimeout(packetqueue_panel.packetqueueupdate_tid);

    if (packetqueue_panel.is(':hidden'))
        return;

    $.get(local_uri_prefix + "packetchain/packet_stats.json")
    .done(function(data) {
        // Common rrd type and source field
        var rrdtype = kismet.RRD_MINUTE;

        // Common point titles
        var pointtitles = new Array();

        for (var x = 60; x > 0; x--) {
            if (x % 5 == 0) {
                pointtitles.push(x + 'm');
            } else {
                pointtitles.push(' ');
            }
        }

        var peak_linedata =
            kismet.RecalcRrdData2(data['kismet.packetchain.peak_packets_rrd'], rrdtype);
        var rate_linedata =
            kismet.RecalcRrdData2(data['kismet.packetchain.packets_rrd'], rrdtype);
        var queue_linedata =
            kismet.RecalcRrdData2(data['kismet.packetchain.queued_packets_rrd'], rrdtype);
        var drop_linedata =
            kismet.RecalcRrdData2(data['kismet.packetchain.dropped_packets_rrd'], rrdtype);
        var dupe_linedata =
            kismet.RecalcRrdData2(data['kismet.packetchain.dupe_packets_rrd'], rrdtype);
        var processing_linedata =
            kismet.RecalcRrdData2(data['kismet.packetchain.processed_packets_rrd'], rrdtype);

        let step = kismet.getStorage('kismet.ui.graph.stepped', false);

        var datasets = [
            {
                label: 'Processed',
                fill: 'false',
                borderColor: 'orange',
                backgroundColor: 'transparent',
                data: processing_linedata,
                pointStyle: 'cross',
                stepped: step,
            },
            {
                label: 'Incoming packets (peak)',
                fill: 'false',
                borderColor: kismet_theme.graphBasicColor,
                backgroundColor: kismet_theme.graphBasicBackgroundColor,
                data: peak_linedata,
                stepped: step,
            },
            {
                label: 'Incoming packets (1 min avg)',
                fill: 'false',
                borderColor: 'purple',
                backgroundColor: 'transparent',
                data: rate_linedata,
                pointStyle: 'rect',
                stepped: step,
            },
            {
                label: 'Queue',
                fill: 'false',
                borderColor: 'blue',
                backgroundColor: 'transparent',
                data: queue_linedata,
                pointStyle: 'cross',
                stepped: step,
            },
            {
                label: 'Dropped / error packets',
                fill: 'false',
                borderColor: 'red',
                backgroundColor: 'transparent',
                data: drop_linedata,
                pointStyle: 'star',
                stepped: step,
            },
            {
                label: 'Duplicates',
                fill: 'false',
                borderColor: 'green',
                backgroundColor: 'transparent',
                data: dupe_linedata,
                pointStyle: 'triangle',
                stepped: step,
            },
        ];

        if (packetqueue_panel.packetqueue_chart == null) {
            var canvas = $('#pq-canvas', packetqueue_panel.pq_content);

            packetqueue_panel.packetqueue_chart = new Chart(canvas, {
                type: 'line',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            position: "left",
                            "id": "mem-axis",
                            ticks: {
                                beginAtZero: true,
                            }
                        },
                    },
                },
                data: {
                    labels: pointtitles,
                    datasets: datasets
                }
            });

        } else {
            packetqueue_panel.packetqueue_chart.data.datasets[0].data = processing_linedata;
            packetqueue_panel.packetqueue_chart.data.datasets[1].data = peak_linedata;
            packetqueue_panel.packetqueue_chart.data.datasets[2].data = rate_linedata;
            packetqueue_panel.packetqueue_chart.data.datasets[3].data = queue_linedata;
            packetqueue_panel.packetqueue_chart.data.datasets[4].data = drop_linedata;
            packetqueue_panel.packetqueue_chart.data.datasets[5].data = dupe_linedata;
            // packetqueue_panel.packetqueue_chart.data.datasets = datasets;
            packetqueue_panel.packetqueue_chart.data.labels = pointtitles;
            packetqueue_panel.packetqueue_chart.update('none');
        }
    })
    .always(function() {
        packetqueue_panel.packetqueueupdate_tid = setTimeout(packetqueuedisplay_refresh, 5000);
    });
};

function datasourcepackets_refresh() {
    if (packetqueue_panel == null)
        return;

    clearTimeout(packetqueue_panel.datasourceupdate_tid);

    if (packetqueue_panel.is(':hidden'))
        return;

    $.get(local_uri_prefix + "datasource/all_sources.json")
    .done(function(data) {
        var datasets = [];
        var num = 0;

        // Common point titles
        var pointtitles = new Array();

        var rval = $('#pq_ds_range', packetqueue_panel.ds_content).val();
        var range = kismet.RRD_SECOND;

        if (rval == "hour")
            range = kismet.RRD_MINUTE;
        if (rval == "day")
            range = kismet.RRD_HOUR;

        if (range == kismet.RRD_SECOND || range == kismet.RRD_MINUTE) {
            for (var x = 60; x > 0; x--) {
                if (x % 5 == 0) {
                    if (range == kismet.RRD_SECOND)
                        pointtitles.push(x + 's');
                    else
                        pointtitles.push(x + 'm');
                } else {
                    pointtitles.push(' ');
                }
            }
        } else {
            for (var x = 23; x > 0; x--) {
                pointtitles.push(x + 'h');
            }
        }

        let step = kismet.getStorage('kismet.ui.graph.stepped', false);

        for (var source of data) {
            var color = parseInt(255 * (num / data.length))

            var linedata;

            if ($('#pq_ds_type', packetqueue_panel.ds_content).val() == "bps")
                linedata =
                    kismet.RecalcRrdData2(source['kismet.datasource.packets_datasize_rrd'],
                    range,
                    {
                        transform: function(data, opt) {
                            var ret = [];

                            for (var d of data)
                                ret.push(d / 1024);

                            return ret;
                        }
                    });
            else
                linedata =
                    kismet.RecalcRrdData2(source['kismet.datasource.packets_rrd'], range);

            datasets.push({
                "label": source['kismet.datasource.name'],
                "borderColor": `hsl(${color}, 100%, 50%)`,
                "data": linedata,
                "fill": false,
                "stepped": step,
            });

            num = num + 1;

        }

        if (packetqueue_panel.datasource_chart == null) {
            packetqueue_panel.datasource_chart =
                new Chart($('#dsg-canvas', packetqueue_panel.ds_content), {
                "type": "line",
                "options": {
                    "responsive": true,
                    "maintainAspectRatio": false,
                    "scales": {
                        y: {
                            "position": "left",
                            "id": "pkts-axis",
                            "ticks": {
                                "beginAtZero": true,
                            }
                        },
                    },
                },
                "data": {
                    "labels": pointtitles,
                    "datasets": datasets,
                }
            });
        } else {
            packetqueue_panel.datasource_chart.data.datasets = datasets;
            packetqueue_panel.datasource_chart.data.labels = pointtitles;
            packetqueue_panel.datasource_chart.update('none');
        }
    })
    .always(function() {
        packetqueue_panel.datasourceupdate_tid = setTimeout(datasourcepackets_refresh, 1000);
    });
};

// Settings options

kismet_ui_settings.AddSettingsPane({
    id: 'graph_settings',
    listTitle: "Graph Options",
    create: (elem) => {
        elem.append('<form><fieldset id="fs_graph"><legend>Graph Options</legend><div id="graphconfig"></div></fieldset></form>');

        let config = $('#graphconfig', elem);

        config.append('<div><input type="checkbox" id="g_step"><label for="g_step">Use stepped graphs</label></div>');
        config.append('<p>Stepped graphs have a blockier representation of the same data.  By default, graphs are displayed in linear mode, which typically shows a more sloped representation of changes.</p>');

        let graph_step = kismet.getStorage('kismet.ui.graph.stepped', false);

        if (graph_step) {
            $('#g_step', elem).prop('checked', 'checked');
        }

        $('#g_step', elem).checkboxradio();

        $('form', elem).on('change', () => {
            kismet_ui_settings.SettingsModified();
        });

    },
    save: (elem) => {
        kismet.putStorage('kismet.ui.graph.stepped', $('#g_step', elem).is(':checked'));

    }
})

kismet_ui_settings.AddSettingsPane({
    id: 'gps_topbar',
    listTitle: "GPS Status",
    create: function(elem) {
        elem.append(
            $('<form>', {
                id: 'form'
            })
            .append(
                $('<fieldset>', {
                    id: 'set_gps'
                })
                .append(
                    $('<legend>', {})
                    .html("GPS Display")
                )
                .append(
                    $('<input>', {
                        type: 'radio',
                        id: 'gps_icon',
                        name: 'gps_status',
                        value: 'icon',
                    })
                )
                .append(
                    $('<label>', {
                        for: 'gps_icon'
                    })
                    .html("Icon only")
                )
                .append($('<div>', { class: 'spacer' }).html(" "))
                .append(
                    $('<input>', {
                        type: 'radio',
                        id: 'gps_text',
                        name: 'gps_status',
                        value: 'text',
                    })
                )
                .append(
                    $('<label>', {
                        for: 'gps_text'
                    })
                    .html("Text only")
                )
                .append($('<div>', { class: 'spacer' }).html(" "))
                .append(
                    $('<input>', {
                        type: 'radio',
                        id: 'gps_both',
                        name: 'gps_status',
                        value: 'both',
                    })
                )
                .append(
                    $('<label>', {
                        for: 'gps_both'
                    })
                    .html("Icon and Text")
                )
                .append($('<div class="k-s-list-div"><input type="checkbox" id="gps-stacked"><label for="gps-stacked">Stack GPS coordinates in toolbar</label></div>'))
            )
        );

        $('#form', elem).on('change', function() {
            kismet_ui_settings.SettingsModified();
        });

        if (kismet.getStorage('kismet.ui.gps.icon', 'True') === 'True') {
            if (kismet.getStorage('kismet.ui.gps.text', 'True') === 'True') {
                $('#gps_both', elem).attr('checked', 'checked');
            } else {
                $('#gps_icon', elem).attr('checked', 'checked');
            }
        } else {
            $('#gps_text', elem).attr('checked', 'checked');
        }

        if (kismet.getStorage('kismet.ui.gps.stack', true)) {
            $('#gps-stacked', elem).attr('checked', 'checked');
        }

        $('#gps-stacked').checkboxradio();

        $('#set_gps', elem).controlgroup();
    },
    save: function(elem) {
        var val = $("input[name='gps_status']:checked", elem).val();

        if (val === "both") {
            kismet.putStorage('kismet.ui.gps.text', 'True');
            kismet.putStorage('kismet.ui.gps.icon', 'True');
        } else if (val === "text") {
            kismet.putStorage('kismet.ui.gps.text', 'True');
            kismet.putStorage('kismet.ui.gps.icon', 'False');
        } else if (val === "icon") {
            kismet.putStorage('kismet.ui.gps.icon', 'True');
            kismet.putStorage('kismet.ui.gps.text', 'False');
        }

        kismet.putStorage('kismet.ui.gps.stack', $('#gps-stacked', elem).is(':checked'));
    }
})

kismet_ui_settings.AddSettingsPane({
    id: 'base_units_measurements',
    listTitle: 'Units &amp; Measurements',
    create: function(elem) {
        elem.append(
            $('<form>', {
                id: 'form'
            })
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
                        value: 'metric',
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
                        value: 'imperial',
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
                        id: 'temp_celsius',
                        name: 'temp',
                        value: 'celsius',
                    })
                )
                .append(
                    $('<label>', {
                        for: 'temp_celsius',
                    })
                    .html('Celsius')
                )
                .append(
                    $('<input>', {
                        type: 'radio',
                        id: 'temp_fahrenheit',
                        name: 'temp',
                        value: 'fahrenheit',
                    })
                )
                .append(
                    $('<label>', {
                        for: 'temp_fahrenheit',
                    })
                    .html('Fahrenheit')
                )
            )
        );

        $('#form', elem).on('change', function() {
            kismet_ui_settings.SettingsModified();
        });

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

        if (kismet.getStorage('kismet.base.unit.temp', 'celsius') === 'celsius') {
            $('#temp_celsius', elem).attr('checked', 'checked');
        } else {
            $('#temp_fahrenheit', elem).attr('checked', 'checked');
        }

        $('#set_distance', elem).controlgroup();
        $('#set_speed', elem).controlgroup();
        $('#set_temp', elem).controlgroup();

    },
    save: function(elem) {
        var dist = $("input[name='distance']:checked", elem).val();
        kismet.putStorage('kismet.base.unit.distance', dist);
        var spd = $("input[name='speed']:checked", elem).val();
        kismet.putStorage('kismet.base.unit.speed', spd);
        var tmp = $("input[name='temp']:checked", elem).val();
        kismet.putStorage('kismet.base.unit.temp', tmp);

        return true;
    },
});

kismet_ui_settings.AddSettingsPane({
    id: 'base_plugins',
    listTitle: 'Plugins',
    create: function(elem) {
        elem.append($('<i>').html('Loading plugin data...'));

        $.get(local_uri_prefix + "plugins/all_plugins.json")
        .done(function(data) {
            elem.empty();

            elem.append('<form><fieldset id="fs_plugins"><legend>Plugins</legend><div id="plugin-content"></div></fieldset></form>')

            if (data.length == 0) {
                $('#plugin-content', elem).html('No plugins loaded...');
            }

            var pdiv = $('#plugin-content', elem);

            for (var pi in data) {
                var pl = data[pi];

                var sharedlib = $('<p>');

                if (pl['kismet.plugin.shared_object'].length > 0) {
                    sharedlib.html("Native code from " + pl['kismet.plugin.shared_object']);
                } else {
                    sharedlib.html("No native code");
                }

                pdiv.append(
                    $('<div>', {
                        class: 'k-b-s-plugin-title',
                    })
                    .append(
                        $('<b>', {
                            class: 'k-b-s-plugin-title',
                        })
                        .html(pl['kismet.plugin.name'])
                    )
                    .append(
                        $('<span>', { })
                        .html(pl['kismet.plugin.version'])
                    )
                )
                .append(
                    $('<div>', {
                        class: 'k-b-s-plugin-content',
                    })
                    .append(
                        $('<p>', { })
                        .html(pl['kismet.plugin.description'])
                    )
                    .append(
                        $('<p>', { })
                        .html(pl['kismet.plugin.author'])
                    )
                    .append(sharedlib)
                );
            }
        });
    },
    save: function(elem) {

    },
});


kismet_ui_settings.AddSettingsPane({
    id: 'base_login_password',
    listTitle: 'Login &amp; Password',
    create: function(elem) {
        elem.append(
            $('<form>', {
                id: 'form'
            })
            .append(
                $('<fieldset>', {
                    id: 'fs_login'
                })
                .append(
                    $('<legend>', {})
                    .html('Server Login')
                )
                .append(
                    $('<p>')
                    .html('Kismet requires a username and password for functionality which changes the server, such as adding interfaces or changing configuration, or accessing some types of data.')
                )
                .append(
                    $('<p>')
                    .html('The Kismet password is stored in <code>~/.kismet/kismet_httpd.conf</code> in the home directory of the user running Kismet.  You will need this password to configure data sources, download pcap and other logs, or change server-side settings.<br>This server is running as <code>' + exports.system_user + '</code>, so the password can be found in <code>~' + exports.system_user + '/.kismet/kismet_httpd.conf</code>')
                )
                .append(
                    $('<p>')
                    .html('If you are a guest on this server you may continue without entering an admin password, but you will not be able to perform some actions or view some data.')
                )
                .append(
                    $('<br>')
                )
                .append(
                    $('<span style="display: inline-block; width: 8em;">')
                    .html('User name: ')
                )
                .append(
                    $('<input>', {
                        type: 'text',
                        name: 'user',
                        id: 'user'
                    })
                )
                .append(
                    $('<br>')
                )
                .append(
                    $('<span style="display: inline-block; width: 8em;">')
                    .html('Password: ')
                )
                .append(
                    $('<input>', {
                        type: 'password',
                        name: 'password',
                        id: 'password'
                    })
                )
                .append(
                    $('<span>', {
                        id: 'pwsuccessdiv',
                        style: 'padding-left: 5px',
                    })
                    .append(
                        $('<i>', {
                            id: 'pwsuccess',
                            class: 'fa fa-refresh fa-spin',
                        })
                    )
                    .append(
                        $('<span>', {
                            id: 'pwsuccesstext'
                        })
                    )
                    .hide()
                )
            )
        );

        $('#form', elem).on('change', function() {
            kismet_ui_settings.SettingsModified();
        });

        var checker_cb = function() {
            // Cancel any pending timer
            if (pw_check_tid > -1)
                clearTimeout(pw_check_tid);

            var checkerdiv = $('#pwsuccessdiv', elem);
            var checker = $('#pwsuccess', checkerdiv);
            var checkertext = $('#pwsuccesstext', checkerdiv);

            checker.removeClass('fa-exclamation-circle');
            checker.removeClass('fa-check-square');

            checker.addClass('fa-spin');
            checker.addClass('fa-refresh');
            checkertext.text("  Checking...");

            checkerdiv.show();

            // Set a timer for a second from now to call the actual check
            // in case the user is still typing
            pw_check_tid = setTimeout(function() {
                exports.LoginCheck(function(success) {
                    if (!success) {
                        checker.removeClass('fa-check-square');
                        checker.removeClass('fa-spin');
                        checker.removeClass('fa-refresh');
                        checker.addClass('fa-exclamation-circle');
                        checkertext.text("  Invalid login");
                    } else {
                        checker.removeClass('fa-exclamation-circle');
                        checker.removeClass('fa-spin');
                        checker.removeClass('fa-refresh');
                        checker.addClass('fa-check-square');
                        checkertext.text("");
                    }
                }, $('#user', elem).val(), $('#password', elem).val());
            }, 1000);
        };

        var pw_check_tid = -1;
        jQuery('#password', elem).on('input propertychange paste', function() {
            kismet_ui_settings.SettingsModified();
            checker_cb();
        });
        jQuery('#user', elem).on('input propertychange paste', function() {
            kismet_ui_settings.SettingsModified();
            checker_cb();
        });

        $('#user', elem).val(kismet.getStorage('kismet.base.login.username', 'kismet'));
        $('#password', elem).val(kismet.getStorage('kismet.base.login.password', 'kismet'));

        if ($('#user', elem).val() === 'kismet' &&
        $('#password', elem).val() === 'kismet') {
            $('#defaultwarning').show();
        }

        $('fs_login', elem).controlgroup();

        // Check the current pw
        checker_cb();
    },
    save: function(elem) {
        kismet.putStorage('kismet.base.login.username', $('#user', elem).val());
        kismet.putStorage('kismet.base.login.password', $('#password', elem).val());
    },
});

function show_role_help(role) {
    var rolehelp = `Unknown role ${role}; this could be assigned as a custom role for a Kismet plugin.`;

    if (role === "admin")
        rolehelp = "The admin role is assigned to the primary web interface, external API plugins which automatically request API access, and other privileged instances.  The admin role has access to all endpoints.";
    else if (role === "readonly")
        rolehelp = "The readonly role has access to any endpoint which does not modify data.  It can not issue commands to the Kismet server, configure sources, or alter devices.  The readonly role is well suited for external data gathering from a Kismet server.";
    else if (role === "datasource")
        rolehelp = "The datasource role allows remote capture over websockets.  This role only has access to the remote capture datasource endpoint.";
    else if (role === "scanreport")
        rolehelp = "The scanreport role allows device scan reports.  This role only has access to the scan report endpoint."
    else if (role === "ADSB")
        rolehelp = "The ADSB role allows access to the combined and device-specific ADSB feeds."
    else if (role === "__explain__") {
        rolehelp = "<p>Kismet uses a basic role system to restrict access to API endpoints.  The default roles are:";
        rolehelp += "<p>&quot;admin&quot; which has access to all API endpoints.";
        rolehelp += "<p>&quot;readonly&quot; which only has access to endpoints which do not alter devices or change the configuration of the server";
        rolehelp += "<p>&quot;datasource&quot; which is used for websockets based remote capture and may not access any other endpoints";
        rolehelp += "<p>&quot;scanreport&quot; which is used for reporting scanning-mode devices";
        rolehelp += "<p>&quot;ADSB&quot; which is used for sharing ADSB feeds";
        rolehelp += "<p>Plugins or other code may define other roles.";

        role = "Kismet API Roles";
    }

    var h = $(window).height() / 4;
    var w = $(window).width() / 2;

    if (w < 450)
        w = $(window).width() - 5;

    if (h < 200)
        h = $(window).height() - 5;

    $.jsPanel({
        id: "item-help",
        headerTitle: `Role: ${role}`,
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        contentSize: `${w} auto`,
        paneltype: 'modal',
        content: `<div style="padding: 10px;"><h3>${role}</h3><p>${rolehelp}`,
    })
    .reposition({
        my: 'center',
        at: 'center',
        of: 'window'
    })
    .front();
}

function delete_role(rolename, elem) {
    var deltd = $('.deltd', elem);

    var delbt =
        $('<button>', {
            'style': 'background-color: #DDAAAA',
        })
        .html(`Delete role &quot;${rolename}&quot;`)
        .button()
        .on('click', function() {
            var pd = {
                'name': rolename,
            };

            var postdata = "json=" + encodeURIComponent(JSON.stringify(pd));

            $.post(local_uri_prefix + "auth/apikey/revoke.cmd", postdata)
            .done(function(data) {
                var delt = elem.parent();

                elem.remove();

                if ($('tr', delt).length == 1) {
                    delt.append(
                        $('<tr>', {
                            'class': 'noapi'
                        })
                        .append(
                            $('<td>', {
                                'colspan': 4
                            })
                            .html("<i>No API keys defined...</i>")
                        )
                    );
                }
            })
        });

    deltd.empty();
    deltd.append(delbt);

}

function make_role_help_closure(role) {
    return function() { show_role_help(role); };
}

function make_role_delete_closure(rolename, elem) {
    return function() { delete_role(rolename, elem); };
}

kismet_ui_settings.AddSettingsPane({
    id: 'base_api_logins',
    listTitle: "API Keys",
    create: function(elem) {
        elem.append($("p").html("Fetching API data..."));

        $.get(local_uri_prefix + "auth/apikey/list.json")
        .done(function(data) {
            data = kismet.sanitizeObject(data);
            elem.empty();

            elem.append('<form><fieldset id="fs_apikeys"><legend>API Keys</legend><table class="apitable" id="apikeytable"></table></fieldset></form>');

            let tb = $('#apikeytable', elem);

            tb.append(
                $('<tr>')
                .append(
                    $('<th>', {
                        'class': 'apith',
                        'style': 'width: 16em;',
                    }).html("Name")
                )
                .append(
                    $('<th>', {
                        'class': 'apith',
                        'style': 'width: 8em;',
                    }).html("Role")
                )
                .append(
                    $('<th>', {
                        'class': 'apith',
                        'style': 'width: 30em;',
                    }).html("Key")
                )
                .append(
                    $('<th>')
                )
            );

            if (data.length == 0) {
                tb.append(
                    $('<tr>', {
                        'class': 'noapi'
                    })
                    .append(
                        $('<td>', {
                            'colspan': 4
                        })
                        .html("<i>No API keys defined...</i>")
                    )
                );
            }

            for (var user of data) {
                var name = user['kismet.httpd.auth.name'];
                var role = user['kismet.httpd.auth.role'];

                var key;

                if ('kismet.httpd.auth.token' in user) {
                    key = user['kismet.httpd.auth.token'];
                } else {
                    key = "<i>Viewing auth tokens is disabled in the Kismet configuration.</i>";
                }

                var tr =
                    $('<tr>', {
                        'class': 'apihover'
                    });

                tr
                    .append(
                        $('<td>').html(name)
                    )
                    .append(
                        $('<td>').html(role)
                        .append(
                            $('<i>', {
                                'class': 'pseudolink fa fa-question-circle',
                                'style': 'padding-left: 5px;',
                            })
                            .on('click', make_role_help_closure(role))
                        )
                    )
                    .append(
                        $('<td>')
                        .append(
                            $('<input>', {
                                'type': 'text',
                                'value': key,
                                'readonly': 'true',
                                'size': 34,
                                'id': name.replace(" ", "_"),
                            })
                        )
                        .append(
                            $('<i>', {
                                'class': 'copyuri pseudolink fa fa-copy',
                                'style': 'padding-left: 5px;',
                                'data-clipboard-target': `#${name.replace(" ", "_")}`,
                            })
                        )
                    )
                    .append(
                        $('<td>', {
                            'class': 'deltd'
                        })
                        .append(
                            $('<i>', {
                                'class': 'pseudolink fa fa-trash',
                            })
                            .on('click', make_role_delete_closure(name, tr))
                        )
                    )

                tb.append(
                    tr
                )
            }

            var adddiv =
                $('<div>', {
                    'id': 'addapidiv'
                })
                .append(
                    $('<fieldset>')
                    .append(
                        $('<button>', {
                            'id': 'addapikeybutton',
                            'class': 'padded',
                        }).html(`<i class="fa fa-plus"></i> Create API Key`)
                    )
                    .append(
                        $('<label>', {
                            'for': 'addapiname',
                            'class': 'padded',
                        }).html("Name")
                    )
                    .append(
                        $('<input>', {
                        'name': 'addapiname',
                        'id': 'addapiname',
                        'type': 'text',
                        'size': 16,
                        })
                    )
                    .append(
                        $('<label>', {
                            'for': 'addapirole',
                            'class': 'padded',
                        }).html("Role")
                    )
                    .append(
                        $('<select>', {
                            'name': 'addapirole',
                            'id': 'addapirole'
                        })
                        .append(
                            $('<option>', {
                                'value': 'readonly',
                                'selected': 'true',
                            }).html("readonly")
                        )
                        .append(
                            $('<option>', {
                                'value': 'datasource',
                            }).html("datasource")
                        )
                        .append(
                            $('<option>', {
                                'value': 'scanreport',
                            }).html("scanreport")
                        )
                        .append(
                            $('<option>', {
                                'value': 'admin',
                            }).html("admin")
                        )
                        .append(
                            $('<option>', {
                                'value': 'ADSB',
                            }).html("ADSB")
                        )
                        .append(
                            $('<option>', {
                                'value': 'custom',
                            }).html("<i>custom</i>")
                        )
                    )
                    .append(
                        $('<input>', {
                            'name': 'addapiroleother',
                            'id': 'addapiroleother',
                            'type': 'text',
                            'size': 16,
                        }).hide()
                    )
                    .append(
                        $('<i>', {
                            'class': 'pseudolink fa fa-question-circle',
                            'style': 'padding-left: 5px;',
                        })
                        .on('click', make_role_help_closure("__explain__"))
                    )
                    .append(
                        $('<div>', {
                            'id': 'addapierror',
                            'style': 'color: red;'
                        }).hide()
                    )
                );

            $('#addapikeybutton', adddiv)
                .button()
                .on('click', function() {
                    var name = $('#addapiname').val();
                    var role_select = $('#addapirole option:selected').text();
                    var role_input = $('#addapiroleother').val();

                    if (name.length == 0) {
                        $('#addapierror').show().html("Missing name.");
                        return;
                    }

                    if (role_select === "custom" && role_input.length == 0) {
                        $('#addapierror').show().html("Missing custom role.");
                        return;
                    }

                    $('#addapierror').hide();

                    var role = role_select;

                    if (role_select === "custom")
                        role = role_input;

                    var pd = {
                        'name': name,
                        'role': role,
                        'duration': 0,
                    };

                    var postdata = "json=" + encodeURIComponent(JSON.stringify(pd));

                    $.post(local_uri_prefix + "auth/apikey/generate.cmd", postdata)
                    .fail(function(response) {
                        var rt = kismet.sanitizeObject(response.responseText);
                        $('#addapierror').show().html(`Failed to add API key: ${rt}`);
                    })
                    .done(function(data) {
                        var key = kismet.sanitizeObject(data);

                        var tr =
                            $('<tr>', {
                                'class': 'apihover'
                            });

                        tr
                            .append(
                                $('<td>').html(name)
                            )
                            .append(
                                $('<td>').html(role)
                                .append(
                                    $('<i>', {
                                        'class': 'pseudolink fa fa-question-circle',
                                        'style': 'padding-left: 5px;',
                                    })
                                    .on('click', make_role_help_closure(role))
                                )
                            )
                            .append(
                                $('<td>')
                                .append(
                                    $('<input>', {
                                        'type': 'text',
                                        'value': key,
                                        'readonly': 'true',
                                        'size': 34,
                                        'id': name.replace(" ", "_"),
                                    })
                                )
                                .append(
                                    $('<i>', {
                                        'class': 'copyuri pseudolink fa fa-copy',
                                        'style': 'padding-left: 5px;',
                                        'data-clipboard-target': `#${name.replace(" ", "_")}`,
                                    })
                                )
                            )
                            .append(
                                $('<td>', {
                                    'class': 'deltd'
                                })
                                .append(
                                    $('<i>', {
                                        'class': 'pseudolink fa fa-trash',
                                    })
                                    .on('click', make_role_delete_closure(name, tr))
                                )
                            );

                        $('#apikeytable').append(tr);

                        $('#addapiname').val('');
                        $("#addapirole").prop("selectedIndex", 0);
                        $("#addapirole").show();
                        $("#addapiroleother").val('').hide();
                    });
                });

            $('#addapirole', adddiv).on('change', function(e) {
                var val = $("#addapirole option:selected" ).text();

                if (val === "custom") {
                    $(this).hide();
                    $('#addapiroleother').show();
                }

            });

            elem.append(adddiv);

            new ClipboardJS('.copyuri');
        });
    },
    save: function(elem) {
        return true;
    },
});



/* Add the messages and channels tabs */
kismet_ui_tabpane.AddTab({
    id: 'messagebus',
    tabTitle: 'Messages',
    createCallback: function(div) {
        div.messagebus();
    },
    priority: -1001,
}, 'south');

kismet_ui_tabpane.AddTab({
    id: 'channels',
    tabTitle: 'Channels',
    createCallback: function(div) {
        div.channels();
    },
    priority: -1000,
}, 'south');

kismet_ui_tabpane.AddTab({
    id: 'devices',
    tabTitle: 'Devices',
    expandable: false,
    createCallback: function(div) {
        kismet_ui.PrepDeviceTable(div);
        // kismet_ui.CreateDeviceTable(div);
    },
    activateCallback: function() {
        kismet_ui.ShowDeviceTab();
    },
    deactivateCallback: function() {
        kismet_ui.HideDeviceTab();
    },
    priority: -1000000,
}, 'center');

exports.DeviceSignalDetails = function(key) {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.5;

    var devsignal_chart = null;

    var devsignal_tid = -1;

    var content =
        $('<div>', {
            class: 'k-dsd-container'
        })
        .append(
            $('<div>', {
                class: 'k-dsd-info'
            })
            .append(
                $('<div>', {
                    class: 'k-dsd-title'
                })
                .html("Signal")
            )
            .append(
                $('<table>', {
                    class: 'k-dsd-table'
                })
                .append(
                    $('<tr>', {
                    })
                    .append(
                        $('<td>', {
                            width: '50%'
                        })
                        .html("Last Signal:")
                    )
                    .append(
                        $('<td>', {
                            width: '50%',
                        })
                        .append(
                            $('<span>', {
                                class: 'k-dsd-lastsignal',
                            })
                        )
                        .append(
                            $('<i>', {
                                class: 'fa k-dsd-arrow k-dsd-arrow-down',
                            })
                            .hide()
                        )
                    )
                )
                .append(
                    $('<tr>', {
                    })
                    .append(
                        $('<td>', {
                            width: '50%'
                        })
                        .html("Min Signal:")
                    )
                    .append(
                        $('<td>', {
                            width: '50%',
                            class: 'k-dsd-minsignal',
                        })
                        .html("n/a")
                    )
                )
                .append(
                    $('<tr>', {
                    })
                    .append(
                        $('<td>', {
                            width: '50%'
                        })
                        .html("Max Signal:")
                    )
                    .append(
                        $('<td>', {
                            width: '50%',
                            class: 'k-dsd-maxsignal',
                        })
                        .html("n/a")
                    )
                )
            )
        )
        .append(
            $('<div>', {
                class: 'k-dsd-graph'
            })
            .append(
                $('<canvas>', {
                    id: 'k-dsd-canvas',
                    class: 'k-dsd-canvas'
                })
            )
        );

    var devsignal_panel = $.jsPanel({
        id: 'devsignal' + key,
        headerTitle: '<i class="fa fa-signal"></i> Signal',
        headerControls: {
            iconfont: 'jsglyph',
        },
        content: content,
        onclosed: function() {
            clearTimeout(devsignal_tid);
        }
    }).resize({
        width: w,
        height: h
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: 20
    })
    .front();

    var emptyminute = new Array();
    for (var x = 0; x < 60; x++) {
        emptyminute.push(0);
    }

    devsignal_tid = devsignal_refresh(key, devsignal_panel,
        devsignal_chart, devsignal_tid, 0, emptyminute);
}

function devsignal_refresh(key, devsignal_panel, devsignal_chart,
    devsignal_tid, lastsignal, fakerrd) {
    clearTimeout(devsignal_tid);

    if (devsignal_panel == null)
        return;

    if (devsignal_panel.is(':hidden'))
        return;

    var signal = lastsignal;

    $.get(local_uri_prefix + "devices/by-key/" + key + "/device.json")
    .done(function(data) {
        var title = '<i class="fa fa-signal"></i> Signal ' +
            kismet.censorMAC(data['kismet.device.base.macaddr']) + ' ' +
            kismet.censorString(data['kismet.device.base.name']);
        devsignal_panel.headerTitle(title);

        var sigicon = $('.k-dsd-arrow', devsignal_panel.content);

        sigicon.removeClass('k-dsd-arrow-up');
        sigicon.removeClass('k-dsd-arrow-down');
        sigicon.removeClass('fa-arrow-up');
        sigicon.removeClass('fa-arrow-down');

        signal = data['kismet.device.base.signal']['kismet.common.signal.last_signal'];

        if (signal < lastsignal) {
            sigicon.addClass('k-dsd-arrow-down');
            sigicon.addClass('fa-arrow-down');
            sigicon.show();
        } else {
            sigicon.addClass('k-dsd-arrow-up');
            sigicon.addClass('fa-arrow-up');
            sigicon.show();
        }

        var typestr = "";
        if (data['kismet.device.base.signal']['kismet.common.signal.type'] == "dbm")
            typestr = " dBm";
        else if (data['kismet.device.base.signal']['kismet.common.signal.type'] == "rssi")
            typestr = " RSSI";

        $('.k-dsd-lastsignal', devsignal_panel.content)
            .text(signal + typestr);

        $('.k-dsd-minsignal', devsignal_panel.content)
        .text(data['kismet.device.base.signal']['kismet.common.signal.min_signal'] + typestr);

        $('.k-dsd-maxsignal', devsignal_panel.content)
        .text(data['kismet.device.base.signal']['kismet.common.signal.max_signal'] + typestr);

        // Common point titles
        var pointtitles = new Array();

        for (var x = 60; x > 0; x--) {
            if (x % 5 == 0) {
                pointtitles.push(x + 's');
            } else {
                pointtitles.push(' ');
            }
        }


        /*
        var rrdata = kismet.RecalcRrdData(
            data['kismet.device.base.signal']['kismet.common.signal.signal_rrd']['kismet.common.rrd.last_time'],
            data['kismet.device.base.signal']['kismet.common.signal.signal_rrd']['kismet.common.rrd.last_time'],
            kismet.RRD_SECOND,
            data['kismet.device.base.signal']['kismet.common.signal.signal_rrd']['kismet.common.rrd.minute_vec'], {});

        // We assume the 'best' a signal can usefully be is -20dbm,
        // that means we're right on top of it.
        // We can assume that -100dbm is a sane floor value for
        // the weakest signal.
        // If a signal is 0 it means we haven't seen it at all so
        // just ignore that data point
        // We turn signals into a 'useful' graph by clamping to
        // -100 and -20 and then scaling it as a positive number.
        var moddata = new Array();

        for (var x = 0; x < rrdata.length; x++) {
            var d = rrdata[x];

            if (d == 0) {
                moddata.push(0);
                continue;
            }

            if (d < -100)
                d = -100;

            if (d > -20)
                d = -20;

            // Normalize to 0-80
            d = (d * -1) - 20;

            // Reverse (weaker is worse), get as percentage
            var rs = (80 - d) / 80;

            moddata.push(100*rs);
        }
        */

        var msignal = signal;

        if (msignal == 0) {
            fakerrd.push(0);
        } else if (msignal < -100) {
            msignal = -100;
        } else if (msignal > -20) {
            msignal = -20;
        }

        msignal = (msignal * -1) - 20;
        var rs = (80 - msignal) / 80;

        fakerrd.push(100 * rs);

        fakerrd.splice(0, 1);

        var moddata = fakerrd;

        var datasets = [
            {
                label: 'Signal (%)',
                fill: 'false',
                borderColor: 'blue',
                backgroundColor: 'rgba(100, 100, 255, 0.83)',
                data: moddata,
            },
        ];

        if (devsignal_chart == null) {
            var canvas = $('#k-dsd-canvas', devsignal_panel.content);

            devsignal_chart = new Chart(canvas, {
                type: 'bar',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false,
                    scales: {
                        y: {
                            ticks: {
                                beginAtZero: true,
                                max: 100,
                            }
                        },
                    },
                },
                data: {
                    labels: pointtitles,
                    datasets: datasets
                }
            });
        } else {
            devsignal_chart.data.datasets[0].data = moddata;
            devsignal_chart.update('none');
        }


    })
    .always(function() {
        devsignal_tid = setTimeout(function() {
                devsignal_refresh(key, devsignal_panel,
                    devsignal_chart, devsignal_tid, signal, fakerrd);
        }, 1000);
    });
};

exports.login_error = false;
exports.login_pending = false;

exports.ProvisionedPasswordCheck = function(cb) {
    $.ajax({
        url: local_uri_prefix + "session/check_setup_ok",

        error: function(jqXHR, textStatus, errorThrown) {
            cb(jqXHR.status);
        },

        success: function(data, textStatus, jqHXR) {
            cb(200);
        },
    });
}

exports.LoginCheck = function(cb, user, pw) {
    user = user || kismet.getStorage('kismet.base.login.username', 'kismet');
    pw = pw || kismet.getStorage('kismet.base.login.password', '');

    $.ajax({
        url: local_uri_prefix + "session/check_login",

        beforeSend: function (xhr) {
            xhr.setRequestHeader ("Authorization", "Basic " + btoa(user + ":" + pw));
        },

        xhrFields: {
            withCredentials: false
        },

        error: function(jqXHR, textStatus, errorThrown) {
            cb(false);
        },

        success: function(data, textStatus, jqXHR) {
            cb(true);
        }

    });
}

exports.FirstLoginCheck = function(first_login_done_cb) {
    var loginpanel = null;
    var username_deferred = $.Deferred();

    $.get(local_uri_prefix + "system/user_status.json")
        .done(function(data) {
            username_deferred.resolve(data['kismet.system.user']);
        })
        .fail(function() {
            username_deferred.resolve("[unknown]");
        });

    var username = "[incomplete]";
    $.when(username_deferred).done(function(v) {

    username = v;

    var required_login_content =
    $('<div>', {
        style: 'padding: 10px;'
    })
    .append(
        $('<p>')
        .html('Kismet requires a login to access data.')
    )
    .append(
        $('<p>')
        .html('Your login is stored in in <code>.kismet/kismet_httpd.conf</code> in the <i>home directory of the user who launched Kismet</i>;  This server is running as ' + username + ', and the login will be saved in <code>~' + username + '/.kismet/kismet_httpd.conf</code>.')
    )
    .append(
        $('<div>', {
            id: 'form'
        })
        .append(
            $('<fieldset>', {
                id: 'fs_login'
            })
            .append(
                $('<span style="display: inline-block; width: 8em;">')
                .html('User name: ')
            )
            .append(
                $('<input>', {
                    type: 'text',
                    name: 'user',
                    id: 'req_user'
                })
            )
            .append(
                $('<br>')
            )
            .append(
                $('<span style="display: inline-block; width: 8em;">')
                .html('Password: ')
            )
            .append(
                $('<input>', {
                    type: 'password',
                    name: 'password',
                    id: 'req_password'
                })
            )
            .append(
                $('<div>', {
                    style: 'padding-top: 10px;'
                })
                .append(
                    $('<button>', {
                        class: 'k-wl-button-close',
                        id: 'login_button',
                    })
                    .text('Log in')
                    .button()
                )
                .append(
                    $('<span>', {
                        id: 'pwsuccessdiv',
                        style: 'padding-left: 5px',
                    })
                    .append(
                        $('<i>', {
                            id: 'pwsuccess',
                            class: 'fa fa-refresh fa-spin',
                        })
                    )
                    .append(
                        $('<span>', {
                            id: 'pwsuccesstext'
                        })
                    )
                    .hide()
                )
            )
        )
    );

    var login_checker_cb = function(content) {
        var savebutton = $('#login_button', content);

        var checkerdiv = $('#pwsuccessdiv', content);
        var checker = $('#pwsuccess', checkerdiv);
        var checkertext = $('#pwsuccesstext', checkerdiv);

        checker.removeClass('fa-exclamation-circle');
        checker.removeClass('fa-check-square');

        checker.addClass('fa-spin');
        checker.addClass('fa-refresh');
        checkertext.text("  Checking...");

        checkerdiv.show();

        exports.LoginCheck(function(success) {
            if (!success) {
                checker.removeClass('fa-check-square');
                checker.removeClass('fa-spin');
                checker.removeClass('fa-refresh');
                checker.addClass('fa-exclamation-circle');
                checkertext.text("  Invalid login");
            } else {
                /* Save the login info */
                kismet.putStorage('kismet.base.login.username', $('#req_user', content).val());
                kismet.putStorage('kismet.base.login.password', $('#req_password', content).val());

                loginpanel.close();

                /* Call the primary callback */
                first_login_done_cb();
            }
        }, $('#req_user', content).val(), $('#req_password', content).val());
    };

    $('#login_button', required_login_content)
        .button()
        .on('click', function() {
            login_checker_cb(required_login_content);
        });

    $('fs_login', required_login_content).controlgroup();

    var set_password_content =
    $('<div>', {
        style: 'padding: 10px;'
    })
    .append(
        $('<p>')
        .html('To finish setting up Kismet, you need to configure a login.')
    )
    .append(
        $('<p>')
        .html('This login will be stored in <code>.kismet/kismet_httpd.conf</code> in the <i>home directory of the user who launched Kismet</i>;  This server is running as ' + username + ', and the login will be saved in <code>~' + username + '/.kismet/kismet_httpd.conf</code>.')
    )
    .append(
        $('<div>', {
            id: 'form'
        })
        .append(
            $('<fieldset>', {
                id: 'fs_login'
            })
            .append(
                $('<legend>', {})
                .html('Set Login')
            )
            .append(
                $('<span style="display: inline-block; width: 8em;">')
                .html('User name: ')
            )
            .append(
                $('<input>', {
                    type: 'text',
                    name: 'user',
                    id: 'user'
                })
            )
            .append(
                $('<br>')
            )
            .append(
                $('<span style="display: inline-block; width: 8em;">')
                .html('Password: ')
            )
            .append(
                $('<input>', {
                    type: 'password',
                    name: 'password',
                    id: 'password'
                })
            )
            .append(
                $('<br>')
            )
            .append(
                $('<span style="display: inline-block; width: 8em;">')
                .html('Confirm: ')
            )
            .append(
                $('<input>', {
                    type: 'password',
                    name: 'password2',
                    id: 'password2'
                })
            )
            .append(
                $('<span>', {
                    id: 'pwsuccessdiv',
                    style: 'padding-left: 5px',
                })
                .append(
                    $('<i>', {
                        id: 'pwsuccess',
                        class: 'fa fa-refresh fa-spin',
                    })
                )
                .append(
                    $('<span>', {
                        id: 'pwsuccesstext'
                    })
                )
                .hide()
            )
        )
    )
    .append(
        $('<div>', {
            style: 'padding-top: 10px;'
        })
        .append(
            $('<button>', {
                class: 'k-wl-button-close',
                id: 'save_password',
            })
            .text('Save')
            .button()
        )
    );

    var checker_cb = function(content) {
        var savebutton = $('#save_password', content);
        var checkerdiv = $('#pwsuccessdiv', content);
        var checker = $('#pwsuccess', checkerdiv);
        var checkertext = $('#pwsuccesstext', checkerdiv);

        savebutton.button("disable");

        checker.removeClass('fa-exclamation-circle');
        checker.removeClass('fa-check-square');

        checker.addClass('fa-spin');
        checker.addClass('fa-refresh');
        checkertext.text("");

        checkerdiv.show();

        if ($('#user', content).val().length == 0) {
            checker.removeClass('fa-check-square');
            checker.removeClass('fa-spin');
            checker.removeClass('fa-refresh');
            checker.addClass('fa-exclamation-circle');
            checkertext.text("  Username required");
            savebutton.button("disable");
            return;
        }

        if ($('#password', content).val().length == 0) {
            checker.removeClass('fa-check-square');
            checker.removeClass('fa-spin');
            checker.removeClass('fa-refresh');
            checker.addClass('fa-exclamation-circle');
            checkertext.text("  Password required");
            savebutton.button("disable");
            return;
        }

        if ($('#password', content).val() != $('#password2', content).val()) {
            checker.removeClass('fa-check-square');
            checker.removeClass('fa-spin');
            checker.removeClass('fa-refresh');
            checker.addClass('fa-exclamation-circle');
            checkertext.text("  Passwords don't match");
            savebutton.button("disable");
            return;
        }

        checker.removeClass('fa-exclamation-circle');
        checker.removeClass('fa-spin');
        checker.removeClass('fa-refresh');
        checker.addClass('fa-check-square');
        checkertext.text("");
        savebutton.button("enable");

    };

    jQuery('#user', set_password_content).on('input propertychange paste', function() {
        checker_cb();
    });
    jQuery('#password', set_password_content).on('input propertychange paste', function() {
        checker_cb();
    });
    jQuery('#password2', set_password_content).on('input propertychange paste', function() {
        checker_cb();
    });

    $('#save_password', set_password_content)
        .button()
        .on('click', function() {
            kismet.putStorage('kismet.base.login.username', $('#user', set_password_content).val());
            kismet.putStorage('kismet.base.login.password', $('#password', set_password_content).val());

            var postdata = {
                "username": $('#user', set_password_content).val(),
                "password": $('#password', set_password_content).val()
            };

            $.ajax({
                type: "POST",
                url: local_uri_prefix + "session/set_password",
                data: postdata,
                error: function(jqXHR, textStatus, errorThrown) {
                    alert("Could not set login, check your kismet server logs.")
                },
            });

            loginpanel.close();

            /* Call the primary callback to load the UI */
            first_login_done_cb();

            /* Check for the first-time running */
            exports.FirstTimeCheck();
        });

    $('fs_login', set_password_content).controlgroup();

    checker_cb(set_password_content);

    var w = ($(window).width() / 2) - 5;
    if (w < 450) {
        w = $(window).width() - 5;
    }

    var content = set_password_content;

    exports.ProvisionedPasswordCheck(function(code) {
        if (code == 200 || code == 406) {
            /* Initial setup has been complete, now check the login itself */
            exports.LoginCheck(function(success) {
                if (!success) {
                    loginpanel = $.jsPanel({
                        id: "login-alert",
                        headerTitle: '<i class="fa fa-exclamation-triangle"></i>Login Required',
                        headerControls: {
                            controls: 'closeonly',
                            iconfont: 'jsglyph',
                        },
                        contentSize: w + " auto",
                        paneltype: 'modal',
                        content: required_login_content,
                    });

                    return true;
                } else {
                    /* Otherwise we're all good, continue to loading the main UI via the callback */
                    first_login_done_cb();
                }
            });
        } else if (code == 500) {
            loginpanel = $.jsPanel({
                id: "login-alert",
                headerTitle: '<i class="fa fa-exclamation-triangle"></i> Set Login',
                headerControls: {
                    controls: 'closeonly',
                    iconfont: 'jsglyph',
                },
                contentSize: w + " auto",
                paneltype: 'modal',
                content: set_password_content,
            });

            return true;
        } else {
            loginpanel = $.jsPanel({
                id: "login-alert",
                headerTitle: '<i class="fa fa-exclamation-triangle"></i> Error connecting',
                headerControls: {
                    controls: 'closeonly',
                    iconfont: 'jsglyph',
                },
                contentSize: w + " auto",
                paneltype: 'modal',
                content: "Error connecting to Kismet and checking provisioning; try reloading the page!",
            });


        }
   });

   // When clause
   });
}

exports.FirstTimeCheck = function() {
    var welcomepanel = null;
    if (kismet.getStorage('kismet.base.seen_welcome', false) == false) {
        var content =
            $('<div>', {
                style: 'padding: 10px;'
            })
            .append(
                $('<p>', { }
                )
                .html("Welcome!")
            )
            .append(
                $('<p>')
                .html('This is the first time you\'ve used this Kismet server in this browser.')
            )
            .append(
                $('<p>')
                .html('Kismet stores local settings in the HTML5 storage of your browser.')
            )
            .append(
                $('<p>')
                .html('You should configure your preferences and login settings in the settings panel!')
            )
            .append(
                $('<div>', {})
                .append(
                    $('<button>', {
                        class: 'k-w-button-settings'
                    })
                    .text('Settings')
                    .button()
                    .on('click', function() {
                        welcomepanel.close();
                        kismet_ui_settings.ShowSettings();
                    })
                )
                .append(
                    $('<button>', {
                        class: 'k-w-button-close',
                        style: 'position: absolute; right: 5px;',
                    })
                    .text('Continue')
                    .button()
                    .on('click', function() {
                        welcomepanel.close();
                    })
                )

            );

        welcomepanel = $.jsPanel({
            id: "welcome-alert",
            headerTitle: '<i class="fa fa-power-off"></i> Welcome',
            headerControls: {
                controls: 'closeonly',
                iconfont: 'jsglyph',
            },
            contentSize: "auto auto",
            paneltype: 'modal',
            content: content,
        });

        kismet.putStorage('kismet.base.seen_welcome', true);

        return true;
    }

    return false;
}

// Keep trying to fetch the servername until we're able to
var servername_tid = -1;
exports.FetchServerName = function(cb) {
    $.get(local_uri_prefix + "system/status.json")
        .done(function (d) {
            d = kismet.sanitizeObject(d);
            cb(d['kismet.system.server_name']);
        })
        .fail(function () {
            servername_tid = setTimeout(function () {
                exports.FetchServerName(cb);
            }, 1000);
        });
}

/* Highlight active devices */
kismet_ui.AddDeviceRowHighlight({
    name: "Active",
    description: "Device has been active in the past 10 seconds",
    priority: 500,
    defaultcolor: "#cee1ff",
    defaultenable: false,
    fields: [
        'kismet.device.base.last_time'
    ],
    selector: function(data) {
        var ts = data['kismet.device.base.last_time'];

        return (kismet.timestamp_sec - ts < 10);
    }
});

/* Bodycam hardware of various types */
kismet_ui.AddDeviceRowHighlight({
    name: "Bodycams",
    description: "Body camera devices",
    priority: 500,
    defaultcolor: "#0089FF",
    defaultenable: true,
    fields: [
        'kismet.device.base.macaddr',
        'kismet.device.base.commonname',
    ],
    selector: function(data) {
        try {
            if (data['kismet.device.base.macaddr'].match("^00:25:DF") != null)
                return true;
            if (data['kismet.device.base.macaddr'].match("^12:20:13") != null)
                return true;
            if (data['kismet.device.base.common_name'].match("^Axon-X") != null)
                return true;
        } catch (e) {
            return false;
        }

        return false;
    }
});


/* Sidebar: Thermal display
 *
 * Thermal and fan display
 */
kismet_ui_sidebar.AddSidebarItem({
    id: 'thermal_sidebar',
    listTitle: '<i class="fa fa-thermometer"></i> Thermals',
    clickCallback: function() {
        exports.ThermalMonitor();
    },
});

var thermal_panel = null;

exports.ThermalMonitor = function() {
    var w = $(window).width() * 0.75;
    var h = $(window).height() * 0.5;
    var offty = 20;

    if ($(window).width() < 450 || $(window).height() < 450) {
        w = $(window).width() - 5;
        h = $(window).height() - 5;
        offty = 0;
    }

    thermal_panel = $.jsPanel({
        id: 'thermal',
        headerTitle: '<i class="fa fa-thermometer"></i> Thermals',
        headerControls: {
            controls: 'closeonly',
            iconfont: 'jsglyph',
        },
        onclosed: function() {
            clearTimeout(thermal_panel.thermalupdate_tid);
        },
        resizable: {
            stop: function(event, ui) {
                let tabs = $('#pqm-tabs', this.content);
                try {
                    $('div#accordion', this.content).accordion('refresh');
                } catch (e) { }
            }
        },
    }).resize({
        width: w,
        height: h,
        callback: function(panel) {
            $('div#accordion', this.content).accordion('refresh');
        }
    }).reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
        offsetY: offty
    })
    .front();

    thermal_refresh();
}

function thermal_refresh() {
    if (thermal_panel == null)
        return;

    clearTimeout(thermal_panel.thermalupdate_tid);

    var accordion = $('div#accordion', thermal_panel.content);
    var theader = $('h3#header_thermal', thermal_panel.content);
    var tcontent = $('div#thermal', thermal_panel.content);
    var fheader = $('h3#header_fan', thermal_panel.content);
    var fcontent = $('div#fan', thermal_panel.content);

    if (accordion.length == 0) {
        accordion =
            $('<div>', {
                id: 'accordion',
            });
        thermal_panel.content.append(accordion);
        thermal_panel.accordion = accordion;

        if (theader.length == 0) {
            theader = $('<h3>', {
                id: 'header_thermal',
            }).html("Temperatures");

            accordion.append(theader);
        }

        if (tcontent.length == 0) {
            tcontent = $('<div>', {
                id: 'thermal',
            });

            accordion.append(tcontent);
        }

        if (fheader.length == 0) {
            fheader = $('<h3>', {
                id: 'header_fan',
            }).html("Fans");

            accordion.append(fheader);
        }

        if (fcontent.length == 0) {
            fcontent = $('<div>', {
                id: 'fan',
            });

            accordion.append(fcontent);
        }


        accordion.accordion({ heightStyle: 'fill' });
    }

    $.get(local_uri_prefix + "system/status.json")
    .done((data) => {
        if ('kismet.system.sensors.temp' in data && Object.keys(data['kismet.system.sensors.temp']).length > 0) {
            for (var t in data['kismet.system.sensors.temp']) {
                var tdiv = $(`#thermal_${kismet.sanitizeId(t)}`, tcontent);

                if (tdiv.length == 0) {
                    tdiv = $('<div>', {
                        id: `thermal_${kismet.sanitizeId(t)}`,
                        style: 'display: flex; flex-direction: row;',
                    }).append(
                        $('<div>', {
                            style: 'flex: 2',
                        }).html(kismet.sanitizeHTML(t)),
                        $('<div>', {
                            id: `thermal_${kismet.sanitizeId(t)}_c`,
                            style: 'flex: 1',
                        }).html(kismet_ui.renderTemperature(data['kismet.system.sensors.temp'][t], 2))
                    );

                    tcontent.append(tdiv);
                } else {
                    var tdif = $(`thermal_${kismet.sanitizeId(t)}_c`, tdiv);
                    tdif.html(kismet_ui.renderTemperature(data['kismet.system.sensors.temp'][t], 2));
                }

            }
        }

        if ('kismet.system.sensors.fan' in data && Object.keys(data['kismet.system.sensors.fan']).length > 0) {
            for (var t in data['kismet.system.sensors.fan']) {
                var tdiv = $(`#fan_${kismet.sanitizeId(t)}`, fcontent);

                if (tdiv.length == 0) {
                    tdiv = $('<div>', {
                        id: `fan_${kismet.sanitizeId(t)}`,
                        style: 'display: flex; flex-direction: row;',
                    }).append(
                        $('<div>', {
                            style: 'flex: 2',
                        }).html(kismet.sanitizeHTML(t)),
                        $('<div>', {
                            id: `fan_${kismet.sanitizeId(t)}_c`,
                            style: 'flex: 1',
                        }).html(`${Math.floor(data['kismet.system.sensors.fan'][t])}RPM`)
                    );

                    fcontent.append(tdiv);
                } else {
                    var tdif = $(`fan_${kismet.sanitizeId(t)}_c`, tdiv);
                    tdif.html(`${Math.floor(data['kismet.system.sensors.fan'][t])}RPM`)
                }

            }

        }
        thermal_panel.accordion.accordion('refresh');
    });

    thermal_panel.thermalupdate_tid = setTimeout(thermal_refresh, 5000);
}

// We're done loading
exports.load_complete = 1;

return exports;

});
