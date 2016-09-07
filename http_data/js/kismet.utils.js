/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet = m(); }
)(function () {
"use strict";

var exports = {};

/* Convert a kismet trackerelement package to standard json.
 * This means pulling out the type variable and converting the
 * special types.
 */

/* Kismet tracker types used in exported tuples */
var KIS_TRACKERTYPE_STRING    = 0;
var KIS_TRACKERTYPE_INT8      = 1;
var KIS_TRACKERTYPE_UINT8     = 2;
var KIS_TRACKERTYPE_INT16     = 3;
var KIS_TRACKERTYPE_UINT16    = 4;
var KIS_TRACKERTYPE_INT32     = 5;
var KIS_TRACKERTYPE_UINT32    = 6;
var KIS_TRACKERTYPE_INT64     = 7;
var KIS_TRACKERTYPE_UINT64    = 8;
var KIS_TRACKERTYPE_FLOAT     = 9;
var KIS_TRACKERTYPE_DOUBLE    = 10;
var KIS_TRACKERTYPE_MAC       = 11;
var KIS_TRACKERTYPE_UUID      = 12;
var KIS_TRACKERTYPE_VECTOR    = 13;
var KIS_TRACKERTYPE_MAP       = 14;
var KIS_TRACKERTYPE_INTMAP    = 15;
var KIS_TRACKERTYPE_MACMAP    = 16;
var KIS_TRACKERTYPE_STRINGMAP = 17;
var KIS_TRACKERTYPE_DOUBLEMAP = 18;

// Convert msgpack mac addresses
exports.ConvertMacaddr = ConvertMacaddr;
function ConvertMacaddr(trackermac) {
    var ret = {};
    ret.macaddr = trackermac[0];
    ret.mask = trackermac[1];
    return ret;
}

// Convert msgpack dictionaries
exports.ConvertTrackerPack = ConvertTrackerPack;
function ConvertTrackerPack(unpacked) {
    if (unpacked[0] == KIS_TRACKERTYPE_VECTOR) {
        var retarr = [];

        for (var x = 0; x < unpacked[1].length; x++) {
            retarr.push(ConvertTrackerPack(unpacked[1][x]));
        }

        return retarr;
    } else if (unpacked[0] == KIS_TRACKERTYPE_MAP ||
            unpacked[0] == KIS_TRACKERTYPE_INTMAP ||
            unpacked[0] == KIS_TRACKERTYPE_MACMAP ||
            unpacked[0] == KIS_TRACKERTYPE_STRINGMAP ||
            unpacked[0] == KIS_TRACKERTYPE_DOUBLEMAP) {
        

        var retdict = {};

        for (var k in unpacked[1]) {
            retdict[k] = ConvertTrackerPack(unpacked[1][k]);
        }

        return retdict;
    } else if (unpacked[0] == KIS_TRACKERTYPE_MAC) {
        return ConvertMacaddr(unpacked[1]);
    } else {
        return unpacked[1];
    }
}

exports.PostGpsLocation = function(gps, callback, failback) {
    $.ajax({
        url: "/gps/update_location.msgpack",
        type: "POST",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        data: msgpack.encode(gps),
        success: function(arbuf) {
            callback();
        },
        error: function(jqx, textStatus, errorThrown) {
            failback("Fetch failed: " + textStatus + " " + errorThrown);
        }
    });
};

// Deprecated by json, here for reference
exports.GetDeviceSummary = function(callback, failback) {
    $.ajax({
        url: "/devices/all_devices.msgpack",
        type: "GET",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        success: function(arbuf) {
            var msg;
            var conv;
            try {
                msg = msgpack.decode(arbuf);
                conv = ConvertTrackerPack(msg);
            } catch (e) {
                failback(e);
            }

            callback(conv);
        },
        error: function(jqx, textStatus, errorThrown) {
            failback("Fetch failed: " + textStatus + " " + errorThrown);
        }
    });
};

// Deprecated by json, here for reference
exports.GetDevice = function(key, callback, failback) {
    $.ajax({
        url: "/devices/" + key + ".msgpack",
        type: "GET",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        success: function(arbuf) {
            var msg;
            var conv;
            try {
                msg = msgpack.decode(arbuf);
                conv = ConvertTrackerPack(msg);
            } catch (e) {
                failback(e);
            }

            callback(conv);
        },
        error: function(jqx, textStatus, errorThrown) {
            failback("Fetch failed: " + textStatus + " " + errorThrown);
        }
    });
};

exports.GetSystemStatus = function(callback, failback) {
    $.ajax({
        url: "/system/status.msgpack",
        type: "GET",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        success: function(arbuf) {
            var msg;
            var conv;
            try {
                msg = msgpack.decode(arbuf);
                conv = ConvertTrackerPack(msg);
            } catch (e) {
                failback(e);
            }

            callback(conv);
        },
        error: function(jqx, textStatus, errorThrown) {
            failback("Fetch failed: " + textStatus + " " + errorThrown);
        }
    });
};

exports.GetChannelData = function(callback, failback) {
    $.ajax({
        url: "/channels/channels.msgpack",
        type: "GET",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        success: function(arbuf) {
            var msg;
            var conv;
            try {
                msg = msgpack.decode(arbuf);
                conv = ConvertTrackerPack(msg);
            } catch (e) {
                failback(e);
            }

            callback(conv);
        },
        error: function(jqx, textStatus, errorThrown) {
            failback("Fetch failed: " + textStatus + " " + errorThrown);
        }
    });
};

// From http://stackoverflow.com/a/6491621
exports.ObjectByString = function(o, s) {
    s = s.replace(/\[(\w+)\]/g, '.$1');
    s = s.replace(/^\./, '');
    var a = s.split('.');
    for (var i = 0, n = a.length; i < n; ++i) {
        var k = a[i];
        if (k in o) {
            o = o[k];
        } else {
            return;
        }
    }

    return o;
}

exports.HumanReadableSize = function(sz) {
    if (sz < 1024) {
        return sz + " bytes";
    } else if (sz < 1024 * 1024) {
        return (sz / 1024).toFixed(2) + " kB";
    } else if (sz < 1024 * 1024 * 1024) {
        return (sz / 1024 / 1024).toFixed(2) + " mB";
    } else if (sz < 1024 * 1024 * 1024 * 1024) {
        return (sz / 1024 / 1024 / 1024).toFixed(2) + " gB";
    }

    return sz;
}

// Load any plugin scripts defined in /system/dynamic.json
exports.GetDynamicIncludes = function() {
    $.get("/system/dynamic.json")
        .done(function(data) {
            for (var plugin in data["dynamic"]) {
                $.getScript(plugin);
            }
        });
}

// List of datatable columns we have available
exports.DeviceColumns = new Array();

/* Add a jquery datatable column that the user can pick from, with various 
 * options:
 *
 * sTitle: datatable column title
 * name: datatable 'name' field (optional)
 * mData: datatable field spec
 * cbmodule: string name of callback module (ie "kismet_dot11") (optional)
 * renderfunc: string name of datatable render function, taking DT arguments
 *  (data, type, row, meta), found in cbmodule (optional)
 * drawfunc: string name of a draw function, taking a row entity as the argument,
 *  found in cbmodule.  This will be called during the drawCallback of the device
 *  table (optional)
 */
exports.AddDeviceColumn = function(id, options) {
    var coldef = {
        sTitle: options.sTitle,
        mData: options.mData
    };

    if ('name' in options) {
        coldev.name = options.name;
    }

    // Set the render function to proxy through the module+function
    if ('cbmodule' in options && 'renderfunc' in options) {
        coldev.render = function(data, type, row, meta) {
            return window[options.cbmodule][options.renderfunc](data, type, row, meta);
        }
    }

    // Set an arbitrary draw hook we call ourselves during the draw loop later
    if ('cbmodule' in options && 'drawfunc' in options) {
        coldev.kismetdraw = function(row) {
            return window[options.cbmodule][options.renderfunc](row);
        }
    }
}



return exports;

});
