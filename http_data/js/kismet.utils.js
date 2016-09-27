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
    if (typeof(o) === 'undefined')
        return;

    s = s.replace(/\[('?"?-?[\w:]+'?"?)\]/g, '.$1');
    s = s.replace(/^\./, '');
    s = s.replace(/\.$/, '');
    s = s.replace(/\.+/, '.');
    var a = s.split('.');
    for (var i = 0, n = a.length; i < n; ++i) {
        var k = a[i];

        if (typeof(o) !== 'object')
            return;

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
        return sz + " B";
    } else if (sz < 1024 * 1024) {
        return (sz / 1024).toFixed(2) + " KB";
    } else if (sz < 1024 * 1024 * 1024) {
        return (sz / 1024 / 1024).toFixed(2) + " MB";
    } else if (sz < 1024 * 1024 * 1024 * 1024) {
        return (sz / 1024 / 1024 / 1024).toFixed(2) + " GB";
    }

    return sz;
}

exports.HumanReadableFrequency = function(f) {
    // Kismet reports in *kHz* so all these values are scaled down by an order
    // of magnitude
    if (f < 1000)
        return f + " KHz";
    else if (f < 1000 * 1000)
        return (f / 1000).toFixed(3) + " MHz";
    else 
        return (f / 1000 / 1000).toFixed(3) + " GHz";
}

// Load any plugin scripts defined in /system/dynamic.json
exports.GetDynamicIncludes = function() {
    // Make a deferred promise that the scripts are loaded
    var scriptchain = $.Deferred();

    $.get("/dynamic.json", function(data) {
        // Build a list of deferred stuff
        var scriptloads = new Array();

        // Trigger them all
        for (var p in data['dynamicjs']) {
            // console.log("calling getscript " + data.dynamicjs[p]['js']);

            $.getScript(data.dynamicjs[p]['js']);
            // console.log("looping to see if it loaded");

            // Make a deferred entry per script we load
            var defer = $.Deferred();

            // Hack it into our data so we can find it later
            data.dynamicjs[p]['defer'] = defer;

            // Add it to our vector so we can apply them all
            // console.log("adding promise to list");
            scriptloads.push(defer);
        }

        var attempts = 0;

        // Now that we know all our deferred loads, make one event loop that looks
        // for them and unlocks all their deferred promises
        var interval = setInterval(function() {
            // console.log(interval);

            for (var p in data['dynamicjs']) {
                var module = data.dynamicjs[p]['module'];
                var defer = data.dynamicjs[p]['defer'];

                if (typeof window[module] !== 'undefined' &&
                        window[module].load_complete == 1) {
                    // window.clearInterval(interval);
                    // Remove this entry from the list
                    data['dynamicjs'].splice(p, 1);
                    // console.log("done loading " + module + " on attempt " + attempts);
                    defer.resolve();
                } else if (attempts >= 100) {
                    // window.clearInterval(interval);
                    // // Remove this entry from the list
                    data['dynamicjs'].splice(p, 1);
                    // console.log("loading went wrong");
                    defer.reject('Something went wrong');
                }
            }

            // If we're done, bail on the loop
            if (data['dynamicjs'].length == 0) {
                window.clearInterval(interval);
            }

            attempts++;
        }, 100);

        // console.log("Waiting for script loads");
        $.when.apply(null, scriptloads).done(function() {
            // console.log("Script load array is done, setting scriptchain to resolved");
            scriptchain.resolve();
        });
    });

    return scriptchain;
}

// Modify a RRD minute record by fast-forwarding it to 'now', and optionally
// applying a transform function which could do something like average it

// Conversion factors / type definitions for RRD data arrays
exports.RRD_SECOND = 1; 
exports.RRD_MINUTE = 60;
exports.RRD_HOUR = 3600;

// exports.RRD_DAY = 86400

exports.RecalcRrdData = function(start, now, type, data, opt) {
    var rrd_len = data.length;

    // Each type value is the number of seconds in each bin of the array
    //
    // A bin for a given time is (time / type) % len
    //
    // A completely expired RRD is (now - start) > (type * len) and should
    // be filled with only zeroes
    //
    // To zero the array between "then" and "now", we simply calculate
    // the bin for "then", the bin for "now", and increment-with-modulo 
    // until we reach "now".

    // Adjusted data we return
    var adj_data = new Array();

    // Check if we're past the recording bounds of the rrd for this type, if we
    // are, we don't have to do any shifting or any manipulation, we just fill
    // the array with zeroes.
    if ((now - start) > (type * rrd_len)) {
        for (var ri = 0; ri < rrd_len; ri++) {
            adj_data.push(0);
        }
    } else {
        // Otherwise, we're valid inside the range of the array.  We know we got
        // no data between the time of the RRD and now, because if we had, the 
        // time would be more current.  Figure out how many bins lie between
        // 'then' and 'now', rescale the array to start at 'now', and fill
        // in the time we got no data with zeroes
        
        var start_bin = Math.round(start / type) % rrd_len;
        var sec_offt = Math.max(0, now - start);
        var now_bin = Math.round(now / type) % rrd_len;

        // Walk the entire array, starting with 'now', and copy zeroes
        // when we fall into the blank spot between 'start' and 'now' when we
        // know we received no data
        for (var ri = 0; ri < rrd_len; ri++) {
            if (ri >= start_bin && ri < now_bin)
                adj_data.push(0);
            else
                adj_data.push(data[(now_bin + ri) % rrd_len]);
        }
    }

    // If we have a transform function in the options, call it, otherwise
    // return the shifted RRD entry
    if ('transform' in opt && typeof(opt.transform) === 'function') {
        var cbopt = {};

        if ('transformopt' in opt)
            cbopt = opt.cbopt;

        return opt.transform(adj_data, cbopt);
    }

    return adj_data;
}

return exports;

});
