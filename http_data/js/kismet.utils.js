/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet = m(); }
)(function () {
"use strict";

var exports = {};

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

exports.timestamp_sec = 0;
exports.timestamp_usec = 0;

function update_ts() {
    $.get(local_uri_prefix + "system/timestamp.json")
    .done(function(data) {
        data = exports.sanitizeObject(data);
        exports.timestamp_sec = data['kismet.system.timestamp.sec'];
        exports.timestamp_usec = data['ksimet.system.timestamp.usec'];
    })
    .always(function() {
        setTimeout(update_ts, 1000);
    })
}

update_ts();

// Make a universal HTML5 storage handler
exports.storage = Storages.localStorage;

// Simple handler for getting stored values with defaults
exports.getStorage = function(key, def = undefined) {
    if (exports.storage.isSet(key))
        return exports.storage.get(key);

    return def;
}

exports.putStorage = function(key, data) {
    exports.storage.set(key, data);
}

// From http://stackoverflow.com/a/6491621
exports.ObjectByString = function(o, s) {
    if (typeof(o) === 'undefined')
        return;

    s = s.replace(/\[('?"?-?[\w:]+'?"?)\]/g, '\/$1');
    s = s.replace(/^\//, '');
    s = s.replace(/\/$/, '');
    s = s.replace(/\/+/, '\/');
    var a = s.split('/');
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
    if (typeof(sz) === 'undefined')
        return '0 B';

    if (typeof(sz) !== 'number') 
        sz = parseInt(sz);

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

var dynamics_loaded = false;
var load_completes = [];
exports.AddLoadComplete = function(f) {
    if (dynamics_loaded)
        f();
    else
        load_completes.push(f);
}

// Load any plugin scripts defined in /system/dynamic.json
exports.GetDynamicIncludes = function() {
    // Make a deferred promise that the scripts are loaded
    var scriptchain = $.Deferred();

    $.get(local_uri_prefix + "dynamic.json", function(data) {
        // Build a list of deferred stuff
        var scriptloads = new Array();

        // Trigger them all
        for (var p in data['dynamicjs']) {
            // console.log("calling getscript " + data.dynamicjs[p]['js']);

            $.getScript(local_uri_prefix + data.dynamicjs[p]['js']);
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

                console.log("defer for module", module);

                if (typeof window[module] !== 'undefined' &&
                        window[module].load_complete == 1) {
                    // window.clearInterval(interval);
                    // Remove this entry from the list
                    data['dynamicjs'].splice(p, 1);
                    // console.log("done loading " + module + " on attempt " + attempts);
                    defer.resolve();
                } else if (attempts >= 20) {
                    // window.clearInterval(interval);
                    // // Remove this entry from the list
                    data['dynamicjs'].splice(p, 1);
                    // console.log("loading went wrong");
                    alert("Failed to load JS module '" + module + "' if you have recently installed any plugins they may be causing errors loading.  Kismet will attempt to load the rest of the UI.");
                    defer.resolve();
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

exports.LoadDynamicIncludes = function(f) {
    exports.GetDynamicIncludes().done(function() {
        dynamics_loaded = true;
        f();
        for (var cb of load_completes) 
            cb();
    });
}

// Modify a RRD minute record by fast-forwarding it to 'now', and optionally
// applying a transform function which could do something like average it

// Conversion factors / type definitions for RRD data arrays
exports.RRD_SECOND = 1; 
exports.RRD_MINUTE = 60;
exports.RRD_HOUR = 3600;

// exports.RRD_DAY = 86400

exports.RecalcRrdData = function(start, now, type, data, opt = {}) {
    if (data == undefined) {
        if (type == exports.RRD_SECOND || type == exports.RRD_MINUTE) {
            data = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0 
            ];
        } else if (type == exports.RRD_HOUR) {
            data = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0
            ];
        }
    }

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
        
        var start_bin = (Math.floor(start / type) % rrd_len) + 1;
        var now_bin = (Math.floor(now / type) % rrd_len) + 1;
        var sec_offt = Math.max(0, now - start);

        /*
        console.log("we think we start in bin" + start_bin);
        console.log("we think now is bin" + now_bin);
        */

        // Walk the entire array, starting with 'now', and copy zeroes
        // when we fall into the blank spot between 'start' and 'now' when we
        // know we received no data
        for (var ri = 0; ri < rrd_len; ri++) {
            var slot = (now_bin + ri) % rrd_len;

            if (slot >= start_bin && slot < now_bin)
                adj_data.push(0);
            else
                adj_data.push(data[slot]);
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

exports.RecalcRrdData2 = function(rrddata, type, opt = {}) {
    var record;

    if (type == exports.RRD_SECOND)
        record = "kismet.common.rrd.minute_vec";
    else if (type == exports.RRD_MINUTE)
        record = "kismet.common.rrd.hour_vec";
    else if (type == exports.RRD_HOUR)
        record = "kismet.common.rrd.day_vec";
    else
        record = "kismet.common.rrd.minute_vec";

    try {
        var data = rrddata[record];
        var rrd_len = data.length;
    } catch (e) {
        if (type == exports.RRD_SECOND || type == exports.RRD_MINUTE) {
            data = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0 
            ];
        } else if (type == exports.RRD_HOUR) {
            data = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0
            ];
        }
    }

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
    var now = rrddata['kismet.common.rrd.serial_time'];
    var start = rrddata['kismet.common.rrd.last_time'];

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
        
        var start_bin = (Math.floor(start / type) % rrd_len) + 1;
        var now_bin = (Math.floor(now / type) % rrd_len) + 1;
        var sec_offt = Math.max(0, now - start);

        /*
        console.log("we think we start in bin" + start_bin);
        console.log("we think now is bin" + now_bin);
        */

        // Walk the entire array, starting with 'now', and copy zeroes
        // when we fall into the blank spot between 'start' and 'now' when we
        // know we received no data
        for (var ri = 0; ri < rrd_len; ri++) {
            var slot = (now_bin + ri) % rrd_len;

            if (slot >= start_bin && slot < now_bin)
                adj_data.push(0);
            else
                adj_data.push(data[slot]);
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

exports.sanitizeId = function(s) {
    return String(s).replace(/[:.&<>"'`=\/\(\)\[\] ]/g, function (s) {
            return '_';
    });
}

exports.sanitizeHTML = function(s) {
    var remap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '`': '&#x60;',
        '=': '&#x3D;',
        '/': '&#x2F;'
    };

    return String(s).replace(/[&<>"'`=\/]/g, function (s) {
            return remap[s];
    });
}

/* Censor a mac-like string, if the global censor_macs option is turned on; must be called by each
 * display component */
exports.censorMAC = function(t) {
    try {
        if (window['censor_macs'])
            return t.replace(/([a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}):[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}/g, "$1:XX:XX:XX");
        else
            return t;
    } catch (e) {
        return t;
    }
}

/* Recurse over a complete object (such as from json), finding all strings,
 * and escaping them to be 'safe' */
exports.sanitizeObject = function(o) {
    if (o === null) {
        return o;
    }

    if (typeof(o) === 'string') {
        return exports.sanitizeHTML(o);
    }

    Object.keys(o).forEach(function(key) {
            o[key] = exports.sanitizeObject(o[key]);
    });

    return o;
}

String.prototype.escapeSpecialChars = function() {
    var s = this.replace(/\n/g, "\\n")
        .replace(/\r/g, "\\r")
        .replace(/\t/g, "\\t");

    return s;
};

String.prototype.convertNewlines = function() {
    var s = this.replace(/\\n/g, "\n");
    s = s.replace(/\\r/g, "");

    return s;
}

return exports;

});
