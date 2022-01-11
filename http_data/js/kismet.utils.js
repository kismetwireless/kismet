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

    var data = [];
    var rrd_len;
    var now;
    var start;

    try {
        data = rrddata[record];

        if (typeof(data) === 'number')
            throw(0);

        now = rrddata['kismet.common.rrd.serial_time'];
        start = rrddata['kismet.common.rrd.last_time'];
    } catch (e) {
        now = 0;
        start = 0;

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

    rrd_len = data.length;

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

/* Censor a location by rounding */
exports.censorLocation = function(t) {
    try {
        if (window['censor_location']) 
            return `${Math.round(t)}.XXXXX`;
        else
            return t;
    } catch (e) {
        return t;
    }
}

// utf8 to unicode converter (used below in deoctalize()).
// "fatal: true" means that the converter will throw an 
// exception if the input is not valid utf8.
exports.decoder = new TextDecoder('utf8', {fatal: true});

/* De-octalize an escaped string, and decode it from utf8.
 * If the input string contains anything unexpected (control
 * characters, invalid values after the backslash, character
 * sequences that are not valid utf8), return the input string.
 * */
exports.deoctalize = function(str) {
    var ret = new Array();

    for (var i = 0; i < str.length; i++) {
        // If the current character is not a backslash, 
        // do not modify it.
        if (str[i] != '\\') {
            ret.push(str.charCodeAt(i))
        // If the current character (a backslash) is followed by a 
        // second backslash, remove the second backslash;
        // no other modification needed.
        } else if (i+1 < str.length && str[i+1] == '\\') {
            ret.push(str.charCodeAt(i));
            i++;
        // If the backslash is followed by a 3-digit octal number
        // in the range 000 to 377, replace the backslash and
        // numerals by the corresponding octal character
        } else if (i + 3 < str.length && str[i + 1] >= '0' && str[i+1] <= '3' &&
                str[i + 2] >= '0' && str[i+2] <= '7' &&
                str[i + 3] >= '0' && str[i+3] <= '7') {

                var sum = 
                    ((str[i + 1] - '0') * 64) +
                    ((str[i + 2] - '0') * 8) +
                    ((str[i + 3] - '0'));

                // If the octal character is less than 32 decimal,
                // then it is a control (non-printing) character.
                // In this case, dont' de-octalize the input string;
                // immediately return the entire input string.
                if (sum < 32) {
                    return str;
                } else {
                    ret.push(sum);
                }

                i += 3;
	// This clause is reached only if a backslash was encountered,
        // but the backslash was not followed by either another
        // backslash or by 3 valid octal digits.  This means that
        // the input string is not a valid octalized string, so we
        // don't know how to de-octalize it.  In this case, return
        // the input string.
	} else {
            return str;
        }
    }

    try {
        // Try to convert the de-octalized string from utf8 to
        // unicode.
        return exports.decoder.decode(Uint8Array.from(ret))
    } catch(e) {
        // The de-octalized string was not valid utf8, so we don't
        // know how to convert it.  In this case, return the input
        // string.
        return str;
    }
}


/* Recurse over a complete object (such as from json), finding all strings,
 * and escaping them to be 'safe' */
exports.sanitizeObject = function(o) {
    if (o === null) {
        return o;
    }

    if (typeof(o) === 'string') {
        return exports.sanitizeHTML(exports.deoctalize(o));
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
