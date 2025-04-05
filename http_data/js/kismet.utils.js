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

    let rrd_len = data.length;

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
    let adj_data = new Array();

    // Check if we're past the recording bounds of the rrd for this type, if we
    // are, we don't have to do any shifting or any manipulation, we just fill
    // the array with zeroes.
    if ((now - start) > (type * rrd_len)) {
        for (let ri = 0; ri < rrd_len; ri++) {
            adj_data.push(0);
        }
    } else {
        // Otherwise, we're valid inside the range of the array.  We know we got
        // no data between the time of the RRD and now, because if we had, the
        // time would be more current.  Figure out how many bins lie between
        // 'then' and 'now', rescale the array to start at 'now', and fill
        // in the time we got no data with zeroes

        let start_bin = (Math.floor(start / type) % rrd_len) + 1;
        let now_bin = (Math.floor(now / type) % rrd_len) + 1;
        let sec_offt = Math.max(0, now - start);

        /*
        console.log("we think we start in bin" + start_bin);
        console.log("we think now is bin" + now_bin);
        */

        // Walk the entire array, starting with 'now', and copy zeroes
        // when we fall into the blank spot between 'start' and 'now' when we
        // know we received no data
        for (let ri = 0; ri < rrd_len; ri++) {
            let slot = (now_bin + ri) % rrd_len;

            if (slot >= start_bin && slot < now_bin)
                adj_data.push(0);
            else
                adj_data.push(data[slot]);
        }
    }

    // If we have a transform function in the options, call it, otherwise
    // return the shifted RRD entry
    if ('transform' in opt && typeof(opt.transform) === 'function') {
        let cbopt = {};

        if ('transformopt' in opt)
            cbopt = opt.transformopt;

        return opt.transform(adj_data, cbopt, adj_data);
    }

    return adj_data;
}

exports.RecalcRrdData2 = function(rrddata, type, opt = {}) {
    let record = "";

    if (type == exports.RRD_SECOND)
        record = "kismet.common.rrd.minute_vec";
    else if (type == exports.RRD_MINUTE)
        record = "kismet.common.rrd.hour_vec";
    else if (type == exports.RRD_HOUR)
        record = "kismet.common.rrd.day_vec";
    else
        record = "kismet.common.rrd.minute_vec";

    let data = [];
    let rrd_len;
    let now;
    let start;
    let fill_val = 0;

    if (rrddata == undefined || rrddata[record] == undefined) {
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
            ];
        } else if (type == exports.RRD_HOUR) {
            data = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ];
        }
    } else {
        data = rrddata[record];

        if (typeof(data) === 'number')
            throw(0);

        // fill_val = rrddata['kismet.common.rrd.blank_val'];

        now = rrddata['kismet.common.rrd.serial_time'];
        start = rrddata['kismet.common.rrd.last_time'];
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
    let adj_data = new Array();

    // Check if we're past the recording bounds of the rrd for this type, if we
    // are, we don't have to do any shifting or any manipulation, we just fill
    // the array with zeroes.
    if ((now - start) > (type * rrd_len)) {
        for (let ri = 0; ri < rrd_len; ri++) {
            adj_data.push(0);
        }
    } else {
        // Otherwise, we're valid inside the range of the array.  We know we got
        // no data between the time of the RRD and now, because if we had, the
        // time would be more current.  Figure out how many bins lie between
        // 'then' and 'now', rescale the array to start at 'now', and fill
        // in the time we got no data with zeroes

        let start_bin = (Math.floor(start / type) % rrd_len) + 1;
        let now_bin = (Math.floor(now / type) % rrd_len) + 1;
        let sec_offt = Math.max(0, now - start);

        // Walk the entire array, starting with 'now', and copy zeroes
        // when we fall into the blank spot between 'start' and 'now' when we
        // know we received no data
        for (let ri = 0; ri < rrd_len; ri++) {
            let slot = (now_bin + ri) % rrd_len;

            if (slot >= start_bin && slot < now_bin)
                adj_data.push(fill_val);
            else
                adj_data.push(data[slot]);
        }
    }

    // If we have a transform function in the options, call it, otherwise
    // return the shifted RRD entry
    if ('transform' in opt && typeof(opt.transform) === 'function') {
        let cbopt = {};

        if ('transformopt' in opt)
            cbopt = opt.transformopt;

        return opt.transform(adj_data, cbopt, rrddata);
    }

    return adj_data;
}

// 'drag' the last value of the RRD forwards over zeroes.
// This manipulates the data to "look" better in a display, at the cost of veracity of the contents,
// but for visualization this is where we want to be
exports.RrdDrag = function(data, opt, rrd) {

    // Find empty elements in the array
    // If there are no elements before the empty slot, fill with the next non-zero element
    // If there are elements before and after the empty slot, fill with the average of the bounding elements
    // If there are no elements after the empty slot, fill with the last valid value

    const nilval = rrd['kismet.common.rrd.blank_val'] ;
    let last = [nilval, -1];

    // find the next fill forward from where we are
    let find_fill_forward = (pos) => {
        for (let ri = pos; ri < data.length; ri++) {
            if (data[ri] !== nilval) {
                return [data[ri], ri];
            }
        }

        return [nilval, data.length];
    };

    // fill nil values with their future value
    let fill = [nilval, -1];

    for (let ri = 0; ri < data.length; ri++) {
        if (data[ri] !== nilval) {
            last = [data[ri], ri];
            continue;
        }

        if (data[ri] === nilval) {
            // if we don't know the next filled value, find it
            if (fill[0] === nilval || fill[1] < ri) {
                fill = find_fill_forward(ri + 1);
            }

            if (last[0] != nilval) {
                // no future fill value, known last value
                if (fill[0] == nilval) {
                    data[ri] = last[0];
                    continue;
                }

                // weighted average
                data[ri] = ((last[0] * (ri - last[ri])) + (fill[0] * (fill[1] - ri))) / (fill[1] - last[1]);
            } else if (fill[0] != nilval) {
                data[ri] = fill[0];
            }
        }
    }
    return data;
}


// Convert RRD data into deltas, doing our best to skip gaps and empties
exports.RrdDelta = function(data, opt, rrd) {
    var ret = new Array();

    var last = 0;
    var last_pos = -1;

    for (var ri = 0; ri < data.length; ri++) {
        if (data[ri] != rrd['kismet.common.rrd.blank_val']) {
            last = data[ri];
            last_pos = ri;
            break;
        }

        ret.push(0);
    }

    if (last_pos == -1)
        return ret;


    for (var ri = last_pos; ri < data.length; ri++) {
        if (data[ri] == rrd['kismet.common.rrd.blank_val']) {
            ret.push(0);
            continue;
        }

        if (data[ri] < last) {
            last = data[ri];
            ret.push(0);
            continue;
        }

        ret.push(data[ri] - last);
        last = data[ri];
    }

    return ret;
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

/* Censor a string by obscuring most of the contents */
exports.censorString = function(t) {
    try {
        if (window['censor_macs']) {
            if (t.length < 6) {
                return new Array(t.length + 1).join('X');
            } else {
                return t.substring(0, 2) + (new Array(t.length - 3).join('X')) + t.substring(t.length - 2, t.length);
            }
        } else {
            return t;
        }
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

String.prototype.MiddleShorten = function(len) {
    if (this.length > len) {
        let epos = len / 2;
        let lpos = this.length - (len / 2);

        while (epos > 1 && this.substr(epos - 1, 1) == ' ') {
            epos = epos - 1;
        }

        while (lpos < len && this.substr(lpos, 1) == ' ') {
            lpos = lpos + 1;
        }

        return this.substr(0,epos) + '...' + this.substr(lpos, this.length);
    }

    return this;
}

exports.ExtractDeviceName = function(device) {
    var ret = device['kismet.device.base.username'];
    if (ret != null && ret != '') {
        return exports.censorString(ret);
    }

    ret = device['kismet.device.base.name'];
    if (ret != null && ret != '') {
        return exports.censorString(ret);
    }

    ret = device['kismet.device.base.commonname'];
    if (ret != null && ret != '') {
        return exports.censorString(ret);
    }

    ret = device['kismet.device.base.macaddr'];
    return exports.censorMAC(ret);
}

return exports;

});
