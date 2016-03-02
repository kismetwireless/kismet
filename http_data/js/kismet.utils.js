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
var KIS_TRACKERTYPE_STRING  = 0;
var KIS_TRACKERTYPE_INT8    = 1;
var KIS_TRACKERTYPE_UINT8   = 2;
var KIS_TRACKERTYPE_INT16   = 3;
var KIS_TRACKERTYPE_UINT16  = 4;
var KIS_TRACKERTYPE_INT32   = 5;
var KIS_TRACKERTYPE_UINT32  = 6;
var KIS_TRACKERTYPE_INT64   = 7;
var KIS_TRACKERTYPE_UINT64  = 8;
var KIS_TRACKERTYPE_FLOAT   = 9;
var KIS_TRACKERTYPE_DOUBLE  = 10;
var KIS_TRACKERTYPE_MAC     = 11;
var KIS_TRACKERTYPE_UUID    = 12;
var KIS_TRACKERTYPE_VECTOR  = 13;
var KIS_TRACKERTYPE_MAP     = 14;
var KIS_TRACKERTYPE_INTMAP  = 15;
var KIS_TRACKERTYPE_MACMAP  = 16;

exports.ConvertMacaddr = ConvertMacaddr;
function ConvertMacaddr(trackermac) {
    var ret = {};
    ret.macaddr = trackermac[0];
    ret.mask = trackermac[1];
    return ret;
}

exports.ConvertTrackerPack = ConvertTrackerPack;
function ConvertTrackerPack(unpacked) {
    if (unpacked[0] == KIS_TRACKERTYPE_VECTOR) {
        var retarr = [];

        for (var x = 0; x < unpacked[1].length; x++) {
            retarr.push(ConvertTrackerPack(unpacked[1][x]));
        }

        return retarr;
    } else if (unpacked[0] == KIS_TRACKERTYPE_MAP ||
            unpacked[0] == KIS_TRACKERTYPE_INTMAP) {
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
        }
    });
};

exports.GetDeviceSummary = function(callback, failback) {
    $.ajax({
        url: "/devices/all_devices.msgpack",
        type: "GET",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        success: function(arbuf) {
            var msg;
            try {
                msg = msgpack.decode(arbuf);
                callback(ConvertTrackerPack(msg));
            } catch (e) {
                failback(e);
            }
        }
    });
};

exports.GetDevice = function(key, callback, failback) {
    $.ajax({
        url: "/devices/" + key + ".msgpack",
        type: "GET",
        dataType: "binary",
        processData: false,
        responseType: 'arraybuffer',
        success: function(arbuf) {
            var msg;
            try {
                msg = msgpack.decode(arbuf);
                callback(ConvertTrackerPack(msg));
            } catch (e) {
                failback(e);
            }
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
            try {
                msg = msgpack.decode(arbuf);
                callback(ConvertTrackerPack(msg));
            } catch (e) {
                failback(e);
            }
        }
    });
};

return exports;

});
