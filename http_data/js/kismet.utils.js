
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

function kismetConvertMacaddr(trackermac) {
    var ret = {};
    ret.macaddr = trackermac[0];
    ret.mask = trackermac[1];
    return ret;
}

function kismetConvertTrackerPack(unpacked) {
    if (unpacked[0] == KIS_TRACKERTYPE_VECTOR) {
        var retarr = [];

        for (var x = 0; x < unpacked[1].length; x++) {
            retarr.push(kismetConvertTrackerPack(unpacked[1][x]));
        }

        return retarr;
    } else if (unpacked[0] == KIS_TRACKERTYPE_MAP ||
            unpacked[0] == KIS_TRACKERTYPE_INTMAP) {
        var retdict = {};

        for (var k in unpacked[1]) {
            retdict[k] = kismetConvertTrackerPack(unpacked[1][k]);
        }

        return retdict;
    } else if (unpacked[0] == KIS_TRACKERTYPE_MAC) {
        return kismetConvertMacaddr(unpacked[1]);
    } else {
        return unpacked[1];
    }
}

function kismetGetDeviceSummary(callback, failback) {
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
                callback(kismetConvertTrackerPack(msg));
            } catch (e) {
                failback(e);
            }
        }
    });
};

function kismetGetDevice(key, callback, failback) {
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
                callback(kismetConvertTrackerPack(msg));
            } catch (e) {
                failback(e);
            }
        }
    });
};

function kismetGetSystemStatus(callback, failback) {
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
                callback(kismetConvertTrackerPack(msg));
            } catch (e) {
                failback(e);
            }
        }
    });
};

