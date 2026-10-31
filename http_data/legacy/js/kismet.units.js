(
  typeof define === "function" ? function (m) { define("kismet-units-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_units = m(); }
)(function () {

"use strict";

var local_uri_prefix = "";
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

var exports = {};

// Use our settings to make some conversion functions for distance and temperature
exports.renderHeightDistance = function(m, precision = 5, lowest = false) {
    if (kismet.getStorage('kismet.base.unit.distance') === 'metric' ||
            kismet.getStorage('kismet.base.unit.distance', '') === '') {
        if (m < 1000 || lowest) {
            return m.toFixed(precision) + ' m';
        }

        return (m / 1000).toFixed(precision) + ' km';
    } else {
        var f = (m * 3.2808399);

        if (f < 5280 || lowest) {
            return f.toFixed(precision) + ' ft';
        }
        return (f / 5280).toFixed(precision) + ' mls';
    }
}

exports.renderHeightDistanceUnitless = function(m, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.distance') === 'metric' ||
            kismet.getStorage('kismet.base.unit.distance', '') === '') {
        return m.toFixed(precision);
    } else {
        var f = (m * 3.2808399);
        return f.toFixed(precision);
    }
}

exports.renderSpeed = function(kph, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.speed') === 'metric' ||
            kismet.getStorage('kismet.base.unit.speed', '') === '') {
        return kph.toFixed(precision) + ' KPH';
    } else {
        return (kph * 0.621371).toFixed(precision) + ' MPH';
    }
}

exports.renderSpeedUnitless = function(kph, precision = 5) {
    if (kismet.getStorage('kismet.base.unit.speed') === 'metric' ||
            kismet.getStorage('kismet.base.unit.speed', '') === '') {
        return kph.toFixed(precision);
    } else {
        return (kph * 0.621371).toFixed(precision);
    }
}

return exports;

});
