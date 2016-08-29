/* jshint browser: true */
/* global define, module */
( // Module boilerplate to support browser globals and browserify and AMD.
  typeof define === "function" ? function (m) { define("kismet-ui-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui = m(); }
)(function () {
"use strict";

var exports = {};

var batteryTid; 

exports.BatteryUi = function(spinner, power, time) {
    spinner.show();
    kismet.GetSystemStatus(function(status) {
        if (status['kismet.system.battery.charging'] == "charging") {
            power.attr("src", "/images/icon_battery_full_charge.svg");
            time.text("Charging " + 
                    status['kismet.system.battery.percentage'] + "% ");
        } else if (status['kismet.system.battery.charging'] == "charged") {
            power.attr("src", "/images/icon_battery_full_charge.svg");
            time.text("Charged");
        } else {
            if (status['kismet.system.battery.percentage'] < 25)
                power.attr("src", "/images/icon_battery_0.svg");
            else if (status['kismet.system.battery.percentage'] < 50)
                power.attr("src", "/images/icon_battery_25.svg");
            else if (status['kismet.system.battery.percentage'] < 75)
                power.attr("src", "/images/icon_battery_50.svg");
            else if (status['kismet.system.battery.percentage'] < 90)
                power.attr("src", "/images/icon_battery_75.svg");
            else 
                power.attr("src", "/images/icon_battery_100.svg");

            var s = status['kismet.system.battery.remaining'];

            if (s > 0) {
                var h = Math.floor(s / 3600);
                s -= 3600 * h;
                var m = Math.floor(s / 60);
                s -= 60 * m;

                if (m < 10)
                    m = '0' + m
                
                time.text(status['kismet.system.battery.percentage'] + "% " + h+"h "+m+"m");
            } else {
                time.text(status['kismet.system.battery.percentage'] + "%")
            }
        }

    }, function() {
        power.attr("src", "/images/icon/battery_no_battery_power.svg");
        power.text("ERROR");
    });
    spinner.hide();

    batteryTid = setTimeout(exports.BatteryUi, 5000, spinner, power, time);
}

return exports;

});
