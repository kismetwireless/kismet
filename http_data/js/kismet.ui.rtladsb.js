(
  typeof define === "function" ? function (m) { define("kismet-ui-rtladsb-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_rtladsb = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Flag we're still loading
exports.load_complete = 0;

/* Highlight rtl devices */
kismet_ui.AddDeviceRowHighlight({
    name: "RTLadsb Devices",
    description: "RTLadsb Sensor",
    priority: 50,
    //defaultcolor: "#efe0c3",
    defaultcolor: "#ffb3b3",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname',
        'rtladsb.device'
    ],
    selector: function(data) {
        var aircraft_names = [
            '^police$',
            '^depart$',
            ];

        if (data['kismet.device.base.phyname'] === 'RTLADSB') {
            for (var re of aircraft_names) {
		 if (data['rtladsb.device']['rtladsb.device.aoperator'].match(new RegExp(re, 'i')) != null)
                    return true;
            }
        } 

        //return data['kismet.device.base.phyname'] === "RTLADSB";
    }
});

kismet_ui.AddDeviceDetail("rtladsb", "RTLADSB (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RTLADSB");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "rtladsbData",
            "fields": [
            {
                field: "rtladsb.device/rtladsb.device.icao",
                liveupdate: true,
                title: "Plane ICAO",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtladsb.device/rtladsb.device.regid",
                liveupdate: true,
                title: "REG ID",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.mdl",
                liveupdate: true,
                title: "MDL",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.atype",
                liveupdate: true,
                title: "Aircraft Type",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.aoperator",
                liveupdate: true,
                title: "Aircraft Operator",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.callsign",
                liveupdate: true,
                title: "Callsign",
                filterOnZero: true,
                filterOnEmpty: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.callsign",
                id: "fa_callsign",
                liveupdate: true,
                title: "Flightaware",
                filterOnZero: true,
                filterOnEmpty: true,
                draw: function(opts) {
                    return '<a href="https://flightaware.com/live/flight/' + opts['value'] + '" target="_new">Track ' + opts['value'] + ' on FlightAware</a>';
                },
            },
            {
                field: "rtladsb.device/rtladsb.device.altitude",
                liveupdate: true,
                title: "Altitude",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.speed",
                liveupdate: true,
                title: "Speed",
                filterOnZero: true,
            },
            {
                field: "rtladsb.device/rtladsb.device.heading",
                liveupdate: true,
                title: "Heading",
                filterOnZero: true,
                draw: function(opts) {

                    return Math.round(opts['value']) + '&deg; <i class="fa fa-plane" style="transform: rotate(' + (opts['value'] -45) + 'deg)" />';

                },
            },
            {
                field: "rtladsb.device/rtladsb.device.latitude",
                liveupdate: true,
                title: "Location",
                filterOnZero: true,
                filterOnEmpty: true,
                draw: function(opts) {
                    try {
                        return opts['data']['rtladsb.device']['rtladsb.device.latitude'] + ', ' + opts['data']['rtladsb.device']['rtladsb.device.longitude'] + ' <a target="_new" href="https://openstreetmap.org/?&mlat=' + opts['data']['rtladsb.device']['rtladsb.device.latitude'] + '&mlon=' + opts['data']['rtladsb.device']['rtladsb.device.longitude'] + '">View on Open Street Maps</a>';
                    } catch (error) {
                        return 'n/a'
                    }

                },
            },
            {
                field: "rtladsb.device/rtladsb.device.asgs",
                liveupdate: true,
                title: "Airspeed(AS) / Groundspeed (GS)",
                filterOnZero: true,
            },
            ],
        });
    },
});


kismet_ui_sidebar.AddSidebarItem({
    id: 'adsb_map',
    listTitle: '<i class="fa fa-plane"></i> ADSB Live Map',
    priority: 99999,
    clickCallback: function() {
        exports.ADSBLiveMap();
    },
});

exports.ADSBLiveMap = function() {

    var w = $(window).width() * 0.95;
    var h = $(window).height() * 0.95;

    $.jsPanel({
        id: "adsb-live-map",
        headerTitle: '<i class="fa fa-plane"></i> Live Map',
        headerControls: {
            iconfont: 'jsglyph',
            minimize: 'remove',
            smallify: 'remove',
        },
        contentIframe: {
            src: local_uri_prefix + '/adsb_map_panel.html?parent_url=' + parent.document.URL + '&local_uri_prefix=' + local_uri_prefix
        },
    })
    .resize({
        width: w,
        height: h
    })
    .reposition({
        my: 'center-top',
        at: 'center-top',
        of: 'window',
    })
    .contentResize();

}

// We're done loading
exports.load_complete = 1;

return exports;

});
