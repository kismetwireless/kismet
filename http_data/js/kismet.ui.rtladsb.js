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
        var aircraft_info = [
            'department',
            'police',
            'agency',
            'dep',
            'gov',
            'federal',
            'royal',
            'force',
            'state',
            'army',
            'navy',
            'patrol',
            'sqdn',
	    'city of',
        ];

	var exclude_list = [
	    'express',
	    'air freight',
	]

	var icao_list = [
	    'acf181',
	    'a980fa',
	    'a7fb8f',
	    'ae4bd7',
	    'a47604',
            'a03bc8',
            'a0b8d6',
            'a0d9f2',
            'a12d51',
            'a15f1d',
            'a169d7',
            'a16c6d',
            'a193c1',
            'a32524',
            'a328db',
            'a32c92',
            'a33049',
            'a33dc3',
            'a3c1be',
            'a3c92c',
            'a3e6e3',
            'a3e6e4',
            'a410bc',
            'a4182a',
            'a44360',
            'a4724d',
            'a483df',
            'a4bc36',
            'a4bfed',
            'a51a10',
            'a51dc7',
            'a54b56',
            'a54f0d',
            'a552c4',
            'a5ed09',
            'a5f9f7',
            'a64217',
            'a645ce',
            'a64985',
            'a64d3c',
            'a654aa',
            'aac551',
            'abaf9c',
            'ac742b',
            'ac7b99',
	    ];

        if (data['kismet.device.base.phyname'] === 'RTLADSB') {
            for (var re of aircraft_info) {
		 var retval = false;
		 if (data['rtladsb.device']['kismet.adsb.icao_record']['adsb.icao.owner'].toLowerCase().includes(re)) {
	            retval = true;
		    for (var excld of exclude_list) {
		      if (data['rtladsb.device']['kismet.adsb.icao_record']['adsb.icao.owner'].toLowerCase().includes(excld)) {
			retval=false;
		      }
	            }
		 }

		 if (Boolean(retval)) {
		     return true;
		 }
	    }
	    for (var re of icao_list) {
		 if (data['rtladsb.device']['rtladsb.device.icao'].toLowerCase().includes(re))
                    return true;
            }
        }
        return false;
    }
});

kismet_ui.AddDeviceDetail("rtladsb", "RTLADSB (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "RTLADSB");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "RtladsbData",
            "fields": [
            {
                field: "rtladsb.device/rtladsb.device.icao",
                liveupdate: true,
                title: "Plane ICAO",
                empty: "<i>Unknown</i>"
            },
            {
                field: "rtladsb.device/rtladsb.device.callsign",
                liveupdate: true,
                title: "Callsign",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Flight registration / Callsign",
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
                field: "rtladsb.device/kismet.adsb.icao_record/adsb.icao.regid",
                liveupdate: true,
                title: "Registration ID",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft registration ID or tail number",
            },
            {
                field: "rtladsb.device/kismet.adsb.icao_record/adsb.icao.atype",
                liveupdate: true,
                title: "Aircraft Classification",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft classification type",
            },
            {
                field: "rtladsb.device/kismet.adsb.icao_record/adsb.icao.model",
                liveupdate: true,
                title: "Model",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft model (general model type)",
            },
            {
                field: "rtladsb.device/kismet.adsb.icao_record/adsb.icao.type",
                liveupdate: true,
                title: "Type",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft type (specific model type)",
            },
            {
                field: "rtladsb.device/kismet.adsb.icao_record/adsb.icao.owner",
                liveupdate: true,
                title: "Aircraft Operator",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft operator or owner of record",
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

kismet_ui_tabpane.AddTab({
    id: 'adsb_live',
    tabTitle: 'ADSB Live',
    expandable: false,
    createCallback: function(div) {
        var url = new URL(parent.document.URL);
        url.searchParams.append('parent_url', url.origin)
        url.searchParams.append('local_uri_prefix', local_uri_prefix);
        url.pathname = `${local_uri_prefix}/adsb_map_panel.html`;

        div.append(
            $('<iframe>', {
                width: '100%',
                height: '100%',
                src: url.href,
            })
        );
    },
    priority: -100,

}, 'center');

// We're done loading
exports.load_complete = 1;

return exports;

});
