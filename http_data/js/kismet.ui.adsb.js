
"use strict";

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

/* Highlight ADSB devices */
kismet_ui.AddDeviceRowHighlight({
    name: "ADSB Government",
    description: "Government &amp; related ADSB-tagged vehicles",
    priority: 50,
    //defaultcolor: "#efe0c3",
    defaultcolor: "#ffb3b3",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname',
        'adsb.device'
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
            'sheriff',
        ];

        var exclude_list = [
            'express',
            'air freight',
        ]

        var icao_list = [
            'acf181', 'a980fa', 'a7fb8f', 'ae4bd7', 'a47604',
            'a03bc8', 'a0b8d6', 'a0d9f2', 'a12d51', 'a15f1d',
            'a169d7', 'a16c6d', 'a193c1', 'a32524', 'a328db',
            'a32c92', 'a33049', 'a33dc3', 'a3c1be', 'a3c92c',
            'a3e6e3', 'a3e6e4', 'a410bc', 'a4182a', 'a44360',
            'a4724d', 'a483df', 'a4bc36', 'a4bfed', 'a51a10',
            'a51dc7', 'a54b56', 'a54f0d', 'a552c4', 'a5ed09',
            'a5f9f7', 'a64217', 'a645ce', 'a64985', 'a64d3c',
            'a654aa', 'aac551', 'abaf9c', 'ac742b', 'ac7b99',
        ];

        if (data['kismet.device.base.phyname'] === 'ADSB') {
            for (var re of aircraft_info) {
		 var retval = false;
		 if (data['adsb.device']['kismet.adsb.icao_record']['adsb.icao.owner'].toLowerCase().includes(re)) {
	            retval = true;
		    for (var excld of exclude_list) {
		      if (data['adsb.device']['kismet.adsb.icao_record']['adsb.icao.owner'].toLowerCase().includes(excld)) {
			retval=false;
		      }
	            }
		 }

		 if (Boolean(retval)) {
		     return true;
		 }
	    }
	    for (var re of icao_list) {
		 if (data['adsb.device']['adsb.device.icao'].toLowerCase().includes(re))
                    return true;
            }
        }
        return false;
    }
});

kismet_ui.AddDeviceDetail("adsb", "ADSB (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "ADSB");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "adsbData",
            "fields": [
            {
                field: "adsb.device/adsb.device.icao",
                liveupdate: true,
                title: "Plane ICAO",
                empty: "<i>Unknown</i>"
            },
            {
                field: "adsb.device/adsb.device.callsign",
                liveupdate: true,
                title: "Callsign",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Flight registration / Callsign",
            },
            {
                field: "adsb.device/adsb.device.callsign",
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
                field: "adsb.device/kismet.adsb.icao_record/adsb.icao.regid",
                liveupdate: true,
                title: "Registration ID",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft registration ID or tail number",
            },
            {
                field: "adsb.device/kismet.adsb.icao_record/adsb.icao.atype",
                liveupdate: true,
                title: "Aircraft Classification",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft classification type",
            },
            {
                field: "adsb.device/kismet.adsb.icao_record/adsb.icao.model",
                liveupdate: true,
                title: "Model",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft model (general model type)",
            },
            {
                field: "adsb.device/kismet.adsb.icao_record/adsb.icao.type",
                liveupdate: true,
                title: "Type",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft type (specific model type)",
            },
            {
                field: "adsb.device/kismet.adsb.icao_record/adsb.icao.owner",
                liveupdate: true,
                title: "Aircraft Operator",
                filterOnZero: true,
                filterOnEmpty: true,
                help: "Aircraft operator or owner of record",
            },
            {
                field: "adsb.device/adsb.device.altitude",
                liveupdate: true,
                title: "Altitude",
                filterOnZero: true,
            },
            {
                field: "adsb.device/adsb.device.speed",
                liveupdate: true,
                title: "Speed",
                filterOnZero: true,
            },
            {
                field: "adsb.device/adsb.device.heading",
                liveupdate: true,
                title: "Heading",
                filterOnZero: true,
                draw: function(opts) {

                    return Math.round(opts['value']) + '&deg; <i class="fa fa-plane" style="transform: rotate(' + (opts['value'] -45) + 'deg)" />';

                },
            },
            {
                field: "adsb.device/adsb.device.latitude",
                liveupdate: true,
                title: "Location",
                filterOnZero: true,
                filterOnEmpty: true,
                draw: function(opts) {
                    try {
                        return opts['data']['adsb.device']['adsb.device.latitude'] + ', ' + opts['data']['adsb.device']['adsb.device.longitude'] + ' <a target="_new" href="https://openstreetmap.org/?&mlat=' + opts['data']['adsb.device']['adsb.device.latitude'] + '&mlon=' + opts['data']['adsb.device']['adsb.device.longitude'] + '">View on Open Street Maps</a>';
                    } catch (error) {
                        return 'n/a'
                    }

                },
            },
            {
                field: "adsb.device/adsb.device.asgs",
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
        url.searchParams.append('KISMET_PROXY_PREFIX', KISMET_PROXY_PREFIX);
        url.pathname = `${local_uri_prefix}${KISMET_PROXY_PREFIX}adsb_map_panel.html`;

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

