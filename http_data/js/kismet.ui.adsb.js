
"use strict";

var local_uri_prefix = "";
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'ADSB') {
        return '<i class="fa fa-plane"></i>';
    }
});

$('<link>')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/leaflet.css'
    })
    .appendTo('head');

$('<link>')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/Control.Loading.css'
    })
    .appendTo('head');

$('<link>')
    .attr({
        type: 'text/css',
        rel: 'stylesheet',
        href: local_uri_prefix + 'css/kismet.adsb.css'
    })
    .appendTo('head');

$('<script>')
    .attr({
        src: "js/leaflet.js",
    })
    .appendTo('head');

$('<script>')
    .attr({
        src: "js/Leaflet.MultiOptionsPolyline.min.js",
    })
    .appendTo('head');

$('<script>')
    .attr({
        src: "js/Control.Loading.js",
    })
    .appendTo('head');

$('<script>')
    .attr({
        src: "js/chroma.min.js",
    })
    .appendTo('head');

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
                        return opts['data']['adsb.device']['adsb.device.latitude'] + ', ' + opts['data']['adsb.device']['adsb.device.longitude'] + ' <a target="_new" href="https://openstreetmap.org/?&mlat=' + opts['data']['adsb.device']['adsb.device.latitude'] + '&mlon=' + opts['data']['adsb.device']['adsb.device.longitude'] + '">View on OpenStreetMap</a>';
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
        div.ready(() => {
            BuildContentElement(div);

            /*

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

            */
        });
    },
    activateCallback: function() {
        ActivateTab();
    },
    priority: -100,

}, 'center');

var markers = {};
var tid = -1;
var map = null;
var adsbTabulator = null;
var load_maps = false;
var units = 'i';

function BuildContentElement(element) {
    element.html(`
    <div id="adsb-holder" style="height: 100%; width: 100%; position: relative;">
    <div id="warning" class="warning">
        <p><b>Warning!</b>
        <p>To display the live ADSB map, your browser will connect to the Leaflet and OpenStreetMap servers to fetch the map tiles.  This requires you have a functional Internet connection, and will reveal something about your location (the bounding region where planes have been seen.)
        <p><input id="dontwarn" type="checkbox">Don't warn me again</input>
        <p><button id="continue">Continue</button>
    </div>
    <div id="alt_scale">
        <div id="alt_min"></div>
        <div id="alt_mini"></div>
        <div id="alt_maxi"></div>
        <div id="alt_max"></div>
        <div id="alt_title"><strong>Altitude</strong></div>
    </div>
    <div id="adsb_map"></div>
    <div class="right-sidebar">
        <div id="plane-count" style="height: 10px">
        <i class="fa fa-plane" style="padding-right: 1em;"></i><span id="numplanes">0</span> planes in the past 10 minutes
        </div>

        <div id="plane-detail" style="padding-top: 10px; height: 75px;"></div>
        <br>
        <div style="width: 100%; height: 100%; font-size: 80%" id="adsb_planes"></div>
    </div>
    </div>
        `);

}

function ActivateTab() {
    $('#adsb_holder').ready(() => {
        if (kismet.getStorage('kismet.base.unit.distance') === 'metric' ||
            kismet.getStorage('kismet.base.unit.distance') === '')
            units = 'm';

        if (units === 'm') {
            $('#alt_min').html("0m");
            $('#alt_mini').html("3000m");
            $('#alt_maxi').html("9000m");
            $('#alt_max').html("12000m");
        } else {
            $('#alt_min').html("0ft");
            $('#alt_mini').html("10000ft");
            $('#alt_maxi').html("30000ft");
            $('#alt_max').html("40000ft");
        }


        // Datatable with fixed columns
        adsbTabulator = new Tabulator('#adsb_planes', {
            layout: 'fitColumns',
            movableColumns: false,
            dataLoader: false,
            sortMode: "local",
            pagination: true,
            paginationMode: "local",
            selectableRows: 1,
            selectableRowsPersistence: true,
            columns: [
                {
                    'field': 'icao',
                    'title': 'ICAO',
                    'headerSort': false,
                },
                {
                    'field': 'pid',
                    'title': 'ID',
                    'headerSort': false,
                },
                {
                    'field': 'alt',
                    'title': 'Alt',
                    'headerSort': true,
                    'formatter': (c, p, o) => {
                        try {
                            return Math.round(kismet_units.renderHeightDistanceUnitless(c.getValue()));
                        } catch (e) {
                            return c.getValue();
                        }
                    },
                    'hozAlign': 'right',
                },
                {
                    'field': 'spd',
                    'title': 'Spd',
                    'formatter': (c, p, o) => {
                        try {
                            return Math.round(kismet_units.renderSpeedUnitless(c.getValue()));
                        } catch (e) {
                            return c.getValue();
                        }
                    },
                    'hozAlign': 'right',
                },
                {
                    'field': 'hed',
                    'title': 'Hed',
                    'formatter': (c, p, o) => {
                        try {
                            return c.getValue().toFixed();
                        } catch (e) {
                            return c.getValue();
                        }
                    },
                    'hozAlign': 'right',
                    'headerSort': false,
                },
                {
                    'field': 'msgs',
                    'title': 'Msgs',
                    'headerSort': true,
                    'hozAlign': 'right',
                },

            ],
        });

        adsbTabulator.on("rowClick", (e, row) => {
            const d = row.getData();
            // console.log("row selected", d);

            $('#plane-detail').html(`
                <b>Flight: </b>${d['callsign']}<br>
                <b>Model: </b>${d['model'].MiddleShorten(20)}<br>
                <b>Operator: </b>${d['operator'].MiddleShorten(20)}<br>
                <b>Altitude: </b>${kismet_units.renderHeightDistance(d['alt'], 0, true)}<br>
                <b>Speed: </b>${kismet_units.renderSpeed(d['spd'], 0)}<br>
                `);

            $('.adsb-selected-plane').removeClass('adsb-selected-plane');
            $('#adsb_marker_icon_' + d['key']).addClass('adsb-selected-plane');
        });

        load_maps = kismet.getStorage('kismet.adsb.maps_ok', false);

        if (load_maps)
            $('#warning').hide();

        $('#continue').on('click', function() {
            if ($('#dontwarn').is(":checked"))
                kismet.putStorage('kismet.adsb.maps_ok', true);
            $('#warning').hide();
            load_maps = true;
        });

        poll_map();

    });
}

function get_alt_color(alt, v_perc=50) {
    // Colors go from 50 to 360 on the HSV slider, so scale to 310
    if (units === 'm') {
        if (alt > 12000)
            alt = 12000;
        if (alt < 0)
            alt = 0;

        var h = 40 + (310 * (alt / 12000));
        var hv = h.toFixed(0);

        return `hsl(${hv}, 100%, ${v_perc}%)`
    } else {
        var alt_f = alt * 3.2808399;
        if (alt_f > 40000)
            alt_f = 40000;
        if (alt_f < 0)
            alt_f = 0;

        var h = 40 + (310 * (alt_f / 40000));
        var hv = h.toFixed(0);

        return `hsl(${hv}, 100%, ${v_perc}%)`
    }
}

var moused_icao = null;
var moused_id = null;

function map_cb(d) {
    var data = kismet.sanitizeObject(d);

    if (map == null) {
        var lat1 = data['kismet.adsb.map.min_lat'];
        var lon1 = data['kismet.adsb.map.min_lon'];
        var lat2 = data['kismet.adsb.map.max_lat'];
        var lon2 = data['kismet.adsb.map.max_lon'];

        console.log(lat1, lon1, lat2, lon2);

        map = L.map('adsb_map', {
            loadingControl: true
        });
        map.fitBounds([[lat1, lon1], [lat2, lon2]])
        L.tileLayer('http://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>',
            className: 'map-tiles',
        }).addTo(map);

        console.log(map.getSize());
    }

    var rows = [];

    for (var d = 0; d < data['kismet.adsb.map.devices'].length; d++) {
        try {
            if (!('kismet.device.base.location' in data['kismet.adsb.map.devices'][d])) {
                continue;
            }

            if (!('kismet.common.location.last' in data['kismet.adsb.map.devices'][d]['kismet.device.base.location'])) {
                continue;
            }

            var lat = data['kismet.adsb.map.devices'][d]['kismet.device.base.location']['kismet.common.location.last']['kismet.common.location.geopoint'][1];
            var lon = data['kismet.adsb.map.devices'][d]['kismet.device.base.location']['kismet.common.location.last']['kismet.common.location.geopoint'][0];
            var heading = data['kismet.adsb.map.devices'][d]['kismet.device.base.location']['kismet.common.location.last']['kismet.common.location.heading'];
            var altitude = data['kismet.adsb.map.devices'][d]['kismet.device.base.location']['kismet.common.location.last']['kismet.common.location.alt'];
            var speed = data['kismet.adsb.map.devices'][d]['kismet.device.base.location']['kismet.common.location.last']['kismet.common.location.speed'];
            var icao = data['kismet.adsb.map.devices'][d]['adsb.device']['adsb.device.icao'];
            var id = data['kismet.adsb.map.devices'][d]['adsb.device']['kismet.adsb.icao_record']['adsb.icao.regid'];
            var packets = data['kismet.adsb.map.devices'][d]['kismet.device.base.packets.data'];
            var atype = data['kismet.adsb.map.devices'][d]['adsb.device']['kismet.adsb.icao_record']['adsb.icao.atype_short'];

            if (lat == 0 || lon == 0)
                continue;

            var key = kismet.sanitizeId(data['kismet.adsb.map.devices'][d]['kismet.device.base.key']);

            rows.push({
                id: key,
                icao: icao,
                pid: id,
                alt: altitude,
                spd: speed,
                hed: heading,
                msgs: packets,
                model: data['kismet.adsb.map.devices'][d]['adsb.device']['kismet.adsb.icao_record']['adsb.icao.model'],
                operator: data['kismet.adsb.map.devices'][d]['adsb.device']['kismet.adsb.icao_record']['adsb.icao.owner'],
                callsign: data['kismet.adsb.map.devices'][d]['adsb.device']['adsb.device.callsign'],
                key: kismet.sanitizeId(data['kismet.adsb.map.devices'][d]['kismet.device.base.key']),
            });



            var icontype = 'fa-plane';

            /*
             * 1 - Glider
             * 2 - Balloon
             * 3 - Blimp/Dirigible
             * 4 - Fixed wing single engine
             * 5 - Fixed wing multi engine
             * 6 - Rotorcraft
             * 7 - Weight-shift-control
             * 8 - Powered Parachute
             * 9 - Gyroplane
             * H - Hybrid Lift
             * O - Other
             */
            if (atype == "1".charCodeAt(0) || atype == "7".charCodeAt(0))
                icontype == 'fa-paper-plane';
            else if (atype == "6".charCodeAt(0))
                icontype == 'fa-helicopter';

            var myIcon = L.divIcon({
                className: 'plane-icon',
                html: `<div id="adsb_marker_${key}" style="width: 24px; height: 24px; transform-origin: center;"><i id="adsb_marker_icon_${key}" class="marker-center fa ${icontype}" style="font-size: 18px; color: ${get_alt_color(altitude)};"></div>`,
                iconAnchor: [12, 12],
            });

            if (key in markers) {
                marker = markers[key]['marker'];
                markers[key]['keep'] = true;

                // Move the marker
                $('#adsb_marker_' + kismet.sanitizeId(key)).css('transform', 'rotate(' + (heading - 45) + 'deg)');
                var new_loc = new L.LatLng(lat, lon);
                marker.setLatLng(new_loc);

                // Recolor the marker
                $('#adsb_marker_icon_' + kismet.sanitizeId(k)).css('color', get_alt_color(altitude));

                /*
                        if (markers[key]['last_lat'] != lat || markers[key]['last_lon'] != lon) {
                            markers[key]['pathlist'].push([lat, lon]);

                            markers[key]['last_lat'] = lat;
                            markers[key]['last_lon'] = lon;
                            markers[key]['heading'] = heading;

                            if (markers[key]['path'] != null) {
                                markers[key]['path'].addLatLng([lat, lon]);
                            } else {
                                markers[key]['path'] = L.polyline(markers[key]['pathlist'], {
                                    color: 'red',
                                    weight: 2,
                                    dashArray: '3',
                                    opacity: 0.85,
                                    smoothFactor: 1,
                                }).addTo(map);

                                markers[key]['path'].on('mouseover', wrap_closure_mouseover(key));
                                markers[key]['path'].on('mouseout', wrap_closure_mouseout(key));
                            }
                        }
                        */

            } else {
                /* Make a new marker */
                var marker = L.marker([lat, lon], { icon: myIcon} ).addTo(map);
                $('#adsb_marker_' + kismet.sanitizeId(key)).css('transform', 'rotate(' + (heading - 45) + 'deg)');

                markers[key] = {};
                markers[key]['marker'] = marker;
                markers[key]['icao'] = icao;
                markers[key]['keep'] = true;
                markers[key]['pathlist'] = [[lat, lon]];
                markers[key]['path'] = null;
                markers[key]['last_path_ts'] = 0;

                markers[key]['model'] = data['kismet.adsb.map.devices'][d]['adsb.device']['kismet.adsb.icao_record']['adsb.icao.model'];
                markers[key]['operator'] = data['kismet.adsb.map.devices'][d]['adsb.device']['kismet.adsb.icao_record']['adsb.icao.owner'];
                markers[key]['callsign'] = data['kismet.adsb.map.devices'][d]['adsb.device']['adsb.device.callsign'];

                var click_fn = (key) => {
                    return () => {
                        const r = adsbTabulator.getRow(key);
                        if (r == false)
                            return;

                        const d = r.getData();
                        if (d == null)
                            return;

                        $('#plane-detail').html(`
                            <b>Flight: </b>${d['callsign']}<br>
                            <b>Model: </b>${d['model'].MiddleShorten(20)}<br>
                            <b>Operator: </b>${d['operator'].MiddleShorten(20)}<br>
                            <b>Altitude: </b>${kismet_units.renderHeightDistance(d['alt'], 0, true)}<br>
                            <b>Speed: </b>${kismet_units.renderSpeed(d['spd'], 0)}<br>
                            `);

                        $('.adsb-selected-plane').removeClass('adsb-selected-plane');
                        $('#adsb_marker_icon_' + d['key']).addClass('adsb-selected-plane');

                        console.log("selecting row:", key);
                        adsbTabulator.deselectRow();
                        adsbTabulator.setPageToRow(key);
                        adsbTabulator.selectRow(key);
                    };
                }

                markers[key]['marker'].on('click', click_fn(key));

                /*
                        markers[key]['marker'].on('mouseover', wrap_closure_mouseover(key));
                        markers[key]['marker'].on('mouseout', wrap_closure_mouseout(key));
                        markers[key]['marker'].on('click', wrap_closure_click(key));
                        */
            }

            markers[key]['altitude'] = altitude;
            markers[key]['heading'] = heading;
            markers[key]['speed'] = speed;
            markers[key]['last_lat'] = lat;
            markers[key]['last_lon'] = lon;

            // Assign the historic path, if location history is available
            try {
                var history = data['kismet.adsb.map.devices'][d]['kismet.device.base.location_cloud']['kis.gps.rrd.samples_100'];

                for (var s in history) {
                    // Ignore non-location historic points (caused by heading/altitude before we got
                    // a location lock
                    var s_lat = history[s]['kismet.historic.location.geopoint'][1];
                    var s_lon = history[s]['kismet.historic.location.geopoint'][0];
                    var s_alt = history[s]['kismet.historic.location.alt'];
                    var s_ts = history[s]['kismet.historic.location.time_sec'];

                    if (s_lat == 0 || s_lon == 0 || s_ts < markers[key]['last_path_ts'])
                        continue

                    markers[key]['last_path_ts'] = s_ts;

                    if (markers[key]['path'] != null) {
                        markers[key]['path'].addLatLng([s_lat, s_lon]);
                    } else {
                        markers[key]['path'] = L.polyline([[s_lat, s_lon], [s_lat, s_lon]], {
                            color: get_alt_color(s_alt, 25),
                            /*
                            // color: 'red',
                                    multiOptions: {
                                        options: function(v) {
                                            return {'color': get_alt_color(s_alt)};
                                        },
                                    },
                                    */
                            weight: 2,
                            dashArray: '3',
                            opacity: 0.30,
                            smoothFactor: 1,
                        }).addTo(map);

                        /*
                                markers[key]['path'].on('mouseover', wrap_closure_mouseover(key));
                                markers[key]['path'].on('mouseout', wrap_closure_mouseout(key));
                                */
                    }
                }
            } catch (error) {
                // console.log(error);
            }

            /*
                                    if (moused_icao != null) {
                                    $(`#ROW_ICAO_${moused_icao}`).css('background-color', 'red');
                                    }
                                    */

        } catch (error) {
            console.log("device processing", error);
        }

    }

    $('#numplanes').html(rows.length);

    const p = adsbTabulator.getPage();
    const r = adsbTabulator.getSelectedRows();
    var i = null;
    if (r.length > 0) {
        i = r[0].getIndex();
    }
    adsbTabulator.replaceData(rows)
        .then(() => {
            if (p != 1) {
                adsbTabulator.setPage(p);
            }

            if (i != null) {
                console.log("Selecting on replace ", i);
                adsbTabulator.selectRow(i);
            }

            if (tid != -1)
                clearTimeout(tid);
            tid = setTimeout(function() { poll_map(); }, 2000);
        })
        .catch((e) => {
            console.log("fail in replacedata", e);
        });


    for (var k in markers) {
        if (markers[k]['keep']) {
            markers[k]['keep'] = false;
            continue;
        }

        if (markers[k]['marker'] != null)
            map.removeLayer(markers[k]['marker']);
        if (markers[k]['path'] != null)
            map.removeLayer(markers[k]['path']);

        delete(markers[k]);
    }
}

function poll_map() {
    if (kismet_ui.window_visible && !$('#adsb_map').is(':hidden') && load_maps) {
        $.get(local_uri_prefix + "phy/ADSB/map_data.json")
            .done(function(d) {
                map_cb(d);
            })
            .fail(() => {
                if (tid != -1)
                    clearTimeout(tid);
                tid = setTimeout(function() { poll_map(); }, 2000);
            });
    } else {
        if (tid != -1)
            clearTimeout(tid);
        tid = setTimeout(function() { poll_map(); }, 2000);
    }
}
