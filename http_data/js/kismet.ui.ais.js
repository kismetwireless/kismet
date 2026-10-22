"use strict";

var local_uri_prefix = "";
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'AIS') {
        var aisclass = kismet.ObjectByString(row['original_data'], 'ais.device/ais.device.class');

        if (aisclass === 'Base Station')
            return '<i class="fa fa-tower-broadcast"></i>';
        if (aisclass === 'AtoN')
            return '<i class="fa fa-anchor"></i>';
        if (aisclass === 'SAR Aircraft')
            return '<i class="fa fa-helicopter"></i>';
        if (aisclass === 'AIS-SART' || aisclass === 'AIS-MOB' || aisclass === 'AIS-EPIRB')
            return '<i class="fa fa-life-ring"></i>';

        return '<i class="fa fa-ship"></i>';
    }
});

kismet_ui.AddHiddenDeviceColumn({'field': 'ais.device/ais.device.mmsi', 'searchable': true});
kismet_ui.AddHiddenDeviceColumn({'field': 'ais.device/ais.device.name', 'searchable': true});
kismet_ui.AddHiddenDeviceColumn({'field': 'ais.device/ais.device.callsign', 'searchable': true});
kismet_ui.AddHiddenDeviceColumn({'field': 'ais.device/ais.device.class'});

/* Highlight emergency beacons */
kismet_ui.AddDeviceRowHighlight({
    name: "AIS Emergency",
    description: "AIS SART, MOB, and EPIRB emergency beacons",
    priority: 10,
    defaultcolor: "#ff6666",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname',
        'ais.device'
    ],
    selector: function(data) {
        if (data['kismet.device.base.phyname'] !== 'AIS')
            return false;

        var aisclass = kismet.ObjectByString(data, 'ais.device/ais.device.class');

        return (aisclass === 'AIS-SART' || aisclass === 'AIS-MOB' || aisclass === 'AIS-EPIRB');
    }
});

function ais_is_class(opts, classes) {
    var aisclass = kismet.ObjectByString(opts['data'], 'ais.device/ais.device.class');
    return classes.includes(aisclass);
}

kismet_ui.AddDeviceDetail("ais", "AIS (SDR)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "AIS");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "aisData",
            "fields": [
            {
                field: "ais.device/ais.device.mmsi",
                liveupdate: true,
                title: "MMSI",
                help: "Maritime Mobile Service Identity",
                draw: function(opts) {
                    return opts['value'] + ' <a href="https://www.marinetraffic.com/en/ais/details/ships/mmsi:' + opts['value'] + '" target="_new">View on MarineTraffic</a>';
                },
            },
            {
                field: "ais.device/ais.device.class",
                liveupdate: true,
                title: "Station class",
                empty: "<i>Unknown</i>",
            },
            {
                field: "ais.device/ais.device.country",
                liveupdate: true,
                title: "Flag",
                help: "Country of registration, derived from the maritime identification digits of the MMSI",
                draw: function(opts) {
                    return opts['value'] + ' (MID ' + kismet.ObjectByString(opts['data'], 'ais.device/ais.device.mid') + ')';
                },
            },
            {
                field: "ais.device/ais.device.name",
                liveupdate: true,
                title: "Name",
                filterOnEmpty: true,
            },
            {
                field: "ais.device/ais.device.callsign",
                liveupdate: true,
                title: "Callsign",
                filterOnEmpty: true,
            },
            {
                field: "ais.device/ais.device.imo",
                liveupdate: true,
                title: "IMO number",
                filterOnZero: true,
            },
            {
                field: "ais.device/ais.device.ship_type_str",
                liveupdate: true,
                title: "Ship type",
                filterOnEmpty: true,
                draw: function(opts) {
                    return opts['value'] + ' (' + kismet.ObjectByString(opts['data'], 'ais.device/ais.device.ship_type') + ')';
                },
            },
            {
                field: "ais.device/ais.device.aton_type_str",
                liveupdate: true,
                title: "Aid to navigation",
                filter: function(opts) {
                    return ais_is_class(opts, ['AtoN']);
                },
                draw: function(opts) {
                    var ret = opts['value'];

                    if (kismet.ObjectByString(opts['data'], 'ais.device/ais.device.aton_virtual'))
                        ret += ' (virtual)';
                    if (kismet.ObjectByString(opts['data'], 'ais.device/ais.device.aton_off_position'))
                        ret += ' <b>off position</b>';

                    return ret;
                },
            },
            {
                field: "ais.device/ais.device.nav_status_str",
                liveupdate: true,
                title: "Navigation status",
                filterOnEmpty: true,
            },
            {
                field: "ais.device/ais.device.dim_bow",
                liveupdate: true,
                title: "Dimensions",
                help: "Overall length and beam, from the reported distances between the AIS antenna and the bow, stern, port, and starboard",
                filter: function(opts) {
                    var d = opts['data']['ais.device'];
                    return (d['ais.device.dim_bow'] + d['ais.device.dim_stern']) > 0;
                },
                draw: function(opts) {
                    var d = opts['data']['ais.device'];
                    return (d['ais.device.dim_bow'] + d['ais.device.dim_stern']) + 'm x ' +
                        (d['ais.device.dim_port'] + d['ais.device.dim_starboard']) + 'm';
                },
            },
            {
                field: "ais.device/ais.device.draught",
                liveupdate: true,
                title: "Draught",
                filterOnZero: true,
                draw: function(opts) {
                    return opts['value'].toFixed(1) + 'm';
                },
            },
            {
                field: "ais.device/ais.device.destination",
                liveupdate: true,
                title: "Destination",
                filterOnEmpty: true,
            },
            {
                field: "ais.device/ais.device.eta",
                liveupdate: true,
                title: "ETA (UTC)",
                filterOnEmpty: true,
            },
            {
                field: "ais.device/ais.device.vendor",
                liveupdate: true,
                title: "Transponder vendor",
                filterOnEmpty: true,
            },
            {
                field: "ais.device/ais.device.sog",
                liveupdate: true,
                title: "Speed",
                filter: function(opts) {
                    return !ais_is_class(opts, ['Base Station', 'AtoN']);
                },
                draw: function(opts) {
                    return opts['value'].toFixed(1) + ' knots';
                },
            },
            {
                field: "ais.device/ais.device.cog",
                liveupdate: true,
                title: "Course",
                filter: function(opts) {
                    return !ais_is_class(opts, ['Base Station', 'AtoN']);
                },
                draw: function(opts) {
                    return opts['value'].toFixed(1) + '&deg;';
                },
            },
            {
                field: "ais.device/ais.device.heading",
                liveupdate: true,
                title: "Heading",
                filter: function(opts) {
                    return !ais_is_class(opts, ['Base Station', 'AtoN']);
                },
                draw: function(opts) {
                    return Math.round(opts['value']) + '&deg; <i class="fa fa-location-arrow" style="transform: rotate(' + (opts['value'] - 45) + 'deg)" />';
                },
            },
            {
                field: "ais.device/ais.device.rot",
                liveupdate: true,
                title: "Rate of turn",
                filterOnZero: true,
                draw: function(opts) {
                    return opts['value'].toFixed(1) + '&deg;/min';
                },
            },
            {
                field: "ais.device/ais.device.altitude",
                liveupdate: true,
                title: "Altitude",
                filter: function(opts) {
                    return ais_is_class(opts, ['SAR Aircraft']);
                },
                draw: function(opts) {
                    return opts['value'] + 'm';
                },
            },
            {
                field: "ais.device/ais.device.utc_time",
                liveupdate: true,
                title: "Station UTC time",
                filterOnEmpty: true,
            },
            {
                field: "kismet.device.base.reported_location/kismet.common.location.last/kismet.common.location.geopoint",
                liveupdate: true,
                title: "Reported location",
                filterOnZero: true,
                filterOnEmpty: true,
                draw: function(opts) {
                    try {
                        var lat = opts['value'][1];
                        var lon = opts['value'][0];

                        if (lat == 0 && lon == 0)
                            return '<i>Unknown</i>';

                        return lat.toFixed(5) + ', ' + lon.toFixed(5) + ' <a target="_new" href="https://www.openstreetmap.org/?&mlat=' + lat + '&mlon=' + lon + '">View on OpenStreetMap</a>';
                    } catch (error) {
                        return '<i>Unknown</i>';
                    }
                },
            },
            {
                field: "ais.device/ais.device.last_msg_type",
                liveupdate: true,
                title: "Last message type",
            },
            ],
        });
    },
});

