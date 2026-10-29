
"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'Cellular') {
        return '<i class="fa fa-tower-cell"></i>';
    }
});

kismet_ui.AddDeviceDetail("cell", "Cell Info", 0, {
    filter: function(data) {
        return (data["cellular.device"] != undefined && data["cellular.device"] != 0);
    },
    draw: function(data, target) {
        target.devicedata(data, {
            id: "cellData",
            fields: [
            {
                field: "cellular.device/cellular.cell.rat",
                title: "RAT",
                help: "Radio Access Technology of the cell: GSM (Global System for Mobile Communications, 2G), UMTS (Universal Mobile Telecommunications System, 3G), LTE (Long Term Evolution, 4G), or NR (New Radio, 5G).",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.key",
                title: "Cell Key",
                help: "Unique key Kismet uses for the cell.  A fully identified cell is keyed by its Mobile Country Code, Mobile Network Code, Tracking Area Code, and Cell ID; a cell only heard as a neighbor is keyed by its Physical Cell ID and channel.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.operator",
                title: "Operator",
                help: "Network operator name, as reported by the modem.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.mcc",
                title: "MCC",
                help: "Mobile Country Code, the 3-digit country code of the network.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.mnc",
                title: "MNC",
                help: "Mobile Network Code, the 2- or 3-digit code of the network within its country.",
                empty: "<i>Unknown</i>",
            },
            {
                // The WiGLE operator token, MCC+MNC as broadcast.
                field: "cellular.device/cellular.cell.plmn",
                title: "PLMN",
                help: "Public Land Mobile Network ID, the Mobile Country Code and Mobile Network Code together.  Identifies the network operator.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.tac",
                title: "TAC",
                help: "Tracking Area Code (4G LTE and 5G NR) or Location Area Code (2G GSM and 3G UMTS), the group of cells this cell belongs to.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.cellid",
                title: "Cell ID",
                help: "Identity of the cell within its network.  Together with the Public Land Mobile Network ID (country and network codes) it identifies the cell globally.",
                empty: "<i>Unknown</i>",
            },
            {
                // LTE only: the ECI split. Unset for NR, where the
                // gNB-ID length is operator-configured and not derivable.
                field: "cellular.device/cellular.cell.enb_id",
                title: "eNB ID",
                help: "LTE base station (eNodeB, evolved Node B) ID, the upper bits of the cell ID.  Cells with the same eNB ID are usually on the same site.  Not available for 5G NR.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.sector",
                title: "Sector",
                help: "LTE cell number within its base station, the low 8 bits of the cell ID; often the antenna sector.  Not available for 5G NR.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.pci",
                title: "PCI",
                help: "Physical Cell ID, the short identifier carried in the radio signal.  Physical Cell IDs are reused across the network, so one only identifies a cell together with its channel and location.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.arfcn",
                title: "ARFCN",
                help: "Absolute Radio Frequency Channel Number, the channel the cell transmits on.  LTE uses EARFCNs (Evolved Universal Terrestrial Radio Access ARFCNs) and 5G NR uses NR-ARFCNs.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.band",
                title: "Band",
                help: "3GPP (3rd Generation Partnership Project) band number of the cell's channel.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.bandwidth",
                title: "Bandwidth",
                help: "Channel bandwidth of the cell.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] + " MHz";
                },
            },
            {
                field: "cellular.device/cellular.cell.duplex",
                title: "Duplex",
                help: "Duplex mode.  FDD (Frequency Division Duplex) uses separate uplink and downlink frequencies; TDD (Time Division Duplex) shares one frequency in alternating time slots.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.rsrp",
                title: "RSRP",
                help: "Reference Signal Received Power, the most recent signal strength measured by the modem, in dBm (decibels relative to a milliwatt).  Roughly, above -80 dBm is strong and below -100 dBm is weak.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    var val = opts['value'];
                    var color = "#ff0000";
                    if (val > -80)
                        color = "#00ff00";
                    else if (val > -100)
                        color = "#ffff00";
                    return '<span style="color: ' + color + ';">' + val + ' dBm</span>';
                },
            },
            {
                field: "cellular.device/cellular.cell.rsrq",
                title: "RSRQ",
                help: "Reference Signal Received Quality, the most recent signal quality in dB (decibels), which accounts for interference and load.  Values closer to 0 are better.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] + " dB";
                },
            },
            {
                field: "cellular.device/cellular.cell.sinr",
                title: "SINR",
                help: "Signal to Interference plus Noise Ratio, from the most recent measurement, in dB (decibels).  Higher is better.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] + " dB";
                },
            },
            {
                field: "cellular.device/cellular.cell.min_rsrp",
                title: "Min RSRP",
                help: "Weakest Reference Signal Received Power (signal strength) seen for this cell.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] + " dBm";
                },
            },
            {
                field: "cellular.device/cellular.cell.max_rsrp",
                title: "Max RSRP",
                help: "Strongest Reference Signal Received Power (signal strength) seen for this cell.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] + " dBm";
                },
            },
            {
                field: "cellular.device/cellular.cell.observation_count",
                title: "Observations",
                help: "Number of times the capture sources have reported this cell.",
                empty: "<i>Unknown</i>",
            },
            {
                field: "cellular.device/cellular.cell.seen_serving",
                title: "Seen as Serving",
                help: "Whether the modem has used this cell as its serving cell, rather than only hearing it as a neighbor.",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] ? "Yes" : "No";
                },
            },
            {
                // The registered field is seen_observed (phy_cell.h). Binding this row to a
                // nonexistent field makes it always render its `empty` placeholder.
                field: "cellular.device/cellular.cell.seen_observed",
                title: "Seen via Observation",
                help: "Whether this cell has been seen in neighbor-cell measurements, which usually give only a partial identity (Physical Cell ID and channel).",
                empty: "<i>Unknown</i>",
                render: function(opts) {
                    return opts['value'] ? "Yes" : "No";
                },
            },
            {
                // Provenance (M3.4): which capture pipe(s) contributed to this
                // tower. seen_via is a string-keyed map (at / diag), each value a
                // per-source record (origin, observation count, last seen, and
                // the fields that source supplies). Rendered as a small table;
                // draw, not render, since devicedata overwrites a render with the
                // raw value.  Values arrive escaped by sanitizeObject, keys don't.
                field: "cellular.device/cellular.cell.seen_via",
                title: "Seen Via",
                help: "Capture sources that reported this cell: the source (AT for the modem's AT command port, DIAG for its Qualcomm diagnostic port), the command or diagnostic log it came from, the observations it contributed, when it last did, and the fields it supplied.",
                draw: function(opts) {
                    var sv = opts['value'];

                    if (sv == undefined || Object.keys(sv).length == 0)
                        return "<i>None</i>";

                    var rows = [];
                    Object.keys(sv).sort().forEach(function(src) {
                        var rec = sv[src];
                        var origin = rec['cellular.prov.origin'] || '';
                        var count = rec['cellular.prov.observation_count'] || 0;
                        var last = rec['cellular.prov.last_seen'] || 0;
                        var fields = rec['cellular.prov.fields'] || [];

                        var when = "";
                        if (last > 0)
                            when = new Date(last * 1000).toLocaleTimeString();

                        rows.push('<tr>' +
                            '<td style="padding-right: 10px;"><b>' + kismet.sanitizeHTML(src) + '</b></td>' +
                            '<td style="padding-right: 10px;">' + origin + '</td>' +
                            '<td style="padding-right: 10px;">' + Number(count) + ' obs</td>' +
                            '<td style="padding-right: 10px;">' + when + '</td>' +
                            '<td>' + fields.join(', ') + '</td>' +
                            '</tr>');
                    });

                    return '<table>' +
                        '<tr>' +
                        '<th style="text-align: left; padding-right: 10px;">Source</th>' +
                        '<th style="text-align: left; padding-right: 10px;">Origin</th>' +
                        '<th style="text-align: left; padding-right: 10px;">Count</th>' +
                        '<th style="text-align: left; padding-right: 10px;">Last Seen</th>' +
                        '<th style="text-align: left;">Fields</th>' +
                        '</tr>' +
                        rows.join('') +
                        '</table>';
                },
            },
            ],
        });
    },
});

/* Override the MAC address column for cell devices — show Cell Key instead,
 * since cell towers don't have MAC addresses (ours are synthetic hashes). */
kismet_ui.AddDeviceColumn("macaddr", {
    'title': 'Address',
    'description': 'Device address (MAC or Cell Key)',
    'field': 'kismet.device.base.macaddr',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        // The PHY registers itself as "Cellular" (phy_cell.cc), and both WiGLE
        // exporters filter on "Cellular". Match that exact name, or the
        // device list shows the synthetic FNV-hashed MAC instead of the cell key.
        if (row != undefined && row['kismet.device.base.phyname'] === 'Cellular') {
            var cd = row['cellular.device'];
            if (cd != undefined && cd['cellular.cell.key'] != undefined)
                return cd['cellular.cell.key'];
        }
        return kismet.censorMAC(data);
    },
});

kismet_ui.AddDeviceColumn("column_cell_rat", {
    sTitle: "Cell RAT",
    field: "cellular.device/cellular.cell.rat",
    description: "Cell Radio Access Technology",
    width: "6em",
    renderfunc: function(d, t, r, m) { return (d === "" || d === 0) ? "" : d; },
    visibility: "hidden",
});

kismet_ui.AddDeviceColumn("column_cell_key", {
    sTitle: "Cell Key",
    field: "cellular.device/cellular.cell.key",
    description: "Cell Tower ID (MCC/MNC_TAC_CellID)",
    width: "14em",
    renderfunc: function(d, t, r, m) { return (d === "" || d === 0) ? "" : d; },
    visibility: "hidden",
});
