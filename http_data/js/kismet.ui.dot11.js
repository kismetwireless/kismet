"use strict";

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

// Crypt set from packet_ieee80211.h
export const crypt_none = 0;
export const crypt_unknown = 1;
export const crypt_wep = (1 << 1);
export const crypt_layer3 = (1 << 2);
export const crypt_wep40 = (1 << 3);
export const crypt_wep104 = (1 << 4);
export const crypt_tkip = (1 << 5);
export const crypt_wpa = (1 << 6);
export const crypt_psk = (1 << 7);
export const crypt_aes_ocb = (1 << 8);
export const crypt_aes_ccm = (1 << 9);
export const crypt_wpa_migmode = (1 << 10);
export const crypt_eap = (1 << 11);
export const crypt_leap = (1 << 12);
export const crypt_ttls = (1 << 13);
export const crypt_tls = (1 << 14);
export const crypt_peap = (1 << 15);
export const crypt_sae = (1 << 16);
export const crypt_wpa_owe = (1 << 17);

export const crypt_protectmask = 0xFFFFF;
export const crypt_isakmp = (1 << 20);
export const crypt_pptp = (1 << 21);
export const crypt_fortress = (1 << 22);
export const crypt_keyguard = (1 << 23);
export const crypt_unknown_protected = (1 << 24);
export const crypt_unknown_nonwep = (1 << 25);
export const crypt_wps = (1 << 26);
export const crypt_version_wpa = (1 << 27);
export const crypt_version_wpa2 = (1 << 28);
export const crypt_version_wpa3 = (1 << 29);

export const crypt_l3_mask = 0x300004;
export const crypt_l2_mask = 0xFBFA;

// Some hex and ascii manipulation
function hexstr_to_bytes(hex) {
    let bytes = [];

    try {
        for (let i = 0; i < hex.length - 1; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
    } catch (_error) {
        // skip
    }

    return bytes;
}

function hexdump(b) {
    if (typeof(b) === 'undefined' || b.length == 0)
        return "..".repeat(8);

    return b.reduce((output, elem) =>
        (output + ('0' + elem.toString(16)).slice(-2) + ""), '') + "..".repeat(8 - b.length);
}

function asciidump(b) {
    var ret = "";

    if (typeof(b) === 'undefined' || b.length == 0)
        return '.'.repeat(8);

    for (var i = 0; i < b.length; i++) {
        if (b[i] >= 32 && b[i] <= 127) {
            var c = String.fromCharCode(b[i]);

            if (c == "<")
                c = "&lt;";
            if (c == ">")
                c = "&gt;";
            if (c == "&")
                c = "&amp;";

            ret = ret + c;
        } else {
            ret = ret + ".";
        }
    }

    ret = ret + ".".repeat(8 - b.length);

    return ret;
}

function pretty_hexdump(b) {
    var groups = [];
    var ret_groups = [];

    if (typeof(b) === 'undefined')
        return "";

    for (var i = 0; i < b.length; i += 8) {
        groups.push(b.slice(i, i + 8));
    }

    if (b.length % 2)
        b.push([]);

    // Print 2 groups of 8, followed by ascii
    for (var i = 0; i < groups.length; i += 2) {
        var hex_str = hexdump(groups[i]) + "  " + hexdump(groups[i + 1]);
        var ascii_str = asciidump(groups[i]) + "  " + asciidump(groups[i + 1]);

        ret_groups.push(hex_str + '&nbsp;&nbsp;&nbsp;&nbsp;' + ascii_str);
    }

    return ret_groups;
}

export const CryptToHumanReadable = (cryptset) => {
    var ret = [];

    if (cryptset == crypt_none)
        return "None / Open";

    if (cryptset == crypt_unknown)
        return "Unknown";

    if (cryptset & crypt_wps)
        ret.push("WPS");

    if ((cryptset & crypt_protectmask) == crypt_wep) {
        ret.push("WEP");
        return ret.join(" ");
    }

    if (cryptset == crypt_wpa_owe)
        return "Open (OWE)";

    if (cryptset & crypt_wpa_owe)
        return "OWE";

    var WPAVER = "WPA";

    if (cryptset & crypt_version_wpa2)
        WPAVER = "WPA2";

    if (cryptset & crypt_version_wpa3)
        WPAVER = "WPA3";

    if (cryptset & crypt_wpa)
        ret.push(WPAVER);

	if ((cryptset & crypt_version_wpa3) && (cryptset & crypt_psk) && (cryptset & crypt_sae))
        ret.push("WPA3-TRANSITION");

    if (cryptset & crypt_psk)
        ret.push(WPAVER + "-PSK");

    if (cryptset & crypt_sae)
        ret.push(WPAVER + "-SAE");

    if (cryptset & crypt_eap)
        ret.push(WPAVER + "-EAP");

    if (cryptset & crypt_peap)
        ret.push(WPAVER + "-PEAP");

    if (cryptset & crypt_leap)
        ret.push("EAP-LEAP");

    if (cryptset & crypt_ttls)
        ret.push("EAP-TTLS");

    if (cryptset & crypt_tls)
        ret.push("EAP-TLS");

    if (cryptset & crypt_wpa_migmode)
        ret.push("WPA-MIGRATION");

    if (cryptset & crypt_wep40)
        ret.push("WEP40");

    if (cryptset & crypt_wep104)
        ret.push("WEP104");

    if (cryptset & crypt_tkip)
        ret.push("TKIP");

    if (cryptset & crypt_aes_ocb)
        ret.push("AES-OCB");

    if (cryptset & crypt_aes_ccm)
        ret.push("AES-CCM");

    if (cryptset & crypt_layer3)
        ret.push("Layer3");

    if (cryptset & crypt_isakmp)
        ret.push("Layer3-ISA-KMP");

    if (cryptset & crypt_pptp)
        ret.push("Layer3-PPTP");

    if (cryptset & crypt_fortress)
        ret.push("Fortress");

    if (cryptset & crypt_keyguard)
        ret.push("Keyguard");

    if (cryptset & crypt_unknown_protected)
        ret.push("Unknown");

    if (cryptset & crypt_unknown_nonwep)
        ret.push("Unknown-Non-WEP");

    return ret.join(" ");
};

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'IEEE802.11') {
        if (row['original_data']['kismet.device.base.type'] === 'Wi-Fi AP') {
            return '<i class="fa fa-wifi"></i>';
        }

        if (row['original_data']['kismet.device.base.type'] === 'Wi-Fi Client') {
            return '<i class="fa fa-computer"></i>';
        }

        if (row['original_data']['kismet.device.base.type'] === 'Wi-Fi Bridged') {
            return '<i class="fa fa-ethernet"></i>';
        }

        return '<i class="fa fa-wifi"></i>';
    }
});

kismet_ui.AddDeviceView("Wi-Fi Access Points", "phydot11_accesspoints", -10000, "Wi-Fi");

kismet_ui.AddChannelList("IEEE802.11", "Wi-Fi (802.11)", function(in_freq) {
    if (in_freq == 0)
        return "n/a";

    in_freq = parseInt(in_freq / 1000);

    if (in_freq == 2484)
        return 14;
    else if (in_freq < 2412)
        return `${in_freq}MHz`;
    else if (in_freq == 5935)
        return 2;
    else if (in_freq < 2484)
        return (in_freq - 2407) / 5;
    else if (in_freq >= 4910 && in_freq <= 4980)
        return (in_freq - 4000) / 5;
    else if (in_freq < 5950)
        return (in_freq - 5000) / 5;
    else if (in_freq <= 45000) /* DMG band lower limit */
        return `${(in_freq - 5950) / 5}W6e`;
    else if (in_freq >= 58320 && in_freq <= 70200)
        return (in_freq - 56160) / 2160;
    else
        return in_freq;
});

/* Highlight WPA handshakes */
kismet_ui.AddDeviceRowHighlight({
    name: "WPA Handshake",
    description: "Network contains a complete WPA handshake",
    priority: 10,
    defaultcolor: "#F00",
    defaultenable: true,
    fields: [
        'dot11.device/dot11.device.wpa_handshake_list'
    ],
    selector: function(data) {
        try {
            for (const dev in data['dot11.device.wpa_handshake_list']) {
                var pmask = 0;
                
                for (const p of data['dot11.device.wpa_handshake_list'][dev]) {
                    pmask = pmask | (1 << p['dot11.eapol.message_num']);

                    if ((pmask & 0x06) == 0x06 || (pmask & 0x0C) == 0x0C)
                        return true;
                }
            }

            return false;

        } catch (e) {
            return false;
        }
    }
});

/* Highlight WPA RSN PMKID */
kismet_ui.AddDeviceRowHighlight({
    name: "RSN PMKID",
    description: "Network contains a RSN PMKID packet",
    priority: 10,
    defaultcolor: "#F55",
    defaultenable: true,
    fields: [
        'dot11.device/dot11.device.pmkid_packet'
    ],
    selector: function(data) {
        try {
            return 'dot11.device.pmkid_packet' in data && data['dot11.device.pmkid_packet'] != 0;
        } catch (e) {
            return false;
        }
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "Wi-Fi Device",
    description: "Highlight all Wi-Fi devices",
    priority: 100,
    defaultcolor: "#99ff99",
    defaultenable: false,
    fields: [
        'kismet.device.base.phyname',
    ],
    selector: function(data) {
        return ('kismet.device.base.phyname' in data && data['kismet.device.base.phyname'] === 'IEEE802.11');
    }
});

kismet_ui.AddDeviceColumn('wifi_clients', {
    'title': 'Clients',
    'description': 'Related Wi-Fi devices (associated and bridged), observed from packets',
    'field': 'dot11.device/dot11.device.num_associated_clients',
    'sortable': true,
    'alignment': 'right',
});

kismet_ui.AddDeviceColumn('wifi_last_bssid', {
    'title': 'BSSID',
    'description': 'Last associated BSSID',
    'field': 'dot11.device/dot11.device.last_bssid',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        try {
            if (data == 0 || data === '00:00:00:00:00:00')
                return '<i>n/a</i>';
        } catch (e) {
            ;
        }

        return kismet.censorMAC(data);
    },
});

kismet_ui.AddDeviceColumn('wifi_bss_uptime', {
    'title': 'Uptime',
    'description': 'Estimated device uptime (from BSS timestamp)',
    'field': 'dot11.device/dot11.device.bss_timestamp',
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        return kismet_ui_base.renderUsecTime(data);
    },
});

kismet_ui.AddDeviceColumn('wifi_qbss_usage', {
    'title': 'QBSS Channel Usage',
    'description': 'Reported channel utilization (802.11e QBSS)',
    'field': 'dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.dot11e_channel_utilization_perc',
    'fields': ['dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.dot11e_qbss'],
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        onrender(() => {
            var perc = "n/a";

            if (row['dot11.advertisedssid.dot11e_qbss'] == 1) {
                if (data == 0)
                    perc = "0%";
                else
                    perc = Number.parseFloat(data).toPrecision(4) + "%";
            }

            $(cell.getElement()).html(`<div class="percentage-border"><span class="percentage-text">${perc}</span><div class="percentage-fill" style="width:${data}%"></div></div>`);
        });
    },
});

kismet_ui.AddDeviceColumn('wifi_qbss_clients', {
    'title': 'QBSS #',
    'description': 'Associated client count (reported by AP via 802.11e QBSS)',
    'field': 'dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.dot11e_qbss_stations',
    'fields': ['dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.dot11e_qbss'],
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (row['dot11.advertisedssid.dot11e_qbss'] == 1) {
            return data;
        } else {
            return '<i>n/a</i>';
        }
    },
});

kismet_ui.AddDeviceColumn('wifi_beacon_name', {
    'title': 'Wi-Fi Beacon Vendor Name',
    'description': 'Additional name / hardware identifier added by some vendors',
    'field': 'dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.beacon_info',
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data.length === 0 || data === 0) {
            return '<i>n/a</i>'
        } else {
            return kismet.censorString(data);
        }
    },
});

/* Custom device details for dot11 data */
kismet_ui.AddDeviceDetail("dot11", "Wi-Fi (802.11)", 0, {
    filter: function(data) {
        try {
            return (data['kismet.device.base.phyname'] === "IEEE802.11");
        } catch (error) {
            return false;
        }
    },
    draw: function(data, target, options, storage) {
        target.devicedata(data, {
            "id": "dot11DeviceData",
            "fields": [
            {
                field: 'dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid',
                title: "Last Beaconed SSID (AP)",
                liveupdate: true,
                draw: function(opts) {
                    if (typeof(opts['value']) === 'undefined')
                        return '<i>None</i>';
                    if (opts['value'].replace(/\s/g, '').length == 0) 
                        return '<i>Cloaked / Empty (' + opts['value'].length + ' spaces)</i>';
                    return kismet.censorString(opts['value']);
                },
                help: "If present, the last SSID (network name) advertised by a device as an access point beacon or as an access point issuing a probe response",
            },
            {
                field: "dot11.device/dot11.device.last_probed_ssid_record/dot11.probedssid.ssid",
                liveupdate: true,
                title: "Last Probed SSID (Client)",
                empty: "<i>None</i>",
                help: "If present, the last SSID (network name) probed for by a device as a client looking for a network.",
                draw: function(opts) {
                    if (typeof(opts['value']) === 'undefined')
                        return '<i>None</i>';
                    if (opts['value'].replace(/\s/g, '').length == 0) 
                        return '<i>Empty (' + opts['value'].length + ' spaces)</i>'
                    return kismet.censorString(opts['value']);
                },
            },
            {
                field: "dot11.device/dot11.device.last_bssid",
                liveupdate: true,
                title: "Last BSSID",
                filter: function(opts) {
                    try {
                        return opts['value'].replace(/0:/g, '').length != 0;
                    } catch (e) {
                        return false;
                    }
                },
                help: "If present, the BSSID (MAC address) of the last network this device was part of.  Each Wi-Fi access point, even those with the same SSID, has a unique BSSID.",
                draw: function(opts) {
                    let mac = kismet.censorMAC(opts['value']);

                    let container =
                        $('<span>');
                    container.append(
                        $('<span>').html(mac)
                    );
                    container.append(
                        $('<i>', {
                            'class': 'copyuri pseudolink fa fa-copy',
                            'style': 'padding-left: 5px;',
                            'data-clipboard-text': `${mac}`, 
                        })
                    );

                    return container;
                },

            },
            {
                field: "dot11.device/dot11.device.bss_timestamp",
                liveupdate: true,
                title: "Uptime",
                draw: function(opts) {
                    if (opts['value'] == 0)
                        return "<i>n/a</i>";

                    const data_sec = opts['value'] / 1000000;

                    const days = Math.floor(data_sec / 86400);
                    const hours = Math.floor((data_sec / 3600) % 24);
                    const minutes = Math.floor((data_sec / 60) % 60);
                    const seconds = Math.floor(data_sec % 60);

                    let ret = "";

                    if (days > 0)
                        ret = ret + days + "d ";
                    if (hours > 0 || days > 0)
                        ret = ret + hours + "h ";
                    if (minutes > 0 || hours > 0 || days > 0)
                        ret = ret + minutes + "m ";
                    ret = ret + seconds + "s";

                    return ret;
                },
                help: "Access points contain a high-precision timestamp which can be used to estimate how long the access point has been running.  Typically access points start this value at zero on boot, but it may be set to an arbitrary number and is not always accurate.",
            },

            {
                field: "dot11_fingerprint_group",
                liveupdate: true,
                groupTitle: "Fingerprints",
                id: "dot11_fingerprint_group",
                fields: [
                {
                    field: "dot11.device/dot11.device.beacon_fingerprint",
                    liveupdate: true,
                    title: "Beacon",
                    empty: "<i>None</i>",
                    help: "Kismet uses attributes included in beacons to build a fingerprint of a device.  This fingerprint is used to identify spoofed devices, whitelist devices, and to attempt to provide attestation about devices.  The beacon fingerprint is only available when a beacon is seen from an access point.",
                }
                ],
            },

            {
                field: "dot11_packet_group",
                liveupdate: true,
                groupTitle: "Packets",
                id: "dot11_packet_group",

                fields: [
                {
                    field: "graph_field_dot11",
                    liveupdate: true,
                    span: true,
                    render: function(opts) {
                        const d = 
                            $('<div>', {
                                style: 'display: flex;'
                            })
                            .append(
                                $('<div>', {
                                    style: 'width: 50%; height: 200px; display: flex; justify-content: center; flex-direction: column; align-items: center; height: 250px',
                                    //style: 'width: 50%; height: 200px; padding-bottom: 5px; float: left;',
                                })
                                .append('<div><b><center>Overall Packets</center></b></div>')
                                .append(
                                    $('<div>')
                                    .append(
                                        $('<canvas>', {
                                            id: 'overalldonut',
                                            style: 'margin: 0 auto; width: 200px; height: 200px;'
                                        })
                                    )
                                )
                            )
                            .append(
                                $('<div>', {
                                    //style: 'width: 50%; height: 200px; padding-bottom: 5px; float: right;',
                                    style: 'width: 50%; height: 200px; display: flex; justify-content: center; flex-direction: column; align-items: center; height: 250px',
                                })
                                .append('<div><b><center>Data Packets</center></b></div>')
                                .append(
                                    $('<div>')
                                    .append(
                                        $('<canvas>', {
                                            id: 'datadonut',
                                            style: 'margin: 0 auto; width: 200px; height: 200px;'
                                        })
                                    )
                                )
                            );

                        return d;
                    },
                    draw: function(opts) {

                        let overalllegend = ['Management', 'Data'];
                        let overalldata = [
                            opts['data']['kismet.device.base.packets.llc'],
                            opts['data']['kismet.device.base.packets.data'],
                        ];
                        let colors = [
                            'rgba(46, 99, 162, 1)',
                            'rgba(96, 149, 212, 1)',
                            'rgba(136, 189, 252, 1)',
                        ];

                        let barChartData = {
                            labels: overalllegend,

                            datasets: [{
                                label: 'Dataset 1',
                                backgroundColor: colors,
                                borderWidth: 0,
                                data: overalldata,
                            }],
                        };

                        if ('dot11overalldonut' in window[storage]) {
                            window[storage].dot11overalldonut.data.datasets[0].data = overalldata;
                            window[storage].dot11overalldonut.update();
                        } else {
                            window[storage].dot11overalldonut = 
                                new Chart($('#overalldonut', opts['container']), {
                                    type: 'doughnut',
                                    data: barChartData,
                                    options: {
                                        global: {
                                            maintainAspectRatio: false,
                                        },
                                        animation: false,
                                        legend: {
                                            display: true,
                                            position: 'bottom',
                                        },
                                        title: {
                                            display: false,
                                            text: 'Packet Types'
                                        },
                                    }
                                });

                            window[storage].dot11overalldonut.render();
                        }

                        const datalegend = ['Data', 'Retry', 'Frag'];
                        const datadata = [
                            opts['data']['kismet.device.base.packets.data'],
                            opts['data']['dot11.device']['dot11.device.num_retries'],
                            opts['data']['dot11.device']['dot11.device.num_fragments'],
                        ];

                        const databarChartData = {
                            labels: datalegend,

                            datasets: [{
                                label: 'Dataset 1',
                                backgroundColor: colors,
                                borderWidth: 0,
                                data: datadata,
                            }],
                        };

                        if ('dot11datadonut' in window[storage]) {
                            window[storage].dot11datadonut.data.datasets[0].data = datadata;
                            window[storage].dot11datadonut.update();
                        } else {
                            window[storage].dot11datadonut = 
                                new Chart($('#datadonut', opts['container']), {
                                    type: 'doughnut',
                                    data: databarChartData,
                                    options: {
                                        global: {
                                            maintainAspectRatio: false,
                                        },
                                        animation: false,
                                        legend: {
                                            display: true,
                                            position: 'bottom'
                                        },
                                        title: {
                                            display: false,
                                            text: 'Packet Types'
                                        },
                                        height: '200px',
                                    }
                                });

                            window[storage].dot11datadonut.render();
                        }

                    }
                },
                {
                    field: "kismet.device.base.packets.total",
                    liveupdate: true,
                    title: "Total Packets",
                    help: "Total packet count seen of all packet types",
                },
                {
                    field: "kismet.device.base.packets.llc",
                    liveupdate: true,
                    title: "LLC/Management",
                    help: "LLC and Management packets define Wi-Fi networks.  They include packets like beacons, probe requests and responses, and other packets.  Access points will almost always have significantly more management packets than any other type.",
                },
                {
                    field: "kismet.device.base.packets.data",
                    liveupdate: true,
                    title: "Data Packets",
                    help: "Wi-Fi data packets encode the actual data being sent by the device.",
                },
                {
                    field: "kismet.device.base.packets.error",
                    liveupdate: true,
                    title: "Error/Invalid Packets",
                    help: "Invalid Wi-Fi packets are packets which have become corrupted in the air or which are otherwise invalid.  Typically these packets are discarded instead of tracked because the validity of their contents cannot be verified, so this will often be 0.",
                },
                {
                    field: "dot11.device/dot11.device.num_fragments",
                    liveupdate: true,
                    title: "Fragmented Packets",
                    help: "The data being sent over Wi-Fi can be fragmented into smaller packets.  Typically this is not desirable because it increases the packet load and can add latency to TCP connections.",
                },
                {
                    field: "dot11.device/dot11.device.num_retries",
                    liveupdate: true,
                    title: "Retried Packets",
                    help: "If a Wi-Fi data packet cannot be transmitted (due to weak signal, interference, or collisions with other packets transmitted at the same time), the Wi-Fi layer will automatically attempt to retransmit it a number of times.  In busy environments, a retransmit rate of 50% or higher is not unusual.",
                },
                {
                    field: "dot11.device/dot11.device.datasize",
                    liveupdate: true,
                    title: "Data (size)",
                    draw: kismet_ui.RenderHumanSize,
                    help: "The amount of data transmitted by this device",
                },
                {
                    field: "dot11.device/dot11.device.datasize_retry",
                    liveupdate: true,
                    title: "Retried Data",
                    draw: kismet_ui.RenderHumanSize,
                    help: "The amount of data re-transmitted by this device, due to lost packets and automatic retry.",
                }
                ],
            },

            {
                field: "dot11_extras",
                id: "dot11_extras",
                help: "Some devices advertise additional information about capabilities via additional tag fields when joining a network.",
                filter: function(opts) {
                    try {
                        if (opts['data']['dot11.device']['dot11.device.min_tx_power'] != 0)
                            return true;

                        if (opts['data']['dot11.device']['dot11.device.max_tx_power'] != 0)
                            return true;

                        if (opts['data']['dot11.device']['dot11.device.supported_channels'].length > 0)
                            return true;

                        return false;
                    } catch (_error) {
                        return false;
                    }
                    
                },
                groupTitle: "Additional Capabilities",
                fields: [
                {
                    field: "dot11.device/dot11.device.min_tx_power",
                    title: "Minimum TX",
                    help: "Some devices advertise their minimum transmit power in association requests.  This data is in the IE 33 field.  This data could be manipulated by hostile devices, but can be informational for normal devices.",
                    filterOnZero: true
                },
                {
                    field: "dot11.device/dot11.device.max_tx_power",
                    title: "Maximum TX",
                    help: "Some devices advertise their maximum transmit power in association requests.  This data is in the IE 33 field.  This data could be manipulated by hostile devices, but can be informational for normal devices.",
                    filterOnZero: true
                },
                {
                    field: "dot11.device/dot11.device.supported_channels",
                    title: "Supported Channels",
                    help: "Some devices advertise the 5GHz channels they support while joining a network.  Supported 2.4GHz channels are not included in this list.  This data is in the IE 36 field.  This data can be manipulated by hostile devices, but can be informational for normal deices.",
                    filter: function(opts) {
                        try {
                            return (opts['data']['dot11.device']['dot11.device.supported_channels'].length);
                        } catch (_error) {
                            return false;
                        }
                    },
                    draw: function(opts) { 
                        try {
                            return opts['data']['dot11.device']['dot11.device.supported_channels'].join(',');
                        } catch (_error) {
                            return "<i>n/a</i>";
                        }
                    }
                },
                ],
            },

            {
                field: "dot11.device/dot11.device.wpa_handshake_list",
                id: "wpa_handshake_title",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.wpa_handshake_list']).length);
                    } catch (_error) {
                        return false;
                    }
                },
                groupTitle: "WPA Handshakes",
            },
            {
                field: "dot11.device/dot11.device.wpa_handshake_list",
                id: "wpa_handshake",
                help: "When a client joins a WPA network, it performs a &quot;handshake&quot; of four packets to establish the connection and the unique per-session key.  To decrypt WPA or derive the PSK, at least two specific packets of this handshake are required.  Kismet provides a simplified pcap file of the handshake packets seen, which can be used with other tools to derive the PSK or decrypt the packet stream.",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.wpa_handshake_list']).length);
                    } catch (_error) {
                        return false;
                    }
                },
                groupIterate: true,

                fields: [
                {
                    field: "device",
                    id: "device",
                    title: "Client MAC",
                    draw: function(opts) {
                        return kismet.censorMAC(opts['index']);
                    },
                },
                {
                    field: "hsnums",
                    id: "hsnums",
                    title: "Packets",
                    draw: function(opts) {
                        let hs = 0;
                        for (const p of kismet.ObjectByString(opts['data'], opts['basekey'])) {
                            hs = hs | (1 << p['dot11.eapol.message_num']);
                        }

                        let n = "";

                        for (const p of [1, 2, 3, 4]) {
                            if (hs & (1 << p)) {
                                n = n + p + " ";
                            }
                        }

                        return n;
                    }
                },
                {
                    field: "wpa_handshake_download",
                    id: "handshake_download",
                    title: "Handshake PCAP",
                    draw: function(opts) {
                        let hs = 0;
                        for (const p of kismet.ObjectByString(opts['data'], opts['basekey'])) {
                            hs = hs | (1 << p['dot11.eapol.message_num']);
                        }

                        // We need packets 1&2 or 2&3 to be able to crack the handshake
                        let warning = "";
                        if (hs != 30) {
                            warning = '<br><i style="color: red;">While handshake packets have been seen, a complete 4-way handshake has not been observed.  You may still be able to utilize the partial handshake.</i>';
                        }

                        const key = opts['data']['kismet.device.base.key'];
                        const url = `<a href="phy/phy80211/by-key/${key}/device/${opts['index']}/pcap/handshake.pcap">` +
                            '<i class="fa fa-download"></i> Download Pcap File</a>' +
                            warning;
                        return url;
                    },
                }
                ]
            },

            {
                field: "dot11.device/dot11.device.pmkid_packet",
                id: "wpa_rsn_pmkid",
                help: "Some access points disclose the RSN PMKID during the first part of the authentication process.  This can be used to attack the PSK via tools like Aircrack-NG or Hashcat.  If a RSN PMKID packet is seen, Kismet can provide a pcap file.",
                filterOnZero: true,
                filterOnEmpty: true,
                groupTitle: "WPA RSN PMKID",

                fields: [
                {
                    field: "pmkid_download",
                    id: "pmkid_download",
                    title: "WPA PMKID PCAP",
                    draw: function(opts) {
                        const key = opts['data']['kismet.device.base.key'];
                        const url = '<a href="phy/phy80211/by-key/' + key + '/pcap/handshake-pmkid.pcap">' +
                            '<i class="fa fa-download"></i> Download Pcap File</a>'; 
                        return url;
                    },
                }
                ]
            },

            {
                // Filler title
                field: "dot11.device/dot11.device.probed_ssid_map",
                id: "probed_ssid_header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.probed_ssid_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Probed SSIDs</b>',
                help: "Wi-Fi clients will send out probe requests for networks they are trying to join.  Probe requests can either be broadcast requests, requesting any network in the area respond, or specific requests, requesting a single SSID the client has used previously.  Different clients may behave differently, and modern clients will typically only send generic broadcast probes.",
            },

            {
                field: "dot11.device/dot11.device.probed_ssid_map",
                id: "probed_ssid",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.probed_ssid_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,

                iterateTitle: function(opts) {
                    const lastprobe = opts['value'][opts['index']];
                    let lastpssid = lastprobe['dot11.probedssid.ssid'];
                    const  key = "probessid" + opts['index'];

                    if (lastpssid === '')
                        lastpssid = "<i>Broadcast</i>";

                    if (lastpssid.replace(/\s/g, '').length == 0) 
                        lastpssid = '<i>Empty (' + lastpssid.length + ' spaces)</i>'

                    return '<a id="' + key + '" class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Probed SSID ' + kismet.censorString(lastpssid) + '</a>';
                },

                draw: function(opts) {
                    $('.expander', opts['cell']).simpleexpand();
                },

                fields: [
                {
                    field: "dot11.probedssid.ssid",
                    title: "Probed SSID",
                    empty: "<i>Broadcast</i>",
                    draw: function(opts) {
                        if (typeof(opts['value']) === 'undefined')
                            return '<i>None</i>';
                        if (opts['value'].replace(/\s/g, '').length == 0) 
                            return 'Empty (' + opts['value'].length + ' spaces)'
                        return kismet.censorString(opts['value']);
                    },
                },
                {
                    field: "dot11.probedssid.wpa_mfp_required",
                    title: "MFP",
                    help: "Management Frame Protection (MFP) attempts to mitigate denial of service attacks by authenticating management packets.  It can be part of the 802.11w Wi-Fi standard, or proprietary Cisco extensions.",
                    draw: function(opts) {
                        if (opts['value'])
                            return "Required (802.11w)";

                        if (opts['base']['dot11.probedssid.wpa_mfp_supported'])
                            return "Supported (802.11w)";

                        return "Unavailable";
                    }
                },
                {
                    field: "dot11.probedssid.first_time",
                    liveupdate: true,
                    title: "First Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.probedssid.last_time",
                    liveupdate: true,
                    title: "Last Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },

                {
                    // Location is its own group
                    groupTitle: "Avg. Location",
                    id: "avg.dot11.probedssid.location",

                    // Group field
                    groupField: "dot11.probedssid.location",

                    liveupdate: true,

                    // Don't show location if we don't know it
                    filter: function(opts) {
                        return (kismet.ObjectByString(opts['base'], "dot11.probedssid.location/kismet.common.location.avg_loc/kismet.common.location.fix") >= 2);
                    },

                    fields: [
                        {
                            field: "kismet.common.location.avg_loc/kismet.common.location.geopoint",
                            title: "Location",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    if (opts['value'][1] == 0 || opts['value'][0] == 0)
                                        return "<i>Unknown</i>";

                                    return kismet.censorLocation(opts['value'][1]) + ", " + kismet.censorLocation(opts['value'][0]);
                                } catch (_error) {
                                    return "<i>Unknown</i>";
                                }
                            }
                        },
                        {
                            field: "kismet.common.location.avg_loc/kismet.common.location.alt",
                            title: "Altitude",
                            liveupdate: true,
                            filter: function(opts) {
                                return (kismet.ObjectByString(opts['base'], "kismet.common.location.avg_loc/kismet.common.location.fix") >= 3);
                            },
                            draw: function(opts) {
                                try {
                                    return kismet_ui.renderHeightDistance(opts['value']);
                                } catch (_error) {
                                    return "<i>Unknown</i>";
                                }
                            },
                        }
                    ],
                },

                {
                    field: "dot11.probedssid.dot11r_mobility",
                    title: "802.11r Mobility",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network.  Typically this is found on enterprise-level access points, on a network where multiple APs service the same area.",
                    draw: function(opts) { return "Enabled"; }
                },
                {
                    field: "dot11.probedssid.dot11r_mobility_domain_id",
                    title: "Mobility Domain",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network."
                },
                {
                    field: "dot11.probedssid.wps_manuf",
                    title: "WPS Manufacturer",
                    filterOnEmpty: true,
                    help: "Clients which support Wi-Fi Protected Setup (WPS) may include the device manufacturer in the WPS advertisements.  WPS is not recommended due to security flaws."
                },
                {
                    field: "dot11.probedssid.wps_device_name",
                    title: "WPS Device",
                    filterOnEmpty: true,
                    help: "Clients which support Wi-Fi Protected Setup (WPS) may include the device name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.probedssid.wps_model_name",
                    title: "WPS Model",
                    filterOnEmpty: true,
                    help: "Clients which support Wi-Fi Protected Setup (WPS) may include the specific device model name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.probedssid.wps_model_number",
                    title: "WPS Model #",
                    filterOnEmpty: true,
                    help: "Clients which support Wi-Fi Protected Setup (WPS) may include the specific model number in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.probedssid.wps_serial_number",
                    title: "WPS Serial #",
                    filterOnEmpty: true,
                    help: "Clients which support Wi-Fi Protected Setup (WPS) may include the device serial number in the WPS advertisements.  This information is not always valid or useful.  WPS is not recommended due to security flaws.",
                },

                ],
            },

            {
                // Filler title
                field: "dot11.device/dot11.device.advertised_ssid_map",
                id: "advertised_ssid_header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.advertised_ssid_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Advertised SSIDs</b>',
                help: "A single BSSID may advertise multiple SSIDs, either changing its network name over time or combining multiple SSIDs into a single BSSID radio address.  Most modern Wi-Fi access points which support multiple SSIDs will generate a dynamic MAC address for each SSID.  Advertised SSIDs have been seen transmitted from the access point in a beacon.",
            },

            {
                field: "dot11.device/dot11.device.advertised_ssid_map",
                id: "advertised_ssid",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.advertised_ssid_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    const lastssid = opts['value'][opts['index']]['dot11.advertisedssid.ssid'];
                    const lastowessid = opts['value'][opts['index']]['dot11.advertisedssid.owe_ssid'];

                    if (lastssid === '') {
                        if ('dot11.advertisedssid.owe_ssid' in opts['value'][opts['index']] && lastowessid !== '') {
                            return "SSID: " + kismet.censorString(lastowessid) + "  <i>(OWE)</i>";
                        }

                        return "SSID: <i>Unknown</i>";
                    }

                    return "SSID: " + kismet.censorString(lastssid);
                },
                fields: [
                {
                    field: "dot11.advertisedssid.ssid",
                    title: "SSID",
                    draw: function(opts) {
                        if (opts['value'].replace(/\s/g, '').length == 0) {
                            if ('dot11.advertisedssid.owe_ssid' in opts['base']) {
                                return "<i>SSID advertised as OWE</i>";
                            } else {
                                return '<i>Cloaked / Empty (' + opts['value'].length + ' spaces)</i>';
                            }
                        }

                        return kismet.censorString(opts['value']);
                    },
                    help: "Advertised SSIDs can be any data, up to 32 characters.  Some access points attempt to cloak the SSID by sending blank spaces or an empty string; these SSIDs can be discovered when a client connects to the network.",
                },
                {
                    field: "dot11.advertisedssid.owe_ssid",
                    liveupdate: true,
                    title: "OWE SSID",
                    filterOnEmpty: true,
                    draw: function(opts) { 
                        return kismet.censorString(opts['value']);
                    },
                    help: "Opportunistic Wireless Encryption (OWE) advertises the original SSID on an alternate BSSID.",
                },
                {
                    field: "dot11.advertisedssid.owe_bssid",
                    liveupdate: true,
                    title: "OWE BSSID",
                    filterOnEmpty: true,
                    help: "Opportunistic Wireless Encryption (OWE) advertises the original SSID with a reference to the linked BSSID.",
                    draw: function(opts) {
                        $.get(local_uri_prefix + "devices/by-mac/" + opts['value'] + "/devices.json")
                        .fail(function() {
                            opts['container'].html(kismet.censorMAC(opts['value']));
                        })
                        .done(function(clidata) {
                            clidata = kismet.sanitizeObject(clidata);

                            for (const cl of clidata) {
                                if (cl['kismet.device.base.phyname'] === 'IEEE802.11') {
                                    opts['container'].html(kismet.censorMAC(opts['value']) + ' <a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + cl['kismet.device.base.key'] + '\')">View AP Details</a>');
                                    return;
                                }

                            }
                            opts['container'].html(kismet.censorMAC(opts['value']));
                        });
                    },
                },
                {
                    field: "dot11.advertisedssid.dot11s.meshid",
                    liveupdate: true,
                    title: "Mesh ID",
                    filterOnEmpty: true,
                    help: "802.11s mesh id, present only in meshing networks.",
                },
                {
                    field: "dot11.advertisedssid.crypt_string",
                    liveupdate: true,
                    title: "Encryption",
                    /*
                    draw: function(opts) {
                        return CryptToHumanReadable(opts['value']);
                    },
                    */
                    help: "Wi-Fi networks advertise encryption options in beacon fields.  The encryption settings are often a mix of WPA, WPA2, and WPA3 options",
                },
                {
                    field: "dot11.advertisedssid.wpa_mfp_required",
                    liveupdate: true,
                    title: "MFP",
                    help: "Management Frame Protection (MFP) attempts to mitigate denial of service attacks by authenticating management packets.  It can be part of the Wi-Fi 802.11w standard or a custom Cisco extension.",
                    draw: function(opts) {
                        if (opts['value'])
                            return "Required (802.11w)";

                        if (opts['base']['dot11.advertisedssid.wpa_mfp_supported'])
                            return "Supported (802.11w)";

                        if (opts['base']['dot11.advertisedssid.cisco_client_mfp'])
                            return "Supported (Cisco)";

                        return "Unavailable";
                    }
                },
                {
                    field: "dot11.advertisedssid.channel",
                    liveupdate: true,
                    title: "Channel",
                    help: "Wi-Fi networks on 2.4GHz (channels 1 through 14) are required to include a channel in the advertisement because channel overlap makes it impossible to determine the exact channel the access point is transmitting on.  Networks on 5GHz channels are typically not required to include the channel.",
                },
                {
                    field: "dot11.advertisedssid.ht_mode",
                    liveupdate: true,
                    title: "HT Mode",
                    help: "802.11n and 802.11AC networks operate on expanded channels; HT40, HT80 HT160, or HT80+80 (found only on 802.11ac wave2 gear).",
                    filterOnEmpty: true
                },
                {
                    field: "dot11.advertisedssid.ht_center_1",
                    liveupdate: true,
                    title: "HT Freq",
                    help: "802.11AC networks operate on expanded channels.  This is the frequency of the center of the expanded channel.",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " (Channel " + (opts['value'] - 5000) / 5 + ")";
                    },
                },
                {
                    field: "dot11.advertisedssid.ht_center_2",
                    liveupdate: true,
                    title: "HT Freq2",
                    help: "802.11AC networks operate on expanded channels.  This is the frequency of the center of the expanded secondary channel.  Secondary channels are only found on 802.11AC wave-2 80+80 gear.",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " (Channel " + (opts['value'] - 5000) / 5 + ")";
                    },
                },
                {
                    field: "dot11.advertisedssid.beacon_info",
                    liveupdate: true,
                    title: "Beacon Info",
                    filterOnEmpty: true,
                    draw: function(opts) { 
                        return kismet.censorString(opts['value']);
                    },
                    help: "Some access points, typically enterprise-class devices such as those from Cisco, Aruba/HP, Mist, Ruckus, Arista, Aerohive, Extreme, and Mojo, can include custom device names in the beacons.  Typically this is used by the network administrators to map where access points are deployed or to indicate the name of the physical device.",
                },
                {
                    field: "dot11.advertisedssid.dot11s.gateway",
                    liveupdate: true,
                    title: "Mesh Gateway",
                    help: "An 802.11s mesh device in gateway mode bridges Wi-Fi traffic to another network, such as a wired Ethernet connection.",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        if (opts['value'] == 1)
                            return "Enabled";
                        return "Disabled (not a gateway)";
                    }
                },
                {
                    field: "dot11.advertisedssid.dot11s.forwarding",
                    liveupdate: true,
                    title: "Mesh Forwarding",
                    help: "An 802.11s mesh device may forward packets to another mesh device for delivery.",
                    filterOnEmpty: true,
                    draw: function(opts) {
                        if (opts['value'] == 1)
                            return "Forwarding";
                        return "No";
                    }
                },
                {
                    field: "dot11.advertisedssid.dot11s.num_peerings",
                    liveupdate: true,
                    title: "Mesh Peers",
                    help: "Number of mesh peers for this device in an 802.11s network.",
                    filterOnEmpty: true,
                },
                {
                    field: "dot11.advertisedssid.dot11e_qbss_stations",
                    liveupdate: true,
                    title: "Connected Stations",
                    help: "Access points which provide 802.11e / QBSS report the number of stations observed on the channel as part of the channel quality of service.",
                    filter: function(opts) {
                        try {
                            return (opts['base']['dot11.advertisedssid.dot11e_qbss'] == 1);
                        } catch (_error) {
                            return false;
                        }
                    }
                },
                {
                    field: "dot11.advertisedssid.dot11e_channel_utilization_perc",
                    liveupdate: true,
                    title: "Channel Utilization",
                    help: "Access points which provide 802.11e / QBSS calculate the estimated channel saturation as part of the channel quality of service.",
                    draw: function(opts) {
                        let perc = "n/a";

                        if (opts['value'] == 0) {
                            perc = "0%";
                        } else {
                            perc = Number.parseFloat(opts['value']).toPrecision(4) + "%";
                        }

                        return '<div class="percentage-border"><span class="percentage-text">' + perc + '</span><div class="percentage-fill" style="width:' + opts['value'] + '%"></div></div>';
                    },
                    filter: function(opts) {
                        try {
                            return (opts['base']['dot11.advertisedssid.dot11e_qbss'] == 1);
                        } catch (_error) {
                            return false;
                        }
                    }
                },
                {
                    field: "dot11.advertisedssid.advertised_txpower",
                    liveupdate: true,
                    title: "Advertised Power",
                    filterOnZero: true,
                    help: "Some APs may advertise transmit power via the IE35 TPC element.",
                    draw: function(opts) {
                        return opts['value'] + "dBm";
                    },
                },
                {
                    field: "dot11.advertisedssid.ccx_txpower",
                    liveupdate: true,
                    title: "Cisco CCX TxPower",
                    filterOnZero: true,
                    help: "Cisco access points may advertise their transmit power in a Cisco CCX IE tag.  Typically this is found on enterprise-level access points, where multiple APs service the same area.",
                    draw: function(opts) {
                        return opts['value'] + "dBm";
                    },
                },
                {
                    field: "dot11.advertisedssid.dot11r_mobility",
                    liveupdate: true,
                    title: "802.11r Mobility",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network.  Typically this is found on enterprise-level access points, on a network where multiple APs service the same area.",
                    draw: function(_opts) { return "Enabled"; }
                },
                {
                    field: "dot11.advertisedssid.dot11r_mobility_domain_id",
                    liveupdate: true,
                    title: "Mobility Domain",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network."
                },
                {
                    field: "dot11.advertisedssid.first_time",
                    liveupdate: true,
                    title: "First Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.advertisedssid.last_time",
                    liveupdate: true,
                    title: "Last Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },

                {
                    // Location is its own group
                    groupTitle: "Avg. Location",
                    id: "avg.dot11.advertisedssid.location",

                    // Group field
                    groupField: "dot11.advertisedssid.location",

                    liveupdate: true,

                    // Don't show location if we don't know it
                    filter: function(opts) {
                        return (kismet.ObjectByString(opts['base'], "dot11.advertisedssid.location/kismet.common.location.avg_loc/kismet.common.location.fix") >= 2);
                    },

                    fields: [
                        {
                            field: "kismet.common.location.avg_loc/kismet.common.location.geopoint",
                            title: "Location",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    if (opts['value'][1] == 0 || opts['value'][0] == 0)
                                        return "<i>Unknown</i>";

                                    return kismet.censorLocation(opts['value'][1]) + ", " + kismet.censorLocation(opts['value'][0]);
                                } catch (_error) {
                                    return "<i>Unknown</i>";
                                }
                            }
                        },
                        {
                            field: "kismet.common.location.avg_loc/kismet.common.location.alt",
                            title: "Altitude",
                            liveupdate: true,
                            filter: function(opts) {
                                return (kismet.ObjectByString(opts['base'], "kismet.common.location.avg_loc/kismet.common.location.fix") >= 3);
                            },
                            draw: function(opts) {
                                try {
                                    return kismet_ui.renderHeightDistance(opts['value']);
                                } catch (_error) {
                                    return "<i>Unknown</i>";
                                }
                            },
                        }
                    ],
                },

                {
                    field: "dot11.advertisedssid.beaconrate",
                    liveupdate: true,
                    title: "Beacon Rate",
                    draw: function(opts) {
                        return opts['value'] + '/sec';
                    },
                    help: "Wi-Fi typically beacons at 10 packets per second; normally there is no reason for an access point to change this rate, but it may be changed in some situations where a large number of SSIDs are hosted on a single access point.",
                },
                {
                    field: "dot11.advertisedssid.maxrate",
                    liveupdate: true,
                    title: "Max. Rate",
                    draw: function(opts) {
                        return opts['value'] + ' MBit/s';
                    },
                    help: "The maximum basic transmission rate supported by this access point",
                },
                {
                    field: "dot11.advertisedssid.dot11d_country",
                    liveupdate: true,
                    title: "802.11d Country",
                    filterOnEmpty: true,
                    help: "The 802.11d standard required access points to identify their operating country code and signal levels.  This caused clients connecting to those access points to adopt the same regulatory requirements.  802.11d has been phased out and is not found on most modern access points but may still be seen on older hardware.",
                },
                {
                    field: "dot11.advertisedssid.wps_manuf",
                    liveupdate: true,
                    title: "WPS Manufacturer",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device manufacturer in the WPS advertisements.  WPS is not recommended due to security flaws."
                },
                {
                    field: "dot11.advertisedssid.wps_device_name",
                    liveupdate: true,
                    title: "WPS Device",
                    filterOnEmpty: true,
                    draw: function(opts) { 
                        return kismet.censorString(opts['value']);
                    },
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_model_name",
                    liveupdate: true,
                    title: "WPS Model",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the specific device model name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_model_number",
                    liveupdate: true,
                    title: "WPS Model #",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the specific model number in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_serial_number",
                    liveupdate: true,
                    title: "WPS Serial #",
                    filterOnEmpty: true,
                    draw: function(opts) { 
                        return kismet.censorString(opts['value']);
                    },
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device serial number in the WPS advertisements.  This information is not always valid or useful.  WPS is not recommended due to security flaws.",
                },

                {
                    field: "dot11.advertisedssid.ie_tag_content",
                    liveupdate: true,
                    filterOnEmpty: true,
                    id: "dot11_ssid_ietags",
                    title: '<b class="k_padding_title">IE tags</b>',
                    help: "IE tags in beacons define the network and the access point attributes; because dot11_keep_ietags is true, Kismet tracks these here.",
                },

                {
                    field: "dot11.advertisedssid.ie_tag_content",
                    liveupdate: true,
                    id: "advertised_ietags",
                    filterOnEmpty: true,
                    span: true,

                    render: function(_opts) {
                        return '<table id="tagdump" border="0" />';
                    },

                    draw: function(opts) {
                        $('table#tagdump', opts['container']).empty();
                        for (const ie in opts['value']) {
                            const tag = opts['value'][ie];

                            const pretty_tag = 
                                $('<tr>', {
                                    class: 'alternating'
                                })
                                .append(
                                    $('<td>', {
                                        width: "25%",
                                        id: "tagno"
                                    })
                                    .append(
                                        $('<div>')
                                        .html("<b>" + tag['dot11.ietag.number'] + "</b>")
                                    )
                                )
                                .append(
                                    $('<td>', {
                                        id: "hexdump"
                                    })
                                );

                            if (tag['dot11.ietag.oui'] != 0) {
                                let oui = ("000000" + tag['dot11.ietag.oui'].toString(16)).substr(-6).replace(/(..)/g, '$1:').slice(0, -1);

                                if (tag['dot11.ietag.oui_manuf'].length != 0)
                                    oui = oui + " (" + tag['dot11.ietag.oui_manuf'] + ")";

                                $('#tagno', pretty_tag).append(
                                    $('<div>')
                                    .text(oui)
                                );
                            }

                            if (tag['dot11.ietag.subtag'] >= 0) {
                                $('#tagno', pretty_tag).append(
                                    $('<div>')
                                    .text("Subtag " + tag['dot11.ietag.subtag'])
                                )
                            }

                            const hexdumps = pretty_hexdump(hexstr_to_bytes(tag['dot11.ietag.data']));

                            for (const i in hexdumps) {
                                $('#hexdump', pretty_tag).append(
                                    $('<div>')
                                    .append(
                                        $('<code>')
                                        .html(hexdumps[i])
                                    )
                                )
                            }

                            $('table#tagdump', opts['container']).append(pretty_tag);
                        }
                    },

                },
                ],
            },


            {
                // Filler title
                field: "dot11.device/dot11.device.responded_ssid_map",
                id: "responded_ssid_header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.responded_ssid_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Responded SSIDs</b>',
                help: "A single BSSID may advertise multiple SSIDs, either changing its network name over time or combining multiple SSIDs into a single BSSID radio address.  Most modern Wi-Fi access points which support multiple SSIDs will generate a dynamic MAC address for each SSID.  SSIDs in the responded categoy have been seen as a probe response from the access point; typically an access point should only respond for SSIDs it also advertises.",
            },

            {
                field: "dot11.device/dot11.device.responded_ssid_map",
                id: "responded_ssid",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.responded_ssid_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    const lastssid = opts['value'][opts['index']]['dot11.advertisedssid.ssid'];
                    const lastowessid = opts['value'][opts['index']]['dot11.advertisedssid.owe_ssid'];

                    if (lastssid === '') {
                        if ('dot11.advertisedssid.owe_ssid' in opts['value'][opts['index']] && lastowessid !== '') {
                            return "SSID: " + kismet.censorString(lastowessid) + "  <i>(OWE)</i>";
                        }

                        return "SSID: <i>Unknown</i>";
                    }

                    return "SSID: " + kismet.censorString(lastssid);
                },
                fields: [
                {
                    field: "dot11.advertisedssid.ssid",
                    title: "SSID",
                    draw: function(opts) {
                        if (opts['value'].replace(/\s/g, '').length == 0) {
                            if ('dot11.advertisedssid.owe_ssid' in opts['base']) {
                                return "<i>SSID advertised as OWE</i>";
                            } else {
                                return '<i>Cloaked / Empty (' + opts['value'].length + ' spaces)</i>';
                            }
                        }

                        return kismet.censorString(opts['value']);
                    },
                    help: "Advertised SSIDs can be any data, up to 32 characters.  Some access points attempt to cloak the SSID by sending blank spaces or an empty string; these SSIDs can be discovered when a client connects to the network.",
                },
                {
                    field: "dot11.advertisedssid.owe_ssid",
                    liveupdate: true,
                    title: "OWE SSID",
                    filterOnEmpty: true,
                    draw: function(opts) { 
                        return kismet.censorString(opts['value']);
                    },
                    help: "Opportunistic Wireless Encryption (OWE) advertises the original SSID on an alternate BSSID.",
                },
                {
                    field: "dot11.advertisedssid.owe_bssid",
                    liveupdate: true,
                    title: "OWE BSSID",
                    filterOnEmpty: true,
                    help: "Opportunistic Wireless Encryption (OWE) advertises the original SSID with a reference to the linked BSSID.",
                    draw: function(opts) {
                        $.get(local_uri_prefix + "devices/by-mac/" + opts['value'] + "/devices.json")
                        .fail(function() {
                            opts['container'].html(opts['value']);
                        })
                        .done(function(clidata) {
                            clidata = kismet.sanitizeObject(clidata);

                            for (const cl of clidata) {
                                if (cl['kismet.device.base.phyname'] === 'IEEE802.11') {
                                    opts['container'].html(kismet.censorMAC(opts['value']) + ' <a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + cl['kismet.device.base.key'] + '\')">View AP Details</a>');
                                    return;
                                }

                            }
                            opts['container'].html(kismet.censorMAC(opts['value']));
                        });
                    },
                },
                {
                    field: "dot11.advertisedssid.crypt_set",
                    liveupdate: true,
                    title: "Encryption",
                    draw: function(opts) {
                        return CryptToHumanReadable(opts['value']);
                    },
                    help: "Encryption at the Wi-Fi layer (open, WEP, and WPA) is defined by the beacon sent by the access point advertising the network.  Layer 3 encryption (such as VPNs) is added later and is not advertised as part of the network itself.",
                },
                {
                    field: "dot11.advertisedssid.wpa_mfp_required",
                    liveupdate: true,
                    title: "MFP",
                    help: "Management Frame Protection (MFP) attempts to mitigate denial of service attacks by authenticating management packets.  It can be part of the Wi-Fi 802.11w standard or a custom Cisco extension.",
                    draw: function(opts) {
                        if (opts['value'])
                            return "Required (802.11w)";

                        if (opts['base']['dot11.advertisedssid.wpa_mfp_supported'])
                            return "Supported (802.11w)";

                        if (opts['base']['dot11.advertisedssid.cisco_client_mfp'])
                            return "Supported (Cisco)";

                        return "Unavailable";
                    }
                },
                {
                    field: "dot11.advertisedssid.ht_mode",
                    liveupdate: true,
                    title: "HT Mode",
                    help: "802.11n and 802.11AC networks operate on expanded channels; HT40, HT80 HT160, or HT80+80 (found only on 802.11ac wave2 gear).",
                    filterOnEmpty: true
                },
                {
                    field: "dot11.advertisedssid.ht_center_1",
                    liveupdate: true,
                    title: "HT Freq",
                    help: "802.11AC networks operate on expanded channels.  This is the frequency of the center of the expanded channel.",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " (Channel " + (opts['value'] - 5000) / 5 + ")";
                    },
                },
                {
                    field: "dot11.advertisedssid.ht_center_2",
                    liveupdate: true,
                    title: "HT Freq2",
                    help: "802.11AC networks operate on expanded channels.  This is the frequency of the center of the expanded secondary channel.  Secondary channels are only found on 802.11AC wave-2 80+80 gear.",
                    filterOnZero: true,
                    draw: function(opts) {
                        return opts['value'] + " (Channel " + (opts['value'] - 5000) / 5 + ")";
                    },
                },
                {
                    field: "dot11.advertisedssid.ccx_txpower",
                    liveupdate: true,
                    title: "Cisco CCX TxPower",
                    filterOnZero: true,
                    help: "Cisco access points may advertise their transmit power in a Cisco CCX IE tag.  Typically this is found on enterprise-level access points, where multiple APs service the same area.",
                    draw: function(opts) {
                        return opts['value'] + "dBm";
                    },
                },
                {
                    field: "dot11.advertisedssid.dot11r_mobility",
                    liveupdate: true,
                    title: "802.11r Mobility",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network.  Typically this is found on enterprise-level access points, on a network where multiple APs service the same area.",
                    draw: function(_opts) { return "Enabled"; }
                },
                {
                    field: "dot11.advertisedssid.dot11r_mobility_domain_id",
                    liveupdate: true,
                    title: "Mobility Domain",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network."
                },
                {
                    field: "dot11.advertisedssid.first_time",
                    liveupdate: true,
                    title: "First Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.advertisedssid.last_time",
                    liveupdate: true,
                    title: "Last Seen",
                    draw: kismet_ui.RenderTrimmedTime,
                },

                {
                    // Location is its own group
                    groupTitle: "Avg. Location",
                    id: "avg.dot11.advertisedssid.location",

                    // Group field
                    groupField: "dot11.advertisedssid.location",

                    liveupdate: true,

                    // Don't show location if we don't know it
                    filter: function(opts) {
                        return (kismet.ObjectByString(opts['base'], "dot11.advertisedssid.location/kismet.common.location.avg_loc/kismet.common.location.fix") >= 2);
                    },

                    fields: [
                        {
                            field: "kismet.common.location.avg_loc/kismet.common.location.geopoint",
                            title: "Location",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    if (opts['value'][1] == 0 || opts['value'][0] == 0)
                                        return "<i>Unknown</i>";

                                    return kismet.censorLocation(opts['value'][1]) + ", " + kismet.censorLocation(opts['value'][0]);
                                } catch (_error) {
                                    return "<i>Unknown</i>";
                                }
                            }
                        },
                        {
                            field: "kismet.common.location.avg_loc/kismet.common.location.alt",
                            title: "Altitude",
                            liveupdate: true,
                            filter: function(opts) {
                                return (kismet.ObjectByString(opts['base'], "kismet.common.location.avg_loc/kismet.common.location.fix") >= 3);
                            },
                            draw: function(opts) {
                                try {
                                    return kismet_ui.renderHeightDistance(opts['value']);
                                } catch (_error) {
                                    return "<i>Unknown</i>";
                                }
                            },
                        }
                    ],
                },


                {
                    field: "dot11.advertisedssid.maxrate",
                    liveupdate: true,
                    title: "Max. Rate",
                    draw: function(opts) {
                        return opts['value'] + ' MBit/s';
                    },
                    help: "The maximum basic transmission rate supported by this access point",
                },
                {
                    field: "dot11.advertisedssid.dot11d_country",
                    liveupdate: true,
                    title: "802.11d Country",
                    filterOnEmpty: true,
                    help: "The 802.11d standard required access points to identify their operating country code and signal levels.  This caused clients connecting to those access points to adopt the same regulatory requirements.  802.11d has been phased out and is not found on most modern access points but may still be seen on older hardware.",
                },
                {
                    field: "dot11.advertisedssid.wps_manuf",
                    liveupdate: true,
                    title: "WPS Manufacturer",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device manufacturer in the WPS advertisements.  WPS is not recommended due to security flaws."
                },
                {
                    field: "dot11.advertisedssid.wps_device_name",
                    liveupdate: true,
                    title: "WPS Device",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_model_name",
                    liveupdate: true,
                    title: "WPS Model",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the specific device model name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_model_number",
                    liveupdate: true,
                    title: "WPS Model #",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the specific model number in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_serial_number",
                    liveupdate: true,
                    title: "WPS Serial #",
                    filterOnEmpty: true,
                    draw: function(opts) { 
                        return kismet.censorString(opts['value']);
                    },
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device serial number in the WPS advertisements.  This information is not always valid or useful.  WPS is not recommended due to security flaws.",
                },

                {
                    field: "dot11.advertisedssid.ie_tag_content",
                    liveupdate: true,
                    filterOnEmpty: true,
                    id: "dot11_ssid_ietags",
                    title: '<b class="k_padding_title">IE tags</b>',
                    help: "IE tags in beacons define the network and the access point attributes; because dot11_keep_ietags is true, Kismet tracks these here.",
                },

                {
                    field: "dot11.advertisedssid.ie_tag_content",
                    liveupdate: true,
                    id: "advertised_ietags",
                    filterOnEmpty: true,
                    span: true,

                    render: function(_opts) {
                        return '<table id="tagdump" border="0" />';
                    },

                    draw: function(opts) {
                        $('table#tagdump', opts['container']).empty();
                        for (const ie in opts['value']) {
                            const tag = opts['value'][ie];

                            const pretty_tag = 
                                $('<tr>', {
                                    class: 'alternating'
                                })
                                .append(
                                    $('<td>', {
                                        width: "25%",
                                        id: "tagno"
                                    })
                                    .append(
                                        $('<div>')
                                        .html("<b>" + tag['dot11.ietag.number'] + "</b>")
                                    )
                                )
                                .append(
                                    $('<td>', {
                                        id: "hexdump"
                                    })
                                );

                            if (tag['dot11.ietag.oui'] != 0) {
                                let oui = ("000000" + tag['dot11.ietag.oui'].toString(16)).substr(-6).replace(/(..)/g, '$1:').slice(0, -1);

                                if (tag['dot11.ietag.oui_manuf'].length != 0)
                                    oui = oui + " (" + tag['dot11.ietag.oui_manuf'] + ")";

                                $('#tagno', pretty_tag).append(
                                    $('<div>')
                                    .text(oui)
                                );
                            }

                            if (tag['dot11.ietag.subtag'] >= 0) {
                                $('#tagno', pretty_tag).append(
                                    $('<div>')
                                    .text("Subtag " + tag['dot11.ietag.subtag'])
                                )
                            }

                            const hexdumps = pretty_hexdump(hexstr_to_bytes(tag['dot11.ietag.data']));

                            for (const i in hexdumps) {
                                $('#hexdump', pretty_tag).append(
                                    $('<div>')
                                    .append(
                                        $('<code>')
                                        .html(hexdumps[i])
                                    )
                                )
                            }

                            $('table#tagdump', opts['container']).append(pretty_tag);
                        }
                    },

                },

                ],
            },

            {
                field: "dot11_bssts_similar",
                id: "bssts_similar_header",
                help: "Wi-Fi access points advertise a high-precision timestamp in beacons.  Multiple devices with extremely similar timestamps are typically part of the same physical access point advertising multiple BSSIDs.",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['kismet.device.base.related_devices']['dot11_bssts_similar']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Shared Hardware (Uptime)</b>'
            },

            {
                field: "kismet.device.base.related_devices/dot11_bssts_similar",
                id: "bssts_similar",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['kismet.device.base.related_devices']['dot11_bssts_similar']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    const key = kismet.ObjectByString(opts['data'], opts['basekey']);
                    if (key != 0) {
                        return '<a id="' + key + '" class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Shared with ' + opts['data'] + '</a>';
                    }

                    return '<a class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Shared with ' + opts['data'] + '</a>';
                },
                draw: function(opts) {
                    $('.expander', opts['cell']).simpleexpand();

                    const key = kismet.ObjectByString(opts['data'], opts['basekey']);
                    const alink = $('a#' + key, opts['cell']);
                    $.get(local_uri_prefix + "devices/by-key/" + key + "/device.json")
                    .done(function(data) {
                        data = kismet.sanitizeObject(data);

                        let ssid = "";
                        let mac = "";

                        try {
                            mac = kismet.censorMAC(data['kismet.device.base.macaddr']);
                        } catch (_error) {
                            // skip
                        }

                        try {
                            ssid = kismet.CensorString(data['dot11.device']['dot11.device.last_beaconed_ssid_record']['dot11.advertisedssid.ssid']);
                        } catch (_error) {
                            // skip
                        }

                        if (ssid == "" || typeof(data) === 'undefined')
                            ssid = "<i>n/a</i>";

                        alink.html("Related to " + mac + " (" + ssid + ")");
                    });
                },

                fields: [
                {
                    field: "dot11.client.bssid_key",
                    title: "Access Point",
                    draw: function(opts) {
                        if (opts['key'] === '') {
                            return "<i>No records for access point</i>";
                        } else {
                            return '<a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + opts['base'] + '\')">View AP Details</a>';
                        }
                    }
                },
                ]
            },

            {
                field: "dot11_wps_uuid_identical",
                id: "wps_uuid_identical_header",
                help: "Some devices change MAC addresses but retain the WPS UUID unique identifier.  These devices have been detected using the same unique ID, which is extremely unlikely to randomly collide.",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['kismet.device.base.related_devices']['dot11_uuid_e']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Shared Hardware (WPS UUID)</b>'
            },

            {
                field: "kismet.device.base.related_devices/dot11_uuid_e",
                id: "wps_uuid_identical",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['kismet.device.base.related_devices']['dot11_uuid_e']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    const key = kismet.ObjectByString(opts['data'], opts['basekey']);
                    if (key != 0) {
                        return '<a id="' + key + '" class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Same WPS UUID as ' + opts['data'] + '</a>';
                    }

                    return '<a class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Same WPS UUID as ' + opts['data'] + '</a>';
                },
                draw: function(opts) {
                    $('.expander', opts['cell']).simpleexpand();

                    const key = kismet.ObjectByString(opts['data'], opts['basekey']);
                    const alink = $('a#' + key, opts['cell']);
                    $.get(local_uri_prefix + "devices/by-key/" + key + "/device.json")
                    .done(function(data) {
                        data = kismet.sanitizeObject(data);

                        let mac = "<i>unknown</i>";

                        try {
                            mac = kismet.censorMAC(data['kismet.device.base.macaddr']);
                        } catch (_error) {
                            // skip
                        }

                        alink.html("Related to " + mac);
                    });
                },

                fields: [
                {
                    field: "dot11.client.bssid_key",
                    title: "Access Point",
                    draw: function(opts) {
                        if (opts['key'] === '') {
                            return "<i>No records for access point</i>";
                        } else {
                            return '<a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + opts['base'] + '\')">View AP Details</a>';
                        }
                    }
                },
                ]
            },

            {
                field: "dot11.device/dot11.device.client_map",
                id: "client_behavior_header",
                help: "A Wi-Fi device may be a client of multiple networks over time, but can only be actively associated with a single access point at once.  Clients typically are able to roam between access points with the same advertised name (SSID).",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.client_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Wi-Fi Client Behavior</b>'
            },

            {
                field: "dot11.device/dot11.device.client_map",
                id: "client_behavior",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.client_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    const key = kismet.ObjectByString(opts['data'], opts['basekey'] + 'dot11.client.bssid_key');
                    if (key != 0) {
                        return '<a id="dot11_bssid_client_' + key + '" class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Client of ' + kismet.censorMAC(opts['index']) + '</a>';
                    }

                    return '<a class="expander collapsed" data-expander-target="#' + opts['containerid'] + '" href="#">Client of ' + kismet.censorMAC(opts['index']) + '</a>';
                },
                draw: function(opts) {
                    $('.expander', opts['cell']).simpleexpand();
                },

                fields: [
                {
                    field: "dot11.client.bssid_key",
                    title: "Access Point",
                    draw: function(opts) {
                        if (opts['key'] === '') {
                            return "<i>No records for access point</i>";
                        } else {
                            return '<a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + opts['value'] + '\')">View AP Details</a>';
                        }
                    }
                },
                {
                    field: "dot11.client.bssid",
                    title: "BSSID",
                    draw: function(opts) {
                        return kismet.censorMAC(opts['value']);
                    },
                },
                {
                    field: "dot11.client.bssid_key",
                    title: "Name",
                    draw: function(opts) {
                        $.get(local_uri_prefix + "devices/by-key/" + opts['value'] +
                                "/device.json/kismet.device.base.commonname")
                        .fail(function() {
                            opts['container'].html('<i>None</i>');
                        })
                        .done(function(clidata) {
                            clidata = kismet.sanitizeObject(clidata);

                            if (clidata === '' || clidata === '""') {
                                opts['container'].html('<i>None</i>');
                            } else {
                                opts['container'].html(kismet.censorMAC(clidata));
                            }
                        });
                    },
                },
                {
                    field: "dot11.client.bssid_key",
                    title: "Last SSID",
                    draw: function(opts) {
                        $.get(local_uri_prefix + "devices/by-key/" + opts['value'] +
                            'dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid')
                        .fail(function() {
                            opts['container'].html('<i>Unknown</i>');
                        })
                        .done(function(clidata) {
                            clidata = kismet.sanitizeObject(clidata);

                            if (clidata === '' || clidata === '""') {
                                opts['container'].html('<i>Unknown</i>');
                            } else {
                                opts['container'].html(clidata);
                            }
                        });
                    },
                },
                {
                    field: "dot11.client.first_time",
                    title: "First Connected",
                    draw: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.client.last_time",
                    title: "Last Connected",
                    draw: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.client.datasize",
                    title: "Data",
                    draw: kismet_ui.RenderHumanSize,
                },
                {
                    field: "dot11.client.datasize_retry",
                    title: "Retried Data",
                    draw: kismet_ui.RenderHumanSize,
                },
                {
                    // Set the field to be the host, and filter on it, but also
                    // define a group
                    field: "dot11.client.dhcp_host",
                    groupTitle: "DHCP",
                    id: "client_dhcp",
                    filterOnEmpty: true,
                    help: "If a DHCP data packet is seen, the requested hostname and the operating system / vendor of the DHCP client can be extracted.",
                    fields: [
                    {
                        field: "dot11.client.dhcp_host",
                        title: "DHCP Hostname",
                        empty: "<i>Unknown</i>"
                    },
                    {
                        field: "dot11.client.dhcp_vendor",
                        title: "DHCP Vendor",
                        empty: "<i>Unknown</i>"
                    }
                    ]
                },
                {
                    field: "dot11.client.eap_identity",
                    title: "EAP Identity",
                    filterOnEmpty: true,
                    help: "If an EAP handshake (part of joining a WPA-Enterprise protected network) is observed, Kismet may be able to extract the EAP identity of a client; this may represent the users login, or it may be empty or 'anonymouse' when joining a network with a phase-2 authentication, like WPA-PEAP",
                },
                {
                    field: "dot11.client.cdp_device",
                    groupTitle: "CDP",
                    id: "client_cdp",
                    filterOnEmpty: true,
                    help: "Clients bridged to a wired network may leak CDP (Cisco Discovery Protocol) packets, which can disclose information about the internal wired network.",
                    fields: [
                    {
                        field: "dot11.client.cdp_device",
                        title: "CDP Device"
                    },
                    {
                        field: "dot11.client.cdp_port",
                        title: "CDP Port",
                        empty: "<i>Unknown</i>"
                    }
                    ]
                },
                {
                    field: "dot11.client.ipdata",
                    groupTitle: "IP",
                    filter: function(opts) {
                        if (kismet.ObjectByString(opts['data'], opts['basekey'] + 'dot11.client.ipdata') == 0)
                            return false;

                        return (kismet.ObjectByString(opts['data'], opts['basekey'] + 'dot11.client.ipdata/kismet.common.ipdata.address') != 0);
                    },
                    help: "Kismet will attempt to derive the IP ranges in use on a network, either from observed traffic or from DHCP server responses.",
                    fields: [
                    {
                        field: "dot11.client.ipdata/kismet.common.ipdata.address",
                        title: "IP Address",
                    },
                    {
                        field: "dot11.client.ipdata/kismet.common.ipdata.netmask",
                        title: "Netmask",
                        zero: "<i>Unknown</i>"
                    },
                    {
                        field: "dot11.client.ipdata/kismet.common.ipdata.gateway",
                        title: "Gateway",
                        zero: "<i>Unknown</i>"
                    }
                    ]
                },
                ]
            },

            {
                // Filler title
                field: "dot11.device/dot11.device.associated_client_map",
                id: "client_list_header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.associated_client_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Associated Clients</b>',
                help: "An access point typically will have clients associated with it.  These client devices can either be wireless devices connected to the access point, or they can be bridged, wired devices on the network the access point is connected to.",
            },

            {
                field: "dot11.device/dot11.device.associated_client_map",
                id: "client_list",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.device']['dot11.device.associated_client_map']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    return '<a id="associated_client_expander_' + opts['base'] + '" class="expander collapsed" href="#" data-expander-target="#' + opts['containerid'] + '">Client ' + kismet.censorMAC(opts['index']) + '</a>';
                },
                draw: function(opts) {
                    $('.expander', opts['cell']).simpleexpand();
                },
                fields: [
                {
                    // Dummy field to get us a nested area since we don't have
                    // a real field in the client list since it's just a key-val
                    // not a nested object
                    field: "dummy",
                    // Span to fill it
                    span: true,
                    draw: function(opts) {
                        return `<div id="associated_client_content_${opts['base']}">`;
                    },
                },
                ]
            },
            ]
        }, storage);
    },

    finalize: function(data, _target, _options, _storage) {
        const apkey = data['kismet.device.base.macaddr'];

        let combokeys = {};

        try {
            Object.values(data['dot11.device']['dot11.device.associated_client_map']).forEach(device => combokeys[device] = 1);
        } catch (_err) {
            // skip
        }

        try {
            Object.values(data['dot11.device']['dot11.device.client_map']).forEach(device => combokeys[device['dot11.client.bssid_key']] = 1);
        } catch (_err) {
            // skip
        }

        const param = {
            devices: Object.keys(combokeys),
            fields: [
                'kismet.device.base.macaddr',
                'kismet.device.base.key',
                'kismet.device.base.type',
                'kismet.device.base.commonname',
                'kismet.device.base.manuf',
                'dot11.device/dot11.device.client_map',
                ['dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid', 'dot11.advertisedssid.lastssid'],
            ]
        };

        const postdata = `json=${encodeURIComponent(JSON.stringify(param))}`;

        $.post(`${local_uri_prefix}devices/multikey/as-object/devices.json`, postdata, "json")
        .done(function(rdevs) {
            const devs = kismet.sanitizeObject(rdevs);

            let client_devs = [];

            try {
                Object.values(data['dot11.device']['dot11.device.client_map']).forEach(device => client_devs.push(device['dot11.client.bssid_key']));
            } catch (_err) {
                // skip
            }

            client_devs.forEach(function(v) {
                if (!(v in devs))
                    return;

                const dev = devs[v];

                let lastssid = dev['dot11.advertisedssid.lastssid'];

                if (typeof(lastssid) !== 'string')
                    lastssid = `<i>None</i>`;
                else if (lastssid.replace(/\s/g, '').length == 0) 
                    lastssid = `<i>Cloaked / Empty (${lastssid.length} characters)</i>`;

                $(`a#dot11_bssid_client_${v}`).html(`Client of ${kismet.censorMAC(dev['kismet.device.base.macaddr'])} (${lastssid})`);
            });

            client_devs = [];

            try {
                client_devs = Object.values(data['dot11.device']['dot11.device.associated_client_map']);
            } catch (_err) {
                // skip
            }

            client_devs.forEach(function(v) {
                if (!(v in devs))
                    return;

                const dev = devs[v];

                $(`#associated_client_expander_${v}`).html(`${kismet.ExtractDeviceName(dev)}`);

                $(`#associated_client_content_${v}`).devicedata(dev, {
                    id: "clientData",
                    fields: [
                        {
                            field: "kismet.device.base.key",
                            title: "Client Info",
                            draw: function(opts) {
                                return '<a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + opts['data']['kismet.device.base.key'] + '\')">View Client Details</a>';
                            }
                        },
                        {
                            field: "kismet.device.base.commonname",
                            title: "Name",
                            filterOnEmpty: "true",
                            empty: "<i>None</i>",
                            draw: function(opts) {
                                return kismet.censorMAC(opts['value']);
                            },
                        },
                        {
                            field: "kismet.device.base.type",
                            title: "Type",
                            empty: "<i>Unknown</i>"

                        },
                        {
                            field: "kismet.device.base.manuf",
                            title: "Manufacturer",
                            empty: "<i>Unknown</i>"
                        },
                        {
                            field: "dot11.device.client_map[" + apkey + "]/dot11.client.first_time",
                            title: "First Connected",
                            draw: kismet_ui.RenderTrimmedTime,
                        },
                        {
                            field: "dot11.device.client_map[" + apkey + "]/dot11.client.last_time",
                            title: "Last Connected",
                            draw: kismet_ui.RenderTrimmedTime,
                        },
                        {
                            field: "dot11.device.client_map[" + apkey + "]/dot11.client.datasize",
                            title: "Data",
                            draw: kismet_ui.RenderHumanSize,
                        },
                        {
                            field: "dot11.device.client_map[" + apkey + "]/dot11.client.datasize_retry",
                            title: "Retried Data",
                            draw: kismet_ui.RenderHumanSize,
                        },
                    ]
                });
            });
        });
    },
});


var ssid_columnlist = new Map();
var ssid_columnlist_hidden = new Map();

var AddSsidColumn = (id, options) => {
    var coldef = {
        'kismetId': id,
        'title': options.title,
        'description': options.description,
        'field': null,
        'fields': null,
        'sortfield': null,
        'render': null,
        'auxdata': null,
        'mutate': null,
        'auxmdata': null,
        'sortable': false,
        'searchable': false,
        'width': null,
        'alignment': null,
    };

    if ('field' in options)
        coldef['field'] = options['field'];

    if ('fields' in options)
        coldef['fields'] = options['fields'];

    if ('sortfield' in options) {
        coldef['sortfield'] = options['sortfield'];
    } else {
        coldef['sortfield'] = coldef['field'];
    }

    if ('width' in options) {
        coldef['width'] = options['width'];
    }

    if ('alignment' in options) {
        coldef['alignment'] = options['alignment'];
    }

    if ('render' in options) {
        coldef['render'] = options['render'];
    } else {
        coldef['render'] = (data, rowdata, cell, auxdata) => {
            return data;
        }
    }

    if ('auxdata' in options)
        coldef['auxdata'] = options['auxdata'];

    if ('sortable' in options)
        coldef['sortable'] = options['sortable'];

    ssid_columnlist.set(id, coldef);
}

var AddHiddenSsidColumn = (coldef) => {
    var f;

    if (typeof(coldef['field']) === 'string') {
        var fs = coldef['field'].split("/");
        f = fs[fs.length - 1];
    } else if (Array.isArray(coldef['field'])) {
        f = coldef['field'][1];
    }

    ssid_columnlist_hidden.set(f, coldef);
}

function GenerateSsidFieldList() {
    var retcols = new Map();

    for (const [k, v] of ssid_columnlist_hidden) {
        if (typeof(v['field']) === 'string') {
            retcols.set(v, v['field']);
        } else if (Array.isArray(v['field'])) {
            retcols.set(v['field'][1], v);
        }
    };

    for (const [k, c] of ssid_columnlist) {
        if (c['field'] != null) {
            if (typeof(c['field']) === 'string') {
                retcols.set(c['field'], c['field']);
            } else if (Array.isArray(c['field'])) {
                retcols.set(c['field'][1], c['field']);
            }
        }

        if (c['fields'] != null) {
            for (const cf of c['fields']) {
                if (typeof(cf) === 'string') {
                    retcols.set(cf, cf);
                } else if (Array.isArray(cf)) {
                    retcols.set(cf[1], cf);
                }

            }
        }
    }

    var ret = [];

    for (const [k, v] of retcols) {
        ret.push(v);
    };

    return ret;
}

function GenerateSsidTabulatorColumn(c) {
    var col = {
        'field': c['kismetId'],
        'title': c['title'],
        'formatter': (cell, params, onrender) => {
            try {
                return c['render'](cell.getValue(), cell.getRow().getData(), cell, onrender, c['auxdata']);
            } catch (e) {
                return cell.getValue();
            }
        },
        'headerSort': c['sortable'],
        /* Don't allow hiding alert columns
        'headerContextMenu':  [ {
            'label': "Hide Column",
            'action': function(e, column) {
                alerttable_prefs['columns'] = alerttable_prefs['columns'].filter(c => {
                    return c !== column.getField();
                });
                SaveAlertTablePrefs();

                alertTabulator.deleteColumn(column.getField())
                .then(col => {
                    ScheduleAlertSummary();
                });
            }
        }, ],
        */
    };

    var colsettings = {};
    if (c['kismetId'] in ssidtable_prefs['colsettings']) {
        colsettings = ssidtable_prefs['colsettings'][c['kismetId']];
    }

    if ('width' in colsettings) {
        col['width'] = colsettings['width'];
    } else if (c['width'] != null) {
        col['width'] = c['width'];
    }

    if (c['alignment'] != null)
        col['hozAlign'] = c['alignment'];

    return col;
}

/* Generate the columns for the devicelist tabulator format */
function GenerateSsidColumns() {
    var columns = [];

    var columnlist = [];
    if (ssidtable_prefs['columns'].length == 0) {
        for (const [k, v] of ssid_columnlist) {
            columnlist.push(k);
        }
    } else {
        columnlist = ssidtable_prefs['columns'];
    }

    for (const k of columnlist) {
        if (!ssid_columnlist.has(k)) {
            continue;
        }

        const c = ssid_columnlist.get(k);

        columns.push(GenerateSsidTabulatorColumn(c));
    }

    return columns;
}

var ssidTid = -1;

var ssidtableHolder = null;
var ssidtableElement = null;
var ssidTabulator = null;
var ssidTablePage = 0;
var ssidTableTotal = 0;
var ssidTableTotalPages = 0;
var ssidTableRefreshBlock = false;
var ssidtable_prefs = {};
var ssidTableRefreshing = false;

var CreateSsidTable = function(element) {
    element.ready(function() { 
        InitializeSsidTable(element);
    });
}

function ScheduleSsidSummary() {
    if (ssidTid != -1)
        clearTimeout(ssidTid);

    ssidTid = setTimeout(ScheduleSsidSummary, 1000);

    try {
        if (!ssidTableRefreshing && ssidTabulator != null && kismet_ui.window_visible && ssidtableElement.is(":visible")) {
            ssidTableRefreshing = true;

            var pageSize = ssidTabulator.getPageSize();
            if (pageSize == 0) {
                throw new Error("Page size 0");
            }

            if (ssidTableRefreshBlock) {
                throw new Error("refresh blocked");
            }

            var colparams = JSON.stringify({'fields': GenerateSsidFieldList()});

            var postdata = {
                "json": colparams,
                "page": ssidTablePage,
                "length": pageSize,
            }

            if (ssid_columnlist.has(ssidtable_prefs['sort']['column'])) {
                var f = ssid_columnlist.get(ssidtable_prefs['sort']['column']);
                if (f['sortfield'] != null) {
                    if (typeof(f['sortfield']) === 'string') {
                        postdata["sort"] = f['sortfield'];
                    } else if (Array.isArray(f['sortfield'])) {
                        postdata["sort"] = f['sortfield'][0];
                    }
                } else {
                    if (typeof(f['field']) === 'string') {
                        postdata["sort"] = f['sortfield'];
                    } else if (Array.isArray(f['field'])) {
                        postdata["sort"] = f['field'][0];
                    }
                }

                postdata["sort_dir"] = ssidtable_prefs['sort']['dir'];
            }

            var searchterm = kismet.getStorage('kismet.ui.ssidview.search', "");
            if (searchterm.length > 0) {
                postdata["search"] = searchterm;
            }

            $.post(local_uri_prefix + `phy/phy80211/ssids/views/ssids.json`, postdata, 
                function(data) { 
                    ssidTableTotal = data["last_row"];
                    ssidTableTotalPages = data["last_page"];

                    // Sanitize the data
                    if (!'data' in data) {
                        throw new Error("Missing data in response");
                    }
                    var rdata = kismet.sanitizeObject(data["data"]);

                    // Permute the data based on the field list and assign the fields to the ID names
                    var procdata = [];

                    for (const d of rdata) {
                        var md = {};

                        md['original_data'] = d;

                        md['ssid_key'] = d['dot11.ssidgroup.hash'];

                        for (const [k, c] of ssid_columnlist) {
                            if (typeof(c['field']) === 'string') {
                                var fs = c['field'].split("/");
                                var fn = fs[fs.length - 1];
                                if (fn in d)
                                    md[c['kismetId']] = d[fn];
                            } else if (Array.isArray(c['field'])) {
                                if (c['field'][1] in d)
                                    md[c['kismetId']] = d[c['field'][1]];
                            }

                            if (c['fields'] != null) {
                                for (const cf of c['fields']) {
                                    if (typeof(cf) === 'string') {
                                        var fs = cf.split("/");
                                        var fn = fs[fs.length - 1];
                                        if (fn in d)
                                            md[fn] = d[fn];
                                    } else if (Array.isArray(cf)) {
                                        if (fn[1] in d)
                                            md[fn[1]] = d[fn[1]]
                                    }

                                }
                            }

                        }

                        procdata.push(md);
                    }

                    ssidTabulator.replaceData(procdata);

                    var paginator = $('#ssid-table .tabulator-paginator');
                    paginator.empty();

                    var firstpage = 
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'First',
                        }).html("First")
                    .on('click', function() {
                        ssidTablePage = 0;
                        return ScheduleSsidSummary();
                    });
                    if (ssidTablePage == 0) {
                        firstpage.attr('disabled', 'disabled');
                    }
                    paginator.append(firstpage);

                    var prevpage = 
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'Prev',
                        }).html("Prev")
                    .on('click', function() {
                        ssidTablePage = ssidTablePage - 1;
                        return ScheduleSsidSummary();
                    });
                    if (ssidTablePage < 1) {
                        prevpage.attr('disabled', 'disabled');
                    }
                    paginator.append(prevpage);

                    var gen_closure = (pg, pgn) => {
                        pg.on('click', () => {
                            ssidTablePage = pgn;
                            return ScheduleSsidSummary();
                        });
                    }

                    var fp = ssidTablePage - 1;
                    if (fp <= 1)
                        fp = 1;
                    var lp = fp + 4;
                    if (lp > ssidTableTotalPages)
                        lp = ssidTableTotalPages;
                    for (let p = fp; p <= lp; p++) {
                        var ppage = 
                            $('<button>', {
                                'class': 'tabulator-page',
                                'type': 'button',
                                'role': 'button',
                                'aria-label': `${p}`,
                            }).html(`${p}`);
                        gen_closure(ppage, p - 1);
                        if (ssidTablePage == p - 1) {
                            ppage.attr('disabled', 'disabled');
                        }
                        paginator.append(ppage);
                    }

                    var nextpage = 
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'Next',
                        }).html("Next")
                    .on('click', function() {
                        ssidTablePage = ssidTablePage + 1;
                        return ScheduleSsidSummary();
                    });
                    if (ssidTablePage >= ssidTableTotalPages - 1) {
                        nextpage.attr('disabled', 'disabled');
                    }
                    paginator.append(nextpage);

                    var lastpage = 
                        $('<button>', {
                            'class': 'tabulator-page',
                            'type': 'button',
                            'role': 'button',
                            'aria-label': 'Last',
                        }).html("Last")
                    .on('click', function() {
                        ssidTablePage = ssidTableTotalPages - 1;
                        return ScheduleSsidSummary();
                    });
                    if (ssidTablePage >= ssidTableTotalPages - 1) {
                        lastpage.attr('disabled', 'disabled');
                    }
                    paginator.append(lastpage);
                },
                "json")
                .always(() => {
                    ssidTableRefreshing = false;
                });
        }

    } catch (error) {
        ssidTableRefreshing = false;
    }
    
    return;
}

function CancelSsidSummary() {
    clearTimeout(ssidTid);
}

function LoadSsidTablePrefs() {
    ssidtable_prefs = kismet.getStorage('kismet.ui.ssidtable.prefs', {
        "columns": [],
        "colsettings": {},
        "sort": {
            "column": "",
            "dir": "asc",
        },
    });

    ssidtable_prefs = $.extend({
        "columns": [],
        "colsettings": {},
        "sort": {
            "column": "",
            "dir": "asc",
        }, 
    }, ssidtable_prefs);
}

function SaveSsidTablePrefs() {
    kismet.putStorage('kismet.ui.ssidtable.prefs', ssidtable_prefs);
}

var InitializeSsidTable = function(element) {
    LoadSsidTablePrefs();

    ssidtableHolder = element;

    var searchterm = kismet.getStorage('kismet.ui.ssidview.search', "");

    if ($('#center-ssid-extras').length == 0) {
        var ssidviewmenu = $(`<input class="ssid_search" type="search" id="ssid_search" placeholder="Filter..." value="${searchterm}"></input>`);
        $('#centerpane-tabs').append($('<div id="center-ssid-extras" style="position: absolute; right: 10px; top: 5px; height: 30px; display: flex;">').append(ssidviewmenu));

        $('#ssid_search').on('keydown', (evt) => {
            var code = evt.charCode || evt.keyCode;
            if (code == 27) {
                $('#ssid_search').val('');
            }
        });

        $('#ssid_search').on('keyup', $.debounce(300, () => {
            var searchterm = $('#ssid_search').val();
            kismet.putStorage('kismet.ui.ssidview.search', searchterm);
            ScheduleSsidSummary();
        }));
    }

    if ($('#ssid-table', element).length == 0) { 
        ssidtableElement =
            $('<div>', {
                id: 'ssid-table',
                'cell-spacing': 0,
                width: '100%',
                height: '100%',
            });

        element.append(ssidtableElement);
    }

    ssidTabulator = new Tabulator('#ssid-table', {
        // This doesn't work well at all on small screens
        // layout: 'fitColumns',

        movableColumns: true,
        columns: GenerateSsidColumns(),

        // No loading animation/text
        dataLoader: false,

        // Server-side filtering and sorting
        sortMode: "remote",
        filterMode: "remote",

        // Server-side pagination
        pagination: true,
        paginationMode: "remote",

        // Override the pagination system to use our local counters, more occurs in
        // the update timer loop to replace pagination
        paginationCounter: function(pageSize, currentRow, currentPage, totalRows, totalPages) {
            if (ssidTableTotal == 0) {
                return "Loading..."
            }

            var frow = pageSize * ssidTablePage;
            if (frow == 0)
                frow = 1;

            var lrow = frow + pageSize;
            if (lrow > ssidTableTotal) 
                lrow = ssidTableTotal;

            return `Showing rows ${frow} - ${lrow} of ${ssidTableTotal}`;
        },

        /*
        rowFormatter: function(row) {
            for (const ri of DeviceRowHighlights) {
                if (!ri['enable'])
                    continue;

                try {
                    if (ri['selector'](row.getData()['original_data'])) {
                        row.getElement().style.backgroundColor = ri['color'];
                    }
                } catch (e) {
                    ;
                }
            }
        },
        */

        initialSort: [{
            "column": ssidtable_prefs["sort"]["column"],
            "dir": ssidtable_prefs["sort"]["dir"],
        }],

    });

    // Get sort events to hijack for the custom query
    ssidTabulator.on("dataSorted", (sorters) => {
        if (sorters.length == 0)
            return;

        var mut = false;
        if (sorters[0].field != ssidtable_prefs['sort']['column']) {
            ssidtable_prefs['sort']['column'] = sorters[0].field;
            mut = true;
        }

        if (sorters[0].dir != ssidtable_prefs['sort']['dir']) {
            ssidtable_prefs['sort']['dir'] = sorters[0].dir;
            mut = true;
        }

        if (mut) {
            SaveSsidTablePrefs();
            ScheduleSsidSummary();
        }
    });

    // Disable refresh while a menu is open
    ssidTabulator.on("menuOpened", function(component){
        ssidTableRefreshBlock = true;
    });

    // Reenable refresh when menu is closed
    ssidTabulator.on("menuClosed", function(component){
        ssidTableRefreshBlock = false;
    });


    // Handle row clicks
    ssidTabulator.on("rowClick", (e, row) => {
        SsidDetailWindow(row.getData()['ssid_key']);
    });

    ssidTabulator.on("columnMoved", function(column, columns){
        var cols = [];

        for (const c of columns) {
            cols.push(c.getField());
        }

        ssidtable_prefs['columns'] = cols;
       
        SaveSsidTablePrefs();

    });

    ssidTabulator.on("columnResized", function(column){
        if (column.getField() in ssidtable_prefs['colsettings']) {
            ssidtable_prefs['colsettings'][column.getField()]['width'] = column.getWidth();
        } else {
            ssidtable_prefs['colsettings'][column.getField()] = {
                'width': column.getWidth(),
            }
        }

        SaveSsidTablePrefs();
    });

    ssidTabulator.on("tableBuilt", function() {
        ScheduleSsidSummary();
    });
}

kismet_ui_tabpane.AddTab({
    id: 'dot11_ssids',
    tabTitle: 'SSIDs',
    createCallback: function(div) {
        // InitializeSsidTable(div);
        ssidtableHolder = div;
    },
    activateCallback: function() {
        ssidtableHolder.ready(() => {
            InitializeSsidTable(ssidtableHolder);
            $('#center-ssid-extras').show();
        });
    },
    deactivateCallback: function() {
        $('#center-ssid-extras').hide();
    },
    priority: -1000,
}, 'center');

AddSsidColumn('col_ssid', {
    'title': 'SSID',
    'description': 'SSID',
    'field': 'dot11.ssidgroup.ssid',
    'sortable': true,
    'searchable': true,
    'render': (data, row, cell, onrender, aux) => {
        if (data.length == 0) {
            return "<i>Cloaked or Empty SSID</i>";
        } else if (/^ +$/.test(data)) {
            return "<i>Blank SSID</i>";
        }

        return kismet.censorString(data);
    },
});

AddSsidColumn('col_ssid_len', {
    'title': 'Length',
    'description': 'SSID name length in bytes',
    'field': 'dot11.ssidgroup.ssid_len',
    'sortable': true,
    'alignment': 'right',    
});

AddSsidColumn('last_seen', {
    'title': 'Last Seen',
    'description': 'Last seen time',
    'field': 'dot11.ssidgroup.last_time',
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        return (new Date(data * 1000).toString()).substring(4, 25);
    },
});

AddSsidColumn('first_seen', {
    'title': 'First Seen',
    'description': 'First seen time',
    'field': 'dot11.ssidgroup.first_time',
    'sortable': true,
    'render': (data, row, cell, onrender, aux) => {
        return (new Date(data * 1000).toString()).substring(4, 25);
    },
});

AddSsidColumn('crypt', {
    'title': 'Encryption',
    'description': 'Advertised encryption settings',
    'field': 'dot11.ssidgroup.crypt_string',
    'seachable': true,
    'sortable': true,
});

AddSsidColumn('ssid_probing', {
    'title': '# Probing',
    'description': 'Number of devices observed probing for this SSID',
    'field': 'dot11.ssidgroup.probing_devices_len',
    'sortable': true,
    'alignment': 'right',    
});

AddSsidColumn('ssid_responding', {
    'title': '# Responding',
    'description': 'Number of devices observed responding for this SSID',
    'field': 'dot11.ssidgroup.responding_devices_len',
    'sortable': true,
    'alignment': 'right',    
});

AddSsidColumn('ssid_advertising', {
    'title': '# Advertising',
    'description': 'Number of devices observed advertising for this SSID',
    'field': 'dot11.ssidgroup.advertising_devices_len',
    'sortable': true,
    'alignment': 'right',    
});

AddHiddenSsidColumn({'field': 'dot11.ssidgroup.hash'});


// SSID panel
var SsidDetails = new Array();

const AddSsidDetail = function(id, title, pos, options) {
    kismet_ui.AddDetail(SsidDetails, id, title, pos, options);
}

const SsidDetailWindow = (key) => {
    kismet_ui.DetailWindow(key, "SSID Details", 
        {
            storage: {},
        },

        function(panel, options) {
            var content = panel.content;

            panel.active = true;

            window['storage_ssid_' + key] = {};
            window['storage_ssid_' + key]['foobar'] = 'bar';

            panel.updater = function() {
                if (kismet_ui.window_visible) {
                    $.get(local_uri_prefix + "phy/phy80211/ssids/by-hash/" + key + "/ssid.json")
                        .done(function(fulldata) {
                            fulldata = kismet.sanitizeObject(fulldata);

                            $('.loadoops', panel.content).hide();

                            panel.headerTitle("SSID: " + kismet.censorString(fulldata['dot11.ssidgroup.ssid']));

                            var accordion = $('div#accordion', content);

                            if (accordion.length == 0) {
                                accordion = $('<div />', {
                                    id: 'accordion'
                                });

                                content.append(accordion);
                            }

                            var detailslist = SsidDetails;

                            for (var dii in detailslist) {
                                var di = detailslist[dii];

                                // Do we skip?
                                if ('filter' in di.options &&
                                    typeof(di.options.filter) === 'function') {
                                    if (di.options.filter(fulldata) == false) {
                                        continue;
                                    }
                                }

                                var vheader = $('h3#header_' + di.id, accordion);

                                if (vheader.length == 0) {
                                    vheader = $('<h3>', {
                                        id: "header_" + di.id,
                                    })
                                        .html(di.title);

                                    accordion.append(vheader);
                                }

                                var vcontent = $('div#' + di.id, accordion);

                                if (vcontent.length == 0) {
                                    vcontent = $('<div>', {
                                        id: di.id,
                                    });
                                    accordion.append(vcontent);
                                }

                                // Do we have pre-rendered content?
                                if ('render' in di.options &&
                                    typeof(di.options.render) === 'function') {
                                    vcontent.html(di.options.render(fulldata));
                                }

                                if ('draw' in di.options && typeof(di.options.draw) === 'function') {
                                    di.options.draw(fulldata, vcontent, options, 'storage_ssid_' + key);
                                }

                                if ('finalize' in di.options &&
                                    typeof(di.options.finalize) === 'function') {
                                    di.options.finalize(fulldata, vcontent, options, 'storage_ssid_' + key);
                                }
                            }
                            accordion.accordion({ heightStyle: 'fill' });
                        })
                        .fail(function(jqxhr, texterror) {
                            content.html("<div class=\"loadoops\" style=\"padding: 10px;\"><h1>Oops!</h1><p>An error occurred loading ssid details for key <code>" + key + 
                                "</code>: HTTP code <code>" + jqxhr.status + "</code>, " + texterror + "</div>");
                        })
                        .always(function() {
                            panel.timerid = setTimeout(function() { panel.updater(); }, 1000);
                        })
                } else {
                    panel.timerid = setTimeout(function() { panel.updater(); }, 1000);
                }

            };

            panel.updater();
        },

        function(panel, options) {
            clearTimeout(panel.timerid);
            panel.active = false;
            window['storage_ssid_' + key] = {};
        });
};

/* Custom device details for dot11 data */
AddSsidDetail("ssid", "Wi-Fi (802.11) SSIDs", 0, {
    draw: function(data, target, options, storage) {
        target.devicedata(data, {
            "id": "ssiddetails",
            "fields": [
            {
                field: 'dot11.ssidgroup.ssid',
                title: "SSID",
                liveupdate: true,
                draw: function(opts) {
                    if (typeof(opts['value']) === 'undefined')
                        return '<i>None</i>';
                    if (opts['value'].replace(/\s/g, '').length == 0) 
                        return '<i>Cloaked / Empty (' + opts['value'].length + ' spaces)</i>';

                    return `${kismet.censorString(opts['value'])} <i>(${data['dot11.ssidgroup.ssid_len']} characters)</i>`;
                },
                help: "SSID advertised or probed by one or more devices",
            },
            {
                field: "dot11.ssidgroup.first_time",
                title: "First Seen",
                liveupdate: true,
                draw: kismet_ui.RenderTrimmedTime,
            },
            {
                field: "dot11.ssidgroup.last_time",
                liveupdate: true,
                title: "Last Seen",
                draw: kismet_ui.RenderTrimmedTime,
            },
            {
                field: "dot11.ssidgroup.crypt_set",
                liveupdate: true,
                title: "Encryption",
                draw: function(opts) {
                    return CryptToHumanReadable(opts['value']);
                },
                help: "Encryption at the Wi-Fi layer (open, WEP, and WPA) is defined by the beacon sent by the access point advertising the network.  Layer 3 encryption (such as VPNs) is added later and is not advertised as part of the network itself.",
            },



            {
                field: "advertising_meta",
                id: "advertising header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.ssidgroup.advertising_devices']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Advertising APs</b>',
                help: "Advertising access points have sent a beacon packet with this SSID.",
            },

            {
                field: "dot11.ssidgroup.advertising_devices",
                id: "advertising_list",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.ssidgroup.advertising_devices']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    return '<a id="ssid_expander_advertising_' + opts['base'] + '" class="ssid_expander_advertising expander collapsed" href="#" data-expander-target="#' + opts['containerid'] + '">Access point ' + opts['index'] + '</a>';
                },
                draw: function(opts) {
                    var tb = $('.expander', opts['cell']).simpleexpand();
                },
                fields: [
                {
                    // Dummy field to get us a nested area since we don't have
                    // a real field in the client list since it's just a key-val
                    // not a nested object
                    field: "dummy",
                    // Span to fill it
                    span: true,
                    draw: function(opts) {
                        return `<div class="ssid_content_advertising" id="ssid_content_advertising_${opts['base']}">`;
                    },
                },
                ]
            },



            {
                field: "responding_meta",
                id: "responding header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.ssidgroup.responding_devices']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Responding APs</b>',
                help: "Responding access points have sent a probe response with this SSID.",
            },

            {
                field: "dot11.ssidgroup.responding_devices",
                id: "responding_list",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.ssidgroup.responding_devices']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    return '<a id="ssid_expander_responding_' + opts['base'] + '" class="ssid_expander_responding expander collapsed" href="#" data-expander-target="#' + opts['containerid'] + '">Access point ' + opts['index'] + '</a>';
                },
                draw: function(opts) {
                    var tb = $('.expander', opts['cell']).simpleexpand();
                },
                fields: [
                {
                    // Dummy field to get us a nested area since we don't have
                    // a real field in the client list since it's just a key-val
                    // not a nested object
                    field: "dummy",
                    // Span to fill it
                    span: true,
                    draw: function(opts) {
                        return `<div class="ssid_content_responding" id="ssid_content_responding_${opts['base']}">`;
                    },
                },
                ]
            },



            {
                field: "probing_meta",
                id: "probing header",
                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.ssidgroup.probing_devices']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },
                title: '<b class="k_padding_title">Probing devices</b>',
                help: "Probing devices have sent a probe request or association request with this SSID",
            },

            {
                field: "dot11.ssidgroup.probing_devices",
                id: "probing_list",

                filter: function(opts) {
                    try {
                        return (Object.keys(opts['data']['dot11.ssidgroup.probing_devices']).length >= 1);
                    } catch (_error) {
                        return false;
                    }
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    return '<a id="ssid_expander_probing_' + opts['base'] + '" class="ssid_expander_probing expander collapsed" href="#" data-expander-target="#' + opts['containerid'] + '">Wi-Fi Device ' + opts['index'] + '</a>';
                },
                draw: function(opts) {
                    var tb = $('.expander', opts['cell']).simpleexpand();
                },
                fields: [
                {
                    // Dummy field to get us a nested area since we don't have
                    // a real field in the client list since it's just a key-val
                    // not a nested object
                    field: "dummy",
                    // Span to fill it
                    span: true,
                    draw: function(opts) {
                        return `<div class="ssid_content_probing" id="ssid_content_probing_${opts['base']}">`;
                    },
                },
                ]
            },

            ],
        }, storage);
    }, 

    finalize: function(data, target, options, storage) {
        var combokeys = {};

        data['dot11.ssidgroup.advertising_devices'].forEach(device => combokeys[device] = 1);
        data['dot11.ssidgroup.probing_devices'].forEach(device => combokeys[device] = 1);
        data['dot11.ssidgroup.responding_devices'].forEach(device => combokeys[device] = 1);

        var param = {
            devices: Object.keys(combokeys),
            fields: [
                'kismet.device.base.macaddr',
                'kismet.device.base.key',
                'kismet.device.base.type',
                'kismet.device.base.commonname',
                'kismet.device.base.manuf',
                'dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid',
                'dot11.device/dot11.device.advertised_ssid_map',
                'dot11.device/dot11.device.responded_ssid_map',
            ]
        };

        var postdata = `json=${encodeURIComponent(JSON.stringify(param))}`;

        $.post(`${local_uri_prefix}devices/multikey/as-object/devices.json`, postdata, "json")
        .done(function(aggcli) {
            aggcli = kismet.sanitizeObject(aggcli);

            data['dot11.ssidgroup.advertising_devices'].forEach(function(v) {
                if (!v in aggcli)
                    return;

                var dev = aggcli[v];

                var devssid;

                try {
                    dev['dot11.device.advertised_ssid_map'].forEach(function (s) {
                        if (s['dot11.advertisedssid.ssid_hash'] == data['dot11.ssidgroup.hash']) {
                            devssid = s;
                        }
                    });
                } catch (e) {
                    ;
                }

                var crypttxt;
                try {
                    crypttxt = CryptToHumanReadable(devssid['dot11.advertisedssid.crypt_set']);
                } catch (e) {
                    ;
                }

                var titlehtml = `${kismet.ExtractDeviceName(dev)} - ${dev['kismet.device.base.macaddr']}`;

                if (crypttxt != null)
                    titlehtml = `${titlehtml} - ${crypttxt}`;

                titlehtml = kismet.censorMAC(titlehtml);

                $(`#ssid_expander_advertising_${v}`).html(titlehtml);

                $(`#ssid_content_advertising_${v}`).devicedata(dev, {
                    id: "ssid_adv_data",
                    fields: [
                        {
                            field: 'kismet.device.base.key',
                            title: "Advertising Device",
                            draw: function(opts) {
                                return `<a href="#" onclick="kismet_ui.DeviceDetailWindow('${opts['data']['kismet.device.base.key']}')">View Device Details</a>`;
                            }
                        }, 
                        {
                            field: "kismet.device.base.macaddr",
                            title: "MAC",
                            draw: function(opts) {
                                return kismet.censorMAC(`${opts['data']['kismet.device.base.macaddr']} (${opts['data']['kismet.device.base.manuf']})`);
                            }
                        },
                        {
                            field: 'kismet.device.base.commonname',
                            title: "Name",
                            liveupdate: true,
                            empty: "<i>None</i>",
                            draw: function(opts) {
                                return kismet.censorString(opts['value']);
                            },
                        },
                        {
                            field: 'kismet.device.base.type',
                            title: "Type",
                            liveupdate: true,
                            empty: "<i>Unknown</i>",
                        },
                        {
                            field: 'meta_advertised_crypto',
                            title: "Advertised encryption",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    return CryptToHumanReadable(devssid['dot11.advertisedssid.crypt_set']);
                                } catch (e) {
                                    return '<i>Unknown</i>';
                                }
                            },
                            help: "The encryption should be the same across all APs advertising the same SSID in the same area, howevever each AP advertises this information independently.",
                        },
                        {
                            field: 'meta_advertised_firsttime',
                            title: "First advertised",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    return kismet_ui.RenderTrimmedTime({value: devssid['dot11.advertisedssid.first_time']});
                                } catch (e) {
                                    return '<i>Unknown</i>';
                                }
                            }
                        },
                        {
                            field: 'meta_advertised_lasttime',
                            title: "Last advertised",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    return kismet_ui.RenderTrimmedTime({value: devssid['dot11.advertisedssid.last_time']});
                                } catch (e) {
                                    return '<i>Unknown</i>';
                                }
                            }
                        },
                        {
                            field: 'dot11.advertisedssid.ssid',
                            title: "Last advertised SSID",
                            liveupdate: true,
                            draw: function(opts) {
                                if (typeof(opts['value']) === 'undefined')
                                    return '<i>None</i>';
                                if (opts['value'].replace(/\s/g, '').length == 0) 
                                    return '<i>Cloaked / Empty (' + opts['value'].length + ' spaces)</i>';

                                return kismet.censorString(opts['value']);
                            },
                        },
                    ]
                });
            });


            data['dot11.ssidgroup.responding_devices'].forEach(function(v) {
                if (!v in aggcli)
                    return;

                var dev = aggcli[v];

                var devssid;

                try {
                    dev['dot11.device.responded_ssid_map'].forEach(function (s) {
                        if (s['dot11.advertisedssid.ssid_hash'] == data['dot11.ssidgroup.hash']) {
                            devssid = s;
                        }
                    });
                } catch (e) {
                    ;
                }

                var crypttxt;
                try {
                    crypttxt = CryptToHumanReadable(devssid['dot11.advertisedssid.crypt_set']);
                } catch (e) {
                    ;
                }

                var titlehtml = `${dev['kismet.device.base.commonname']} - ${dev['kismet.device.base.macaddr']}`;

                if (crypttxt != null)
                    titlehtml = `${titlehtml} - ${crypttxt}`;

                titlehtml = kismet.censorMAC(titlehtml);

                $(`#ssid_expander_responding_${v}`).html(titlehtml);

                $(`#ssid_content_responding_${v}`).devicedata(dev, {
                    id: "ssid_adv_data",
                    fields: [
                        {
                            field: 'kismet.device.base.key',
                            title: "Responding Device",
                            draw: function(opts) {
                                return `<a href="#" onclick="kismet_ui.DeviceDetailWindow('${opts['data']['kismet.device.base.key']}')">View Device Details</a>`;
                            }
                        }, 
                        {
                            field: "kismet.device.base.macaddr",
                            title: "MAC",
                            draw: function(opts) {
                                return kismet.censorMAC(`${opts['data']['kismet.device.base.macaddr']} (${opts['data']['kismet.device.base.manuf']})`);
                            }
                        },
                        {
                            liveupdate: true,
                            field: 'kismet.device.base.commonname',
                            title: "Name",
                            empty: "<i>None</i>",
                            draw: function(opts) {
                                return kismet.censorMAC(opts['value']);
                            },
                        },
                        {
                            liveupdate: true,
                            field: 'kismet.device.base.type',
                            title: "Type",
                            empty: "<i>Unknown</i>",
                        },
                        {
                            field: 'meta_advertised_crypto',
                            title: "Advertised encryption",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    return CryptToHumanReadable(devssid['dot11.advertisedssid.crypt_set']);
                                } catch (e) {
                                    return '<i>Unknown</i>';
                                }
                            },
                            help: "The encryption should be the same across all APs advertising the same SSID in the same area, howevever each AP advertises this information independently.",
                        },
                        {
                            field: 'meta_advertised_firsttime',
                            title: "First responded",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    return kismet_ui.RenderTrimmedTime({value: devssid['dot11.advertisedssid.first_time']});
                                } catch (e) {
                                    return '<i>Unknown</i>';
                                }
                            }
                        },
                        {
                            field: 'meta_advertised_lasttime',
                            title: "Last responded",
                            liveupdate: true,
                            draw: function(opts) {
                                try {
                                    return kismet_ui.RenderTrimmedTime({value: devssid['dot11.advertisedssid.last_time']});
                                } catch (e) {
                                    return '<i>Unknown</i>';
                                }
                            }
                        },
                        {
                            liveupdate: true,
                            field: 'dot11.advertisedssid.ssid',
                            title: "Last advertised SSID",
                            draw: function(opts) {
                                if (typeof(opts['value']) === 'undefined')
                                    return '<i>None</i>';
                                if (opts['value'].replace(/\s/g, '').length == 0) 
                                    return '<i>Cloaked / Empty (' + opts['value'].length + ' spaces)</i>';

                                return opts['value'];
                            },
                        },
                    ]
                });
            });


            data['dot11.ssidgroup.probing_devices'].forEach(function(v) {
                if (!v in aggcli)
                    return;

                var dev = aggcli[v];

                $(`#ssid_expander_probing_${v}`).html(kismet.censorMAC(`${dev['kismet.device.base.commonname']} - ${dev['kismet.device.base.macaddr']}`));

                $(`#ssid_content_probing_${v}`).devicedata(dev, {
                    id: "ssid_adv_data",
                    fields: [
                        {
                            field: 'kismet.device.base.key',
                            title: "Probing Device",
                            draw: function(opts) {
                                return `<a href="#" onclick="kismet_ui.DeviceDetailWindow('${opts['data']['kismet.device.base.key']}')">View Device Details</a>`;
                            }
                        }, 
                        {
                            field: "kismet.device.base.macaddr",
                            title: "MAC",
                            draw: function(opts) {
                                return kismet.censorMAC(`${opts['data']['kismet.device.base.macaddr']} (${opts['data']['kismet.device.base.manuf']})`);
                            }
                        },
                        {
                            field: 'kismet.device.base.commonname',
                            title: "Name",
                            empty: "<i>None</i>",
                            draw: function(opts) {
                                return kismet.censorMAC(opts['value']);
                            },
                        },
                        {
                            field: 'kismet.device.base.type',
                            title: "Type",
                            empty: "<i>Unknown</i>",
                        },
                    ]
                });
            });

        });
    }

});

