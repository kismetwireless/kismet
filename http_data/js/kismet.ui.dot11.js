(
  typeof define === "function" ? function (m) { define("kismet-ui-dot11-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_dot11 = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

// Crypt set from packet_ieee80211.h
exports.crypt_none = 0;
exports.crypt_unknown = 1;
exports.crypt_wep = (1 << 1);
exports.crypt_layer3 = (1 << 2);
exports.crypt_wep40 = (1 << 3);
exports.crypt_wep104 = (1 << 4);
exports.crypt_tkip = (1 << 5);
exports.crypt_wpa = (1 << 6);
exports.crypt_psk = (1 << 7);
exports.crypt_aes_ocb = (1 << 8);
exports.crypt_aes_ccm = (1 << 9);
exports.crypt_wpa_migmode = (1 << 10);
exports.crypt_eap = (1 << 11);
exports.crypt_leap = (1 << 12);
exports.crypt_ttls = (1 << 13);
exports.crypt_tls = (1 << 14);
exports.crypt_peap = (1 << 15);

exports.crypt_protectmask = 0xFFFFF;
exports.crypt_isakmp = (1 << 20);
exports.crypt_pptp = (1 << 21);
exports.crypt_fortress = (1 << 22);
exports.crypt_keyguard = (1 << 23);
exports.crypt_unknown_protected = (1 << 24);
exports.crypt_unknown_nonwep = (1 << 25);
exports.crypt_wps = (1 << 26);
exports.crypt_version_wpa = (1 << 27);
exports.crypt_version_wpa2 = (1 << 28);

exports.crypt_l3_mask = 0x300004;
exports.crypt_l2_mask = 0xFBFA;

exports.CryptToHumanReadable = function(cryptset) {
    var ret = [];

    if (cryptset == exports.crypt_none)
        return "None / Open";

    if (cryptset == exports.crypt_unknown)
        return "Unknown";

    if (cryptset & exports.crypt_wps)
        ret.push("WPS");

    if ((cryptset & exports.crypt_protectmask) == exports.crypt_wep) {
        ret.push("WEP");
        return ret.join(" ");
    }

    if (cryptset & exports.crypt_wpa)
        ret.push("WPA");

    if (cryptset & exports.crypt_psk)
        ret.push("WPA-PSK");

    if (cryptset & exports.crypt_eap)
        ret.push("WPA-EAP");

    if (cryptset & exports.crypt_peap)
        ret.push("EAP-PEAP");

    if (cryptset & exports.crypt_leap)
        ret.push("EAP-LEAP");

    if (cryptset & exports.crypt_ttls)
        ret.push("EAP-TTLS");

    if (cryptset & exports.crypt_tls)
        ret.push("EAP-TLS");

    if (cryptset & exports.crypt_wpa_migmode)
        ret.push("WPA-MIGRATION");

    if (cryptset & exports.crypt_wep40)
        ret.push("WEP40");

    if (cryptset & exports.crypt_wep104)
        ret.push("WEP104");

    if (cryptset & exports.crypt_tkip)
        ret.push("TKIP");

    if (cryptset & exports.crypt_aes_ocb)
        ret.push("AES-OCB");

    if (cryptset & exports.crypt_aes_ccm)
        ret.push("AES-CCM");

    if (cryptset & exports.crypt_layer3)
        ret.push("Layer3");

    if (cryptset & exports.crypt_isakmp)
        ret.push("Layer3-ISA-KMP");

    if (cryptset & exports.crypt_pptp)
        ret.push("Layer3-PPTP");

    if (cryptset & exports.crypt_fortress)
        ret.push("Fortress");

    if (cryptset & exports.crypt_keyguard)
        ret.push("Keyguard");

    if (cryptset & exports.crypt_unknown_protected)
        ret.push("Unknown");

    if (cryptset & exports.crypt_unkown_nonwep)
        ret.push("Unknown-Non-WEP");

    return ret.join(" ");
};

kismet_ui.AddChannelList("Wi-Fi (802.11)", function(in_freq) {
    in_freq = parseInt(in_freq / 1000);

    if (in_freq == 2484)
        return 14;
    else if (in_freq < 2484)
        return (in_freq - 2407) / 5;
    else if (in_freq >= 4910 && in_freq <= 4980)
        return (in_freq - 4000) / 5;
    else if (in_freq <= 45000)
        return (in_freq - 5000) / 5;
    else if (in_freq >= 58320 && in_freq <= 64800)
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
        'dot11.device/dot11.device.wpa_present_handshake'
    ],
    selector: function(data) {
        var pnums = data['dot11.device.wpa_present_handshake'];

        // We need packets 1&2 or 2&3 to be able to crack the handshake
        if ((pnums & 0x06) == 0x06 || (pnums & 0x0C) == 0x0C) {
            return true;
        }

        return false;
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "Wi-Fi Device",
    description: "Highlight all Wi-Fi devices",
    priority: 100,
    defaultcolor: "#99ff99",
    defaultenable: false,
    fields: [
        'dot11.device'
    ],
    selector: function(data) {
        return ('dot11.device' in data && data['dot11.device'] != 0);
    }
});

/* Custom device details for dot11 data */
kismet_ui.AddDeviceDetail("dot11", "Wi-Fi (802.11)", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "IEEE802.11");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "dot11DeviceData",
            "fields": [
            {
                field: "dot11.device/dot11.device.last_beaconed_ssid",
                title: "Last Beaconed SSID (AP)",
                empty: "<i>None</i>",
                help: "If present, the last SSID (network name) advertised by a device as an access point beacon or as an access point issuing a probe response",
            },
            {
                field: "dot11.device/dot11.device.last_probed_ssid",
                title: "Last Probed SSID (Client)",
                empty: "<i>None</i>",
                help: "If present, the last SSID (network name) probed for by a device as a client looking for a network.",
            },
            {
                field: "dot11.device/dot11.device.last_bssid",
                title: "Last BSSID",
                filter: function(opts) {
                    return opts['value'] !== '00:00:00:00:00:00';
                },
                render: function(opts) {
                    return opts['value'];
                },
                help: "If present, the BSSID (MAC address) of the last network this device was part of.  Each Wi-Fi access point, even those with the same SSID, has a unique BSSID.",
            },
            {
                field: "dot11_packet_group",
                groupTitle: "Packets",
                id: "dot11_packet_group",

                fields: [
                {
                    field: "graph_field_dot11",
                    span: true,
                    render: function(opts) {
                        return '<div class="smalldonut" id="overall" style="float: left;" />' +
                            '<div class="smalldonut" id="data" style="float: right;" />';
                    },
                    draw: function(opts) {
                        var overalldiv = $('#overall', opts['container']);
                        var datadiv = $('#data', opts['container']);

                        // Make an array morris likes using our whole data record
                        var modoverall = [
                        { label: "Mgmt", value: opts['data']['kismet.device.base.packets.llc'] },
                        { label: "Data", value: opts['data']['kismet.device.base.packets.data'] }
                        ];

                        if (opts['data']['kismet.device.base.packets.error'] != 0)
                            modoverall.push({ label: "Error", value: opts['data']['kismet.device.base.packets.error'] });

                        Morris.Donut({
                            element: overalldiv,
                            data: modoverall
                        });

                        var moddata = [
                        { label: "Data", value: opts['data']['kismet.device.base.packets.data'] },
                        { label: "Retry", value: opts['data']['dot11.device']['dot11.device.num_retries'] },
                        { label: "Frag", value: opts['data']['dot11.device']['dot11.device.num_fragments'] }
                        ];

                        Morris.Donut({
                            element: datadiv,
                            data: moddata
                        });
                    }
                },
                {
                    field: "kismet.device.base.packets.total",
                    title: "Total Packets",
                    help: "Total packet count seen of all packet types",
                },
                {
                    field: "kismet.device.base.packets.llc",
                    title: "LLC/Management",
                    help: "LLC and Management packets define Wi-Fi networks.  They include packets like beacons, probe requests and responses, and other packets.  Access points will almost always have significantly more management packets than any other type.",
                },
                {
                    field: "kismet.device.base.packets.data",
                    title: "Data Packets",
                    help: "Wi-Fi data packets encode the actual data being sent by the device.",
                },
                {
                    field: "kismet.device.base.packets.error",
                    title: "Error/Invalid Packets",
                    help: "Invalid Wi-Fi packets are packets which have become corrupted in the air or which are otherwise invalid.  Typically these packets are discarded instead of tracked because the validity of their contents cannot be verified, so this will often be 0.",
                },
                {
                    field: "dot11.device/dot11.device.num_fragments",
                    title: "Fragmented Packets",
                    help: "The data being sent over Wi-Fi can be fragmented into smaller packets.  Typically this is not desirable because it increases the packet load and can add latency to TCP connections.",
                },
                {
                    field: "dot11.device/dot11.device.num_retries",
                    title: "Retried Packets",
                    help: "If a Wi-Fi data packet cannot be transmitted (due to weak signal, interference, or collisions with other packets transmitted at the same time), the Wi-Fi layer will automatically attempt to retransmit it a number of times.  In busy environments, a retransmit rate of 50% or higher is not unusual.",
                },
                {
                    field: "dot11.device/dot11.device.datasize",
                    title: "Data (size)",
                    render: kismet_ui.RenderHumanSize,
                    help: "The amount of data transmitted by this device",
                },
                {
                    field: "dot11.device/dot11.device.datasize.retry",
                    title: "Retried Data",
                    render: kismet_ui.RenderHumanSize,
                    help: "The amount of data re-transmitted by this device, due to lost packets and automatic retry.",
                }
                ],
            },
            {
                field: "dot11.device/dot11.device.wpa_handshake_list",
                id: "wpa_handshake",
                help: "When a client joins a WPA network, it performs a &quot;handshake&quot; of four packets to establish the connection and the unique per-session key.  To decrypt WPA or derive the PSK, at least two specific packets of this handshake are required.  Kismet provides a simplified pcap file of the handshake packets seen, which can be used with other tools to derive the PSK or decrypt the packet stream.",
                filter: function(opts) {
                    return (opts['data']['dot11.device']['dot11.device.wpa_handshake_list'].length);
                },
                groupTitle: "WPA Key Exchange",

                fields: [
                {
                    field: "wpa_handshake_count",
                    id: "handshake_count",
                    title: "Handshake Packets",
                    render: function(opts) {
                        var hs = opts['data']['dot11.device']['dot11.device.wpa_handshake_list'];
                        return (hs.length);
                    },
                },
                {
                    field: "wpa_handshake_download",
                    id: "handshake_download",
                    title: "Handshake PCAP",
                    render: function(opts) {
                        var pnums = opts['data']['dot11.device']['dot11.device.wpa_present_handshake'];

                        // We need packets 1&2 or 2&3 to be able to crack the handshake
                        var warning = "";
                        if ((pnums & 0x06) != 0x06 &&
                            (pnums & 0x0C) != 0x0C) {
                            warning = '<br><i style="color: red;">While handshake packets have been seen, no complete handshakes collected.</i>';
                        }

                        var key = opts['data']['kismet.device.base.key'];
                        var url = '<a href="/phy/phy80211/by-key/' + key + '/pcap/' +
                            key + '-handshake.pcap">' +
                            '<i class="fa fa-download"></i> Download Pcap File</a>' +
                            warning;
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
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.probed_ssid_map']).length >= 1);
                },
                title: '<b class="k_padding_title">Probed SSIDs</b>',
                help: "Wi-Fi clients will send out probe requests for networks they are trying to join.  Probe requests can either be broadcast requests, requesting any network in the area respond, or specific requests, requesting a single SSID the client has used previously.  Different clients may behave differently, and modern clients will typically only send generic broadcast probes.",
            },

            {
                field: "dot11.device/dot11.device.probed_ssid_map",
                id: "probed_ssid",

                filter: function(opts) {
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.probed_ssid_map']).length >= 1);
                },

                groupIterate: true,

                iterateTitle: function(opts) {
                    var lastprobe = opts['value'][opts['index']];
                    var lastpssid = lastprobe['dot11.probedssid.ssid'];
                    var key = "probessid" + opts['index'];

                    if (lastpssid === '')
                        lastpssid = "<i>Broadcast</i>";

                    return '<a id="' + key + '" class="expander collapsed" data-expander-target="#probed_ssid" href="#">Probed SSID ' + lastpssid + '</a>';
                },

                draw: function(opts) {
                    var tb = $('.expander', opts['container']).simpleexpand();
                },

                fields: [
                {
                    field: "dot11.probedssid.ssid",
                    title: "Probed SSID",
                    empty: "<i>Broadcast</i>"
                },
                {
                    field: "dot11.probedssid.first_time",
                    title: "First Seen",
                    render: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.probedssid.last_time",
                    title: "Last Seen",
                    render: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.probedssid.dot11r_mobility",
                    title: "802.11r Mobility",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network.  Typically this is found on enterprise-level access points, on a network where multiple APs service the same area.",
                    render: function(opts) { return "Enabled"; }
                },
                {
                    field: "dot11.probedssid.dot11r_mobility_domain_id",
                    title: "Mobility Domain",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network."
                },

                ],
            },

            {
                // Filler title
                field: "dot11.device/dot11.device.advertised_ssid_map",
                id: "advertised_ssid_header",
                filter: function(opts) {
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.advertised_ssid_map']).length >= 1);
                },
                title: '<b class="k_padding_title">Advertised SSIDs</b>',
                help: "A single BSSID may advertise multiple SSIDs, either changing its network name over time or combining multiple SSIDs into a single BSSID radio address.  Most modern Wi-Fi access points which support multiple SSIDs will generate a dynamic MAC address for each SSID.",
            },

            {
                field: "dot11.device/dot11.device.advertised_ssid_map",
                id: "advertised_ssid",

                filter: function(opts) {
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.advertised_ssid_map']).length >= 1);
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    var lastssid = opts['value'][opts['index']]['dot11.advertisedssid.ssid'];
                    if (lastssid === '')
                        return "SSID: <i>Unknown</i>";

                    return "SSID: " + lastssid;
                },
                fields: [
                {
                    field: "dot11.advertisedssid.ssid",
                    title: "SSID",
                    empty: "<i>Unknown</i>",
                    help: "Advertised SSIDs can be any data, up to 32 characters.  Some access points attempt to cloak the SSID by sending blank spaces or an empty string; these SSIDs can be discovered when a client connects to the network.",
                },
                {
                    field: "dot11.advertisedssid.crypt_set",
                    title: "Encryption",
                    render: function(opts) {
                        return exports.CryptToHumanReadable(opts['value']);
                    },
                    help: "Encryption at the Wi-Fi layer (open, WEP, and WPA) is defined by the beacon sent by the access point advertising the network.  Layer 3 encryption (such as VPNs) is added later and is not advertised as part of the network itself.",
                },
                {
                    field: "dot11.advertisedssid.channel",
                    title: "Channel",
                    help: "Wi-Fi networks on 2.4GHz (channels 1 through 14) are required to include a channel in the advertisement because channel overlap makes it impossible to determine the exact channel the access point is transmitting on.  Networks on 5GHz channels are typically not required to include the channel.",
                },
                {
                    field: "dot11.advertisedssid.beacon_info",
                    title: "Beacon Info",
                    filterOnEmpty: true,
                    help: "Some access points, such as those made by Cisco, can include arbitrary custom info in beacons.  Typically this is used by the network administrators to map where access points are deployed.",
                },

                {
                    // Filler title
                    field: "dot11.advertisedssid.dot11e_qbss",
                    id: "dot11e_header",
                    title: '<b class="k_padding_title">Channel QBSS</b>',
                    filterOnZero: true,
                    render: function(opts) { return ""; },
                    help: "802.11e, or QBSS, allows an access point to report statistics about the channel, including the number of connected Wi-Fi devices and the estimated channel usage percentage.  This is typically found on enterprise-class access points.",
                },
                {
                    field: "dot11.advertisedssid.dot11e_qbss_stations",
                    title: "Connected Stations",
                    help: "802.11e / QBSS access points can report the number of stations observed on the channel as part of the channel quality of service.",
                },
                {
                    field: "dot11.advertisedssid.dot11e_channel_utilization_perc",
                    title: "Channel Utilization",
                    help: "802.11e / QBSS access points can calculate the estimated channel saturation as part of the channel quality of service.",
                    render: function(opts) {
                        return opts['value'].toFixed(2) + '%';
                    },
                },
                {
                    field: "dot11.advertisedssid.dot11r_mobility",
                    title: "802.11r Mobility",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network.  Typically this is found on enterprise-level access points, on a network where multiple APs service the same area.",
                    render: function(opts) { return "Enabled"; }
                },
                {
                    field: "dot11.advertisedssid.dot11r_mobility_domain_id",
                    title: "Mobility Domain",
                    filterOnZero: true,
                    help: "The 802.11r standard allows for fast roaming between access points on the same network."
                },
                {
                    field: "dot11.advertisedssid.first_time",
                    title: "First Seen",
                    render: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.advertisedssid.last_time",
                    title: "Last Seen",
                    render: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.advertisedssid.beaconrate",
                    title: "Beacon Rate",
                    render: function(opts) {
                        return opts['value'] + '/sec';
                    },
                    help: "Wi-Fi typically beacons at 10 packets per second; normally there is no reason for an access point to change this rate, but it may be changed in some situations where a large number of SSIDs are hosted on a single access point.",
                },
                {
                    field: "dot11.advertisedssid.maxrate",
                    title: "Max. Rate",
                    render: function(opts) {
                        return opts['value'] + ' mbit';
                    },
                    help: "The maximum basic transmission rate supported by this access point",
                },
                {
                    field: "dot11.advertisedssid.dot11d_country",
                    title: "802.11d Country",
                    filterOnEmpty: true,
                    help: "The 802.11d standard required access points to identify their operating country code and signal levels.  This caused clients connecting to those access points to adopt the same regulatory requirements.  802.11d has been phased out and is not found on most modern access points but may still be seen on older hardware.",
                },
                {
                    field: "dot11.advertisedssid.wps_manuf",
                    groupTitle: "WPS",
                    id: "dot11_wps_group",
                    filterOnEmpty: true,
                    help: "WPS, or Wireless Protected Setup, is a mechanism for configuring clients without entering the complete WPA key.  It is susceptible to several attacks and should be, if possible, disabled.",

                    fields: [
                    {
                        field: "dot11.advertisedssid.wps_manuf",
                        title: "WPS Manufacturer"
                    },
                    {
                        field: "dot11.advertisedssid.wps_device_name",
                        title: "WPS Device",
                        filterOnEmpty: true,
                    },
                    {
                        field: "dot11.advertisedssid.wps_model_name",
                        title: "WPS Model",
                        filterOnEmpty: true,
                    },
                    {
                        field: "dot11.advertisedssid.wps_model_number",
                        title: "WPS Model #",
                        filterOnEmpty: true,
                    }
                    ]
                },

                ]
            },

            {
                // Filler title
                field: "dot11.device/dot11.device.client_map",
                id: "client_behavior_header",
                help: "A Wi-Fi device may be a client of multiple networks over time, but can only be actively associated with a single access point at a time.",
                filter: function(opts) {
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.client_map']).length >= 1);
                },
                title: '<b class="k_padding_title">Wi-Fi Client Behavior</b>'
            },

            {
                field: "dot11.device/dot11.device.client_map",
                id: "client_behavior",

                filter: function(opts) {
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.client_map']).length >= 1);
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    var key = kismet.ObjectByString(opts['data'], opts['basekey'] + 'dot11.client.bssid_key');
                    if (key != 0) {
                        return '<a id="' + key + '" class="expander collapsed" data-expander-target="#client_behavior" href="#">Client of ' + opts['index'] + '</a>';
                    }

                    return '<a class="expander collapsed" data-expander-target="#client_behavior" href="#">Client of ' + opts['index'] + '</a>';
                },
                draw: function(opts) {
                    var tb = $('.expander', opts['container']).simpleexpand();

                    var key = kismet.ObjectByString(opts['data'], opts['basekey'] + 'dot11.client.bssid_key');
                    var mac = kismet.ObjectByString(opts['data'], opts['basekey'] + 'dot11.client.bssid');
                    var alink = $('a#' + key, opts['container']);
                    $.get("/devices/by-key/" + key +
                            "/device.json/dot11.device/dot11.device.last_beaconed_ssid")
                    .done(function(clidata) {
                        clidata = kismet.sanitizeObject(clidata);

                        if (clidata !== '' && clidata !== '""') {
                            alink.html("Client of " + mac + " (" + clidata + ")");
                        }
                    });
                },

                fields: [
                {
                    field: "dot11.client.bssid_key",
                    title: "Access Point",
                    render: function(opts) {
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
                    render: function(opts) {
                        var ret = opts['value'];
                        return ret;
                    }
                },
                {
                    field: "dot11.client.bssid_key",
                    title: "Last SSID",
                    draw: function(opts) {
                        $.get("/devices/by-key/" + opts['value'] +
                                "/device.json/dot11.device/dot11.device.last_beaconed_ssid")
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
                    render: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.client.last_time",
                    title: "Last Connected",
                },
                {
                    field: "dot11.client.datasize",
                    title: "Data",
                    render: kismet_ui.RenderHumanSize,
                },
                {
                    field: "dot11.client.datasize_retry",
                    title: "Retried Data",
                    render: kismet_ui.RenderHumanSize,
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
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.associated_client_map']).length >= 1);
                },
                title: '<b class="k_padding_title">Associated Clients</b>',
                help: "An access point typically will have clients associated with it.  These client devices can either be wireless devices connected to the access point, or they can be bridged, wired devices on the network the access point is connected to.",
            },

            {
                field: "dot11.device/dot11.device.associated_client_map",
                id: "client_list",

                filter: function(opts) {
                    return (Object.keys(opts['data']['dot11.device']['dot11.device.associated_client_map']).length >= 1);
                },

                groupIterate: true,
                iterateTitle: function(opts) {
                    return '<a class="expander collapsed" href="#" data-expander-target="#client_list">Client ' + opts['index'] + '</a>';
                },
                draw: function(opts) {
                    var tb = $('.expander', opts['container']).simpleexpand();
                },
                fields: [
                {
                    // Dummy field to get us a nested area since we don't have
                    // a real field in the client list since it's just a key-val
                    // not a nested object
                    field: "dummy",
                    // Span to fill it
                    span: true,
                    // Render nothing into the container
                    render: "",
                    draw: function(opts) {
                        // Now we get the client id, form an ajax query, and embed
                        // a whole new devicedata into our container.  It works!
                        var clientid = kismet.ObjectByString(data, opts['basekey']);
                        var apkey = data['kismet.device.base.macaddr'];

                        $.get("/devices/by-key/" + clientid + "/device.json")
                        .done(function(clidata) {
                            clidata = kismet.sanitizeObject(clidata);

                            opts['container'].devicedata(clidata, {
                                id: "clientData",
                                fields: [
                                {
                                    field: "kismet.device.base.key",
                                    title: "Client Info",
                                    render: function(opts) {
                                        return '<a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + opts['data']['kismet.device.base.key'] + '\')">View Client Details</a>';
                                    }
                                },
                                {
                                    field: "kismet.device.base.name",
                                    title: "Name",
                                    empty: "<i>None</i>"
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
                                    field: "dot11.device/dot11.device.client_map[" + apkey + "]/dot11.client.first_time",
                                    title: "First Connected",
                                    render: kismet_ui.RenderTrimmedTime,
                                },
                                {
                                    field: "dot11.device/dot11.device.client_map[" + apkey + "]/dot11.client.last_time",
                                    title: "Last Connected",
                                    render: kismet_ui.RenderTrimmedTime,
                                },
                                {
                                    field: "dot11.device/dot11.device.client_map[" + apkey + "]/dot11.client.datasize",
                                    title: "Data",
                                    render: kismet_ui.RenderHumanSize,
                                },
                                {
                                    field: "dot11.device/dot11.device.client_map[" + apkey + "]/dot11.client.datasize_retry",
                                    title: "Retried Data",
                                    render: kismet_ui.RenderHumanSize,
                                },
                                ]
                            });
                        })
                        .fail(function(xhr, status, error) {
                            opts['container'].html("Unable to load client details.  Device data may have been timed out by the Kismet server (" + error + ").");
                        });
                    }
                },
                ]
            },
            ]
        });
    }
});

// We're done loading
exports.load_complete = 1;

return exports;

});
