(
  typeof define === "function" ? function (m) { define("kismet-ui-dot11-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_dot11 = m(); }
)(function () {

"use strict";

var exports = {};

var local_uri_prefix = ""; 
if (typeof(KISMET_URI_PREFIX) !== 'undefined')
    local_uri_prefix = KISMET_URI_PREFIX;

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
exports.crypt_sae = (1 << 16);
exports.crypt_wpa_owe = (1 << 17);

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
exports.crypt_version_wpa3 = (1 << 29);

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

    if (cryptset == exports.crypt_wpa_owe)
        return "Open (OWE)";

    if (cryptset & exports.crypt_wpa_owe)
        return "OWE";

    var WPAVER = "WPA";

    if (cryptset & exports.crypt_version_wpa2)
        WPAVER = "WPA2";

    if (cryptset & exports.crypt_version_wpa3)
        WPAVER = "WPA3";

    if (cryptset & exports.crypt_wpa)
        ret.push(WPAVER);

	if ((cryptset & exports.crypt_version_wpa3) && (cryptset & exports.crypt_psk) && (cryptset & exports.crypt_sae))
        ret.push("WPA3-TRANSITION");

    if (cryptset & exports.crypt_psk)
        ret.push(WPAVER + "-PSK");

    if (cryptset & exports.crypt_sae)
        ret.push(WPAVER + "-SAE");

    if (cryptset & exports.crypt_eap)
        ret.push(WPAVER + "-EAP");

    if (cryptset & exports.crypt_peap)
        ret.push(WPAVER + "-PEAP");

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

    if (cryptset & exports.crypt_unknown_nonwep)
        ret.push("Unknown-Non-WEP");

    return ret.join(" ");
};

kismet_ui.AddDeviceView("Wi-Fi Access Points", "phydot11_accesspoints", -10000, "Wi-Fi");

kismet_ui.AddChannelList("IEEE802.11", "Wi-Fi (802.11)", function(in_freq) {
    if (in_freq == 0)
        return "n/a";

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
        return kismet.HumanReadableFrequency(in_freq);
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
        return data['dot11.device.pmkid_packet'] != 0;
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
    sTitle: 'Clients',
    field: 'dot11.device/dot11.device.num_associated_clients',
    description: 'Count of associated Wi-Fi clients',
    width: '2em'
});

kismet_ui.AddDeviceColumn('wifi_last_bssid', {
    sTitle: 'BSSID',
    field: 'dot11.device/dot11.device.last_bssid',
    description: 'Last associated BSSID',
    sortable: true,
    searchable: true
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
                field: "dot11_fingerprint_group",
                groupTitle: "Fingerprints",
                id: "dot11_fingerprint_group",
                fields: [
                {
                    field: "dot11.device/dot11.device.beacon_fingerprint",
                    title: "Beacon",
                    empty: "<i>None</i>",
                    help: "Kismet uses attributes included in beacons to build a fingerprint of a device.  This fingerprint is used to identify spoofed devices, whitelist devices, and to attempt to provide attestation about devices.  The beacon fingerprint is only available when a beacon is seen from an access point.",
                }
                ],
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
                field: "dot11_extras",
                id: "dot11_extras",
                help: "Some devices advertise additional information about capabilities via additional tag fields when joining a network.",
                filter: function(opts) {
                    if (opts['data']['dot11.device']['dot11.device.min_tx_power'] != 0)
                        return true;

                    if (opts['data']['dot11.device']['dot11.device.max_tx_power'] != 0)
                        return true;

                    if (opts['data']['dot11.device']['dot11.device.supported_channels'].length > 0)
                        return true;

                    return false;
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
                        return (opts['data']['dot11.device']['dot11.device.supported_channels'].length);
                    },
                    render: function(opts) {
                        return opts['data']['dot11.device']['dot11.device.supported_channels'].join(',');
                    }
                },
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
                        var url = '<a href="phy/phy80211/by-key/' + key + '/pcap/' +
                            key + '-handshake.pcap">' +
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
                groupTitle: "RSN PMKID",

                fields: [
                {
                    field: "pmkid_download",
                    id: "pmkid_download",
                    title: "PMKID PCAP",
                    render: function(opts) {
                        var key = opts['data']['kismet.device.base.key'];
                        var url = '<a href="phy/phy80211/by-key/' + key + '/pcap/' + key + '-pmkid.pcap">' +
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
                    field: "dot11.probedssid.wpa_mfp_required",
                    title: "MFP",
                    help: "Management Frame Protection (MFP) attempts to mitigate denial of service attacks by authenticating management packets.  It can be part of the 802.11w Wi-Fi standard, or proprietary Cisco extensions.",
                    render: function(opts) {
                        if (opts['value'])
                            return "Required (802.11w)";

                        if (opts['base']['dot11.probedssid.wpa_mfp_supported'])
                            return "Supported (802.11w)";

                        return "Unavailable";
                    }
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
                    var lastowessid = opts['value'][opts['index']]['dot11.advertisedssid.owe_ssid'];

                    if (lastssid === '') {
                        if ('dot11.advertisedssid.owe_ssid' in opts['value'][opts['index']] && lastowessid !== '') {
                            return "SSID: " + lastowessid + "  <i>(OWE)</i>";
                        }

                        return "SSID: <i>Unknown</i>";
                    }

                    return "SSID: " + lastssid;
                },
                fields: [
                {
                    field: "dot11.advertisedssid.ssid",
                    title: "SSID",
                    render: function(opts) {
                        if (opts['value'] === '') {
                            if ('dot11.advertisedssid.owe_ssid' in opts['base']) {
                                return "<i>SSID advertised as OWE</i>";
                            } else {
                                return "<i>Unknown / Cloaked</i>";
                            }
                        }

                        return opts['value'];
                    },
                    help: "Advertised SSIDs can be any data, up to 32 characters.  Some access points attempt to cloak the SSID by sending blank spaces or an empty string; these SSIDs can be discovered when a client connects to the network.",
                },
                {
                    field: "dot11.advertisedssid.owe_ssid",
                    title: "OWE SSID",
                    filterOnEmpty: true,
                    help: "Opportunistic Wireless Encryption (OWE) advertises the original SSID on an alternate BSSID.",
                },
                {
                    field: "dot11.advertisedssid.owe_bssid",
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

                            for (var cl of clidata) {
                                if (cl['kismet.device.base.phyname'] === 'IEEE802.11') {
                                    opts['container'].html(opts['value'] + ' <a href="#" onclick="kismet_ui.DeviceDetailWindow(\'' + cl['kismet.device.base.key'] + '\')">View AP Details</a>');
                                    return;
                                }

                            }
                            opts['container'].html(opts['value']);
                        });
                    },
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
                    field: "dot11.advertisedssid.wpa_mfp_required",
                    title: "MFP",
                    help: "Management Frame Protection (MFP) attempts to mitigate denial of service attacks by authenticating management packets.  It can be part of the Wi-Fi 802.11w standard or a custom Cisco extension.",
                    render: function(opts) {
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
                    title: "Channel",
                    help: "Wi-Fi networks on 2.4GHz (channels 1 through 14) are required to include a channel in the advertisement because channel overlap makes it impossible to determine the exact channel the access point is transmitting on.  Networks on 5GHz channels are typically not required to include the channel.",
                },
                {
                    field: "dot11.advertisedssid.ht_mode",
                    title: "HT Mode",
                    help: "802.11n and 802.11AC networks operate on expanded channels; HT40, HT80 HT160, or HT80+80 (found only on 802.11ac wave2 gear).",
                    filterOnEmpty: true
                },
                {
                    field: "dot11.advertisedssid.ht_center_1",
                    title: "HT Freq",
                    help: "802.11AC networks operate on expanded channels.  This is the frequency of the center of the expanded channel.",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " (Channel " + (opts['value'] - 5000) / 5 + ")";
                    },
                },
                {
                    field: "dot11.advertisedssid.ht_center_2",
                    title: "HT Freq2",
                    help: "802.11AC networks operate on expanded channels.  This is the frequency of the center of the expanded secondary channel.  Secondary channels are only found on 802.11AC wave-2 80+80 gear.",
                    filterOnZero: true,
                    render: function(opts) {
                        return opts['value'] + " (Channel " + (opts['value'] - 5000) / 5 + ")";
                    },
                },
                {
                    field: "dot11.advertisedssid.beacon_info",
                    title: "Beacon Info",
                    filterOnEmpty: true,
                    help: "Some access points, such as those made by Cisco, can include arbitrary custom info in beacons.  Typically this is used by the network administrators to map where access points are deployed.",
                },
                {
                    field: "dot11.advertisedssid.dot11e_qbss_stations",
                    title: "Connected Stations",
                    help: "Access points which provide 802.11e / QBSS report the number of stations observed on the channel as part of the channel quality of service.",
                    filter: function(opts) {
                        console.log(opts);
                        return (opts['base']['dot11.advertisedssid.dot11e_qbss'] == 1);
                    }
                },
                {
                    field: "dot11.advertisedssid.dot11e_channel_utilization_perc",
                    title: "Channel Utilization",
                    help: "Access points which provide 802.11e / QBSS calculate the estimated channel saturation as part of the channel quality of service.",
                    render: function(opts) {
                        return opts['value'].toFixed(2) + '%';
                    },
                    filter: function(opts) {
                        return (opts['base']['dot11.advertisedssid.dot11e_qbss'] == 1);
                    }
                },
                {
                    field: "dot11.advertisedssid.ccx_txpower",
                    title: "Cisco CCX TxPower",
                    filterOnZero: true,
                    help: "Cisco access points may advertise their transmit power in a Cisco CCX IE tag.  Typically this is found on enterprise-level access points, where multiple APs service the same area.",
                    render: function(opts) {
                        return opts['value'] + "dBm";
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
                    title: "WPS Manufacturer",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device manufacturer in the WPS advertisements.  WPS is not recommended due to security flaws."
                },
                {
                    field: "dot11.advertisedssid.wps_device_name",
                    title: "WPS Device",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_model_name",
                    title: "WPS Model",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the specific device model name in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_model_number",
                    title: "WPS Model #",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the specific model number in the WPS advertisements.  WPS is not recommended due to security flaws.",
                },
                {
                    field: "dot11.advertisedssid.wps_serial_number",
                    title: "WPS Serial #",
                    filterOnEmpty: true,
                    help: "Access points which advertise Wi-Fi Protected Setup (WPS) may include the device serial number in the WPS advertisements.  This information is not always valid or useful.  WPS is not recommended due to security flaws.",
                }
            ],
            },

            {
                // Filler title
                field: "dot11.device/dot11.device.client_map",
                id: "client_behavior_header",
                help: "A Wi-Fi device may be a client of multiple networks over time, but can only be actively associated with a single access point at once.  Clients typically are able to roam between access points with the same name (SSID).",
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
                    $.get(local_uri_prefix + "devices/by-key/" + key +
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
                                opts['container'].html(clidata);
                            }
                        });
                    },
                },
                {
                    field: "dot11.client.bssid_key",
                    title: "Last SSID",
                    draw: function(opts) {
                        $.get(local_uri_prefix + "devices/by-key/" + opts['value'] +
                                "/device.json/dot11.device/dot11.device.last_beaconed_ssid")
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
                    render: kismet_ui.RenderTrimmedTime,
                },
                {
                    field: "dot11.client.last_time",
                    title: "Last Connected",
                    render: kismet_ui.RenderTrimmedTime,
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

                        $.get(local_uri_prefix + "devices/by-key/" + clientid + "/device.json")
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
                                    field: "kismet.device.base.commonname",
                                    title: "Name",
                                    filterOnEmpty: "true",
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
