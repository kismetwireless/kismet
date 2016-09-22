(
  typeof define === "function" ? function (m) { define("kismet-ui-dot11-js", m); } :
  typeof exports === "object" ? function (m) { module.exports = m(); } :
  function(m){ this.kismet_ui_dot11 = m(); }
)(function () {

"use strict";

var exports = {};

// Flag we're still loading
exports.load_complete = 0;

/* Define some callback functions for the table */

console.log("adding device detail 'dot11'");
kismet_ui.AddDeviceDetail("dot11", "Wi-Fi (802.11)", 0, {
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "dot11DeviceData",
            "fields": [
            {
                field: "dot11_device.dot11_device_last_beaconed_ssid",
                title: "Last Beaconed SSID (AP)",
                empty: "<i>None</i>"
            },
            {
                field: "dot11_device.dot11_device_last_probed_ssid",
                title: "Last Probed SSID (Client)",
                empty: "<i>None</i>"
            },
            {
                field: "dot11_device.dot11_device_last_bssid",
                title: "Last BSSID",
                filter: function(key, data, value) {
                    return value.split('/')[0] !== '00:00:00:00:00:00';
                },
                render: function(key, data, value) {
                    return value.split('/')[0];
                }
            },
            {
                field: "dot11_packet_group",
                groupTitle: "Packets",
                id: "dot11_packet_group",

                fields: [
                {
                    field: "graph_field_dot11",
                    span: true,
                    render: function(key, data, value) {
                        return '<div class="smalldonut" id="overall" style="float: left;" />' +
                            '<div class="smalldonut" id="data" style="float: right;" />';
                    },
                    draw: function(key, data, value, container) {
                        var overalldiv = $('#overall', container);
                        var datadiv = $('#data', container);

                        // Make an array morris likes using our whole data record
                        var modoverall = [
                        { label: "Mgmt", value: data.kismet_device_base_packets_llc },
                        { label: "Data", value: data.kismet_device_base_packets_data }
                        ];

                        if (data.kismet_device_base_packets_error != 0)
                            modoverall.push({ label: "Error", value: data.kismet_device_base_packets_error });

                        Morris.Donut({
                            element: overalldiv,
                            data: modoverall
                        });

                        var moddata = [
                        { label: "Data", value: data.kismet_device_base_packets_data },
                        { label: "Retry", value: data.dot11_device.dot11_device_num_retries },
                        { label: "Frag", value: data.dot11_device.dot11_device_num_fragments }
                        ];

                        Morris.Donut({
                            element: datadiv,
                            data: moddata
                        });
                    }
                },
                {
                    field: "kismet_device_base_packets_total",
                    title: "Total Packets"
                },
                {
                    field: "kismet_device_base_packets_llc",
                    title: "LLC/Management"
                },
                {
                    field: "kismet_device_base_packets_error",
                    title: "Error/Invalid"
                },
                {
                    field: "dot11_device.dot11_device_num_fragments",
                    title: "Fragmented Packets"
                },
                {
                    field: "dot11_device.dot11_device_num_retries",
                    title: "Retried Packets"
                },
                {
                    field: "dot11_device.dot11_device_datasize",
                    title: "Data",
                    render: function(key, data, value) {
                        return kismet.HumanReadableSize(value);
                    }
                },
                {
                    field: "dot11_device.dot11_device_datasize_retry",
                    title: "Retried Data",
                    render: function(key, data, value) {
                        return kismet.HumanReadableSize(value);
                    }
                }
                ],
            },
            {
                field: "dot11_device.dot11_device_advertised_ssid_map",
                id: "advertised_ssid",

                filter: function(key, data, value) {
                    return (Object.keys(data.dot11_device.dot11_device_advertised_ssid_map).length >= 1);
                },

                groupIterate: true,
                iterateTitle: function(key, data, value, index) {
                    var lastssid = value[index].dot11_advertisedssid_ssid;
                    if (lastssid === '')
                        return "Advertised SSID: <i>Unknown</i>";

                    return "Advertised SSID: " + lastssid;
                },
                fields: [
                {
                    field: "dot11_advertisedssid_ssid",
                    title: "SSID",
                    empty: "<i>Unknown</i>"
                        
                },
                {
                    field: "dot11_advertisedssid_channel",
                    title: "Channel"
                },
                {
                    field: "dot11_advertisedssid_first_time",
                    title: "First Seen",
                    render: function(key, data, value) {
                        return new Date(value * 1000);
                    }
                },
                {
                    field: "dot11_advertisedssid_last_time",
                    title: "Last Seen",
                    render: function(key, data, value) {
                        return new Date(value * 1000);
                    }
                },
                {
                    field: "dot11_advertisedssid_beaconrate",
                    title: "Beacon Rate",
                    render: function(key, data, value) {
                        return value + '/sec';
                    }
                },
                {
                    field: "dot11_advertisedssid_maxrate",
                    title: "Max. Rate",
                    render: function(key, data, value) {
                        return value + ' mbit';
                    }
                },
                {
                    field: "dot11_advertisedssid_dot11d_country",
                    title: "802.11d Country",
                    filter: function(key, data, value) {
                        return value !== '';
                    }
                },
                {
                    field: "dot11_advertisedssid_wps_manuf",
                    groupTitle: "WPS",
                    id: "dot11_wps_group",

                    filter: function(key, data, value) {
                        return value !== '';
                    },

                    fields: [
                    {
                        field: "dot11_advertisedssid_wps_manuf",
                        title: "WPS Manufacturer"
                    },
                    {
                        field: "dot11_advertisedssid_wps_device_name",
                        title: "WPS Device",
                        filter: function(key, data, value) {
                            return value !== '';
                        }
                    },
                    {
                        field: "dot11_advertisedssid_wps_model_name",
                        title: "WPS Model",
                        filter: function(key, data, value) {
                            return value !== '';
                        }
                    },
                    {
                        field: "dot11_advertisedssid_wps_model_number",
                        title: "WPS Model #",
                        filter: function(key, data, value) {
                            return value !== '';
                        }
                    }
                    ]
                },

                ]
            },
            {
                field: "dot11_device.dot11_device_client_map",
                id: "client_behavior",

                filter: function(key, data, value) {
                    return (Object.keys(data.dot11_device.dot11_device_client_map).length >= 1);
                },

                groupIterate: true,
                iterateTitle: function(key, data, value, index) {
                    return "Client for: " + index;
                },

                fields: [
                {
                    field: "dot11_client_bssid",
                    title: "BSSID",
                    render: function(key, data, value) {
                        console.log(key + " " + value);
                        return value.split("/")[0];
                    }
                },
                {
                    field: "dot11_client_first_time",
                    title: "First Seen",
                    render: function(key, data, value) {
                        return new Date(value * 1000);
                    }
                },
                {
                    field: "dot11_client_last_time",
                    title: "Last Seen",
                    render: function(key, data, value) {
                        return new Date(value * 1000);
                    }
                },
                {
                    field: "dot11_client_datasize",
                    title: "Data",
                    render: function(key, data, value) {
                        return kismet.HumanReadableSize(value);
                    }
                },
                {
                    field: "dot11_client_dhcp_host",
                    groupTitle: "DHCP",
                    id: "client_dhcp",
                    filter: function(key, data, value) {
                        return value !== '';
                    },
                    fields: [
                    {
                        field: "dot11_client_dhcp_host",
                        title: "DHCP Hostname",
                        empty: "<i>Unknown</i>"
                    },
                    {
                        field: "dot11_client_dhcp_vendor",
                        title: "DHCP Vendor",
                        empty: "<i>Unknown</i>"
                    }
                    ]
                },
                {
                    field: "dot11_client_eap_identity",
                    title: "EAP Identity",
                    filter: function(key, data, value) {
                        return value !== '';
                    }
                },
                {
                    field: "dot11_client_cdp_device",
                    groupTitle: "CDP",
                    id: "client_cdp",
                    filter: function(key, data, value) {
                        return value !== '';
                    },
                    fields: [
                    {
                        field: "dot11_client_cdp_device",
                        title: "CDP Device"
                    },
                    {
                        field: "dot11_client_cdp_port",
                        title: "CDP Port",
                        empty: "<i>Unknown</i>"
                    }
                    ]
                },
                {
                    field: "dot11_client_ipdata",
                    groupTitle: "IP",
                    filter: function(key, data, value) {
                        return value['kismet_common_ipdata_address'] != 0;
                    },
                    fields: [
                    {
                        field: "dot11_client_ipdata.kismet_common_ipdata_address",
                        title: "IP Address",
                    },
                    {
                        field: "dot11_client_ipdata.kismet_common_ipdata_netmask",
                        title: "Netmask",
                        zero: "<i>Unknown</i>"
                    },
                    {
                        field: "dot11_client_ipdata.kismet_common_ipdata_gateway",
                        title: "Gateway",
                        zero: "<i>Unknown</i>"
                    }
                    ]
                },
                ]
            },
            ]
        });
    }
});

console.log("kismet.ui.dot11.js returning, we think we loaded everything?");

// We're done loading
exports.load_complete = 1;

return exports;

});


