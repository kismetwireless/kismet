"use strict";

kismet_ui.AddDeviceDetail("nrfmousejack", "nRF24 (Enhanced ShockBurst)", 0, {
    filter: function(data) {
        return data['kismet.device.base.phyname'] === "NrfMousejack";
    },
    draw: function(data, target) {
        target.devicedata(data, {
            id: "nrfmousejackdata",
            fields: [
            {
                field: "nrfmousejack.device/nrfmousejack.device.kind",
                title: "Device",
                empty: "Unknown",
                help: "What its payloads show: Logitech Unifying mouse reports, keystroke reports (encrypted or not), keep-alives; Microsoft and Amazon devices by the MouseJack research's fingerprints.",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.receiver",
                title: "Receiver",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "nrfmousejack.device/nrfmousejack.device.receiver") !== "";
                },
                help: "The Logitech receiver (dongle) it is paired with: the devices of one receiver share these four address octets.",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.rf_channel",
                title: "Channel",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "nrfmousejack.device/nrfmousejack.device.rf_channel") >= 0;
                },
                draw: function(opts) {
                    return opts['value'] + " (" + (2400 + opts['value']) + " MHz)";
                },
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.rate_kbps",
                title: "Data rate",
                filter: function(opts) {
                    return kismet.ObjectByString(opts['data'], "nrfmousejack.device/nrfmousejack.device.rate_kbps") > 0;
                },
                draw: function(opts) {
                    return (opts['value'] / 1000) + " Mbit/s";
                },
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.mouse_reports",
                title: "Mouse reports",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.encrypted_keys",
                title: "Encrypted keystrokes",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.plaintext_keys",
                title: "Unencrypted keystrokes",
                help: "Keystroke reports sent in the clear: anyone in radio range can read them.",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.keepalives",
                title: "Keep-alives",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.acks",
                title: "Acknowledgements",
                help: "Empty packets its receiver sends back with the device's address.",
            },
            {
                field: "nrfmousejack.device/nrfmousejack.device.other_packets",
                title: "Other packets",
            },
            ],
        });
    },
});
