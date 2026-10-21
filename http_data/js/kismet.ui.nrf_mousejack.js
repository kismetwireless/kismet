"use strict";

/* A keyboard for keyboards and unidentified input devices, a mouse for mice */
kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'NrfMousejack') {
        var type = row['original_data']['kismet.device.base.type'] || '';

        if (type.indexOf('mouse') >= 0 && type.indexOf('keyboard') < 0)
            return '<i class="fa fa-computer-mouse"></i>';

        return '<i class="fa fa-keyboard"></i>';
    }
});

/* Highlight nRF24 keyboards and mice */
kismet_ui.AddDeviceRowHighlight({
    name: "nRF24 Keyboards and Mice",
    description: "Nordic Enhanced ShockBurst (MouseJack) wireless keyboards, mice and receivers",
    priority: 100,
    defaultcolor: "#f2d9f7",
    defaultenable: true,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return data['kismet.device.base.phyname'] === 'NrfMousejack';
    }
});

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
