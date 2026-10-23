"use strict";

/*
 * A keyboard for keyboards, a mouse for mice, and for a keyboard and mouse together or an input
 * device not yet identified, a keyboard with a smaller mouse over its lower right corner (outlined
 * in the row's highlight colour, so the two stay apart where they overlap)
 */
var nrfKeyboardAndMouse =
    '<span style="position: relative; display: inline-block; width: 1.4em; height: 1em; vertical-align: -0.125em;">' +
    '<i class="fa fa-keyboard" style="position: absolute; left: 0; top: 0;"></i>' +
    '<i class="fa fa-computer-mouse" style="position: absolute; left: 1.45em; top: 0.62em; font-size: 0.62em; ' +
    'paint-order: stroke fill; -webkit-text-stroke: 0.22em var(--k-row-highlight, transparent);"></i></span>';

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'NrfMousejack') {
        var type = row['original_data']['kismet.device.base.type'] || '';
        var mouse = type.indexOf('mouse') >= 0, keyboard = type.indexOf('keyboard') >= 0;

        if (mouse && !keyboard)
            return '<i class="fa fa-computer-mouse"></i>';

        if (keyboard && !mouse)
            return '<i class="fa fa-keyboard"></i>';

        return nrfKeyboardAndMouse;
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
