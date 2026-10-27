"use strict";

kismet_ui.AddDeviceDetail("bluetooth", "Bluetooth", 0, {
    filter: function(data) {
        return (data['kismet.device.base.phyname'] === "Bluetooth");
    },
    draw: function(data, target) {
        target.devicedata(data, {
            "id": "bluetoothDeviceData",
            "fields": [
            {
                field: "bluetooth.device/bluetooth.device.major_class",
                title: "Class",
                filterOnEmpty: true,
                help: "BR/EDR class of device: what the device says it is.",
            },
            {
                field: "bluetooth.device/bluetooth.device.minor_class",
                title: "Subclass",
                filterOnEmpty: true,
            },
            {
                field: "bluetooth.device/bluetooth.device.service_classes",
                title: "Services",
                filterOnEmpty: true,
                draw: function(opts) {
                    return opts['value'].join(", ");
                },
                help: "Service classes from the class of device.",
            },
            {
                field: "bluetooth.device/bluetooth.device.lmp_version",
                title: "Bluetooth Version",
                filterOnEmpty: true,
                help: "The Bluetooth version the device's controller reported when a host connected to it.",
            },
            {
                field: "bluetooth.device/bluetooth.device.chip_manufacturer",
                title: "Chip Maker ID",
                filterOnEmpty: true,
                help: "Bluetooth company ID of the device's controller chip.",
            },
            {
                field: "bluetooth.device/bluetooth.device.lmp_subversion",
                title: "Chip Firmware",
                filterOnZero: true,
                help: "The controller's firmware subversion, chosen by the chip maker.",
            },
            {
                field: "bluetooth.device/bluetooth.device.appearance_name",
                title: "Appearance",
                filterOnEmpty: true,
                help: "What a BLE device advertises itself as (the Bluetooth appearance value).",
            },
            {
                field: "bluetooth.device/bluetooth.device.txpower",
                title: "TX Power",
                filterOnZero: true,
                draw: function(opts) {
                    return opts['value'] + " dBm";
                },
            },
            {
                field: "bluetooth.device/bluetooth.device.service_uuid_strs",
                title: "Service UUIDs",
                filterOnEmpty: true,
                draw: function(opts) {
                    return opts['value'].join(", ");
                },
            },
            {
                field: "bluetooth.device/bluetooth.device.beacon",
                groupTitle: "Beacon",
                filterOnEmpty: true,
                id: "bluetooth_beacon",
                help: "Identity advertised by a proximity beacon (iBeacon, AltBeacon, or Eddystone).",
                fields: [
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.type",
                    title: "Format",
                },
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.uuid",
                    title: "UUID",
                    filterOnEmpty: true,
                },
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.major",
                    title: "Major",
                    filterOnEmpty: true,
                },
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.minor",
                    title: "Minor",
                    filterOnEmpty: true,
                },
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.namespace",
                    title: "Namespace",
                    filterOnEmpty: true,
                },
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.instance",
                    title: "Instance",
                    filterOnEmpty: true,
                },
                {
                    field: "bluetooth.device/bluetooth.device.beacon/btle.device.beacon.url",
                    title: "URL",
                    filterOnEmpty: true,
                },
                ],
            },
            ],
        });
    },
});

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'Bluetooth' ||
        row['original_data']['kismet.device.base.phyname'] === 'BTLE') {
        // Inline so the icon follows the row text colour, including highlighted rows; sized
        // like the font icons of the other phys so every device row is the same height
        return '<svg height="1em" width="1em" style="vertical-align: -0.125em;" viewBox="0 0 217.499 217.499" fill="currentColor">' +
            '<path d="M123.264,108.749l45.597-44.488c1.736-1.693,2.715-4.016,2.715-6.441s-0.979-4.748-2.715-6.441l-50.038-48.82 c-2.591-2.528-6.444-3.255-9.78-1.853c-3.336,1.406-5.505,4.674-5.505,8.294v80.504l-42.331-41.3 c-3.558-3.471-9.255-3.402-12.727,0.156c-3.471,3.558-3.401,9.256,0.157,12.727l48.851,47.663l-48.851,47.663 c-3.558,3.471-3.628,9.169-0.157,12.727s9.17,3.628,12.727,0.156l42.331-41.3v80.504c0,3.62,2.169,6.888,5.505,8.294 c1.128,0.476,2.315,0.706,3.493,0.706c2.305,0,4.572-0.886,6.287-2.559l50.038-48.82c1.736-1.693,2.715-4.016,2.715-6.441 s-0.979-4.748-2.715-6.441L123.264,108.749z M121.539,30.354l28.15,27.465l-28.15,27.465V30.354z M121.539,187.143v-54.93 l28.15,27.465L121.539,187.143z"/></svg>';
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "Bluetooth Device",
    description: "Highlight all Bluetooth devices",
    priority: 100,
    defaultcolor: "#b3d1ff",
    defaultenable: false,
    fields: [
        'bluetooth.device'
    ],
    selector: function(data) {
        return ('bluetooth.device' in data && data['bluetooth.device'] != 0);
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "Bluetooth BR/EDR Device",
    description: "Highlight classic BR/EDR Bluetooth devices",
    priority: 101,
    defaultcolor: "#ddccff",
    defaultenable: false,
    fields: [
        'kismet.device.base.type',
    ],
    selector: function(data) {
        return (data['kismet.device.base.type'] === 'BR/EDR');
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "Bluetooth BLE Device",
    description: "Highlight BLE Bluetooth devices",
    priority: 101,
    defaultcolor: "#b3d9ff",
    defaultenable: false,
    fields: [
        'kismet.device.base.type',
    ],
    selector: function(data) {
        return (data['kismet.device.base.type'] === 'BTLE');
    }
});

