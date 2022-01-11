"use strict";

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

