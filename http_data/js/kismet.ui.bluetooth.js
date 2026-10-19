"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === 'Bluetooth' ||
        row['original_data']['kismet.device.base.phyname'] === 'BTLE') {
        // Inline so the icon follows the row text colour, including highlighted rows
        return '<svg height="20px" width="20px" viewBox="0 0 217.499 217.499" fill="currentColor">' +
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

