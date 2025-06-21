"use strict";

kismet_ui.AddDeviceIcon((row) => {
    if (row['original_data']['kismet.device.base.phyname'] === '802.15.4') {
        if (kismet_theme.theme === 'dark') {
            return '<img src="images/zigbee-icon-dark.svg" height="20px" width="20px">';
        } else {
            return '<img src="images/zigbee-icon.svg" height="20px" width="20px">';
        }
    }
});

kismet_ui.AddDeviceRowHighlight({
    name: "802.15.4/Zigbee Device",
    description: "Highlight all 802.15.4/Zigbee devices",
    priority: 100,
    defaultcolor: "#b3d1b3",
    defaultenable: false,
    fields: [
        'kismet.device.base.phyname'
    ],
    selector: function(data) {
        return ('kismet.device.base.phyname' in data && data['kismet.device.base.phyname'] == '802.15.4');
    }
});

