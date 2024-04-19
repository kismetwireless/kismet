/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "bluetooth_types.h"

kis_bt_types::kis_bt_types() {
    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    major_class_id = 
        entrytracker->register_field("bluetooth.device.major_class", 
                tracker_element_factory<tracker_element_string>(), "bt major class");

    minor_class_id = 
        entrytracker->register_field("bluetooth.device.minor_class", 
                tracker_element_factory<tracker_element_string>(), "bt minor class");

    bt_major_dev_class = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(major_class_id, "Miscellaneous") },
        {0x01, std::make_shared<tracker_element_string>(major_class_id, "Computer") },
        {0x02, std::make_shared<tracker_element_string>(major_class_id, "Phone") },
        {0x03, std::make_shared<tracker_element_string>(major_class_id, "LAN/Network Access Point") },
        {0x04, std::make_shared<tracker_element_string>(major_class_id, "Audio/Video") },
        {0x05, std::make_shared<tracker_element_string>(major_class_id, "Peripheral (HID)") },
        {0x06, std::make_shared<tracker_element_string>(major_class_id, "Imaging") },
        {0x07, std::make_shared<tracker_element_string>(major_class_id, "Wearable") },
        {0x08, std::make_shared<tracker_element_string>(major_class_id, "Toy") },
        {0x09, std::make_shared<tracker_element_string>(major_class_id, "Health") },
        {0x1F, std::make_shared<tracker_element_string>(major_class_id, "Uncategorized") },
    };


    bt_minor_dev_class_computer = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "Uncategorized") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Desktop workstation") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Server-class computer") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Laptop") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Handheld PC/PDA (clamshell)") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Palm-size PC/PDA") },
        {0x06, std::make_shared<tracker_element_string>(minor_class_id, "Wearable computer (watch size)") },
        {0x07, std::make_shared<tracker_element_string>(minor_class_id, "Tablet") },
    };

    bt_minor_dev_class_phone = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "Uncategorized") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Cellular") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Cordless") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Smartphone") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Wired modem or voice gateway") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Common ISDN access") },
    };

    bt_minor_dev_class_lan_load = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "0% utilized") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "1% to 17% utilized") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "17% to 33% utilized") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "33% to 50% utilized") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "50% to 67% utilized") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "67% to 83% utilized") },
        {0x06, std::make_shared<tracker_element_string>(minor_class_id, "83% to 99% utilized") },
        {0x07, std::make_shared<tracker_element_string>(minor_class_id, "No service available") },
    };

    bt_minor_dev_class_av = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "Uncategorized") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Wearable Headset Device") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Hands-free Device") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Microphone") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Loudspeaker") },
        {0x06, std::make_shared<tracker_element_string>(minor_class_id, "Headphones") },
        {0x07, std::make_shared<tracker_element_string>(minor_class_id, "Portable Audio") },
        {0x08, std::make_shared<tracker_element_string>(minor_class_id, "Car audio") },
        {0x09, std::make_shared<tracker_element_string>(minor_class_id, "Set-top box") },
        {0x0A, std::make_shared<tracker_element_string>(minor_class_id, "HiFi Audio Device") },
        {0x0B, std::make_shared<tracker_element_string>(minor_class_id, "VCR") },
        {0x0C, std::make_shared<tracker_element_string>(minor_class_id, "Video Camera") },
        {0x0D, std::make_shared<tracker_element_string>(minor_class_id, "Camcorder") },
        {0x0E, std::make_shared<tracker_element_string>(minor_class_id, "Video Monitor") },
        {0x0F, std::make_shared<tracker_element_string>(minor_class_id, "Video Display and Loudspeaker") },
        {0x10, std::make_shared<tracker_element_string>(minor_class_id, "Video Conferencing") },
        {0x12, std::make_shared<tracker_element_string>(minor_class_id, "Gaming/Toy") },
    };

    bt_minor_dev_class_peripheral = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "Unknown Peripheral Device") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Keyboard") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Pointing device") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Combo keyboard/pointing device") },
    };

    bt_minor_dev_type_peripheral = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "Uncategorized") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Joystick") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Gamepad") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Remote control") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Sensing device") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Digitizer tablet") },
        {0x06, std::make_shared<tracker_element_string>(minor_class_id, "Card Reader") },
        {0x07, std::make_shared<tracker_element_string>(minor_class_id, "Digital Pen") },
        {0x08, std::make_shared<tracker_element_string>(minor_class_id, "Handheld barcode scanner") },
        {0x09, std::make_shared<tracker_element_string>(minor_class_id, "Handheld gestural input device") },
    };

    bt_minor_dev_class_wearable = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Wristwatch") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Pager") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Jacket") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Helmet") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Glasses") },
    };

    bt_minor_dev_class_toy = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Robot") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Vehicle") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Doll / Action figure") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Controller") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Game") },
    };

    bt_minor_dev_class_health = std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string>> {
        {0x00, std::make_shared<tracker_element_string>(minor_class_id, "Undefined") },
        {0x01, std::make_shared<tracker_element_string>(minor_class_id, "Blood Pressure Monitor") },
        {0x02, std::make_shared<tracker_element_string>(minor_class_id, "Thermometer") },
        {0x03, std::make_shared<tracker_element_string>(minor_class_id, "Weighing Scale") },
        {0x04, std::make_shared<tracker_element_string>(minor_class_id, "Glucose Meter") },
        {0x05, std::make_shared<tracker_element_string>(minor_class_id, "Pulse Oximeter") },
        {0x06, std::make_shared<tracker_element_string>(minor_class_id, "Heart/Pulse Rate Monitor") },
        {0x07, std::make_shared<tracker_element_string>(minor_class_id, "Health Data Display") },
        {0x08, std::make_shared<tracker_element_string>(minor_class_id, "Step Counter") },
        {0x09, std::make_shared<tracker_element_string>(minor_class_id, "Body Composition Analyzer") },
        {0x0A, std::make_shared<tracker_element_string>(minor_class_id, "Peak Flow Monitor") },
        {0x0B, std::make_shared<tracker_element_string>(minor_class_id, "Medication Monitor") },
        {0x0C, std::make_shared<tracker_element_string>(minor_class_id, "Knee Prosthesis") },
        {0x0D, std::make_shared<tracker_element_string>(minor_class_id, "Ankle Prosthesis") },
        {0x0E, std::make_shared<tracker_element_string>(minor_class_id, "Generic Health Manager") },
        {0x0F, std::make_shared<tracker_element_string>(minor_class_id, "Personal Mobility Device") },
    };

    std::unordered_map<unsigned int, const char *> bt_appearance{
        {0, "Unknown"},
        {64, "Generic Phone"},
        {128, "Generic Computer"},
        {192, "Generic Watch"},
        {193, "Watch: Sports Watch"},
        {256, "Generic Clock"},
        {320, "Generic Display"},
        {384, "Generic Remote Control"},
        {448, "Generic Eye-glasses"},
        {512, "Generic Tag"},
        {576, "Generic Keyring"},
        {640, "Generic Media Player"},
        {704, "Generic Barcode Scanner"},
        {768, "Generic Thermometer"},
        {769, "Thermometer: Ear"},
        {832, "Generic Heart rate Sensor"},
        {833, "Heart Rate Sensor: Heart Rate Belt"},
        {896, "Generic Blood Pressure"},
        {897, "Blood Pressure: Arm"},
        {898, "Blood Pressure: Wrist"},
        {960, "Human Interface Device (HID)"},
        {961, "Keyboard"},
        {962, "Mouse"},
        {963, "Joystick"},
        {964, "Gamepad"},
        {965, "Digitizer Tablet"},
        {966, "Card Reader"},
        {967, "Digital Pen"},
        {968, "Barcode Scanner"},
        {1024, "Generic Glucose Meter"},
        {1088, "Generic: Running Walking Sensor"},
        {1089, "Running Walking Sensor: In-Shoe"},
        {1090, "Running Walking Sensor: On-Shoe"},
        {1091, "Running Walking Sensor: On-Hip"},
        {1152, "Generic: Cycling"},
        {1153, "Cycling: Cycling Computer"},
        {1154, "Cycling: Speed Sensor"},
        {1155, "Cycling: Cadence Sensor"},
        {1156, "Cycling: Power Sensor"},
        {1157, "Cycling: Speed and Cadence Sensor"},
        {1216, "Generic Control Device"},
        {1217, "Switch"},
        {1218, "Multi-switch"},
        {1219, "Button"},
        {1220, "Slider"},
        {1221, "Rotary"},
        {1222, "Touch-panel"},
        {1280, "Generic Network Device"},
        {1281, "Access Point"},
        {1344, "Generic Sensor"},
        {1345, "Motion Sensor"},
        {1346, "Air Quality Sensor"},
        {1347, "Temperature Sensor"},
        {1348, "Humidity Sensor"},
        {1349, "Leak Sensor"},
        {1350, "Smoke Sensor"},
        {1351, "Occupancy Sensor"},
        {1352, "Contact Sensor"},
        {1353, "Carbon Monoxide Sensor"},
        {1354, "Carbon Dioxide Sensor"},
        {1355, "Ambient Light Sensor"},
        {1356, "Energy Sensor"},
        {1357, "Color Light Sensor"},
        {1358, "Rain Sensor"},
        {1359, "Fire Sensor"},
        {1360, "Wind Sensor"},
        {1361, "Proximity Sensor"},
        {1362, "Multi-Sensor"},
        {1408, "Generic Light Fixtures"},
        {1409, "Wall Light"},
        {1410, "Ceiling Light"},
        {1411, "Floor Light"},
        {1412, "Cabinet Light"},
        {1413, "Desk Light"},
        {1414, "Troffer Light"},
        {1415, "Pendant Light"},
        {1416, "In-ground Light"},
        {1417, "Flood Light"},
        {1418, "Underwater Light"},
        {1419, "Bollard with Light"},
        {1420, "Pathway Light"},
        {1421, "Garden Light"},
        {1422, "Pole-top Light"},
        {1423, "Spotlight"},
        {1424, "Linear Light"},
        {1425, "Street Light"},
        {1426, "Shelves Light"},
        {1427, "High-bay / Low-bay Light"},
        {1428, "Emergency Exit Light"},
        {1472, "Generic Fan"},
        {1473, "Ceiling Fan"},
        {1474, "Axial Fan"},
        {1475, "Exhaust Fan"},
        {1476, "Pedestal Fan"},
        {1477, "Desk Fan"},
        {1478, "Wall Fan"},
        {1536, "Generic HVAC"},
        {1537, "Thermostat"},
        {1600, "Generic Air Conditioning"},
        {1664, "Generic Humidifier"},
        {1728, "Generic Heating"},
        {1729, "Radiator"},
        {1730, "Boiler"},
        {1731, "Heat Pump"},
        {1732, "Infrared Heater"},
        {1733, "Radiant Panel Heater"},
        {1734, "Fan Heater"},
        {1735, "Air Curtain"},
        {1792, "Generic Access Control"},
        {1793, "Access Door"},
        {1794, "Garage Door"},
        {1795, "Emergency Exit Door"},
        {1796, "Access Lock"},
        {1797, "Elevator"},
        {1798, "Window"},
        {1799, "Entrance Gate"},
        {1856, "Generic Motorized Device"},
        {1857, "Motorized Gate"},
        {1858, "Awning"},
        {1859, "Blinds or Shades"},
        {1860, "Curtains"},
        {1861, "Screen"},
        {1920, "Generic Power Device"},
        {1921, "Power Outlet"},
        {1922, "Power Strip"},
        {1923, "Plug"},
        {1924, "Power Supply"},
        {1925, "LED Driver"},
        {1926, "Fluorescent Lamp Gear"},
        {1927, "HID Lamp Gear"},
        {1984, "Generic Light Source"},
        {1985, "Incandescent Light Bulb"},
        {1986, "LED Bulb"},
        {1987, "HID Lamp"},
        {1988, "Fluorescent Lamp"},
        {1989, "LED Array"},
        {1990, "Multi-Color LED Array"},
        {3136, "Generic: Pulse Oximeter"},
        {3137, "Fingertip"},
        {3138, "Wrist Worn"},
        {3200, "Generic: Weight Scale"},
        {3264, "Generic Personal Mobility Device"},
        {3265, "Powered Wheelchair"},
        {3266, "Mobility Scooter"},
        {3328, "Generic Continuous Glucose Monitor"},
        {5184, "Generic: Outdoor Sports Activity"},
        {5185, "Location Display Device"},
        {5186, "Location and Navigation Display Device"},
        {5187, "Location Pod"},
        {5188, "Location and Navigation Pod"},
    };

    std::unordered_map<unsigned int, const char *> bt_io_capability{
        {0x00, "Display Only" },
        {0x01, "Display Yes/No" },
        {0x02, "Keyboard Only" },
        {0x03, "No Input, No Output" },
    };

}


