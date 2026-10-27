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

#include "bt_assigned.h"

#include <iterator>

#include "fmt.h"

namespace bt_assigned {

namespace {

struct name_entry {
    uint16_t code;
    const char *name;
};

template<size_t N>
constexpr const char *lookup(const name_entry (&table)[N], uint16_t code) {
    for (const auto& e : table)
        if (e.code == code)
            return e.name;
    return nullptr;
}

constexpr name_entry cod_majors[] = {
    {0x00, "Miscellaneous"}, {0x01, "Computer"}, {0x02, "Phone"},
    {0x03, "LAN/Network Access Point"}, {0x04, "Audio/Video"}, {0x05, "Peripheral"},
    {0x06, "Imaging"}, {0x07, "Wearable"}, {0x08, "Toy"}, {0x09, "Health"},
    {0x1F, "Uncategorized"},
};

constexpr name_entry cod_computer[] = {
    {0, "Uncategorized"}, {1, "Desktop workstation"}, {2, "Server"}, {3, "Laptop"},
    {4, "Handheld PC/PDA"}, {5, "Palm-size PC/PDA"}, {6, "Wearable computer"}, {7, "Tablet"},
};

constexpr name_entry cod_phone[] = {
    {0, "Uncategorized"}, {1, "Cellular"}, {2, "Cordless"}, {3, "Smartphone"},
    {4, "Wired modem or voice gateway"}, {5, "Common ISDN access"},
};

constexpr name_entry cod_lan_load[] = {
    {0, "Fully available"}, {1, "1-17% utilized"}, {2, "17-33% utilized"},
    {3, "33-50% utilized"}, {4, "50-67% utilized"}, {5, "67-83% utilized"},
    {6, "83-99% utilized"}, {7, "No service available"},
};

constexpr name_entry cod_av[] = {
    {0, "Uncategorized"}, {1, "Wearable headset"}, {2, "Hands-free"}, {4, "Microphone"},
    {5, "Loudspeaker"}, {6, "Headphones"}, {7, "Portable audio"}, {8, "Car audio"},
    {9, "Set-top box"}, {10, "HiFi audio"}, {11, "VCR"}, {12, "Video camera"},
    {13, "Camcorder"}, {14, "Video monitor"}, {15, "Video display and loudspeaker"},
    {16, "Video conferencing"}, {18, "Gaming/toy"},
};

constexpr name_entry cod_peripheral_kind[] = {
    {1, "Keyboard"}, {2, "Pointing device"}, {3, "Combo keyboard/pointing device"},
};

constexpr name_entry cod_peripheral_type[] = {
    {1, "Joystick"}, {2, "Gamepad"}, {3, "Remote control"}, {4, "Sensing device"},
    {5, "Digitizer tablet"}, {6, "Card reader"}, {7, "Digital pen"},
    {8, "Handheld scanner"}, {9, "Handheld gestural input device"},
};

constexpr name_entry cod_wearable[] = {
    {1, "Wristwatch"}, {2, "Pager"}, {3, "Jacket"}, {4, "Helmet"}, {5, "Glasses"},
    {6, "Pin"},
};

constexpr name_entry cod_toy[] = {
    {1, "Robot"}, {2, "Vehicle"}, {3, "Doll/action figure"}, {4, "Controller"},
    {5, "Game"},
};

constexpr name_entry cod_health[] = {
    {0, "Undefined"}, {1, "Blood pressure monitor"}, {2, "Thermometer"},
    {3, "Weighing scale"}, {4, "Glucose meter"}, {5, "Pulse oximeter"},
    {6, "Heart/pulse rate monitor"}, {7, "Health data display"}, {8, "Step counter"},
    {9, "Body composition analyzer"}, {10, "Peak flow monitor"},
    {11, "Medication monitor"}, {12, "Knee prosthesis"}, {13, "Ankle prosthesis"},
    {14, "Generic health manager"}, {15, "Personal mobility device"},
};

/* Bits 13-23 */
constexpr name_entry cod_services[] = {
    {13, "Limited discoverable"}, {14, "LE audio"}, {16, "Positioning"},
    {17, "Networking"}, {18, "Rendering"}, {19, "Capturing"}, {20, "Object transfer"},
    {21, "Audio"}, {22, "Telephony"}, {23, "Information"},
};

/* Appearance categories, by value >> 6 */
constexpr name_entry appearance_categories[] = {
    {0, "Unknown"}, {1, "Phone"}, {2, "Computer"}, {3, "Watch"}, {4, "Clock"},
    {5, "Display"}, {6, "Remote control"}, {7, "Eye-glasses"}, {8, "Tag"},
    {9, "Keyring"}, {10, "Media player"}, {11, "Barcode scanner"}, {12, "Thermometer"},
    {13, "Heart rate sensor"}, {14, "Blood pressure"}, {15, "Human interface device"},
    {16, "Glucose meter"}, {17, "Running walking sensor"}, {18, "Cycling"},
    {19, "Control device"}, {20, "Network device"}, {21, "Sensor"},
    {22, "Light fixture"}, {23, "Fan"}, {24, "HVAC"}, {25, "Air conditioning"},
    {26, "Humidifier"}, {27, "Heating"}, {28, "Access control"},
    {29, "Motorized device"}, {30, "Power device"}, {31, "Light source"},
    {32, "Window covering"}, {33, "Audio sink"}, {34, "Audio source"},
    {35, "Motorized vehicle"}, {36, "Domestic appliance"},
    {37, "Wearable audio device"}, {38, "Aircraft"}, {39, "AV equipment"},
    {40, "Display equipment"}, {41, "Hearing aid"}, {42, "Gaming"}, {43, "Signage"},
    {49, "Pulse oximeter"}, {50, "Weight scale"}, {51, "Personal mobility device"},
    {52, "Continuous glucose monitor"}, {53, "Insulin pump"},
    {54, "Medication delivery"}, {55, "Spirometer"}, {81, "Outdoor sports activity"},
};

/* The subcategories seen most, by full value */
constexpr name_entry appearance_subcategories[] = {
    {0x0081, "Desktop workstation"}, {0x0082, "Server"}, {0x0083, "Laptop"},
    {0x0084, "Handheld PC/PDA"}, {0x0085, "Palm-size PC/PDA"},
    {0x0086, "Wearable computer"}, {0x0087, "Tablet"}, {0x0088, "Docking station"},
    {0x0089, "All in one"}, {0x008A, "Blade server"}, {0x008B, "Convertible"},
    {0x008C, "Detachable"}, {0x008D, "IoT gateway"}, {0x008E, "Mini PC"},
    {0x008F, "Stick PC"},
    {0x00C1, "Sports watch"}, {0x00C2, "Smartwatch"},
    {0x0301, "Ear thermometer"},
    {0x0341, "Heart rate belt"},
    {0x0381, "Arm blood pressure"}, {0x0382, "Wrist blood pressure"},
    {0x03C1, "Keyboard"}, {0x03C2, "Mouse"}, {0x03C3, "Joystick"}, {0x03C4, "Gamepad"},
    {0x03C5, "Digitizer tablet"}, {0x03C6, "Card reader"}, {0x03C7, "Digital pen"},
    {0x03C8, "Barcode scanner"}, {0x03C9, "Touchpad"}, {0x03CA, "Presentation remote"},
    {0x0441, "In-shoe running sensor"}, {0x0442, "On-shoe running sensor"},
    {0x0443, "On-hip running sensor"},
    {0x0481, "Cycling computer"}, {0x0482, "Cycling speed sensor"},
    {0x0483, "Cycling cadence sensor"}, {0x0484, "Cycling power sensor"},
    {0x0485, "Cycling speed and cadence sensor"},
    {0x0501, "Access point"},
    {0x0541, "Motion sensor"}, {0x0542, "Air quality sensor"},
    {0x0543, "Temperature sensor"}, {0x0544, "Humidity sensor"}, {0x0545, "Leak sensor"},
    {0x0546, "Smoke sensor"}, {0x0547, "Occupancy sensor"}, {0x0548, "Contact sensor"},
    {0x0549, "Carbon monoxide sensor"}, {0x054A, "Carbon dioxide sensor"},
    {0x054B, "Ambient light sensor"}, {0x054C, "Energy sensor"},
    {0x054D, "Color light sensor"}, {0x054E, "Rain sensor"}, {0x054F, "Fire sensor"},
    {0x0550, "Wind sensor"}, {0x0551, "Proximity sensor"}, {0x0552, "Multi-sensor"},
    {0x0841, "Standalone speaker"}, {0x0842, "Soundbar"}, {0x0843, "Bookshelf speaker"},
    {0x0844, "Standmounted speaker"}, {0x0845, "Speakerphone"},
    {0x0941, "Earbud"}, {0x0942, "Headset"}, {0x0943, "Headphones"},
    {0x0944, "Neck band"},
    {0x0A41, "In-ear hearing aid"}, {0x0A42, "Behind-ear hearing aid"},
    {0x0A43, "Cochlear implant"},
    {0x0A81, "Home video game console"}, {0x0A82, "Portable handheld console"},
};

}

const char *cod_major_name(uint8_t major) {
    auto n = lookup(cod_majors, major);
    return n != nullptr ? n : "Reserved";
}

std::string cod_minor_name(uint8_t major, uint8_t minor) {
    const char *n = nullptr;

    switch (major) {
        case 0x01:
            n = lookup(cod_computer, minor);
            break;
        case 0x02:
            n = lookup(cod_phone, minor);
            break;
        case 0x03:
            n = lookup(cod_lan_load, minor >> 3);
            break;
        case 0x04:
            n = lookup(cod_av, minor);
            break;
        case 0x05: {
            /* A kind (keyboard, pointer) and a type, either of which may be absent */
            auto kind = lookup(cod_peripheral_kind, minor >> 4);
            auto type = lookup(cod_peripheral_type, minor & 0x0F);
            if (kind != nullptr && type != nullptr)
                return fmt::format("{}, {}", kind, type);
            if (kind != nullptr)
                return kind;
            if (type != nullptr)
                return type;
            return "Uncategorized";
        }
        case 0x06: {
            /* Any combination of these bits */
            std::string r;
            constexpr const char *imaging[] = {"Display", "Camera", "Scanner", "Printer"};
            for (unsigned int b = 0; b < std::size(imaging); b++) {
                if (minor & (0x04 << b)) {
                    if (r.length())
                        r += ", ";
                    r += imaging[b];
                }
            }
            return r.length() ? r : "Uncategorized";
        }
        case 0x07:
            n = lookup(cod_wearable, minor);
            break;
        case 0x08:
            n = lookup(cod_toy, minor);
            break;
        case 0x09:
            n = lookup(cod_health, minor);
            break;
        default:
            break;
    }

    if (n != nullptr)
        return n;

    if (minor == 0)
        return "Uncategorized";

    return fmt::format("Unknown ({})", minor);
}

std::vector<std::string> cod_service_names(uint32_t cod) {
    std::vector<std::string> r;

    for (const auto& s : cod_services)
        if (cod & (1U << s.code))
            r.push_back(s.name);

    return r;
}

std::string appearance_name(uint16_t appearance) {
    auto sub = lookup(appearance_subcategories, appearance);
    if (sub != nullptr)
        return sub;

    auto cat = lookup(appearance_categories, appearance >> 6);
    if (cat == nullptr)
        return fmt::format("Unknown (0x{:04x})", appearance);

    if ((appearance & 0x3F) == 0)
        return cat;

    return fmt::format("{} (0x{:04x})", cat, appearance);
}

}

