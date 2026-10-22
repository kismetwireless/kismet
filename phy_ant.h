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

#ifndef __PHY_ANT_H__
#define __PHY_ANT_H__

#include "config.h"

#include <string>

#include "globalregistry.h"
#include "packetchain.h"
#include "devicetracker.h"
#include "devicetracker_component.h"

/*
 * ANT and ANT+ (Garmin / Dynastream): heart-rate straps, bike speed, cadence and power sensors, foot
 * pods, fitness equipment, radars and lights, and the watches and head units that read them. GFSK
 * at 1 Mbit/s on 1 MHz channels from 2400 to 2524 MHz; ANT+ is always 2457 MHz.
 *
 * On the air an ANT packet is Nordic ShockBurst without the packet control field: a preamble, the
 * 2-octet network address (derived from the 8-octet network key; a6:c5 for ANT+), the device number
 * (least significant octet first), the device type (bit 7: the pairing bit), the transmission type,
 * a length (the payload's octets and the CRC's: 10), the 8-octet payload, and a CRC-16-CCITT over
 * the address to the payload.
 *
 * Read from SDR receivers that write ANT packets as pcap, such as w1700k's wifi-rx --ant-pcap, with
 * the pcapfile source: user link type 148 with the header below.
 */

// LINKTYPE_USER1, as an ANT packet with a 12-octet header: 'A' 'N' 'T', version 1, the RF channel
// (MHz - 2400), flags (bit 1 CRC ok, bit 3 bits repaired to make the CRC check, bit 4 the ANT+
// network), a reserved octet, the signal in dBm (int8), the address length (2), the payload length
// (8, 16 or 24), two reserved octets; then the network address, device number, device type,
// transmission type, length, payload and CRC as sent.
#ifndef KDLT_USER1
#define KDLT_USER1              148
#endif

#define ANT_HDR_LEN             12
#define ANT_PKT_HDR_LEN         7

class kis_ant_packinfo : public packet_component {
public:
    kis_ant_packinfo() { }

    void reset() {
        ant_plus = false;
        network = device_number = device_type = trans_type = 0;
        pairing = false;
        rf_channel = -1;
        payload.clear();
    }

    bool ant_plus = false;
    unsigned int network = 0;       // the 2-octet network address, as sent (a6c5 for ANT+)
    unsigned int device_number = 0;
    unsigned int device_type = 0;   // without the pairing bit
    bool pairing = false;
    unsigned int trans_type = 0;
    int rf_channel = -1;
    std::string payload;
};

class ant_tracked_device : public tracker_component {
public:
    ant_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    ant_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    ant_tracked_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    ant_tracked_device(const ant_tracked_device *p) :
        tracker_component{p} {

        __ImportField(network, p);
        __ImportField(ant_plus, p);
        __ImportField(device_number, p);
        __ImportField(device_type, p);
        __ImportField(device_type_name, p);
        __ImportField(trans_type, p);
        __ImportField(rf_channel, p);
        __ImportField(pairing_seen, p);
        __ImportField(last_page, p);
        __ImportField(last_payload, p);
        __ImportField(heart_rate, p);
        __ImportField(manufacturer_id, p);
        __ImportField(manufacturer, p);
        __ImportField(model, p);
        __ImportField(serial, p);
        __ImportField(sw_version, p);
        __ImportField(hw_version, p);
        __ImportField(battery_status, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("ant_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(network, std::string, std::string, std::string, network);
    __Proxy(ant_plus, uint8_t, bool, bool, ant_plus);
    __Proxy(device_number, uint16_t, uint16_t, uint16_t, device_number);
    __Proxy(device_type, uint8_t, uint8_t, uint8_t, device_type);
    __Proxy(device_type_name, std::string, std::string, std::string, device_type_name);
    __Proxy(trans_type, uint8_t, uint8_t, uint8_t, trans_type);
    __Proxy(rf_channel, int16_t, int16_t, int16_t, rf_channel);
    __Proxy(pairing_seen, uint8_t, bool, bool, pairing_seen);
    __Proxy(last_page, int16_t, int16_t, int16_t, last_page);
    __Proxy(last_payload, std::string, std::string, std::string, last_payload);
    __Proxy(heart_rate, uint16_t, uint16_t, uint16_t, heart_rate);
    __Proxy(manufacturer_id, uint16_t, uint16_t, uint16_t, manufacturer_id);
    __Proxy(manufacturer, std::string, std::string, std::string, manufacturer);
    __Proxy(model, uint16_t, uint16_t, uint16_t, model);
    __Proxy(serial, uint32_t, uint32_t, uint32_t, serial);
    __Proxy(sw_version, std::string, std::string, std::string, sw_version);
    __Proxy(hw_version, uint16_t, uint16_t, uint16_t, hw_version);
    __Proxy(battery_status, std::string, std::string, std::string, battery_status);

protected:

    virtual void register_fields() override {
        register_field("ant.device.network", "Network address (2 octets as sent; A6:C5 is ANT+)", &network);
        register_field("ant.device.ant_plus", "On the ANT+ network", &ant_plus);
        register_field("ant.device.device_number", "Device number", &device_number);
        register_field("ant.device.device_type", "Device type (without the pairing bit)", &device_type);
        register_field("ant.device.device_type_name", "Device type: the ANT+ device profile", &device_type_name);
        register_field("ant.device.trans_type", "Transmission type", &trans_type);
        register_field("ant.device.rf_channel", "RF channel (MHz - 2400)", &rf_channel);
        register_field("ant.device.pairing_seen", "Has sent with the pairing bit set", &pairing_seen);
        register_field("ant.device.last_page", "Last data page number (ANT+, -1 if none)", &last_page);
        register_field("ant.device.last_payload", "Last payload (hex)", &last_payload);
        register_field("ant.device.heart_rate", "Heart rate (bpm, ANT+ heart-rate monitor; 0 if none)", &heart_rate);
        register_field("ant.device.manufacturer_id", "ANT+ manufacturer ID (0 if not sent)", &manufacturer_id);
        register_field("ant.device.manufacturer", "Manufacturer (from its ANT+ manufacturer ID)", &manufacturer);
        register_field("ant.device.model", "Model number (0 if not sent)", &model);
        register_field("ant.device.serial", "Serial number (0 if not sent)", &serial);
        register_field("ant.device.sw_version", "Software version", &sw_version);
        register_field("ant.device.hw_version", "Hardware revision", &hw_version);
        register_field("ant.device.battery_status", "Battery status", &battery_status);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        if (e == nullptr) {
            set_rf_channel(-1);
            set_last_page(-1);
        }
    }

    std::shared_ptr<tracker_element_string> network;
    std::shared_ptr<tracker_element_uint8> ant_plus;
    std::shared_ptr<tracker_element_uint16> device_number;
    std::shared_ptr<tracker_element_uint8> device_type;
    std::shared_ptr<tracker_element_string> device_type_name;
    std::shared_ptr<tracker_element_uint8> trans_type;
    std::shared_ptr<tracker_element_int16> rf_channel;
    std::shared_ptr<tracker_element_uint8> pairing_seen;
    std::shared_ptr<tracker_element_int16> last_page;
    std::shared_ptr<tracker_element_string> last_payload;
    std::shared_ptr<tracker_element_uint16> heart_rate;
    std::shared_ptr<tracker_element_uint16> manufacturer_id;
    std::shared_ptr<tracker_element_string> manufacturer;
    std::shared_ptr<tracker_element_uint16> model;
    std::shared_ptr<tracker_element_uint32> serial;
    std::shared_ptr<tracker_element_string> sw_version;
    std::shared_ptr<tracker_element_uint16> hw_version;
    std::shared_ptr<tracker_element_string> battery_status;
};

class kis_ant_phy : public kis_phy_handler {
public:
    kis_ant_phy() :
        kis_phy_handler() { }

    kis_ant_phy(int in_phyid);

    virtual ~kis_ant_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_ant_phy(in_phyid);
    }

    static int dissector_ant(CHAINCALL_PARMS);
    static int classifier_ant(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int ant_device_entry_id;
    int pack_comp_linkframe;
    int pack_comp_ant;

    std::shared_ptr<tracker_element_string> ant_manuf;
};

#endif
