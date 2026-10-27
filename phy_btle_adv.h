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

#ifndef __PHY_BTLE_ADV_H__
#define __PHY_BTLE_ADV_H__

/* What both Bluetooth phys decode from advertising and EIR data beyond the basics:
 * company and UUID names, the classic Device ID, and the vendor and ecosystem formats
 * in bluetooth_parsers.  Kept as one dynamic record so devices without any of it
 * carry nothing. */

#include "config.h"

#include <stdint.h>
#include <time.h>

#include <memory>
#include <string>
#include <vector>

#include "globalregistry.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

#include "bluetooth_parsers/btle_adtypes.h"
#include "bluetooth_parsers/btle_continuity.h"
#include "bluetooth_parsers/btle_sensor.h"
#include "bluetooth_parsers/btle_vendor.h"

// Classic EIR Device ID: who made the device, and which product it is
class bt_tracked_device_id : public tracker_component {
public:
    bt_tracked_device_id() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_device_id(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_device_id(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_device_id");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(vendor_source, std::string, std::string, std::string, vendor_source);
    __Proxy(vendor, uint16_t, uint16_t, uint16_t, vendor);
    __Proxy(product, uint16_t, uint16_t, uint16_t, product);
    __Proxy(version, std::string, std::string, std::string, version);
    __ProxyTrackable(vendor_name, tracker_element_string, vendor_name);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("bluetooth.adv.device_id.vendor_source",
                "Assigner of the vendor ID (bluetooth or usb)", &vendor_source);
        register_field("bluetooth.adv.device_id.vendor", "Vendor ID", &vendor);
        register_field("bluetooth.adv.device_id.product", "Product ID", &product);
        register_field("bluetooth.adv.device_id.version", "Product version", &version);
    }

    std::shared_ptr<tracker_element_string> vendor_source;
    std::shared_ptr<tracker_element_uint16> vendor;
    std::shared_ptr<tracker_element_uint16> product;
    std::shared_ptr<tracker_element_string> version;
    std::shared_ptr<tracker_element_string> vendor_name;
};

// A Matter smart home device waiting to be commissioned
class bt_tracked_matter : public tracker_component {
public:
    bt_tracked_matter() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_matter(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_matter(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_matter");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(discriminator, uint16_t, uint16_t, uint16_t, discriminator);
    __Proxy(vendor_id, uint16_t, uint16_t, uint16_t, vendor_id);
    __Proxy(vendor_name, std::string, std::string, std::string, vendor_name);
    __Proxy(product_id, uint16_t, uint16_t, uint16_t, product_id);
    __Proxy(adv_version, uint8_t, uint8_t, uint8_t, adv_version);
    __Proxy(extended_announcement, uint8_t, bool, bool, extended_announcement);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("bluetooth.adv.matter.discriminator", "Commissioning discriminator",
                &discriminator);
        register_field("bluetooth.adv.matter.vendor_id", "CSA vendor ID", &vendor_id);
        register_field("bluetooth.adv.matter.vendor_name", "Vendor, when known", &vendor_name);
        register_field("bluetooth.adv.matter.product_id", "Vendor's product ID", &product_id);
        register_field("bluetooth.adv.matter.adv_version", "Advertisement version", &adv_version);
        register_field("bluetooth.adv.matter.extended_announcement",
                "Commissioning window opened for an extended period", &extended_announcement);
    }

    std::shared_ptr<tracker_element_uint16> discriminator;
    std::shared_ptr<tracker_element_uint16> vendor_id;
    std::shared_ptr<tracker_element_string> vendor_name;
    std::shared_ptr<tracker_element_uint16> product_id;
    std::shared_ptr<tracker_element_uint8> adv_version;
    std::shared_ptr<tracker_element_uint8> extended_announcement;
};

// Readings an environmental sensor advertises
class bt_tracked_sensor : public tracker_component {
public:
    bt_tracked_sensor() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_sensor(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_sensor(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_sensor");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(source, std::string, std::string, std::string, source);
    __ProxyDynamic(temperature, double, double, double, temperature, temperature_id);
    __ProxyDynamic(humidity, double, double, double, humidity, humidity_id);
    __ProxyDynamic(pressure, double, double, double, pressure, pressure_id);
    __ProxyDynamic(battery_mv, uint32_t, uint32_t, uint32_t, battery_mv, battery_mv_id);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("bluetooth.adv.sensor.source", "Sensor advertisement format", &source);
        temperature_id =
            register_dynamic_field("bluetooth.adv.sensor.temperature", "Temperature, C",
                    &temperature);
        humidity_id =
            register_dynamic_field("bluetooth.adv.sensor.humidity", "Relative humidity, %",
                    &humidity);
        pressure_id =
            register_dynamic_field("bluetooth.adv.sensor.pressure", "Air pressure, hPa", &pressure);
        battery_mv_id =
            register_dynamic_field("bluetooth.adv.sensor.battery_mv", "Battery voltage, mV",
                    &battery_mv);
        register_field("bluetooth.adv.sensor.last_time", "Last reading", &last_time);
    }

    std::shared_ptr<tracker_element_string> source;
    std::shared_ptr<tracker_element_double> temperature;
    uint16_t temperature_id;
    std::shared_ptr<tracker_element_double> humidity;
    uint16_t humidity_id;
    std::shared_ptr<tracker_element_double> pressure;
    uint16_t pressure_id;
    std::shared_ptr<tracker_element_uint32> battery_mv;
    uint16_t battery_mv_id;
    std::shared_ptr<tracker_element_uint64> last_time;
};

// Bluetooth mesh beacons and services
class bt_tracked_mesh : public tracker_component {
public:
    bt_tracked_mesh() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_mesh(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_mesh(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_mesh");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __ProxyDynamic(beacon, std::string, std::string, std::string, beacon, beacon_id);
    __ProxyDynamic(network_id, std::string, std::string, std::string, network_id, network_id_id);
    __ProxyDynamic(iv_index, uint32_t, uint32_t, uint32_t, iv_index, iv_index_id);
    __ProxyDynamic(key_refresh, uint8_t, uint8_t, uint8_t, key_refresh, key_refresh_id);
    __ProxyDynamic(iv_update, uint8_t, uint8_t, uint8_t, iv_update, iv_update_id);
    __ProxyDynamic(device_uuid, std::string, std::string, std::string, device_uuid, device_uuid_id);
    __ProxyDynamic(oob_info, std::string, std::string, std::string, oob_info, oob_info_id);
    __ProxyDynamic(proxy, std::string, std::string, std::string, proxy, proxy_id);
    __ProxyDynamic(message, uint8_t, uint8_t, uint8_t, message, message_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        beacon_id =
            register_dynamic_field("bluetooth.adv.mesh.beacon", "Mesh beacon type", &beacon);
        network_id_id =
            register_dynamic_field("bluetooth.adv.mesh.network_id", "Mesh network ID", &network_id);
        iv_index_id =
            register_dynamic_field("bluetooth.adv.mesh.iv_index", "Mesh IV index", &iv_index);
        key_refresh_id =
            register_dynamic_field("bluetooth.adv.mesh.key_refresh", "Mesh key refresh in progress",
                    &key_refresh);
        iv_update_id =
            register_dynamic_field("bluetooth.adv.mesh.iv_update", "Mesh IV update in progress",
                    &iv_update);
        device_uuid_id =
            register_dynamic_field("bluetooth.adv.mesh.device_uuid",
                    "UUID of an unprovisioned mesh device", &device_uuid);
        oob_info_id =
            register_dynamic_field("bluetooth.adv.mesh.oob_info",
                    "Provisioning OOB information an unprovisioned device offers", &oob_info);
        proxy_id =
            register_dynamic_field("bluetooth.adv.mesh.proxy", "Mesh proxy identification type",
                    &proxy);
        message_id =
            register_dynamic_field("bluetooth.adv.mesh.message",
                    "Device sends mesh network messages", &message);
    }

    std::shared_ptr<tracker_element_string> beacon;
    uint16_t beacon_id;
    std::shared_ptr<tracker_element_string> network_id;
    uint16_t network_id_id;
    std::shared_ptr<tracker_element_uint32> iv_index;
    uint16_t iv_index_id;
    std::shared_ptr<tracker_element_uint8> key_refresh;
    uint16_t key_refresh_id;
    std::shared_ptr<tracker_element_uint8> iv_update;
    uint16_t iv_update_id;
    std::shared_ptr<tracker_element_string> device_uuid;
    uint16_t device_uuid_id;
    std::shared_ptr<tracker_element_string> oob_info;
    uint16_t oob_info_id;
    std::shared_ptr<tracker_element_string> proxy;
    uint16_t proxy_id;
    std::shared_ptr<tracker_element_uint8> message;
    uint16_t message_id;
};

// LE Audio broadcast and unicast announcements
class bt_tracked_audio : public tracker_component {
public:
    bt_tracked_audio() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_audio(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_audio(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_audio");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __ProxyDynamic(broadcast_name, std::string, std::string, std::string, broadcast_name,
            broadcast_name_id);
    __ProxyDynamic(broadcast_id, std::string, std::string, std::string, broadcast_id,
            broadcast_id_id);
    __ProxyDynamic(program_info, std::string, std::string, std::string, program_info,
            program_info_id);
    __ProxyDynamic(language, std::string, std::string, std::string, language, language_id);
    __ProxyDynamic(encrypted, uint8_t, uint8_t, uint8_t, encrypted, encrypted_id);
    __ProxyDynamic(quality, std::string, std::string, std::string, quality, quality_id);
    __ProxyDynamic(unicast, std::string, std::string, std::string, unicast, unicast_id);
    __ProxyDynamic(sink_contexts, std::string, std::string, std::string, sink_contexts,
            sink_contexts_id);
    __ProxyDynamic(source_contexts, std::string, std::string, std::string, source_contexts,
            source_contexts_id);
    __ProxyDynamic(coordinated_set, std::string, std::string, std::string, coordinated_set,
            coordinated_set_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        broadcast_name_id =
            register_dynamic_field("bluetooth.adv.audio.broadcast_name", "Auracast broadcast name",
                    &broadcast_name);
        broadcast_id_id =
            register_dynamic_field("bluetooth.adv.audio.broadcast_id", "Broadcast audio ID",
                    &broadcast_id);
        program_info_id =
            register_dynamic_field("bluetooth.adv.audio.program_info",
                    "Public broadcast program info", &program_info);
        language_id =
            register_dynamic_field("bluetooth.adv.audio.language", "Public broadcast language",
                    &language);
        encrypted_id =
            register_dynamic_field("bluetooth.adv.audio.encrypted", "Public broadcast is encrypted",
                    &encrypted);
        quality_id =
            register_dynamic_field("bluetooth.adv.audio.quality", "Public broadcast audio quality",
                    &quality);
        unicast_id =
            register_dynamic_field("bluetooth.adv.audio.unicast",
                    "Unicast audio announcement (ASCS or CAS, general or targeted)", &unicast);
        sink_contexts_id =
            register_dynamic_field("bluetooth.adv.audio.sink_contexts",
                    "Audio contexts available as a sink", &sink_contexts);
        source_contexts_id =
            register_dynamic_field("bluetooth.adv.audio.source_contexts",
                    "Audio contexts available as a source", &source_contexts);
        coordinated_set_id =
            register_dynamic_field("bluetooth.adv.audio.set_id",
                    "Resolvable set identifier of a coordinated set (earbuds, hearing aids)",
                    &coordinated_set);
    }

    std::shared_ptr<tracker_element_string> broadcast_name;
    uint16_t broadcast_name_id;
    std::shared_ptr<tracker_element_string> broadcast_id;
    uint16_t broadcast_id_id;
    std::shared_ptr<tracker_element_string> program_info;
    uint16_t program_info_id;
    std::shared_ptr<tracker_element_string> language;
    uint16_t language_id;
    std::shared_ptr<tracker_element_uint8> encrypted;
    uint16_t encrypted_id;
    std::shared_ptr<tracker_element_string> quality;
    uint16_t quality_id;
    std::shared_ptr<tracker_element_string> unicast;
    uint16_t unicast_id;
    std::shared_ptr<tracker_element_string> sink_contexts;
    uint16_t sink_contexts_id;
    std::shared_ptr<tracker_element_string> source_contexts;
    uint16_t source_contexts_id;
    std::shared_ptr<tracker_element_string> coordinated_set;
    uint16_t coordinated_set_id;
};

// Indoor Positioning service location a beacon advertises
class bt_tracked_indoor : public tracker_component {
public:
    bt_tracked_indoor() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_indoor(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_indoor(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_indoor");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __ProxyDynamic(latitude, double, double, double, latitude, latitude_id);
    __ProxyDynamic(longitude, double, double, double, longitude, longitude_id);
    __ProxyDynamic(north_dm, int16_t, int16_t, int16_t, north_dm, north_dm_id);
    __ProxyDynamic(east_dm, int16_t, int16_t, int16_t, east_dm, east_dm_id);
    __ProxyDynamic(floor, int32_t, int32_t, int32_t, floor, floor_id);
    __ProxyDynamic(altitude_dm, int32_t, int32_t, int32_t, altitude_dm, altitude_dm_id);
    __ProxyDynamic(tx_power, int8_t, int8_t, int8_t, tx_power, tx_power_id);
    __ProxyDynamic(mobile, uint8_t, uint8_t, uint8_t, mobile, mobile_id);
    __ProxyDynamic(precision, uint8_t, uint8_t, uint8_t, precision, precision_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        latitude_id =
            register_dynamic_field("bluetooth.adv.indoor.latitude", "Advertised latitude",
                    &latitude);
        longitude_id =
            register_dynamic_field("bluetooth.adv.indoor.longitude", "Advertised longitude",
                    &longitude);
        north_dm_id =
            register_dynamic_field("bluetooth.adv.indoor.north_dm",
                    "Advertised local north coordinate, decimeters", &north_dm);
        east_dm_id =
            register_dynamic_field("bluetooth.adv.indoor.east_dm",
                    "Advertised local east coordinate, decimeters", &east_dm);
        floor_id =
            register_dynamic_field("bluetooth.adv.indoor.floor", "Advertised floor number", &floor);
        altitude_dm_id =
            register_dynamic_field("bluetooth.adv.indoor.altitude_dm",
                    "Advertised altitude, decimeters", &altitude_dm);
        tx_power_id =
            register_dynamic_field("bluetooth.adv.indoor.tx_power", "Advertised transmit power",
                    &tx_power);
        mobile_id =
            register_dynamic_field("bluetooth.adv.indoor.mobile", "Advertised position is mobile",
                    &mobile);
        precision_id =
            register_dynamic_field("bluetooth.adv.indoor.precision",
                    "Position precision code, 0 (under 0.1 m) to 6 (over 50 m)", &precision);
    }

    std::shared_ptr<tracker_element_double> latitude;
    uint16_t latitude_id;
    std::shared_ptr<tracker_element_double> longitude;
    uint16_t longitude_id;
    std::shared_ptr<tracker_element_int16> north_dm;
    uint16_t north_dm_id;
    std::shared_ptr<tracker_element_int16> east_dm;
    uint16_t east_dm_id;
    std::shared_ptr<tracker_element_int32> floor;
    uint16_t floor_id;
    std::shared_ptr<tracker_element_int32> altitude_dm;
    uint16_t altitude_dm_id;
    std::shared_ptr<tracker_element_int8> tx_power;
    uint16_t tx_power_id;
    std::shared_ptr<tracker_element_uint8> mobile;
    uint16_t mobile_id;
    std::shared_ptr<tracker_element_uint8> precision;
    uint16_t precision_id;
};

// Apple Continuity messages; the identifying hashes and counters some carry are never kept
class bt_tracked_continuity : public tracker_component {
public:
    bt_tracked_continuity() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_continuity(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_continuity(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_continuity");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(seen_types, uint32_t, uint32_t, uint32_t, seen_types);
    __Proxy(messages, std::string, std::string, std::string, messages);
    __ProxyDynamic(activity, std::string, std::string, std::string, activity, activity_id);
    __ProxyDynamic(wifi_on, uint8_t, uint8_t, uint8_t, wifi_on, wifi_on_id);
    __ProxyDynamic(airdrop_receiving, uint8_t, uint8_t, uint8_t, airdrop_receiving,
            airdrop_receiving_id);
    __ProxyDynamic(nearby_action, std::string, std::string, std::string, nearby_action,
            nearby_action_id);
    __ProxyDynamic(setup_device, std::string, std::string, std::string, setup_device,
            setup_device_id);
    __ProxyDynamic(homekit_category, std::string, std::string, std::string, homekit_category,
            homekit_category_id);
    __ProxyDynamic(homekit_id, std::string, std::string, std::string, homekit_id, homekit_id_id);
    __ProxyDynamic(homekit_paired, uint8_t, uint8_t, uint8_t, homekit_paired, homekit_paired_id);
    __ProxyDynamic(homekit_config, uint8_t, uint8_t, uint8_t, homekit_config, homekit_config_id);
    __ProxyDynamic(airplay_ipv4, std::string, std::string, std::string, airplay_ipv4,
            airplay_ipv4_id);
    __ProxyDynamic(airprint_address, std::string, std::string, std::string, airprint_address,
            airprint_address_id);
    __ProxyDynamic(hotspot_battery, uint8_t, uint8_t, uint8_t, hotspot_battery, hotspot_battery_id);
    __ProxyDynamic(hotspot_network, std::string, std::string, std::string, hotspot_network,
            hotspot_network_id);
    __ProxyDynamic(hotspot_bars, uint8_t, uint8_t, uint8_t, hotspot_bars, hotspot_bars_id);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("bluetooth.adv.continuity.seen_types",
                "Bitmask of the Continuity message types seen", &seen_types);
        register_field("bluetooth.adv.continuity.messages",
                "Continuity message types seen", &messages);
        activity_id =
            register_dynamic_field("bluetooth.adv.continuity.activity",
                    "Nearby Info activity (screen on, on a call, driving, ...)", &activity);
        wifi_on_id =
            register_dynamic_field("bluetooth.adv.continuity.wifi_on", "Nearby Info: Wi-Fi is on",
                    &wifi_on);
        airdrop_receiving_id =
            register_dynamic_field("bluetooth.adv.continuity.airdrop_receiving",
                    "Nearby Info: AirDrop receiving is on", &airdrop_receiving);
        nearby_action_id =
            register_dynamic_field("bluetooth.adv.continuity.nearby_action",
                    "Nearby Action (Wi-Fi password sharing, setup, ...)", &nearby_action);
        setup_device_id =
            register_dynamic_field("bluetooth.adv.continuity.setup_device",
                    "Kind of device being set up", &setup_device);
        homekit_category_id =
            register_dynamic_field("bluetooth.adv.continuity.homekit.category",
                    "HomeKit accessory category", &homekit_category);
        homekit_id_id =
            register_dynamic_field("bluetooth.adv.continuity.homekit.device_id",
                    "HomeKit accessory device ID", &homekit_id);
        homekit_paired_id =
            register_dynamic_field("bluetooth.adv.continuity.homekit.paired",
                    "HomeKit accessory is paired", &homekit_paired);
        homekit_config_id =
            register_dynamic_field("bluetooth.adv.continuity.homekit.config_number",
                    "HomeKit configuration number", &homekit_config);
        airplay_ipv4_id =
            register_dynamic_field("bluetooth.adv.continuity.airplay_ipv4",
                    "IPv4 address an AirPlay target advertises", &airplay_ipv4);
        airprint_address_id =
            register_dynamic_field("bluetooth.adv.continuity.airprint_address",
                    "Address an AirPrint printer advertises", &airprint_address);
        hotspot_battery_id =
            register_dynamic_field("bluetooth.adv.continuity.hotspot.battery",
                    "Hotspot battery, percent", &hotspot_battery);
        hotspot_network_id =
            register_dynamic_field("bluetooth.adv.continuity.hotspot.network",
                    "Hotspot cellular network type", &hotspot_network);
        hotspot_bars_id =
            register_dynamic_field("bluetooth.adv.continuity.hotspot.signal_bars",
                    "Hotspot cellular signal bars", &hotspot_bars);
        register_field("bluetooth.adv.continuity.last_time", "Last Continuity message",
                &last_time);
    }

    std::shared_ptr<tracker_element_uint32> seen_types;
    std::shared_ptr<tracker_element_string> messages;
    std::shared_ptr<tracker_element_string> activity;
    uint16_t activity_id;
    std::shared_ptr<tracker_element_uint8> wifi_on;
    uint16_t wifi_on_id;
    std::shared_ptr<tracker_element_uint8> airdrop_receiving;
    uint16_t airdrop_receiving_id;
    std::shared_ptr<tracker_element_string> nearby_action;
    uint16_t nearby_action_id;
    std::shared_ptr<tracker_element_string> setup_device;
    uint16_t setup_device_id;
    std::shared_ptr<tracker_element_string> homekit_category;
    uint16_t homekit_category_id;
    std::shared_ptr<tracker_element_string> homekit_id;
    uint16_t homekit_id_id;
    std::shared_ptr<tracker_element_uint8> homekit_paired;
    uint16_t homekit_paired_id;
    std::shared_ptr<tracker_element_uint8> homekit_config;
    uint16_t homekit_config_id;
    std::shared_ptr<tracker_element_string> airplay_ipv4;
    uint16_t airplay_ipv4_id;
    std::shared_ptr<tracker_element_string> airprint_address;
    uint16_t airprint_address_id;
    std::shared_ptr<tracker_element_uint8> hotspot_battery;
    uint16_t hotspot_battery_id;
    std::shared_ptr<tracker_element_string> hotspot_network;
    uint16_t hotspot_network_id;
    std::shared_ptr<tracker_element_uint8> hotspot_bars;
    uint16_t hotspot_bars_id;
    std::shared_ptr<tracker_element_uint64> last_time;
};

class bt_tracked_adv : public tracker_component {
public:
    bt_tracked_adv() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_adv(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    bt_tracked_adv(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("bt_tracked_adv");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    // Shared name records from the company and UUID tables
    __ProxyTrackable(company_name, tracker_element_string, company_name);
    __ProxyDynamicTrackable(service_names, tracker_element_vector, service_names, service_names_id);

    __ProxyDynamic(service_class, std::string, std::string, std::string, service_class,
            service_class_id);

    __ProxyDynamicTrackable(device_id, bt_tracked_device_id, device_id, device_id_id);

    __ProxyDynamic(microsoft_device, std::string, std::string, std::string, microsoft_device,
            microsoft_device_id);
    __ProxyDynamic(swift_pair_name, std::string, std::string, std::string, swift_pair_name,
            swift_pair_name_id);
    __ProxyDynamic(fast_pair_model, std::string, std::string, std::string, fast_pair_model,
            fast_pair_model_id);
    __ProxyDynamicTrackable(matter, bt_tracked_matter, matter, matter_id);
    __ProxyDynamic(vehicle, std::string, std::string, std::string, vehicle, vehicle_id);
    __ProxyDynamicTrackable(sensor, bt_tracked_sensor, sensor, sensor_id);
    __ProxyDynamicTrackable(continuity, bt_tracked_continuity, continuity, continuity_id);
    __ProxyDynamicTrackable(mesh, bt_tracked_mesh, mesh, mesh_id);
    __ProxyDynamicTrackable(audio, bt_tracked_audio, audio, audio_id);
    __ProxyDynamicTrackable(indoor, bt_tracked_indoor, indoor, indoor_id);
    __ProxyDynamic(uri, std::string, std::string, std::string, uri, uri_id);
    __ProxyDynamic(adv_interval_us, uint64_t, uint64_t, uint64_t, adv_interval_us,
            adv_interval_us_id);
    __ProxyDynamic(le_role, std::string, std::string, std::string, le_role, le_role_id);
    __ProxyDynamic(conn_interval_min_us, uint32_t, uint32_t, uint32_t, conn_interval_min_us,
            conn_interval_min_us_id);
    __ProxyDynamic(conn_interval_max_us, uint32_t, uint32_t, uint32_t, conn_interval_max_us,
            conn_interval_max_us_id);
    __ProxyDynamic(le_features, std::string, std::string, std::string, le_features, le_features_id);
    __ProxyDynamic(transports, std::string, std::string, std::string, transports, transports_id);

    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        service_names_id =
            register_dynamic_field("bluetooth.adv.service_names", "Names of the advertised services",
                    &service_names);
        service_class_id =
            register_dynamic_field("bluetooth.adv.service_class",
                    "Kind of device its services suggest (hearing aid, glucose monitor, ...)",
                    &service_class);
        device_id_id =
            register_dynamic_field("bluetooth.adv.device_id", "Device ID record", &device_id);

        microsoft_device_id =
            register_dynamic_field("bluetooth.adv.microsoft_device",
                    "Device type from a Microsoft Connected Devices beacon", &microsoft_device);
        swift_pair_name_id =
            register_dynamic_field("bluetooth.adv.swift_pair_name",
                    "Name offered for Windows Swift Pair", &swift_pair_name);
        fast_pair_model_id =
            register_dynamic_field("bluetooth.adv.fast_pair_model",
                    "Google Fast Pair model ID, while pairable", &fast_pair_model);
        matter_id =
            register_dynamic_field("bluetooth.adv.matter", "Matter commissioning", &matter);
        vehicle_id =
            register_dynamic_field("bluetooth.adv.vehicle",
                    "Vehicle maker or digital key, from the name or services", &vehicle);
        sensor_id =
            register_dynamic_field("bluetooth.adv.sensor", "Environmental sensor readings",
                    &sensor);
        continuity_id =
            register_dynamic_field("bluetooth.adv.continuity", "Apple Continuity messages",
                    &continuity);
        mesh_id =
            register_dynamic_field("bluetooth.adv.mesh", "Bluetooth mesh", &mesh);
        audio_id =
            register_dynamic_field("bluetooth.adv.audio", "LE Audio announcements", &audio);
        indoor_id =
            register_dynamic_field("bluetooth.adv.indoor", "Indoor Positioning location", &indoor);
        uri_id =
            register_dynamic_field("bluetooth.adv.uri", "Advertised URI", &uri);
        adv_interval_us_id =
            register_dynamic_field("bluetooth.adv.adv_interval_us",
                    "Advertised advertising interval, microseconds", &adv_interval_us);
        le_role_id =
            register_dynamic_field("bluetooth.adv.le_role", "Advertised LE role", &le_role);
        conn_interval_min_us_id =
            register_dynamic_field("bluetooth.adv.conn_interval_min_us",
                    "Preferred minimum connection interval, microseconds", &conn_interval_min_us);
        conn_interval_max_us_id =
            register_dynamic_field("bluetooth.adv.conn_interval_max_us",
                    "Preferred maximum connection interval, microseconds", &conn_interval_max_us);
        le_features_id =
            register_dynamic_field("bluetooth.adv.le_features",
                    "Advertised LE supported features, hex", &le_features);
        transports_id =
            register_dynamic_field("bluetooth.adv.transports",
                    "Transports offered over Transport Discovery", &transports);

        register_field("bluetooth.adv.last_time", "Last time any of this was seen", &last_time);
    }

    std::shared_ptr<tracker_element_string> company_name;
    std::shared_ptr<tracker_element_vector> service_names;
    uint16_t service_names_id;
    std::shared_ptr<tracker_element_string> service_class;
    uint16_t service_class_id;
    std::shared_ptr<bt_tracked_device_id> device_id;
    uint16_t device_id_id;

    std::shared_ptr<tracker_element_string> microsoft_device;
    uint16_t microsoft_device_id;
    std::shared_ptr<tracker_element_string> swift_pair_name;
    uint16_t swift_pair_name_id;
    std::shared_ptr<tracker_element_string> fast_pair_model;
    uint16_t fast_pair_model_id;
    std::shared_ptr<bt_tracked_matter> matter;
    uint16_t matter_id;
    std::shared_ptr<tracker_element_string> vehicle;
    uint16_t vehicle_id;
    std::shared_ptr<bt_tracked_sensor> sensor;
    uint16_t sensor_id;
    std::shared_ptr<bt_tracked_continuity> continuity;
    uint16_t continuity_id;
    std::shared_ptr<bt_tracked_mesh> mesh;
    uint16_t mesh_id;
    std::shared_ptr<bt_tracked_audio> audio;
    uint16_t audio_id;
    std::shared_ptr<bt_tracked_indoor> indoor;
    uint16_t indoor_id;
    std::shared_ptr<tracker_element_string> uri;
    uint16_t uri_id;
    std::shared_ptr<tracker_element_uint64> adv_interval_us;
    uint16_t adv_interval_us_id;
    std::shared_ptr<tracker_element_string> le_role;
    uint16_t le_role_id;
    std::shared_ptr<tracker_element_uint32> conn_interval_min_us;
    uint16_t conn_interval_min_us_id;
    std::shared_ptr<tracker_element_uint32> conn_interval_max_us;
    uint16_t conn_interval_max_us_id;
    std::shared_ptr<tracker_element_string> le_features;
    uint16_t le_features_id;
    std::shared_ptr<tracker_element_string> transports;
    uint16_t transports_id;
    std::shared_ptr<tracker_element_uint64> last_time;
};

// Everything decoded from one advertisement or EIR block
struct bt_adv_decode {
    int company_id = -1;

    // 16 bit UUIDs advertised as services or service data, for the names and class
    std::vector<uint16_t> uuid16;

    std::string name;

    bool has_device_id = false;
    uint16_t did_source = 0;
    uint16_t did_vendor = 0;
    uint16_t did_product = 0;
    uint16_t did_version = 0;

    bool has_microsoft = false;
    btle_vendor::microsoft_info microsoft;
    bool has_fastpair = false;
    btle_vendor::fastpair_info fastpair;
    bool has_matter = false;
    btle_vendor::matter_info matter;
    bool has_digital_key = false;
    bool has_sensor = false;
    btle_sensor::info sensor;
    bool has_continuity = false;
    btle_continuity::info continuity;

    bool has_mesh_beacon = false;
    btle_adtypes::mesh_beacon mesh_beacon;
    bool has_mesh_proxy = false;
    btle_adtypes::mesh_proxy mesh_proxy;
    bool has_mesh_prov = false;
    btle_adtypes::mesh_provisioning mesh_prov;
    bool has_mesh_message = false;

    std::string broadcast_name;
    bool has_broadcast = false;
    btle_adtypes::broadcast_audio broadcast;
    bool has_public_broadcast = false;
    btle_adtypes::public_broadcast public_broadcast;
    bool has_unicast = false;
    btle_adtypes::unicast_announcement unicast;
    std::string coordinated_set;

    bool has_indoor = false;
    btle_adtypes::indoor_positioning indoor;

    std::string uri;
    uint64_t adv_interval_us = 0;
    bool has_le_role = false;
    btle_adtypes::le_role role = btle_adtypes::le_role::peripheral_only;
    bool has_conn_interval = false;
    btle_adtypes::conn_interval_range conn_interval;
    std::string le_features;
    bool has_tds = false;
    btle_adtypes::transport_discovery tds;

    // Feed one AD or EIR structure: its type and the bytes after it
    void ad(uint8_t type, const uint8_t *data, size_t len);

    // Feed a whole AD or EIR block of length, type, data structures
    void block(const uint8_t *data, size_t len);

    bool any() const;
};

class kis_bt_manuf;
class kis_bt_oid;

void apply_adv(bt_tracked_adv& adv, const bt_adv_decode& d, kis_bt_manuf *btmanuf,
        kis_bt_oid *btoid, time_t now);

#endif
