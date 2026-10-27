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

#ifndef __PHY_BTLE_H__
#define __PHY_BTLE_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "randomized_alias.h"

#include "bluetooth_parsers/btle_tracker.h"
#include "bluetooth_ids.h"
#include "phy_btle_adv.h"

class bluetooth_btle;

class btle_tracked_advertised_service : public tracker_component {
public:
    btle_tracked_advertised_service() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_advertised_service(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_advertised_service(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_advertised_service");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

protected:
    virtual void register_fields() override {
        // Manufacturer is added in dynamically
        tracker_component::register_fields();
        register_field("btle.short_service.uuid", "16bit service UUID", &short_uuid);
        register_field("btle.short_service.data", "Service data", &advertised_data);
    }

    std::shared_ptr<tracker_element_uint16> short_uuid;
    std::shared_ptr<tracker_element_byte_array> advertised_data;
};

// Location tracker (item finder) state decoded from the advertisements; only present
// on devices which advertised as a known tracker.  Vendor specific values are dynamic
// so a tracker type only carries the fields it advertises.
class btle_tracked_tracker : public tracker_component {
public:
    btle_tracked_tracker() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_tracker(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_tracker(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_tracker");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(tracker_type, std::string, std::string, std::string, tracker_type);
    __Proxy(state, uint8_t, uint8_t, uint8_t, state);
    __Proxy(state_name, std::string, std::string, std::string, state_name);
    __Proxy(separated, uint8_t, bool, bool, separated);
    __Proxy(battery, std::string, std::string, std::string, battery);
    __Proxy(flags, uint8_t, uint8_t, uint8_t, flags);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __ProxyDynamic(uwb, uint8_t, bool, bool, uwb, uwb_id);
    __ProxyDynamic(aging_counter, uint32_t, uint32_t, uint32_t, aging_counter, aging_counter_id);
    __ProxyDynamic(privacy_id, std::string, std::string, std::string, privacy_id, privacy_id_id);
    __ProxyDynamic(subtype, std::string, std::string, std::string, subtype, subtype_id);
    __ProxyDynamic(ephemeral_id, std::string, std::string, std::string, ephemeral_id, ephemeral_id_id);
    __ProxyDynamic(network_id, uint8_t, uint8_t, uint8_t, network_id, network_id_id);
    __ProxyDynamic(maintained, uint8_t, bool, bool, maintained, maintained_id);
    __ProxyDynamic(follow_time, uint64_t, uint64_t, uint64_t, follow_time, follow_time_id);
    __ProxyDynamic(follow_locations, uint8_t, uint8_t, uint8_t, follow_locations, follow_locations_id);

    // Following state, not exported; see tracker_follow_check
    time_t follow_first = 0;
    time_t follow_last = 0;
    bool follow_alerted = false;
    std::vector<std::pair<double, double>> follow_points;

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.tracker.type",
                "Tracker type (samsung_smarttag, apple_findmy, google_fmdn, dult, tile, chipolo, "
                "pebblebee)", &tracker_type);
        register_field("btle.device.tracker.state", "Raw operating state advertised by the tracker",
                &state);
        register_field("btle.device.tracker.state_name",
                "Operating state (premature_offline, offline, overmature_offline, connected, "
                "separated, near_owner, normal, unwanted_tracking_protection, activated, "
                "not_activated, unknown)",
                &state_name);
        register_field("btle.device.tracker.separated",
                "Tracker advertises that it is away from its owner", &separated);
        register_field("btle.device.tracker.battery",
                "Battery level (full, medium, low, very_low, unknown)", &battery);
        register_field("btle.device.tracker.flags", "Raw flags byte advertised by the tracker", &flags);
        register_field("btle.device.tracker.last_time", "Last time a tracker advertisement was seen",
                &last_time);

        uwb_id =
            register_dynamic_field("btle.device.tracker.uwb", "Tracker supports UWB ranging", &uwb);
        aging_counter_id =
            register_dynamic_field("btle.device.tracker.aging_counter",
                    "Aging counter advertised by the tracker", &aging_counter);
        privacy_id_id =
            register_dynamic_field("btle.device.tracker.privacy_id",
                    "Rotating privacy ID advertised by the tracker (hex); a salted hash for "
                    "Tile", &privacy_id);
        subtype_id =
            register_dynamic_field("btle.device.tracker.subtype",
                    "Kind of device within the tracker type (airtag, findmy_accessory, airpods)",
                    &subtype);
        ephemeral_id_id =
            register_dynamic_field("btle.device.tracker.ephemeral_id",
                    "Ephemeral identifier advertised by the tracker, rotates every 1024 seconds; "
                    "a salted hash, never the identifier itself",
                    &ephemeral_id);
        network_id_id =
            register_dynamic_field("btle.device.tracker.network_id",
                    "Finding network ID from the DULT advertisement", &network_id);
        maintained_id =
            register_dynamic_field("btle.device.tracker.maintained",
                    "Owner connected to the tracker within the current key period", &maintained);
        follow_time_id =
            register_dynamic_field("btle.device.tracker.follow_time",
                    "Seconds the tracker has been seen continuously while separated", &follow_time);
        follow_locations_id =
            register_dynamic_field("btle.device.tracker.follow_locations",
                    "Distinct locations the separated tracker was seen at", &follow_locations);
    }

    std::shared_ptr<tracker_element_string> tracker_type;
    std::shared_ptr<tracker_element_uint8> state;
    std::shared_ptr<tracker_element_string> state_name;
    std::shared_ptr<tracker_element_uint8> separated;
    std::shared_ptr<tracker_element_string> battery;
    std::shared_ptr<tracker_element_uint8> flags;
    std::shared_ptr<tracker_element_uint64> last_time;

    std::shared_ptr<tracker_element_uint8> uwb;
    uint16_t uwb_id;
    std::shared_ptr<tracker_element_uint32> aging_counter;
    uint16_t aging_counter_id;
    std::shared_ptr<tracker_element_string> privacy_id;
    uint16_t privacy_id_id;
    std::shared_ptr<tracker_element_string> subtype;
    uint16_t subtype_id;
    std::shared_ptr<tracker_element_string> ephemeral_id;
    uint16_t ephemeral_id_id;
    std::shared_ptr<tracker_element_uint8> network_id;
    uint16_t network_id_id;
    std::shared_ptr<tracker_element_uint8> maintained;
    uint16_t maintained_id;
    std::shared_ptr<tracker_element_uint64> follow_time;
    uint16_t follow_time_id;
    std::shared_ptr<tracker_element_uint8> follow_locations;
    uint16_t follow_locations_id;
};

// Every tracker advertisement in one packet, filled from its AD records by the BTLE and
// Bluetooth (HCI) phys
struct btle_tracker_frames {
    btle_tracker::smarttag_info smarttag;
    bool is_smarttag = false;
    btle_tracker::findmy_info findmy;
    bool is_findmy = false;
    btle_tracker::fmdn_info fmdn;
    bool is_fmdn = false;
    btle_tracker::dult_info dult;
    bool is_dult = false;
    btle_tracker::identified_info identified;
    bool is_identified = false;

    // Manufacturer data and 16-bit service data: ID then payload
    void manuf_data(const uint8_t *data, size_t len);
    void service_data(const uint8_t *data, size_t len);
    void service_uuid(uint16_t uuid);

    bool any() const {
        return is_smarttag || is_findmy || is_fmdn || is_dult || is_identified;
    }

    // For the new device message
    std::string describe() const;
};

// Callers hold the device list lock
void apply_tracker_frames(btle_tracked_tracker& tracker, const btle_tracker_frames& frames,
        time_t now);

// Hex of a truncated SHA-256 of the tracker type and identifier, salted with a value
// picked once per run: it links advertisements within this run without exposing the
// identifier or matching across logs
std::string tracker_privacy_hash(btle_tracker::tracker_type type, const std::string& material);

// Tracks how long and across how many places a separated tracker has been seen; true
// while it is over the following thresholds and follow_alerted isn't set yet
bool tracker_follow_check(btle_tracked_tracker& tracker, const kis_gps_packinfo& gps, time_t now);
std::string tracker_follow_text(btle_tracked_tracker& tracker);

// Raised by the BTLE and Bluetooth phys
int activate_tracker_follow_alert(const std::shared_ptr<alert_tracker>& alertracker, int phyid);

// Battery level advertised in the clear (see bluetooth_parsers/btle_battery.h); only
// present on devices which advertised one.  Percents are -1 when not known.
class btle_tracked_battery : public tracker_component {
public:
    btle_tracked_battery() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_battery(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_battery(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_battery");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(source, std::string, std::string, std::string, source);
    __Proxy(percent, int8_t, int8_t, int8_t, percent);
    __Proxy(charging, uint8_t, bool, bool, charging);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __ProxyDynamic(millivolts, uint16_t, uint16_t, uint16_t, millivolts, millivolts_id);
    __ProxyDynamic(left_percent, int8_t, int8_t, int8_t, left_percent, left_percent_id);
    __ProxyDynamic(left_charging, uint8_t, bool, bool, left_charging, left_charging_id);
    __ProxyDynamic(right_percent, int8_t, int8_t, int8_t, right_percent, right_percent_id);
    __ProxyDynamic(right_charging, uint8_t, bool, bool, right_charging, right_charging_id);
    __ProxyDynamic(case_percent, int8_t, int8_t, int8_t, case_percent, case_percent_id);
    __ProxyDynamic(case_charging, uint8_t, bool, bool, case_charging, case_charging_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.battery.source",
                "Where the level came from (apple_proximity, fast_pair, bthome, pvvx, atc1441, "
                "eddystone_tlm, battery_service, ruuvi)", &source);
        register_field("btle.device.battery.percent", "Battery percent, -1 if not known",
                &percent);
        register_field("btle.device.battery.charging", "Battery is charging", &charging);
        register_field("btle.device.battery.last_time",
                "Last time a battery level was advertised", &last_time);

        millivolts_id =
            register_dynamic_field("btle.device.battery.millivolts", "Battery voltage, mV",
                    &millivolts);
        left_percent_id =
            register_dynamic_field("btle.device.battery.left_percent",
                    "Left earbud battery percent, -1 if not known", &left_percent);
        left_charging_id =
            register_dynamic_field("btle.device.battery.left_charging", "Left earbud is charging",
                    &left_charging);
        right_percent_id =
            register_dynamic_field("btle.device.battery.right_percent",
                    "Right earbud battery percent, -1 if not known", &right_percent);
        right_charging_id =
            register_dynamic_field("btle.device.battery.right_charging",
                    "Right earbud is charging", &right_charging);
        case_percent_id =
            register_dynamic_field("btle.device.battery.case_percent",
                    "Earbud case battery percent, -1 if not known", &case_percent);
        case_charging_id =
            register_dynamic_field("btle.device.battery.case_charging", "Earbud case is charging",
                    &case_charging);
    }

    std::shared_ptr<tracker_element_string> source;
    std::shared_ptr<tracker_element_int8> percent;
    std::shared_ptr<tracker_element_uint8> charging;
    std::shared_ptr<tracker_element_uint64> last_time;

    std::shared_ptr<tracker_element_uint16> millivolts;
    uint16_t millivolts_id;
    std::shared_ptr<tracker_element_int8> left_percent;
    uint16_t left_percent_id;
    std::shared_ptr<tracker_element_uint8> left_charging;
    uint16_t left_charging_id;
    std::shared_ptr<tracker_element_int8> right_percent;
    uint16_t right_percent_id;
    std::shared_ptr<tracker_element_uint8> right_charging;
    uint16_t right_charging_id;
    std::shared_ptr<tracker_element_int8> case_percent;
    uint16_t case_percent_id;
    std::shared_ptr<tracker_element_uint8> case_charging;
    uint16_t case_charging_id;
};

// Estimated distance from the signal received and the power the device says it
// transmits (see bluetooth_parsers/btle_ranging.h); only present on devices which
// advertised a power level.  A rough guide only: walls, bodies, and antennas easily
// move it by a factor of two or more.
class btle_tracked_ranging : public tracker_component {
public:
    btle_tracked_ranging() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_ranging(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_ranging(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_ranging");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(source, std::string, std::string, std::string, source);
    __Proxy(ref_power, int16_t, int16_t, int16_t, ref_power);
    __Proxy(rssi, double, double, double, rssi);
    __Proxy(distance, double, double, double, distance);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    // Not exported; see apply_ranging
    uint8_t src_rank = 0;
    time_t src_time = 0;

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.ranging.source",
                "Where the power level came from (ibeacon, altbeacon, eddystone, ruuvi, "
                "tx_power_level)", &source);
        register_field("btle.device.ranging.ref_power",
                "Signal expected at 1 meter, dBm", &ref_power);
        register_field("btle.device.ranging.rssi", "Smoothed signal used for the estimate, dBm",
                &rssi);
        register_field("btle.device.ranging.distance", "Estimated distance, meters", &distance);
        register_field("btle.device.ranging.last_time", "Last time the estimate was updated",
                &last_time);
    }

    std::shared_ptr<tracker_element_string> source;
    std::shared_ptr<tracker_element_int16> ref_power;
    std::shared_ptr<tracker_element_double> rssi;
    std::shared_ptr<tracker_element_double> distance;
    std::shared_ptr<tracker_element_uint64> last_time;
};

// The identity a proximity beacon advertises; see bluetooth_parsers/btle_beacon.h
class btle_tracked_beacon : public tracker_component {
public:
    btle_tracked_beacon() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_beacon(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_beacon(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_beacon");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(beacon_type, std::string, std::string, std::string, beacon_type);
    __ProxyDynamic(uuid, std::string, std::string, std::string, uuid, uuid_id);
    __ProxyDynamic(major, uint16_t, uint16_t, uint16_t, major, major_id);
    __ProxyDynamic(minor, uint16_t, uint16_t, uint16_t, minor, minor_id);
    __ProxyDynamic(eddystone_namespace, std::string, std::string, std::string,
            eddystone_namespace, eddystone_namespace_id);
    __ProxyDynamic(eddystone_instance, std::string, std::string, std::string,
            eddystone_instance, eddystone_instance_id);
    __ProxyDynamic(url, std::string, std::string, std::string, url, url_id);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.beacon.type",
                "Beacon format (ibeacon, altbeacon, eddystone_uid, eddystone_url)", &beacon_type);
        uuid_id = register_dynamic_field("btle.device.beacon.uuid",
                "iBeacon proximity UUID or AltBeacon ID", &uuid);
        major_id = register_dynamic_field("btle.device.beacon.major", "iBeacon or AltBeacon major",
                &major);
        minor_id = register_dynamic_field("btle.device.beacon.minor", "iBeacon or AltBeacon minor",
                &minor);
        eddystone_namespace_id = register_dynamic_field("btle.device.beacon.namespace",
                "Eddystone UID namespace", &eddystone_namespace);
        eddystone_instance_id = register_dynamic_field("btle.device.beacon.instance",
                "Eddystone UID instance", &eddystone_instance);
        url_id = register_dynamic_field("btle.device.beacon.url", "Eddystone URL", &url);
        register_field("btle.device.beacon.last_time", "Last time the beacon was seen",
                &last_time);
    }

    std::shared_ptr<tracker_element_string> beacon_type;
    std::shared_ptr<tracker_element_string> uuid;
    uint16_t uuid_id;
    std::shared_ptr<tracker_element_uint16> major;
    uint16_t major_id;
    std::shared_ptr<tracker_element_uint16> minor;
    uint16_t minor_id;
    std::shared_ptr<tracker_element_string> eddystone_namespace;
    uint16_t eddystone_namespace_id;
    std::shared_ptr<tracker_element_string> eddystone_instance;
    uint16_t eddystone_instance_id;
    std::shared_ptr<tracker_element_string> url;
    uint16_t url_id;
    std::shared_ptr<tracker_element_uint64> last_time;
};

// The connection a central last made to this device, from its CONNECT_IND
class btle_tracked_connection : public tracker_component {
public:
    btle_tracked_connection() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_connection(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_connection(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_connection");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(central, mac_addr, mac_addr, mac_addr, central);
    __Proxy(access_address, uint32_t, uint32_t, uint32_t, access_address);
    __Proxy(interval_us, uint32_t, uint32_t, uint32_t, interval_us);
    __Proxy(latency, uint16_t, uint16_t, uint16_t, latency);
    __Proxy(timeout_ms, uint32_t, uint32_t, uint32_t, timeout_ms);
    __Proxy(hop, uint8_t, uint8_t, uint8_t, hop);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.connection.central", "Address of the connecting central",
                &central);
        register_field("btle.device.connection.access_address", "Connection access address",
                &access_address);
        register_field("btle.device.connection.interval_us", "Connection interval, microseconds",
                &interval_us);
        register_field("btle.device.connection.latency", "Peripheral latency, in events",
                &latency);
        register_field("btle.device.connection.timeout_ms", "Supervision timeout, milliseconds",
                &timeout_ms);
        register_field("btle.device.connection.hop", "Channel hop increment", &hop);
        register_field("btle.device.connection.last_time", "Last time a connection was seen",
                &last_time);
    }

    std::shared_ptr<tracker_element_mac_addr> central;
    std::shared_ptr<tracker_element_uint32> access_address;
    std::shared_ptr<tracker_element_uint32> interval_us;
    std::shared_ptr<tracker_element_uint16> latency;
    std::shared_ptr<tracker_element_uint32> timeout_ms;
    std::shared_ptr<tracker_element_uint8> hop;
    std::shared_ptr<tracker_element_uint64> last_time;
};

namespace btle_battery {
struct info;
}

namespace btle_beacon {
struct info;
}

namespace btle_ranging {
struct info;
}

void apply_battery_info(btle_tracked_battery& battery, const btle_battery::info& info, time_t now);

void apply_beacon(btle_tracked_beacon& beacon, const btle_beacon::info& info, time_t now);

// Takes the power level from the best source seen recently and smooths the signal;
// rssi is the signal of this packet in dBm
void apply_ranging(btle_tracked_ranging& ranging, const btle_ranging::info& info, int rssi,
        double exponent, time_t now);

// The packet's signal in dBm, or false when the capture didn't report one
bool btle_packet_rssi(const kis_packet *in_pack, int& rssi);

// btle_distance_exponent from the config, the path loss exponent: 2 in free space,
// about 3 indoors
double btle_distance_exponent();

// Future btle attributes
class btle_tracked_device : public tracker_component {
public:
    btle_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_device(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    btle_tracked_device(int in_id,
            std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("btle_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

   __Proxy(le_limited_discoverable, uint8_t, bool, bool, le_limited_discoverable);
   __Proxy(le_general_discoverable, uint8_t, bool, bool, le_general_discoverable);
   __Proxy(br_edr_unsupported, uint8_t, bool, bool, br_edr_unsupported);
   __Proxy(simultaneous_br_edr_controller, uint8_t, bool, bool, simultaneous_br_edr_controller);
   __Proxy(simultaneous_br_edr_host, uint8_t, bool, bool, simultaneous_br_edr_host);
   __Proxy(pdu_type, uint8_t, uint8_t, uint8_t, pdu_type);

   // Advertised 16/32/128-bit service UUIDs, accumulated across every
   // advertisement seen (as hex strings, not this codebase's uuid type).
   __ProxyTrackable(service_uuid_vec, tracker_element_vector_string, service_uuid_vec);

   // Manufacturer Specific Data from the most recent match; not
   // accumulated, unlike service_uuid_vec, since it commonly rotates.
   __Proxy(manuf_company_id, std::string, std::string, std::string, manuf_company_id);
   __Proxy(manuf_data, std::string, std::string, std::string, manuf_data);

   // Set when btle_link_randomized links this address to others of the same device
   __ProxyDynamic(alias_group, std::string, std::string, std::string, alias_group, alias_group_id);
   __ProxyDynamic(alias_method, std::string, std::string, std::string, alias_method, alias_method_id);

   // Only created for devices advertising as a location tracker
   __ProxyDynamicTrackable(tracker, btle_tracked_tracker, tracker, tracker_id);
   __ProxyDynamicTrackable(battery, btle_tracked_battery, battery, battery_id);
   __ProxyDynamicTrackable(ranging, btle_tracked_ranging, ranging, ranging_id);
   __ProxyDynamicTrackable(beacon, btle_tracked_beacon, beacon, beacon_id);
   __ProxyDynamicTrackable(connection, btle_tracked_connection, connection, connection_id);
   __ProxyDynamic(adv_sid, uint8_t, uint8_t, uint8_t, adv_sid, adv_sid_id);
   __ProxyDynamicTrackable(adv, bt_tracked_adv, adv, adv_id);

   __ProxyDynamic(appearance, uint16_t, uint16_t, uint16_t, appearance, appearance_id);
   __ProxyDynamic(appearance_name, std::string, std::string, std::string, appearance_name,
           appearance_name_id);

   // Only set for random addresses; see btle_random_address_type
   __ProxyDynamic(random_address_type, std::string, std::string, std::string, random_address_type,
           random_address_type_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("btle.device.le_limited_discoverable", "BT LE limited discoverable mode",
                &le_limited_discoverable);
        register_field("btle.device.le_general_discoverable", "BT LE general discoverable mode",
                &le_general_discoverable);
        register_field("btle.device.br_edr_unsupported", "BT LE BR/EDR unsupported",
                &br_edr_unsupported);
        register_field("btle.device.simultaneous_br_edr_controller",
                "BT LE simultaneous BR/EDR controller mode",
                &simultaneous_br_edr_controller);
        register_field("btle.device.simultaneous_br_edr_host", "BT LE simultaneous BR/EDR host mode",
                &simultaneous_br_edr_host);
        register_field("btle.device.pdu_type", "BTLE advertising PDU type",
                &pdu_type);
        register_field("btle.device.service_uuid_vec", "advertised service UUIDs", &service_uuid_vec);
        register_field("btle.device.manuf_company_id", "manufacturer company ID", &manuf_company_id);
        register_field("btle.device.manuf_data", "manufacturer data payload", &manuf_data);

        alias_group_id =
            register_dynamic_field("btle.device.alias_group",
                    "key of the first device in a chain of randomized addresses linked as one device",
                    &alias_group);
        alias_method_id =
            register_dynamic_field("btle.device.alias_method",
                    "how this address was linked to the previous one (payload)", &alias_method);

        tracker_id =
            register_dynamic_field("btle.device.tracker", "location tracker advertisement", &tracker);
        battery_id =
            register_dynamic_field("btle.device.battery", "advertised battery level", &battery);
        ranging_id =
            register_dynamic_field("btle.device.ranging", "estimated distance", &ranging);
        beacon_id =
            register_dynamic_field("btle.device.beacon", "advertised beacon identity", &beacon);
        connection_id =
            register_dynamic_field("btle.device.connection", "last connection to this device",
                    &connection);
        adv_sid_id =
            register_dynamic_field("btle.device.adv_sid", "extended advertising set ID", &adv_sid);
        adv_id =
            register_dynamic_field("btle.device.adv", "decoded advertising data", &adv);

        appearance_id =
            register_dynamic_field("btle.device.appearance", "advertised appearance", &appearance);
        appearance_name_id =
            register_dynamic_field("btle.device.appearance_name", "advertised appearance, as text",
                    &appearance_name);

        random_address_type_id =
            register_dynamic_field("btle.device.random_address_type",
                    "kind of random address (static, resolvable, non-resolvable, reserved)",
                    &random_address_type);
    }

    std::shared_ptr<tracker_element_uint8> le_limited_discoverable;
    std::shared_ptr<tracker_element_uint8> le_general_discoverable;
    std::shared_ptr<tracker_element_uint8> br_edr_unsupported;
    std::shared_ptr<tracker_element_uint8> simultaneous_br_edr_controller;
    std::shared_ptr<tracker_element_uint8> simultaneous_br_edr_host;
    std::shared_ptr<tracker_element_uint8> pdu_type;
    std::shared_ptr<tracker_element_vector_string> service_uuid_vec;
    std::shared_ptr<tracker_element_string> manuf_company_id;
    std::shared_ptr<tracker_element_string> manuf_data;

    std::shared_ptr<btle_tracked_tracker> tracker;
    uint16_t tracker_id;
    std::shared_ptr<btle_tracked_battery> battery;
    uint16_t battery_id;
    std::shared_ptr<btle_tracked_ranging> ranging;
    uint16_t ranging_id;
    std::shared_ptr<btle_tracked_beacon> beacon;
    uint16_t beacon_id;
    std::shared_ptr<btle_tracked_connection> connection;
    uint16_t connection_id;
    std::shared_ptr<tracker_element_uint8> adv_sid;
    uint16_t adv_sid_id;
    std::shared_ptr<bt_tracked_adv> adv;
    uint16_t adv_id;

    std::shared_ptr<tracker_element_uint16> appearance;
    uint16_t appearance_id;
    std::shared_ptr<tracker_element_string> appearance_name;
    uint16_t appearance_name_id;

    std::shared_ptr<tracker_element_string> random_address_type;
    uint16_t random_address_type_id;

    std::shared_ptr<tracker_element_string> alias_group;
    uint16_t alias_group_id;
    std::shared_ptr<tracker_element_string> alias_method;
    uint16_t alias_method_id;
};

class kis_btle_phy : public kis_phy_handler {
public:
    kis_btle_phy() :
        kis_phy_handler() { }

    kis_btle_phy(int in_phyid);

    virtual ~kis_btle_phy();

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_btle_phy(in_phyid);
    }

    static int dissector(CHAINCALL_PARMS);
    static int common_classifier(CHAINCALL_PARMS);

    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;

    static uint32_t ble_crc24(uint32_t crc_init, const char *data, size_t len);

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

    // Relationships from scan requests, connections and directed advertisements
    void link_peer(kis_tracked_device_base& device, const bluetooth_btle& decode, time_t now);

    std::shared_ptr<btle_tracked_device> fetch_btle_record(const std::shared_ptr<kis_tracked_device_base>& dev) {
        return dev->get_sub_as<btle_tracked_device>(btle_device_id);
    }

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<alert_tracker> alertracker;
    std::shared_ptr<kis_bt_manuf> btmanuf;
    std::shared_ptr<kis_bt_oid> btoid;

    int pack_comp_linkframe, pack_comp_decap, pack_comp_btle, pack_comp_remoteid;

    int btle_device_id, btle_uuid_id;

    std::unordered_map<uint16_t, std::shared_ptr<tracker_element_string>> btle_uuid_cache;

    bool ignore_random;
    double distance_exponent;

    // Links a random address to the one before it when the advertising payload,
    // which changes at other times than the address, carries over
    std::unique_ptr<randomized_alias_linker> alias_linker;

    int alert_bleedingtooth_ref, alert_flipper_ref, alert_trackerfollow_ref;

    std::shared_ptr<tracker_element_string> devtype_tracker;
};

#endif

