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

#ifndef __PHY_UAV_DRONE_H__
#define __PHY_UAV_DRONE_H__

#include "trackedelement.h"
#include "trackedlocation.h"
#include "phyhandler.h"
#include "packetchain.h"

#include "dot11_parsers/dot11_ie_221_dji_droneid.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

/* An abstract model of a UAV (drone/quadcopter/plane) device.
 *
 * A UAV may have multiple communications protocols (bluetooth, wi-fi, RF)
 * which comprise the same device; references to the independent devices of
 * other phys are linked in the optional descriptors.
 *
 * A UAV is worthy of its own top-level device because it also introduces
 * independent tracking requirements; location history may be sources
 * from UAV telemetry independent of the devices/kismet sensor locations.
 *
 */

class uav_tracked_telemetry : public tracker_component {
public:
    uav_tracked_telemetry() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    uav_tracked_telemetry(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    uav_tracked_telemetry(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    uav_tracked_telemetry(const uav_tracked_telemetry *p) :
        tracker_component{p} {

        __ImportField(location, p);
        __ImportField(telem_ts, p);
        __ImportField(yaw, p);
        __ImportField(pitch, p);
        __ImportField(roll, p);
        __ImportField(height, p);
        __ImportField(v_north, p);
        __ImportField(v_east, p);
        __ImportField(v_up, p);
        __ImportField(motor_on, p);
        __ImportField(airborne, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("uav_tracked_telemetry");
    }

    virtual ~uav_tracked_telemetry() { }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    __ProxyTrackable(location, kis_tracked_location_triplet, location);
    __Proxy(telem_timestamp, double, double, double, telem_ts);
    __Proxy(yaw, double, double, double, yaw);
    __Proxy(pitch, double, double, double, pitch);
    __Proxy(roll, double, double, double, roll);
    __Proxy(height, double, double, double, height);
    __Proxy(v_north, double, double, double, v_north);
    __Proxy(v_east, double, double, double, v_east);
    __Proxy(v_up, double, double, double, v_up);

    __Proxy(motor_on, uint8_t, bool, bool, motor_on);
    __Proxy(airborne, uint8_t, bool, bool, airborne);

    void from_droneid_flight_reg(std::shared_ptr<dot11_ie_221_dji_droneid::dji_subcommand_flight_reg> flight_reg) {
        if (flight_reg->state_gps_valid()) {
            location->set(flight_reg->lat(), flight_reg->lon());
            
            if (flight_reg->state_alt_valid()) {
                location->set_alt(flight_reg->altitude());
                location->set_fix(3);
            } else {
                location->set_fix(2);
            }
        }

        set_yaw(flight_reg->yaw());
        set_pitch(flight_reg->pitch());
        set_roll(flight_reg->roll());

        if (flight_reg->state_horiz_valid()) {
            set_v_east(flight_reg->v_east());
            set_v_north(flight_reg->v_north());
        }

        if (flight_reg->state_vup_valid()) 
            set_v_up(flight_reg->v_up());

        if (flight_reg->state_height_valid())
            set_height(flight_reg->height());

        set_motor_on(flight_reg->state_motor_on());
        set_airborne(flight_reg->state_in_air());
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("uav.telemetry.location", "UAV GPS location", &location);
        register_field("uav.telemetry.timestamp", "timestamp (sec.usec)", &telem_ts);
        register_field("uav.telemetry.yaw", "yaw", &yaw);
        register_field("uav.telemetry.pitch", "pitch", &pitch);
        register_field("uav.telemetry.roll", "roll", &roll);
        register_field("uav.telemetry.height", "height above ground", &height);
        register_field("uav.telemetry.v_north", "velocity relative to n/s", &v_north);
        register_field("uav.telemetry.v_east", "velocity relative to e/w", &v_east);
        register_field("uav.telemetry.v_up", "velocity relative to up/down", &v_up);

        register_field("uav.telemetry.motor_on", "device reports motor enabled", &motor_on);
        register_field("uav.telemetry.airborne", "device reports UAV is airborne", &airborne);
    }

    std::shared_ptr<kis_tracked_location_triplet> location;
    std::shared_ptr<tracker_element_double> telem_ts;
    std::shared_ptr<tracker_element_double> yaw;
    std::shared_ptr<tracker_element_double> pitch;
    std::shared_ptr<tracker_element_double> roll;
    std::shared_ptr<tracker_element_double> height;
    std::shared_ptr<tracker_element_double> v_north;
    std::shared_ptr<tracker_element_double> v_east;
    std::shared_ptr<tracker_element_double> v_up;

    std::shared_ptr<tracker_element_uint8> motor_on;
    std::shared_ptr<tracker_element_uint8> airborne;
};

// Match a manufacturer (such as OUI, SSID, or both)
class uav_manuf_match : public tracker_component {
public:
    uav_manuf_match() :
        tracker_component() {

#ifdef HAVE_LIBPCRE
        re = NULL;
        study = NULL;
#endif

        register_fields();
        reserve_fields(NULL);
    }

    uav_manuf_match(int in_id) :
        tracker_component(in_id) {

#ifdef HAVE_LIBPCRE
        re = NULL;
        study = NULL;
#endif

        register_fields();
        reserve_fields(NULL);
    }

    uav_manuf_match(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {

#ifdef HAVE_LIBPCRE
        re = NULL;
        study = NULL;
#endif

        register_fields();
        reserve_fields(e);
    }

    virtual ~uav_manuf_match() { 
#ifdef HAVE_LIBPCRE
        if (re != NULL)
            pcre_free(re);

        if (study != NULL)
            pcre_free(study);
#endif
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("uav_match");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    __Proxy(uav_match_name, std::string, std::string, std::string, uav_match_name);

    __Proxy(uav_manuf_name, std::string, std::string, std::string, uav_manuf_name);
    __Proxy(uav_manuf_model, std::string, std::string, std::string, uav_manuf_model);
    __Proxy(uav_manuf_mac, mac_addr, mac_addr, mac_addr, uav_manuf_mac);

    void set_uav_manuf_ssid_regex(const std::string&);
    __ProxyGet(uav_manuf_ssid_regex, std::string, std::string, uav_manuf_ssid_regex);

    __Proxy(uav_manuf_partial, uint8_t, bool, bool, uav_manuf_partial);

    bool match_record(const mac_addr& in_mac, const std::string& in_ssid);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("uav_match_name", "Match name", &uav_match_name);
        register_field("uav.manufmatch.name", "Matched manufacturer name", &uav_manuf_name);
        register_field("uav.manufmatch.model", "Matched model name", &uav_manuf_model);

        register_field("uav.manufmatch.mac", "Matching mac address fragment", &uav_manuf_mac);
        register_field("uav.manufmatch.ssid_regex", "Matching SSID regex", &uav_manuf_ssid_regex);

        register_field("uav.manufmatch.partial", 
                "Allow partial matches (only manuf or only ssid)", &uav_manuf_partial);
    }

    std::shared_ptr<tracker_element_string> uav_match_name;
    std::shared_ptr<tracker_element_string> uav_manuf_name;
    std::shared_ptr<tracker_element_string> uav_manuf_model;
    std::shared_ptr<tracker_element_mac_addr> uav_manuf_mac;
    std::shared_ptr<tracker_element_string> uav_manuf_ssid_regex;
    std::shared_ptr<tracker_element_uint8> uav_manuf_partial;

#ifdef HAVE_LIBPCRE
    pcre *re;
    pcre_extra *study;
#endif
};

/* A 'light' phy which attaches additional records to existing phys */
class uav_tracked_device : public tracker_component {
public:
    uav_tracked_device() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    uav_tracked_device(int in_id) :
        tracker_component(in_id) {

        register_fields();
        reserve_fields(NULL);
    }

    uav_tracked_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {

        register_fields();
        reserve_fields(e);
    }

    uav_tracked_device(const uav_tracked_device *p) :
        tracker_component{p} {

        __ImportField(uav_manufacturer, p);
        __ImportField(uav_model, p);
        __ImportField(uav_serialnumber, p);

        __ImportId(last_telem_loc_id, p);

        __ImportField(uav_telem_history, p);
        __ImportId(telem_history_entry_id, p);

        __ImportField(uav_match_type, p);

        __ImportId(home_location_id, p);
        __ImportId(matched_type_id, p);

        reserve_fields(nullptr);
    }

    virtual ~uav_tracked_device() { }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("uav_tracked_device");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(this));
        return std::move(dup);
    }

    __Proxy(uav_manufacturer, std::string, std::string, std::string, uav_manufacturer);
    __Proxy(uav_model, std::string, std::string, std::string, uav_model);
    __Proxy(uav_serialnumber, std::string, std::string, std::string, uav_serialnumber);
    
    __ProxyDynamicTrackable(last_telem_loc, uav_tracked_telemetry, last_telem_loc, last_telem_loc_id);

    std::shared_ptr<uav_tracked_telemetry> new_telemetry() {
        return std::make_shared<uav_tracked_telemetry>(telem_history_entry_id);
    }

    __ProxyTrackable(uav_telem_history, tracker_element_vector, uav_telem_history);

    __Proxy(uav_match_type, std::string, std::string, std::string, uav_match_type);

    __ProxyDynamicTrackable(home_location, kis_tracked_location_triplet, 
            home_location, home_location_id);
    __ProxyDynamicTrackable(matched_type, uav_manuf_match, matched_type, matched_type_id);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("uav.manufacturer", "Manufacturer", &uav_manufacturer);
        register_field("uav.model", "Model", &uav_model);
        register_field("uav.serialnumber", "Serial number", &uav_serialnumber);

        last_telem_loc_id =
            register_field("uav.last_telemetry", "Last drone telemetry location", &last_telem_loc);

        register_field("uav.telemetry_history", "Previous telemetry location data", &uav_telem_history);

        telem_history_entry_id =
            register_field("uav.telemetry_entry",
                    tracker_element_factory<uav_tracked_telemetry>(),
                    "historical telemetry");

        register_field("uav.match_type", "Match type (drone characteristics)", &uav_match_type);

        home_location_id =
            register_field("uav.telemetry.home_location", "UAV takeoff/home location",
                    &home_location);

        matched_type_id =
            register_field("uav.type", "Matched device", &matched_type);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            for (auto l = uav_telem_history->begin(); l != uav_telem_history->end(); ++l) {
                auto telem =
                    std::make_shared<uav_tracked_telemetry>(telem_history_entry_id,
                            std::static_pointer_cast<tracker_element_map>(*l));
                *l = telem;
            }
        }
    }

    std::shared_ptr<tracker_element_string> uav_manufacturer;
    std::shared_ptr<tracker_element_string> uav_model;
    std::shared_ptr<tracker_element_string> uav_serialnumber;

    std::shared_ptr<uav_tracked_telemetry> last_telem_loc;
    int last_telem_loc_id;

    std::shared_ptr<tracker_element_vector> uav_telem_history;

    int telem_history_entry_id;

    std::shared_ptr<tracker_element_string> uav_match_type;

    std::shared_ptr<kis_tracked_location_triplet> home_location;
    int home_location_id;

    std::shared_ptr<uav_manuf_match> matched_type;
    int matched_type_id;
};

/* Frankenphy which absorbs other phys */
class Kis_UAV_Phy : public kis_phy_handler {
public:
    virtual ~Kis_UAV_Phy();

    Kis_UAV_Phy() :
        kis_phy_handler() { }

    virtual kis_phy_handler *create_phy_handler(int in_phyid) {
        return new Kis_UAV_Phy(in_phyid);
    }

    Kis_UAV_Phy(int in_phyid);

    // Common classifier to make new UAV records
    static int CommonClassifier(CHAINCALL_PARMS);

    // Restore stored UAV records
    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device);

protected:
    bool parse_manuf_definition(std::string def);

    kis_mutex uav_mutex;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<device_tracker> devicetracker;

    /* We need to look at the dot11 packet to see if we've got a droneid ie tag */
    int pack_comp_common, pack_comp_80211, pack_comp_device;

    int uav_device_id;

    std::shared_ptr<tracker_element_vector> manuf_match_vec;
};

#endif

