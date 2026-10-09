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

#ifndef __KIS_GPS_H__
#define __KIS_GPS_H__

#include "config.h"

#include <array>

#include "entrytracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "packetchain.h"
#include "trackedelement.h"
#include "util.h"
#include "gps_proto.h"

class kis_gps_location;
class kis_gps_packinfo;

class kis_gps_builder;
typedef std::shared_ptr<kis_gps_builder> shared_gps_builder;

class kis_gps;
typedef std::shared_ptr<kis_gps> shared_gps;

class gps_tracker;

// GPS builders are responsible for telling the GPS tracker what sort of GPS,
// the basic priority, the type and default name, and so on.
class kis_gps_builder : public tracker_component {
public:
    kis_gps_builder() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    kis_gps_builder(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    virtual ~kis_gps_builder() { }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("kis_gps_builder");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual void initialize() { };

    // Take a shared_ptr reference to ourselves from the caller, because we can't 
    // consistently get a universal shared_ptr to 'this'
    virtual shared_gps build_gps(shared_gps_builder, uint64_t) {
        return NULL;
    }

    __ProxyPrivSplit(gps_class, std::string, std::string, std::string, gps_class);
    __ProxyPrivSplit(gps_class_description, std::string, std::string, std::string, 
            gps_class_description);
    __ProxyPrivSplit(gps_priority, int32_t, int32_t, int32_t, gps_priority);
    __ProxyPrivSplit(default_name, std::string, std::string, std::string, gps_default_name);
    __ProxyPrivSplit(singleton, uint8_t, bool, bool, singleton);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.gps.type.class", "Class/type", &gps_class);
        register_field("kismet.gps.type.description", "Class description", &gps_class_description);
        register_field("kismet.gps.type.priority", "Default priority", &gps_priority);
        register_field("kismet.gps.type.default_name", "Default name", &gps_default_name);
        register_field("kismet.gps.type.singleton", "Single instance of this gps type", &singleton);
    }

    std::shared_ptr<tracker_element_string> gps_class;
    std::shared_ptr<tracker_element_string> gps_class_description;
    std::shared_ptr<tracker_element_int32> gps_priority;
    std::shared_ptr<tracker_element_string> gps_default_name;
    std::shared_ptr<tracker_element_uint8> singleton;
};

// GPS superclass; built by a GPS builder; GPS drivers implement the low-level GPS 
// interaction (such as serial port, network, etc)
class kis_gps : public tracker_component {
public:
    kis_gps(shared_gps_builder in_builder, uint64_t in_id);

    virtual ~kis_gps();

    virtual void initialize() { };

    constexpr const uint64_t& get_id() const {
        return gps_id;
    }

    __ProxyPrivSplitM(gps_name, std::string, std::string, std::string, 
            gps_name, data_mutex);
    __ProxyPrivSplitM(gps_description, std::string, std::string, std::string, 
            gps_description, data_mutex);
    __ProxyPrivSplitM(gps_uuid, uuid, uuid, uuid, gps_uuid, data_mutex);
    __ProxyPrivSplitM(gps_definition, std::string, std::string, std::string, 
            gps_definition, data_mutex);
    __ProxyPrivSplitM(gps_priority, int32_t, int32_t, int32_t, gps_priority, data_mutex);
    __ProxyPrivSplitM(gps_data_only, uint8_t, bool, bool, gps_data_only, data_mutex);
    __ProxyPrivSplitM(gps_reconnect, uint8_t, bool, bool, gps_reconnect, data_mutex);
    __ProxyTrackableM(gps_prototype, kis_gps_builder, gps_prototype, data_mutex);

    __ProxyPrivSplitM(gps_data_time, uint64_t, time_t, time_t, gps_data_time, data_mutex);
    __ProxyPrivSplitM(gps_signal_time, uint64_t, time_t, time_t, gps_signal_time, 
            data_mutex);

    __ProxyPrivSplitVM(device_connected, uint8_t, bool, bool, gps_connected, data_mutex);

    virtual void pre_serialize() override {
        kis_lock_guard<kis_mutex> lk(data_mutex, kismet::retain_lock, "gps preserialize");
        publish_quality(time(0));
    }

    virtual void post_serialize() override {
        kis_lock_guard<kis_mutex> lk(data_mutex, std::adopt_lock);
    }

    virtual std::shared_ptr<kis_gps_packinfo> get_location() { 
        kis_lock_guard<kis_mutex> lk(data_mutex);
        return gps_location;
    }

    virtual std::shared_ptr<kis_gps_packinfo> get_last_location() { 
        kis_lock_guard<kis_mutex> lk(data_mutex);
        return gps_last_location;
    }

    // Fetch if we have a valid location anymore; per-gps-driver logic 
    // will determine if we consider a value to still be valid
    virtual bool get_location_valid() { return false; }

    virtual bool open_gps(std::string in_definition);

    // Stop the device when the GPS is removed; it won't reconnect
    virtual void close_gps() { }

    // Copy the current signal quality fields into a location report
    void add_signal_report(tracker_component& report);

    // Various GPS transformation utility functions
    static double gps_calc_heading(double in_lat, double in_lon, double in_lat2, double in_lon2);
    static double gps_calc_rad(double lat);
    static double gps_rad_to_deg(double x);
    static double gps_deg_to_rad(double x);
    static double gps_earth_distance(double in_lat, double in_lon, double in_lat2, double in_lon2);

protected:
    // We share mutexes down to the driver engines so we use a shared
    kis_mutex gps_mutex, data_mutex;

    // Unique ID
    uint64_t gps_id;

    // Split out local var-key pairs for the source definition
    std::map<std::string, std::string> source_definition_opts;

    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.gps.name", "GPS instance name", &gps_name);
        register_field("kismet.gps.description", "GPS instance description", &gps_description);

        register_field("kismet.gps.connected", "GPS device is connected", &gps_connected);

        register_field("kismet.gps.reconnect", "GPS device will reconnect if there is an error", &gps_reconnect);

        register_field("kismet.gps.location", "current location", &tracked_location);
        register_field("kismet.gps.last_location", "previous location", &tracked_last_location);

        register_field("kismet.gps.uuid", "UUID", &gps_uuid);
        register_field("kismet.gps.definition", "GPS definition", &gps_definition);

        register_field("kismet.gps.priority", "Multi-gps priority", &gps_priority);

        register_field("kismet.gps.data_only", 
                "GPS is used for populating data only, never for live location", &gps_data_only);

        register_field("kismet.gps.data_time",
                "Unix timestamp of last data from GPS", &gps_data_time);
        register_field("kismet.gps.signal_time",
                "Unix timestamp of last signal from GPS", &gps_signal_time);

        // Signal quality; only present while known
        sats_used_id = register_dynamic_field<tracker_element_uint8>("kismet.gps.satellites_used",
                "Satellites used in the fix");
        sats_visible_id = register_dynamic_field<tracker_element_uint8>("kismet.gps.satellites_visible",
                "Satellites in view");
        hdop_id = register_dynamic_field<tracker_element_double>("kismet.gps.hdop",
                "Horizontal dilution of precision, as reported by the GPS");
        vdop_id = register_dynamic_field<tracker_element_double>("kismet.gps.vdop",
                "Vertical dilution of precision, as reported by the GPS");
        precision_h_id = register_dynamic_field<tracker_element_double>("kismet.gps.precision_h",
                "Estimated horizontal position error, in meters");
        precision_v_id = register_dynamic_field<tracker_element_double>("kismet.gps.precision_v",
                "Estimated vertical position error, in meters");
        precision_source_id = register_dynamic_field<tracker_element_string>("kismet.gps.precision_source",
                "Position error source: 'reported' by the GPS (each GPS uses its own confidence "
                "level), 'estimated' from the dilution of precision, or 'mixed'");
        signal_cn0_id = register_dynamic_field<tracker_element_double>("kismet.gps.signal_cn0",
                "Average signal strength (C/N0) of the strongest satellites, in dB-Hz");
        signal_quality_id = register_dynamic_field<tracker_element_uint8>("kismet.gps.signal_quality",
                "Estimated GPS signal quality, 0 (no fix) to 100");
    }

    // Push the locations into the tracked locations and swap
    virtual void update_locations();

    // Merge a decoded protocol report into the current location
    void apply_fix(const gps_fix_update& update);

    // Merge signal quality which arrived without a location
    void apply_quality(const gps_quality_update& update);

    // Forget the signal quality, such as when the device disconnects
    void clear_quality();

    // Quality values are dropped when no report has refreshed them for this long; slow
    // reports such as UBX NAV-SAT at low baud rates arrive every 10 seconds
    static constexpr time_t quality_expire = 12;

    // Pseudorange error used to estimate the position error from the DOP, meters
    static constexpr double estimated_uere = 4.0;

    enum class quality_field : uint8_t {
        sats_used,
        sats_visible,
        hdop,
        vdop,
        error_h,
        error_v,
        cn0,
        count,
    };

    struct quality_value {
        bool present = false;
        double value = 0;
        time_t time = 0;
        gps_quality_update::source_rank rank = gps_quality_update::source_rank::nmea;
    };

    // Under data_mutex
    std::array<quality_value, static_cast<size_t>(quality_field::count)> quality_state;

    quality_value& quality_at(quality_field f) {
        return quality_state[static_cast<size_t>(f)];
    }

    void merge_quality(const gps_quality_update& update, time_t now);
    void expire_quality(time_t now);
    // Position error for a fix from the current quality values; 0 when unknown
    double quality_precision(bool vertical, bool& reported);
    // Update the tracked quality fields from the current values and location
    void publish_quality(time_t now);

    template<typename T, typename V>
    void set_quality_field(uint16_t id, const V& v) {
        auto ci = find(id);

        if (ci == end()) {
            auto e = Globalreg::globalreg->entrytracker->get_shared_instance_as<T>(id);
            e->set(v);
            insert(e);
            return;
        }

        std::static_pointer_cast<T>(ci->second)->set(v);
    }

    void clear_quality_field(uint16_t id) {
        auto ci = find(id);

        if (ci != end())
            erase(ci);
    }

    uint16_t sats_used_id, sats_visible_id, hdop_id, vdop_id, precision_h_id, precision_v_id,
             precision_source_id, signal_cn0_id, signal_quality_id;

    // Last time heading was set or calculated; calculating it more often than every few
    // seconds is mostly noise
    time_t fix_heading_time = 0;

    // Last time the receiver reported its fix mode (NMEA GSA or a binary navigation report)
    static constexpr time_t fix_reported_stale = 3;
    time_t fix_reported_time = 0;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<gps_tracker> gpstracker;

    std::shared_ptr<kis_gps_builder> gps_prototype;

    std::shared_ptr<tracker_element_string> gps_name;
    std::shared_ptr<tracker_element_string> gps_description;

    std::shared_ptr<tracker_element_uint8> gps_connected;

    std::shared_ptr<tracker_element_uint8> gps_reconnect;

    std::shared_ptr<tracker_element_int32> gps_priority;

    std::shared_ptr<kis_tracked_location_full> tracked_location;
    std::shared_ptr<kis_tracked_location_full> tracked_last_location;

    std::shared_ptr<kis_gps_packinfo> gps_last_location;
    std::shared_ptr<kis_gps_packinfo> gps_location;

    std::shared_ptr<tracker_element_uuid> gps_uuid;
    std::shared_ptr<tracker_element_string> gps_definition;

    std::shared_ptr<tracker_element_uint8> gps_data_only;

    std::shared_ptr<tracker_element_uint64> gps_data_time;
    std::shared_ptr<tracker_element_uint64> gps_signal_time;
};

#endif

