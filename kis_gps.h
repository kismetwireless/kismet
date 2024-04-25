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

#include "entrytracker.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "packetchain.h"
#include "trackedelement.h"
#include "util.h"

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
    virtual shared_gps build_gps(shared_gps_builder) {
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
    kis_gps(shared_gps_builder in_builder);

    virtual ~kis_gps();

    virtual void initialize() { };

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

    // Various GPS transformation utility functions
    static double gps_calc_heading(double in_lat, double in_lon, double in_lat2, double in_lon2);
    static double gps_calc_rad(double lat);
    static double gps_rad_to_deg(double x);
    static double gps_deg_to_rad(double x);
    static double gps_earth_distance(double in_lat, double in_lon, double in_lat2, double in_lon2);

protected:
    // We share mutexes down to the driver engines so we use a shared
    kis_mutex gps_mutex, data_mutex;

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
    }

    // Push the locations into the tracked locations and swap
    virtual void update_locations();

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

