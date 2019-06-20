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

#include <pthread.h>

#include "util.h"

#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "devicetracker_component.h"

class Kis_Gps_Location;
class kis_gps_packinfo;

class KisGpsBuilder;
typedef std::shared_ptr<KisGpsBuilder> SharedGpsBuilder;

class KisGps;
typedef std::shared_ptr<KisGps> SharedGps;

// GPS builders are responsible for telling the GPS tracker what sort of GPS,
// the basic priority, the type and default name, and so on.
class KisGpsBuilder : public tracker_component {
public:
    KisGpsBuilder() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    KisGpsBuilder(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    virtual ~KisGpsBuilder() { }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("KisGpsBuilder");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    virtual void initialize() { };

    // Take a shared_ptr reference to ourselves from the caller, because we can't 
    // consistently get a universal shared_ptr to 'this'
    virtual SharedGps build_gps(SharedGpsBuilder) {
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

        RegisterField("kismet.gps.type.class", "Class/type", &gps_class);
        RegisterField("kismet.gps.type.description", "Class description", &gps_class_description);
        RegisterField("kismet.gps.type.priority", "Default priority", &gps_priority);
        RegisterField("kismet.gps.type.default_name", "Default name", &gps_default_name);
        RegisterField("kismet.gps.type.singleton", "Single instance of this gps type", &singleton);
    }

    std::shared_ptr<TrackerElementString> gps_class;
    std::shared_ptr<TrackerElementString> gps_class_description;
    std::shared_ptr<TrackerElementInt32> gps_priority;
    std::shared_ptr<TrackerElementString> gps_default_name;
    std::shared_ptr<TrackerElementUInt8> singleton;
};

// GPS superclass; built by a GPS builder; GPS drivers implement the low-level GPS 
// interaction (such as serial port, network, etc)
class KisGps : public tracker_component {
public:
    KisGps(SharedGpsBuilder in_builder);

    virtual ~KisGps();

    virtual void initialize() { };

    __ProxyPrivSplit(gps_name, std::string, std::string, std::string, gps_name);
    __ProxyPrivSplit(gps_description, std::string, std::string, std::string, gps_description);
    __ProxyPrivSplit(gps_uuid, uuid, uuid, uuid, gps_uuid);
    __ProxyPrivSplit(gps_definition, std::string, std::string, std::string, gps_definition);
    __ProxyPrivSplit(gps_priority, int32_t, int32_t, int32_t, gps_priority);
    __ProxyPrivSplit(gps_data_only, uint8_t, bool, bool, gps_data_only);
    __ProxyPrivSplit(device_connected, uint8_t, bool, bool, gps_connected);
    __ProxyTrackable(gps_prototype, KisGpsBuilder, gps_prototype);

    virtual kis_gps_packinfo *get_location() { return gps_location; }
    virtual kis_gps_packinfo *get_last_location() { return gps_last_location; }

    // Fetch if we have a valid location anymore; per-gps-driver logic 
    // will determine if we consider a value to still be valid
    virtual bool get_location_valid() { return false; }

    virtual bool open_gps(std::string in_definition);

    // Various GPS transformation utility functions
    static double GpsCalcHeading(double in_lat, double in_lon, double in_lat2, double in_lon2);
    static double GpsCalcRad(double lat);
    static double GpsRad2Deg(double x);
    static double GpsDeg2Rad(double x);
    static double GpsEarthDistance(double in_lat, double in_lon, double in_lat2, double in_lon2);

protected:
    // We share mutexes down to the driver engines so we use a shared
    std::shared_ptr<kis_recursive_timed_mutex> gps_mutex;

    // Split out local var-key pairs for the source definition
    std::map<std::string, std::string> source_definition_opts;

    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.gps.name", "GPS instance name", &gps_name);
        RegisterField("kismet.gps.description", "GPS instance description", &gps_description);

        RegisterField("kismet.gps.connected", "GPS device is connected", &gps_connected);

        RegisterField("kismet.gps.location", "current location", &tracked_location);
        RegisterField("kismet.gps.last_location", "previous location", &tracked_last_location);

        RegisterField("kismet.gps.uuid", "UUID", &gps_uuid);
        RegisterField("kismet.gps.definition", "GPS definition", &gps_definition);

        RegisterField("kismet.gps.priority", "Multi-gps priority", &gps_priority);

        RegisterField("kismet.gps.data_only", 
                "GPS is used for populating data only, never for live location", &gps_data_only);
    }

    // Push the locations into the tracked locations and swap
    virtual void update_locations();

    std::shared_ptr<KisGpsBuilder> gps_prototype;

    std::shared_ptr<TrackerElementString> gps_name;
    std::shared_ptr<TrackerElementString> gps_description;

    std::shared_ptr<TrackerElementUInt8> gps_connected;

    std::shared_ptr<TrackerElementInt32> gps_priority;

    std::shared_ptr<kis_tracked_location_triplet> tracked_location;
    std::shared_ptr<kis_tracked_location_triplet> tracked_last_location;

    kis_gps_packinfo *gps_location;
    kis_gps_packinfo *gps_last_location;

    std::shared_ptr<TrackerElementUUID> gps_uuid;
    std::shared_ptr<TrackerElementString> gps_definition;

    std::shared_ptr<TrackerElementUInt8> gps_data_only;
};

#endif

