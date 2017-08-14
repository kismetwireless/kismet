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
#include <mutex>

#include "util.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "devicetracker_component.h"

class Kis_Gps_Location;
class kis_gps_packinfo;

class KisGpsBuilder;
typedef shared_ptr<KisGpsBuilder> SharedGpsBuilder;

class KisGps;
typedef shared_ptr<KisGps> SharedGps;

// GPS builders are responsible for telling the GPS tracker what sort of GPS,
// the basic priority, the type and default name, and so on.
class KisGpsBuilder : public tracker_component {
public:
    KisGpsBuilder(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.gps.type_driver",
                    TrackerMap, "GPS type definition / driver");
        }

        initialize();
    }

    KisGpsBuilder(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.log.type_driver",
                    TrackerMap, "Log type definition / driver");
        }

        initialize();
    }

    virtual ~KisGpsBuilder() { }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisGpsBuilder(globalreg, get_id()));
    }

    virtual void initialize() { };

    // Take a shared_ptr reference to ourselves from the caller, because we can't 
    // consistently get a universal shared_ptr to 'this'
    virtual SharedGps build_gps(SharedGpsBuilder) {
        return NULL;
    }

    __Proxy(gps_class, string, string, string, gps_class);
    __Proxy(gps_priority, int32_t, int32_t, int32_t, gps_priority);
    __Proxy(default_name, string, string, string, gps_default_name);
    __Proxy(singleton, uint8_t, bool, bool, singleton);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.gps.type.class", TrackerString,
                "Class/type", &gps_class);
        RegisterField("kismet.gps.type.priority", TrackerInt32,
                "Default priority", &gps_priority);
        RegisterField("kismet.gps.type.default_name", TrackerString,
                "Default name", &gps_default_name);
        RegisterField("kismet.gps.type.singleton", TrackerUInt8,
                "Single instance of this gps type", &singleton);
    }

    SharedTrackerElement gps_class;
    SharedTrackerElement gps_priority;
    SharedTrackerElement gps_default_name;
    SharedTrackerElement singleton;
};

// GPS superclass; built by a GPS builder; GPS drivers implement the low-level GPS 
// interaction (such as serial port, network, etc)
class KisGps : public tracker_component {
    KisGps(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(NULL);

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.gps.type_driver",
                    TrackerMap, "GPS type definition / driver");
        }

        initialize();
    }

    KisGps(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.log.type_driver",
                    TrackerMap, "Log type definition / driver");
        }

        initialize();
    }

    virtual ~KisGps() { }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisGpsBuilder(globalreg, get_id()));
    }

    virtual void initialize() { };

    __ProxyPrivSplit(gps_name, string, string, string, gps_name);
    __ProxyPrivSplit(gps_description, string, string, string, gps_description);
    __ProxyTrackable(location, kis_tracked_location_triplet, location);
    __ProxyTrackable(last_location, kis_tracked_location_triplet, last_location);
    __ProxyPrivSplit(gps_uuid, uuid, uuid, uuid, gps_uuid);
    __ProxyPrivSplit(gps_definition, string, string, string, gps_definition);

    // Fetch if we have a valid location anymore; per-gps-driver logic 
    // will determine if we consider a value to still be valid
    virtual bool get_location_valid() { return false; }

    // Are we connected to our gps device?
    virtual bool get_device_connected() { return false; }

    virtual bool open_gps(string in_definition);

    // Various GPS transformation utility functions
    static double GpsCalcHeading(double in_lat, double in_lon, 
            double in_lat2, double in_lon2);
    static double GpsCalcRad(double lat);
    static double GpsRad2Deg(double x);
    static double GpsDeg2Rad(double x);
    static double GpsEarthDistance(double in_lat, double in_lon, 
            double in_lat2, double in_lon2);

protected:
    std::recursive_timed_mutex gps_mutex;

    // Split out local var-key pairs for the source definition
    std::map<std::string, std::string> source_definition_opts;

    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.gps.name", TrackerString,
                "GPS instance name", &gps_name);
        RegisterField("kismet.gps.description", TrackerString,
                "GPS instance description", &gps_description);

        RegisterComplexField("kismet.gps.location", 
                shared_ptr<kis_tracked_location_triplet>(new kis_tracked_location_triplet(globalreg, 0)),
                "current location");
        RegisterComplexField("kismet.gps.last_location",
                shared_ptr<kis_tracked_location_triplet>(new kis_tracked_location_triplet(globalreg, 0)),
                "previous location");

        RegisterField("kismet.gps.uuid", TrackerUuid, "UUID", &gps_uuid);
        RegisterField("kismet.gps.definition", TrackerString, 
                "GPS definition", &gps_definition);

    }

    SharedTrackerElement gps_name;
    SharedTrackerElement gps_description;

    shared_ptr<kis_tracked_location_triplet> location;
    shared_ptr<kis_tracked_location_triplet> last_location;

    SharedTrackerElement gps_uuid;
    SharedTrackerElement gps_definition;
};

#endif

