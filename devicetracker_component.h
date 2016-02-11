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

#ifndef __TRACKERCOMPONENT_H__
#define __TRACKERCOMPONENT_H__

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
#include "trackedelement.h"
#include "entrytracker.h"
#include "packet.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gpscore.h"
#include "uuid.h"
#include "configfile.h"
#include "phyhandler.h"
#include "devicetracker.h"
#include "packinfo_signal.h"

class Packinfo_Sig_Combo;

// Basic unit being tracked in a tracked device
class tracker_component : public TrackerElement {

// Ugly trackercomponent macro for proxying trackerelement values
// Defines get_<name> function, for a TrackerElement of type <ptype>, returning type 
// <rtype>, referencing class variable <cvar>
// Defines set_<name> funciton, for a TrackerElement of type <ptype>, taking type 
// <itype>, which must be castable to the TrackerElement type (itype), referencing 
// class variable <cvar>
#define __Proxy(name, ptype, itype, rtype, cvar) \
    rtype get_##name() const { \
        return (rtype) GetTrackerValue<ptype>(cvar); \
    } \
    void set_##name(itype in) { \
        cvar->set((ptype) in); \
    }

// Only proxy a Get function
#define __ProxyGet(name, ptype, rtype, cvar) \
    rtype get_##name() { \
        return (rtype) GetTrackerValue<ptype>(cvar); \
    } 

// Only proxy a Set function for overload
#define __ProxySet(name, ptype, stype, cvar) \
    void set_##name(stype in) { \
        cvar->set((stype) in); \
    } 

// Proxy increment and decrement functions
#define __ProxyIncDec(name, ptype, rtype, cvar) \
    void inc_##name() { \
        (*cvar)++; \
    } \
    void inc_##name(rtype i) { \
        (*cvar) += (ptype) i; \
    } \
    void dec_##name() { \
        (*cvar)--; \
    } \
    void dec_##name(rtype i) { \
        (*cvar) -= (ptype) i; \
    }

// Proxy add/subtract
#define __ProxyAddSub(name, ptype, itype, cvar) \
    void add_##name(itype i) { \
        (*cvar) += (ptype) i; \
    } \
    void sub_##name(itype i) { \
        (*cvar) -= (ptype) i; \
    }

// Proxy sub-trackable (name, trackable type, class variable)
#define __ProxyTrackable(name, ttype, cvar) \
    ttype *get_##name() { return cvar; } \
    void set_##name(ttype *in) { \
        if (cvar != NULL) \
            cvar->unlink(); \
        cvar = in; \
        cvar->link(); \
    } 


public:
    // Legacy
    tracker_component() {
        fprintf(stderr, "debug - legacy tracker_component() called\n");
        set_type(TrackerMap);
        self_destruct = 1; 

        register_fields();
        reserve_fields(NULL);

        tracker = NULL;
        globalreg = NULL;
    }

	tracker_component(GlobalRegistry *in_globalreg) { 
        globalreg = in_globalreg;
        tracker = in_globalreg->entrytracker;

        set_type(TrackerMap);

        register_fields();
        reserve_fields(NULL);

        self_destruct = 1; 
    }

    tracker_component(GlobalRegistry *in_globalreg, int in_id) {
        globalreg = in_globalreg;
        tracker = in_globalreg->entrytracker;

        set_type(TrackerMap);
        set_id(in_id);

        register_fields();
        reserve_fields(NULL);

        self_destruct = 1;
    }

    tracker_component(GlobalRegistry *in_globalreg, TrackerElement *e) {
        globalreg = in_globalreg;
        tracker = in_globalreg->entrytracker;

        set_type(TrackerMap);

        register_fields();
        reserve_fields(e);

        self_destruct = 1;
    }

	virtual ~tracker_component() { 
        for (unsigned int i = 0; i < registered_fields.size(); i++) {
            delete registered_fields[i];
        }
    }

    virtual TrackerElement *clone() {
        return new tracker_component(globalreg, get_id());
    }

	int self_destruct;

protected:
    // Reserve a field via the entrytracker, using standard entrytracker build methods.
    // This field will be automatically assigned or created during the reservefields 
    // stage.
    int RegisterField(string in_name, TrackerType in_type, string in_desc, 
            void **in_dest) {
        int id = tracker->RegisterField(in_name, in_type, in_desc);

        registered_field *rf = new registered_field(id, in_dest);

        registered_fields.push_back(rf);

        return id;
    }

    // Reserve a field via the entrytracker, using standard entrytracker build methods,
    // but do not assign or create during the reservefields stage.
    // This can be used for registering sub-components of maps which are not directly
    // instantiated as top-level fields.
    int RegisterField(string in_name, TrackerType in_type, string in_desc) {
        int id = tracker->RegisterField(in_name, in_type, in_desc);
        return id;
    }

    // Reserve a field via the entrytracker, using standard entrytracker build methods.
    // This field will be automatically assigned or created during the reservefields 
    // stage.
    // You will nearly always want to use registercomplex below since fields with 
    // specific builders typically want to inherit from a subtype
    int RegisterField(string in_name, TrackerElement *in_builder, string in_desc, 
            void **in_dest) {
        int id = tracker->RegisterField(in_name, in_builder, in_desc);

        registered_field *rf = new registered_field(id, in_dest);

        registered_fields.push_back(rf);

        return id;
    }

    // Reserve a complex via the entrytracker, using standard entrytracker build methods.
    // This field will NOT be automatically assigned or built during the reservefields 
    // stage, callers should manually create these fields, importing from the parent
    int RegisterComplexField(string in_name, TrackerElement *in_builder, string in_desc) {
        int id = tracker->RegisterField(in_name, in_builder, in_desc);
        return id;
    }

    // Register field types and get a field ID.  Called during record creation, prior to 
    // assigning an existing trackerelement tree or creating a new one
    virtual void register_fields() { }

    // Populate fields - either new (e == NULL) or from an existing structure which
    //  may contain a generic version of our data.
    // When populating from an existing structure, bind each field to this instance so
    //  that we can track usage and delete() appropriately.
    // Populate automatically based on the fields we have reserved, subclasses can 
    // override if they really need to do something special
    virtual void reserve_fields(TrackerElement *e) {
        for (unsigned int i = 0; i < registered_fields.size(); i++) {
            registered_field *rf = registered_fields[i];
            *(rf->assign) = import_or_new(e, rf->id);
        }
    }

    // Inherit from an existing element or assign a new one.
    // Add imported or new field to our map for use tracking.
    virtual TrackerElement *import_or_new(TrackerElement *e, int i) {
        TrackerElement *r;

        // Find the value in the importer element
        if (e != NULL) {
            r = e->get_map_value(i);

            if (r != NULL) {
                add_map(r);
                return r;
            }
        }

        r = tracker->GetTrackedInstance(i);
        add_map(r);

        return r;
    }

    class registered_field {
        public:
            registered_field(int id, void **assign) { 
                this->id = id; 
                this->assign = (TrackerElement **) assign;
            }

            int id;
            TrackerElement** assign;
    };

    GlobalRegistry *globalreg;
    EntryTracker *tracker;

    vector<registered_field *> registered_fields;

};

enum kis_ipdata_type {
	ipdata_unknown = 0,
	ipdata_factoryguess = 1,
	ipdata_udptcp = 2,
	ipdata_arp = 3,
	ipdata_dhcp = 4,
	ipdata_group = 5
};

// New component-based ip data
class kis_tracked_ip_data : public tracker_component {
public:
    kis_tracked_ip_data(GlobalRegistry *in_globalreg) : 
        tracker_component(in_globalreg) { }

    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { } 

    // Inherit from an existing non-specific tracked set of records - point at the parent node
    // of a common ipdata record
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone() {
        return new kis_tracked_ip_data(globalreg, get_id());
    }

    __Proxy(ip_type, int32_t, kis_ipdata_type, kis_ipdata_type, ip_type);
    __Proxy(ip_addr, uint64_t, uint64_t, uint64_t, ip_addr_block);
    __Proxy(ip_netmask, uint64_t, uint64_t, uint64_t, ip_netmask);
    __Proxy(ip_gateway, uint64_t, uint64_t, uint64_t, ip_gateway);

protected:
    virtual void register_fields() {
        ip_type_id = 
            RegisterField("kismet.common.ipdata.type", TrackerInt32, 
                    "ipdata type enum", (void**) &ip_type);
        ip_addr_block_id = 
            RegisterField("kismet.common.ipdata.address", TrackerUInt64,
                    "ip address", (void**) &ip_addr_block);
        ip_netmask_id =
            RegisterField("kismet.common.ipdata.netmask", TrackerUInt64,
                    "ip netmask", (void**) &ip_netmask);
        ip_gateway_id =
            RegisterField("kismet.common.ipdata.gateway", TrackerUInt64,
                    "ip gateway", (void**) &ip_gateway);
    }

    int ip_type_id, ip_addr_block_id, ip_netmask_id, ip_gateway_id;

    TrackerElement *ip_type;
    TrackerElement *ip_addr_block;
    TrackerElement *ip_netmask;
    TrackerElement *ip_gateway;
};

// Component-tracker common GPS element
class kis_tracked_location_triplet : public tracker_component {
public:
    kis_tracked_location_triplet(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { } 

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone() {
        return new kis_tracked_location_triplet(globalreg, get_id());
    }

    // Use proxy macro to define get/set
    __Proxy(lat, double, double, double, lat);
    __Proxy(lon, double, double, double, lon);
    __Proxy(alt, double, double, double, alt);
    __Proxy(speed, double, double, double, spd);
    __Proxy(fix, uint8_t, uint8_t, uint8_t, fix);
    __Proxy(valid, uint8_t, bool, bool, valid);

    void set(double in_lat, double in_lon, double in_alt, unsigned int in_fix) {
        set_lat(in_lat);
        set_lon(in_lon);
        set_alt(in_alt);
        set_fix(in_fix);
        set_valid(1);
    }

    void set(double in_lat, double in_lon) {
        set_lat(in_lat);
        set_lon(in_lon);
        set_fix(2);
        set_valid(1);
    }

	inline kis_tracked_location_triplet& operator= (const kis_tracked_location_triplet& in) {
        set_lat(in.get_lat());
        set_lon(in.get_lon());
        set_alt(in.get_alt());
        set_speed(in.get_speed());
        set_fix(in.get_fix());
        set_valid(in.get_valid());

        return *this;
    }

protected:
    virtual void register_fields() {
        lat_id = 
            RegisterField("kismet.common.location.lat", TrackerDouble,
                    "latitude", (void **) &lat);
        lon_id = 
            RegisterField("kismet.common.location.lon", TrackerDouble,
                    "longitude", (void **) &lon);
        alt_id =
            RegisterField("kismet.common.location.alt", TrackerDouble,
                    "altitude", (void **) &alt);
        spd_id =
            RegisterField("kismet.common.location.speed", TrackerDouble,
                    "speed", (void **) &spd);
        fix_id =
            RegisterField("kismet.common.location.fix", TrackerUInt8,
                    "gps fix", (void **) &fix);
        valid_id =
            RegisterField("kismet.common.location.valid", TrackerUInt8,
                    "valid location", (void **) &valid);
    }

    int lat_id, lon_id, alt_id, spd_id, fix_id, valid_id;

    TrackerElement *lat, *lon, *alt, *spd, *fix, *valid;
};

// min/max/avg location
class kis_tracked_location : public tracker_component {
public:
    const static int precision_multiplier = 10000;

    kis_tracked_location(GlobalRegistry *in_globalreg) : 
        tracker_component(in_globalreg) { }

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { }

    virtual TrackerElement *clone() {
        return new kis_tracked_location(globalreg, get_id());
    }

    kis_tracked_location(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        register_fields();
        reserve_fields(e);
    }

    void add_loc(double in_lat, double in_lon, double in_alt, unsigned int fix) {
        set_valid(1);

        if (fix > get_fix()) {
            set_fix(fix);
        }

        if (in_lat < min_loc->get_lat() || min_loc->get_lat() == 0) {
            min_loc->set_lat(in_lat);
        }

        if (in_lat > max_loc->get_lat() || max_loc->get_lat() == 0) {
            max_loc->set_lat(in_lat);
        }

        if (in_lon < min_loc->get_lon() || min_loc->get_lon() == 0) {
            min_loc->set_lon(in_lon);
        }

        if (in_lon > max_loc->get_lon() || max_loc->get_lon() == 0) {
            max_loc->set_lon(in_lon);
        }

        if (fix > 2) {
            if (in_alt < min_loc->get_alt() || min_loc->get_alt() == 0) {
                min_loc->set_alt(in_alt);
            }

            if (in_alt > max_loc->get_alt() || max_loc->get_alt() == 0) {
                max_loc->set_alt(in_alt);
            }
        }


        // Append to averaged location
        (*avg_lat) += (int64_t) (in_lat * precision_multiplier);
        (*avg_lon) += (int64_t) (in_lon * precision_multiplier);

        if (fix > 2) {
            (*avg_alt) += (int64_t) (in_alt * precision_multiplier);
            (*num_alt_avg)++;
        }

        double calc_lat, calc_lon, calc_alt;

        calc_lat = (double) (GetTrackerValue<int64_t>(avg_lat) / 
                GetTrackerValue<uint64_t>(num_avg)) / precision_multiplier;
        calc_lon = (double) (GetTrackerValue<int64_t>(avg_lon) / 
                GetTrackerValue<uint64_t>(num_avg)) / precision_multiplier;
        calc_alt = (double) (GetTrackerValue<int64_t>(avg_alt) / 
                GetTrackerValue<uint64_t>(num_alt_avg)) / precision_multiplier;
        avg_loc->set(calc_lat, calc_lon, calc_alt, 3);
    }

    __Proxy(valid, uint8_t, bool, bool, loc_valid);
    __Proxy(fix, uint8_t, unsigned int, unsigned int, loc_fix);

    kis_tracked_location_triplet *get_min_loc() { return min_loc; }
    kis_tracked_location_triplet *get_max_loc() { return max_loc; }
    kis_tracked_location_triplet *get_avg_loc() { return avg_loc; }

    __Proxy(agg_lat, uint64_t, uint64_t, uint64_t, avg_lat);
    __Proxy(agg_lon, uint64_t, uint64_t, uint64_t, avg_lon);
    __Proxy(agg_alt, uint64_t, uint64_t, uint64_t, avg_alt);
    __Proxy(num_agg, uint64_t, uint64_t, uint64_t, num_avg);
    __Proxy(num_alt_agg, uint64_t, uint64_t, uint64_t, num_alt_avg);

protected:
    virtual void register_fields() {
        kis_tracked_location_triplet *loc_builder = new kis_tracked_location_triplet(globalreg, 0);

        loc_valid_id = RegisterField("kismet.common.location.loc_valid", TrackerUInt8,
                "location data valid", (void **) &loc_valid);

        loc_fix_id = RegisterField("kismet.common.location.loc_fix", TrackerUInt8,
                "location fix precision (2d/3d)", (void **) &loc_fix);

        min_loc_id = RegisterComplexField("kismet.common.location.min_loc", loc_builder, 
                "minimum corner of bounding rectangle");
        max_loc_id = RegisterComplexField("kismet.common.location.max_loc", loc_builder,
                "maximum corner of bounding rectangle");
        avg_loc_id = RegisterComplexField("kismet.common.location.avg_loc", loc_builder,
                "average corner of bounding rectangle");

        avg_lat_id = RegisterField("kismet.common.location.avg_lat", TrackerInt64,
                "run-time average latitude", (void **) &avg_lat);
        avg_lon_id = RegisterField("kismet.common.location.avg_lon", TrackerInt64,
                "run-time average longitude", (void **) &avg_lon);
        avg_alt_id = RegisterField("kismet.common.location.avg_alt", TrackerInt64,
                "run-time average altitude", (void **) &avg_alt);
        num_avg_id = RegisterField("kismet.common.location.avg_num", TrackerUInt64,
                "number of run-time average samples", (void **) &num_avg);
        num_alt_avg_id = RegisterField("kismet.common.location.avg_alt_num", TrackerUInt64,
                "number of run-time average samples (altitude)", (void **) &num_alt_avg);

    }

    // We have to override this because we need to build our complex types on top of the 
    // automatic types we get from tracker_component
    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        min_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(min_loc_id));
        max_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(max_loc_id));
        avg_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(avg_loc_id));
    }

    kis_tracked_location_triplet *min_loc, *max_loc, *avg_loc;
    int min_loc_id, max_loc_id, avg_loc_id;

    TrackerElement *avg_lat, *avg_lon, *avg_alt, *num_avg, *num_alt_avg;
    int avg_lat_id, avg_lon_id, avg_alt_id, num_avg_id, num_alt_avg_id;

    TrackerElement *loc_valid;
    int loc_valid_id;

    TrackerElement *loc_fix;
    int loc_fix_id;
};

// Component-tracker based signal data
// TODO operator overloading once rssi/dbm fixed upstream
class kis_tracked_signal_data : public tracker_component {
public:
    kis_tracked_signal_data(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { } 

    // Inherit from an existing non-specific tracked set of records - point at the parent node
    // of a common ipdata record
    kis_tracked_signal_data(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone() {
        return new kis_tracked_signal_data(globalreg, get_id());
    }

	kis_tracked_signal_data& operator+= (const Packinfo_Sig_Combo& in) {
        if (in.lay1 != NULL) {
            if (in.lay1->signal_type == kis_l1_signal_type_dbm) {
                if (in.lay1->signal_dbm != 0) {

                    last_signal_dbm->set((int32_t) in.lay1->signal_dbm);

                    if ((*min_signal_dbm) == (int32_t) 0 ||
                            (*min_signal_dbm) > (int32_t) in.lay1->signal_dbm) {
                        min_signal_dbm->set((int32_t) in.lay1->signal_dbm);
                    }

                    if ((*max_signal_dbm) == (int32_t) 0 ||
                            (*max_signal_dbm) < (int32_t) in.lay1->signal_dbm) {
                        max_signal_dbm->set((int32_t) in.lay1->signal_dbm);

                        if (in.gps != NULL) {
                            peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt, in.gps->gps_fix);
                        }
                    }
                }

                if (in.lay1->noise_dbm != 0) {
                    last_noise_dbm->set((int32_t) in.lay1->noise_dbm);

                    if ((*min_noise_dbm) == (int32_t) 0 ||
                            (*min_noise_dbm) > (int32_t) in.lay1->noise_dbm) {
                        min_noise_dbm->set((int32_t) in.lay1->noise_dbm);
                    }

                    if ((*max_noise_dbm) == (int32_t) 0 ||
                            (*max_noise_dbm) < (int32_t) in.lay1->noise_dbm) {
                        max_noise_dbm->set((int32_t) in.lay1->noise_dbm);
                    }
                }
            } else if (in.lay1->signal_type == kis_l1_signal_type_rssi) {
                if (in.lay1->signal_rssi != 0) {
                    last_signal_rssi->set((int32_t) in.lay1->signal_rssi);

                    if ((*min_signal_rssi) == (int32_t) 0 ||
                            (*min_signal_rssi) > (int32_t) in.lay1->signal_rssi) {
                        min_signal_dbm->set((int32_t) in.lay1->signal_rssi);
                    }

                    if ((*max_signal_rssi) == (int32_t) 0 ||
                            (*max_signal_rssi) < (int32_t) in.lay1->signal_rssi) {
                        max_signal_rssi->set((int32_t) in.lay1->signal_rssi);

                        if (in.gps != NULL) {
                            peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt, in.gps->gps_fix);
                        }
                    }
                }

                if (in.lay1->noise_rssi != 0) {
                    last_noise_rssi->set((int32_t) in.lay1->noise_rssi);

                    if ((*min_noise_rssi) == (int32_t) 0 ||
                            (*min_noise_rssi) > (int32_t) in.lay1->noise_rssi) {
                        min_noise_rssi->set((int32_t) in.lay1->noise_rssi);
                    }

                    if ((*max_noise_rssi) == (int32_t) 0 ||
                            (*max_noise_rssi) < (int32_t) in.lay1->noise_rssi) {
                        max_noise_rssi->set((int32_t) in.lay1->noise_rssi);
                    }
                }

            }

            (*carrierset) |= (uint64_t) in.lay1->carrier;
            (*encodingset) |= (uint64_t) in.lay1->encoding;

            if ((*maxseenrate) < (double) in.lay1->datarate) {
                maxseenrate->set((double) in.lay1->datarate);
            }
		}

		return *this;
	}

    __ProxyGet(last_signal_dbm, int32_t, int, last_signal_dbm);
    __ProxyGet(min_signal_dbm, int32_t, int, min_signal_dbm);
    __ProxyGet(max_signal_dbm, int32_t, int, max_signal_dbm);

    __ProxyGet(last_noise_dbm, int32_t, int, last_noise_dbm);
    __ProxyGet(min_noise_dbm, int32_t, int, min_noise_dbm);
    __ProxyGet(max_noise_dbm, int32_t, int, max_noise_dbm);

    __ProxyGet(last_signal_rssi, int32_t, int, last_signal_rssi);
    __ProxyGet(min_signal_rssi, int32_t, int, min_signal_rssi);
    __ProxyGet(max_signal_rssi, int32_t, int, max_signal_rssi);

    __ProxyGet(last_noise_rssi, int32_t, int, last_noise_rssi);
    __ProxyGet(min_noise_rssi, int32_t, int, min_noise_rssi);
    __ProxyGet(max_noise_rssi, int32_t, int, max_noise_rssi);

    __ProxyGet(maxseenrate, double, double, maxseenrate);
    __ProxyGet(encodingset, uint64_t, uint64_t, encodingset);
    __ProxyGet(carrierset, uint64_t, uint64_t, carrierset);

    kis_tracked_location_triplet *get_peak_loc() { return peak_loc; }

protected:
    virtual void register_fields() {
        last_signal_dbm_id =
            RegisterField("kismet.common.signal.last_signal_dbm", TrackerInt32,
                    "most recent signal (dBm)", (void **) &last_signal_dbm);
        last_noise_dbm_id =
            RegisterField("kismet.common.signal.last_noise_dbm", TrackerInt32,
                    "most recent noise (dBm)", (void **) &last_noise_dbm);

        min_signal_dbm_id =
            RegisterField("kismet.common.signal.min_signal_dbm", TrackerInt32,
                    "minimum signal (dBm)", (void **) &min_signal_dbm);
        min_noise_dbm_id =
            RegisterField("kismet.common.signal.min_noise_dbm", TrackerInt32,
                    "minimum noise (dBm)", (void **) min_noise_dbm);

        max_signal_dbm_id =
            RegisterField("kismet.common.signal.max_signal_dbm", TrackerInt32,
                    "maximum signal (dBm)", (void **) &max_signal_dbm);
        max_noise_dbm_id =
            RegisterField("kismet.common.signal.max_noise_dbm", TrackerInt32,
                    "maximum noise (dBm)", (void **) &max_noise_dbm);

        last_signal_rssi_id =
            RegisterField("kismet.common.signal.last_signal_rssi", TrackerInt32,
                    "most recent signal (RSSI)", (void**) &last_signal_rssi);
        last_noise_rssi_id =
            RegisterField("kismet.common.signal.last_noise_rssi", TrackerInt32,
                    "most recent noise (RSSI)", (void **) &last_noise_rssi);

        min_signal_rssi_id =
            RegisterField("kismet.common.signal.min_signal_rssi", TrackerInt32,
                    "minimum signal (rssi)", (void **) &min_signal_rssi);
        min_noise_rssi_id =
            RegisterField("kismet.common.signal.min_noise_rssi", TrackerInt32,
                    "minimum noise (RSSI)", (void **) &min_noise_rssi);

        max_signal_rssi_id =
            RegisterField("kismet.common.signal.max_signal_rssi", TrackerInt32,
                    "maximum signal (RSSI)", (void **) &max_signal_rssi);
        max_noise_rssi_id =
            RegisterField("kismet.common.signal.max_noise_rssi", TrackerInt32,
                    "maximum noise (RSSI)", (void **) &max_noise_rssi);


        kis_tracked_location_triplet *loc_builder = new kis_tracked_location_triplet(globalreg, 0);
        peak_loc_id = 
            RegisterComplexField("kismet.common.signal.peak_loc", loc_builder,
                    "location of strongest signal");

        maxseenrate_id =
            RegisterField("kismet.common.signal.maxseenrate", TrackerDouble,
                    "maximum observed data rate (phy dependent)", (void **) &maxseenrate);
        encodingset_id =
            RegisterField("kismet.common.signal.encodingset", TrackerUInt64,
                    "bitset of observed encodings", (void **) &encodingset);
        carrierset_id =
            RegisterField("kismet.common.signal.carrierset", TrackerUInt64,
                    "bitset of observed carrier types", (void **) &carrierset);
    }

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);
        peak_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(peak_loc_id));
    }

    int last_signal_dbm_id, last_noise_dbm_id,
        min_signal_dbm_id, min_noise_dbm_id,
        max_signal_dbm_id, max_noise_dbm_id,

        last_signal_rssi_id, last_noise_rssi_id,
        min_signal_rssi_id, min_noise_rssi_id,
        max_signal_rssi_id, max_noise_rssi_id,

        peak_loc_id,
        maxseenrate_id, encodingset_id, carrierset_id;

    TrackerElement *last_signal_dbm, *last_noise_dbm;
    TrackerElement *min_signal_dbm, *min_noise_dbm;
    TrackerElement *max_signal_dbm, *max_noise_dbm;

    TrackerElement *last_signal_rssi, *last_noise_rssi;
    TrackerElement *min_signal_rssi, *min_noise_rssi;
    TrackerElement *max_signal_rssi, *max_noise_rssi;

    kis_tracked_location_triplet *peak_loc;

    TrackerElement *maxseenrate, *encodingset, *carrierset;
};

class kis_tracked_seenby_data : public tracker_component {
public:
    kis_tracked_seenby_data(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { } 

    virtual TrackerElement *clone() {

        return new kis_tracked_signal_data(globalreg, get_id());
    }

    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        register_fields();
        reserve_fields(e);
    }

    __Proxy(uuid, uuid, uuid, uuid, src_uuid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
    __ProxyIncDec(num_packets, uint64_t, uint64_t, num_packets);

    // Intmaps need special care by the caller
    TrackerElement *get_freq_mhz_map() { return freq_mhz_map; }

    void inc_frequency_count(int frequency) {
        TrackerElement::map_iterator i = freq_mhz_map->find(frequency);

        if (i == freq_mhz_map->end()) {
            TrackerElement *e = globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
            e->set((uint64_t) 1);
            freq_mhz_map->add_intmap(frequency, e);
        } else {
            (*(i->second))++;
        }
    }

protected:
    virtual void register_fields() {
        src_uuid_id =
            RegisterField("kismet.common.seenby.uuid", TrackerUuid,
                    "UUID of source", (void **) &src_uuid);
        first_time_id =
            RegisterField("kismet.common.seenby.first_time", TrackerUInt64,
                    "first time seen time_t", (void **) &first_time);
        last_time_id =
            RegisterField("kismet.common.seenby.last_time", TrackerUInt64,
                    "last time seen time_t", (void **) &last_time);
        num_packets_id =
            RegisterField("kismet.common.seenby.num_packets", TrackerUInt64,
                    "number of packets seen by this device", (void **) &num_packets);
        freq_mhz_map_id =
            RegisterField("kismet.common.seenby.freq_mhz_map", TrackerIntMap,
                    "packets seen per frequency (mhz)", (void **) &freq_mhz_map);

        frequency_val_id =
            globalreg->entrytracker->RegisterField("kismet.common.seenby.frequency.count",
                    TrackerUInt64, "frequency packet count");
    }

    TrackerElement *src_uuid;
    int src_uuid_id;

    TrackerElement *first_time; 
    int first_time_id;

    TrackerElement *last_time;
    int last_time_id;

    TrackerElement *num_packets;
    int num_packets_id;

    TrackerElement *freq_mhz_map;
    int freq_mhz_map_id;

    int frequency_val_id;
};

// Arbitrary tag data added to network
class kis_tracked_tag : public tracker_component {
public:
    kis_tracked_tag(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_tag(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { }

    virtual TrackerElement *clone() {
        return new kis_tracked_tag(globalreg, get_id());
    }

    kis_tracked_tag(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        register_fields();
        reserve_fields(e);
    }

    __Proxy(value, string, string, string, value);
    __Proxy(dirty, uint8_t, bool, bool, dirty);

protected:
    virtual void register_fields() {
        value_id =
            RegisterField("kismet.common.tag.value", TrackerString,
                    "arbitrary tag", (void **) &value);
        dirty_id =
            RegisterField("kismet.common.tag.dirty", TrackerUInt8,
                    "tag has been modified", (void **) &dirty);
    }

    int value_id, dirty_id;
    TrackerElement *value, *dirty;
};

#endif

