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

#ifndef __DEVICE_TRACKER_H__
#define __DEVICE_TRACKER_H__

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

// Ugly macro to register a field and add it to the map
#define __RegisterField(F, N, T, D)    tracker->RegisterAndGetField(N, T, D); add_map(F)

// How big the main vector of components is, if we ever get more than this
// many tracked components we'll need to expand this but since it ties to 
// memory and track record creation it starts relatively low
#define MAX_TRACKER_COMPONENTS	64

#define KIS_PHY_ANY	-1
#define KIS_PHY_UNKNOWN -2

// fwd
class Devicetracker;

// Basic unit being tracked in a tracked device
class tracker_component : public TrackerElement {
public:
    // Legacy
    tracker_component() {
        fprintf(stderr, "debug - legacy tracker_component() called\n");
        set_type(TrackerMap);
        self_destruct = 1; 

        reserve_fields();
        register_fields(NULL);

        tracker = NULL;
        globalreg = NULL;
    }

	tracker_component(GlobalRegistry *in_globalreg) { 
        globalreg = in_globalreg;
        tracker = in_globalreg->entrytracker;

        set_type(TrackerMap);

        reserve_fields();
        register_fields(NULL);

        self_destruct = 1; 
    }

    tracker_component(GlobalRegistry *in_globalreg, int in_id) {
        globalreg = in_globalreg;
        tracker = in_globalreg->entrytracker;

        set_type(TrackerMap);
        set_id(in_id);

        reserve_fields();
        register_fields(NULL);

        self_destruct = 1;
    }

	virtual ~tracker_component() { }

    virtual TrackerElement *clone() {
        return new tracker_component(globalreg, get_id());
    }

	int self_destruct;

protected:
    // Reserve field numbers
    virtual void reserve_fields() { }

    // Populate fields - either new (e == NULL) or from an existing structure which
    // may contain a generic version of our data.
    // When populating from an existing structure, bind each field to this instance so
    // that we can track usage and delete() appropriately
    virtual void register_fields(TrackerElement *) { }

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

    GlobalRegistry *globalreg;
    EntryTracker *tracker;
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

        reserve_fields();
        register_fields(e);
    }

    virtual TrackerElement *clone() {
        return new kis_tracked_ip_data(globalreg, get_id());
    }

    void set_ip_type(kis_ipdata_type in_type) {
        ip_type->set((uint32_t) in_type);
    }


protected:
    virtual void reserve_fields() {
        ip_type_id = 
            tracker->RegisterField("kismet.common.ipdata.type", TrackerInt32, 
                    "ipdata type enum");
        ip_addr_block_id = 
            tracker->RegisterField("kismet.common.ipdata.address", TrackerUInt64,
                    "ip address");
        ip_netmask_id =
            tracker->RegisterField("kismet.common.ipdata.netmask", TrackerUInt64,
                    "ip netmask");
        ip_gateway_id =
            tracker->RegisterField("kismet.common.ipdata.gateway", TrackerUInt64,
                    "ip gateway");
    }

    virtual void register_fields(TrackerElement *e) {
        ip_type = import_or_new(e, ip_type_id);
        ip_addr_block = import_or_new(e, ip_addr_block_id);
        ip_netmask = import_or_new(e, ip_netmask_id);
        ip_gateway = import_or_new(e, ip_gateway_id);
    }

    int ip_type_id, ip_addr_block_id, ip_netmask_id, ip_gateway_id;

    TrackerElement *ip_type;
    TrackerElement *ip_addr_block;
    TrackerElement *ip_netmask;
    TrackerElement *ip_gateway;
    
};

class kis_ip_data {
public:
	kis_ip_data() {
		ip_type = ipdata_unknown;
		ip_addr_block.s_addr = 0;
		ip_netmask.s_addr = 0;
		ip_gateway.s_addr = 0;
	}

	kis_ipdata_type ip_type;

	in_addr ip_addr_block;
	in_addr ip_netmask;
	in_addr ip_gateway;

	inline kis_ip_data& operator= (const kis_ip_data& in) {
		ip_addr_block.s_addr = in.ip_addr_block.s_addr;
		ip_netmask.s_addr = in.ip_netmask.s_addr;
		ip_gateway.s_addr = in.ip_gateway.s_addr;
		ip_type = in.ip_type;

		return *this;
	}
};

class Packinfo_Sig_Combo {
public:
	Packinfo_Sig_Combo(kis_layer1_packinfo *l1, kis_gps_packinfo *gp) {
		lay1 = l1;
		gps = gp;
	}

	kis_layer1_packinfo *lay1;
	kis_gps_packinfo *gps;
};

// Component-tracker common GPS element
class kis_tracked_location_triplet : public tracker_component {
public:
    kis_tracked_location_triplet(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { } 

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        reserve_fields();
        register_fields(e);
    }

    virtual TrackerElement *clone() {
        return new kis_tracked_location_triplet(globalreg, get_id());
    }

    void set_lat(double in_lat) {
        lat->set(in_lat);
    }

    void set_lon(double in_lon) {
        lat->set(in_lon);
    }

    void set_alt(double in_alt) {
        alt->set(in_alt);
    }

    double get_lat() const {
        return GetTrackerValue<double>(lat);
    }

    double get_lon() const {
        return GetTrackerValue<double>(lon);
    }

    double get_alt() const {
        return GetTrackerValue<double>(alt);
    }

    void set(double in_lat, double in_lon, double in_alt) {
        lat->set(in_lat);
        lon->set(in_lon);
        alt->set(in_alt);
    }

    void set(double in_lat, double in_lon) {
        lat->set(in_lat);
        lon->set(in_lon);
    }

	inline kis_tracked_location_triplet& operator= (const kis_tracked_location_triplet& in) {
        this->set(in.get_lat(), in.get_lon(), in.get_alt());

        return *this;
    }

protected:
    virtual void reserve_fields() {
        lat_id = 
            tracker->RegisterField("kismet.common.location.lat", TrackerDouble,
                    "latitude");
        lon_id = 
            tracker->RegisterField("kismet.common.location.lon", TrackerDouble,
                    "longitude");
        alt_id =
            tracker->RegisterField("kismet.common.location.alt", TrackerDouble,
                    "altitude");
    }

    virtual void register_fields(TrackerElement *e) {
        lat = import_or_new(e, lat_id);
        lon = import_or_new(e, lon_id);
        alt = import_or_new(e, alt_id);
    }

    int lat_id, lon_id, alt_id;

    TrackerElement *lat, *lon, *alt;
};

// min/max/avg location
class kis_tracked_location : public tracker_component {
public:
    const static int precision_multiplier = 10000;

    kis_tracked_location(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { }

    virtual TrackerElement *clone() {
        return new kis_tracked_location(globalreg, get_id());
    }

    kis_tracked_location(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        reserve_fields();
        register_fields(e);
    }

    void add_loc(double in_lat, double in_lon, double in_alt) {
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

        if (in_alt < min_loc->get_alt() || min_loc->get_alt() == 0) {
            min_loc->set_alt(in_alt);
        }

        if (in_alt > max_loc->get_alt() || max_loc->get_alt() == 0) {
            max_loc->set_alt(in_alt);
        }

        (*avg_lat) += (int64_t) (in_lat * precision_multiplier);
        (*avg_lon) += (int64_t) (in_lon * precision_multiplier);
        (*avg_alt) += (int64_t) (in_alt * precision_multiplier);
        (*num_avg)++;

        double calc_lat, calc_lon, calc_alt;

        calc_lat = (double) (GetTrackerValue<int64_t>(avg_lat) / 
                GetTrackerValue<uint64_t>(num_avg)) / precision_multiplier;
        calc_lon = (double) (GetTrackerValue<int64_t>(avg_lon) / 
                GetTrackerValue<uint64_t>(num_avg)) / precision_multiplier;
        calc_alt = (double) (GetTrackerValue<int64_t>(avg_alt) / 
                GetTrackerValue<uint64_t>(num_avg)) / precision_multiplier;
        avg_loc->set(calc_lat, calc_lon, calc_alt);

    }

protected:
    virtual void reserve_fields() {
        kis_tracked_location_triplet *loc_builder = new kis_tracked_location_triplet(globalreg, 0);

        min_loc_id = tracker->RegisterField("kismet.common.location.min_loc", loc_builder, 
                "minimum corner of bounding rectangle");
        max_loc_id = tracker->RegisterField("kismet.common.location.max_loc", loc_builder,
                "maximum corner of bounding rectangle");
        avg_loc_id = tracker->RegisterField("kismet.common.location.avg_loc", loc_builder,
                "average corner of bounding rectangle");

        avg_lat_id = tracker->RegisterField("kismet.common.location.avg_lat", TrackerInt64,
                "run-time average latitude");
        avg_lon_id = tracker->RegisterField("kismet.common.location.avg_lon", TrackerInt64,
                "run-time average longitude");
        avg_alt_id = tracker->RegisterField("kismet.common.location.avg_alt", TrackerInt64,
                "run-time average altitude");
        num_avg_id = tracker->RegisterField("kismet.common.location.avg_num", TrackerUInt64,
                "number of run-time average samples");

    }

    virtual void register_fields(TrackerElement *e) {
        min_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(min_loc_id));
        max_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(max_loc_id));
        avg_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(avg_loc_id));

        avg_lat = import_or_new(e, avg_lat_id);
        avg_lon = import_or_new(e, avg_lon_id);
        avg_alt = import_or_new(e, avg_alt_id);
        num_avg = import_or_new(e, num_avg_id);
    }

    int min_loc_id, max_loc_id, avg_loc_id;
    int avg_lat_id, avg_lon_id, avg_alt_id, num_avg_id;

    kis_tracked_location_triplet *min_loc, *max_loc, *avg_loc;

    TrackerElement *avg_lat, *avg_lon, *avg_alt, *num_avg;
};

// SNR info

#define KIS_SIGNAL_DBM_BOGUS_MIN	0
#define KIS_SIGNAL_DBM_BOGUS_MAX	-256
#define KIS_SIGNAL_RSSI_BOGUS_MIN	1024
#define KIS_SIGNAL_RSSI_BOGUS_MAX	0

enum {
    kis_signal_unknown = 0,
    kis_signal_dbm = 1,
    kis_signal_rssi = 2
};

// Component-tracker based signal data
// TODO operator overloading once rssi/dbm fixed upstream
class kis_tracked_signal_data : public tracker_component {
public:
    kis_tracked_signal_data(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) { }

    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { } 

    virtual TrackerElement *clone() {
        return new kis_tracked_signal_data(globalreg, get_id());
    }

    kis_tracked_signal_data(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        reserve_fields();
        register_fields(e);
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
                            if (in.gps->gps_fix > 2)
                                peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt);
                            else
                                peak_loc->set(in.gps->lat, in.gps->lon);
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
                            if (in.gps->gps_fix > 2)
                                peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt);
                            else
                                peak_loc->set(in.gps->lat, in.gps->lon);
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

protected:
    virtual void reserve_fields() {
        last_signal_dbm_id =
            tracker->RegisterField("kismet.common.signal.last_signal_dbm", TrackerInt32,
                    "most recent signal (dBm)");
        last_noise_dbm_id =
            tracker->RegisterField("kismet.common.signal.last_noise_dbm", TrackerInt32,
                    "most recent noise (dBm)");

        min_signal_dbm_id =
            tracker->RegisterField("kismet.common.signal.min_signal_dbm", TrackerInt32,
                    "minimum signal (dBm)");
        min_noise_dbm_id =
            tracker->RegisterField("kismet.common.signal.min_noise_dbm", TrackerInt32,
                    "minimum noise (dBm)");

        max_signal_dbm_id =
            tracker->RegisterField("kismet.common.signal.max_signal_dbm", TrackerInt32,
                    "maximum signal (dBm)");
        max_noise_dbm_id =
            tracker->RegisterField("kismet.common.signal.max_noise_dbm", TrackerInt32,
                    "maximum noise (dBm)");

        last_signal_rssi_id =
            tracker->RegisterField("kismet.common.signal.last_signal_rssi", TrackerInt32,
                    "most recent signal (RSSI)");
        last_noise_rssi_id =
            tracker->RegisterField("kismet.common.signal.last_noise_rssi", TrackerInt32,
                    "most recent noise (RSSI)");

        min_signal_rssi_id =
            tracker->RegisterField("kismet.common.signal.min_signal_rssi", TrackerInt32,
                    "minimum signal (rssi)");
        min_noise_rssi_id =
            tracker->RegisterField("kismet.common.signal.min_noise_rssi", TrackerInt32,
                    "minimum noise (RSSI)");

        max_signal_rssi_id =
            tracker->RegisterField("kismet.common.signal.max_signal_rssi", TrackerInt32,
                    "maximum signal (RSSI)");
        max_noise_rssi_id =
            tracker->RegisterField("kismet.common.signal.max_noise_rssi", TrackerInt32,
                    "maximum noise (RSSI)");


        kis_tracked_location_triplet *loc_builder = new kis_tracked_location_triplet(globalreg, 0);
        peak_loc_id = 
            tracker->RegisterField("kismet.common.signal.peak_loc", loc_builder,
                    "location of strongest signal");

        maxseenrate_id =
            tracker->RegisterField("kismet.common.signal.maxseenrate", TrackerDouble,
                    "maximum observed data rate (phy dependent)");
        encodingset_id =
            tracker->RegisterField("kismet.common.signal.encodingset", TrackerUInt64,
                    "bitset of observed encodings");
        carrierset_id =
            tracker->RegisterField("kismet.common.signal.carrierset", TrackerUInt64,
                    "bitset of observed carrier types");
    }

    virtual void register_fields(TrackerElement *e) {
        last_signal_dbm = import_or_new(e, last_signal_dbm_id);
        last_noise_dbm = import_or_new(e, last_noise_dbm_id);
        min_signal_dbm = import_or_new(e, min_signal_dbm_id);
        min_noise_dbm = import_or_new(e, min_noise_dbm_id);
        max_signal_dbm = import_or_new(e, max_signal_dbm_id);
        max_noise_dbm = import_or_new(e, max_noise_dbm_id);

        last_signal_rssi = import_or_new(e, last_signal_rssi_id);
        last_noise_rssi = import_or_new(e, last_noise_rssi_id);
        min_signal_rssi = import_or_new(e, min_signal_rssi_id);
        min_noise_rssi = import_or_new(e, min_noise_rssi_id);
        max_signal_rssi = import_or_new(e, max_signal_rssi_id);
        max_noise_rssi = import_or_new(e, max_noise_rssi_id);

        peak_loc = new kis_tracked_location_triplet(globalreg, e->get_map_value(peak_loc_id));

        maxseenrate = import_or_new(e, maxseenrate_id);
        carrierset = import_or_new(e, carrierset_id);
        encodingset = import_or_new(e, encodingset_id);
    }

    int last_signal_dbm_id, last_noise_dbm_id,
        min_signal_dbm_id, min_noise_dbm_id,
        max_signal_dbm_id, max_noise_dbm_id,

        last_signal_rssi_id, last_noise_rssi_id,
        min_signal_rssi_id, min_noise_rssi_id,
        max_signal_rssi_id, max_noise_rssi_id,

        peak_loc_id,
        maxseenrate_id, encodingset_id, carrierset_id;

    TrackerElement *signal_type;

    TrackerElement *last_signal_dbm, *last_noise_dbm;
    TrackerElement *min_signal_dbm, *min_noise_dbm;
    TrackerElement *max_signal_dbm, *max_noise_dbm;

    TrackerElement *last_signal_rssi, *last_noise_rssi;
    TrackerElement *min_signal_rssi, *min_noise_rssi;
    TrackerElement *max_signal_rssi, *max_noise_rssi;

    kis_tracked_location_triplet *peak_loc;

    TrackerElement *maxseenrate, *encodingset, *carrierset;
};

struct kis_signal_data {
	kis_signal_data() {
		// These all go to 0 since we don't know if it'll be positive or
		// negative
		last_signal_dbm = last_noise_dbm = KIS_SIGNAL_DBM_BOGUS_MIN;
		min_signal_dbm = min_noise_dbm = KIS_SIGNAL_DBM_BOGUS_MIN;
		max_signal_dbm = max_noise_dbm = KIS_SIGNAL_DBM_BOGUS_MAX;

		last_signal_rssi = last_noise_rssi = KIS_SIGNAL_RSSI_BOGUS_MIN;
		min_signal_rssi = min_noise_rssi = KIS_SIGNAL_RSSI_BOGUS_MIN;
		max_signal_rssi = max_noise_rssi = KIS_SIGNAL_RSSI_BOGUS_MAX;

		peak_lat = peak_lon = 0;
		peak_alt = KIS_GPS_ALT_BOGUS_MIN;

		maxseenrate = 0;
		encodingset = 0;
		carrierset = 0;
	}

	int last_signal_dbm, last_noise_dbm;
	int min_signal_dbm, min_noise_dbm;
	int max_signal_dbm, max_noise_dbm;

	int last_signal_rssi, last_noise_rssi;
	int min_signal_rssi, min_noise_rssi;
	int max_signal_rssi, max_noise_rssi;
	// Peak locations
	double peak_lat, peak_lon, peak_alt;

	// Max rate
	int maxseenrate;

	// Seen encodings
	uint32_t encodingset;
	uint32_t carrierset;

	inline kis_signal_data& operator= (const kis_signal_data& in) {
		last_signal_dbm = in.last_signal_dbm;
		last_noise_dbm = in.last_noise_dbm;

		min_signal_dbm = in.min_signal_dbm;
		max_signal_dbm = in.max_signal_dbm;

		min_noise_dbm = in.min_noise_dbm;
		max_noise_dbm = in.max_noise_dbm;

		last_signal_rssi = in.last_signal_rssi;
		last_noise_rssi = in.last_noise_rssi;

		min_signal_rssi = in.min_signal_rssi;
		max_signal_rssi = in.max_signal_rssi;

		min_noise_rssi = in.min_noise_rssi;
		max_noise_rssi = in.max_noise_rssi;

		peak_lat = in.peak_lat;
		peak_lon = in.peak_lon;
		peak_alt = in.peak_alt;

		maxseenrate = in.maxseenrate;

		encodingset = in.encodingset;
		carrierset = in.carrierset;

		return *this;
	}

	inline kis_signal_data& operator+= (const Packinfo_Sig_Combo& in) {
		if (in.lay1 != NULL) {
			int gpscopy = 0;

			if (in.lay1->signal_dbm < min_signal_dbm &&
				in.lay1->signal_dbm != 0)
				min_signal_dbm = in.lay1->signal_dbm;

			if (in.lay1->signal_rssi < min_signal_rssi &&
				in.lay1->signal_rssi != 0)
				min_signal_rssi = in.lay1->signal_rssi;

			if (in.lay1->signal_dbm > max_signal_dbm &&
				in.lay1->signal_dbm != 0) {
				max_signal_dbm = in.lay1->signal_dbm;
				gpscopy = 1;
			}

			if (in.lay1->signal_rssi > max_signal_rssi &&
				in.lay1->signal_rssi != 0) {
				max_signal_rssi = in.lay1->signal_rssi;
				gpscopy = 1;
			}

			if (in.lay1->noise_dbm < min_noise_dbm &&
				in.lay1->noise_dbm != 0)
				min_noise_dbm = in.lay1->noise_dbm;

			if (in.lay1->noise_rssi < min_noise_rssi &&
				in.lay1->noise_rssi != 0)
				min_noise_rssi = in.lay1->noise_rssi;

			if (in.lay1->noise_dbm > max_noise_dbm &&
				in.lay1->noise_dbm != 0)
				max_noise_dbm = in.lay1->noise_dbm;

			if (in.lay1->noise_rssi > max_noise_rssi &&
				in.lay1->noise_rssi != 0) 
				max_noise_rssi = in.lay1->noise_rssi;

			if (in.lay1->signal_rssi != 0)
				last_signal_rssi = in.lay1->signal_rssi;
			if (in.lay1->signal_dbm != 0)
				last_signal_dbm = in.lay1->signal_dbm;
			if (in.lay1->noise_rssi != 0)
				last_noise_rssi = in.lay1->noise_rssi;
			if (in.lay1->noise_dbm != 0)
				last_noise_dbm = in.lay1->noise_dbm;

			carrierset |= in.lay1->carrier;
			encodingset |= in.lay1->encoding;

			if (in.lay1->datarate > maxseenrate)
				maxseenrate = in.lay1->datarate;

			if (gpscopy && in.gps != NULL) {
				peak_lat = in.gps->lat;
				peak_lon = in.gps->lon;
				peak_alt = in.gps->alt;
			}
		}

		return *this;
	}

	inline kis_signal_data& operator+= (const kis_signal_data& in) {
		if (in.min_signal_dbm < min_signal_dbm)
			min_signal_dbm = in.min_signal_dbm;

		if (in.min_signal_rssi < min_signal_rssi)
			min_signal_rssi = in.min_signal_rssi;

		if (in.max_signal_dbm > max_signal_dbm) {
			max_signal_dbm = in.max_signal_dbm;
			peak_lat = in.peak_lat;
			peak_lon = in.peak_lon;
			peak_alt = in.peak_alt;
		}

		if (in.max_signal_rssi > max_signal_rssi) {
			max_signal_rssi = in.max_signal_rssi;
			peak_lat = in.peak_lat;
			peak_lon = in.peak_lon;
			peak_alt = in.peak_alt;
		}

		if (in.min_noise_dbm < min_noise_dbm)
			min_noise_dbm = in.min_noise_dbm;

		if (in.min_noise_rssi < min_noise_rssi)
			min_noise_rssi = in.min_noise_rssi;

		if (in.max_noise_dbm > max_noise_dbm)
			max_noise_dbm = in.max_noise_dbm;

		if (in.max_noise_rssi > max_noise_rssi)
			max_noise_rssi = in.max_noise_rssi;

		encodingset |= in.encodingset;
		carrierset |= in.carrierset;

		if (maxseenrate < in.maxseenrate)
			maxseenrate = in.maxseenrate;

		return *this;
	}
};

// Seenby records for tracking the packet sources which have seen this device
// and how much of the device they've seen
class kis_seenby_data {
public:
	time_t first_time;
	time_t last_time;
	uint32_t num_packets;

	// Map of frequencies seen by this device
	map<unsigned int, unsigned int> freq_mhz_map;
};

class kis_tag_data {
public:
	string value;
	bool dirty;
};

// Fwd ktd
class kis_tracked_device;

// Bitfield of basic types a device is classified as.  The device may be multiple
// of these depending on the phy.  The UI will display them based on the type
// in the display filter.
//
// Generic device.  Everything is a device.  If the phy has no
// distinguishing factors for classifying it as anything else, this is 
// what it gets to be.
#define KIS_DEVICE_BASICTYPE_DEVICE		0
// Access point (in wifi terms) or otherwise central coordinating device
// (if available in other PHYs)
#define KIS_DEVICE_BASICTYPE_AP			1
// Wireless client device (up to the implementor if a peer-to-peer phy
// classifies all as clients, APs, or simply devices)
#define KIS_DEVICE_BASICTYPE_CLIENT		2
// Bridged/wired client, something that isn't itself homed on the wireless
// medium
#define KIS_DEVICE_BASICTYPE_WIRED		4
// Adhoc/peer network
#define KIS_DEVICE_BASICTYPE_PEER		8
// Common mask of client types
#define KIS_DEVICE_BASICTYPE_CLIENTMASK	6

// Basic encryption types
#define KIS_DEVICE_BASICCRYPT_NONE		0
#define KIS_DEVICE_BASICCRYPT_ENCRYPTED	(1 << 1)
// More detailed encryption data if available
#define KIS_DEVICE_BASICCRYPT_L2		(1 << 2)
#define KIS_DEVICE_BASICCRYPT_L3		(1 << 3)
#define KIS_DEVICE_BASICCRYPT_WEAKCRYPT	(1 << 4)
#define KIS_DEVICE_BASICCRYPT_DECRYPTED	(1 << 5)

// Base of all device tracking under the new trackerentry system
class kis_tracked_device_base : public tracker_component {
public:
    kis_tracked_device_base(GlobalRegistry *in_globalreg) : tracker_component(in_globalreg) {

    }

    // Unique key
    TrackerElement *key;
    int key_id;

    // Printable name for UI summary.  For APs could be latest SSID, for BT the UAP
    // guess, etc.
    TrackerElement *name;
    int name_id;

    // Printable basic type relevant to the phy, ie "Wired", "AP", "Bluetooth", etc.
    // This can be set per-phy and is treated as a printable interpretation.  This should
    // be empty if the phy layer is unable to add something intelligent
    TrackerElement *type_string;
    int type_string_id;

    // Basic phy-neutral type for sorting and classification
    TrackerElement *basic_type_set;
    int basic_type_set_id;

    // Printable crypt string, which is set by the phy and is the best printable
    // representation of the phy crypt options.  This should be empty if the phy
    // layer hasn't added something intelligent.
    TrackerElement *crypt_string;
    int crypt_string_id;

    // Bitset of basic phy-neutral crypt options
    TrackerElement *basic_crypt_set;
    int basic_crypt_set_id;

    // First and last seen
    TrackerElement *first_time, *last_time;
    int first_time_id, last_time_id;

    // Packet counts
    TrackerElement *packets, *tx_packets, *rx_packets,
                   // link-level packets
                   *llc_packets, 
                   // known-bad packets
                   *error_packets,
                   // data packets
                   *data_packets, 
                   // Encrypted data packets (double-counted with data)
                   *crypt_packets,
                   // Excluded / filtered packets
                   *filter_packets;
    int packets_id, tx_packets_id, rx_packets_id,
        llc_packets_id, error_packets_id, data_packets_id,
        crypt_packets_id, filter_packets_id;

    // Data seen in bytes
    TrackerElement *datasize_tx, *datasize_rx;
    int datasize_tx_id, datasize_rx_id;

    // New # of packets and amount of data bytes since last tick
    TrackerElement *new_packets;
    int new_packets_id;

	// Channel and frequency as per PHY type
    TrackerElement *channel, *frequency;
    int channel_id, frequency_id;

    // Signal data
    kis_tracked_signal_data *signal_data;
    int signal_data_id;

    // Manufacturer, if we're able to derive, either from OUI or from other data (phy-dependent)
    TrackerElement *manuf;
    int manuf_id;

    // Alerts triggered on this device
    TrackerElement *alert;
    int alert_id;

    kis_tracked_device_base(GlobalRegistry *in_globalreg, TrackerElement *e) : 
        tracker_component(in_globalreg) {

        reserve_fields();
        register_fields(e);
    }

protected:
    virtual void register_fields(TrackerElement *e) {
        key = import_or_new(e, key_id);

        name = import_or_new(e, name_id);

        type_string = import_or_new(e, type_string_id);
        basic_type_set = import_or_new(e, basic_type_set_id);

        crypt_string = import_or_new(e, crypt_string_id);
        basic_crypt_set = import_or_new(e, basic_type_set_id);

        first_time = import_or_new(e, first_time_id);
        last_time = import_or_new(e, last_time_id);

        packets = import_or_new(e, packets_id);
        rx_packets = import_or_new(e, rx_packets_id);
        tx_packets = import_or_new(e, tx_packets_id);
        llc_packets = import_or_new(e, llc_packets_id);
        error_packets = import_or_new(e, error_packets_id);
        data_packets = import_or_new(e, data_packets_id);
        crypt_packets = import_or_new(e, crypt_packets_id);
        filter_packets = import_or_new(e, filter_packets_id);

        datasize_tx = import_or_new(e, datasize_tx_id);
        datasize_rx = import_or_new(e, datasize_rx_id);
        
        new_packets = import_or_new(e, new_packets_id);

        signal_data = new kis_tracked_signal_data(globalreg, e->get_map_value(signal_data_id));

        channel = import_or_new(e, channel_id);
        frequency = import_or_new(e, frequency_id);

        manuf = import_or_new(e, manuf_id);

        alert = import_or_new(e, alert_id);
    }

    virtual void reserve_fields() {
        key_id =
            tracker->RegisterField("kismet.device.base.key", TrackerUInt64,
                    "unique integer key");

        name_id = 
            tracker->RegisterField("kismet.device.base.name", TrackerString,
                    "printable device name");

        type_string_id = 
            tracker->RegisterField("kismet.device.base.type", TrackerString,
                    "printable device type");

        basic_type_set_id =
            tracker->RegisterField("kismet.device.base.basic_type_set", TrackerUInt64,
                    "bitset of basic type");

        crypt_string_id =
            tracker->RegisterField("kismet.device.base.crypt", TrackerString,
                    "printable encryption type");

        basic_crypt_set_id =
            tracker->RegisterField("kismet.device.base.basic_crypt_set", TrackerUInt64,
                    "bitset of basic encryption");

        first_time_id = 
            tracker->RegisterField("kismet.device.base.first_time", TrackerUInt64,
                    "first time seen time_t");
        last_time_id =
            tracker->RegisterField("kismet.device.base.last_time", TrackerUInt64,
                    "last time seen time_t");

        packets_id =
            tracker->RegisterField("kismet.device.base.packets.total", TrackerUInt64,
                    "total packets seen of all types");
        rx_packets_id =
            tracker->RegisterField("kismet.device.base.packets.rx", TrackerUInt64,
                        "observed packets sent to device");
        tx_packets_id =
            tracker->RegisterField("kismet.device.base.packets.tx", TrackerUInt64,
                        "observed packets from device");
        llc_packets_id =
            tracker->RegisterField("kismet.device.base.packets.llc", TrackerUInt64,
                        "observed protocol control packets");
        error_packets_id =
            tracker->RegisterField("kismet.device.base.packets.error", TrackerUInt64,
                        "corrupt/error packets");
        data_packets_id =
            tracker->RegisterField("kismet.device.base.packets.data", TrackerUInt64,
                        "data packets");
        crypt_packets_id =
            tracker->RegisterField("kismet.device.base.packets.crypt", TrackerUInt64,
                        "data packets using encryption");
        filter_packets_id =
            tracker->RegisterField("kismet.device.base.packets.filtered", TrackerUInt64,
                        "packets dropped by filter");

        datasize_tx_id =
            tracker->RegisterField("kismet.device.base.datasize.tx", TrackerUInt64,
                        "transmitted data in bytes");
        datasize_rx_id =
            tracker->RegisterField("kismet.device.base.datasize.rx", TrackerUInt64,
                        "received data in bytes");

        new_packets_id =
            tracker->RegisterField("kismet.device.base.packets.new", TrackerUInt64,
                        "new packets since last report");

        kis_tracked_signal_data *sig_builder = new kis_tracked_signal_data(globalreg, 0);
        signal_data_id =
            tracker->RegisterField("kismet.device.base.signal", sig_builder,
                    "signal data");

        channel_id =
            tracker->RegisterField("kismet.device.base.channel", TrackerUInt64,
                        "channel (phy specific)");
        frequency_id =
            tracker->RegisterField("kismet.device.base.frequency", TrackerUInt64,
                        "frequency");

        manuf_id =
            tracker->RegisterField("kismet.device.base.manuf", TrackerString,
                        "manufacturer name");

        alert_id =
            tracker->RegisterField("kismet.device.base.num_alerts", TrackerUInt32,
                        "number of alerts on this device");
    }
};

// Common values across all PHY types, as the PHY is capable of filling them in
class kis_device_common : public tracker_component {
public:
	~kis_device_common() {
		for (map<uuid, kis_seenby_data *>::iterator s = seenby_map.begin();
			 s != seenby_map.end(); ++s) {
			delete s->second;
		}
	}

	kis_tracked_device *device;

	// Printable name for the UI summary, etc.  For APs could be the latest SSID,
	// for bluetooth the UAP guess, etc
	string name;

	// Printable type as relevant to the phy, ie "Wired", "AP", etc... This 
	// can be set by the phy and is usually the best printable interpretation
	// this should be empty if the phy layer hasn't added something intelligent
	string type_string;

	// Basic phy-neutral type for sorting and classification
	uint32_t basic_type_set;

	// Printable crypt string, which can be set by the phy and is usually
	// the best printable interpretation
	// This should be empty, if the phy layer hasn't added something
	// intelligent
	string crypt_string;

	// Basic encryption data
	uint32_t basic_crypt_set;

	// Time values
	time_t first_time;
	time_t last_time;

	// Total packets
	unsigned int packets;
	// TX/RX packet breakdown
	unsigned int tx_packets;
	unsigned int rx_packets;

	// Link level packets (mgmt frames, etc)
	unsigned int llc_packets;
	// PHY level failures on errors
	unsigned int error_packets;

	// Data and encrypted data
	unsigned int data_packets;
	unsigned int crypt_packets;

	// Filtered packets
	unsigned int filter_packets;

	// Amount of data seen
	uint64_t datasize;

	// # of packets since last tick
	unsigned int new_packets;

	// Logical channel as per PHY type
	int channel;

	// Frequency
	unsigned int frequency;

	// raw freqs seen mapped to # of times seen
	map<unsigned int, unsigned int> freq_mhz_map;

	// GPS info
	kis_gps_data gpsdata;

	// SNR
	kis_signal_data snrdata;

	// Alert triggered on this device
	int alert;

	// Arbitrary tags associated with this device
	// Tags are case sensitive
	map<string, kis_tag_data *> arb_tag_map;

	// Sources which have seen this device
	map<uuid, kis_seenby_data *> seenby_map;

	// Who makes this device, if we can tell
	string manuf;

	kis_device_common() {
		device = NULL;

		basic_type_set = KIS_DEVICE_BASICTYPE_DEVICE;

		basic_crypt_set = KIS_DEVICE_BASICCRYPT_NONE;

		first_time = last_time = 0;

		packets = tx_packets = rx_packets = 0;

		llc_packets = data_packets = crypt_packets = error_packets = filter_packets = 0;

		datasize = 0;

		new_packets = 0;

		channel = 0;

		frequency = 0;

		alert = 0;
	}
};

// Packinfo references
class kis_tracked_device_info : public packet_component {
public:
	kis_tracked_device_info() {
		self_destruct = 1;
		devref = NULL;
	}

	kis_tracked_device *devref;
};

// Handler element for a phy
//  Registered with Devicetracker
//  Devicetracker feeds packets to phyhandlers, no need to register with packet 
//   chain on each
//  Registered phy id is passed from devicetracker
//
// 	Subclasses are expected to:
// 	  Register packet handlers in the packet chain
// 	  Register packet components in the packet chain
// 	  Decode trackable data from a packetsource
// 	  Generate trackable devices in the devicetracker
// 	  Update tracked device common data via the devicetracker
// 	  Provide appropriate network sentences to export non-common tracking data
// 	   for the phy type (ie advertised SSID, etc)
// 	  Provide per-phy filtering (if reasonable)
// 	  Provide per-phy commands (as applicable)
// 	  Logging in plaintext and xml
class Kis_Phy_Handler {
public:
	Kis_Phy_Handler() { fprintf(stderr, "fatal oops: kis_phy_handler();\n"); exit(1); }

	// Create a 'weak' handler which provides enough structure to call CreatePhyHandler
	Kis_Phy_Handler(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;
		devicetracker = NULL;
		phyid = -1;
		phyname = "NONE";
	}

	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) = 0;

	Kis_Phy_Handler(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
					int in_phyid) {
		globalreg = in_globalreg;
		phyid = in_phyid;
		devicetracker = in_tracker;
	}

	virtual ~Kis_Phy_Handler() {
		// none
	}

	virtual string FetchPhyName() { return phyname; }
	virtual int FetchPhyId() { return phyid; }

	// Timer event carried from devicetracker, for sending updated 
	// phy-specific records, etc
	virtual int TimerKick() = 0;

	// Send devices (all, or dirty).  Phy should trigger all protocol sentences
	// it defines for these devices
	virtual void BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist) = 0;

	// XSD locations - override as necessary if you provide your xsd, which 
	// you really should
	virtual string FetchPhyXsdNs() { return phyname; }
	virtual string FetchPhyXsdUrl() { 
		return string("http://www.kismetwireless.net/xml/" + FetchPhyXsdNs() + ".xsd"); 
	}

	// Export a device to a central devicetracker-common log file
	//
	// This is used only by the devicetracker registered components to make
	// a unified log file of all devices seen.  This is meant to replace 
	// individual foophy.txt log files, not to supplant a custom dumpfile
	// format.  Plugins / Phy's may still define custom dumpfiles, and should
	// continue to do so, for records which make no sense in the common log.
	//
	// This can not fail - if a phy can't figure out how to log something,
	// it should just bail.
	//
	// The common logger will have already exported the common device statistics
	// such as gps, signal, etc - everything found in the device_common record -
	// and as such a phy logger should export only the data which is not in
	// the common domain.
	//
	// Log type will be the class of log file being written, typically 'xml' 
	// or 'text' but with the option for others in the future.
	//
	// logfile is a standard FILE stream; the location and future handling of it
	// should be considered opaque.  In the case of large written-once files like
	// kisxml the renaming and moving will be handled entirely by the dumpfile
	// class associated.  The logger should only fwrite/fprintf/whatever in
	// whatever format is considered appropriate for the logtype.
	//
	// lineindent is the number of spaces assumed to be used in the display offset
	// already.  For formats such as xml this is irrelevant, but for text output
	// this is the level of indentation which should be done for a consistent look.
	virtual void ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent) = 0;


protected:
	GlobalRegistry *globalreg;
	Devicetracker *devicetracker;

	string phyname;
	int phyid;
};
	
class Devicetracker {
public:
	Devicetracker() { fprintf(stderr, "FATAL OOPS: Kis_Tracker()\n"); exit(0); }
	Devicetracker(GlobalRegistry *in_globalreg);
	~Devicetracker();

	// Register a phy handler weak class, used to instantiate the strong class
	// inside devtracker
	int RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler);
	// Register a tracked device component
	int RegisterDeviceComponent(string in_component);
	// Get a device component name
	string FetchDeviceComponentName(int in_id);

	vector<kis_tracked_device *> *FetchDevices(int in_phy);

	Kis_Phy_Handler *FetchPhyHandler(int in_phy);

	int FetchNumDevices(int in_phy);
	int FetchNumPackets(int in_phy);
	int FetchNumDatapackets(int in_phy);
	int FetchNumCryptpackets(int in_phy);
	int FetchNumErrorpackets(int in_phy);
	int FetchNumFilterpackets(int in_phy);
	int FetchPacketRate(int in_phy);

	int AddFilter(string in_filter);
	int AddNetCliFilter(string in_filter);

	int SetDeviceTag(mac_addr in_device, string in_tag, string in_data,
					 int in_persistent);
	int ClearDeviceTag(mac_addr in_device, string in_tag);
	string FetchDeviceTag(mac_addr in_device, string in_tag);

	// Look for an existing device record
	kis_tracked_device *FetchDevice(mac_addr in_device);
	kis_tracked_device *FetchDevice(mac_addr in_device, unsigned int in_phy);
	
	// Make or find a device record for a mac
	kis_tracked_device *MapToDevice(mac_addr in_device, kis_packet *in_pack);

	typedef map<mac_addr, kis_tracked_device *>::iterator device_itr;
	typedef map<mac_addr, kis_tracked_device *>::const_iterator const_device_itr;

	static void Usage(char *argv);

	// Kick the timer event to update the network clients
	int TimerKick();

	// Common classifier for keeping phy counts
	int CommonTracker(kis_packet *in_packet);

	// Scrape detected strings and push them out to the client
	int StringCollector(kis_packet *in_packet);

	// Send all devices to everyone
	void BlitDevices(int in_fd);

	// send all phy records to everyone
	void BlitPhy(int in_fd);

	// Initiate a logging cycle
	int LogDevices(string in_logclass, string in_logtype, FILE *in_logfile);

	// Populate the common components of a device
	int PopulateCommon(kis_tracked_device *device, kis_packet *in_pack);
protected:
	void SaveTags();

	GlobalRegistry *globalreg;

	int next_componentid;
	map<string, int> component_str_map;
	map<int, string> component_id_map;

	// Total # of packets
	int num_packets;
	int num_datapackets;
	int num_errorpackets;
	int num_filterpackets;
	int num_packetdelta;

	// Per-phy #s of packets
	map<int, int> phy_packets;
	map<int, int> phy_datapackets;
	map<int, int> phy_errorpackets;
	map<int, int> phy_filterpackets;
	map<int, int> phy_packetdelta;

	// Per-phy device list
	map<int, vector<kis_tracked_device *> *> phy_device_vec;

	// Per-phy dirty list
	map<int, vector<kis_tracked_device *> *> phy_dirty_vec;

	// Common device component
	int devcomp_ref_common;

	// Timer id for main timer kick
	int timerid;

	// Network protocols
	int proto_ref_phymap, proto_ref_commondevice, proto_ref_trackinfo,
		proto_ref_devtag, proto_ref_string, proto_ref_devicedone;

	int pack_comp_device, pack_comp_common, pack_comp_string, pack_comp_basicdata,
		pack_comp_radiodata, pack_comp_gps, pack_comp_capsrc;

	int cmd_adddevtag, cmd_deldevtag;

	// Tracked devices
	map<mac_addr, kis_tracked_device *> tracked_map;
	// Vector of tracked devices so we can iterate them quickly
	vector<kis_tracked_device *> tracked_vec;

	// Vector of dirty elements for pushing to clients, better than walking
	// the map every tick, looking for dirty records
	vector<kis_tracked_device *> dirty_device_vec;

	// Filtering
	FilterCore *track_filter;

	// Tag records as a config file
	ConfigFile *tag_conf;
	time_t conf_save;

	// Registered PHY types
	int next_phy_id;
	map<int, Kis_Phy_Handler *> phy_handler_map;

	// Log helpers
	void WriteXML(FILE *in_logfile);
	void WriteTXT(FILE *in_logfile);

	// Build a device record
	kis_tracked_device *BuildDevice(mac_addr in_device, kis_packet *in_pack);
};

// Container that holds tracked information & a unique key.  Key should be unique
// across all PHY types & must be generated in consistent way
class kis_tracked_device {
public:
	mac_addr key;

	int phy_type;
	int dirty;

	vector<tracker_component *> content_vec;

	kis_tracked_device() {
		fprintf(stderr, "FATAL: kis_tracked_device()\n");
		exit(1);
	}

	kis_tracked_device(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;

		phy_type = KIS_PHY_UNKNOWN;
		content_vec.resize(MAX_TRACKER_COMPONENTS, NULL);
		dirty = 0;
	}

	~kis_tracked_device() {
		for (unsigned int y = 0; y < MAX_TRACKER_COMPONENTS; y++) {
			tracker_component *tcm = content_vec[y];

			if (tcm == NULL)
				continue;

			if (tcm->self_destruct)
				delete tcm;

			content_vec[y] = NULL;
		}
	}

	inline void insert(const unsigned int index, tracker_component *data) {
		if (index >= MAX_TRACKER_COMPONENTS)
			return;

		if (content_vec[index] != NULL) 
			fprintf(stderr, "DEBUG/ALERT - Leaking memory for device component %u, "
					"double insert\n", index);

		content_vec[index] = data;
	}

	inline void *fetch(const unsigned int index) {
		if (index >= MAX_TRACKER_COMPONENTS)
			return NULL;

		return content_vec[index];
	}

	inline void erase(const unsigned int index) {
		if (index >= MAX_TRACKER_COMPONENTS)
			return;

		if (content_vec[index] != NULL) {
			if (content_vec[index]->self_destruct)
				delete content_vec[index];

			content_vec[index] = NULL;
		}
	}

	inline tracker_component *operator[] (const unsigned int& index) const {
		if (index >= MAX_TRACKER_COMPONENTS)
			return NULL;

		return content_vec[index];
	}

protected:
	GlobalRegistry *globalreg;
};


#endif

