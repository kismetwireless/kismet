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
#include <pthread.h>
#include <msgpack.hpp>

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packet.h"
#include "uuid.h"
#include "packinfo_signal.h"

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
    // Since we're a subclass we're responsible for initializing our fields
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    } 

    // Since we're a subclass, we're responsible for initializing our fields
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_ip_data(globalreg, get_id());
    }

    __Proxy(ip_type, int32_t, kis_ipdata_type, kis_ipdata_type, ip_type);
    __Proxy(ip_addr, uint64_t, uint64_t, uint64_t, ip_addr_block);
    __Proxy(ip_netmask, uint64_t, uint64_t, uint64_t, ip_netmask);
    __Proxy(ip_gateway, uint64_t, uint64_t, uint64_t, ip_gateway);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

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
    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    } 

    kis_tracked_location_triplet(GlobalRegistry *in_globalreg, int in_id,
            TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
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
        tracker_component::register_fields();

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

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_location(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_location(globalreg, get_id());
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
        tracker_component::register_fields();

        kis_tracked_location_triplet *loc_builder = 
            new kis_tracked_location_triplet(globalreg, 0);

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
        num_alt_avg_id = RegisterField("kismet.common.location.avg_alt_num", 
                TrackerUInt64,
                "number of run-time average samples (altitude)", (void **) &num_alt_avg);

    }

    // We override this to nest our complex structures on top; we can be created
    // over a standard trackerelement map and inherit its sub-maps directly
    // into locations
    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            min_loc = new kis_tracked_location_triplet(globalreg, min_loc_id,
                    e->get_map_value(min_loc_id));
            max_loc = new kis_tracked_location_triplet(globalreg, max_loc_id,
                    e->get_map_value(max_loc_id));
            avg_loc = new kis_tracked_location_triplet(globalreg, avg_loc_id,
                    e->get_map_value(avg_loc_id));
        } else {
            min_loc = new kis_tracked_location_triplet(globalreg, min_loc_id);
            add_map(min_loc);

            max_loc = new kis_tracked_location_triplet(globalreg, max_loc_id);
            add_map(max_loc);

            avg_loc = new kis_tracked_location_triplet(globalreg, avg_loc_id);
            add_map(avg_loc);
        }
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
    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);      
    } 

    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
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
                            peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                    in.gps->gps_fix);
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
                            peak_loc->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                    in.gps->gps_fix);
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
        tracker_component::register_fields();

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
                    "minimum noise (dBm)", (void **) &min_noise_dbm);

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


        kis_tracked_location_triplet *loc_builder = 
            new kis_tracked_location_triplet(globalreg, 0);
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

        if (e != NULL) {
            peak_loc = new kis_tracked_location_triplet(globalreg, peak_loc_id,
                    e->get_map_value(peak_loc_id)); 
        } else {
            peak_loc = new kis_tracked_location_triplet(globalreg, peak_loc_id);
            add_map(peak_loc);
        }
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
    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id) : 
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);
    } 

    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_signal_data(globalreg, get_id());
    }

    __Proxy(src_uuid, uuid, uuid, uuid, src_uuid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
    __ProxyIncDec(num_packets, uint64_t, uint64_t, num_packets);

    // Intmaps need special care by the caller
    TrackerElement *get_freq_mhz_map() { return freq_mhz_map; }

    void inc_frequency_count(int frequency) {
        TrackerElement::map_iterator i = freq_mhz_map->find(frequency);

        if (i == freq_mhz_map->end()) {
            TrackerElement *e = 
                globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
            e->set((uint64_t) 1);
            freq_mhz_map->add_intmap(frequency, e);
        } else {
            (*(i->second))++;
        }
    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

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
    kis_tracked_tag(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_tag(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_tag(globalreg, get_id());
    }


    __Proxy(value, string, string, string, value);
    __Proxy(dirty, uint8_t, bool, bool, dirty);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

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

// Currently borked
class kis_tracked_rrd : public tracker_component {
public:
    kis_tracked_rrd(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    kis_tracked_rrd(GlobalRegistry *in_globalreg, int in_id, TrackerElement *e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);
    }

    virtual TrackerElement *clone_type() {
        return new kis_tracked_rrd(globalreg, get_id());
    }

    void add_sample(uint64_t in_s, uint64_t in_time) {
        // Find the second bucket
        int sec_bucket = in_time % 60;

        TrackerElement *se = *(second_vec->get_vector()->begin() + sec_bucket);
        (*se) += in_s;

    }

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        second_vec_id = 
            RegisterField("kismet.common.rrd.second_vec", TrackerVector,
                    "second values", (void **) &second_vec);
        minute_vec_id = 
            RegisterField("kismet.common.rrd.minute_vec", TrackerVector,
                    "minute values", (void **) &second_vec);
        hour_vec_id = 
            RegisterField("kismet.common.rrd.hour_vec", TrackerVector,
                    "hour values", (void **) &second_vec);

        second_entry_id = 
            RegisterField("kismet.common.rrd.second", TrackerUInt64, 
                    "second value", NULL);
        minute_entry_id = 
            RegisterField("kismet.common.rrd.minute", TrackerUInt64, 
                    "minute value", NULL);
        hour_entry_id = 
            RegisterField("kismet.common.rrd.hour", TrackerUInt64, 
                    "hour value", NULL);

    } 

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        last_min = 0;
        last_hour = 0;

        // Build slots for all the times
        int x;
        if ((x = second_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                TrackerElement *se =
                    new TrackerElement(TrackerUInt64, second_entry_id);
                second_vec->add_vector(se);
            }
        }

        if ((x = minute_vec->get_vector()->size()) != 60) {
            for ( ; x < 60; x++) {
                TrackerElement *me =
                    new TrackerElement(TrackerUInt64, minute_entry_id);
                second_vec->add_vector(me);
            }
        }

        if ((x = hour_vec->get_vector()->size()) != 24) {
            for ( ; x < 24; x++) {
                TrackerElement *he =
                    new TrackerElement(TrackerUInt64, hour_entry_id);
                second_vec->add_vector(he);
            }
        }
    }

    int second_vec_id;
    TrackerElement *second_vec;
    int second_entry_id;

    int minute_vec_id;
    TrackerElement *minute_vec;
    int minute_entry_id;
    uint64_t last_min;

    int hour_vec_id;
    TrackerElement *hour_vec;
    int hour_entry_id;
    uint64_t last_hour;


};

#endif

