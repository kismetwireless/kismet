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

#ifndef __DEVICETRACKER_COMPONENT_H__
#define __DEVICETRACKER_COMPONENT_H__

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

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "packet.h"
#include "uuid.h"
#include "tracked_location.h"
#include "tracked_rrd.h"
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
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id);

    // Since we're a subclass, we're responsible for initializing our fields
    kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e);

    virtual SharedTrackerElement clone_type();

    __Proxy(ip_type, int32_t, kis_ipdata_type, kis_ipdata_type, ip_type);
    __Proxy(ip_addr, uint64_t, uint64_t, uint64_t, ip_addr_block);
    __Proxy(ip_netmask, uint64_t, uint64_t, uint64_t, ip_netmask);
    __Proxy(ip_gateway, uint64_t, uint64_t, uint64_t, ip_gateway);

protected:
    virtual void register_fields();

    SharedTrackerElement ip_type;
    SharedTrackerElement ip_addr_block;
    SharedTrackerElement ip_netmask;
    SharedTrackerElement ip_gateway;
};

// Component-tracker based signal data
// TODO operator overloading once rssi/dbm fixed upstream
class kis_tracked_signal_data : public tracker_component {
public:
    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id);

    kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e);

    virtual SharedTrackerElement clone_type();

    kis_tracked_signal_data& operator+= (const kis_layer1_packinfo& lay1);
	kis_tracked_signal_data& operator+= (const Packinfo_Sig_Combo& in);

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

    typedef kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> msig_rrd;
    __ProxyDynamicTrackable(signal_min_rrd, msig_rrd, signal_min_rrd, signal_min_rrd_id);

    __ProxyDynamicTrackable(peak_loc, kis_tracked_location_triplet, 
            peak_loc, peak_loc_id);

protected:
    virtual void register_fields();
    virtual void reserve_fields(SharedTrackerElement e);

    SharedTrackerElement last_signal_dbm, last_noise_dbm;
    SharedTrackerElement min_signal_dbm, min_noise_dbm;
    SharedTrackerElement max_signal_dbm, max_noise_dbm;

    SharedTrackerElement last_signal_rssi, last_noise_rssi;
    SharedTrackerElement min_signal_rssi, min_noise_rssi;
    SharedTrackerElement max_signal_rssi, max_noise_rssi;

    int peak_loc_id;
    shared_ptr<kis_tracked_location_triplet> peak_loc;

    SharedTrackerElement maxseenrate, encodingset, carrierset;

    // Signal record over the past minute, either rssi or dbm.  Devices
    // should not mix rssi and dbm signal reporting.
    int signal_min_rrd_id;
    shared_ptr<kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> > signal_min_rrd;
};

class kis_tracked_seenby_data : public tracker_component {
public:
    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id);

    kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e);

    virtual SharedTrackerElement clone_type();

    __Proxy(src_uuid, uuid, uuid, uuid, src_uuid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __Proxy(num_packets, uint64_t, uint64_t, uint64_t, num_packets);
    __ProxyIncDec(num_packets, uint64_t, uint64_t, num_packets);

    __ProxyTrackable(freq_khz_map, TrackerElement, freq_khz_map);
    __ProxyDynamicTrackable(signal_data, kis_tracked_signal_data,
            signal_data, signal_data_id);

    void inc_frequency_count(int frequency);

protected:
    virtual void register_fields();
    virtual void reserve_fields(SharedTrackerElement e);

    SharedTrackerElement src_uuid;
    SharedTrackerElement first_time; 
    SharedTrackerElement last_time;
    SharedTrackerElement num_packets;

    SharedTrackerElement freq_khz_map;
    int frequency_val_id;

    shared_ptr<kis_tracked_signal_data> signal_data;
    int signal_data_id;
};

#endif

