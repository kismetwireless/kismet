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

#include "devicetracker_component.h"

kis_tracked_ip_data::kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id) : 
    tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_tracked_ip_data::kis_tracked_ip_data(GlobalRegistry *in_globalreg, int in_id, 
        SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_tracked_ip_data::clone_type() {
    return SharedTrackerElement(new kis_tracked_ip_data(globalreg, get_id()));
}

void kis_tracked_ip_data::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.ipdata.type", TrackerInt32, 
            "ipdata type enum", &ip_type);
    RegisterField("kismet.common.ipdata.address", TrackerUInt64,
            "ip address", &ip_addr_block);
    RegisterField("kismet.common.ipdata.netmask", TrackerUInt64,
            "ip netmask", &ip_netmask);
    RegisterField("kismet.common.ipdata.gateway", TrackerUInt64,
            "ip gateway", &ip_gateway);
}

kis_tracked_signal_data::kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id) : 
    tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(NULL);      
} 

kis_tracked_signal_data::kis_tracked_signal_data(GlobalRegistry *in_globalreg, int in_id, 
        SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_tracked_signal_data::clone_type() {
    return SharedTrackerElement(new kis_tracked_signal_data(globalreg, get_id()));
}

kis_tracked_signal_data& kis_tracked_signal_data::operator+= (const kis_layer1_packinfo& lay1) {
    if (lay1.signal_type == kis_l1_signal_type_dbm) {
        if (lay1.signal_dbm != 0) {

            last_signal_dbm->set((int32_t) lay1.signal_dbm);

            if ((*min_signal_dbm) == (int32_t) 0 ||
                    (*min_signal_dbm) > (int32_t) lay1.signal_dbm) {
                min_signal_dbm->set((int32_t) lay1.signal_dbm);
            }

            if ((*max_signal_dbm) == (int32_t) 0 ||
                    (*max_signal_dbm) < (int32_t) lay1.signal_dbm) {
                max_signal_dbm->set((int32_t) lay1.signal_dbm);
            }
        }

        if (lay1.noise_dbm != 0) {
            last_noise_dbm->set((int32_t) lay1.noise_dbm);

            if ((*min_noise_dbm) == (int32_t) 0 ||
                    (*min_noise_dbm) > (int32_t) lay1.noise_dbm) {
                min_noise_dbm->set((int32_t) lay1.noise_dbm);
            }

            if ((*max_noise_dbm) == (int32_t) 0 ||
                    (*max_noise_dbm) < (int32_t) lay1.noise_dbm) {
                max_noise_dbm->set((int32_t) lay1.noise_dbm);
            }
        }
    } else if (lay1.signal_type == kis_l1_signal_type_rssi) {
        if (lay1.signal_rssi != 0) {
            last_signal_rssi->set((int32_t) lay1.signal_rssi);

            if ((*min_signal_rssi) == (int32_t) 0 ||
                    (*min_signal_rssi) > (int32_t) lay1.signal_rssi) {
                min_signal_dbm->set((int32_t) lay1.signal_rssi);
            }

            if ((*max_signal_rssi) == (int32_t) 0 ||
                    (*max_signal_rssi) < (int32_t) lay1.signal_rssi) {
                max_signal_rssi->set((int32_t) lay1.signal_rssi);
            }
        }

        if (lay1.noise_rssi != 0) {
            last_noise_rssi->set((int32_t) lay1.noise_rssi);

            if ((*min_noise_rssi) == (int32_t) 0 ||
                    (*min_noise_rssi) > (int32_t) lay1.noise_rssi) {
                min_noise_rssi->set((int32_t) lay1.noise_rssi);
            }

            if ((*max_noise_rssi) == (int32_t) 0 ||
                    (*max_noise_rssi) < (int32_t) lay1.noise_rssi) {
                max_noise_rssi->set((int32_t) lay1.noise_rssi);
            }
        }

        (*carrierset) |= (uint64_t) lay1.carrier;
        (*encodingset) |= (uint64_t) lay1.encoding;

        if ((*maxseenrate) < (double) lay1.datarate) {
            maxseenrate->set((double) lay1.datarate);
        }
    }

    return *this;
}

kis_tracked_signal_data& kis_tracked_signal_data::operator+= (const Packinfo_Sig_Combo& in) {
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
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                in.gps->fix);
                    }
                }

                get_signal_min_rrd()->add_sample(in.lay1->signal_dbm, 
                        globalreg->timestamp.tv_sec);
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
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                in.gps->fix);
                    }
                }

                get_signal_min_rrd()->add_sample(in.lay1->signal_rssi, 
                        globalreg->timestamp.tv_sec);
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

void kis_tracked_signal_data::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.signal.last_signal_dbm", TrackerInt32,
            "most recent signal (dBm)", &last_signal_dbm);
    RegisterField("kismet.common.signal.last_noise_dbm", TrackerInt32,
            "most recent noise (dBm)", &last_noise_dbm);

    RegisterField("kismet.common.signal.min_signal_dbm", TrackerInt32,
            "minimum signal (dBm)", &min_signal_dbm);
    RegisterField("kismet.common.signal.min_noise_dbm", TrackerInt32,
            "minimum noise (dBm)", &min_noise_dbm);

    RegisterField("kismet.common.signal.max_signal_dbm", TrackerInt32,
            "maximum signal (dBm)", &max_signal_dbm);
    RegisterField("kismet.common.signal.max_noise_dbm", TrackerInt32,
            "maximum noise (dBm)", &max_noise_dbm);

    RegisterField("kismet.common.signal.last_signal_rssi", TrackerInt32,
            "most recent signal (RSSI)", &last_signal_rssi);
    RegisterField("kismet.common.signal.last_noise_rssi", TrackerInt32,
            "most recent noise (RSSI)", &last_noise_rssi);

    RegisterField("kismet.common.signal.min_signal_rssi", TrackerInt32,
            "minimum signal (rssi)", &min_signal_rssi);
    RegisterField("kismet.common.signal.min_noise_rssi", TrackerInt32,
            "minimum noise (RSSI)", &min_noise_rssi);

    RegisterField("kismet.common.signal.max_signal_rssi", TrackerInt32,
            "maximum signal (RSSI)", &max_signal_rssi);
    RegisterField("kismet.common.signal.max_noise_rssi", TrackerInt32,
            "maximum noise (RSSI)", &max_noise_rssi);


    shared_ptr<kis_tracked_location_triplet> 
        loc_builder(new kis_tracked_location_triplet(globalreg, 0));
    peak_loc_id = 
        RegisterComplexField("kismet.common.signal.peak_loc", loc_builder,
                "location of strongest signal");

    RegisterField("kismet.common.signal.maxseenrate", TrackerDouble,
            "maximum observed data rate (phy dependent)", &maxseenrate);
    RegisterField("kismet.common.signal.encodingset", TrackerUInt64,
            "bitset of observed encodings", &encodingset);
    RegisterField("kismet.common.signal.carrierset", TrackerUInt64,
            "bitset of observed carrier types", &carrierset);

    shared_ptr<kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator> >
        signal_min_rrd_builder(new kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>(globalreg, 0));
    signal_min_rrd_id =
        RegisterComplexField("kismet.common.signal.signal_rrd",
                signal_min_rrd_builder, "signal data for past minute");
}

void kis_tracked_signal_data::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    if (e != NULL) {
        peak_loc.reset(new kis_tracked_location_triplet(globalreg, peak_loc_id,
                    e->get_map_value(peak_loc_id))); 

        signal_min_rrd.reset(new kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>(globalreg, signal_min_rrd_id, e->get_map_value(signal_min_rrd_id)));
    } 

    add_map(peak_loc_id, peak_loc);
    add_map(signal_min_rrd_id, signal_min_rrd);
}

kis_tracked_seenby_data::kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id) : 
    tracker_component(in_globalreg, in_id) { 
    register_fields();
    reserve_fields(NULL);
} 

kis_tracked_seenby_data::kis_tracked_seenby_data(GlobalRegistry *in_globalreg, int in_id, 
        SharedTrackerElement e) : tracker_component(in_globalreg, in_id) {
    register_fields();
    reserve_fields(e);
}

SharedTrackerElement kis_tracked_seenby_data::clone_type() {
    return SharedTrackerElement(new kis_tracked_signal_data(globalreg, get_id()));
}

void kis_tracked_seenby_data::inc_frequency_count(int frequency) {
    TrackerElement::map_iterator i = freq_khz_map->find(frequency);

    if (i == freq_khz_map->end()) {
        SharedTrackerElement e = 
            globalreg->entrytracker->GetTrackedInstance(frequency_val_id);
        e->set((uint64_t) 1);
        freq_khz_map->add_intmap(frequency, e);
    } else {
        (*(i->second))++;
    }
}

void kis_tracked_seenby_data::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.seenby.uuid", TrackerUuid,
            "UUID of source", &src_uuid);
    RegisterField("kismet.common.seenby.first_time", TrackerUInt64,
            "first time seen time_t", &first_time);
    RegisterField("kismet.common.seenby.last_time", TrackerUInt64,
            "last time seen time_t", &last_time);
    RegisterField("kismet.common.seenby.num_packets", TrackerUInt64,
            "number of packets seen by this device", &num_packets);
    RegisterField("kismet.common.seenby.freq_khz_map", TrackerIntMap,
            "packets seen per frequency (khz)", &freq_khz_map);
    frequency_val_id =
        globalreg->entrytracker->RegisterField("kismet.common.seenby.frequency.count",
                TrackerUInt64, "frequency packet count");
}

