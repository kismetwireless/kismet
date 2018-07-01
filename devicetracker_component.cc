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

kis_tracked_ip_data::kis_tracked_ip_data() :
    tracker_component() {
    register_fields();
    reserve_fields(NULL);
}

kis_tracked_ip_data::kis_tracked_ip_data(int in_id) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(NULL);
} 

kis_tracked_ip_data::kis_tracked_ip_data(int in_id, std::shared_ptr<TrackerElementMap> e) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

void kis_tracked_ip_data::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.ipdata.type", "ipdata type enum", &ip_type);
    RegisterField("kismet.common.ipdata.address", "ip address", &ip_addr_block);
    RegisterField("kismet.common.ipdata.netmask", "ip netmask", &ip_netmask);
    RegisterField("kismet.common.ipdata.gateway", "ip gateway", &ip_gateway);
}

kis_tracked_signal_data::kis_tracked_signal_data() :
    tracker_component(0) {
    register_fields();
    reserve_fields(NULL);
}

kis_tracked_signal_data::kis_tracked_signal_data(int in_id) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(NULL);      
} 

kis_tracked_signal_data::kis_tracked_signal_data(int in_id, std::shared_ptr<TrackerElementMap> e) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

kis_tracked_signal_data& kis_tracked_signal_data::operator+= (const kis_layer1_packinfo& lay1) {
    if (lay1.signal_type == kis_l1_signal_type_dbm) {
        if (lay1.signal_dbm != 0) {
            last_signal_dbm->set(lay1.signal_dbm);

            if ((*min_signal_dbm) == 0 || (*min_signal_dbm) > lay1.signal_dbm) {
                min_signal_dbm->set(lay1.signal_dbm);
            }

            if ((*max_signal_dbm) == 0 || (*max_signal_dbm) < lay1.signal_dbm) {
                max_signal_dbm->set(lay1.signal_dbm);
            }
        }

        if (lay1.noise_dbm != 0) {
            last_noise_dbm->set(lay1.noise_dbm);

            if ((*min_noise_dbm) == 0 || (*min_noise_dbm) > lay1.noise_dbm) {
                min_noise_dbm->set(lay1.noise_dbm);
            }

            if ((*max_noise_dbm) == 0 || (*max_noise_dbm) < lay1.noise_dbm) {
                max_noise_dbm->set(lay1.noise_dbm);
            }
        }
    } else if (lay1.signal_type == kis_l1_signal_type_rssi) {
        if (lay1.signal_rssi != 0) {
            last_signal_rssi->set(lay1.signal_rssi);

            if ((*min_signal_rssi) == 0 || (*min_signal_rssi) > lay1.signal_rssi) {
                min_signal_dbm->set(lay1.signal_rssi);
            }

            if ((*max_signal_rssi) == 0 || (*max_signal_rssi) < lay1.signal_rssi) {
                max_signal_rssi->set(lay1.signal_rssi);
            }
        }

        if (lay1.noise_rssi != 0) {
            last_noise_rssi->set(lay1.noise_rssi);

            if ((*min_noise_rssi) == 0 || (*min_noise_rssi) > lay1.noise_rssi) {
                min_noise_rssi->set(lay1.noise_rssi);
            }

            if ((*max_noise_rssi) == 0 || (*max_noise_rssi) < lay1.noise_rssi) {
                max_noise_rssi->set(lay1.noise_rssi);
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

                last_signal_dbm->set(in.lay1->signal_dbm);

                if ((*min_signal_dbm) == 0 || (*min_signal_dbm) > in.lay1->signal_dbm) {
                    min_signal_dbm->set(in.lay1->signal_dbm);
                }

                if ((*max_signal_dbm) == 0 || (*max_signal_dbm) < in.lay1->signal_dbm) {
                    max_signal_dbm->set(in.lay1->signal_dbm);

                    if (in.gps != NULL) {
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, in.gps->fix);
                    }
                }

                get_signal_min_rrd()->add_sample(in.lay1->signal_dbm, time(0));
            }

            if (in.lay1->noise_dbm != 0) {
                last_noise_dbm->set(in.lay1->noise_dbm);

                if ((*min_noise_dbm) == 0 || (*min_noise_dbm) > in.lay1->noise_dbm) {
                    min_noise_dbm->set(in.lay1->noise_dbm);
                }

                if ((*max_noise_dbm) == 0 || (*max_noise_dbm) < in.lay1->noise_dbm) {
                    max_noise_dbm->set(in.lay1->noise_dbm);
                }
            }
        } else if (in.lay1->signal_type == kis_l1_signal_type_rssi) {
            if (in.lay1->signal_rssi != 0) {
                last_signal_rssi->set(in.lay1->signal_rssi);

                if ((*min_signal_rssi) == 0 || (*min_signal_rssi) > in.lay1->signal_rssi) {
                    min_signal_dbm->set(in.lay1->signal_rssi);
                }

                if ((*max_signal_rssi) == 0 || (*max_signal_rssi) < in.lay1->signal_rssi) {
                    max_signal_rssi->set(in.lay1->signal_rssi);

                    if (in.gps != NULL) {
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                in.gps->fix);
                    }
                }

                get_signal_min_rrd()->add_sample(in.lay1->signal_rssi, time(0));
            }

            if (in.lay1->noise_rssi != 0) {
                last_noise_rssi->set(in.lay1->noise_rssi);

                if ((*min_noise_rssi) == 0 || (*min_noise_rssi) > in.lay1->noise_rssi) {
                    min_noise_rssi->set(in.lay1->noise_rssi);
                }

                if ((*max_noise_rssi) == 0 || (*max_noise_rssi) < in.lay1->noise_rssi) {
                    max_noise_rssi->set(in.lay1->noise_rssi);
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

    RegisterField("kismet.common.signal.last_signal", "most recent signal", &last_signal_dbm);
    RegisterField("kismet.common.signal.last_noise", "most recent noise (dBm)", &last_noise_dbm);

    RegisterField("kismet.common.signal.min_signal", "minimum signal (dBm)", &min_signal_dbm);
    RegisterField("kismet.common.signal.min_noise_dbm", "minimum noise (dBm)", &min_noise_dbm);

    RegisterField("kismet.common.signal.max_signal_dbm", "maximum signal (dBm)", &max_signal_dbm);
    RegisterField("kismet.common.signal.max_noise_dbm", "maximum noise (dBm)", &max_noise_dbm);

    RegisterField("kismet.common.signal.last_signal_rssi", 
            "most recent signal (RSSI)", &last_signal_rssi);
    RegisterField("kismet.common.signal.last_noise_rssi", 
            "most recent noise (RSSI)", &last_noise_rssi);

    RegisterField("kismet.common.signal.min_signal_rssi",
            "minimum signal (rssi)", &min_signal_rssi);
    RegisterField("kismet.common.signal.min_noise_rssi",
            "minimum noise (RSSI)", &min_noise_rssi);

    RegisterField("kismet.common.signal.max_signal_rssi",
            "maximum signal (RSSI)", &max_signal_rssi);
    RegisterField("kismet.common.signal.max_noise_rssi",
            "maximum noise (RSSI)", &max_noise_rssi);


    peak_loc_id =
        RegisterDynamicField("kismet.common.signal.peak_loc",
                "location of strongest observed signal", &peak_loc);

    RegisterField("kismet.common.signal.maxseenrate",
            "maximum observed data rate (phy dependent)", &maxseenrate);
    RegisterField("kismet.common.signal.encodingset", 
            "bitset of observed encodings", &encodingset);
    RegisterField("kismet.common.signal.carrierset", 
            "bitset of observed carrier types", &carrierset);

    signal_min_rrd_id =
        RegisterDynamicField("kismet.common.signal.signal_rrd",
                "past minute of signal data", &signal_min_rrd);
}

kis_tracked_seenby_data::kis_tracked_seenby_data() :
    tracker_component(0) {
    register_fields();
    reserve_fields(NULL);
    }

kis_tracked_seenby_data::kis_tracked_seenby_data(int in_id) : 
    tracker_component(in_id) { 
    register_fields();
    reserve_fields(NULL);
} 

kis_tracked_seenby_data::kis_tracked_seenby_data(int in_id, std::shared_ptr<TrackerElementMap> e) :
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

void kis_tracked_seenby_data::inc_frequency_count(int frequency) {
    auto i = freq_khz_map->find(frequency);

    if (i == freq_khz_map->end()) {
        auto e = std::make_shared<TrackerElementUInt64>(frequency_val_id);
        e->set(1);
        freq_khz_map->insert(std::make_pair(frequency, e));
    } else {
        *(std::static_pointer_cast<TrackerElementUInt64>(i->second)) += 1;
    }
}

void kis_tracked_seenby_data::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.seenby.uuid", "UUID of source", &src_uuid);
    RegisterField("kismet.common.seenby.first_time", "first time seen time_t", &first_time);
    RegisterField("kismet.common.seenby.last_time", "last time seen time_t", &last_time);
    RegisterField("kismet.common.seenby.num_packets", 
            "number of packets seen by this device", &num_packets);

    RegisterField("kismet.common.seenby.freq_khz_map", 
            "packets seen per frequency (khz)", &freq_khz_map);

    frequency_val_id =
        RegisterField("kismet.common.seenby.frequency.count",
                TrackerElementFactory<TrackerElementUInt64>(), "packets per frequency");

    signal_data_id =
        RegisterDynamicField("kismet.common.seenby.signal", "signal data", &signal_data);
}


