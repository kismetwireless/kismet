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
#include "kis_datasource.h"

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

    sig_type = 0;
    signal_type->set("none");
}

kis_tracked_signal_data::kis_tracked_signal_data(int in_id) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(NULL);      

    sig_type = 0;
    signal_type->set("none");
} 

kis_tracked_signal_data::kis_tracked_signal_data(int in_id, std::shared_ptr<TrackerElementMap> e) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);

    if (signal_type->get() == "dbm")
        sig_type = 1;
    else if (signal_type->get() == "rssi")
        sig_type = 2;
    else
        sig_type = 0;

}

void  kis_tracked_signal_data::append_signal(const kis_layer1_packinfo& lay1, bool update_rrd) {
    if (lay1.signal_type == kis_l1_signal_type_dbm && (sig_type == 0 || sig_type == 1)) {
        if (sig_type == 0) {
            signal_type->set("dbm");
            sig_type = 1;
        }

        if (lay1.signal_dbm != 0) {
            last_signal->set(lay1.signal_dbm);

            if (min_signal->get() == 0 || min_signal->get() > lay1.signal_dbm) {
                min_signal->set(lay1.signal_dbm);
            }

            if (max_signal->get() == 0 || max_signal->get() < lay1.signal_dbm) {
                max_signal->set(lay1.signal_dbm);
            }

            if (update_rrd)
                get_signal_min_rrd()->add_sample(lay1.signal_dbm, time(0));
        }

        if (lay1.noise_dbm != 0) {
            last_noise->set(lay1.noise_dbm);

            if (min_noise->get() == 0 || min_noise->get() > lay1.noise_dbm) {
                min_noise->set(lay1.noise_dbm);
            }

            if (max_noise->get() == 0 || max_noise->get() < lay1.noise_dbm) {
                max_noise->set(lay1.noise_dbm);
            }
        }
    } else if (lay1.signal_type == kis_l1_signal_type_rssi && (sig_type == 0 || sig_type == 2)) {
        if (sig_type == 0) {
            signal_type->set("rssi");
            sig_type = 2;
        }

        if (lay1.signal_rssi != 0) {
            last_signal->set(lay1.signal_rssi);

            if (min_signal->get() == 0 || min_signal->get() > lay1.signal_rssi) {
                min_signal->set(lay1.signal_rssi);
            }

            if (max_signal->get() == 0 || max_signal->get() < lay1.signal_rssi) {
                max_signal->set(lay1.signal_rssi);
            }

            if (update_rrd)
                get_signal_min_rrd()->add_sample(lay1.signal_rssi, time(0));
        }

        if (lay1.noise_rssi != 0) {
            last_noise->set(lay1.noise_rssi);

            if (min_noise->get() == 0 || min_noise->get() > lay1.noise_rssi) {
                min_noise->set(lay1.noise_rssi);
            }

            if (max_noise->get() == 0 || max_noise->get() < lay1.noise_rssi) {
                max_noise->set(lay1.noise_rssi);
            }
        }

        (*carrierset) |= (uint64_t) lay1.carrier;
        (*encodingset) |= (uint64_t) lay1.encoding;

        if (maxseenrate->get() < (double) lay1.datarate) {
            maxseenrate->set((double) lay1.datarate);
        }
    }
}

void kis_tracked_signal_data::append_signal(const Packinfo_Sig_Combo& in, bool update_rrd) {
    if (in.lay1 != NULL) {
        if (in.lay1->signal_type == kis_l1_signal_type_dbm && (sig_type == 0 || sig_type == 1)) {
            if (sig_type == 0) {
                signal_type->set("dbm");
                sig_type = 1;
            }

            if (in.lay1->signal_dbm != 0) {

                last_signal->set(in.lay1->signal_dbm);

                if (min_signal->get() == 0 || min_signal->get() > in.lay1->signal_dbm) {
                    min_signal->set(in.lay1->signal_dbm);
                }

                if (max_signal->get() == 0 || max_signal->get() < in.lay1->signal_dbm) {
                    max_signal->set(in.lay1->signal_dbm);

                    if (in.gps != NULL) {
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, in.gps->fix);
                    }
                }

                if (update_rrd)
                    get_signal_min_rrd()->add_sample(in.lay1->signal_dbm, time(0));
            }

            if (in.lay1->noise_dbm != 0) {
                last_noise->set(in.lay1->noise_dbm);

                if (min_noise->get() == 0 || min_noise->get() > in.lay1->noise_dbm) {
                    min_noise->set(in.lay1->noise_dbm);
                }

                if (max_noise->get() == 0 || max_noise->get() < in.lay1->noise_dbm) {
                    max_noise->set(in.lay1->noise_dbm);
                }
            } 
        } else if (in.lay1->signal_type == kis_l1_signal_type_rssi && (sig_type == 0 || sig_type == 2)) {
            if (sig_type == 0) {
                signal_type->set("rssi");
                sig_type = 2;
            }

            if (in.lay1->signal_rssi != 0) {
                last_signal->set(in.lay1->signal_rssi);

                if (min_signal->get() == 0 || min_signal->get() > in.lay1->signal_rssi) {
                    min_signal->set(in.lay1->signal_rssi);
                }

                if (max_signal->get() == 0 || max_signal->get() < in.lay1->signal_rssi) {
                    max_signal->set(in.lay1->signal_rssi);

                    if (in.gps != NULL) {
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, 
                                in.gps->fix);
                    }
                }

                if (update_rrd)
                    get_signal_min_rrd()->add_sample(in.lay1->signal_rssi, time(0));
            }

            if (in.lay1->noise_rssi != 0) {
                last_noise->set(in.lay1->noise_rssi);

                if (min_noise->get() == 0 || min_noise->get() > in.lay1->noise_rssi) {
                    min_noise->set(in.lay1->noise_rssi);
                }

                if (max_noise->get() == 0 || max_noise->get() < in.lay1->noise_rssi) {
                    max_noise->set(in.lay1->noise_rssi);
                }
            }

        }

        (*carrierset) |= (uint64_t) in.lay1->carrier;
        (*encodingset) |= (uint64_t) in.lay1->encoding;

        if ((*maxseenrate) < (double) in.lay1->datarate) {
            maxseenrate->set((double) in.lay1->datarate);
        }
    }
}

void kis_tracked_signal_data::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.common.signal.type", "signal type", &signal_type);

    RegisterField("kismet.common.signal.last_signal", "most recent signal", &last_signal);
    RegisterField("kismet.common.signal.last_noise", "most recent noise", &last_noise);

    RegisterField("kismet.common.signal.min_signal", "minimum signal", &min_signal);
    RegisterField("kismet.common.signal.min_noise", "minimum noise", &min_noise);

    RegisterField("kismet.common.signal.max_signal", "maximum signal", &max_signal);
    RegisterField("kismet.common.signal.max_noise", "maximum noise", &max_noise);

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
    tracker_component() {
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
        freq_khz_map->insert(frequency, 1);
    } else {
        i->second += 1;
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

void kis_tracked_device_base::inc_frequency_count(double frequency) {
    if (frequency <= 0)
        return;

    auto i = freq_khz_map->find(frequency);

    if (i == freq_khz_map->end()) {
        freq_khz_map->insert(frequency, 1);
    } else {
        i->second += 1;
    }
}

void kis_tracked_device_base::inc_seenby_count(KisDatasource *source, 
        time_t tv_sec, int frequency, Packinfo_Sig_Combo *siginfo,
        bool update_rrd) {
    std::shared_ptr<kis_tracked_seenby_data> seenby;

    auto seenby_iter = seenby_map->find(source->get_source_key());

    // Make a new seenby record
    if (seenby_iter == seenby_map->end()) {
        seenby = std::make_shared<kis_tracked_seenby_data>(seenby_val_id);

        seenby->set_src_uuid(source->get_source_uuid());
        seenby->set_first_time(tv_sec);
        seenby->set_last_time(tv_sec);
        seenby->set_num_packets(1);

        if (frequency > 0)
            seenby->inc_frequency_count(frequency);

        if (siginfo != NULL)
            (seenby->get_signal_data())->append_signal(*siginfo, update_rrd);

        seenby_map->insert(source->get_source_key(), seenby);

    } else {
        seenby = std::static_pointer_cast<kis_tracked_seenby_data>(seenby_iter->second);

        seenby->set_last_time(tv_sec);
        seenby->inc_num_packets();

        if (frequency > 0)
            seenby->inc_frequency_count(frequency);

        if (siginfo != NULL)
            seenby->get_signal_data()->append_signal(*siginfo, update_rrd);
    }
}

void kis_tracked_device_base::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.device.base.key", "unique device key across phy and server", &key);
    RegisterField("kismet.device.base.macaddr", "mac address", &macaddr);
    RegisterField("kismet.device.base.phyname", "phy name", &phyname);
	RegisterField("kismet.device.base.phyid", "phy internal id", &phyid);
    RegisterField("kismet.device.base.name", "printable device name", &devicename);
    username_id = 
        RegisterDynamicField("kismet.device.base.username", "user name", &username);
    RegisterField("kismet.device.base.commonname", 
            "common name alias of custom or device names", &commonname);
    RegisterField("kismet.device.base.type", "printable device type", &type_string);
    RegisterField("kismet.device.base.basic_type_set", "bitset of basic type", &basic_type_set);
    RegisterField("kismet.device.base.crypt", "printable encryption type", &crypt_string);
    RegisterField("kismet.device.base.basic_crypt_set", 
            "bitset of basic encryption", &basic_crypt_set);
    RegisterField("kismet.device.base.first_time", "first time seen time_t", &first_time);
    RegisterField("kismet.device.base.last_time", "last time seen time_t", &last_time);
    RegisterField("kismet.device.base.mod_time", 
            "internal timestamp of last record change", &mod_time);
    RegisterField("kismet.device.base.packets.total", "total packets seen of all types", &packets);
    RegisterField("kismet.device.base.packets.rx", "observed packets sent to device", &rx_packets);
    RegisterField("kismet.device.base.packets.tx", "observed packets from device", &tx_packets);
    RegisterField("kismet.device.base.packets.llc", "observed protocol control packets", &llc_packets);
    RegisterField("kismet.device.base.packets.error", "corrupt/error packets", &error_packets);
    RegisterField("kismet.device.base.packets.data", "data packets", &data_packets);
    RegisterField("kismet.device.base.packets.crypt", "data packets using encryption", &crypt_packets);
    RegisterField("kismet.device.base.packets.filtered", "packets dropped by filter", &filter_packets);
    RegisterField("kismet.device.base.datasize", "transmitted data in bytes", &datasize);
    
    packets_rrd_id =
        RegisterDynamicField("kismet.device.base.packets.rrd", "packet rate rrd", &packets_rrd);
    data_rrd_id =
        RegisterDynamicField("kismet.device.base.datasize.rrd", "packet size rrd", &data_rrd);
    signal_data_id =
        RegisterDynamicField("kismet.device.base.signal", "signal data", &signal_data);

    RegisterField("kismet.device.base.freq_khz_map", "packets seen per frequency (khz)", &freq_khz_map);
    RegisterField("kismet.device.base.channel", "channel (phy specific)", &channel);
    RegisterField("kismet.device.base.frequency", "frequency", &frequency);
    RegisterField("kismet.device.base.manuf", "manufacturer name", &manuf);
    RegisterField("kismet.device.base.num_alerts", "number of alerts on this device", &alert);
    RegisterField("kismet.device.base.tags", "set of arbitrary tags, including user notes", &tag_map);

    tag_entry_id =
        RegisterField("kismet.device.base.tag", 
                TrackerElementFactory<TrackerElementString>(), "arbitrary tag");

    location_id =
        RegisterDynamicField("kismet.device.base.location", "location", &location);
    location_cloud_id =
        RegisterDynamicField("kismet.device.base.location_cloud", 
                "historic location cloud", &location_cloud);

    RegisterField("kismet.device.base.seenby", "sources that have seen this device", &seenby_map);

    // Packet count, not actual frequency, so uint64 not double
    frequency_val_id =
        RegisterField("kismet.device.base.frequency.count",
                TrackerElementFactory<TrackerElementUInt64>(), "frequency packet count");

    seenby_val_id =
        RegisterField("kismet.device.base.seenby.data",
                TrackerElementFactory<kis_tracked_seenby_data>(),
                "datasource seen-by data");

    packet_rrd_bin_250_id =
        RegisterDynamicField("kismet.device.base.packet.bin.250", "RRD of packets up to 250 bytes",
                &packet_rrd_bin_250);
    packet_rrd_bin_500_id =
        RegisterDynamicField("kismet.device.base.packet.bin.500", "RRD of packets up to 500 bytes",
                &packet_rrd_bin_500);
    packet_rrd_bin_1000_id =
        RegisterDynamicField("kismet.device.base.packet.bin.1000", "RRD of packets up to 1000 bytes",
                &packet_rrd_bin_1000);
    packet_rrd_bin_1500_id =
        RegisterDynamicField("kismet.device.base.packet.bin.1500", "RRD of packets up to 1500 bytes",
                &packet_rrd_bin_1500);
    packet_rrd_bin_jumbo_id =
        RegisterDynamicField("kismet.device.base.packet.bin.jumbo", "RRD of packets over 1500 bytes",
                &packet_rrd_bin_jumbo);

    RegisterField("kismet.device.base.server_uuid", 
            "UUID of server which saw this device", &server_uuid);
}

void kis_tracked_device_base::reserve_fields(std::shared_ptr<TrackerElementMap> e) {
    tracker_component::reserve_fields(e);

    if (e != NULL) {
        // If we're inheriting, it's our responsibility to kick submaps with
        // complex types as well; since they're not themselves complex objects
        for (auto s : *seenby_map) {
            // Build a proper seenby record for each item in the list
            auto sbd = 
                std::make_shared<kis_tracked_seenby_data>(seenby_val_id, 
                        std::static_pointer_cast<TrackerElementMap>(s.second));
            // And assign it over the same key
            s.second = sbd;
        }
    }
}
