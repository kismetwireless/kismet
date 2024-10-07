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

#include "datasourcetracker.h"
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

kis_tracked_ip_data::kis_tracked_ip_data(int in_id, std::shared_ptr<tracker_element_map> e) : 
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

kis_tracked_ip_data::kis_tracked_ip_data(const kis_tracked_ip_data *p) :
    tracker_component{p} {
        __ImportField(ip_type, p);
        __ImportField(ip_addr_block, p);
        __ImportField(ip_netmask, p);
        __ImportField(ip_gateway, p);
        reserve_fields(nullptr);
    }

void kis_tracked_ip_data::register_fields() {
    tracker_component::register_fields();

    register_field("kismet.common.ipdata.type", "ipdata type enum", &ip_type);
    register_field("kismet.common.ipdata.address", "ip address", &ip_addr_block);
    register_field("kismet.common.ipdata.netmask", "ip netmask", &ip_netmask);
    register_field("kismet.common.ipdata.gateway", "ip gateway", &ip_gateway);
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

kis_tracked_signal_data::kis_tracked_signal_data(int in_id, std::shared_ptr<tracker_element_map> e) : 
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

kis_tracked_signal_data::kis_tracked_signal_data(const kis_tracked_signal_data *p) :
    tracker_component{p} {

        __ImportField(signal_type, p);

        __ImportField(last_signal, p);
        __ImportField(last_noise, p);

        __ImportField(min_signal, p);
        __ImportField(min_noise, p);

        __ImportField(max_signal, p);
        __ImportField(max_noise, p);

        __ImportId(peak_loc_id, p);

        __ImportField(maxseenrate, p);
        __ImportField(encodingset, p);
        __ImportField(carrierset, p);

        __ImportId(signal_min_rrd_id, p);

        reserve_fields(nullptr);
        sig_type = 0;
        signal_type->set("none");
    }

void  kis_tracked_signal_data::append_signal(const kis_layer1_packinfo& lay1, bool update_rrd, time_t rrd_ts) {
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
                get_signal_min_rrd()->add_sample(lay1.signal_dbm, rrd_ts);
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
                get_signal_min_rrd()->add_sample(lay1.signal_rssi, rrd_ts);
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

void kis_tracked_signal_data::append_signal(const packinfo_sig_combo& in, bool update_rrd, time_t rrd_ts) {
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
                    get_signal_min_rrd()->add_sample(in.lay1->signal_dbm, rrd_ts);
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
                    get_signal_min_rrd()->add_sample(in.lay1->signal_rssi, rrd_ts);
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

    register_field("kismet.common.signal.type", "signal type", &signal_type);

    register_field("kismet.common.signal.last_signal", "most recent signal", &last_signal);
    register_field("kismet.common.signal.last_noise", "most recent noise", &last_noise);

    register_field("kismet.common.signal.min_signal", "minimum signal", &min_signal);
    register_field("kismet.common.signal.min_noise", "minimum noise", &min_noise);

    register_field("kismet.common.signal.max_signal", "maximum signal", &max_signal);
    register_field("kismet.common.signal.max_noise", "maximum noise", &max_noise);

    peak_loc_id =
        register_dynamic_field<kis_tracked_location_triplet>("kismet.common.signal.peak_loc",
                "location of strongest observed signal");

    register_field("kismet.common.signal.maxseenrate",
            "maximum observed data rate (phy dependent)", &maxseenrate);
    register_field("kismet.common.signal.encodingset", 
            "bitset of observed encodings", &encodingset);
    register_field("kismet.common.signal.carrierset", 
            "bitset of observed carrier types", &carrierset);

    signal_min_rrd_id =
        register_dynamic_field<kis_tracked_minute_rrd<kis_tracked_rrd_peak_signal_aggregator>>("kismet.common.signal.signal_rrd",
                "past minute of signal data");
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

kis_tracked_seenby_data::kis_tracked_seenby_data(int in_id, std::shared_ptr<tracker_element_map> e) :
    tracker_component(in_id) {
    register_fields();
    reserve_fields(e);
}

kis_tracked_seenby_data::kis_tracked_seenby_data(const kis_tracked_seenby_data *p) :
    tracker_component{p} {

		__ImportField(src_uuid, p);
		__ImportField(datasource_alias, p);

        __ImportField(first_time, p);
        __ImportField(last_time, p);
        __ImportField(num_packets, p);

        __ImportId(freq_khz_map_id, p);
        __ImportId(signal_data_id, p);


        reserve_fields(nullptr);
    }

void kis_tracked_seenby_data::set_datasource_alias(std::shared_ptr<kis_datasource> src) {
	src_uuid->set(src->get_tracker_source_uuid());
	datasource_alias->set(src);
}

void kis_tracked_seenby_data::inc_frequency_count(int frequency) {
    auto m = get_tracker_freq_khz_map();
    auto i = m->find(frequency);

    if (i == m->end()) {
        m->insert(frequency, 1);
    } else {
        i->second += 1;
    }
}

void kis_tracked_seenby_data::register_fields() {
    tracker_component::register_fields();

	register_field("kismet.common.seenby.uuid", "UUID of source", &src_uuid);
	register_field("kismet.common.seenby.source", "datasource", &datasource_alias);

    register_field("kismet.common.seenby.first_time", "first time seen time_t", &first_time);
    register_field("kismet.common.seenby.last_time", "last time seen time_t", &last_time);
    register_field("kismet.common.seenby.num_packets", 
            "number of packets seen by this device", &num_packets);

    freq_khz_map_id =
        register_dynamic_field<tracker_element_double_map_double>("kismet.common.seenby.freq_khz_map", 
            "packets seen per frequency (khz)");

    frequency_val_id =
        register_field("kismet.common.seenby.frequency.count",
                tracker_element_factory<tracker_element_uint64>(), "packets per frequency");

    signal_data_id =
        register_dynamic_field<kis_tracked_signal_data>("kismet.common.seenby.signal", "signal data");
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

void kis_tracked_device_base::inc_seenby_count(kis_datasource *source, 
        time_t tv_sec, int frequency, packinfo_sig_combo *siginfo,
        bool update_rrd) {
    std::shared_ptr<kis_tracked_seenby_data> seenby;

    auto seenby_iter = seenby_map->find(source->get_source_key());

    // Make a new seenby record
    if (seenby_iter == seenby_map->end()) {
		auto resolved_src = Globalreg::globalreg->datasourcetracker->find_datasource(source->get_source_uuid());
		if (resolved_src != nullptr) {
			seenby = Globalreg::globalreg->entrytracker->get_shared_instance_as<kis_tracked_seenby_data>(seenby_val_id);

			seenby->set_datasource_alias(resolved_src);

			seenby->set_first_time(tv_sec);
			seenby->set_last_time(tv_sec);
			seenby->set_num_packets(1);

			if (frequency > 0)
				seenby->inc_frequency_count(frequency);

			if (siginfo != NULL)
				(seenby->get_signal_data())->append_signal(*siginfo, update_rrd, tv_sec);

			seenby_map->insert(source->get_source_key(), seenby);
		}
    } else {
        auto seenby_r = static_cast<kis_tracked_seenby_data *>(seenby_iter->second.get());

        seenby_r->set_last_time(tv_sec);
        seenby_r->inc_num_packets();

        if (frequency > 0)
            seenby_r->inc_frequency_count(frequency);

        if (siginfo != NULL)
            seenby_r->get_signal_data()->append_signal(*siginfo, update_rrd, tv_sec);
    }
}

void kis_tracked_device_base::register_fields() {
    tracker_component::register_fields();
    
    phy_id = 0;

    register_field("kismet.device.base.key", "unique device key across phy and server", &key);
    register_field("kismet.device.base.macaddr", "mac address", &macaddr);
    register_field("kismet.device.base.phyname", "phy name", &phyname);
    register_field("kismet.device.base.name", "printable device name", &devicename);
    username_id = 
        register_dynamic_field("kismet.device.base.username", "user name", &username);
    register_field("kismet.device.base.commonname", 
            "common name alias of custom or device names", &commonname);
    register_field("kismet.device.base.type", "printable device type", &type_string);
    register_field("kismet.device.base.basic_type_set", "bitset of basic type", &basic_type_set);

    register_field("kismet.device.base.crypt", "printable basic encryption information", &crypt_string);

    register_field("kismet.device.base.basic_crypt_set", 
            "bitset of basic encryption", &basic_crypt_set);
    register_field("kismet.device.base.first_time", "first time seen time_t", &first_time);
    register_field("kismet.device.base.last_time", "last time seen time_t", &last_time);
    register_field("kismet.device.base.mod_time", 
            "timestamp of last seen time (local clock)", &mod_time);
    register_field("kismet.device.base.packets.total", "total packets seen of all types", &packets);
    register_field("kismet.device.base.packets.rx_total", "total transmitted packets seen of all types", &rx_packets);
    register_field("kismet.device.base.packets.tx_total", "total received packets (addressed to this device) seen of all types", &tx_packets);
    register_field("kismet.device.base.packets.llc", "observed protocol control packets", &llc_packets);
    register_field("kismet.device.base.packets.error", "corrupt/error packets", &error_packets);
    register_field("kismet.device.base.packets.data", "data packets", &data_packets);
    register_field("kismet.device.base.packets.crypt", "data packets using encryption", &crypt_packets);
    register_field("kismet.device.base.packets.filtered", "packets dropped by filter", &filter_packets);
    register_field("kismet.device.base.datasize", "transmitted data in bytes", &datasize);
    
    packets_rrd_id =
        register_dynamic_field<kis_tracked_rrd<>>("kismet.device.base.packets.rrd", "packet rate rrd");
    data_rrd_id =
        register_dynamic_field<kis_tracked_rrd<>>("kismet.device.base.datasize.rrd", "packet size rrd");
    packets_rx_rrd_id =
        register_dynamic_field<kis_tracked_rrd<>>("kismet.device.base.rx_packets.rrd", "received packet rate rrd");
    packets_tx_rrd_id =
        register_dynamic_field<kis_tracked_rrd<>>("kismet.device.base.tx_packets.rrd", "transmitted packet rate rrd");

    signal_data_id =
        register_dynamic_field("kismet.device.base.signal", "signal data", &signal_data);

    register_field("kismet.device.base.freq_khz_map", "packets seen per frequency (khz)", &freq_khz_map);
    register_field("kismet.device.base.channel", "channel (phy specific)", &channel);
    register_field("kismet.device.base.frequency", "frequency", &frequency);
    register_field("kismet.device.base.manuf", "manufacturer name", &manuf);
    register_field("kismet.device.base.num_alerts", "number of alerts on this device", &alert);
    
    tag_map_id =
        register_dynamic_field("kismet.device.base.tags", "set of arbitrary tags, including user notes", &tag_map);

    tag_entry_id =
        register_field("kismet.device.base.tag", 
                tracker_element_factory<tracker_element_string>(), "arbitrary tag");

    location_id =
        register_dynamic_field<kis_tracked_location>("kismet.device.base.location", "location");

    register_field("kismet.device.base.seenby", "sources that have seen this device", &seenby_map);

    // Packet count, not actual frequency, so uint64 not double
    frequency_val_id =
        register_field("kismet.device.base.frequency.count",
                tracker_element_factory<tracker_element_uint64>(), "frequency packet count");

    seenby_val_id =
        register_field("kismet.device.base.seenby.data",
                tracker_element_factory<kis_tracked_seenby_data>(),
                "datasource seen-by data");

    register_field("kismet.device.base.related_devices",
            "Related devices, organized by relationship", &related_devices_map);

    related_device_group_id = register_field("kismet.device.base.related_group",
        tracker_element_factory<tracker_element_device_key_map>(),
        "Related devices, by key");

    location_cloud_id = register_dynamic_field<kis_location_rrd>(
        "kismet.device.base.location_cloud", "RRD-like location history");
}

void kis_tracked_device_base::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);

    seenby_map->set_as_vector(true);

    if (e != NULL) {
        // If we're inheriting, it's our responsibility to kick submaps with
        // complex types as well; since they're not themselves complex objects
        for (auto s : *seenby_map) {
            // Build a proper seenby record for each item in the list
            auto sbd = 
                std::make_shared<kis_tracked_seenby_data>(seenby_val_id, 
                        std::static_pointer_cast<tracker_element_map>(s.second));
            // And assign it over the same key
            s.second = sbd;
        }
    }
}

void kis_tracked_device_base::add_related_device(const std::string& in_relationship, const device_key in_key) {
    auto related_group_i = related_devices_map->find(in_relationship);

    if (related_group_i == related_devices_map->end()) {
        auto related_group = std::make_shared<tracker_element_device_key_map>(related_device_group_id);
        related_group->set_as_key_vector(true);
        related_group->insert(in_key, nullptr);
        related_devices_map->insert(in_relationship, related_group);
    } else {
        auto related_group = static_cast<tracker_element_device_key_map *>(related_group_i->second.get());
        related_group->insert(in_key, nullptr);
    }
}

