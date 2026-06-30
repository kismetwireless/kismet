
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

#include "devicetracker_component_v2.h"

#include "fmt/format.h"

device_key_v2::device_key_v2() :
    spkey_{0},
    dkey_{0},
    error_{true} { }

device_key_v2::device_key_v2(const device_key_v2& k) {
    spkey_ = k.spkey_;
    dkey_ = k.dkey_;
    error_ = k.error_;
}

device_key_v2::device_key_v2(const device_key_v2&& k) {
    spkey_ = k.spkey_;
    dkey_ = k.dkey_;
    error_ = k.error_;
}

device_key_v2::device_key_v2(uint32_t in_pkey, uint64_t in_dkey) {
    spkey_ = in_pkey & 0xFFFFFFFF;
    dkey_ = in_dkey;
    error_ = false;
}

device_key_v2::device_key_v2(uint32_t in_pkey, mac_addr in_device) {
    spkey_ = in_pkey & 0xFFFFFFFF;
    dkey_ = in_device.longmac;
    error_ = false;
}

device_key_v2::device_key_v2(const std::string& in_keystr) {
    unsigned long long int k1, k2;

    if (sscanf(in_keystr.c_str(), "%llx_%llx", &k1, &k2) != 2) {
        error_ = true;
        spkey_ = 0;
        dkey_ = 0;
        return;
    }

    // Convert from big endian exported format
    spkey_ = (uint64_t) kis_ntoh64(k1);
    dkey_ = (uint64_t) kis_ntoh64(k2);
    error_ = false;
}

void device_key_v2::reset() {
    spkey_ = 0;
    dkey_ = 0;
    error_ = true;
}

std::string device_key_v2::as_string() const {
    return fmt::format("{:X}_{:X}", spkey_, dkey_);
}

uint32_t device_key_v2::gen_pkey(const std::string& phy) {
    return adler32_checksum(phy.c_str(), phy.length());
}

uint32_t device_key_v2::gen_pkey(const std::string_view& phy) {
    return adler32_checksum(phy.data(), phy.length());
}

uint64_t device_key_v2::gen_spkey(uuid s_uuid, const std::string& phy) {
    uint64_t uuid32 = adler32_checksum((const char *) s_uuid.hash, sizeof(std::size_t));
    uint64_t phy32 = gen_pkey(phy);
    return (uuid32 << 32) | phy32;
}

bool operator <(const device_key_v2& x, const device_key_v2& y) {
    if (x.spkey_ == y.spkey_)
        return x.dkey_ < y.dkey_;

    return x.spkey_ < y.spkey_;
}

bool operator ==(const device_key_v2& x, const device_key_v2& y) {
    return (x.spkey_ == y.spkey_ && x.dkey_ == y.dkey_);
}

auto fmt::formatter<device_key_v2>::format(const device_key_v2& k, format_context& ctx) const -> format_context::iterator {
    return formatter<string_view>::format(k.as_string(), ctx);
}

void kis_tracked_signal_data_v2::append_signal(const kis_layer1_packinfo& lay1, bool update_rrd, time_t rrd_ts) {
    if (lay1.signal_type == kis_l1_signal_type_dbm && (sig_type == 0 || sig_type == 1)) {
        sig_type = 1;

        if (lay1.signal_dbm != 0) {
            last_signal = lay1.signal_dbm;

            if (min_signal == 0 || min_signal > lay1.signal_dbm) {
                min_signal = lay1.signal_dbm;
            }

            if (max_signal == 0 || max_signal < lay1.signal_dbm) {
                max_signal = lay1.signal_dbm;
            }

            /*
            if (update_rrd)
                get_signal_min_rrd()->add_sample(lay1.signal_dbm, rrd_ts);
                */
        }

        if (lay1.noise_dbm != 0) {
            last_noise = lay1.noise_dbm;

            if (min_noise == 0 || min_noise > lay1.noise_dbm) {
                min_noise = lay1.noise_dbm;
            }

            if (max_noise == 0 || max_noise < lay1.noise_dbm) {
                max_noise = lay1.noise_dbm;
            }
        }
    } else if (lay1.signal_type == kis_l1_signal_type_rssi && (sig_type == 0 || sig_type == 2)) {
        sig_type = 2;

        if (lay1.signal_rssi != 0) {
            last_signal = lay1.signal_rssi;

            if (min_signal == 0 || min_signal > lay1.signal_rssi) {
                min_signal = lay1.signal_rssi;
            }

            if (max_signal == 0 || max_signal < lay1.signal_rssi) {
                max_signal = lay1.signal_rssi;
            }

            /*
            if (update_rrd)
                get_signal_min_rrd()->add_sample(lay1.signal_rssi, rrd_ts);
                */
        }

        if (lay1.noise_rssi != 0) {
            last_noise = lay1.noise_rssi;

            if (min_noise == 0 || min_noise > lay1.noise_rssi) {
                min_noise = lay1.noise_rssi;
            }

            if (max_noise == 0 || max_noise < lay1.noise_rssi) {
                max_noise = lay1.noise_rssi;
            }
        }

        carrierset |= (uint64_t) lay1.carrier;
        encodingset |= (uint64_t) lay1.encoding;

        if (maxseenrate < (double) lay1.datarate) {
            maxseenrate = (double) lay1.datarate;
        }
    }
}

void kis_tracked_signal_data_v2::append_signal(const packinfo_sig_combo& in, bool update_rrd, time_t rrd_ts) {
    if (in.lay1 != NULL) {
        if (in.lay1->signal_type == kis_l1_signal_type_dbm && (sig_type == 0 || sig_type == 1)) {
            sig_type = 1;

            if (in.lay1->signal_dbm != 0) {
                last_signal = in.lay1->signal_dbm;

                if (min_signal == 0 || min_signal > in.lay1->signal_dbm) {
                    min_signal = in.lay1->signal_dbm;
                }

                if (max_signal == 0 || max_signal < in.lay1->signal_dbm) {
                    max_signal = in.lay1->signal_dbm;

                    /*
                    if (in.gps != NULL) {
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt, in.gps->fix);
                    }
                    */
                }

                /*
                if (update_rrd)
                    get_signal_min_rrd()->add_sample(in.lay1->signal_dbm, rrd_ts);
                    */
            }

            if (in.lay1->noise_dbm != 0) {
                last_noise = in.lay1->noise_dbm;

                if (min_noise == 0 || min_noise > in.lay1->noise_dbm) {
                    min_noise = in.lay1->noise_dbm;
                }

                if (max_noise == 0 || max_noise < in.lay1->noise_dbm) {
                    max_noise = in.lay1->noise_dbm;
                }
            }
        } else if (in.lay1->signal_type == kis_l1_signal_type_rssi && (sig_type == 0 || sig_type == 2)) {
            sig_type = 2;

            if (in.lay1->signal_rssi != 0) {
                last_signal = in.lay1->signal_rssi;

                if (min_signal == 0 || min_signal > in.lay1->signal_rssi) {
                    min_signal = in.lay1->signal_rssi;
                }

                if (max_signal == 0 || max_signal < in.lay1->signal_rssi) {
                    max_signal = in.lay1->signal_rssi;

                    /*
                    if (in.gps != NULL) {
                        get_peak_loc()->set(in.gps->lat, in.gps->lon, in.gps->alt,
                                in.gps->fix);
                    }
                    */
                }

                /*
                if (update_rrd)
                    get_signal_min_rrd()->add_sample(in.lay1->signal_rssi, rrd_ts);
                    */
            }

            if (in.lay1->noise_rssi != 0) {
                last_noise = in.lay1->noise_rssi;

                if (min_noise == 0 || min_noise > in.lay1->noise_rssi) {
                    min_noise = in.lay1->noise_rssi;
                }

                if (max_noise == 0 || max_noise < in.lay1->noise_rssi) {
                    max_noise = in.lay1->noise_rssi;
                }
            }

        }

        carrierset |= (uint64_t) in.lay1->carrier;
        encodingset |= (uint64_t) in.lay1->encoding;

        if (maxseenrate < (double) in.lay1->datarate) {
            maxseenrate = (double) in.lay1->datarate;
        }
    }
}

void kis_tracked_signal_data_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    std::string signal_type;
    switch (sig_type) {
    case 1:
        signal_type = "dBm";
        break;
    case 2:
        signal_type = "RSSI";
        break;
    default:
        signal_type = "raw";
        break;
    }

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.common.signal.type", opts, signal_type);

    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.common.signal.last_signal", opts, last_signal);
    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.common.signal.last_noise", opts, last_noise);

    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.common.signal.min_signal", opts, min_signal);
    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.common.signal.min_noise", opts, min_noise);

    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.common.signal.max_signal", opts, max_signal);
    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "kismet.common.signal.max_noise", opts, max_noise);

    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.common.signal.maxseenrate", opts, maxseenrate);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.signal.encodingset", opts, encodingset);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.signal.carrierset", opts, carrierset);

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void kis_tracked_signal_data_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    std::string signal_type;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.common.signal.type"):
                switch (sig_type) {
                    case 1:
                        signal_type = "dBm";
                        break;
                    case 2:
                        signal_type = "RSSI";
                        break;
                    default:
                        signal_type = "raw";
                        break;
                }
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, signal_type);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.last_signal"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, last_signal);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.last_noise"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, last_noise);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.min_signal"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, min_signal);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.min_noise"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, min_noise);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.max_signal"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, max_signal);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.max_noise"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, max_noise);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.maxseenrate"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, maxseenrate);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.encodingset"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, encodingset);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.carrierset"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, carrierset);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void kis_tracked_seenby_data_v2::inc_seenby(uint64_t frequency, uint64_t time,
        const kis_tracked_signal_data_v2& signal) {
    last_time_ = time;
    num_packets_++;
    freq_khz_map_[frequency]++;
    signal_data_ = signal;
}

void kis_tracked_seenby_data_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    if (datasource_ != nullptr) {
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.common.seenby.uuid", opts, datasource_->get_source_uuid().uuid_to_string());
    } else {
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.common.seenby.uuid", opts, uuid{}.uuid_to_string());
    }

    // TODO needs v2 datasource json to complete embedding the DS

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.seenby.first_time", opts, first_time_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.seenby.last_time", opts, last_time_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.seenby.num_packets", opts, num_packets_);
    json_adapter_v2::json_encode_keyed_map<freq_khz_map_iter_t>{}(os, "kismet.common.seenby.freq_khz_map", opts,
            freq_khz_map_.begin(), freq_khz_map_.end());
    json_adapter_v2::json_encode_keyed<kis_tracked_signal_data_v2>{}(os, "kismet.common.seenby.signal", opts, signal_data_);

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void kis_tracked_seenby_data_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    // TODO needs v2 datasource json to cmoplete embedding the DS

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    std::string signal_type;
    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.common.seenby.uuid"):
                if (datasource_ != nullptr) {
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, datasource_->get_source_uuid().uuid_to_string());
                } else {
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, uuid{}.uuid_to_string());
                }
                break;
            case json_adapter_v2::consthash("kismet.common.seenby.first_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.seenby.first_time", opts, first_time_);
                break;
            case json_adapter_v2::consthash("kismet.common.seenby.last_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.seenby.last_time", opts, last_time_);
                break;
            case json_adapter_v2::consthash("kismet.common.seenby.num_packets"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.common.seenby.num_packets", opts, num_packets_);
                break;
            case json_adapter_v2::consthash("kismet.common.seenby.freq_khz_map"):
                json_adapter_v2::json_encode_keyed_map<freq_khz_map_iter_t>{}(os, "kismet.common.seenby.freq_khz_map", opts,
                        freq_khz_map_.begin(), freq_khz_map_.end());
                break;
            case json_adapter_v2::consthash("kismet.common.seenby.signal"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_signal_data_v2>{}(os, f.first, opts, signal_data_, subgroup);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    opts->next_key_comma = sv_comma;
    fmt::print(os, "}}");
}

kis_tracked_device_base_v2::kis_tracked_device_base_v2() :
    json_adapter_v2::jsonable() {
    mutex_.set_name("kis_tracked_device_base_v2");
    reset();
}

kis_tracked_device_base_v2::~kis_tracked_device_base_v2() {
    auto lg = kis_unique_lock(mutex_, __func__);
    for (const auto& s : sub_component_map_) {
        delete s.second.sub_component_;
    }
}

void kis_tracked_device_base_v2::reset() {
    internal_id_ = 0;
    key_ = {};
    mac_addr_ = {};
    phyname_ = {};
    phyid_ = 0;

    devicename_ = {};
    username_ = {};
    commonname_ = {};

    type_string_ = {};
    basic_type_set_ = 0;

    crypt_string_ = {};
    basic_crypt_set_ = 0;

    first_time_ = 0;
    last_time_ = 0;
    mod_time_ = 0;

    packets_ = 0;
    rx_packets_ = 0;
    tx_packets_ = 0;
    llc_packets_ = 0;
    data_packets_ = 0;
    error_packets_ = 0;
    crypt_packets_ = 0;
    filter_packets_ = 0;
    duplicate_packets_ = 0;

    datasize_ = 0;

    packets_rrd_.reset();
    data_rrd_.reset();

    channel_ = {};
    frequency_khz_ = 0;

    signal_ = {};

    freq_khz_distribution_ = {};

    manuf_ = {};

    tag_map_ = {};

    location_ = {};
    location_history_ = {};

    seenby_map_ = {};

    related_devices_ = {};
}

void kis_tracked_device_base_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    auto lg = kis_shared_lock(mutex_, __func__);

    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<device_key_v2>{}(os, "kismet.device.base.key", opts, key());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.device.base.macaddr", opts, mac_addr().as_string());

    json_adapter_v2::json_encode_keyed<std::string_view>{}(os, "kismet.device.base.phyname", opts, phyname());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.device.base.name", opts, devicename());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.device.base.username", opts, username());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.device.base.commonname", opts, commonname());

    json_adapter_v2::json_encode_keyed<std::string_view>{}(os, "kismet.device.base.type", opts, type_string());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.basic_type_set", opts, basic_type_set());

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.device.base.crypt", opts, crypt_string());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.basic_crypt_set", opts, basic_crypt_set());

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.first_time", opts, first_time());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.last_time", opts, last_time());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.mod_time", opts, mod_time());

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.total", opts, packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.rx_total", opts, rx_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.tx_total", opts, tx_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.llc", opts, llc_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.error", opts, error_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.data", opts, data_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.crypt", opts, crypt_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.filter", opts, filter_packets());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.packets.duplicate", opts, duplicate_packets());

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.datasize", opts, datasize());

    json_adapter_v2::json_encode_keyed<kis_rrd_v2<>>{}(os, "kismet.device.base.packets.rrd", opts, packets_rrd());
    json_adapter_v2::json_encode_keyed<kis_rrd_v2<>>{}(os, "kismet.device.base.datasize.rrd", opts, data_rrd());

    json_adapter_v2::json_encode_keyed<kis_tracked_signal_data_v2>{}(os, "kismet.device.base.signal", opts, signal());

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.device.base.channel", opts, channel());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.frequency", opts, frequency_khz());
    json_adapter_v2::json_encode_keyed_map<freq_khz_distribution_iter_t_>{}(os, "kismet.device.base.freq_khz_map", opts,
            freq_khz_distribution().begin(), freq_khz_distribution().end());

    json_adapter_v2::json_encode_keyed<std::string_view>{}(os, "kismet.device.base.manuf", opts, manuf());

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.device.base.num_alerts", opts, num_alerts());

    json_adapter_v2::json_encode_keyed_map<tag_map_iter_t_>{}(os, "kismet.device.base.tags", opts,
            tag_map().begin(), tag_map().end());

    json_adapter_v2::json_encode_keyed<kis_tracked_location_full_v2>{}(os, "kismet.device.base.location", opts, location());
    json_adapter_v2::json_encode_keyed<kis_historic_location_v2>{}(os, "kismet.device.base.location_cloud", opts, location_history());

    json_adapter_v2::json_encode_keyed_map<seenby_map_iter_t_>{}(os, "kismet.device.base.seenby", opts,
            seenby_map().begin(), seenby_map().end());

    json_adapter_v2::json_encode_keyed_map_custom<related_devices_iter_t_,
        json_adapter_v2::json_encode_map_keys<related_devices_sub_t_::iterator, related_devices_sub_t_>>{}(os, "kismet.device.base.related_devices", opts,
                related_devices().begin(), related_devices().end());

    for (const auto& s : sub_component_map_) {
        fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(s.second.field_));
        opts->next_key_comma = false;
        s.second.encode_fn_(os, opts, s.second.sub_component_, {});
        opts->next_key_comma = true;
    }

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void kis_tracked_device_base_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    ssize_t hash;

    auto lg = kis_shared_lock(mutex_, __func__);

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch ((hash = json_adapter_v2::consthash(f.first))) {
            case json_adapter_v2::consthash("kismet.device.base.key"):
                json_adapter_v2::json_encode_keyed<device_key_v2>{}(os, f.second.rename, opts, key());
                break;
            case json_adapter_v2::consthash("kismet.device.base.macaddr"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, mac_addr().as_string());
                break;
            case json_adapter_v2::consthash("kismet.device.base.phyname"):
                json_adapter_v2::json_encode_keyed<std::string_view>{}(os, f.second.rename, opts, phyname());
                break;
            case json_adapter_v2::consthash("kismet.device.base.name"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, devicename());
                break;
            case json_adapter_v2::consthash("kismet.device.base.username"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, username());
                break;
            case json_adapter_v2::consthash("kismet.device.base.commonname"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, commonname());
                break;
            case json_adapter_v2::consthash("kismet.device.base.type"):
                json_adapter_v2::json_encode_keyed<std::string_view>{}(os, f.second.rename, opts, type_string());
                break;
            case json_adapter_v2::consthash("kismet.device.base.type_set"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, basic_type_set());
                break;
            case json_adapter_v2::consthash("kismet.device.base.crypt"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, crypt_string());
                break;
            case json_adapter_v2::consthash("kismet.device.base.crypt_set"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, basic_crypt_set());
                break;
            case json_adapter_v2::consthash("kismet.device.base.first_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, first_time());
                break;
            case json_adapter_v2::consthash("kismet.device.base.last_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_time());
                break;
            case json_adapter_v2::consthash("kismet.device.base.mod_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, mod_time());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.total"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.rx_total"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, rx_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.tx_total"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, tx_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.llc"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, llc_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.error"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, error_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.data"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, data_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.crypt"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, crypt_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.filter"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, filter_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.duplicate"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, duplicate_packets());
                break;
            case json_adapter_v2::consthash("kismet.device.base.datasize"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, datasize());
                break;
            case json_adapter_v2::consthash("kismet.device.base.packets.rrd"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_rrd_v2<>>{}(os, f.second.rename, opts, packets_rrd(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.device.base.datasize.rrd"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_rrd_v2<>>{}(os, f.second.rename, opts, data_rrd(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.device.base.signal"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_signal_data_v2>{}(os, f.second.rename, opts, signal(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.device.base.channel"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel());
                break;
            case json_adapter_v2::consthash("kismet.device.base.frequency"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, frequency_khz());
                break;
            case json_adapter_v2::consthash("kismet.device.base.freq_khz_map"):
                json_adapter_v2::json_encode_keyed_map<freq_khz_distribution_iter_t_>{}(os, f.second.rename, opts,
                        freq_khz_distribution().begin(), freq_khz_distribution().end());
                break;
            case json_adapter_v2::consthash("kismet.device.base.manuf"):
                json_adapter_v2::json_encode_keyed<std::string_view>{}(os, f.second.rename, opts, manuf());
                break;
            case json_adapter_v2::consthash("kismet.device.base.num_alerts"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, num_alerts());
                break;
            case json_adapter_v2::consthash("kismet.device.base.tags"):
                json_adapter_v2::json_encode_keyed_map<tag_map_iter_t_>{}(os, f.second.rename, opts,
                        tag_map().begin(), tag_map().end());
                break;
            case json_adapter_v2::consthash("kismet.device.base.location"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_location_full_v2>{}(os, f.second.rename, opts, location(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.device.base.location_cloud"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_historic_location_v2>{}(os, f.second.rename, opts, location_history());
                break;
            case json_adapter_v2::consthash("kismet.device.base.seenby"):
                json_adapter_v2::json_encode_keyed_map<seenby_map_iter_t_>{}(os, f.second.rename, opts,
                        seenby_map().begin(), seenby_map().end());
                break;
            case json_adapter_v2::consthash("kismet.device.base.related_devices"):
                json_adapter_v2::json_encode_keyed_map_custom<related_devices_iter_t_,
                    json_adapter_v2::json_encode_map_keys<related_devices_sub_t_::iterator, related_devices_sub_t_>>{}(os, f.second.rename, opts,
                            related_devices().begin(), related_devices().end());
                break;
            default:
                const auto& sf = sub_component_map_.find(hash);
                if (sf != sub_component_map_.end()) {
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(sf->second.field_));
                    opts->next_key_comma = false;
                    sf->second.encode_fn_(os, opts, sf->second.sub_component_, subgroup);
                    opts->next_key_comma = true;
                } else {
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
                }
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;

}

void kis_tracked_device_base_v2::add_subcomponent(const std::string& field,
        subcomponent_encoder_fn_t encoder, json_adapter_v2::jsonable *object) {
    const auto hash = json_adapter_v2::consthash(field);

    auto lg = kis_unique_lock(mutex_, __func__);

    const auto& emp = sub_component_map_.try_emplace(hash, sub_component{
            .field_ = field,
            .sub_component_ = object,
            .encode_fn_ = encoder,
            });

    if (!emp.second) {
        throw std::runtime_error(fmt::format("device already has subcomponent {}", field));
    }
}
