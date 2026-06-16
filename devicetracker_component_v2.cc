
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

void kis_tracked_signal_data_v2::append_signal(const kis_layer1_packinfo& lay1, bool update_rrd, time_t rrd_ts) {
    if (lay1.signal_type == kis_l1_signal_type_dbm && (sig_type == 0 || sig_type == 1)) {
        if (sig_type == 0) {
            signal_type = "dbm";
            sig_type = 1;
        }

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
        if (sig_type == 0) {
            signal_type = "rssi";
            sig_type = 2;
        }

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
            if (sig_type == 0) {
                signal_type = "dbm";
                sig_type = 1;
            }

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
            if (sig_type == 0) {
                signal_type = "rssi";
                sig_type = 2;
            }

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

void kis_tracked_signal_data_v2::as_json(std::ostream& os,
        json_adapter_v2::opts *opts) {

    fmt::print(os, "{{");

	auto sv_comma = opts->next_key_comma;
	opts->next_key_comma = false;

    json_adapter_v2::encode_keyed(os, "kismet.common.signal.type", opts, signal_type);

    json_adapter_v2::encode_keyed(os, "kismet.common.signal.last_signal", opts, last_signal);
    json_adapter_v2::encode_keyed(os, "kismet.common.signal.last_noise", opts, last_noise);

    json_adapter_v2::encode_keyed(os, "kismet.common.signal.min_signal", opts, min_signal);
    json_adapter_v2::encode_keyed(os, "kismet.common.signal.min_noise", opts, min_noise);

    json_adapter_v2::encode_keyed(os, "kismet.common.signal.max_signal", opts, max_signal);
    json_adapter_v2::encode_keyed(os, "kismet.common.signal.max_noise", opts, max_noise);

    json_adapter_v2::encode_keyed(os, "kismet.common.signal.maxseenrate", opts, maxseenrate);
    json_adapter_v2::encode_keyed(os, "kismet.common.signal.encodingset", opts, encodingset);

	opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void kis_tracked_signal_data_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

	auto sv_comma = opts->next_key_comma;
	opts->next_key_comma = false;

	fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.common.signal.type"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, signal_type);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.last_signal"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, last_signal);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.last_noise"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, last_noise);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.min_signal"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, min_signal);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.min_noise"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, min_noise);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.max_signal"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, max_signal);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.max_noise"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, max_noise);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.maxseenrate"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, maxseenrate);
                break;
            case json_adapter_v2::consthash("kismet.common.signal.encodingset"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, encodingset);
                break;
            default:
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, 0);
        }
    }

	fmt::print(os, "}}");
	opts->next_key_comma = sv_comma;
}
