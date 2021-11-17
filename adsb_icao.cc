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
#include "configfile.h"
#include "entrytracker.h"
#include "messagebus.h"
#include "util.h"

#include "adsb_icao.h"

kis_adsb_icao::kis_adsb_icao() {
    mutex.set_name("kis_adsb_icao");

    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    icao_id = 
        entrytracker->register_field("kismet.adsb.icao_record", 
                tracker_element_factory<tracked_adsb_icao>(), "ADSB ICAO registration");
    icao_type_id = 
        entrytracker->register_field("adsb.icao.atype", 
                tracker_element_factory<tracker_element_string>(),
                "Aircraft type");

    // Populate the known types

    /*
     * 1 - Glider
     * 2 - Balloon
     * 3 - Blimp/Dirigible
     * 4 - Fixed wing single engine
     * 5 - Fixed wing multi engine
     * 6 - Rotorcraft
     * 7 - Weight-shift-control
     * 8 - Powered Parachute
     * 9 - Gyroplane
     * H - Hybrid Lift
     * O - Other
     */

    atype_map['1'] = std::make_shared<tracker_element_string>(icao_type_id, "Glider");
    atype_map['2'] = std::make_shared<tracker_element_string>(icao_type_id, "Balloon");
    atype_map['3'] = std::make_shared<tracker_element_string>(icao_type_id, "Blimp/Dirigible");
    atype_map['4'] = std::make_shared<tracker_element_string>(icao_type_id, "Fixed wing single engine");
    atype_map['5'] = std::make_shared<tracker_element_string>(icao_type_id, "Fixed wing multiple engine");
    atype_map['6'] = std::make_shared<tracker_element_string>(icao_type_id, "Helicopter / Rotorcraft");
    atype_map['7'] = std::make_shared<tracker_element_string>(icao_type_id, "Weight-shifted-control");
    atype_map['8'] = std::make_shared<tracker_element_string>(icao_type_id, "Powered parachute");
    atype_map['9'] = std::make_shared<tracker_element_string>(icao_type_id, "Gyroplane");
    atype_map['H'] = std::make_shared<tracker_element_string>(icao_type_id, "Hybrid lift");
    atype_map['O'] = std::make_shared<tracker_element_string>(icao_type_id, "Other Aircraft");
    atype_map['U'] = std::make_shared<tracker_element_string>(icao_type_id, "Unknown Aircraft");

    unknown_icao = std::make_shared<tracked_adsb_icao>(icao_id);
    unknown_icao->set_icao(0x0);
    unknown_icao->set_model("Unknown");
    unknown_icao->set_model_type("Unknown");
    unknown_icao->set_owner("Unknown");
    unknown_icao->set_regid("Unknown");
    unknown_icao->set_atype(atype_map['U']);
    unknown_icao->set_atype_short('U');

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("icao_lookup", true) == false) {
        _MSG_INFO("Disabling ADSB ICAO lookup");
        return;
    }

    auto fname = 
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("icaofile", 
                "%S/kismet/kismet_adsb_icao.txt.gz");

    auto expanded =
        Globalreg::globalreg->kismet_config->expand_log_path(fname, "", "", 0, 1);

    if ((zmfile = gzopen(expanded.c_str(), "r")) == nullptr) {
        _MSG_ERROR("Could not open ICAO database {}, ADSB ICAO lookup will not be available.",
                expanded);
        return;
    }

    index();
}

void kis_adsb_icao::index() {
    char buf[2048];
    int line = 0;
    z_off_t prev_pos;
    uint32_t last_icao = 0;

    kis_lock_guard<kis_mutex> lk(mutex, "adsb icao index");

    if (zmfile == nullptr)
        return;

    _MSG_INFO("Indexing ADSB ICAO db");

    prev_pos = gzseek(zmfile, 0, SEEK_CUR);

    while (!gzeof(zmfile)) {
        if (gzgets(zmfile, buf, 2048) == NULL || gzeof(zmfile))
            break;

        if (buf[0] == '#') {
            line--;
            continue;
        }

        if ((line % 50) == 0) {
            auto fields = quote_str_tokenize(buf, "\t");

            if (fields.size() != 6) {
                _MSG_ERROR("Invalid ICAO entry: '{}'", buf);
                gzclose(zmfile);
                zmfile = nullptr;
                return;
            }

            index_pos ip;
            
            auto icao = string_to_n<uint32_t>(fields[0], std::hex);

            if (icao < last_icao) {
                _MSG_ERROR("ADSB ICAO file appears to be out of order, expected sorted "
                        "ICAO records.");
                gzclose(zmfile);
                zmfile = nullptr;
                return;
            }

            ip.icao = icao;
            ip.pos = prev_pos;

            index_vec.push_back(ip);
        }

        prev_pos = gzseek(zmfile, 0, SEEK_CUR);
        line++;
    }

    _MSG_INFO("Completed indexing ADSB ICAO db, {} lines {} indexes",
            line, index_vec.size());
}

std::shared_ptr<tracked_adsb_icao> kis_adsb_icao::lookup_icao(uint32_t icao) {
    int matched = -1;
    char buf[2048];

    if (zmfile == nullptr) {
        return unknown_icao;
    }

    {
        kis_lock_guard<kis_mutex> lk(mutex, "adsb icao lookup");

        auto cached = icao_map.find(icao);
        if (cached != icao_map.end())
            return cached->second;

        for (unsigned int x = 0; x < index_vec.size(); x++) {
            if (icao > index_vec[x].icao) {
                matched = x;
                continue;
            }

            break;
        }

        if (matched < 0) {
            icao_map[icao] = unknown_icao;
            return unknown_icao;
        }

        if (matched > 0)
            matched -= 1;

        gzseek(zmfile, index_vec[matched].pos, SEEK_SET);
    
        while (!gzeof(zmfile)) {
            if (gzgets(zmfile, buf, 2048) == NULL || gzeof(zmfile))
                break;

            if (buf[0] == '#') {
                continue;
            }

            auto fields = quote_str_tokenize(buf, "\t");

            if (fields.size() != 6) {
                _MSG_ERROR("Invalid ICAO entry: '{}'", buf);
                icao_map[icao] = unknown_icao;
                return unknown_icao;
            }

            auto f_icao = string_to_n<uint32_t>(fields[0], std::hex);

            if (f_icao == icao) {
                if (fields[5].length() == 0) {
                    _MSG_ERROR("Invalid ICAO entry: '{}'", buf);
                    icao_map[icao] = unknown_icao;
                    return unknown_icao;
                }

                auto icao_rec = 
                    std::make_shared<tracked_adsb_icao>(icao_id);
                icao_rec->set_icao(icao);
                icao_rec->set_regid(munge_to_printable(fields[1]));
                icao_rec->set_model_type(munge_to_printable(fields[2]));
                icao_rec->set_model(munge_to_printable(fields[3]));
                icao_rec->set_owner(munge_to_printable(fields[4]));

                auto atype_l = atype_map.find(fields[5][0]);

                if (atype_l == atype_map.end()) {
                    icao_rec->set_atype(atype_map['U']);
                    icao_rec->set_atype_short('U');
                } else {
                    icao_rec->set_atype(atype_l->second);
                    icao_rec->set_atype_short(fields[5][0]);
                }

                icao_map[icao] = icao_rec;
                return icao_rec;
            } else if (f_icao > icao) {
                icao_map[icao] = unknown_icao;
                return unknown_icao;
            }
        }
    }

    return unknown_icao;
}



