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

#include <algorithm>

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
    std::string block;
    uint32_t block_first = 0;
    uint32_t last_icao = 0;
    size_t block_count = 0;
    size_t records = 0;

    if (zmfile == nullptr)
        return;

    auto abort_load = [this](const std::string& err) {
        _MSG_ERROR("{}", err);
        gzclose(zmfile);
        zmfile = nullptr;
        icao_blocks.clear();
        icao_block_data.clear();
    };

    _MSG_INFO("Loading ADSB ICAO db");

    while (gzgets(zmfile, buf, sizeof(buf)) != nullptr) {
        if (buf[0] == '#')
            continue;

        char *end = nullptr;
        const auto icao = strtoul(buf, &end, 16);

        if (end == buf || *end != '\t' || icao > UINT32_MAX) {
            abort_load(fmt::format("Invalid ICAO entry: '{}'", buf));
            return;
        }

        if (icao < last_icao) {
            abort_load("ADSB ICAO file appears to be out of order, expected sorted ICAO records.");
            return;
        }
        last_icao = icao;

        if (block_count == 0)
            block_first = icao;

        block.append(buf);
        if (block.back() != '\n')
            block.push_back('\n');

        block_count++;
        records++;

        if (block_count == icao_block_lines) {
            if (!compress_icao_block(block_first, block)) {
                abort_load("Unable to compress ADSB ICAO db block");
                return;
            }

            block.clear();
            block_count = 0;
        }
    }

    if (block_count > 0 && !compress_icao_block(block_first, block)) {
        abort_load("Unable to compress ADSB ICAO db block");
        return;
    }

    gzclose(zmfile);
    zmfile = nullptr;

    icao_blocks.shrink_to_fit();
    icao_block_data.shrink_to_fit();

    _MSG_INFO("Loaded ADSB ICAO db, {} records in {} blocks, {} compressed bytes",
            records, icao_blocks.size(), icao_block_data.size());
}

bool kis_adsb_icao::compress_icao_block(uint32_t first_icao, const std::string& raw) {
    const auto offset = icao_block_data.size();
    auto comp_len = compressBound(raw.size());

    if (offset + comp_len > UINT32_MAX || raw.size() > UINT32_MAX)
        return false;

    icao_block_data.resize(offset + comp_len);

    if (compress2(reinterpret_cast<Bytef *>(&icao_block_data[offset]), &comp_len,
                reinterpret_cast<const Bytef *>(raw.data()), raw.size(), Z_DEFAULT_COMPRESSION) != Z_OK) {
        icao_block_data.resize(offset);
        return false;
    }

    icao_block_data.resize(offset + comp_len);
    icao_blocks.push_back({first_icao, (uint32_t) offset, (uint32_t) comp_len, (uint32_t) raw.size()});

    return true;
}

std::shared_ptr<tracked_adsb_icao> kis_adsb_icao::parse_icao_line(uint32_t icao, const std::string& line) {
    auto fields = quote_str_tokenize(line, "\t");

    if (fields.size() != 6 || fields[5].length() == 0) {
        _MSG_ERROR("Invalid ICAO entry: '{}'", line);
        return unknown_icao;
    }

    auto icao_rec = std::make_shared<tracked_adsb_icao>(icao_id);
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

    return icao_rec;
}

std::shared_ptr<tracked_adsb_icao> kis_adsb_icao::lookup_icao(uint32_t icao) {
    // Called for every ADSB message, so known and unknown ICAOs are both cached
    {
        kis_lock_guard<kis_mutex> lk(mutex, "adsb icao lookup");

        auto cached = icao_map.find(icao);
        if (cached != icao_map.end())
            return cached->second;
    }

    if (icao_blocks.empty())
        return unknown_icao;

    auto record = unknown_icao;

    // The block a record would be in is the last one starting at or below it
    auto bi = std::upper_bound(icao_blocks.begin(), icao_blocks.end(), icao,
            [](uint32_t i, const icao_block& b) { return i < b.first_icao; });

    if (bi != icao_blocks.begin()) {
        --bi;

        std::string raw(bi->raw_len, '\0');
        uLongf raw_len = bi->raw_len;

        if (uncompress(reinterpret_cast<Bytef *>(&raw[0]), &raw_len,
                    reinterpret_cast<const Bytef *>(icao_block_data.data() + bi->offset),
                    bi->comp_len) != Z_OK || raw_len != bi->raw_len) {
            _MSG_ERROR("ADSB ICAO db block failed to decompress");
        } else {
            size_t pos = 0;

            while (pos < raw.size()) {
                auto eol = raw.find('\n', pos);
                if (eol == std::string::npos)
                    eol = raw.size();

                // Lines were validated as starting with a hex ICAO and a tab when loaded
                const auto f_icao = strtoul(raw.c_str() + pos, nullptr, 16);

                if (f_icao == icao) {
                    record = parse_icao_line(icao, raw.substr(pos, eol - pos));
                    break;
                }

                if (f_icao > icao)
                    break;

                pos = eol + 1;
            }
        }
    }

    // Another thread may have resolved it first; keep one shared record per ICAO
    kis_lock_guard<kis_mutex> lk(mutex, "adsb icao lookup insert");
    return icao_map.try_emplace(icao, record).first->second;
}
