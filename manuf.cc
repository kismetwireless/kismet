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
#include "manuf.h"

kis_manuf::kis_manuf() {
    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    manuf_id = 
        entrytracker->register_field("kismet.device.base.manuf", 
                tracker_element_factory<tracker_element_string>(), "manufacturer name");

    unknown_manuf = std::make_shared<tracker_element_string>(manuf_id);
    unknown_manuf->set("Unknown");

    random_manuf = std::make_shared<tracker_element_string>(manuf_id);
    random_manuf->set("Randomized");

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("manuf_lookup", true) == false) {
        _MSG("Disabling OUI lookup.", MSGFLAG_INFO);
        return;
    }

    for (auto m : Globalreg::globalreg->kismet_config->fetch_opt_vec("manuf")) {
        auto m_pair = str_tokenize(m, ",");
        short int si[3];

        if (m_pair.size() != 2) {
            _MSG_ERROR("Expected 'manuf=AA:BB:CC,Name' for a config file manuf record.");
            continue;
        }

        if (sscanf(m_pair[0].c_str(), "%hx:%hx:%hx", &(si[0]), &(si[1]), &(si[2])) == 3) {
            uint32_t oui;

            oui = 0;
            oui |= (uint32_t) si[0] << 16;
            oui |= (uint32_t) si[1] << 8;
            oui |= (uint32_t) si[2];

            manuf_data md;
            md.oui = oui;
            md.manuf = std::make_shared<tracker_element_string>(manuf_id);
            md.manuf->set(m_pair[1]);
            oui_map[oui] = md;
        } else {
            _MSG_ERROR("Expected 'manuf=AA:BB:CC,Name' for a config file manuf record.");
            continue;
        }
    }

    auto fname = Globalreg::globalreg->kismet_config->fetch_opt_vec("ouifile");
    if (fname.size() == 0) {
        _MSG("Missing 'ouifile' option in config, will not resolve manufacturer "
             "names for MAC addresses", MSGFLAG_ERROR);
        return;
    }

    for (auto f : fname) {
        auto expanded = Globalreg::globalreg->kismet_config->expand_log_path(f, "", "", 0, 1);

        if ((zmfile = gzopen(expanded.c_str(), "r")) != nullptr) {
            _MSG("Opened OUI file '" + expanded, MSGFLAG_INFO);
            break;
        }

        _MSG("Could not open OUI file '" + expanded + "': " + std::string(strerror(errno)), MSGFLAG_INFO);
    }

    if (zmfile == nullptr) {
        _MSG("No OUI files were available, will not resolve manufacturer "
             "names for MAC addresses", MSGFLAG_ERROR);
        return;
    }

    IndexOUI();
}

void kis_manuf::IndexOUI() {
    char buf[1024];
    short int m[3];
    uint32_t last_oui = 0;
    bool sorted = true;

    if (zmfile == nullptr)
        return;

    _MSG("Loading manufacturer db", MSGFLAG_INFO);

    // Lines are 'AA:BB:CC<tab>Name'
    while (gzgets(zmfile, buf, sizeof(buf)) != nullptr) {
        auto len = strlen(buf);

        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            len--;

        if (len < 10 || buf[8] != '\t')
            continue;

        if (sscanf(buf, "%2hx:%2hx:%2hx", &(m[0]), &(m[1]), &(m[2])) != 3)
            continue;

        const uint32_t oui = ((uint32_t) (m[0] & 0xFF) << 16) |
            ((uint32_t) (m[1] & 0xFF) << 8) | (uint32_t) (m[2] & 0xFF);

        if (oui < last_oui)
            sorted = false;
        last_oui = oui;

        oui_records.push_back({oui, (uint32_t) oui_names.size(), (uint16_t) (len - 9)});
        oui_names.append(buf + 9, len - 9);
    }

    gzclose(zmfile);
    zmfile = nullptr;

    // Stable so the first record for a duplicated OUI still wins
    if (!sorted) {
        _MSG("Warning:  kis_manuf file appears to be out of order, expected "
                "sorted manuf OUI data", MSGFLAG_ERROR);
        std::stable_sort(oui_records.begin(), oui_records.end(),
                [](const oui_record& a, const oui_record& b) { return a.oui < b.oui; });
    }

    oui_records.shrink_to_fit();
    oui_names.shrink_to_fit();

    _MSG_INFO("Loaded manufacturer db, {} records", oui_records.size());
}

std::shared_ptr<tracker_element_string> kis_manuf::lookup_oui(mac_addr in_mac) {
    // Addresses shorter than an OUI (802.15.4 short addresses) have no manufacturer; OUI()
    // would pad them with zeros and could match a real OUI
    if (in_mac.length() < 3)
        return unknown_manuf;

    return lookup_oui(in_mac.OUI());
}

std::shared_ptr<tracker_element_string> kis_manuf::lookup_oui(uint32_t in_oui) {
    // Config file records and previously resolved OUIs
    {
        kis_lock_guard<kis_mutex> lk(mutex);

        auto ci = oui_map.find(in_oui);
        if (ci != oui_map.end())
            return ci->second.manuf;
    }

    // oui_records is immutable after construction, so search it without the lock
    auto ri = std::lower_bound(oui_records.begin(), oui_records.end(), in_oui,
            [](const oui_record& r, uint32_t o) { return r.oui < o; });

    // Unknown OUIs aren't cached; randomized addresses would grow the cache without bound
    if (ri == oui_records.end() || ri->oui != in_oui)
        return unknown_manuf;

    auto manuf = std::make_shared<tracker_element_string>(manuf_id);
    manuf->set(munge_to_printable(oui_names.data() + ri->name_offset, ri->name_len));

    // Another thread may have resolved it first; keep one shared record per OUI
    kis_lock_guard<kis_mutex> lk(mutex);
    return oui_map.try_emplace(in_oui, manuf_data{in_oui, manuf}).first->second.manuf;
}

std::shared_ptr<tracker_element_string> kis_manuf::make_manuf(const std::string& in_manuf) {
    auto manuf = std::make_shared<tracker_element_string>(manuf_id);
    manuf->set(in_manuf);
    return manuf;
}

bool kis_manuf::is_unknown_manuf(std::shared_ptr<tracker_element_string> in_manuf) {
    return in_manuf == unknown_manuf;
}

