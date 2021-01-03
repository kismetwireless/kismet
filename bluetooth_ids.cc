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

#include "bluetooth_ids.h"

#include "configfile.h"
#include "entrytracker.h"
#include "messagebus.h"

kis_bt_oid::kis_bt_oid() {
    mutex.set_name("kis_bt_oid");

    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    oid_id =
        entrytracker->register_field("kismet.device.base.btoid",
                tracker_element_factory<tracker_element_string>(), "Bluetooth OID name");

    unknown_oid = std::make_shared<tracker_element_string>(oid_id);
    unknown_oid->set("Unknown");

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("btoid_lookup", true) == false) {
        _MSG_INFO("Disabling Bluetooth OID name lookup");
        return;
    }

    for (auto o : Globalreg::globalreg->kismet_config->fetch_opt_vec("btoid")) {
        auto o_pair = str_tokenize(o, ",");
        unsigned int oid;

        if (o_pair.size() != 2) {
            _MSG_ERROR("Expected 'btoid=AABB,Name' for a config file OID record.");
            continue;
        }

        try {
            oid = string_to_n<unsigned int>(o_pair[0], std::hex);
        } catch (const std::runtime_error& e) {
            _MSG_ERROR("Expected 'btoid=AABB,Name' for a config file OID record.");
            continue;
        }

        oid_data od;
        od.oid = oid;
        od.data = std::make_shared<tracker_element_string>(oid_id, o_pair[1]);
        oid_map[oid] = od;
    }

    auto fname = 
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("btoidfile", "%S/kismet/kismet_bluetooth_ids.txt");

    auto expanded = Globalreg::globalreg->kismet_config->expand_log_path(fname, "", "", 0, 1);

    if ((zofile = gzopen(expanded.c_str(), "r")) == nullptr) {
        _MSG_ERROR("BTOID file {} was not found, will not resolve Bluetooth service names.",
                expanded);
        return;
    }

    index_bt_oids();
}

kis_bt_oid::~kis_bt_oid() {
    Globalreg::globalreg->remove_global(global_name());

    if (zofile != nullptr)
        gzclose(zofile);
}

void kis_bt_oid::index_bt_oids() {
    char buf[1024];
    int line = 0;
    z_off_t prev_pos;
    uint32_t oid;

    if (zofile == nullptr)
        return;

    kis_lock_guard<kis_mutex> lk(mutex, "kis_btoit index_bt_oids");

    _MSG_INFO("Indexing Bluetooth OID list");

    prev_pos = gzseek(zofile, 0, SEEK_CUR);

    while (!gzeof(zofile)) {
        if (gzgets(zofile, buf, 1024) == nullptr || gzeof(zofile))
            break;

        if ((line % 50) == 0) {
            if (sscanf(buf, "%x", &oid) != 1) {
                line--;
                continue;
            }

            index_pos ip;

            ip.oid = oid;
            ip.pos = prev_pos;

            index_vec.push_back(ip);
        }

        prev_pos = gzseek(zofile, 0, SEEK_CUR);
        line++;
    }

    _MSG_INFO("Completed indexing Bluetooth OID database, {} entries, {} indexes.",
            line, index_vec.size());
}

std::shared_ptr<tracker_element_string> kis_bt_oid::lookup_oid(uint32_t in_oid) {
    int matched = -1;
    char buf[1024];
    uint32_t poid;

    if (zofile == nullptr)
        return unknown_oid;

    kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_oit lookup_oid");

    if (oid_map.find(in_oid) != oid_map.end())
        return oid_map[in_oid].data;

    for (unsigned int x = 0; x < index_vec.size(); x++) {
        if (in_oid > index_vec[x].oid) {
            matched = x;
            continue;
        }

        break;
    }

    if (matched < 0) {
        oid_data od;
        od.oid = in_oid;
        od.data = unknown_oid;
        oid_map[in_oid] = od;

        return od.data;
    }

    if (matched > 0)
        matched -= 1;

    gzseek(zofile, index_vec[matched].pos, SEEK_SET);

    while (!gzeof(zofile)) {
        if (gzgets(zofile, buf, 1024) == nullptr || gzeof(zofile))
            break;

        if (strlen(buf) < 5)
            continue;

        auto mlen = strlen(buf + 5) - 1;

        if (mlen == 0)
            continue;

        if (sscanf(buf, "%x", &poid) != 1)
            continue;

        if (poid == in_oid) {
            oid_data od;
            od.oid = poid;
            od.data = 
                std::make_shared<tracker_element_string>(oid_id, munge_to_printable(std::string(buf + 5, mlen)));
            oid_map[poid] = od;
            return od.data;
        }

        if (poid > in_oid) {
            oid_data od;
            od.oid = in_oid;
            od.data = unknown_oid;
            oid_map[in_oid] = od;

            return od.data;
        }

    }

    return unknown_oid;
}

bool kis_bt_oid::is_unknown_oid(std::shared_ptr<tracker_element_string> in_oid) {
    return in_oid == unknown_oid;
}


kis_bt_manuf::kis_bt_manuf() {
    mutex.set_name("kis_bt_manuf");

    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    manuf_id =
        entrytracker->register_field("kismet.device.base.btmanuf",
                tracker_element_factory<tracker_element_string>(), "Bluetooth manufacturer name");

    unknown_manuf = std::make_shared<tracker_element_string>(manuf_id);
    unknown_manuf->set("Unknown");

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("btmanuf_lookup", true) == false) {
        _MSG_INFO("Disabling Bluetooth manufacturer name lookup");
        return;
    }

    for (auto m : Globalreg::globalreg->kismet_config->fetch_opt_vec("btmanuf")) {
        auto m_pair = str_tokenize(m, ",");
        unsigned int id;

        if (m_pair.size() != 2) {
            _MSG_ERROR("Expected 'btmanuf=AABB,Name' for a config file manufacturer record.");
            continue;
        }

        try {
            id = string_to_n<unsigned int>(m_pair[0], std::hex);
        } catch (const std::runtime_error& e) {
            _MSG_ERROR("Expected 'btmanuf=AABB,Name' for a config file manufacturer record.");
            continue;
        }

        manuf_data md;
        md.id = id;
        md.manuf = std::make_shared<tracker_element_string>(manuf_id, m_pair[1]);
        manuf_map[id] = md;
    }

    auto fname = 
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("btmanuffile", "%S/kismet/kismet_bluetooth_manuf.txt");

    auto expanded = Globalreg::globalreg->kismet_config->expand_log_path(fname, "", "", 0, 1);

    if ((zmfile = gzopen(expanded.c_str(), "r")) == nullptr) {
        _MSG_ERROR("BTMANUF file {} was not found, will not resolve Bluetooth service names.",
                expanded);
        return;
    }

    index_bt_manufs();
}

kis_bt_manuf::~kis_bt_manuf() {
    Globalreg::globalreg->remove_global(global_name());

    if (zmfile != nullptr)
        gzclose(zmfile);
}

void kis_bt_manuf::index_bt_manufs() {
    char buf[1024];
    int line = 0;
    z_off_t prev_pos;
    uint32_t oid;

    if (zmfile == nullptr)
        return;

    kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_manuf index_bt_manufs");

    _MSG_INFO("Indexing Bluetooth manufacturer list");

    prev_pos = gzseek(zmfile, 0, SEEK_CUR);

    while (!gzeof(zmfile)) {
        if (gzgets(zmfile, buf, 1024) == nullptr || gzeof(zmfile))
            break;

        if ((line % 50) == 0) {
            if (sscanf(buf, "%x", &oid) != 1) {
                line--;
                continue;
            }

            index_pos ip;

            ip.id = oid;
            ip.pos = prev_pos;

            index_vec.push_back(ip);
        }

        prev_pos = gzseek(zmfile, 0, SEEK_CUR);
        line++;
    }

    _MSG_INFO("Completed indexing Bluetooth manufacturer database, {} entries, {} indexes.",
            line, index_vec.size());
}

std::shared_ptr<tracker_element_string> kis_bt_manuf::lookup_manuf(uint32_t in_id) {
    int matched = -1;
    char buf[1024];
    uint32_t pid;

    if (zmfile == nullptr)
        return unknown_manuf;

    kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_manuf lookup_manuf");

    if (manuf_map.find(in_id) != manuf_map.end())
        return manuf_map[in_id].manuf;

    for (unsigned int x = 0; x < index_vec.size(); x++) {
        if (in_id > index_vec[x].id) {
            matched = x;
            continue;
        }

        break;
    }

    if (matched < 0) {
        manuf_data md;
        md.id = in_id;
        md.manuf = unknown_manuf;
        manuf_map[in_id] = md;

        return md.manuf;
    }

    if (matched > 0)
        matched -= 1;

    gzseek(zmfile, index_vec[matched].pos, SEEK_SET);

    while (!gzeof(zmfile)) {
        if (gzgets(zmfile, buf, 1024) == nullptr || gzeof(zmfile))
            break;

        if (strlen(buf) < 5)
            continue;

        auto mlen = strlen(buf + 5) - 1;

        if (mlen == 0)
            continue;

        if (sscanf(buf, "%x", &pid) != 1)
            continue;

        if (pid == in_id) {
            manuf_data md;
            md.id = pid;
            md.manuf = 
                std::make_shared<tracker_element_string>(manuf_id, 
                        munge_to_printable(std::string(buf + 5, mlen)));
            manuf_map[pid] = md;
            return md.manuf;
        }

        if (pid > in_id) {
            manuf_data md;
            md.id = in_id;
            md.manuf = unknown_manuf;
            manuf_map[in_id] = md;

            return md.manuf;
        }

    }

    return unknown_manuf;
}

bool kis_bt_manuf::is_unknown_manuf(std::shared_ptr<tracker_element_string> in_manuf) {
    return in_manuf == unknown_manuf;
}
