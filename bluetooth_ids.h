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

#ifndef __BLUETOOTH_IDS__
#define __BLUETOOTH_IDS__ 

#include "config.h"

#include <stdint.h>
#include <zlib.h>

#include <memory>
#include <string>
#include <unordered_map>

#include "globalregistry.h"
#include "trackedelement.h"

class kis_bt_oid : public lifetime_global {
public:
    static std::string global_name() { return "BTOID"; }
    static std::shared_ptr<kis_bt_oid> create_bt_oid() {
        std::shared_ptr<kis_bt_oid> mon(new kis_bt_oid());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    kis_bt_oid();

public:
    virtual ~kis_bt_oid();

    void index_bt_oids();

    std::shared_ptr<tracker_element_string> lookup_oid(uint32_t in_oid);

    struct index_pos {
        uint32_t oid;
        z_off_t pos;
    };

    struct oid_data {
        uint32_t oid;
        std::shared_ptr<tracker_element_string> data;
    };

    bool is_unknown_oid(std::shared_ptr<tracker_element_string> in_oid);

protected:
    kis_mutex mutex;

    std::vector<index_pos> index_vec;

    std::unordered_map<uint32_t, oid_data> oid_map;

    gzFile zofile;

    int oid_id;
    std::shared_ptr<tracker_element_string> unknown_oid;
};

class kis_bt_manuf : public lifetime_global {
public:
    static std::string global_name() { return "BTMANUF"; }
    static std::shared_ptr<kis_bt_manuf> create_bt_manuf() {
        std::shared_ptr<kis_bt_manuf> mon(new kis_bt_manuf());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    kis_bt_manuf();

public:
    virtual ~kis_bt_manuf();

    void index_bt_manufs();

    std::shared_ptr<tracker_element_string> lookup_manuf(uint32_t in_manuf);

    struct index_pos {
        uint32_t id;
        z_off_t pos;
    };

    struct manuf_data {
        uint32_t id;
        std::shared_ptr<tracker_element_string> manuf;
    };

    bool is_unknown_manuf(std::shared_ptr<tracker_element_string> in_manuf);

protected:
    kis_mutex mutex;

    std::vector<index_pos> index_vec;

    std::unordered_map<uint32_t, manuf_data> manuf_map;

    gzFile zmfile;

    int manuf_id;
    std::shared_ptr<tracker_element_string> unknown_manuf;
};

#endif /* ifndef BLUETOOTH_IDS */
