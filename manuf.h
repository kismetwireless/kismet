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

#ifndef __MANUF_H__
#define __MANUF_H__

#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <zlib.h>

#include <string>

#include "globalregistry.h"
#include "unordered_dense.h"
#include "trackedelement.h"
#include "util.h"

class kis_manuf {
public:
    kis_manuf();

    void IndexOUI();

    std::shared_ptr<tracker_element_string> lookup_oui(mac_addr in_mac);
    std::shared_ptr<tracker_element_string> lookup_oui(uint32_t in_oui);

    std::shared_ptr<tracker_element_string> make_manuf(const std::string& in_manuf);

    std::shared_ptr<tracker_element_string> get_random_manuf() const {
        return random_manuf;
    }

    struct index_pos {
        uint32_t oui;
        z_off_t pos;
    };

    struct manuf_data {
        uint32_t oui;
        std::shared_ptr<tracker_element_string> manuf;
    }; 

    bool is_unknown_manuf(std::shared_ptr<tracker_element_string> in_manuf);

protected:
    kis_mutex mutex;

    std::vector<index_pos> index_vec;

    ankerl::unordered_dense::map<uint32_t, manuf_data> oui_map;

    gzFile zmfile;

    // IDs for manufacturer objects
    int manuf_id;
    std::shared_ptr<tracker_element_string> unknown_manuf;
    std::shared_ptr<tracker_element_string> random_manuf;
};

#endif

