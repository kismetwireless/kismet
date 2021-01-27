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

#include <string.h>

#include "dlttracker.h"
#include "util.h"

dlt_tracker::dlt_tracker() {
    mutex.set_name("dlttracker");
}

dlt_tracker::~dlt_tracker() {

}

uint32_t dlt_tracker::register_linktype(const std::string& in_linktype) {
    uint32_t csum = adler32_checksum(str_lower(in_linktype));
    
    if (csum < 4096)
        csum += 4096;

    kis_lock_guard<kis_mutex> lk(mutex, "dlt_tracker register_linktype");

    dlt_to_name_map[csum] = str_lower(in_linktype);

    return csum;
}

std::string dlt_tracker::get_linktype_name(uint32_t in_dlt) {
    kis_lock_guard<kis_mutex> lk(mutex, "dlt_tracker get_linktype_name");

    auto i = dlt_to_name_map.find(in_dlt);

    if (i != dlt_to_name_map.end())
        return i->second;

    return "unknown";
}

