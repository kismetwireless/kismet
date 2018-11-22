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

DltTracker::DltTracker() {

}

DltTracker::~DltTracker() {
    local_locker lock(&mutex);

}

uint32_t DltTracker::register_linktype(const std::string& in_linktype) {
    uint32_t csum = Adler32Checksum(StrLower(in_linktype));
    
    if (csum < 4096)
        csum += 4096;

    local_locker l(&mutex);

    dlt_to_name_map[csum] = StrLower(in_linktype);

    return csum;
}

std::string DltTracker::get_linktype_name(uint32_t in_dlt) {
    local_locker l(&mutex);

    auto i = dlt_to_name_map.find(in_dlt);

    if (i != dlt_to_name_map.end())
        return i->second;

    return "unknown";
}

