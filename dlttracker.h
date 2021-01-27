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

#ifndef __DLTTRACKER_H__
#define __DLTTRACKER_H__

#include "config.h"

#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <functional>

#include "globalregistry.h"
#include "util.h"
#include "kis_datasource.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_beast_httpd.h"
#include "entrytracker.h"
#include "kis_mutex.h"

// Custom DLT tracker.
// Some datasources represent data which is not assigned a TCPDUMP DLT; for fast-lookup
// reasons we need to track custom DLTs.
//
// Generally we can take the adler32 of the linktype name; if we get an adler32 of less
// than 4096 we adjust it to make sure we don't overlap with any real DLTs (even tho they're
// < 190 generally lets leave some room)
//
// This provides an exceedingly minimal mechanism for assigning custom DLTs

class dlt_tracker : public lifetime_global {
public:
    static std::shared_ptr<dlt_tracker> create_dltt() {
        auto mon = std::make_shared<dlt_tracker>();
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global("DLTTRACKER", mon);

        return mon;
    }

    dlt_tracker();
    virtual ~dlt_tracker();

    uint32_t register_linktype(const std::string& in_linktype);
    std::string get_linktype_name(uint32_t in_dlt);

protected:
    kis_mutex mutex;

    std::map<uint32_t, std::string> dlt_to_name_map;

};

#endif


