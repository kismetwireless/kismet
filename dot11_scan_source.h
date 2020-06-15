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

#ifndef __DOT11_SCAN_SOURCE__
#define __DOT11_SCAN_SOURCE__ 

#include "config.h"

#include "globalregistry.h"
#include "kis_datasource.h"
#include "kis_net_microhttpd.h"
#include "kis_net_microhttpd_handlers.h"

// Virtual dot11 datasource which supports scanning results from other systems; scans are turned
// into dot11 networks with as much info as is available

class dot11_scan_source : public lifetime_global {
public:
    static std::string global_name() { return "dot11_scan_source"; }

    static std::shared_ptr<dot11_scan_source> create_dot11_scan_source() {
        std::shared_ptr<dot11_scan_source> ssrc(new dot11_scan_source());
        Globalreg::globalreg->register_lifetime_global(ssrc);
        Globalreg::globalreg->insert_global(global_name(), ssrc);
        return ssrc;
    }

private:
    dot11_scan_source();

public:
    virtual ~dot11_scan_source();

protected:
    kis_recursive_timed_mutex mutex;

    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<packet_chain> packetchain;

    std::shared_ptr<kis_net_httpd_simple_post_endpoint> scan_result_endp;
    unsigned int scan_result_endp_handler(std::ostream& stream, 
            const std::string& uri, const Json::Value& json,
            kis_net_httpd_connection::variable_cache_map& variable_cache);

    int pack_comp_common, pack_comp_json, pack_comp_datasrc, pack_comp_gps,
        pack_comp_l1info;

};

#endif /* ifndef DOT11_SCAN_SOURCE */
