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

#ifndef __DATASOURCE_SCAN_H__
#define __DATASOURCE_SCAN_H__ 

#include "config.h"

#include "globalregistry.h"
#include "kis_datasource.h"
#include "kis_net_beast_httpd.h"

// Virtual dot11 datasource which supports scanning results from other systems; scans are turned
// into dot11 networks with as much info as is available

class datasource_scan_source {
public:
    datasource_scan_source(const std::string& uri, const std::string& source_type, 
            const std::string& json_component_type);

    virtual ~datasource_scan_source();

protected:
    kis_mutex mutex;

    std::string endpoint_uri;
    std::string virtual_source_type;
    std::string json_component_type;

    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<packet_chain> packetchain;

    void scan_result_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);

    int pack_comp_common, pack_comp_json, pack_comp_datasrc, pack_comp_gps,
        pack_comp_l1info, pack_comp_devicetag;

    // Validation function; can either return 'false' for generic error, or throw a specific error
    // exception to be returned to the submitter
    bool validate_report(nlohmann::json& report) { return true; }
};

#endif /* ifndef DATASOURCE_SCAN_H__ */
