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

#include "datasource_scan.h"
#include "globalregistry.h"
#include "kis_datasource.h"

// Virtual dot11 datasource which supports scanning results from other systems; scans are turned
// into dot11 networks with as much info as is available

class dot11_scan_source : public datasource_scan_source, public lifetime_global {
public:
    static std::string global_name() { return "dot11_scan_source"; }

    static std::shared_ptr<dot11_scan_source> create_dot11_scan_source() {
        std::shared_ptr<dot11_scan_source> ssrc(new dot11_scan_source());
        Globalreg::globalreg->register_lifetime_global(ssrc);
        Globalreg::globalreg->insert_global(global_name(), ssrc);
        return ssrc;
    }

private:
    dot11_scan_source() : 
        datasource_scan_source("/phy/phy80211/scan/scan_report",
                "IEEE80211 scan",
                "DOT11SCAN"),
        lifetime_global() { }

public:
    virtual ~dot11_scan_source() { };
};

#endif /* ifndef DOT11_SCAN_SOURCE */
