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

#ifndef __PHY_80211_SSIDSCAN__
#define __PHY_80211_SSIDSCAN__ 

#include "config.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

class phy_80211_ssid_scan : public lifetime_global {
public:
    static std::string global_name() { return "DOT11_SSIDSCAN"; }

    static std::shared_ptr<phy_80211_ssid_scan> create_ssidscan() {
        std::shared_ptr<phy_80211_ssid_scan> shared(new phy_80211_ssid_scan());
        Globalreg::globalreg->register_lifetime_global(shared);
        Globalreg::globalreg->insert_global(global_name(), shared);
        return shared;
    }

private:
    phy_80211_ssid_scan();

public:
    virtual ~phy_80211_ssid_scan();


protected:
    // Target SSIDs
    std::shared_ptr<tracker_element_vector> target_ssids;

    std::shared_ptr<tracker_element_vector> hopping_datasources;
    std::shared_ptr<tracker_element_vector> locking_datasources;

};

#endif /* ifndef PHY_80211_SSIDSCAN */
