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

#include "kis_net_microhttpd.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

class Phy_80211_SsidScan : public LifetimeGlobal {
public:
    static std::string global_name() { return "DOT11_SSIDSCAN"; }

    static std::shared_ptr<Phy_80211_SsidScan> create_ssidscan() {
        std::shared_ptr<Phy_80211_SsidScan> shared(new Phy_80211_SsidScan());
        Globalreg::globalreg->RegisterLifetimeGlobal(shared);
        Globalreg::globalreg->InsertGlobal(global_name(), shared);
        return shared;
    }

private:
    Phy_80211_SsidScan();

public:
    virtual ~Phy_80211_SsidScan();


protected:
    // Target SSIDs
    std::shared_ptr<TrackerElementVector> target_ssids;

    std::shared_ptr<TrackerElementVector> hopping_datasources;
    std::shared_ptr<TrackerElementVector> locking_datasources;

};

#endif /* ifndef PHY_80211_SSIDSCAN */
