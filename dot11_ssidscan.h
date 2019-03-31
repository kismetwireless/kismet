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

class Dot11_SsidScan : public LifetimeGlobal {
public:
    static std::string global_name() { return "DOT11_SSIDSCAN"; }

    static std::shared_ptr<Dot11_SsidScan> create_ssidscan() {
        std::shared_ptr<Dot11_SsidScan> shared(new Dot11_SsidScan());
        Globalreg::globalreg->RegisterLifetimeGlobal(shared);
        Globalreg::globalreg->InsertGlobal(global_name(), shared);
        return shared;
    }

private:
    Dot11_SsidScan();

public:
    virtual ~Dot11_SsidScan();


protected:
    // Target SSIDs
    std::shared_ptr<TrackerElementVector> target_ssids;

    // Pool of sources (if multiple are available)
    std::shared_ptr<TrackerElementVector> hopping_datasources;
    std::shared_ptr<TrackerElementVector> locking_datasources;

    // Do we ignore after we think we got a handshake?
    std::shared_ptr<TrackerElementUInt8> ignore_after_handshake;

    // Maximum time spent capturing if no free source is in the 'hopping' pool
    std::shared_ptr<TrackerElementUInt32> max_contend_cap_seconds;

    // Minimum time spent hopping looking for targets if no free source is in the 
    // 'locked' pool
    std::shared_ptr<TrackerElementUInt32> min_scan_seconds;

    // Automatically set the log filters on startup
    std::shared_ptr<TrackerElementUInt8> set_initial_log_filters;

    // Filter logging
    std::shared_ptr<TrackerElementUInt8> filter_logs;

};

#endif /* ifndef PHY_80211_SSIDSCAN */
