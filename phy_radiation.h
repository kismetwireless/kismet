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

#ifndef __PHY_RADIATION_H__
#define __PHY_RADIATION_H__

#include "config.h"
#include "globalregistry.h"
#include "phyhandler.h"

class kis_radiation_phy : public kis_phy_handler {
public:
    virtual ~kis_radiation_phy();

    kis_radiation_phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { };

    virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg,
            int in_phyid) override {
        return new kis_radiation_phy(in_globalreg, in_phyid);
    }

    kis_radiation_phy(global_registry *in_globalreg, int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<device_tracker> devicetracker;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_radiodata;
};


#endif

