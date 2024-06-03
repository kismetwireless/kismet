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

#ifndef __PHYHANDLER_H__
#define __PHYHANDLER_H__

#include "config.h"

#include <stdio.h>

#include "globalregistry.h"
#include "trackedelement.h"
#include "packetchain.h"

class device_tracker;
class kis_tracked_device_base;

class kis_phy_handler {
public:
	// Create a 'weak' handler which provides enough structure to call create_phy_handler
    kis_phy_handler() :
        phyname{"NONE"},
        phyid{-1},
        indexed{true} { }

    virtual kis_phy_handler *create_phy_handler(int in_phyid) = 0;

    kis_phy_handler(int in_phyid) :
        phyname{"NONE"},
        phyid{in_phyid},
        indexed{true} { }

	virtual ~kis_phy_handler() { }

	std::string fetch_phy_name() { return phyname; }
	int fetch_phy_id() { return phyid; }
    uint32_t fetch_phyname_hash() { return phyname_hash; }
    bool fetch_phy_indexed() { return indexed; }

    // Called for all instantiated phys when restoring a network object from
    // a stored record; This function is expected to inspect the abstract object
    // tree 'in_storage', generate a proper phy tracked object if the data is present,
    // and insert it into the device record in in_device
    virtual void load_phy_storage(shared_tracker_element in_storage __attribute__((unused)), 
            shared_tracker_element in_device __attribute__((unused))) { }

    // Allow phys to override if the device is part of this phy
    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) {
        return false;
    }

protected:
    void set_phy_name(std::string in_phyname) {
        phyname = in_phyname;
        phyname_hash = device_key::gen_pkey(phyname);
    }

    std::string phyname;
    uint32_t phyname_hash;
	int phyid;
    bool indexed;
};

#endif

