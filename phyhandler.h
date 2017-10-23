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

class Devicetracker;

class kis_tracked_device_base;

class Kis_Phy_Handler {
public:
	// Create a 'weak' handler which provides enough structure to call CreatePhyHandler
	Kis_Phy_Handler(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;
		devicetracker = NULL;
		phyid = -1;
		phyname = "NONE";
	}

    virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
            Devicetracker *in_tracker, int in_phyid) = 0;

    Kis_Phy_Handler(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
            int in_phyid) {
		globalreg = in_globalreg;
		phyid = in_phyid;
		devicetracker = in_tracker;
	}

	virtual ~Kis_Phy_Handler() { }

	virtual std::string FetchPhyName() { return phyname; }
	virtual int FetchPhyId() { return phyid; }
    virtual uint32_t FetchPhynameHash() { return phyname_hash; }

    // Called for all instantiated phys when restoring a network object from
    // a stored record; This function is expected to inspect the abstract object
    // tree 'in_storage', generate a proper phy tracked object if the data is present,
    // and insert it into the device record in in_device
    virtual void LoadPhyStorage(SharedTrackerElement in_storage, 
            SharedTrackerElement in_device) { }

protected:
    virtual void SetPhyName(std::string in_phyname) {
        phyname = in_phyname;
        phyname_hash = TrackedDeviceKey::gen_pkey(phyname);
    }

	GlobalRegistry *globalreg;
	Devicetracker *devicetracker;

    std::string phyname;
    uint32_t phyname_hash;
	int phyid;
};

#endif

