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

#ifndef __PHY_DOT15D4_H__
#define __PHY_DOT15D4_H__

#include <config.h>
#include <globalregistry.h>
#include <devicetracker.h>

#include "packet_btscan.h"

class btscan_dev_component : public tracker_component {
public:
	mac_addr mac;
	mac_addr bd_addr;
	string bd_name, bd_class;
};

class Btscan_Phy : public Kis_Phy_Handler {
public:
	Btscan_Phy() { }
	~Btscan_Phy();

	Btscan_Phy(GlobalRegistry *in_globalreg) :
		Kis_Phy_Handler(in_globalreg) { };

	// Weak constructor
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) {
		return new Btscan_Phy(in_globalreg, in_tracker, in_phyid);
	}

	// Strong constructor
	Btscan_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
			   int in_phyid);

	// Packet classifier to common
	int ClassifierBtscan(kis_packet *in_pack);

	// BTScan record classifier
	int TrackerBtscan(kis_packet *in_pack);

	virtual int TimerKick();

	virtual void BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist);

	virtual void ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent);

	virtual string FetchPhyXsdNs() {
		return "phybtscan";
	}

protected:
	// *BTSCANDEV sentence
	int proto_ref_btscandev;

	// tracked device component
	int dev_comp_btscan, dev_comp_common;

	// Packet components
	int pack_comp_btscan, pack_comp_common, pack_comp_device;
};

#endif

