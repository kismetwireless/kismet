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

	CODE IN BOTH phy_80211.cc AND phy_80211_dissectors.cc
*/

#ifndef __PHY_DOT15D4_H__
#define __PHY_DOT15D4_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <globalregistry.h>
#include <packetchain.h>
#include <kis_netframe.h>
#include <timetracker.h>
#include <filtercore.h>
#include <gpscore.h>
#include <packet.h>
#include <uuid.h>
#include <configfile.h>

#include <devicetracker.h>

#include "packet_dot15d4.h"

class dot15d4_device_component : public tracker_component {
public:
	dot15d4_device_component() {

	}

	unsigned int source_pan;
	unsigned int dest_pan;
	unsigned int crypt;
};

class Dot15d4_Phy : public Kis_Phy_Handler {
public:
	Dot15d4_Phy() { }
	~Dot15d4_Phy();

	// Weak constructor
	Dot15d4_Phy(GlobalRegistry *in_globalreg) :
		Kis_Phy_Handler(in_globalreg) { };

	// Builder
	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) {
		return new Dot15d4_Phy(in_globalreg, in_tracker, in_phyid);
	}

	// Strong constructor
	Dot15d4_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
			 int in_phyid);

	int DissectorDot15d4(kis_packet *in_pack);

	int ClassifierDot15d4(kis_packet *in_pack);

	int TrackerDot15d4(kis_packet *in_pack);

	// Timer called from devicetracker
	virtual int TimerKick();

	virtual void BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist);

	virtual void ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent);

protected:
	// Protocol references
	int proto_ref_dot15d4dev;

	// Device components
	int dev_comp_dot15d4dev, dev_comp_common;

	// Packet components
	int pack_comp_dot15d4, pack_comp_common, pack_comp_device;
};

#endif

