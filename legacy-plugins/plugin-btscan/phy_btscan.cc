/*
    Copyright 2009, 2010, 2011 Mike Kershaw
 
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
#include <alertracker.h>
#include <configfile.h>
#include <devicetracker.h>

#include "phy_btscan.h"
#include "packet_btscan.h"

enum BTSCANDEV_fields {
	BTSCANDEV_mac, BTSCANDEV_bdaddr, BTSCANDEV_name, BTSCANDEV_class,
	BTSCANDEV_maxfield
};

const char *BTSCANDEV_fields_text[] = {
	"mac", "bdaddr", "name", "class",
	NULL
};

int Protocol_BTSCANDEV(PROTO_PARMS) {
	btscan_dev_component *btdev = (btscan_dev_component *) data;
	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];

		if (fnum > BTSCANDEV_maxfield) {
			out_string = "\001Unknown field\001";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		scratch = "";

		switch (fnum) {
			case BTSCANDEV_mac:
				scratch = btdev->mac.Mac2String();
				break;
			case BTSCANDEV_bdaddr:
				scratch = btdev->bd_addr.Mac2String();
				break;
			case BTSCANDEV_name:
				scratch = "\001" + btdev->bd_name + "\001";
				break;
			case BTSCANDEV_class:
				scratch = "\001" + btdev->bd_class + "\001";
				break;
		}

		cache->Cache(fnum, scratch);
		out_string += scratch + " ";
	}

	return 1;
}

void Protocol_BTSCANDEV_enable(PROTO_ENABLE_PARMS) {
	((Btscan_Phy *) data)->BlitDevices(in_fd, NULL);
}

int phybtscan_packethook_classify(CHAINCALL_PARMS) {
	return ((Btscan_Phy *) auxdata)->ClassifierBtscan(in_pack);
}

int phybtscan_packethook_tracker(CHAINCALL_PARMS) {
	return ((Btscan_Phy *) auxdata)->TrackerBtscan(in_pack);
}

Btscan_Phy::Btscan_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
					   int in_phyid) : Kis_Phy_Handler(in_globalreg, in_tracker,
													   in_phyid) {
	globalreg->InsertGlobal("PHY_BTSCAN", this);
	phyname = "BTscan";

	// No need for a dissector here because the packet component is 
	// dissected already; it's virtual data coming from the scan results
	globalreg->packetchain->RegisterHandler(&phybtscan_packethook_classify, this,
											CHAINPOS_CLASSIFIER, 0);
	globalreg->packetchain->RegisterHandler(&phybtscan_packethook_tracker, this,
											CHAINPOS_TRACKER, 100);

	dev_comp_btscan = devicetracker->RegisterDeviceComponent("BTSCAN_DEV");
	dev_comp_common = devicetracker->RegisterDeviceComponent("COMMON");

	pack_comp_btscan = globalreg->packetchain->RegisterPacketComponent("BTSCAN");
	pack_comp_common = globalreg->packetchain->RegisterPacketComponent("COMMON");
	pack_comp_device = globalreg->packetchain->RegisterPacketComponent("DEVICE");

	proto_ref_btscandev =
		globalreg->kisnetserver->RegisterProtocol("BTSCANDEV", 0, 1,
												  BTSCANDEV_fields_text,
												  &Protocol_BTSCANDEV,
												  &Protocol_BTSCANDEV_enable,
												  this);
}

Btscan_Phy::~Btscan_Phy() {
	globalreg->packetchain->RemoveHandler(&phybtscan_packethook_classify,
										  CHAINPOS_CLASSIFIER);
	globalreg->packetchain->RemoveHandler(&phybtscan_packethook_tracker,
										  CHAINPOS_TRACKER);
}

int Btscan_Phy::ClassifierBtscan(kis_packet *in_pack) {
	btscan_packinfo *bti = (btscan_packinfo *) in_pack->fetch(pack_comp_btscan);

	if (bti == NULL)
		return 0;

	kis_common_info *common = new kis_common_info;

	common->phyid = phyid;
	common->type = packet_basic_mgmt;

	common->device = bti->bd_addr;
	common->source = common->device;

	in_pack->insert(pack_comp_common, common);

	return 1;
}

int Btscan_Phy::TrackerBtscan(kis_packet *in_pack) {
	btscan_packinfo *bti = (btscan_packinfo *) in_pack->fetch(pack_comp_btscan);
	kis_tracked_device_info *devinfo =
		(kis_tracked_device_info *) in_pack->fetch(pack_comp_device);
	btscan_dev_component *btscandev = NULL;
	kis_tracked_device *dev = NULL;

	if (bti == NULL || in_pack->filtered || devinfo == NULL)
		return 0;

	dev = devinfo->devref;

	btscandev = (btscan_dev_component *) dev->fetch(dev_comp_btscan);
	kis_device_common *commondev = (kis_device_common *) dev->fetch(dev_comp_common);

	if (commondev == NULL)
		return 0;

	bool newdev = false;

	if (btscandev == NULL) {
		btscandev = new btscan_dev_component;
		btscandev->bd_addr = bti->bd_addr;
		dev->insert(dev_comp_btscan, btscandev);
		newdev = true;
	}

	btscandev->bd_name = MungeToPrintable(bti->bd_name);
	btscandev->bd_class = MungeToPrintable(bti->bd_class);

	commondev->name = btscandev->bd_name;
	commondev->type_string = "Bluetooth";
	// Bluetooth has no central AP so any device is an AP and a
	// client
	commondev->basic_type_set =
		(KIS_DEVICE_BASICTYPE_AP | KIS_DEVICE_BASICTYPE_CLIENT |
		 KIS_DEVICE_BASICTYPE_PEER);
	
	if (newdev) 
		_MSG("Detected new discoverable Bluetooth device \"" + 
			 btscandev->bd_name + "\" class \"" +
			 btscandev->bd_class + "\"", MSGFLAG_INFO);

	return 1;
}

int Btscan_Phy::TimerKick() {
	return 1;
}

void Btscan_Phy::BlitDevices(int in_fd, vector<kis_tracked_device *> *devlist) {
	if (devlist == NULL)
		devlist = devicetracker->FetchDevices(phyid);

	for (unsigned int x = 0; x < devlist->size(); x++) {
		kis_protocol_cache cache;

		btscan_dev_component *btscandev;

		if ((btscandev = (btscan_dev_component *) (*devlist)[x]->fetch(dev_comp_btscan)) != NULL) {
			if (in_fd == -1)
				globalreg->kisnetserver->SendToAll(proto_ref_btscandev,
												   (void *) btscandev);
			else
				globalreg->kisnetserver->SendToClient(in_fd, proto_ref_btscandev,
													  (void *) btscandev, &cache);
		}
	}
}

void Btscan_Phy::ExportLogRecord(kis_tracked_device *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent) {
	btscan_dev_component *btscandev =
		(btscan_dev_component *) in_device->fetch(dev_comp_btscan);

	if (btscandev == NULL)
		return;

	if (in_logtype == "xml") {
		fprintf(in_logfile, "<bdAddr>%s</bdAddr>\n", 
				btscandev->bd_addr.Mac2String().c_str());
		fprintf(in_logfile, "<bdName>%s</bdName>\n",
				SanitizeXML(btscandev->bd_name).c_str());
		fprintf(in_logfile, "<bdClass>%s</bdClass>\n",
				SanitizeXML(btscandev->bd_class).c_str());
	}

	return;
}

