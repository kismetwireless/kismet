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

#include "config.h"
#include <sstream>
#include "statealert.h"

int bsstsalert_chain_hook(CHAINCALL_PARMS) {

	return ((BSSTSStateAlert *) auxdata)->ProcessPacket(in_pack);
}

BSSTSStateAlert::BSSTSStateAlert(GlobalRegistry *in_globalreg) :
	StateAlert(in_globalreg) {

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS: BSSTSStateAlert before packetchain\n");
		exit(1);
	}

	if (globalreg->alertracker == NULL) {
		fprintf(stderr, "FATAL OOPS: BSSTSStateAlert before alertracker\n");
		exit(1);
	}

	// Register the packet chain element
	globalreg->packetchain->RegisterHandler(&bsstsalert_chain_hook, this,
											CHAINPOS_CLASSIFIER, -50);

	// Activate our alert
	alert_bss_ts_ref = 
		globalreg->alertracker->ActivateConfiguredAlert("BSSTIMESTAMP");
}

BSSTSStateAlert::~BSSTSStateAlert() {
	for (map<mac_addr, bss_rec *>::iterator x = state_map.begin(); 
		 x != state_map.end(); ++x) {
		delete x->second;
	}

	state_map.clear();
}

int BSSTSStateAlert::ProcessPacket(kis_packet *in_pack) {
	// Get the 802.11 data
	kis_ieee80211_packinfo *packinfo =
		(kis_ieee80211_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211));

	if (packinfo == NULL)
		return 0;

	if (packinfo->type != packet_management ||
		packinfo->subtype != packet_sub_beacon ||
		packinfo->distrib == distrib_adhoc)
		return 0;

	map<mac_addr, bss_rec *>::iterator smi =
		state_map.find(packinfo->bssid_mac);

	if (smi == state_map.end()) {
		bss_rec *r = new bss_rec;
		r->incident = 0;
		r->bss_timestamp = packinfo->timestamp;
		state_map[packinfo->bssid_mac] = r;
		return 0;
	}

	bss_rec *br = smi->second;

	if (packinfo->timestamp < (br->bss_timestamp - 500000)) {
		if (br->incident > 0) {
			// Raise an alert
			ostringstream oss;

			oss << "Network BSSID " << packinfo->bssid_mac.Mac2String() << 
				" BSS timestamp fluctuating, which may indicate a spoofed "
				"network cloning the MAC address";
			globalreg->alertracker->RaiseAlert(alert_bss_ts_ref, in_pack,
											   packinfo->bssid_mac,
											   packinfo->source_mac,
											   packinfo->dest_mac,
											   packinfo->other_mac,
											   packinfo->channel,
											   oss.str());
			br->incident = 0;
		} else {
			br->incident += 5;
		}
	} else if (br->incident > 0) {
		br->incident--;
	}

	br->bss_timestamp = packinfo->timestamp;

	return 1;
}
	
