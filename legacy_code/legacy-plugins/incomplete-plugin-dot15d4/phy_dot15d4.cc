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
#include <endian_magic.h>

#include "phy_dot15d4.h"
#include "packet_dot15d4.h"

int phydot15d4_packethook_dissect(CHAINCALL_PARMS) {
	return ((Dot15d4_Phy *) auxdata)->DissectorDot15d4(in_pack);
}

int phydot15d4_packethook_classify(CHAINCALL_PARMS) {
	return ((Dot15d4_Phy *) auxdata)->ClassifierDot15d4(in_pack);
}

int phydot15d4_packethook_tracker(CHAINCALL_PARMS) {
	return ((Dot15d4_Phy *) auxdata)->TrackerDot15d4(in_pack);
}

Dot15d4_Phy::Dot15d4_Phy(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
						 int in_phyid) : Kis_Phy_Handler(in_globalreg, in_tracker,
														 in_phyid) {
	globalreg->InsertGlobal("PHY_DOT15D4_TRACKER", this);
	phyname = "Dot15d4";

	globalreg->packetchain->RegisterHandler(&phydot15d4_packethook_dissect, this,
											CHAINPOS_LLCDISSECT, 0);
	globalreg->packetchain->RegisterHandler(&phydot15d4_packethook_classify, this,
											CHAINPOS_CLASSIFIER, 0);
	globalreg->packetchain->RegisterHandler(&phydot15d4_packethook_tracker, this,
											CHAINPOS_TRACKER, 100);

	dev_comp_dot15d4dev = devicetracker->RegisterDeviceComponent("DOT15D4_DEV");
	dev_comp_common = devicetracker->RegisterDeviceComponent("COMMON");

	pack_comp_dot15d4 = globalreg->packetchain->RegisterPacketComponent("DOT15D4");
	pack_comp_common = globalreg->packetchain->RegisterPacketComponent("COMMON");
	pack_comp_device = globalreg->packetchain->RegisterPacketComponent("DEVICE");

}

Dot15d4_Phy::~Dot15d4_Phy() {
	globalreg->packetchain->RemoveHandler(&phydot15d4_packethook_dissect,
										  CHAINPOS_LLCDISSECT);
	globalreg->packetchain->RemoveHandler(&phydot15d4_packethook_tracker,
										  CHAINPOS_TRACKER);
	globalreg->packetchain->RemoveHandler(&phydot15d4_packethook_classify,
										  CHAINPOS_CLASSIFIER);
}

int Dot15d4_Phy::DissectorDot15d4(kis_packet *in_pack) {
	unsigned int offset = 0;

	dot15d4_packinfo *pi = NULL;

	if (in_pack->error)
		return 0;

	kis_datachunk *chunk =
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));

	if (chunk == NULL)
		return 0;

	if (chunk->dlt != KDLT_IEEE802_15_4)
		return 0;

	if (chunk->length < 11) {
		_MSG("Short dot15d4 frame!", MSGFLAG_ERROR);
		in_pack->error = 1;
		return 0;
	}

	pi = new dot15d4_packinfo();

	uint16_t fh;

	fh = kis_letoh16(*((uint16_t *) chunk->data));

	pi->frame_header = fh;
	pi->type = DOT154_FH_FRAMETYPE(fh);
	pi->security = DOT154_FH_SECURITY(fh);
	pi->sourceaddr_mode = DOT154_FH_SRCADDRMODE(fh);
	pi->destaddr_mode = DOT154_FH_DESTADDRMODE(fh);
	pi->version = DOT154_FH_FRAMEVERSION(fh);
	pi->intrapan = DOT154_FH_INTRAPAN(fh);

#if 0
	printf("Packet %d FH: %4.04x\n", debugno, fh);
	printf("  Frame Type    : %d\n", DOT154_FH_FRAMETYPE(fh));
	printf("  Frame Security: %d\n", DOT154_FH_SECURITY(fh));
	printf("  Frame SA Mode : %u\n", DOT154_FH_SRCADDRMODE(fh));
	printf("  Frame Version : %u\n", DOT154_FH_FRAMEVERSION(fh));
#endif

	pi->seqno = chunk->data[2];

	offset = 3;
	
	if (pi->type == d15d4_type_beacon) {
		if (chunk->length < offset + 2) {
			delete pi;
			in_pack->error = 1;
			return 0;
		}

		memcpy(&(pi->source_pan), &(chunk->data[offset]), 2);
		offset += 2;

		if (pi->sourceaddr_mode == DOT154_FH_ADDR_LONG) {
			if (chunk->length < offset + 8) {
				delete pi;
				in_pack->error = 1;
				return 0;
			}

			memcpy(&(pi->source_addr), &(chunk->data[offset]), 8);
			offset += 8;
		} else {
			if (chunk->length < offset + 2) {
				delete pi;
				in_pack->error = 1;
				return 0;
			}

			memcpy(&(pi->source_addr), &(chunk->data[offset]), 2);
			offset += 2;
		}
	}

	if (pi->type == d15d4_type_data ||
		pi->type == d15d4_type_command) {

		if (chunk->length < offset + 2) {
			delete pi;
			in_pack->error = 1;
			return 0;
		}

		memcpy(&(pi->dest_pan), &(chunk->data[offset]), 2);
		offset += 2;

		if (pi->destaddr_mode == DOT154_FH_ADDR_LONG) {
			if (chunk->length < offset + 8) {
				delete pi;
				in_pack->error = 1;
				return 0;
			}

			memcpy(&(pi->dest_addr), &(chunk->data[offset]), 8);
			offset += 8;
		} else {
			if (chunk->length < offset + 2) {
				delete pi;
				in_pack->error = 1;
				return 0;
			}

			memcpy(&(pi->dest_addr), &(chunk->data[offset]), 2);
			offset += 2;
		}

		if (pi->intrapan == 0) {
			memcpy(&(pi->source_pan), &(chunk->data[offset]), 2);
			offset += 2;
		}

		if (pi->sourceaddr_mode == DOT154_FH_ADDR_LONG) {
			if (chunk->length < offset + 8) {
				delete pi;
				in_pack->error = 1;
				return 0;
			}

			memcpy(&(pi->source_addr), &(chunk->data[offset]), 8);
			offset += 8;
		} else {
			if (chunk->length < offset + 2) {
				delete pi;
				in_pack->error = 1;
				return 0;
			}

			memcpy(&(pi->source_addr), &(chunk->data[offset]), 2);
			offset += 2;
		}
	}

	in_pack->insert(pack_comp_dot15d4, pi);

	return 1;

}


