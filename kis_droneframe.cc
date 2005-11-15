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

#include <string>
#include <sstream>

#include "util.h"
#include "endian_magic.h"
#include "configfile.h"
#include "packet.h"
#include "packetchain.h"
#include "kis_droneframe.h"
#include "tcpserver.h"
#include "getopt.h"
#include "gpscore.h"

void KisDroneframe_MessageClient::ProcessMessage(string in_msg, int in_flags) {
	string msg;

	if ((in_flags & MSGFLAG_LOCAL) || (in_flags & MSGFLAG_ALERT))
		return;

	if (in_flags & MSGFLAG_DEBUG)
		msg = string("DEBUG - ") + in_msg;
	else if (in_flags & MSGFLAG_INFO)
		msg = string("INFO - ") + in_msg;
	else if (in_flags & MSGFLAG_ERROR)
		msg = string("ERROR - ") + in_msg;
	else if (in_flags & MSGFLAG_FATAL)
		msg = string("FATAL - ") + in_msg;

	((KisDroneFramework *) auxptr)->SendText(msg);
}

int kisdrone_chain_hook(CHAINCALL_PARMS) {
	return ((KisDroneFramework *) auxdata)->chain_handler(in_pack);
}

void KisDroneFramework::Usage(char *name) {
	printf(" *** Kismet Remote Drone Options ***\n");
	printf("     --drone-listen           Override Kismet drone listen options\n");
}

KisDroneFramework::KisDroneFramework() {
	fprintf(stderr, "FATAL OOPS:  KisDroneFramework() called with no globalreg\n");
	exit(1);
}

KisDroneFramework::KisDroneFramework(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	netserver = NULL;
	int port = 0, maxcli = 0;
	char srv_proto[11], srv_bindhost[129];
	TcpServer *tcpsrv;
	string listenline;

    // Sanity check for timetracker
    if (globalreg->timetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: KisDroneFramework called without timetracker\n");
        exit(1);
    }

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS: KisDroneFramework called without "
				"kismet_config\n");
		exit(1);
	}

	if (globalreg->messagebus == NULL) {
		fprintf(stderr, "FATAL OOPS: KisDroneFramework called without messagebus\n");
		exit(1);
	}

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS: KisDroneFramework called without packetchain\n");
		exit(1);
	}

	int dlc = globalreg->getopt_long_num++;
	
	// Commandline stuff
	static struct option droneframe_long_options[] = {
		{ "drone-listen", required_argument, 0, dlc },
		{ 0, 0, 0, 0 }
	};
	int option_idx = 0;

	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv,
							"",
							droneframe_long_options, &option_idx);
		if (r < 0) break;

		if (r == dlc) {
			listenline = string(optarg);
		}
	}

	if (listenline.length() == 0 &&
		(listenline = globalreg->kismet_config->FetchOpt("dronelisten")) == "") {
		_MSG("No 'dronelisten' config line defined for the Kismet drone server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	if (sscanf(listenline.c_str(), "%10[^:]://%128[^:]:%d",
			   srv_proto, srv_bindhost, &port) != 3) {
		_MSG("Malformed 'dronelisten' config line provided for the Kismet "
			 "drone server", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}
	
	if (globalreg->kismet_config->FetchOpt("dronemaxclients") == "") {
		_MSG("No 'dronemaxclients' config line defined for the Kismet drone "
			 "server, defaulting to 5 clients.", MSGFLAG_INFO);
		maxcli = 5;
	} else if (sscanf(globalreg->kismet_config->FetchOpt("dronemaxclients").c_str(),
					  "%d", &maxcli) != 1) {
		_MSG("Malformed 'dronemaxclients' config line provided for the Kismet"
			 "drone server", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	if (globalreg->kismet_config->FetchOpt("droneallowedhosts") == "") {
		_MSG("No 'droneallowedhosts' config line defined for the Kismet drone "
			 "server", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	// We only know how to set up a tcp server
	if (strncasecmp(srv_proto, "tcp", 10) == 0) {
		tcpsrv = new TcpServer(globalreg);
		tcpsrv->SetupServer(port, maxcli, srv_bindhost,
							globalreg->kismet_config->FetchOpt("droneallowedhosts"));
		netserver = tcpsrv;
		server_type = 0;
	} else {
		server_type = -1;
		_MSG("Invalid protocol '" + string(srv_proto) + "' in 'dronelisten' for the "
			 "Kismet UI server", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	// Create the message bus attachment to forward messages to the client
    kisdrone_msgcli = new KisDroneframe_MessageClient(globalreg, this);
    globalreg->messagebus->RegisterClient(kisdrone_msgcli, MSGFLAG_ALL);

	// Register the packet handler
	globalreg->packetchain->RegisterHandler(&kisdrone_chain_hook, this,
											CHAINPOS_POSTCAP, -100);

}

KisDroneFramework::~KisDroneFramework() {
	if (globalreg != NULL && globalreg->messagebus != NULL) {
		globalreg->messagebus->RemoveClient(kisdrone_msgcli);
	}
}

int KisDroneFramework::Activate() {
	ostringstream osstr;

	if (server_type != 0) {
		_MSG("KisDroneFramework unknown server type, something didn't "
			 "initialize", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	TcpServer *tcpsrv = (TcpServer *) netserver;

	if (tcpsrv->EnableServer() < 0 || globalreg->fatal_condition) {
		_MSG("Failed to enable TCP listener for Kismet drone server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	netserver->RegisterServerFramework(this);

	osstr << "Created Kismet drone TCP server on port " << tcpsrv->FetchPort();
	_MSG(osstr.str(), MSGFLAG_INFO);

	return 1;
}

int KisDroneFramework::Accept(int in_fd) {

}

int KisDroneFramework::ParseData(int in_fd) {

}

int KisDroneFramework::KillConnection(int in_fd) {

}

int KisDroneFramework::BufferDrained(int in_fd) {

}

void KisDroneFramework::SendText(string in_text) {

}

int KisDroneFramework::chain_handler(kis_packet *in_pack) {
	kis_gps_packinfo *gpsinfo = NULL;
	kis_ieee80211_packinfo *eight11 = NULL;
	kis_layer1_packinfo *radio = NULL;
	kis_datachunk *chunk = NULL;

	// Get gps info
	gpsinfo = (kis_gps_packinfo *) in_pack->fetch(_PCM(PACK_COMP_GPS));

	// Get 80211 decoded info
	eight11 = (kis_ieee80211_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211));

	// Get radio-header info
	radio = (kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	// Try to find if we have a data chunk through various means
	chunk = (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));
	if (chunk == NULL) {
		if ((chunk =
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME))) == NULL) {
			chunk = (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));
		}
	}

	// Add up the size of the packet for the data[0] component 
	uint32_t packet_len = sizeof(drone_capture_packet);
	if (gpsinfo != NULL)
		packet_len += sizeof(drone_capture_sub_gps);
	if (radio != NULL)
		packet_len += sizeof(drone_capture_sub_radio);
	if (eight11 != NULL) 
		packet_len += sizeof(drone_capture_sub_80211);
	if (chunk != NULL)
		packet_len += chunk->length;

	// Packet = size of a normal packet + dynamic packetlen
	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								(sizeof(drone_packet) + packet_len));
	// Zero it
	memset(dpkt, 0, sizeof(uint8_t) * (sizeof(drone_packet) + packet_len));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_CAPPACKET);
	dpkt->data_len = kis_hton32(packet_len);

	// Capture frame starts at the drone_packet data field
	drone_capture_packet *dcpkt = (drone_capture_packet *) dpkt->data;

	// Fill in the bitmap
	if (radio != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_RADIO);
	}

	if (gpsinfo != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_GPS);
	}

	if (eight11 != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_IEEEPACKET);
	}

	if (chunk != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_RAW_DATA);
	}

	return 1;
}

