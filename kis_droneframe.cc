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

	((KisDroneFramework *) auxptr)->SendAllText(msg, in_flags);
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
	drone_packet *dpkt =
		(drone_packet *) malloc(sizeof(uint8_t) *
								(sizeof(drone_packet) + 
								 sizeof(drone_helo_packet)));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_HELO);
	dpkt->data_len = kis_hton32(sizeof(drone_helo_packet));

	drone_helo_packet *hpkt = (drone_helo_packet *) dpkt->data;
	hpkt->version = kis_hton32(KIS_DRONE_VERSION);

	int ret = 0;
	ret = SendPacket(in_fd, dpkt);

	free(dpkt);

	return ret;
}

int KisDroneFramework::ParseData(int in_fd) {
	return 1;
}

int KisDroneFramework::KillConnection(int in_fd) {
	// Nothing to do here since we don't track per-client attributes
	return 1;
}

int KisDroneFramework::BufferDrained(int in_fd) {
	// Nothing to do here since we don't care about draining buffers since
	// we don't keep a client backlog
	return 1;
}

int KisDroneFramework::SendText(int in_cl, string in_text, int flags) {
	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								(sizeof(drone_packet) + sizeof(drone_string_packet) +
								 in_text.length()));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_STRING);
	dpkt->data_len = kis_hton32(sizeof(drone_string_packet) + in_text.length());

	drone_string_packet *spkt = (drone_string_packet *) dpkt->data;

	spkt->msg_flags = kis_hton32(flags);
	spkt->msg_len = kis_hton32(in_text.length());
	memcpy(spkt->msg, in_text.c_str(), in_text.length());

	int ret = 0;

	ret = SendPacket(in_cl, dpkt);

	free(dpkt);

	return ret;
}

int KisDroneFramework::SendAllText(string in_text, int flags) {
	vector<int> clvec;
	int nsent = 0;

	if (netserver == NULL)
		return 0;

	netserver->FetchClientVector(&clvec);

	for (unsigned int x = 0; x < clvec.size(); x++) {
		if (SendText(x, in_text, flags) > 0)
			nsent++;
	}

	return nsent;
}

int KisDroneFramework::SendPacket(int in_cl, drone_packet *in_pack) {
	int nlen = kis_ntoh32(in_pack->data_len) + sizeof(drone_packet);

	int ret = 0;

	ret = netserver->WriteData(in_cl, in_pack, nlen);

	if (ret == -2) {
		ostringstream osstr;
		osstr << "Kismet drone server client fd " << in_cl << " ring buffer "
			"full, throwing away packet";
		_MSG(osstr.str(), MSGFLAG_LOCAL);
		return 0;
	}

	return ret;
}

int KisDroneFramework::SendAllPacket(drone_packet *in_pack) {
	vector<int> clvec;
	int nsent = 0;

	if (netserver == NULL)
		return 0;

	netserver->FetchClientVector(&clvec);

	for (unsigned int x = 0; x < clvec.size(); x++) {
		if (SendPacket(x, in_pack) > 0)
			nsent++;
	}

	return nsent;
}

// Grab a frame off the chain and format it as best we can to send to the
// drone client.  We automatically handle sending or not sending GPS data
// based on its presence in the chain packet.  Same with signal level data.
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

	unsigned int suboffst = 0;

	// Fill in the bitmap
	if (radio != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_RADIO);

		drone_capture_sub_radio *rcpkt = 
			(drone_capture_sub_radio *) &(dcpkt->content[suboffst]);
		
		suboffst += sizeof(drone_capture_sub_radio);

		rcpkt->radio_hdr_len = kis_hton16(sizeof(drone_capture_sub_radio));
		// We have all the frields.  This could be reduced to an integer
		// assign but that would suck to edit in the future, and this all
		// optomizes away into a single assign anyhow during compile
		rcpkt->radio_content_bitmap |=
			(DRONEBIT(DRONE_RADIO_ACCURACY) |
			 DRONEBIT(DRONE_RADIO_CHANNEL) |
			 DRONEBIT(DRONE_RADIO_SIGNAL) |
			 DRONEBIT(DRONE_RADIO_NOISE) |
			 DRONEBIT(DRONE_RADIO_CARRIER) |
			 DRONEBIT(DRONE_RADIO_ENCODING) |
			 DRONEBIT(DRONE_RADIO_DATARATE));

		rcpkt->radio_accuracy = kis_hton16(radio->accuracy);
		rcpkt->radio_channel = kis_hton16(radio->channel);
		rcpkt->radio_signal = kis_hton16(radio->signal);
		rcpkt->radio_noise = kis_hton16(radio->noise);
		rcpkt->radio_carrier = kis_hton32((uint32_t) radio->carrier);
		rcpkt->radio_encoding = kis_hton32((uint32_t) radio->encoding);
		rcpkt->radio_datarate = kis_hton32(radio->datarate);
	}

	if (gpsinfo != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_GPS);

		drone_capture_sub_gps *gppkt = 
			(drone_capture_sub_gps *) &(dcpkt->content[suboffst]);
		
		suboffst += sizeof(drone_capture_sub_gps);

		gppkt->gps_hdr_len = kis_hton16(sizeof(drone_capture_sub_gps));

		gppkt->gps_content_bitmap |=
			(DRONEBIT(DRONE_GPS_FIX) |
			 DRONEBIT(DRONE_GPS_LAT) |
			 DRONEBIT(DRONE_GPS_LON) |
			 DRONEBIT(DRONE_GPS_ALT) |
			 DRONEBIT(DRONE_GPS_SPD) |
			 DRONEBIT(DRONE_GPS_HEADING));

		gppkt->gps_fix = kis_hton16(gpsinfo->gps_fix);
		DRONE_CONV_DOUBLE(gpsinfo->lat, &(gppkt->gps_lat));
		DRONE_CONV_DOUBLE(gpsinfo->lon, &(gppkt->gps_lon));
		DRONE_CONV_DOUBLE(gpsinfo->alt, &(gppkt->gps_alt));
		DRONE_CONV_DOUBLE(gpsinfo->spd, &(gppkt->gps_spd));
		DRONE_CONV_DOUBLE(gpsinfo->heading, &(gppkt->gps_heading));
	}

	// Finally the eight11 headers and the packet chunk itself
	if (eight11 != NULL && chunk != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_IEEEPACKET);

		drone_capture_sub_80211 *e1pkt =
			(drone_capture_sub_80211 *) &(dcpkt->content[suboffst]);

		suboffst += sizeof(drone_capture_sub_80211);

		e1pkt->eight11_hdr_len = kis_hton16(sizeof(drone_capture_sub_80211));

		e1pkt->eight11_content_bitmap |=
			(DRONEBIT(DRONE_EIGHT11_PACKLEN) |
			 DRONEBIT(DRONE_EIGHT11_ERROR) |
			 DRONEBIT(DRONE_EIGHT11_TVSEC) |
			 DRONEBIT(DRONE_EIGHT11_TVUSEC));

		e1pkt->packet_len = kis_hton16(chunk->length);
		e1pkt->error = kis_hton16(in_pack->error);
		e1pkt->tv_sec = kis_hton64(in_pack->ts.tv_sec);
		e1pkt->tv_usec = kis_hton64(in_pack->ts.tv_usec);

		// This should be big enough for the packet because we malloc'd it to
		// be, but lets be sure
		if (suboffst + chunk->length + sizeof(drone_capture_packet) >= packet_len) {
			_MSG("Drone packet tx - something went wrong in allocating a "
				 "packet to transmit the frame, bailing.", MSGFLAG_ERROR);
			free(dpkt);
			return 0;
		}

		memcpy(e1pkt->packdata, chunk->data, chunk->length);

		dcpkt->cap_packet_offset = kis_hton32(suboffst);
	}

	SendAllPacket(dpkt);

	free(dpkt);

	return 1;
}

