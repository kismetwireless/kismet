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
#include <iomanip>

#include "util.h"
#include "endian_magic.h"
#include "configfile.h"
#include "packet.h"
#include "packetsource.h"
#include "packetchain.h"
#include "kis_droneframe.h"
#include "tcpserver.h"
#include "getopt.h"
#include "gpscore.h"
#include "version.h"
#include "packetsourcetracker.h"
#include "phy_80211.h"

void KisDroneframe_MessageClient::ProcessMessage(string in_msg, int in_flags) {
	string msg;

	if ((in_flags & MSGFLAG_LOCAL) || (in_flags & MSGFLAG_ALERT))
		return;

	((KisDroneFramework *) auxptr)->SendAllText(in_msg, in_flags);
}

int kisdrone_chain_hook(CHAINCALL_PARMS) {
	return ((KisDroneFramework *) auxdata)->chain_handler(in_pack);
}

int kisdrone_time_hook(TIMEEVENT_PARMS) {
	return ((KisDroneFramework *) auxptr)->time_handler();
}

int dronecmd_channelset_hook(DRONE_CMD_PARMS) {
	return ((KisDroneFramework *) auxptr)->channel_handler(data);
}

void drone_pst_sourceact_hook(SOURCEACT_PARMS) {
	((KisDroneFramework *) auxptr)->sourceact_handler(src, action, flags);
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

	valid = 0;

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

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: KisDroneFramework called without "
				"packetsourcetracker\n");
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
							"-",
							droneframe_long_options, &option_idx);
		if (r < 0) break;

		if (r == dlc) {
			listenline = string(optarg);
		}
	}

	if (listenline.length() == 0 &&
		(listenline = globalreg->kismet_config->FetchOpt("dronelisten")) == "") {
		_MSG("No 'dronelisten' config line and no command line drone-listen "
			 "argument given, Kismet drone server will not be enabled.",
			 MSGFLAG_INFO);
		server_type = -1;
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
	if (strncasecmp(srv_proto, "tcp", 4) == 0) {
		tcpsrv = new TcpServer(globalreg);
		tcpsrv->SetupServer(port, maxcli, srv_bindhost,
							globalreg->kismet_config->FetchOpt("droneallowedhosts"));
		netserver = tcpsrv;
		server_type = 0;
	} else {
		server_type = -1;
		_MSG("Invalid protocol '" + string(srv_proto) + "' in 'dronelisten' for the "
			 "Kismet drone server", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	if (globalreg->kismet_config->FetchOpt("droneringlen") != "") {
		int rl;
		if (sscanf(globalreg->kismet_config->FetchOpt("droneringlen").c_str(),
				   "%d", &rl) != 1) {
			_MSG("Invalid value in 'droneringlen' for the Kismet dorne server",
				 MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
		_MSG("Setting drone connection buffer to " +
			 globalreg->kismet_config->FetchOpt("droneringlen") + " bytes",
			 MSGFLAG_INFO);
		tcpsrv->SetRingSize(rl);
	}

	// Create the message bus attachment to forward messages to the client
    kisdrone_msgcli = new KisDroneframe_MessageClient(globalreg, this);
    globalreg->messagebus->RegisterClient(kisdrone_msgcli, MSGFLAG_ALL);

	// Register the packet handler
	globalreg->packetchain->RegisterHandler(&kisdrone_chain_hook, this,
											CHAINPOS_POSTCAP, 100);

	// Register the source action handler
	globalreg->sourcetracker->RegisterSourceActCallback(&drone_pst_sourceact_hook,
														(void *) this);

	// Event trigger
	eventid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, 
											  &kisdrone_time_hook, (void *) this);

	// Register the internals so nothing else can, but they just get nulls
	RegisterDroneCmd(DRONE_CMDNUM_NULL, NULL, this);
	RegisterDroneCmd(DRONE_CMDNUM_HELO, NULL, this);
	RegisterDroneCmd(DRONE_CMDNUM_STRING, NULL, this);
	RegisterDroneCmd(DRONE_CMDNUM_CAPPACKET, NULL, this);
	RegisterDroneCmd(DRONE_CMDNUM_CHANNELSET, dronecmd_channelset_hook, this);
	RegisterDroneCmd(DRONE_CMDNUM_SOURCE, NULL, this);

	valid = 1;
}

KisDroneFramework::~KisDroneFramework() {
	// Unregister the source action
	globalreg->sourcetracker->RemoveSourceActCallback(&drone_pst_sourceact_hook);

	if (globalreg != NULL && globalreg->messagebus != NULL) {
		globalreg->messagebus->RemoveClient(kisdrone_msgcli);
	}

	if (eventid >= 0) {
		globalreg->timetracker->RemoveTimer(eventid);
	}
}

int KisDroneFramework::Activate() {
	ostringstream osstr;

	if (server_type == -1) {
		_MSG("Kismet drone framework disabled, drone will not be activated.",
			 MSGFLAG_INFO);
		return 0;
	}

	if (server_type != 0) {
		_MSG("KisDroneFramework unknown server type, something didn't "
			 "initialize", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (netserver->EnableServer() < 0 || globalreg->fatal_condition) {
		_MSG("Failed to enable TCP listener for Kismet drone server",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	netserver->RegisterServerFramework(this);

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
	hpkt->drone_version = kis_hton32(KIS_DRONE_VERSION);
	snprintf((char *) hpkt->kismet_version, 32, "%s-%s-%s", 
			 VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
	snprintf((char *) hpkt->host_name, 32, "%s", globalreg->servername.c_str());

	SendPacket(in_fd, dpkt);

	free(dpkt);

	// Send them all the sources
	vector<pst_packetsource *> *srcv = globalreg->sourcetracker->FetchSourceVec();
	for (unsigned int x = 0; x < srcv->size(); x++) {
		SendSource(in_fd, (*srcv)[x], 0);
		SendChannels(in_fd, (*srcv)[x]);
	}

	return 1;
}

int KisDroneFramework::RegisterDroneCmd(uint32_t in_cmdid, 
										DroneCmdCallback in_callback, void *in_aux) {
	ostringstream osstr;

	if (drone_cmd_map.find(in_cmdid) != drone_cmd_map.end()) {
		osstr << "Drone cannot register command id " << in_cmdid << " (" <<
			hex << setprecision(4) << in_cmdid << ") because it already exists";
		_MSG(osstr.str(), MSGFLAG_ERROR);
		return -1;
	}

	drone_cmd_rec *rec = new drone_cmd_rec;
	rec->auxptr = in_aux;
	rec->callback = in_callback;

	drone_cmd_map[in_cmdid] = rec;

	return 1;
}

int KisDroneFramework::RemoveDroneCmd(uint32_t in_cmdid) {
	map<unsigned int, drone_cmd_rec *>::iterator dcritr = 
		drone_cmd_map.find(in_cmdid);

	if (dcritr == drone_cmd_map.end()) {
		return 0;
	}

	delete dcritr->second;
	drone_cmd_map.erase(dcritr);

	return 1;
}

int KisDroneFramework::ParseData(int in_fd) {
	int len, rlen;
	uint8_t *buf;
	ostringstream osstr;
	int pos = 0;

	len = netserver->FetchReadLen(in_fd);

	// We don't care at all if we're less than the size of a drone frame
	if ((unsigned int) len < sizeof(drone_packet))
		return 0;
	
	buf = new uint8_t[len + 1];

	if (netserver->ReadData(in_fd, buf, len, &rlen) < 0) {
		osstr << "DroneFramework::ParseData failed to fetch data from "
			"client id " << in_fd;
		_MSG(osstr.str(), MSGFLAG_ERROR);
		delete[] buf;
		return -1;
	}

	if ((unsigned int) rlen < sizeof(drone_packet)) {
		delete[] buf;
		return 0;
	}

	while ((rlen - pos) >= (int) sizeof(drone_packet)) {
		drone_packet *dpkt = (drone_packet *) &(buf[pos]);

		if (kis_ntoh32(dpkt->sentinel) != DroneSentinel) {
			osstr << "DroneFramework::ParseData failed to find sentinel "
				"value in packet header, dropping connection to client " << in_fd;
			_MSG(osstr.str(), (MSGFLAG_ERROR | MSGFLAG_LOCAL));
			delete[] buf;
			return -1;
		}

		unsigned int dplen = kis_ntoh32(dpkt->data_len);

		// Check for an incomplete packet in the buffer
		if (rlen - (int) pos < (int) (dplen + sizeof(drone_packet))) {
			delete[] buf;
			return 0;
		}

		// Take it out of the ring buffer
		netserver->MarkRead(in_fd, (dplen + sizeof(drone_packet)));

		unsigned int dcid = kis_ntoh32(dpkt->drone_cmdnum);

		int ret = 1;

		// Do something with the command
		map<unsigned int, drone_cmd_rec *>::iterator dcritr = 
			drone_cmd_map.find(dcid);
		if (dcritr == drone_cmd_map.end()) {
			osstr << "DroneFramework::ParseData got unknown packet type " <<
				dcid << "(" << hex << setprecision(4) << dcid << ")";
			_MSG(osstr.str(), (MSGFLAG_INFO | MSGFLAG_LOCAL));
		} else {
			if (dcritr->second->callback == NULL) {
				osstr << "DroneFramework::ParseData throwing away packet of known "
					"type " << dcid << " (" << hex << setprecision(4) << dcid << ") "
					"with no handler";
				_MSG(osstr.str(), (MSGFLAG_INFO | MSGFLAG_LOCAL));
			} else {
				ret = 
					(*dcritr->second->callback)(globalreg, dpkt, 
												dcritr->second->auxptr);
			}
		}

		pos += dplen + sizeof(drone_packet);
	}

	delete[] buf;
	
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
		if (SendText(clvec[x], in_text, flags) > 0)
			nsent++;
	}

	return nsent;
}

int KisDroneFramework::SendSource(int in_cl, pst_packetsource *in_int, int invalid) {
	if (in_int->strong_source == NULL)
		return 0;

	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								(sizeof(drone_packet) + sizeof(drone_source_packet)));
	memset(dpkt, 0, sizeof(uint8_t) * (sizeof(drone_packet) + 
									   sizeof(drone_source_packet)));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_SOURCE);
	dpkt->data_len = kis_hton32(sizeof(drone_source_packet));

	drone_source_packet *spkt = (drone_source_packet *) dpkt->data;

	spkt->source_hdr_len = kis_hton16(sizeof(drone_source_packet));
	spkt->source_content_bitmap =
		kis_hton32(DRONEBIT(DRONE_SRC_UUID) |
				   DRONEBIT(DRONE_SRC_INVALID) |
				   DRONEBIT(DRONE_SRC_NAMESTR) |
				   DRONEBIT(DRONE_SRC_INTSTR) |
				   DRONEBIT(DRONE_SRC_TYPESTR) |
				   DRONEBIT(DRONE_SRC_CHANHOP) |
				   DRONEBIT(DRONE_SRC_CHANNELDWELL) |
				   DRONEBIT(DRONE_SRC_CHANNELRATE));

	DRONE_CONV_UUID(in_int->strong_source->FetchUUID(), &(spkt->uuid));

	if (invalid) {
		spkt->invalidate = kis_hton16(1);
	} else {
		spkt->invalidate = kis_hton16(0);

		// Send the older style name/interface/type and recreate a source
		// line on the other end - saves us more effort than converting it to
		// a long ncsource style line, and we don't gain anything pulling
		// the local options into the drone mirror since they don't mean
		// anything there
		snprintf((char *) spkt->name_str, 16, "%s", 
				 in_int->strong_source->FetchName().c_str());
		snprintf((char *) spkt->interface_str, 16, "%s",
				 in_int->strong_source->FetchInterface().c_str());
		snprintf((char *) spkt->type_str, 16, "%s",
				 in_int->strong_source->FetchType().c_str());

		if (in_int->channel_hop)
			spkt->channel_hop = 1;

		spkt->channel_dwell = kis_hton16(in_int->channel_dwell);
		spkt->channel_rate = kis_hton16(in_int->channel_rate);
	}

	int ret = 0;

	ret = SendPacket(in_cl, dpkt);

	free(dpkt);

	return ret;
}

int KisDroneFramework::SendAllSource(pst_packetsource *in_int, int invalid) {
	vector<int> clvec;
	int nsent = 0;

	if (netserver == NULL)
		return 0;

	netserver->FetchClientVector(&clvec);

	for (unsigned int x = 0; x < clvec.size(); x++) {
		if (SendSource(clvec[x], in_int, invalid) > 0)
			nsent++;
	}

	return nsent;
}

int KisDroneFramework::SendSourceReport(int in_cl, pst_packetsource *in_int) {
	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								(sizeof(drone_packet) + sizeof(drone_report_packet)));
	memset(dpkt, 0, sizeof(uint8_t) * (sizeof(drone_packet) + 
									   sizeof(drone_report_packet)));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_REPORT);
	dpkt->data_len = kis_hton32(sizeof(drone_report_packet));

	drone_report_packet *rpkt = (drone_report_packet *) dpkt->data;

	rpkt->report_hdr_len = kis_hton16(sizeof(drone_report_packet));
	rpkt->report_content_bitmap =
		kis_hton32(DRONEBIT(DRONE_REPORT_UUID) |
				   DRONEBIT(DRONE_REPORT_FLAGS) |
				   DRONEBIT(DRONE_REPORT_HOP_TM_SEC) |
				   DRONEBIT(DRONE_REPORT_HOP_TM_USEC));

	DRONE_CONV_UUID(in_int->strong_source->FetchUUID(), &(rpkt->uuid));

	rpkt->flags = DRONE_REPORT_FLAG_NONE;
	if (in_int->error)
		rpkt->flags |= DRONE_REPORT_FLAG_ERROR;

	rpkt->hop_tm_sec = kis_hton32(in_int->tm_hop_time.tv_sec);
	rpkt->hop_tm_usec = kis_hton32(in_int->tm_hop_time.tv_usec);

	int ret = 0;

	ret = SendPacket(in_cl, dpkt);

	free(dpkt);

	return ret;
}

int KisDroneFramework::SendAllSourceReport(pst_packetsource *in_int) {
	vector<int> clvec;
	int nsent = 0;

	if (netserver == NULL)
		return 0;

	netserver->FetchClientVector(&clvec);

	for (unsigned int x = 0; x < clvec.size(); x++) {
		if (SendSourceReport(clvec[x], in_int) > 0)
			nsent++;
	}

	return nsent;
}

int KisDroneFramework::SendChannels(int in_cl, pst_packetsource *in_int) {
	if (in_int->strong_source == NULL)
		return 0;

	pst_channellist *channels = 
		globalreg->sourcetracker->FetchSourceChannelList(in_int);

	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								(sizeof(drone_packet) + 
								 sizeof(drone_channelset_packet)));
	memset(dpkt, 0, sizeof(uint8_t) * (sizeof(drone_packet) + 
									   sizeof(drone_channelset_packet)));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_CHANNELSET);
	dpkt->data_len = kis_hton32(sizeof(drone_channelset_packet));

	drone_channelset_packet *cpkt = (drone_channelset_packet *) dpkt->data;

	cpkt->channelset_hdr_len = kis_hton16(sizeof(drone_channelset_packet));
	cpkt->channelset_content_bitmap =
		kis_hton32(DRONEBIT(DRONE_CHANNELSET_UUID) |
				   DRONEBIT(DRONE_CHANNELSET_CMD) |
				   DRONEBIT(DRONE_CHANNELSET_CURCH) |
				   DRONEBIT(DRONE_CHANNELSET_HOP) |
				   DRONEBIT(DRONE_CHANNELSET_NUMCH) |
				   DRONEBIT(DRONE_CHANNELSET_CHANNELS) |
				   DRONEBIT(DRONE_CHANNELSET_CHANNELSDWELL) |
				   DRONEBIT(DRONE_CHANNELSET_HOPRATE) |
				   DRONEBIT(DRONE_CHANNELSET_HOPDWELL));

	DRONE_CONV_UUID(in_int->strong_source->FetchUUID(), &(cpkt->uuid));

	cpkt->command = kis_ntoh16(DRONE_CHS_CMD_NONE);

	cpkt->cur_channel = kis_hton16(in_int->strong_source->FetchChannel());
	cpkt->channel_hop = kis_hton16(in_int->channel_hop);

	cpkt->num_channels = kis_hton16(channels->channel_vec.size());
	for (unsigned int x = 0; 
		 x < kismin(channels->channel_vec.size(), IPC_SOURCE_MAX_CHANS); x++) {
		if (channels->channel_vec[x].range == 0) {
			cpkt->chandata[x].u.chan_t.channel =
				kis_hton16(channels->channel_vec[x].u.chan_t.channel);
			cpkt->chandata[x].u.chan_t.dwell =
				kis_hton16(channels->channel_vec[x].u.chan_t.channel);
		} else {
			cpkt->chandata[x].u.range_t.start =
				kis_hton16(channels->channel_vec[x].u.range_t.start | (1 << 15));
			cpkt->chandata[x].u.range_t.end =
				kis_hton16(channels->channel_vec[x].u.range_t.end);
			cpkt->chandata[x].u.range_t.width =
				kis_hton16(channels->channel_vec[x].u.range_t.width);
			cpkt->chandata[x].u.range_t.iter =
				kis_hton16(channels->channel_vec[x].u.range_t.iter);
		}
	   /*
	   cpkt->channels[x] = kis_hton16(channels->channel_vec[x].channel);
	   cpkt->channels_dwell[x] = kis_hton16(channels->channel_vec[x].dwell);
	   */
	}

	cpkt->channel_rate = kis_hton16(in_int->channel_rate);
	cpkt->channel_dwell = kis_hton16(in_int->channel_dwell);

	int ret = 0;

	ret = SendPacket(in_cl, dpkt);

	free(dpkt);

	return ret;
}

int KisDroneFramework::SendAllChannels(pst_packetsource *in_int) {
	vector<int> clvec;
	int nsent = 0;

	if (netserver == NULL)
		return 0;

	netserver->FetchClientVector(&clvec);

	for (unsigned int x = 0; x < clvec.size(); x++) {
		if (SendChannels(clvec[x], in_int) > 0)
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
		_MSG(osstr.str(), (MSGFLAG_INFO | MSGFLAG_LOCAL));
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
		if (SendPacket(clvec[x], in_pack) > 0)
			nsent++;
	}

	return nsent;
}

// Send a new source to all the clients
void KisDroneFramework::sourceact_handler(pst_packetsource *src, int action,
										  int flags) {
	if (action == SOURCEACT_ADDSOURCE) {
		// Push a new source
		SendAllSource(src, 0);
	} else if (action == SOURCEACT_DELSOURCE) {
		// Push a remove action
		SendAllSource(src, 1);
	} else if (action == SOURCEACT_HOPENABLE || action == SOURCEACT_HOPDISABLE || 
			   action == SOURCEACT_CHVECTOR) {
		// Push a full channel info frame if we change hopping or channel vector
		SendAllChannels(src);
	}
}

// Grab a frame off the chain and format it as best we can to send to the
// drone client.  We automatically handle sending or not sending GPS data
// based on its presence in the chain packet.  Same with signal level data.
int KisDroneFramework::chain_handler(kis_packet *in_pack) {
	vector<int> clvec;

	if (netserver == NULL)
		return 0;

	netserver->FetchClientVector(&clvec);

	if (clvec.size() <= 0)
		return 0;

	kis_gps_packinfo *gpsinfo = NULL;
	kis_layer1_packinfo *radio = NULL;
	kis_datachunk *chunk = NULL;
	kis_ref_capsource *csrc_ref = NULL;
	kis_packet_checksum *fcs = NULL;

	// Get the capsource info
	csrc_ref = (kis_ref_capsource *) in_pack->fetch(_PCM(PACK_COMP_KISCAPSRC));

	// Get gps info
	gpsinfo = (kis_gps_packinfo *) in_pack->fetch(_PCM(PACK_COMP_GPS));

	// Get radio-header info
	radio = (kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	// Get any fcs data
	fcs = (kis_packet_checksum *) in_pack->fetch(_PCM(PACK_COMP_CHECKSUM));

	// Try to find if we have a data chunk through various means
	chunk = (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));
	if (chunk == NULL) {
		chunk = (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_DECAP));
	}
	if (chunk == NULL) {
		chunk = (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));
	}

	if (fcs == NULL) {
		fcs = new kis_packet_checksum;
		uint8_t fcsb[4] = {0xDE, 0xAD, 0xBE, 0xEF};
		fcs->set_data(fcsb, 4);
	}

	// Add up the size of the packet for the data[0] component 
	uint32_t packet_len = sizeof(drone_capture_packet);
	if (gpsinfo != NULL && gpsinfo->gps_fix >= 2) 
		packet_len += sizeof(drone_capture_sub_gps);
	if (radio != NULL)
		packet_len += sizeof(drone_capture_sub_radio);
	if (fcs != NULL)
		packet_len += 4;
	if (chunk != NULL) {
		packet_len += sizeof(drone_capture_sub_data);
		packet_len += chunk->length;
	}

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
		rcpkt->radio_content_bitmap =
			kis_hton32(DRONEBIT(DRONE_RADIO_ACCURACY) |
					   DRONEBIT(DRONE_RADIO_FREQ_MHZ) |
					   DRONEBIT(DRONE_RADIO_SIGNAL_DBM) |
					   DRONEBIT(DRONE_RADIO_NOISE_DBM) |
					   DRONEBIT(DRONE_RADIO_CARRIER) |
					   DRONEBIT(DRONE_RADIO_ENCODING) |
					   DRONEBIT(DRONE_RADIO_DATARATE) |
					   DRONEBIT(DRONE_RADIO_SIGNAL_RSSI) |
					   DRONEBIT(DRONE_RADIO_NOISE_RSSI));

		rcpkt->radio_accuracy = kis_hton16(radio->accuracy);
		rcpkt->radio_freq_mhz = kis_hton16(radio->freq_mhz);
		rcpkt->radio_signal_dbm = kis_hton16((int16_t) radio->signal_dbm);
		rcpkt->radio_noise_dbm = kis_hton16((int16_t) radio->noise_dbm);
		rcpkt->radio_carrier = kis_hton32((uint32_t) radio->carrier);
		rcpkt->radio_encoding = kis_hton32((uint32_t) radio->encoding);
		rcpkt->radio_datarate = kis_hton32(radio->datarate);
		rcpkt->radio_signal_rssi = kis_hton16((int16_t) radio->signal_rssi);
		rcpkt->radio_noise_rssi = kis_hton16((int16_t) radio->noise_rssi);
	}

	if (gpsinfo != NULL && gpsinfo->gps_fix >= 2) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_GPS);

		drone_capture_sub_gps *gppkt = 
			(drone_capture_sub_gps *) &(dcpkt->content[suboffst]);
		
		suboffst += sizeof(drone_capture_sub_gps);

		gppkt->gps_hdr_len = kis_hton16(sizeof(drone_capture_sub_gps));

		gppkt->gps_content_bitmap =
			kis_hton32(DRONEBIT(DRONE_GPS_FIX) |
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

	if (fcs != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_FCS);

		memcpy(&(dcpkt->content[suboffst]), fcs->data, 4);
		
		suboffst += 4;
	}

	// Other packet types go here

	// Finally the eight11 headers and the packet chunk itself
	if (chunk != NULL && in_pack->error == 0 && csrc_ref != NULL) {
		dcpkt->cap_content_bitmap |= DRONEBIT(DRONE_CONTENT_IEEEPACKET);

		drone_capture_sub_data *e1pkt =
			(drone_capture_sub_data *) &(dcpkt->content[suboffst]);

		// Set the offset to be the head of the eight11 frame since we
		// skip to the end of the content set
		dcpkt->cap_packet_offset = kis_hton32(suboffst);

		suboffst += sizeof(drone_capture_sub_data);

		e1pkt->data_hdr_len = kis_hton16(sizeof(drone_capture_sub_data));

		e1pkt->data_content_bitmap =
			kis_hton32(DRONEBIT(DRONE_DATA_PACKLEN) |
					   DRONEBIT(DRONE_DATA_UUID) |
					   DRONEBIT(DRONE_DATA_TVSEC) |
					   DRONEBIT(DRONE_DATA_TVUSEC) |
					   DRONEBIT(DRONE_DATA_DLT));

		DRONE_CONV_UUID(csrc_ref->ref_source->FetchUUID(), &(e1pkt->uuid));
		e1pkt->packet_len = kis_hton16(chunk->length);
		e1pkt->tv_sec = kis_hton64(in_pack->ts.tv_sec);
		e1pkt->tv_usec = kis_hton64(in_pack->ts.tv_usec);
		e1pkt->dlt = kis_hton32(chunk->dlt);

		memcpy(e1pkt->packdata, chunk->data, chunk->length);
	}

	dcpkt->cap_content_bitmap = kis_hton32(dcpkt->cap_content_bitmap);
	SendAllPacket(dpkt);

	free(dpkt);

	return 1;
}

int KisDroneFramework::time_handler() {
	// Send everyone a NULL frame as a keepalove
	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								sizeof(drone_packet));

	memset(dpkt, 0, sizeof(uint8_t) * sizeof(drone_packet));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_NULL);
	dpkt->data_len = kis_hton32(0);

	SendAllPacket(dpkt);

	return 1;
}

int KisDroneFramework::channel_handler(const drone_packet *in_pack) {
	ostringstream osstr;
	uint32_t len = kis_ntoh32(in_pack->data_len);
	if (len < sizeof(drone_channelset_packet))
		return -1;

	drone_channelset_packet *csp = (drone_channelset_packet *) in_pack->data;

	uint32_t cbm = kis_ntoh32(csp->channelset_content_bitmap);

	// We can't handle it if it doesn't have at least this much set
	if ((cbm & DRONEBIT(DRONE_CHANNELSET_UUID)) == 0 ||
		(cbm & DRONEBIT(DRONE_CHANNELSET_CMD)) == 0) {
		return 0;
	}

	uuid intuuid;
	UUID_CONV_DRONE(&(csp->uuid), intuuid);

	int cmd;
	cmd = kis_ntoh16(csp->command);

	if (cmd == DRONE_CHS_CMD_SETVEC &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_NUMCH)) &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_CHANNELS)) &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_CHANNELSDWELL))) {

		ostringstream chstr;
		uint16_t nch = kis_ntoh16(csp->num_channels);

		// Make a new channel list based on the UUID
		chstr << intuuid.UUID2String() << ":";

		for (unsigned int x = 0; x < nch; x++) {
			/*
			uint16_t ch = kis_ntoh16(csp->channels[x]);
			uint16_t dw = kis_ntoh16(csp->channels_dwell[x]);
			chstr << ch << ":" << dw << ",";
			*/

			if (kis_ntoh16(csp->chandata[x].u.chan_t.channel) >> 15) {
				chstr << "range-" <<
					(kis_ntoh16(csp->chandata[x].u.range_t.start) & ~(1 << 15)) <<
					"-" <<
					kis_ntoh16(csp->chandata[x].u.range_t.end) << "-" <<
					kis_ntoh16(csp->chandata[x].u.range_t.width) << "-" <<
					kis_ntoh16(csp->chandata[x].u.range_t.iter);
			} else {
				chstr << kis_ntoh16(csp->chandata[x].u.chan_t.channel) << ":" <<
					kis_ntoh16(csp->chandata[x].u.chan_t.dwell);
			}

			if (x != (unsigned int) nch - 1)
				chstr << ",";
		}

		_MSG("Setting source " + intuuid.UUID2String() + " channel vector to " +
			 chstr.str(), MSGFLAG_INFO);

		return globalreg->sourcetracker->SetSourceNewChannellist(intuuid, chstr.str());
	}

	if ((cmd == DRONE_CHS_CMD_SETHOP || cmd == DRONE_CHS_CMD_SETCUR) &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_HOP)) &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_CURCH))) {
		int hopping = kis_ntoh16(csp->channel_hop);

		uint16_t curch = kis_ntoh16(csp->cur_channel);

		osstr << (hopping ? string("Enabling") : string("Disabling")) << " ";
		osstr << "channel hopping on " << intuuid.UUID2String();
		if (hopping)
			osstr << " and locking to channel " << curch;

		_MSG(osstr.str(), MSGFLAG_INFO);

		return globalreg->sourcetracker->SetSourceHopping(intuuid, hopping, curch);
	}

	if (cmd == DRONE_CHS_CMD_SETHOPDWELL &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_HOPRATE)) &&
		(cbm & DRONEBIT(DRONE_CHANNELSET_HOPDWELL))) {
		uint16_t hoprate = kis_ntoh16(csp->channel_rate);
		uint16_t hopdwell = kis_ntoh16(csp->channel_dwell);

		if (hoprate != 0)
			osstr << "Setting hop rate to " << hoprate << " channels per second on "
				"source " << intuuid.UUID2String();
		else
			osstr << "Setting channel dwell to " << hopdwell << " seconds per "
				"channel on source " << intuuid.UUID2String();

		_MSG(osstr.str(), MSGFLAG_INFO);

		return globalreg->sourcetracker->SetSourceHopDwell(intuuid, hoprate, hopdwell);
	}

	return 0;
}

