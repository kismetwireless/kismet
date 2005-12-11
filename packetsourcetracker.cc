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
#include "packetsourcetracker.h"
#include "packetsource.h"
#include "configfile.h"
#include "getopt.h"

#ifdef SYS_LINUX
// Bring in the ifcontrol stuff for 'auto'
#include "ifcontrol.h"
#endif

char *CARD_fields_text[] = {
    "interface", "type", "username", "channel", "uuid", "packets", "hopping",
    NULL
};

int Protocol_CARD(PROTO_PARMS) {
	KisPacketSource *csrc = (KisPacketSource *) data;
	ostringstream osstr;

	// Allocate the cache
	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		if (fnum >= CARD_maxfield) {
			out_string = "Unknown field requested";
			return -1;
		}

		osstr.str("");

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch (fnum) {
			case CARD_interface:
				cache->Cache(fnum, csrc->FetchInterface());
				break;
			case CARD_type:
				cache->Cache(fnum, csrc->FetchType());
				break;
			case CARD_username:
				cache->Cache(fnum, "\001" + MungeToPrintable(csrc->FetchName()) + 
							 "\001");
				break;
			case CARD_channel:
				osstr << csrc->FetchChannel();
				cache->Cache(fnum, osstr.str());
				break;
			case CARD_uuid:
				cache->Cache(fnum, csrc->FetchUUID().UUID2String());
				break;
			case CARD_packets:
				osstr << csrc->FetchNumPackets();
				cache->Cache(fnum, osstr.str());
				break;
			case CARD_hopping:
				if (csrc->FetchChannelHop())
					cache->Cache(fnum, "1");
				else
					cache->Cache(fnum, "0");
				break;
		}

		out_string += cache->GetCache(fnum) + " ";
	}

    return 1;
}

// Enable hook to blit known cards
void Protocol_CARD_enable(PROTO_ENABLE_PARMS) {
	Packetsourcetracker *pstrak = (Packetsourcetracker *) data;

	pstrak->BlitCards(in_fd);

	return;
}

int Clicmd_CHANLOCK_hook(CLIENT_PARMS) {
	return 
		((Packetsourcetracker *) auxptr)->cmd_chanlock(in_clid, framework,
													   globalreg, errstr, cmdline,
													   parsedcmdline, auxptr);
}

int Clicmd_CHANHOP_hook(CLIENT_PARMS) {
	return 
		((Packetsourcetracker *) auxptr)->cmd_chanhop(in_clid, framework,
													  globalreg, errstr, cmdline,
													  parsedcmdline, auxptr);
}

int Clicmd_PAUSE_hook(CLIENT_PARMS) {
	return 
		((Packetsourcetracker *) auxptr)->cmd_pause(in_clid, framework,
													globalreg, errstr, cmdline,
													parsedcmdline, auxptr);
}

int Clicmd_RESUME_hook(CLIENT_PARMS) {
	return 
		((Packetsourcetracker *) auxptr)->cmd_resume(in_clid, framework,
													 globalreg, errstr, cmdline,
													 parsedcmdline, auxptr);
}

int Packetsourcetracker::cmd_chanlock(CLIENT_PARMS) {
    if (parsedcmdline->size() != 2) {
        snprintf(errstr, 1024, "Illegal chanlock request");
        return -1;
    }

	uuid srcuuid = uuid((*parsedcmdline)[0].word);
	if (srcuuid.error) {
		snprintf(errstr, 1024, "Illegal chanlock request, invalid UUID");
		return -1;
	}

    int chnum;
    if (sscanf(((*parsedcmdline)[1]).word.c_str(), "%d", &chnum) != 1) {
        snprintf(errstr, 1024, "Illegal chanlock request");
        return -1;
    }

	KisPacketSource *src = FindUUID(srcuuid);

	if (src == NULL) {
		snprintf(errstr, 1024, "Illegal chanlock request, unknown uuid");
		return -1;
	}

	// Try to set the channel
	if (SetChannel(chnum, src) < 0) {
		snprintf(errstr, 1024, "Illegal chanlock request, source could not "
				 "set channel %d", chnum);
		return -1;
	}

	// Lock it to not hop on this source
	src->SetChannelHop(0);

    snprintf(errstr, 1024, "Locking source '%s' to channel %d", 
			 src->FetchName().c_str(), chnum);
    _MSG(errstr, MSGFLAG_INFO);
    
    return 1;
}

int Packetsourcetracker::cmd_chanhop(CLIENT_PARMS) {
    if (parsedcmdline->size() != 1) {
        snprintf(errstr, 1024, "Illegal chanhop request");
        return -1;
    }

	uuid srcuuid = (*parsedcmdline)[0].word;
	if (srcuuid.error) {
		snprintf(errstr, 1024, "Illegal chanhop request, invalid UUID");
		return -1;
	}

	KisPacketSource *src = FindUUID(srcuuid);

	if (src == NULL) {
		snprintf(errstr, 1024, "Illegal chanhop request, unknown uuid");
		return -1;
	}

	// Lock it to not hop on this source
	if (src->SetChannelHop(1) < 0) {
		snprintf(errstr, 1024, "Illegal chanhop request, source cannot "
				 "perform channel hopping");
		return -1;
	}

	snprintf(errstr, 1024, "Enabling channel hopping on source '%s'",
			 src->FetchName().c_str());
    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    
    return 1;
}

int Packetsourcetracker::cmd_pause(CLIENT_PARMS) {
    if (parsedcmdline->size() == 1) {
		uuid srcuuid = (*parsedcmdline)[0].word;
		if (srcuuid.error) {
			snprintf(errstr, 1024, "Illegal pause request, invalid UUID");
			return -1;
		}

		KisPacketSource *src = FindUUID(srcuuid);

		if (src == NULL) {
			snprintf(errstr, 1024, "Illegal pause request, unknown uuid");
			return -1;
		}

		// Try to pause it
		src->Pause();

		snprintf(errstr, 1024, "Pausing source '%s'", src->FetchName().c_str());
		_MSG(errstr, MSGFLAG_INFO);
    
		return 1;
	} else if (parsedcmdline->size() == 0) {
		for (unsigned int x = 0; x < live_packsources.size(); x++) {
			live_packsources[x]->Pause();
		}

		snprintf(errstr, 1024, "Pausing all packet sources");
		_MSG(errstr, MSGFLAG_INFO);
		return 1;
	}

	snprintf(errstr, 1024, "Illegal pause request");
	return -1;
}

int Packetsourcetracker::cmd_resume(CLIENT_PARMS) {
    if (parsedcmdline->size() == 1) {
		uuid srcuuid = (*parsedcmdline)[0].word;
		if (srcuuid.error) {
			snprintf(errstr, 1024, "Illegal resume request, invalid UUID");
			return -1;
		}

		KisPacketSource *src = FindUUID(srcuuid);

		if (src == NULL) {
			snprintf(errstr, 1024, "Illegal resume request, unknown uuid");
			return -1;
		}

		// Try to resume it
		src->Resume();

		snprintf(errstr, 1024, "Resuming source '%s'", src->FetchName().c_str());
		_MSG(errstr, MSGFLAG_INFO);
    
		return 1;
	} else if (parsedcmdline->size() == 0) {
		for (unsigned int x = 0; x < live_packsources.size(); x++) {
			live_packsources[x]->Resume();
		}

		snprintf(errstr, 1024, "Resuming all packet sources");
		_MSG(errstr, MSGFLAG_INFO);
		return 1;
	}

	snprintf(errstr, 1024, "Illegal resume request");
	return -1;
}

int Event_CARD(TIMEEVENT_PARMS) {
	// Just send everything
	globalreg->sourcetracker->BlitCards(-1);

	return 1;
}

// Handle channel hopping... this is actually really simple.
int ChannelHopEvent(TIMEEVENT_PARMS) {
    // Just call advancechannel
    globalreg->sourcetracker->AdvanceChannel();
    
    return 1;
}

int packsrc_chan_ipc(IPC_CMD_PARMS) {
	// Parents don't do anything with channel set commands
	if (parent)
		return 0;

	if (len < (int) sizeof(Packetsourcetracker::chanchild_changepacket))
		return 0;

	Packetsourcetracker::chanchild_changepacket *chpak =
		(Packetsourcetracker::chanchild_changepacket *) data;

	// Kick our IPC-child copy of the channel set command
	((Packetsourcetracker *) auxptr)->SetIPCChannel(chpak->channel,
													chpak->meta_num);

	return 1;
}

int packsrc_haltall_ipc(IPC_CMD_PARMS) {
	if (parent)
		return 0;

	// Kick the IPC copy to shutdown this metanum
	((Packetsourcetracker *) auxptr)->ShutdownIPCSources();

	return 1;
}

void Packetsourcetracker::Usage(char *name) {
	printf(" *** Packet Capture Source Options ***\n");
	printf(" -I, --initial-channel        Initial channel for a capture source\n"
		   "                              (name,channel)\n"
		   " -X, --channel-hop            Enabled/Disable channel hopping\n"
		   " -c, --capture-source         Provide a capture source on the command\n"
		   "                              line that is not present in the config\n"
		   "                              file (type,interface,name[,channel])\n"
		   " -C, --enable-capture-sources Enable named capture sources from the\n"
		   "                              config file (comma-separated list)\n");
}

Packetsourcetracker::Packetsourcetracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  Packetsourcetracker called before "
				"packetchain\n");
		exit(1);
	}

	if (globalreg->kisnetserver == NULL) {
		fprintf(stderr, "FATAL OOPS:  Packetsourcetracker called before "
				"kisnetframework\n");
		exit(1);
	} 

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Packetsourcetracker called before "
				"kismet_config\n");
		exit(1);
	}

	if (globalreg->rootipc == NULL) {
		fprintf(stderr, "FATAL OOPS:  Packetsourcetracker called before rootipc\n");
		exit(1);
	}

	// Register the CARD protocol
	card_protoref =
		globalreg->kisnetserver->RegisterProtocol("CARD", 0, 1,
												  CARD_fields_text,
												  &Protocol_CARD,
												  &Protocol_CARD_enable,
												  this);
	// Register the card commands
	cmdid_chanlock =
		globalreg->kisnetserver->RegisterClientCommand("CHANLOCK", 
													   &Clicmd_CHANLOCK_hook, NULL);
	cmdid_chanhop =
		globalreg->kisnetserver->RegisterClientCommand("CHANHOP", 
													   &Clicmd_CHANHOP_hook, NULL);
	cmdid_pause =
		globalreg->kisnetserver->RegisterClientCommand("PAUSE", 
													   &Clicmd_PAUSE_hook, NULL);
	cmdid_resume =
		globalreg->kisnetserver->RegisterClientCommand("RESUME", 
													   &Clicmd_RESUME_hook, NULL);

	// Register our packet components 
	// back-refer to the capsource so we can get names and parameters
	_PCM(PACK_COMP_KISCAPSRC) =
		globalreg->packetchain->RegisterPacketComponent("KISCAPSRC");
	// Basic packet chunks everyone needs
	_PCM(PACK_COMP_RADIODATA) =
		globalreg->packetchain->RegisterPacketComponent("RADIODATA");
	_PCM(PACK_COMP_LINKFRAME) =
		globalreg->packetchain->RegisterPacketComponent("LINKFRAME");
	_PCM(PACK_COMP_80211FRAME) =
		globalreg->packetchain->RegisterPacketComponent("80211FRAME");

	// Add our null source
	AddKisPacketsource(new NullPacketSource(globalreg));

	// Register the packetsourcetracker as a pollable subsystem
	globalreg->RegisterPollableSubsys(this);

	// Assign the IPC commands and make it pollable
	chan_ipc_id = globalreg->rootipc->RegisterIPCCmd(&packsrc_chan_ipc, this);
	haltall_ipc_id = globalreg->rootipc->RegisterIPCCmd(&packsrc_haltall_ipc, this);
}

Packetsourcetracker::~Packetsourcetracker() {
	globalreg->RemovePollableSubsys(this);

    for (map<string, packsource_protorec *>::iterator x = cardtype_map.begin();
         x != cardtype_map.end(); ++x)
        delete x->second;
}

// Add a packet source type (just call the registersources with ourself)
int Packetsourcetracker::AddKisPacketsource(KisPacketSource *in_source) {
	return in_source->RegisterSources(this);
}

// Add a live packet source into our internal tracking system
int Packetsourcetracker::RegisterLiveKisPacketsource(KisPacketSource *in_livesource) {
	// Add it to the strong sources vector and the UUID vector (we wait until
	// now to give sources a chance to fill in their UUID at monitor time with
	// a real node ID derived from the MAC.
	live_packsources.push_back(in_livesource);
	ps_map[in_livesource->FetchUUID()] = in_livesource;

	// Send a notify to all the registered callbacks
	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		(*(cb_vec[x]->cb))(globalreg, in_livesource, 1, cb_vec[x]->auxdata);
	}

	return 1;
}

int Packetsourcetracker::RemoveLiveKisPacketsource(KisPacketSource *in_livesource) {
	// If it isn't in the ps_map we don't have it.
	map<uuid, KisPacketSource *>::iterator psmi;
	psmi = ps_map.find(in_livesource->FetchUUID());
	if (psmi == ps_map.end()) {
		return 0;
	}

	// Send a notify to all the registered callbacks
	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		(*(cb_vec[x]->cb))(globalreg, in_livesource, 0, cb_vec[x]->auxdata);
	}

	// Remove it from the packetsource map
	ps_map.erase(psmi);

	// Remove it from the live sources vector
	for (unsigned int x = 0; x < live_packsources.size(); x++) {
		if (live_packsources[x] == in_livesource) {
			live_packsources.erase(live_packsources.begin() + x);
			break;
		}
	}

	return 1;
}

int Packetsourcetracker::RegisterLiveSourceCallback(LiveSourceCallback in_cb,
													void *in_aux) {
	// Make a cb rec
	addsourcecb_rec *cbr = new addsourcecb_rec;
	cbr->cb = in_cb;
	cbr->auxdata = in_aux;

	cb_vec.push_back(cbr);

	return 1;
}

int Packetsourcetracker::RemoveLiveSourceCallback(LiveSourceCallback in_cb) {
	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		if (cb_vec[x]->cb != in_cb)
			continue;

		delete cb_vec[x];
		cb_vec.erase(cb_vec.begin() + x);
		return 1;
	}

	return 0;
}

// Process the cards from kismet.conf and the command line
int Packetsourcetracker::LoadConfiguredCards() {
	// Commandline stuff
	string named_sources;
	vector<string> src_input_vec;
	vector<string> src_init_vec;
	int option_idx = 0;
	int from_cmdline = 0;

    // Default channels
    vector<string> defaultchannel_vec;
    // Custom channel lists for sources
    vector<string> src_customchannel_vec;

	// Zero state stuff
	channel_hop = -1;
	channel_split = -1;
	channel_dwell = -1;
	channel_velocity = -1;

	// longopts for the packetsourcetracker component
	static struct option packetsource_long_options[] = {
		{ "initial-channel", required_argument, 0, 'I' },
		{ "channel-hop", required_argument, 0, 'X' },
		{ "capture-source", required_argument, 0, 'c' },
		{ "enable-capture-sources", required_argument, 0, 'C' },
		{ 0, 0, 0, 0 }
	};

	// Hack the extern getopt index
	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv,
							"-I:X:c:C:", 
							packetsource_long_options, &option_idx);
		if (r < 0) break;
		switch (r) {
			case 'I':
				src_init_vec.push_back(string(optarg));
				break;
			case 'X':
				if (strcmp(optarg, "yes") == 0 ||
					strcmp(optarg, "true") == 0 ||
					strcmp(optarg, "1") == 0) {
					_MSG("Explicitly enabling channel hopping on all supported "
						 "sources", MSGFLAG_INFO);
					channel_hop = 1;
				} else {
					_MSG("Explicity disabling channel hopping on all sources",
						 MSGFLAG_INFO);
					channel_hop = 0;
				}
				break;
			case 'c':
				src_input_vec.push_back(string(optarg));
				from_cmdline = 1;
				break;
			case 'C':
				named_sources = string(optarg);
				break;
		}
	}
	
	// Read all of our packet sources, tokenize the input and then start opening
	// them.

	if (named_sources.length() == 0 && from_cmdline == 0) {
		_MSG("No specific sources named, all sources defined in kismet.conf will "
			 "be enabled.", MSGFLAG_INFO);
		named_sources = 
			globalreg->kismet_config->FetchOpt("enablesources");
	}

	// Read the config file if we didn't get any sources on the command line
	if (src_input_vec.size() == 0)
		src_input_vec = globalreg->kismet_config->FetchOptVec("source");

	// Now look at our channel options
	if (channel_hop == -1) {
		if (globalreg->kismet_config->FetchOpt("channelhop") == "true") {
			_MSG("Channel hopping enabled in config file", MSGFLAG_INFO);
			channel_hop = 1;
		} else {
			_MSG("Channel hopping disabled in config file", MSGFLAG_INFO);
			channel_hop = 0;
		}
	}

	if (channel_hop == 1) {
		if (globalreg->kismet_config->FetchOpt("channelsplit") == "true") {
			_MSG("Channel splitting enabled in config file", MSGFLAG_INFO);
			channel_split = 1;
		} else {
			_MSG("Channel splitting disabled in config file", MSGFLAG_INFO);
			channel_split = 0;
		}

		if (globalreg->kismet_config->FetchOpt("channelvelocity") != "") {
			if (sscanf(globalreg->kismet_config->FetchOpt("channelvelocity").c_str(),
					   "%d", &channel_velocity) != 1) {
				snprintf(errstr, STATUS_MAX, "Illegal config file value '%s' for "
						 "channelvelocity, must be an integer",
						 globalreg->kismet_config->FetchOpt("channelvelocity").c_str());
				_MSG(errstr, MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}

			if (channel_velocity < 1 || channel_velocity > 10) {
				_MSG("Illegal value for channelvelocity, must be "
					 "between 1 and 10", MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}
		}

		if (globalreg->kismet_config->FetchOpt("channeldwell") != "") {
			if (sscanf(globalreg->kismet_config->FetchOpt("channeldwell").c_str(), 
					   "%d", &channel_dwell) != 1) {
				snprintf(errstr, STATUS_MAX, "Illegal config file value '%s' for "
						 "channeldwell, must be an integer",
						 globalreg->kismet_config->FetchOpt("channeldwell").c_str());
				_MSG(errstr, MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}

			if (channel_dwell < 1) {
				_MSG("Illegal value for channeldwell, must be between 1 and 10",
					 MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}
		}

		// Fetch the vector of default channels
		defaultchannel_vec = globalreg->kismet_config->FetchOptVec("defaultchannels");
		if (defaultchannel_vec.size() == 0) {
			_MSG("Could not find any defaultchannels config lines "
				 "and channel hopping was requested.  Something is "
				 "broken in the config file.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		// Fetch custom channels for individual sources
		src_customchannel_vec = 
			globalreg->kismet_config->FetchOptVec("sourcechannels");
	}

	// Register our default channels
	if (RegisterDefaultChannels(&defaultchannel_vec) < 0) {
		return -1;
	}

	// Turn all our config data into meta packsources, or fail...  If we're
	// passing the sources from the command line, we enable them all, so we
	// null the named_sources string
	int old_chhop = channel_hop;
	// Zero the enable line if we used the command line to get a source
	// definition.
	if (from_cmdline)
		named_sources = "";

	if (ProcessCardList(named_sources, &src_input_vec, 
						&src_customchannel_vec, &src_init_vec,
						channel_hop, channel_split) < 0) {
		return -1;
	}

	// This would only change if we're channel hopping and processcardlist had
	// to turn it off because nothing supports it, so print a notice...
	if (old_chhop != channel_hop)
		globalreg->messagebus->InjectMessage("Disabling channel hopping, no enabled "
											 "sources are able to set channels.",
											 MSGFLAG_INFO);

	if (channel_hop) {
		if (channel_dwell < 1)
			hop_eventid = 
				globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC / 
													  channel_velocity, 
													  NULL, 1, &ChannelHopEvent, 
													  NULL);
		else
			hop_eventid = 
				globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 
													  channel_dwell, NULL, 1, 
													  &ChannelHopEvent, NULL);
	}

	card_eventid =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC,
											  NULL, 1, &Event_CARD, NULL);

	return 1;
}

unsigned int Packetsourcetracker::MergeSet(unsigned int in_max_fd, fd_set *out_rset, 
										   fd_set *out_wset) {
	// Don't probe during spindown
	if (globalreg->spindown)
		return in_max_fd;

    unsigned int max = in_max_fd;

    for (unsigned int livc = 0; livc < live_packsources.size(); livc++) {
        KisPacketSource *psrc = live_packsources[livc];
		int capd = psrc->FetchDescriptor();

		if (capd < 0)
			continue;

        FD_SET(capd, out_rset);
        if (capd > (int) max)
            max = capd;
    }

    return max;
}

// Read from the socket and return text if we have any
int Packetsourcetracker::Poll(fd_set& in_rset, fd_set& in_wset) {
	if (globalreg->spindown)
		return 0;

	// Sweep the packet sources
	for (unsigned int x = 0; x < live_packsources.size(); x++) {
		int desc = 
			live_packsources[x]->FetchDescriptor();

		if (desc >= 0 && FD_ISSET(desc, &in_rset)) {
			live_packsources[x]->Poll();
		}
	}

    return 1;
}

KisPacketSource *Packetsourcetracker::FindUUID(uuid in_id) {
	// Try to find the source
	map<uuid, KisPacketSource *>::iterator psmi = ps_map.find(in_id);
	if (psmi == ps_map.end()) {
		return NULL;
	}

	return psmi->second;
}

// Explicitly set a channel.  Caller is responsible for turning off hopping
// on this source if they want it to really stay on this channel
int Packetsourcetracker::SetChannel(int in_ch, KisPacketSource *src) {
#ifndef HAVE_SUID
    int ret = src->SetChannel(in_ch);

    if (ret < 0)
        return ret;
#else
	// Don't use IPC to set "local control" sources (why use IPC to set snmp?)

	// This looks like it's inefficient, but there aren't going to be hundreds
	// of packet sources, and an iteration through a 1-10 element array (avg)
	// isn't going to be measurably more expensive than a tree search.  Plus
	// it gets us the offset index we need.
	unsigned int live_offt = 0;
	int match = 0;
	for (live_offt = 0; live_offt < live_packsources.size(); live_offt++) {
		if (live_packsources[live_offt] == src) {
			match = 1;
			break; 
		}
	}

	if (match == 0) {
		_MSG("Packetsourcetracker unable to find reference to source pointer in "
			 "live source vec for SetChannel.  Perhaps called with a dynamic "
			 "source not added?", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (src->ChildIPCControl() == 0) {
		int ret;
		ret = src->SetChannel(in_ch);

		return ret;
	}
	
	ipc_packet *pack =
		(ipc_packet *) malloc(sizeof(ipc_packet) + 
							  sizeof(chanchild_changepacket));
	chanchild_changepacket *chpak = (chanchild_changepacket *) pack->data;

	chpak->meta_num = live_offt;
	chpak->channel = in_ch;

	pack->data_len = sizeof(chanchild_changepacket);
	pack->ipc_cmdnum = chan_ipc_id;

	globalreg->rootipc->SendIPC(pack);
#endif

    return 1;
}

int Packetsourcetracker::SetIPCChannel(int in_ch, unsigned int meta_num) {
	// This usually happens inside the IPC fork, so remember not to screw with
	// things that aren't set yet!  Meta is safe, other stuff isn't.  Globalreg
	// got remapped by the IPC system to funnel back over IPC
	if (meta_num >= live_packsources.size()) {
		_MSG("Packetsourcetracker SetIPCChannel got illegal packet source "
			 "card number to set", MSGFLAG_ERROR);
		return 0;
	}

	KisPacketSource *src = live_packsources[meta_num];

	int ret = src->SetChannel(in_ch);

	if (ret < 0) {
		// Redundant but can't hurt
		globalreg->rootipc->ShutdownIPC(NULL);
	}

	return -1;
}

int Packetsourcetracker::SetHopping(int in_hopping, uuid in_uuid) {
	KisPacketSource *src = FindUUID(in_uuid);

	if (src == NULL) {
		_MSG("Could not set hopping for source UUID " + in_uuid.UUID2String() + 
			 ", unable to find source", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return src->SetChannelHop(in_hopping);
}

// Hop the packet sources up a channel
int Packetsourcetracker::AdvanceChannel() {
	// Don't hop if it's queued up/un-ack'd
	if (globalreg->rootipc->FetchReadyState() == 0)
		return 0;

	for (unsigned int livec = 0; livec < live_packsources.size(); livec++) {
		KisPacketSource *liv = live_packsources[livec];

		if (liv->FetchChannelCapable() == 0) {
			continue;
		}

		if (liv->FetchChannelHop() == 0 || liv->FetchLocalChannelHop() == 0) {
			continue;
		}

		// Get the next channel from the source
		int nextchan = liv->FetchNextChannel();

		if (nextchan <= 0)
			continue;

		// Call the IPC dispatcher
		int ret = SetChannel(nextchan, liv);

		// Blow up if something died
		if (ret < 0)
			return ret;
	}

    return 1;
}

// Map a cardtype string to the registrant function.  Should be called from main() or 
// wherever packet sources get loaded from.  (Plugin hook)
int Packetsourcetracker::RegisterPacketsource(const char *in_cardtype, 
											  KisPacketSource *in_weaksource,
											  int in_root, 
											  const char *in_defaultchanset, 
                                              int in_initch) {
    // Do we have it?  Can't register a type that's already registered.
    if (cardtype_map.find(in_cardtype) != cardtype_map.end())
        return -1;

    // Register it.
    packsource_protorec *rec = new packsource_protorec;

	rec->type = in_cardtype;
    rec->root_required = in_root;
    rec->default_channelset = in_defaultchanset;
    rec->initial_channel = in_initch;
	rec->weak_source = in_weaksource;

    cardtype_map[StrLower(in_cardtype)] = rec;

	return 1;
}

int Packetsourcetracker::RemovePacketsource(const char *in_cardtype) {
	map<string, packsource_protorec *>::iterator itr =
		cardtype_map.find(in_cardtype);

    if (itr == cardtype_map.end())
        return -1;

	delete itr->second;
	cardtype_map.erase(itr);

	return 1;
}

int Packetsourcetracker::RegisterDefaultChannels(vector<string> *in_defchannels) {
    vector<string> tokens;

    for (unsigned int sc = 0; sc < in_defchannels->size(); sc++) {
        tokens.clear();
        tokens = StrTokenize((*in_defchannels)[sc], ":");

        if (tokens.size() < 2) {
            snprintf(errstr, 1024, "Illegal default channel line '%s'", 
                     (*in_defchannels)[sc].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        vector<int> channel_bits = Str2IntVec(tokens[1]);

        if (channel_bits.size() == 0) {
            snprintf(errstr, 1024, "Illegal channel list '%s' in default channel "
                     "line '%s'", tokens[1].c_str(), (*in_defchannels)[sc].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        if (defaultch_map.find(StrLower(tokens[0])) != defaultch_map.end()) {
            snprintf(errstr, 1024, "Already have defaults for type '%s'",
                     tokens[0].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        defaultch_map[StrLower(tokens[0])] = channel_bits;

    }
    // Default channels for non-hopping types
    vector<int> no_channel;
    no_channel.push_back(0);
    defaultch_map["na"] = no_channel;
    return 1;
}

vector<KisPacketSource *> Packetsourcetracker::FetchSourceVec() {
	return live_packsources;
}

// Big scary function to build the contents of prebuild_protosources, which
// will then be used by bindsources to build the real, strong-packsource
// instances.
//
// enableline: vector of source names to be enabled
// cardlines: vector of config lines defining actual capture sources,
// sourcechannels: vector of config lines defining explicit channel sequences for a 
// source
// initchannels: vector of initial channel settings
// chhop: Is hopping enabled?
// chsplit: Are channel allocations split across multiple interfaces?
int Packetsourcetracker::ProcessCardList(string in_enableline, 
                                         vector<string> *in_cardlines, 
                                         vector<string> *in_sourcechannels, 
                                         vector<string> *in_initchannels,
                                         int& in_chhop, int in_chsplit) {
    // reuseable token vector
    vector<string> tokens;
    // capsource names to be enabled
    map<string, int> enable_map;
    // We enable all packet sources if none were explicitly listed
    int all_enable = 0;
    // Capsource names mapped to initial channel
    map<string, int> initch_map;
    // Lots of maps to track the channel divisions
    // capname to sequence id
    map<string, int> chan_cap_seqid_map;
    // sequence id to channel sequence
    map<int, vector<int> > chan_seqid_seq_map;
    // Sequence counts, if we're splitting we need to know how many instances use 
    // each seqid
    map<int, int> chan_seqid_count_map;
    // Sequence id counter
    int chan_seqid = 0;

    // Split the enable lines into a map saying if a source should be turned on
    tokens.clear();
    tokens = StrTokenize(in_enableline, ",");
    for (unsigned int x = 0; x < tokens.size(); x++) {
        enable_map[StrLower(tokens[x])] = 1;
    }

    if (enable_map.size() == 0) {
        all_enable = 1;
    }

    // Split the initial channel allocations, with a little help for people with 
	// only one capture source enabled - if only a number is given, assume it's 
	// a for the only enabled source.
    if (enable_map.size() == 1 && in_initchannels->size() == 1 &&
        (*in_initchannels)[0].find(":") == string::npos) {
        int tmpchan;
        if (sscanf((*in_initchannels)[0].c_str(), "%d", &tmpchan) != 1) {
            snprintf(errstr, 1024, "Illegal initial channel '%s'", 
                     (*in_initchannels)[0].c_str());
            _MSG(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        initch_map[enable_map.begin()->first] = tmpchan;
    } else {
        for (unsigned int nic = 0; nic < in_initchannels->size(); nic++) {
            tokens.clear();
            tokens = StrTokenize((*in_initchannels)[nic], ":");

            if (tokens.size() < 2) {
                snprintf(errstr, 1024, "Illegal initial channel '%s'", 
                         (*in_initchannels)[nic].c_str());
                _MSG(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return -1;
            }

            int tmpchan;
            if (sscanf(tokens[1].c_str(), "%d", &tmpchan) != 1) {
                snprintf(errstr, 1024, "Illegal initial channel '%s'", 
                         (*in_initchannels)[nic].c_str());
                _MSG(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return -1;
            }

            initch_map[StrLower(tokens[0])] = tmpchan;
        }
    }

    // Register the default channels by making them look like capsource name maps, 
    // giving them their own sequence ids we can count during assignment to see how 
	// we need to split things
    for (map<string, vector<int> >::iterator dchi = defaultch_map.begin(); 
         dchi != defaultch_map.end(); ++dchi) {
        chan_cap_seqid_map[dchi->first] = chan_seqid;
        chan_seqid_seq_map[chan_seqid] = dchi->second;
        chan_seqid++;
    }
    
    // Parse the channel lines into our channel assignment tracking maps
    for (unsigned int sc = 0; sc < in_sourcechannels->size(); sc++) {
        tokens.clear();
        tokens = StrTokenize((*in_sourcechannels)[sc], ":");

        if (tokens.size() < 2) {
            snprintf(errstr, 1024, "Illegal sourcechannel line '%s'", 
					 (*in_sourcechannels)[sc].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        vector<string> chan_capsource_bits = StrTokenize(tokens[0], ",");
        vector<int> chan_channel_bits = Str2IntVec(tokens[1]);

        if (chan_channel_bits.size() == 0) {
            snprintf(errstr, 1024, "Illegal channel list '%s' in sourcechannel "
					 "line '%s'", tokens[1].c_str(), 
					 (*in_sourcechannels)[sc].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        // Assign the intvec a sequence id
        chan_seqid_seq_map[chan_seqid] = chan_channel_bits;

        // Assign it to each name slot
        for (unsigned int cap = 0; cap < chan_capsource_bits.size(); cap++) {
            if (chan_cap_seqid_map.find(StrLower(chan_capsource_bits[cap])) != 
                chan_cap_seqid_map.end()) {
                snprintf(errstr, 1024, "Capture source '%s' assigned multiple "
						 "channel sequences.", chan_capsource_bits[cap].c_str());
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return -1;
            }

            chan_cap_seqid_map[StrLower(chan_capsource_bits[cap])] = chan_seqid;
        }

        // Set this up now to make math easy later
        chan_seqid_count_map[chan_seqid] = 0;
        
        chan_seqid++;
    }
    
    // Parse the card lines into meta records for the sources that will be enabled
    for (unsigned int cl = 0; cl < in_cardlines->size(); cl++) {
        tokens.clear();
        tokens = StrTokenize((*in_cardlines)[cl], ",");
        int sourceline_initch = -1;

        if (tokens.size() < 3) {
            snprintf(errstr, 1024, "Illegal card source line '%s'", 
					 (*in_cardlines)[cl].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

		// Look for the auto cards
		packsource_protorec *curproto = NULL;
		if (StrLower(tokens[0]) == "auto") {
			for (map<string, packsource_protorec *>::iterator psi = 
				 cardtype_map.begin(); psi != cardtype_map.end(); ++psi) {
				int ret = 0;

				if (psi->second->weak_source == NULL)
					continue;

				ret = psi->second->weak_source->AutotypeProbe(tokens[1]);

				if (ret > 0) {
					curproto = psi->second;
					_MSG("Resolved '" + tokens[1] + "' auto source type to " 
						 "source type " + curproto->type, MSGFLAG_INFO);
				} else if (ret < 0 || globalreg->fatal_condition == 1) {
					globalreg->fatal_condition = 1;
					return -1;
				}
			}

			if (curproto == NULL) {
				_MSG("Failed to find a matching source type for autosource "
					 "interface " + tokens[1] + ".  This does not always mean that "
					 "the device is unsupported, please consult the Kismet "
					 "README file for information about configuring capture "
					 "sources", MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}
		} else {
			// Look for the card type, we won't even create a source if we 
			// don't have one.
			if (cardtype_map.find(StrLower(tokens[0])) == cardtype_map.end()) {
				snprintf(errstr, 1024, "Unknown capture source type '%s' in "
						 "source '%s'", tokens[0].c_str(), 
						 (*in_cardlines)[cl].c_str());
				globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}
		}

        // If they have four elements in the source line, take the fourth as the
        // initial channel
        if (tokens.size() > 3) {
            if (sscanf(tokens[3].c_str(), "%d", &sourceline_initch) != 1) {
                snprintf(errstr, 1024, "Illegal initial channel '%s' specified on "
                         "the sourceline for '%s'", tokens[3].c_str(), 
                         tokens[0].c_str());
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return -1;
            }
        }

        if (enable_map.find(StrLower(tokens[2])) != enable_map.end() ||
            all_enable == 1) {

			packsource_protorec *meta = new packsource_protorec;

			meta->name = tokens[2];
			meta->interface = tokens[1];
			meta->type = StrLower(tokens[0]);

			// Grab the defaults
			if (curproto == NULL)
				curproto = cardtype_map[meta->type];

			meta->root_required = curproto->root_required;
			meta->default_channelset = curproto->default_channelset;
			meta->weak_source = curproto->weak_source;

            // Assign the initial channel - the kismet command line takes the highest
            // priority, then if they defined a quad-element sourceline, and finally
            // the prototype default if nothing overrides it
            if (initch_map.find(StrLower(meta->name)) != initch_map.end()) {
                meta->initial_channel = initch_map[StrLower(meta->name)];
            } else {
                // If they didn't request an initial channel, and they specified 
				// one on the source line, set it to that, otherwise use the 
				// prototype initial channel
                if (sourceline_initch > 0)
                    meta->initial_channel = sourceline_initch;
                else
                    meta->initial_channel = curproto->initial_channel;
            }

			// Assign the channels - if it doesn't have a specific name, we look
			// for the default channel set.  Assignment counts are used in the
			// next block to assign channel offsets.  The map referenes are
			// admittedly pretty nuts, but they only happen during startup so
			// it just doesn't pay to try to optimize them
            if (chan_cap_seqid_map.find(StrLower(meta->name)) != 
                chan_cap_seqid_map.end()) {

                meta->channelvec_id = chan_cap_seqid_map[StrLower(meta->name)];
                chan_seqid_count_map[meta->channelvec_id]++;

            } else if (chan_cap_seqid_map.find(StrLower(meta->default_channelset)) 
                       != chan_cap_seqid_map.end()) {

                meta->channelvec_id = 
                    chan_cap_seqid_map[StrLower(meta->default_channelset)];
                chan_seqid_count_map[meta->channelvec_id]++;
            }

			// If we're hopping, turn it on
			if (in_chhop)
				meta->interface_hop = 1;

			prebuild_protosources.push_back(meta);
        }
    }

    // Now we assign split channels by going through all the meta sources, if we're 
    // hopping and splitting channels, that is.
	//
	// If this interface has a specific "do not hop" set, we allocate the
	// channels anyway and then don't enable hopping, since we might want to turn
	// it on again later
    if (in_chhop) {
        map<int, int> tmp_seqid_assign_map;

        for (unsigned int metc = 0; metc < prebuild_protosources.size(); metc++) {
			packsource_protorec *meta = prebuild_protosources[metc];

            meta->channel_vec = chan_seqid_seq_map[meta->channelvec_id];
    
            // Bail if we don't split hop positions
            if (in_chsplit == 0)
                continue;

            // Track how many actual assignments we've made use it to 
            // offset the channel position.
            if (tmp_seqid_assign_map.find(meta->channelvec_id) == 
                tmp_seqid_assign_map.end())
				continue;

			meta->cv_offset = (meta->channel_vec.size() / 
							   chan_seqid_count_map[meta->channelvec_id]) * 
				tmp_seqid_assign_map[meta->channelvec_id];

            tmp_seqid_assign_map[meta->channelvec_id]++;
        }
    }

    if (prebuild_protosources.size() == 0) {
        snprintf(errstr, STATUS_MAX, "No packsources were enabled.  Make sure that "
                 "if you use an enablesource line that you specify the correct "
                 "sources.");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    return 1;
}

int Packetsourcetracker::BindSources(int in_root) {
    // Walk through the packet sources and create/open all the ones that we can.
    // Dual-pass for root and non-root
    for (unsigned int x = 0; x < prebuild_protosources.size(); x++) {
		packsource_protorec *meta = prebuild_protosources[x];

        // Skip sources that don't apply to this user mode
        if (!meta->root_required && in_root) {
            continue;
        } else if (meta->root_required && !in_root) {
            continue;
        }
       
		// Use the weak source to create a strong one
		KisPacketSource *strong = 
			meta->weak_source->CreateSource(globalreg, meta->type, meta->name,
											meta->interface);

		// Enable monitor mode
		snprintf(errstr, STATUS_MAX, "Source %d (%s): Enabling monitor mode for "
				 "%s source interface %s channel %d...",
				 x, meta->name.c_str(), meta->type.c_str(), 
				 meta->interface.c_str(), meta->initial_channel);
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

		// Set the initial channel vec
		if (strong->SetChannelSequence(meta->channel_vec) < 0) {
			snprintf(errstr, STATUS_MAX, "Source %d (%s): Failed to set channel "
					 "list.", x, meta->name.c_str());
			_MSG(errstr, MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		// Set the vector position
		if (strong->SetChannelSeqPos(meta->cv_offset) < 0) {
			snprintf(errstr, STATUS_MAX, "Source %d (%s): Failed to set starting "
					 "position in channel list.", x, meta->name.c_str());
			_MSG(errstr, MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		// Set hopping mode
		if (strong->SetChannelHop(meta->interface_hop) < 0) {
			snprintf(errstr, STATUS_MAX, "Source %d (%s): Failed to enable "
					 "channel hopping.", x, meta->name.c_str());
			_MSG(errstr, MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		if (strong->EnableMonitor() < 0 || globalreg->fatal_condition) {
			globalreg->fatal_condition = 1;
			return -1;
		}

		// Add it to the standard live sources mechanism
		RegisterLiveKisPacketsource(strong);

        // Open it
        snprintf(errstr, STATUS_MAX, "Source %d (%s): Opening %s source "
                 "interface %s...", x, meta->name.c_str(), 
                 meta->type.c_str(), meta->interface.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

		if (strong->OpenSource() < 0 || globalreg->fatal_condition) {
			// Try to drop back to normal
			strong->DisableMonitor();
			globalreg->fatal_condition = 1;
			return -1;
		}

		snprintf(errstr, STATUS_MAX, "Source %d (%s): Opened source. "
				 "UUID: %s", x, meta->name.c_str(),
				 strong->FetchUUID().UUID2String().c_str());
		_MSG(errstr, MSGFLAG_INFO);
    }

    return 0;
}

int Packetsourcetracker::PauseSources() {
    for (unsigned int metc = 0; metc < live_packsources.size(); metc++) {
		KisPacketSource *meta = live_packsources[metc];

      	meta->Pause();
    }

    return 1;
}

int Packetsourcetracker::ResumeSources() {
    for (unsigned int metc = 0; metc < live_packsources.size(); metc++) {
		KisPacketSource *meta = live_packsources[metc];

      	meta->Resume();
    }
    return 1;
}

int Packetsourcetracker::CloseSources() {
#ifndef HAVE_SUID
	return ShutdownIPCSources();
#else
	ipc_packet *pack = (ipc_packet *) malloc(sizeof(ipc_packet));

	pack->data_len = 0;
	pack->ipc_cmdnum = haltall_ipc_id;

	globalreg->rootipc->SendIPC(pack);
#endif

    return 1;
}

int Packetsourcetracker::ShutdownIPCSources() {
    uid_t uid = getuid();
    int talk = -1;
	int uidbork = 0;

    for (unsigned int metc = 0; metc < live_packsources.size(); metc++) {
        KisPacketSource *meta = live_packsources[metc];

		// Pull the root requirement from the cardtype map... just skip entirely
		// if we can't figure out what to do with it because its not in the ct map
		if (cardtype_map.find(meta->FetchType()) == cardtype_map.end())
			return 0;

        // If we're not root and we can't close stuff, don't.  This might need to
        // turn into something that checks caps later...
        if (uid != 0 && cardtype_map[meta->FetchType()]->root_required != 0) {
			uidbork = 1;
            continue;
		}

		meta->CloseSource();
        
        // Unmonitor if we can
		int umon_ret = 0;
		if ((umon_ret = meta->DisableMonitor()) < 0) {
			snprintf(errstr, STATUS_MAX, "Unable to cleanly disable monitor mode.");
			globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
			snprintf(errstr, STATUS_MAX, "%s (%s) left in an unknown state.  "
					 "You may need to manually restart or reconfigure it for "
					 "normal operation.", meta->FetchName().c_str(), 
					 meta->FetchInterface().c_str());
			_MSG(errstr, MSGFLAG_ERROR);
		} else if (umon_ret == PACKSOURCE_UNMONITOR_RET_SILENCE && talk == -1) {
			talk = 0;
		} else if (umon_ret == PACKSOURCE_UNMONITOR_RET_OKWITHWARN) {
			talk = 1;
		} else if (umon_ret == PACKSOURCE_UNMONITOR_RET_CANTUNMON) {
            snprintf(errstr, STATUS_MAX, "%s (%s) unable to exit monitor mode "
                     "automatically. You may need to manually restart the device "
                     "and reconfigure it for normal operation.", 
                     meta->FetchName().c_str(), meta->FetchInterface().c_str()); 
            _MSG(errstr, MSGFLAG_ERROR);
        }

    }

    if (talk == 1) {
        fprintf(stderr, "WARNING: Sometimes cards don't always come out "
                "of monitor mode\n"
                "         cleanly.  If your card is not fully working, you "
                "may need to\n"
                "         restart or reconfigure it for normal operation.\n");
    }

	return 1;
}

void Packetsourcetracker::BlitCards(int in_fd) {
	kis_protocol_cache cache;

	for (unsigned int x = 0; x < live_packsources.size(); x++) {
		if (in_fd == -1) {
			if (globalreg->kisnetserver->SendToAll(card_protoref, 
												   (void *) live_packsources[x]) < 0)
				break;
		} else {
			if (globalreg->kisnetserver->SendToClient(in_fd, card_protoref,
													  (void *) live_packsources[x],
													  &cache) < 0)
				break;
		}
	}
}

