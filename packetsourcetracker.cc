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
#include "packetsource_pcap.h"
#include "packetsource_wext.h"
#include "packetsource_bsdrt.h"
#include "packetsource_drone.h"
#include "configfile.h"
#include "getopt.h"

#ifdef SYS_LINUX
// Bring in the ifcontrol stuff for 'auto'
#include "ifcontrol.h"
#endif

char *CARD_fields_text[] = {
    "interface", "type", "username", "channel", "id", "packets", "hopping",
    NULL
};

int Protocol_CARD(PROTO_PARMS) {
    meta_packsource *csrc = (meta_packsource *) data;
	ostringstream osstr;

	// Fill up the cache
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
				cache->Cache(fnum, csrc->device);
				break;
			case CARD_type:
				cache->Cache(fnum, csrc->prototype->cardtype);
				break;
			case CARD_username:
				cache->Cache(fnum, "\001" + MungeToPrintable(csrc->name) + "\001");
				break;
			case CARD_channel:
				osstr << csrc->capsource->FetchChannel();
				cache->Cache(fnum, osstr.str());
				break;
			case CARD_id:
				osstr << csrc->id;
				cache->Cache(fnum, osstr.str());
				break;
			case CARD_packets:
				osstr << csrc->capsource->FetchNumPackets();
				cache->Cache(fnum, osstr.str());
				break;
			case CARD_hopping:
				if (csrc->ch_hop)
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

KisPacketSource *nullsource_registrant(REGISTRANT_PARMS) {
    return new NullPacketSource(globalreg, in_meta, in_name, in_device);
}

int unmonitor_nullsource(MONITOR_PARMS) {
    return 0;
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
    next_packsource_id = 0;
    next_meta_id = 0;

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

	// Register the CARD protocol
	card_protoref =
		globalreg->kisnetserver->RegisterProtocol("CARD", 0, 1,
												  CARD_fields_text,
												  &Protocol_CARD,
												  &Protocol_CARD_enable,
												  this);

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

    // Register all our packet sources
    // RegisterPacketsource(name, root, channelset, init channel, register,
    // monitor, unmonitor, channelchanger)
    //
    // We register sources we known about but didn't compile support for as
    // NULL so we can report a sensible error if someone tries to use it
    // 
    // Plugins will go here after null sources, somehow
 
    // Null source, error registrant and can't autoreg
    RegisterPacketsource("none", 0, "na", 0, NULL,
                         nullsource_registrant,
                         NULL, unmonitor_nullsource, NULL, 0);

	// Everyone gets a drone
	RegisterPacketsource("drone", 0, "na", 0, NULL,
						 packetsource_drone_registrant,
						 NULL, unmonitor_drone, NULL, 0);

#ifdef HAVE_LIBPCAP
    // pcapfile doesn't have channel or monitor controls and can't autoreg
    RegisterPacketsource("pcapfile", 0, "na", 0, NULL,
                         packetsource_pcapfile_registrant,
                         NULL, unmonitor_pcapfile, NULL, 0);

#ifdef WIRELESS_EXT
	RegisterPacketsource("acx100", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("admtek", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("atmel_usb", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("hostap", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("ipw2100", 1, "IEEE80211b", 6,
						 autoprobe_ipw2100,
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("ipw2200", 1, "IEEE80211b", 6,
						 autoprobe_ipw2200,
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("ipw2915", 1, "IEEE80211ab", 6,
						 NULL, // FIXME -- what to do?
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);
	
	// Madwifi builtin sources
	RegisterPacketsource("madwifi_a", 1, "IEEE80211a", 36,
						 NULL,
						 packetsource_wext_fcs_registrant,
						 monitor_madwifi_a, unmonitor_madwifi,
						 chancontrol_wext_std, 1);
	// Only madwifi_b gets the autolearn for now until we get a mode probe
	// working and a way to tie it in
	RegisterPacketsource("madwifi_b", 1, "IEEE80211b", 6,
						 autoprobe_madwifi,
						 packetsource_wext_fcs_registrant,
						 monitor_madwifi_b, unmonitor_madwifi,
						 chancontrol_wext_std, 1);
	RegisterPacketsource("madwifi_g", 1, "IEEE80211b", 6,
						 NULL, // FIXME - do we need a detector?
						 packetsource_wext_fcs_registrant,
						 monitor_madwifi_g, unmonitor_madwifi,
						 chancontrol_wext_std, 1);
	RegisterPacketsource("madwifi_ag", 1, "IEEE80211ab", 6,
						 NULL, // FIXME -- do we need a detector?
						 packetsource_wext_fcs_registrant,
						 monitor_madwifi_ag, unmonitor_madwifi,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("prism54g", 1, "IEEE80211g", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("rt2400", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("rt2500", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("rt8180", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

#endif // Wext

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD) || defined(SYS_FREEBSD)
	// BSD pcap-based common radiotap capture sources
	RegisterPacketsource("radiotap_bsd_ag", 1, "IEEE80211ab", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_bsdrtap_registrant,
						 monitor_bsdrtap_std, unmonitor_bsdrtap_std,
						 chancontrol_bsdrtap_std, 1);
	RegisterPacketsource("radiotap_bsd_a", 1, "IEEE80211a", 36,
						 NULL, // FIXME -- add a detector
						 packetsource_bsdrtap_registrant,
						 monitor_bsdrtap_std, unmonitor_bsdrtap_std,
						 chancontrol_bsdrtap_std, 1);
	RegisterPacketsource("radiotap_bsd_g", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_bsdrtap_registrant,
						 monitor_bsdrtap_std, unmonitor_bsdrtap_std,
						 chancontrol_bsdrtap_std, 1);
	RegisterPacketsource("radiotap_bsd_b", 1, "IEEE80211b", 6,
						 NULL, // FIXME -- add a detector
						 packetsource_bsdrtap_registrant,
						 monitor_bsdrtap_std, unmonitor_bsdrtap_std,
						 chancontrol_bsdrtap_std, 1);
#endif // BSD

#endif // pcap

	// Register the packetsourcetracker as a pollable subsystem
	globalreg->RegisterPollableSubsys(this);

	// Assign the IPC commands and make it pollable
	chan_remote = new IPCRemote(globalreg, "channel control");
	chan_ipc_id = chan_remote->RegisterIPCCmd(&packsrc_chan_ipc, this);
	haltall_ipc_id = chan_remote->RegisterIPCCmd(&packsrc_haltall_ipc, this);
	globalreg->RegisterPollableSubsys(chan_remote);
}

Packetsourcetracker::~Packetsourcetracker() {
	globalreg->RemovePollableSubsys(this);

	chan_remote->ShutdownIPC(NULL);
	globalreg->RemovePollableSubsys(chan_remote);
	delete chan_remote;

    for (map<string, packsource_protorec *>::iterator x = cardtype_map.begin();
         x != cardtype_map.end(); ++x)
        delete x->second;
}

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

    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];
		int capd = meta->capsource->FetchDescriptor();

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

meta_packsource *Packetsourcetracker::FetchMetaID(int in_id) {
    if (in_id < 0 || in_id >= (int) meta_packsources.size())
        return NULL;

    return meta_packsources[in_id];
}

// Explicitly set a channel.  Caller is responsible for turning off hopping
// on this source if they want it to really stay on this channel
int Packetsourcetracker::SetChannel(int in_ch, meta_packsource *in_meta) {
    if (in_meta->prototype->channelcon == NULL)
        return 0;

#ifndef HAVE_SUID
    int ret = (*in_meta->prototype->channelcon)(globalreg, in_meta->device.c_str(),
                                                in_ch, (void *) in_meta->capsource);
    if (ret < 0)
        return ret;
#else
	// Don't use IPC to set "local control" sources (why use IPC to set snmp?)
    if (in_meta->prototype->child_control == 0) {
        int ret;
        ret = (*in_meta->prototype->channelcon)(globalreg, in_meta->device.c_str(),
                                                in_ch, (void *) in_meta->capsource);
        if (ret < 0)
            return ret;
    }

	ipc_packet *pack =
		(ipc_packet *) malloc(sizeof(ipc_packet) + 
							  sizeof(chanchild_changepacket));
	chanchild_changepacket *chpak = (chanchild_changepacket *) pack->data;

	chpak->meta_num = in_meta->id;
	chpak->channel = in_ch;

	pack->data_len = sizeof(chanchild_changepacket);
	pack->ipc_cmdnum = chan_ipc_id;

	chan_remote->SendIPC(pack);
#endif

    return 1;

}

int Packetsourcetracker::SetIPCChannel(int in_ch, unsigned int meta_num) {
	// This usually happens inside the IPC fork, so remember not to screw with
	// things that aren't set yet!  Meta is safe, other stuff isn't.  Globalreg
	// got remapped by the IPC system to funnel back over IPC
	if (meta_num >= meta_packsources.size()) {
		_MSG("Packetsourcetracker SetIPCChannel got illegal metasource "
			 "card number to set", MSGFLAG_ERROR);
		return 0;
	}

	meta_packsource *meta = meta_packsources[meta_num];

	if (meta->prototype->channelcon == NULL) {
		_MSG("Packetsourcetracker SetIPCChannel tried to set a metasource "
			 "with no channel control function", MSGFLAG_ERROR);
		return 0;
	}

	int ret = 
		(*meta->prototype->channelcon)(globalreg, meta->device.c_str(),
									   in_ch, (void *) meta->capsource);
	if (ret >= 0) {
		meta->consec_errors = 0;
		return 1;
	}

	meta->consec_errors++;

	if (meta->consec_errors >= MAX_CONSEC_CHAN_ERR) {
		ostringstream osstr;
		osstr << "Packet source " << meta->name << " (" << meta->device << ") "
			"has had " << meta->consec_errors << " consecutive errors.  This "
			"most likely means the drivers or firmware have become confused. "
			"Kismet cannot continue.";
		_MSG(osstr.str(), MSGFLAG_FATAL);
		// Redundant but can't hurt
		chan_remote->ShutdownIPC(NULL);
	}

	return -1;
}

int Packetsourcetracker::SetHopping(int in_hopping, meta_packsource *in_meta) {
    if (in_meta->prototype->channelcon == NULL)
        return 0;

    in_meta->ch_hop = in_hopping;

    return 0;
}

// Hop the packet sources up a channel
int Packetsourcetracker::AdvanceChannel() {
	// Don't hop if it's queued up/un-ack'd
	if (chan_remote->FetchReadyState() == 0)
		return 0;

    for (unsigned int metac = 0; metac < meta_packsources.size(); metac++) {
        meta_packsource *meta = meta_packsources[metac];

        // Don't do anything for sources with no channel controls
        if (meta->prototype->channelcon == NULL)
            continue;

        // Don't do anything if this source doesn't hop
        if (meta->ch_hop == 0)
            continue;

        int ret = SetChannel(meta->channels[meta->ch_pos++], meta);
        

        if (meta->ch_pos >= (int) meta->channels.size())
            meta->ch_pos = 0;

        if (ret < 0)
            return ret;

    }

    return 1;
}

// Map a cardtype string to the registrant function.  Should be called from main() or 
// wherever packet sources get loaded from.  (Plugin hook)
int Packetsourcetracker::RegisterPacketsource(const char *in_cardtype, int in_root, 
                                              const char *in_defaultchanset, 
                                              int in_initch, 
											  packsource_autoprobe in_autoprobe,
                                              packsource_registrant in_registrant, 
                                              packsource_monitor in_monitor,
                                              packsource_monitor in_unmonitor,
                                              packsource_chcontrol in_channelcon,
                                              int in_childcontrol) {
    // Do we have it?  Can't register a type that's already registered.
    if (cardtype_map.find(in_cardtype) != cardtype_map.end())
        return -1;

    // Register it.
    packsource_protorec *rec = new packsource_protorec;

    rec->id = next_packsource_id++;
    rec->root_required = in_root;
    rec->default_channelset = in_defaultchanset;
    rec->initial_channel = in_initch;

	rec->autoprobe = in_autoprobe;
    rec->registrant = in_registrant;
    rec->monitor_enable = in_monitor;
    rec->monitor_disable = in_unmonitor;
    rec->channelcon = in_channelcon;

    rec->child_control = in_childcontrol;

    rec->cardtype = in_cardtype;

    cardtype_map[StrLower(in_cardtype)] = rec;

    return rec->id;
}

int Packetsourcetracker::RemovePacketsource(const char *in_cardtype) {
	// We can't fully clean it, but we can make it unusable.
	
	map<string, packsource_protorec *>::iterator itr =
		cardtype_map.find(in_cardtype);

    if (itr == cardtype_map.end())
        return -1;

	itr->second->autoprobe = NULL;
	itr->second->registrant = NULL;
	itr->second->monitor_disable = NULL;
	itr->second->monitor_enable = NULL;
	itr->second->channelcon = NULL;

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

vector<meta_packsource *> Packetsourcetracker::FetchMetaSourceVec() {
    return meta_packsources;
}

// Big scary function to build the meta-packsource records from the requested configs 
// provided. These configs can come from either the config file or the command line 
// options, caller is responsible for figuring out which ones override and get sent 
// to us.
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
    // Was anything able to hop?
    int hop_possible = 0;

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
			string driver, version, firmware;
#if defined(SYS_LINUX)
			ethtool_drvinfo drvinfo;
			if (Linux_GetDrvInfo(tokens[1].c_str(), errstr, &drvinfo) < 0) {
				_MSG(errstr, MSGFLAG_FATAL);
				_MSG("Failed to get the ethtool driver info from device " +
					 tokens[1] + ".  This information is used to detect the capture "
					 "type for 'auto' sources.", MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}

			driver = drvinfo.driver;
			version = drvinfo.version;
			firmware = drvinfo.fw_version;
#else
			// Short out if we don't know what to do
			_MSG("Currently the 'auto' card type detection is only supported "
				 "under Linux.  Please consult the README file for information "
				 "on the exact card type which should be used for your card.",
				 MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
#endif

			for (map<string, packsource_protorec *>::iterator psi = 
				 cardtype_map.begin(); psi != cardtype_map.end(); ++psi) {
				int ret = 0;
				if (psi->second->autoprobe == NULL)
					continue;

				ret = (*(psi->second->autoprobe))(globalreg, tokens[2],
												  tokens[1], driver, 
												  version, firmware);
				if (ret > 0) {
					curproto = psi->second;
					_MSG("Resolved " + tokens[1] + " auto source type to " 
						 "source type " + curproto->cardtype, MSGFLAG_INFO);
				} else if (ret < 0 || globalreg->fatal_condition == 1) {
					globalreg->fatal_condition = 1;
					return -1;
				}
			}

			if (curproto == NULL) {
				_MSG("Failed to find a matching source type for autosource "
					 "interface " + tokens[1] + ".  Got info ('" + driver + "', '" + 
					 version + "'," " '" + firmware + "') for the device.", 
					 MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}
		} else {
			// Look for the card type, we won't even create a metasource if we 
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

        // Look for stuff the code knows about but which was disabled
        if (cardtype_map[StrLower(tokens[0])]->registrant == NULL) {
            snprintf(errstr, 1024, "Support for capture source type '%s' was not "
					 "built.  Check the output from 'configure' for more information "
					 "about why it might not have been compiled in.", 
					 tokens[0].c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
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

            meta_packsource *meta = new meta_packsource;
            meta->id = next_meta_id++;
            meta->valid = 0;
            meta->cmd_ack = 1;
			if (curproto == NULL)
				meta->prototype = cardtype_map[StrLower(tokens[0])];
			else
				meta->prototype = curproto;
            meta->name = tokens[2];
            meta->device = tokens[1];
            meta->capsource = NULL;
            meta->stored_interface = NULL;
            meta->ch_pos = 0;
            meta->cur_ch = 0;
			meta->consec_errors = 0;
            // Hopping is turned on in any source that has a channel control pointer.
            // This isn't controlling if kismet hops in general, only if this source
            // changes channel when Kismet decides to channel hop.
            if (meta->prototype->channelcon == NULL) {
                meta->ch_hop = 0;
            } else {
                meta->ch_hop = 1;
                hop_possible++;
            }

            // Assign the initial channel - the kismet command line takes the highest
            // priority, then if they defined a quad-element sourceline, and finally
            // the prototype default if nothing overrides it
            if (initch_map.find(StrLower(meta->name)) != initch_map.end()) {
                meta->cur_ch = initch_map[StrLower(meta->name)];
            } else {
                // If they didn't request an initial channel, and they specified one on
                // the source line, set it to that, otherwise use the prototype initial
                // channel
                if (sourceline_initch > 0)
                    meta->cur_ch = sourceline_initch;
                else
                    meta->cur_ch = meta->prototype->initial_channel;
            }

            // Assign the channels - if it doesn't have a specific name, we look for 
            // the default channel set.  Assignment counts are used in the next run 
            // through to assign initial channel offsets.  These map references are 
            // pretty ridiculous, but they only happen once during startup so it 
            // doesn't make much sense to go nuts trying to optimize them
            if (chan_cap_seqid_map.find(StrLower(meta->name)) != 
                chan_cap_seqid_map.end()) {
                // Hard-fault on sources that have an explicit channel hop but can't 
                // hop...
                if (meta->prototype->default_channelset == "none") {
                    snprintf(errstr, 1024, "Channel set assigned to capsource %s, "
                             "which cannot channel hop.",
                             meta->name.c_str());
                    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                    globalreg->fatal_condition = 1;
                    return -1;
                }

                meta->channel_seqid = chan_cap_seqid_map[StrLower(meta->name)];
                chan_seqid_count_map[meta->channel_seqid]++;
            } else if (chan_cap_seqid_map.find(StrLower(meta->prototype->default_channelset)) 
                       != chan_cap_seqid_map.end()) {

                meta->channel_seqid = 
                    chan_cap_seqid_map[StrLower(meta->prototype->default_channelset)];
                chan_seqid_count_map[meta->channel_seqid]++;
            }
                        
            meta_packsources.push_back(meta);
        }
    }

    // Even if we asked for channel hopping, if nothing we enabled is able to,
    // turn it off.
    if (hop_possible == 0)
        in_chhop = 0;
    
    // Now we assign split channels by going through all the meta sources, if we're 
    // hopping and splitting channels, that is.
    //
    // If we're not hopping, this doesn't happen, meta->channels.size() == 0, and 
    // we know not to hop on this device
    if (in_chhop) {
        map<int, int> tmp_seqid_assign_map;

        for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
            meta_packsource *meta = meta_packsources[metc];

            meta->channels = chan_seqid_seq_map[meta->channel_seqid];
    
            // Bail if we don't split hop positions
            if (in_chsplit == 0)
                continue;

            // Track how many actual assignments we've made so far and use it to 
            // offset the channel position.
            if (tmp_seqid_assign_map.find(meta->channel_seqid) == 
                tmp_seqid_assign_map.end())
                tmp_seqid_assign_map[meta->channel_seqid] = 0;

            meta->ch_pos = (meta->channels.size() / 
                            chan_seqid_count_map[meta->channel_seqid]) * 
                tmp_seqid_assign_map[meta->channel_seqid];

            tmp_seqid_assign_map[meta->channel_seqid]++;
        }
    }

    if (meta_packsources.size() == 0) {
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
    for (unsigned int x = 0; x < meta_packsources.size(); x++) {
        meta_packsource *meta = meta_packsources[x];

        // Skip sources that don't apply to this user mode
        if (!meta->prototype->root_required && in_root) {
            continue;
        } else if (meta->prototype->root_required && !in_root) {
            continue;
        }
        
        // Call the registrant to allocate a packet source ... nasty little error
        // handler but it works.
        errstr[0] = '\0';
        meta->capsource = 
            (*meta->prototype->registrant)(globalreg, meta, meta->name, meta->device);

        if (meta->capsource == NULL) {
            snprintf(errstr, 1024, "Unable to create source instance for source '%s'",
                     meta->name.c_str());
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        // Enable monitor mode
        int ret = 0;
        if (meta->prototype->monitor_enable != NULL) {
            snprintf(errstr, STATUS_MAX, "Source %d (%s): Enabling monitor mode for "
					 "%s source interface %s channel %d...",
                    x, meta->name.c_str(), meta->prototype->cardtype.c_str(), 
                    meta->device.c_str(), meta->cur_ch);
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

            ret = (*meta->prototype->monitor_enable)(globalreg, meta->device.c_str(), 
                                                     meta->cur_ch, 
													 &meta->stored_interface,
                                                     (void *) meta->capsource);
        }

        if (ret < 0) {
            // Monitor enable dealt with printing stuff
            return -1;
        }

        // Add it to the live sources vector
        live_packsources.push_back(meta->capsource);
        
        // Open it
        snprintf(errstr, STATUS_MAX, "Source %d (%s): Opening %s source "
                 "interface %s...", x, meta->name.c_str(), 
                 meta->prototype->cardtype.c_str(), meta->device.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
        if (meta->capsource->OpenSource() < 0) {
            meta->valid = 0;
            return -1;
        }

        meta->valid = 1;

    }

    return 0;
    
}

int Packetsourcetracker::PauseSources() {
    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];

        meta->capsource->Pause();
    }

    return 1;
}

int Packetsourcetracker::ResumeSources() {
    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];

        meta->capsource->Resume();
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

	chan_remote->SendIPC(pack);
#endif

    return 1;
}

int Packetsourcetracker::ShutdownIPCSources() {
    uid_t uid = getuid();
    int talk = 0;
	int uidbork = 0;

    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];

        // If we're not root and we can't close stuff, don't.  This might need to
        // turn into something that checks caps later...
        if (uid != 0 && meta->prototype->root_required != 0) {
			uidbork = 1;
            continue;
		}

        // close if we can
        if (meta->valid)
            meta->capsource->CloseSource();
        
        // delete
        delete meta->capsource;

        meta->valid = 0;

        // Unmonitor if we can
        if (meta->prototype->monitor_disable != NULL) {
            int umon_ret = 0;
            if ((umon_ret = 
                 (*meta->prototype->monitor_disable)(globalreg, 
													 meta->device.c_str(), 0, 
                                                     &meta->stored_interface,
                                                     (void *) meta->capsource)) < 0) {
                snprintf(errstr, STATUS_MAX, "Unable to cleanly disable "
						 "monitor mode.");
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
                snprintf(errstr, STATUS_MAX, "%s (%s) left in an unknown state.  "
                         "You may need to manually restart or reconfigure it for "
                         "normal operation.", meta->name.c_str(), 
						 meta->device.c_str());
                _MSG(errstr, MSGFLAG_ERROR);
            }

            // return 0 if we want to be quiet
            if (umon_ret != 0)
                talk = 1;
        } else {
            snprintf(errstr, STATUS_MAX, "%s (%s) unable to exit monitor mode "
                     "automatically. You may need to manually restart the device "
                     "and reconfigure it for normal operation.", 
                     meta->name.c_str(), meta->device.c_str()); 
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

	for (unsigned int x = 0; x < meta_packsources.size(); x++) {
		// Don't send ones with no info
		if (meta_packsources[x]->capsource == NULL)
			continue;

		if (in_fd == -1) {
			if (globalreg->kisnetserver->SendToAll(card_protoref, 
												   (void *) meta_packsources[x]) < 0)
				break;
		} else {
			if (globalreg->kisnetserver->SendToClient(in_fd, card_protoref,
													  (void *) meta_packsources[x],
													  &cache) < 0)
				break;
		}
	}
}

int Packetsourcetracker::SpawnChannelChild() {
#ifndef HAVE_SUID
	return 1;
#endif

	int child_control = 0;
	for (unsigned int metac = 0; metac < meta_packsources.size(); metac++) {
		if (meta_packsources[metac]->prototype->child_control) {
			child_control = 1;
			break;
		}
	}

	// Don't spawn IPC if we don't have anything to do
	if (child_control == 0)
		return 1;

	// Spawn the IPC handler
	int ret = chan_remote->SpawnIPC();

	if (ret < 0 || globalreg->fatal_condition) {
		_MSG("Packetsourcetracker failed to create an IPC child process",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	ostringstream osstr;

	osstr << "Packetsourcetracker spawned IPC child process pid " <<
		chan_remote->FetchSpawnPid();
	_MSG(osstr.str(), MSGFLAG_INFO);

	return 1;
}

int Packetsourcetracker::ShutdownChannelChild() {
#ifndef HAVE_SUID
	return 1;
#endif

	chan_remote->ShutdownIPC(NULL);

	return 1;
}

