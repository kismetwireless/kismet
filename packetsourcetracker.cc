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
#include "packetsource_bsd.h"
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

void Packetcontrolchild_MessageClient::ProcessMessage(string in_msg, int in_flags) {
    // Redirect stuff into the protocol to talk to the parent control

    int chflag = CHANFLAG_NONE;

    if (in_flags & MSGFLAG_LOCAL)
        return;

    if (in_flags & MSGFLAG_FATAL)
        chflag = CHANFLAG_FATAL;
    
    // This is a godawfully ugly call
    globalreg->sourcetracker->child_ipc_buffer.push_front(globalreg->sourcetracker->CreateTextPacket(in_msg, chflag));
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
    chanchild_pid = 0;
    sockpair[0] = sockpair[1] = 0;

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

	RegisterPacketsource("ipw2200", 1, "IEEE80211b", 6,
						 autoprobe_ipw2200,
						 packetsource_wext_registrant,
						 monitor_wext_std, unmonitor_wext_std,
						 chancontrol_wext_std, 1);

	RegisterPacketsource("ipw2100", 1, "IEEE80211b", 6,
						 autoprobe_ipw2100,
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
						 NULL,
						 packetsource_wext_fcs_registrant,
						 monitor_madwifi_g, unmonitor_madwifi,
						 chancontrol_wext_std, 1);
	RegisterPacketsource("madwifi_ag", 1, "IEEE80211ab", 6,
						 NULL,
						 packetsource_wext_fcs_registrant,
						 monitor_madwifi_ag, unmonitor_madwifi,
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

#endif

	// Register the packetsourcetracker as a pollable subsystem
	globalreg->RegisterPollableSubsys(this);
}

Packetsourcetracker::~Packetsourcetracker() {
	globalreg->RemovePollableSubsys(this);

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

    dataframe_only = 0;

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
    unsigned int max = in_max_fd;

    if (chanchild_pid != 0) {
        if (in_max_fd < (unsigned int) sockpair[1])
            max = sockpair[1];

        // Set the read sock all the time
        FD_SET(sockpair[1], out_rset);

        // Set it for writing if we have some queued
        if (ipc_buffer.size() > 0)
            FD_SET(sockpair[1], out_wset);
    }

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
    // This should only ever get called when the fd is set so we don't need to do our 
    // own select...
    chanchild_packhdr in_pak;
    uint8_t *data;

    // Write packets out if we have them queued, and write as many as we can
    if (FD_ISSET(sockpair[1], &in_wset)) {
        while (ipc_buffer.size() > 0) {
            chanchild_packhdr *pak = ipc_buffer.front();

            // Send the header if we didn't already
            if (dataframe_only == 0) {
                if (send(sockpair[1], pak, 
						 sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
                    if (errno == ENOBUFS) {
                        break;
                    } else {
                        snprintf(errstr, 1024, "ipc header send() failed: %s", 
								 strerror(errno));
                        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                        globalreg->fatal_condition = 1;
                        return -1;
                    }
                } 
            }

            // send the payload if there is one
            if (pak->datalen > 0) {
                if (send(sockpair[1], pak->data, pak->datalen, 0) < 0) {
                    if (errno == ENOBUFS) {
                        dataframe_only = 1;
                        break;
                    } else {
                        snprintf(errstr, 1024, "ipc content send() failed: %s", 
								 strerror(errno));
                        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                        globalreg->fatal_condition = 1;
                        return -1;
                    }
                }

            }

            dataframe_only = 0;

            ipc_buffer.pop_front();
            free(pak->data);
            delete pak;
        }

    }
    
    // Read responses from the capture child
    if (FD_ISSET(sockpair[1], &in_rset)) {
        if (recv(sockpair[1], &in_pak, 
				 sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
            snprintf(errstr, 1024, "header recv() error: %s", strerror(errno));
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        // Keep trying to go on...
        if (in_pak.sentinel != CHANSENTINEL) {
            snprintf(errstr, 1024, "Got packet from channel control process with "
                     "invalid sentinel.");
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return 1;
        }

        // These don't mean anything to us.
        if (in_pak.packtype == CHANPACK_DIE || in_pak.packtype == CHANPACK_CHANNEL)
            return 0;

        if (in_pak.datalen == 0) {
            return 0;
        }

        // Other packets have a data component so we need to allocate it plus a null
        data = (uint8_t *) malloc(sizeof(uint8_t) * (in_pak.datalen + 1));

        if (recv(sockpair[1], data, in_pak.datalen, 0) < 0) {
            snprintf(errstr, 1024, "data recv() error: %s", strerror(errno));
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        // Packet acks just set the flag
        if (in_pak.packtype == CHANPACK_CMDACK) {
            // Data should be an 8bit uint with the meta number.
            if (data[0] >= meta_packsources.size()) {
                snprintf(errstr, 1024, "illegal command ack for meta number %d", 
						 data[0]);
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return -1;
            }

            // Set the command ack
            meta_packsources[data[0]]->cmd_ack = 1;

            free(data);

            return 0;
        } else if (in_pak.packtype == CHANPACK_TEXT) {
            // Just to be safe
            data[in_pak.datalen] = '\0';
            snprintf(errstr, 1024, "%s", (char *) data);

            free(data);

            // Fatal packets return a fatal condition 
            if (in_pak.flags & CHANFLAG_FATAL) {
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
            } else {
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
            }

            return 1;
        }
    }

	// Sweep the packet sources
	for (unsigned int x = 0; x < live_packsources.size(); x++) {
		if (FD_ISSET(live_packsources[x]->FetchDescriptor(), &in_rset)) {
			live_packsources[x]->Poll();
		}
	}

    return 0;
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
    if (in_meta->prototype->child_control == 0) {
        int ret;
        ret = (*in_meta->prototype->channelcon)(globalreg, in_meta->device.c_str(),
                                                in_ch, (void *) in_meta->capsource);
        if (ret < 0)
            return ret;
    }

    chanchild_packhdr *chancmd = new chanchild_packhdr;
    chanchild_changepacket *data = (chanchild_changepacket *)
        malloc(sizeof(chanchild_changepacket));

    memset(chancmd, 0, sizeof(chanchild_packhdr));

    if (data == NULL) {
        snprintf(errstr, STATUS_MAX, "Could not allocate data struct for "
                 "changing channels: %s", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }
    memset(data, 0, sizeof(chanchild_changepacket));

    chancmd->sentinel = CHANSENTINEL;
    chancmd->packtype = CHANPACK_CHANNEL;
    chancmd->flags = CHANFLAG_NONE;
    chancmd->datalen = sizeof(chanchild_changepacket);
    chancmd->data = (uint8_t *) data;

    data->meta_num = (uint8_t) in_meta->id;
    data->channel = (uint16_t) in_ch;

    ipc_buffer.push_back(chancmd);
#endif

    return 1;

}

int Packetsourcetracker::SetHopping(int in_hopping, meta_packsource *in_meta) {
    if (in_meta->prototype->channelcon == NULL)
        return 0;

    in_meta->ch_hop = in_hopping;

    return 0;
}

// Hop the packet sources up a channel
int Packetsourcetracker::AdvanceChannel() {
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
    uid_t uid = getuid();
    int talk = 0;

    for (unsigned int metc = 0; metc < meta_packsources.size(); metc++) {
        meta_packsource *meta = meta_packsources[metc];
     
        // If we're not root and we can't close stuff, don't.  This might need to
        // turn into something that checks caps later...
        if (uid != 0 && meta->prototype->root_required != 0)
            continue;

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
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
            }

            // return 0 if we want to be quiet
            if (umon_ret != 0)
                talk = 1;
        } else {
            snprintf(errstr, STATUS_MAX, "%s (%s) unable to exit monitor mode "
                     "automatically. You may need to manually restart the device "
                     "and reconfigure it for normal operation.", 
                     meta->name.c_str(), meta->device.c_str()); 
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
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

int Packetsourcetracker::SpawnChannelChild() {
    // If we don't do priv dropping don't bother opening a channel control child
#ifndef HAVE_SUID
    return 1;
#else

    int child_control = 0;
    for (unsigned int metac = 0; metac < meta_packsources.size(); metac++) {
        if (meta_packsources[metac]->prototype->child_control == 1) {
            child_control = 1;
            break;
        }
    }

    // Don't spawn a process if we don't ahve anyting to do with it
    if (child_control == 0) {
        chanchild_pid = 0;
        return 1;
    }
    
    // Generate socket pair before we split
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sockpair) < 0) {
        fprintf(stderr, "FATAL:  Unable to create child socket pair for "
				"channel control: %d, %s\n", errno, strerror(errno));
        return -1;
    }

    // Fork
    if ((chanchild_pid = fork()) < 0) {
        fprintf(stderr, "FATAL:  Unable to create child process for "
				"channel control.\n");
        return -1;
    } else if (chanchild_pid == 0) {
        // Kluge a new messagebus into the childs global registry
        globalreg->messagebus = new MessageBus;
        Packetcontrolchild_MessageClient *pccmc = 
			new Packetcontrolchild_MessageClient(globalreg);
        globalreg->messagebus->RegisterClient(pccmc, MSGFLAG_ALL);
        
        // Spawn the child loop code
        ChannelChildLoop();
        exit(0);
    }

    fprintf(stderr, "Spawned channelc control process %d\n", chanchild_pid);
    
    return 1;
#endif
}

// Die cleanly
int Packetsourcetracker::ShutdownChannelChild() {
#ifndef HAVE_SUID
    return 1;
#else
    chanchild_packhdr death_packet;

    if (chanchild_pid == 0)
        return 1;
   
    memset(&death_packet, 0, sizeof(chanchild_packhdr));
    
    death_packet.sentinel = CHANSENTINEL;
    death_packet.packtype = CHANPACK_DIE;
    death_packet.flags = CHANFLAG_FATAL;
    death_packet.datalen = 0;
    death_packet.data = NULL;

	// We'll use fprintf here since the messagebus might not be running anymore

    // THIS NEEDS TO BE TIMERED against blocking
    fprintf(stderr, "Sending termination request to channel control child %d...\n",
            chanchild_pid);
    send(sockpair[1], &death_packet, sizeof(chanchild_packhdr) - sizeof(void *), 0);

    // THIS NEEDS TO BE TIMERED TOO
    // At least it should die in 5 seconds from lack of commands if nothing
    // else....
    fprintf(stderr, "Waiting for channel control child %d to exit...\n",
            chanchild_pid);
    wait4(chanchild_pid, NULL, 0, NULL);

    return 1;
#endif
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

// Interrupt handler - we just die.
void ChanChildSignal(int sig) {
    exit(0);
}

// Handle reading channel change requests and driving them
void Packetsourcetracker::ChannelChildLoop() {
    fd_set rset, wset;
    int child_dataframe_only = 0;
    char txtbuf[1024];
   
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, ChanChildSignal);
    
    while (1) {
        int max_fd = 0;

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(sockpair[0], &rset);
        max_fd = sockpair[0];

        // Do we need to send packets?
        if (child_ipc_buffer.size() > 0)
            FD_SET(sockpair[0], &wset);

        struct timeval tm;
        tm.tv_sec = 1;
        tm.tv_usec = 0;

        // Timeout after 1 second to see if we stopped getting commands
        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            // Die violently if select blows itself up
            fprintf(stderr, "FATAL:  Channel control child %d got select() error "
                    "%d:%s\n", getpid(), errno, strerror(errno));
            exit(1);
        }

        // Obey incoming data
        if (FD_ISSET(sockpair[0], &rset)) {
            chanchild_packhdr pak;
            int ret;

            if ((ret = recv(sockpair[0], &pak, sizeof(chanchild_packhdr) - 
							sizeof(void *), 0)) < 0) {
                exit(1);
            }

            if (pak.sentinel != CHANSENTINEL) {
                snprintf(txtbuf, 1024, "capture child %d got IPC frame without valid "
                         "sentinel", getpid());
                child_ipc_buffer.push_front(CreateTextPacket(txtbuf, CHANFLAG_NONE));
                continue;
            }

            // Drop dead
            if (pak.packtype == CHANPACK_DIE || pak.flags & CHANFLAG_FATAL) {
                CloseSources();
                exit(1);
            }
          
            if (pak.packtype == CHANPACK_CMDACK)
                continue;

            // Handle changing channels
            if (pak.packtype == CHANPACK_CHANNEL) {
                chanchild_changepacket chanpak;

                // Just die if we can't receive data
                if (recv(sockpair[0], &chanpak, 
						 sizeof(chanchild_changepacket), 0) < 0)
                    exit(1);

                // Sanity check
                if (chanpak.meta_num >= meta_packsources.size()) {
                    snprintf(txtbuf, 1024, "Channel control got illegal metasource "
							 "number %d", chanpak.meta_num);
                    child_ipc_buffer.push_front(CreateTextPacket(txtbuf, 
																 CHANFLAG_NONE));
                    continue;
                }

				meta_packsource *meta = meta_packsources[chanpak.meta_num];

                // Can this source change the channel?
                if (meta->prototype->channelcon == NULL)
                    continue;

                // Actually change it and blow up if we failed.
                // We pass a void * cast of the instance, which may or may not
                // be valid - channel change stuff has to be smart enough to test
                // for null and report an error accordingly if it uses this
                // data.
				//
				// If a channel has more than N consecutive errors, we actually
				// fail out, send a fatal condition, and die.
                if ((*meta->prototype->channelcon) 
					(globalreg, 
					 meta_packsources[chanpak.meta_num]->device.c_str(), 
                     chanpak.channel, (void *) (meta->capsource)) < 0) {

					meta->consec_errors++;

					if (meta->consec_errors >= MAX_CONSEC_CHAN_ERR) {
						// Push an explanation and the final error
						snprintf(txtbuf, 1024, "Packet source %s (%s) has suffered "
								 "%d consecutive errors setting the channel.  This "
								 "most likely means the drivers have become "
								 "confused.",
								 meta_packsources[chanpak.meta_num]->name.c_str(),
								 meta_packsources[chanpak.meta_num]->device.c_str(),
								 MAX_CONSEC_CHAN_ERR);
						child_ipc_buffer.push_front(CreateTextPacket(txtbuf, 
																	 CHANFLAG_NONE));

						snprintf(txtbuf, 1024, "%s", errstr);
						child_ipc_buffer.push_front(CreateTextPacket(txtbuf, 
																	 CHANFLAG_FATAL));
						continue;
					}
                } else {
					// Otherwise reset the error count
					meta->consec_errors = 0;
				}

                // Acknowledge
                chanchild_packhdr *ackpak = new chanchild_packhdr;

                memset(ackpak, 0, sizeof(chanchild_packhdr));
                ackpak->sentinel = CHANSENTINEL;
                ackpak->packtype = CHANPACK_CMDACK;
                ackpak->flags = CHANFLAG_NONE;
                ackpak->datalen = 1;
                ackpak->data = (uint8_t *) malloc(1);
                ackpak->data[0] = (uint8_t) chanpak.meta_num;
                child_ipc_buffer.push_back(ackpak);

            }
        } 

        // Write a packet - wset should never be set if child_ipc_buffer is empty
        if (FD_ISSET(sockpair[0], &wset)) {
            chanchild_packhdr *pak = child_ipc_buffer.front();

            // Send the header if we didn't already
            if (child_dataframe_only == 0) {
                if (send(sockpair[0], pak, sizeof(chanchild_packhdr) - sizeof(void *), 0) < 0) {
                    if (errno == ENOBUFS)
                        continue;
                    else
                        exit(1);
                } 
            }

            // send the payload if there is one
            if (pak->datalen > 0) {
                if (send(sockpair[0], pak->data, pak->datalen, 0) < 0) {
                    if (errno == ENOBUFS) {
                        child_dataframe_only = 1;
                        continue;
                    } else {
                        exit(1);
                    }
                }
            }

            child_dataframe_only = 0;

            // Blow ourselves away if we just wrote a fatal failure
            if (pak->flags & CHANFLAG_FATAL)
                exit(1);

            child_ipc_buffer.pop_front();
            free(pak->data);
            delete pak;
        }

    }

    exit(1);
}

Packetsourcetracker::chanchild_packhdr *Packetsourcetracker::CreateTextPacket(string in_text, int8_t in_flags) {
    chanchild_packhdr *ret = new chanchild_packhdr;

    memset(ret, 0, sizeof(chanchild_packhdr));
    ret->sentinel = CHANSENTINEL;
    ret->packtype = CHANPACK_TEXT;
    ret->flags = in_flags;
    ret->datalen = in_text.length();
    ret->data = (uint8_t *) strdup(in_text.c_str());

    return ret;
}


