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

#ifndef __PACKETSOURCETRACKER_H__
#define __PACKETSOURCETRACKER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include "globalregistry.h"
#include "timetracker.h"
#include "gpsdclient.h"
#include "packetsource.h"
#include "pollable.h"
#include "ipc_remote.h"

// Maximum number of consecutive failures before we die
#define MAX_CONSEC_CHAN_ERR		5

// Pre-prototype
class Packetsourcetracker;

// Packet source prototype for building an instance
typedef struct {
    int id;
    string cardtype;
    int root_required;
    string default_channelset;
    int initial_channel;
	packsource_autoprobe autoprobe;
    packsource_registrant registrant;
    packsource_monitor monitor_enable;
    packsource_monitor monitor_disable;
    packsource_chcontrol channelcon;
    int child_control;
	// Failure tracking to allow conditional failing
	int n_failures;
	time_t last_failure;
} packsource_protorec;

// Meta packetsource for handling created packetsources, channel control, etc
// Needs to contain all the information needed to control the packetsource without
// having a valid instance of that packetsource - the root channel control process
// has to be able to control sources not opened until user-time
class meta_packsource {
public:
    int id;
    int valid;

    // Channel control
    int cmd_ack;
    int channel_seqid;
    vector<int> channels;
    int ch_pos;
    int ch_hop;
    int cur_ch; 

    // Capsource prototype
    packsource_protorec *prototype;

    // Capsource name
    string name;
    // Card device
    string device;

    // Actual packetsource
    KisPacketSource *capsource;

    // Interface settings to store
    void *stored_interface;

	// Consecutive errors doing something
	int consec_errors;
};

// Packetchain reference for packet sources to be attached to the 
// item captured
class kis_ref_capsource : public packet_component {
public:
	KisPacketSource *ref_source;

	kis_ref_capsource() {
		self_destruct = 1; // We're just a ptr container
		ref_source = NULL;
	}

	~kis_ref_capsource() { };
};

// Channel control event
int ChannelHopEvent(TIMEEVENT_PARMS);

// Internal NULL packet source that's always present to remind the users to configure
// the software
class NullPacketSource : public KisPacketSource {
public:
    NullPacketSource(GlobalRegistry *in_globalreg, meta_packsource *in_meta,
					 string in_name, string in_dev) : 
        KisPacketSource(in_globalreg, in_meta, in_name, in_dev) { }
	virtual ~NullPacketSource() { }

    virtual int OpenSource() {
        char errstr[STATUS_MAX];
        snprintf(errstr, 1024, "Please configure at least one packet source.  "
                 "Kismet will not function if no packet sources are defined in "
                 "kismet.conf or on the command line.  Please read the README "
                 "for more information about configuring Kismet.");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    virtual int CloseSource() {
        return 1;
    }

    virtual int FetchDescriptor() {
        return -1;
    }

    virtual int FetchChannel() {
        return -1;
    }

	virtual int Poll() {
		return -1;
	}

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { }
};

KisPacketSource *nullsource_registrant(REGISTRANT_PARMS);
int unmonitor_nullsource(MONITOR_PARMS);

// Shortcut for registering uncompiled sources
#define REG_EMPTY_CARD(y) RegisterPacketsource(y, 0, "na", 0, \
                                               NULL, NULL, NULL, NULL, NULL, 0)

class Packetsourcetracker : public Pollable {
public:
    Packetsourcetracker(GlobalRegistry *in_globalreg);
    virtual ~Packetsourcetracker();

	// Handle the commandline and config file and load cards (has to be outside
	// of constructor to make plugins able to insert capture types)
	int LoadConfiguredCards();

    // Merge descriptors into a set
    unsigned int MergeSet(unsigned int in_max_fd, fd_set *out_rset, 
						  fd_set *out_wset);

    // Poll the socket for command acks and text.
    // Text gets put in errstr with a return code > 0.
    int Poll(fd_set& in_rset, fd_set& in_wset);

    // Fetch a meta record for an id
    meta_packsource *FetchMetaID(int in_id);
    // Set the channel
    int SetChannel(int in_ch, meta_packsource *in_meta);
    // Control if a metasource hops or not
    int SetHopping(int in_hopping, meta_packsource *in_meta);
    // Advance all the sources one channel
    int AdvanceChannel();

	// State fetches
	int FetchChannelHop() { return channel_hop; }
	int FetchChannelSplit() { return channel_split; }
	int FetchChannelDwell() { return channel_dwell; }
	int FetchChannelVelolcity() { return channel_velocity; }

    // Register a packet prototype source...  Card type string, root binding 
	// requirement, function to generate an instance of the source, and function to 
	// change channel.  This fills out the prototype. Sources that don't hop 
    // should request a default channelset of "none"
    // Turning off child control puts the channel changing into the core of the
    // server.  This isn't really a good thing to do, but one source (viha)
    // requires it.
    int RegisterPacketsource(const char *in_cardtype, int in_root, 
                             const char *in_defaultchanset, int in_initch, 
							 packsource_autoprobe in_autoprobe,
                             packsource_registrant in_registrant, 
                             packsource_monitor in_monitor,
                             packsource_monitor in_unmonitor,
                             packsource_chcontrol in_channelcon,
                             int in_childcontrol);

    // Register default channels 
    int RegisterDefaultChannels(vector<string> *in_defchannels);

    // Spawn root child channel control process
    int SpawnChannelChild();

    // Do a clean termination of the channel child (blocking)
    int ShutdownChannelChild();

    // Return a vector of packet sources for other things to process with 
	// (this should be self-contained in the future, probably)
    vector<KisPacketSource *> FetchSourceVec();
    vector<meta_packsource *> FetchMetaSourceVec();
   
    // Build the meta-packsource records from the requested configs provided either 
    // by the config file or the command line options.  
    // enableline: vector of source names to be enabled
    // cardlines: vector of config lines defining actual capture sources,
    // sourcechannels: vector of config lines defining explicit channel sequences 
    // for a source 
    // chhop: Is hopping enabled globally
    // chsplit: Are channel allocations split across multiple interfaces?
    int ProcessCardList(string in_enableline, vector<string> *in_cardlines, 
                        vector<string> *in_sourcechannels, 
                        vector<string> *in_initchannels,
                        int& in_chhop, int in_chsplit);

    // Bind to sources.  in_root == 1 when binding root sources, obviosuly
    int BindSources(int in_root);

    // Pause/unpause our sources
    int PauseSources();
    int ResumeSources();
    
    // Release sources, disabling monitor if possible
    int CloseSources();

	// Blit out what we know about
	void BlitCards(int in_fd);

	// Usage
	static void Usage(char *name);

protected:
    // IPC data frame to set a channel
    typedef struct {
        uint16_t meta_num;
        uint16_t channel;
    } chanchild_changepacket;

	// Local card set used by the ipc callback
    int SetIPCChannel(int in_ch, unsigned int meta_num);
	// Shutdown all sources (actually do the work)
	int ShutdownIPCSources();

    GlobalRegistry *globalreg;

	int card_protoref;
	int hop_eventid;
	int card_eventid;
    
    int next_packsource_id;
    int next_meta_id;

    map<string, packsource_protorec *> cardtype_map;
    map<string, vector<int> > defaultch_map;

	// State stuff
	int channel_hop;
	int channel_split;
	int channel_dwell;
	int channel_velocity;

	char errstr[1024];
	
    // We track this twice so we don't have to convert the meta_packsource into 
    // a packsource vec every loop
    vector<meta_packsource *> meta_packsources;
    vector<KisPacketSource *> live_packsources;

	IPCRemote *chan_remote;
	uint32_t chan_ipc_id;
	uint32_t haltall_ipc_id;

	friend int ChannelHopEvent(TIMEEVENT_PARMS);
	friend int packsrc_chan_ipc(IPC_CMD_PARMS);
	friend int packsrc_haltall_ipc(IPC_CMD_PARMS);
};

enum CARD_fields {
    CARD_interface, CARD_type, CARD_username, CARD_channel, CARD_id, CARD_packets,
    CARD_hopping,
	CARD_maxfield
};
extern char *CARD_fields_text[];

int Protocol_CARD(PROTO_PARMS);
void Protocol_CARD_enable(PROTO_ENABLE_PARMS);

#endif

