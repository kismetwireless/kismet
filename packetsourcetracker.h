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

// Callback for actions on sources.  Gives the source and action type, flags,
// and an arbitrary pointer.
#define SOURCEACT_PARMS GlobalRegistry *globalreg, KisPacketSource *src, \
	int action, int flags, void *auxptr
typedef void (*SourceActCallback)(SOURCEACT_PARMS);
// Various actions.  Adding, deleting, hop setting, vector setting
#define SOURCEACT_ADDSOURCE 	0
#define SOURCEACT_DELSOURCE		1
#define SOURCEACT_HOPSET		2
#define SOURCEACT_CHVECTOR		3

// Packet source prototype used to create new packetsources from string
// definitions
typedef struct {
	// Part of both the initial build of sources we understand, and the second
	// build of sources we're going to create
	string type;
    int root_required;
    string default_channelset;
    int initial_channel;
	// "weak" packetsource instance used to generate the real packet source
	KisPacketSource *weak_source;

	// This is used in the second run of prototyping, used to build the vector
	// of sources we're going to allocate strong versions of
	string name, interface;
	// Channels to push to the source
	vector<int> channel_vec;
	// Offset to the channel vec to push (for multisource stuff)
	int cv_offset;
	// ID of the channel vec (for calculating offset & # of sources using this vec)
	int channelvec_id;
	// Does this specific interface have a hop/nothop set?
	int interface_hop;
} packsource_protorec;

// Channel control event
int ChannelHopEvent(TIMEEVENT_PARMS);

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

	// Explicit channel control of sources
	
    // Set the channel
    int SetChannel(int in_ch, uuid in_uuid);
	// Set a channel sequence
	int SetChannelSequence(vector<int> in_seq, uuid in_uuid);
	// Control if a source hops or not
    int SetHopping(int in_hopping, uuid in_uuid);

    // Advance all the sources one channel
    int AdvanceChannel();

	// State fetches
	int FetchChannelHop() { return channel_hop; }
	int FetchChannelSplit() { return channel_split; }
	int FetchChannelDwell() { return channel_dwell; }
	int FetchChannelVelolcity() { return channel_velocity; }

	// Add a weak packet source to the system.  This queues it for being
	// asked to register its source types and be available for autoprobe,
	// etc.
	int AddKisPacketsource(KisPacketSource *in_source);

	// Add a live precreated packetsource to the system.  This takes a strong
	// packet source.
	int RegisterLiveKisPacketsource(KisPacketSource *in_livesource);
	// Remove a packet source from the system
	int RemoveLiveKisPacketsource(KisPacketSource *in_livesource);
	// Add a callback for notifying external elements when a packet source is added
	int RegisterSourceActCallback(SourceActCallback in_cb, void *in_aux);
	int RemoveSourceActCallback(SourceActCallback in_cb);

	// Register a packet source:  (this should be called by the PacketSource
	// AddSources(...) function
	// This expects a "weak" instance of the packetsource (see packetsource.h),
	// indications if it requires root privs for setup, the default channel
	// set name, initial channel, and if it can be controlled by a child process
	// Turning off child control indicates that it has to be controlled from the
	// master process.  this prevents privsep, but some things require it
    int RegisterPacketsource(const char *in_cardtype, 
							 KisPacketSource *in_weaksource,
							 int in_root, 
                             const char *in_defaultchanset, int in_initch);
	int RemovePacketsource(const char *in_cardtype);

    // Register default channels
    int RegisterDefaultChannels(vector<string> *in_defchannels);

    // Return a vector of packet sources for other things to process with 
	// (this should be self-contained in the future, probably)
    vector<KisPacketSource *> FetchSourceVec();
  
	// Buiild the packetsources from the requested config file and cmdline
	// options
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

    // Bind to sources.  in_root == 1 when binding root sources, obviously
    int BindSources(int in_root);

    // Pause/unpause all sources
    int PauseSources();
    int ResumeSources();
    
    // Release sources, disabling monitor if possible
    int CloseSources();

	// Blit out what we know about
	void BlitCards(int in_fd);

	// Find a source by the UUID
	KisPacketSource *FindUUID(uuid in_id);

	// Usage
	static void Usage(char *name);

	typedef struct {
		SourceActCallback cb;
		void *auxdata;
	} sourceactcb_rec;

protected:
	// Client commands
	int cmd_chanlock(CLIENT_PARMS);
	int cmd_chanhop(CLIENT_PARMS);
	int cmd_pause(CLIENT_PARMS);
	int cmd_resume(CLIENT_PARMS);

	friend int Clicmd_CHANHOP_hook(CLIENT_PARMS);
	friend int Clicmd_CHANLOCK_hook(CLIENT_PARMS);
	friend int Clicmd_RESUME_hook(CLIENT_PARMS);
	friend int Clicmd_PAUSE_hook(CLIENT_PARMS);
	
    // IPC data frame to set a channel
    typedef struct {
        uint16_t meta_num;
        uint16_t channel;
    } chanchild_changepacket;

	// High-level channel setting dispatcher that calls the packetsource
	// directly or dispatches it to IPC
	int SetChannel(int in_ch, KisPacketSource *src);
	// Local card set used by the ipc callback
    int SetIPCChannel(int in_ch, unsigned int meta_num);
	// Shutdown all sources (actually do the work)
	int ShutdownIPCSources();

    GlobalRegistry *globalreg;

	int card_protoref;
	int hop_eventid;
	int card_eventid;
    
	int cmdid_chanlock, cmdid_chanhop, cmdid_pause, cmdid_resume;

	// Callbacks for adding a source
	vector<Packetsourcetracker::sourceactcb_rec *> cb_vec;

    map<string, packsource_protorec *> cardtype_map;
    map<string, vector<int> > defaultch_map;

	// State stuff
	int channel_hop;
	int channel_split;
	int channel_dwell;
	int channel_velocity;

	char errstr[1024];

	// Intermediary of prototype sources and weak mappings used to finally
	// generate the full live sources.  This is populated by processcardlist
	vector<packsource_protorec *> prebuild_protosources;

	// All live packet sources
    vector<KisPacketSource *> live_packsources;

	// UUIDs to live packetsources
	map<uuid, KisPacketSource *> ps_map;

	uint32_t chan_ipc_id;
	uint32_t haltall_ipc_id;

	friend int ChannelHopEvent(TIMEEVENT_PARMS);
	friend int packsrc_chan_ipc(IPC_CMD_PARMS);
	friend int packsrc_haltall_ipc(IPC_CMD_PARMS);
};

// Internal NULL packet source that's always present to remind the users to configure
// the software
class NullPacketSource : public KisPacketSource {
public:
	NullPacketSource() {
		fprintf(stderr, "FATAL OOPS: NullPacketSource() called\n");
		exit(1);
	}

	NullPacketSource(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {
	}

	virtual NullPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										   string in_type, string in_name,
										   string in_dev) {
		return new NullPacketSource(in_globalreg, in_type, in_name,
									in_dev);
	}

	virtual ~NullPacketSource() { }

	NullPacketSource(GlobalRegistry *, string, string, string) {
		// Nothing here either
	}

    virtual int OpenSource() {
		_MSG("You must configure at least one packet source.  Kismet will not "
			 "function if no packet sources are defined in kismet.conf or on "
			 "the command line.  Please read the README for more information "
			 "on how to configure Kismet.", MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    virtual int CloseSource() { return 1; }
	virtual int AutotypeProbe(string in_device) { return 0; }

	virtual int RegisterSources(Packetsourcetracker *tracker) {
		tracker->RegisterPacketsource("none", this, 0, "n/a", 0);
		return 1;
	}

    virtual int FetchDescriptor() { return -1; }
	virtual int FetchChannelCapable() { return -1; }
    virtual int FetchChannel() { return -1; }
	virtual int Poll() { return -1; }
	virtual int EnableMonitor() { return -1; }
	virtual int DisableMonitor() { return -1; }
	virtual int ChildIPCControl() { return 0; }
	virtual int SetChannel(int) { return -1; }
	virtual int SetChannelSequence(vector<int> in_seq) { return -1; }
	virtual int HopNextChannel() { return -1; }

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { }
};


enum CARD_fields {
    CARD_interface, CARD_type, CARD_username, CARD_channel, 
	CARD_uuid, CARD_packets, CARD_hopping,
	CARD_maxfield
};
extern char *CARD_fields_text[];

int Protocol_CARD(PROTO_PARMS);
void Protocol_CARD_enable(PROTO_ENABLE_PARMS);

// Network commands
int Clicmd_CHANLOCK_hook(CLIENT_PARMS);
int Clicmd_CHANHOP_hook(CLIENT_PARMS);
int Clicmd_PAUSE_hook(CLIENT_PARMS);
int Clicmd_RESUME_hook(CLIENT_PARMS);

#endif

