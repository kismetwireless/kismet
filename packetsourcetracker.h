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

// Sentinel for starting a new packet
#define CHANSENTINEL      0xDECAFBAD

// What type of frame it is in the child datagram
#define CHANPACK_CHANNEL  1
#define CHANPACK_TEXT     2
#define CHANPACK_CMDACK   3
#define CHANPACK_DIE      254

// What sort of extra info can we carry with the text?
#define CHANFLAG_NONE     0
#define CHANFLAG_FATAL    1

// Pre-prototype
class Packetsourcetracker;

// Packet source prototype for building an instance
typedef struct {
    int id;
    string cardtype;
    int root_required;
    string default_channelset;
    int initial_channel;
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
typedef struct {
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
} meta_packsource;

// Messagebus client to intercept messages from the forked client 
class Packetcontrolchild_MessageClient : public MessageClient {
public:
    Packetcontrolchild_MessageClient(GlobalRegistry *in_globalreg) :
        MessageClient(in_globalreg) { };
    void ProcessMessage(string in_msg, int in_flags);
};

// Packetchain reference for packet sources to be attached to the 
// item captured
class kis_ref_capsource {
public:
	KisPacketSource *ref_source;

	kis_ref_capsource() {
		ref_source = NULL;
	}

	~kis_ref_capsource() { };
};

// Channel control event
int ChannelHopEvent(Timetracker::timer_event *evt, void *parm, 
					GlobalRegistry *globalreg);

// Internal NULL packet source that's always present to remind the users to configure
// the software
class NullPacketSource : public KisPacketSource {
public:
    NullPacketSource(GlobalRegistry *in_globalreg, string in_name, string in_dev) : 
        KisPacketSource(in_globalreg, in_name, in_dev) { }

    int OpenSource() {
        char errstr[STATUS_MAX];
        snprintf(errstr, 1024, "Please configure at least one packet source.  "
                 "Kismet will not function if no packet sources are defined in "
                 "kismet.conf or on the command line.  Please read the README "
                 "for more information about configuring Kismet.");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    int CloseSource() {
        return 1;
    }

    int FetchDescriptor() {
        return -1;
    }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
        return -1;
    }

    int FetchChannel() {
        return -1;
    }
};
KisPacketSource *nullsource_registrant(REGISTRANT_PARMS);
int unmonitor_nullsource(MONITOR_PARMS);

// Shortcut for registering uncompiled sources
#define REG_EMPTY_CARD(y) RegisterPacketsource(y, 0, "na", 0, \
                                               NULL, NULL, NULL, NULL, 0)

class Packetsourcetracker : public Pollable {
public:

    Packetsourcetracker(GlobalRegistry *in_globalreg);
    ~Packetsourcetracker();

    // Merge descriptors into a set
    unsigned int MergeSet(unsigned int in_max_fd, fd_set *out_rset, 
						  fd_set *out_wset);

    // Return the pid of the channel control child
    pid_t FetchChildPid() { return chanchild_pid; }

    // Poll the socket for command acks and text.
    // Text gets put in errstr with a return code > 0.
    int Poll(fd_set *in_rset, fd_set *in_wset);

    // Fetch a meta record for an id
    meta_packsource *FetchMetaID(int in_id);
    // Set the channel
    int SetChannel(int in_ch, meta_packsource *in_meta);
    // Control if a metasource hops or not
    int SetHopping(int in_hopping, meta_packsource *in_meta);
    // Advance all the sources one channel
    int AdvanceChannel();

    // Register a packet prototype source...  Card type string, root binding requirement,
    // function to generate an instance of the source, and function to change channel 
    // for this card type.  This fills out the prototype. Sources that don't hop 
    // should request a default channelset of "none"
    // Turning off child control puts the channel changing into the core of the
    // server.  This isn't really a good thing to do, but one source (viha)
    // requires it.
    int RegisterPacketsource(const char *in_cardtype, int in_root, 
                             const char *in_defaultchanset, int in_initch, 
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

    // Return a vector of packet sources for other things to process with (this should be
    // self-contained in the future, probably)
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

    // Turn on parameters for a vector of card types (kluge for fuzzycrypt,
    // maybe do this better later...)
    int SetTypeParms(string in_types, packet_parm in_parm);

    // Pause/unpause our sources
    int PauseSources();
    int ResumeSources();
    
    // Release sources, disabling monitor if possible
    int CloseSources();

protected:
    // IPC packet header - All is sent besides the data pointer
    typedef struct {
        uint32_t sentinel;
        uint8_t packtype;
        int8_t flags;
        int32_t datalen;
        uint8_t *data;
    } chanchild_packhdr;

    // IPC data frame to set a channel
    typedef struct {
        // If anyone ever needs more than 256 sources on one capture server, let me
        // know, until then...
        uint8_t meta_num;
        uint16_t channel;
    } chanchild_changepacket;

    GlobalRegistry *globalreg;
    
    char errstr[1024];

    pid_t chanchild_pid;

    // outbound packets
    list<chanchild_packhdr *> ipc_buffer;
    list<chanchild_packhdr *> child_ipc_buffer;
    int dataframe_only;
    
    int next_packsource_id;
    int next_meta_id;

    map<string, packsource_protorec *> cardtype_map;
    map<string, vector<int> > defaultch_map;

    // We track this twice so we don't have to convert the meta_packsource into 
    // a packsource vec every loop
    vector<meta_packsource *> meta_packsources;
    vector<KisPacketSource *> live_packsources;

    int sockpair[2];

    // Core of the channel control child process
    void ChannelChildLoop();

    // Generate a text packet
    chanchild_packhdr *CreateTextPacket(string in_text, int8_t in_flags);

    friend class Packetcontrolchild_MessageClient;
    friend int ChannelHopEvent(Timetracker::timer_event *evt, 
                               void *parm, GlobalRegistry *globalreg);
};

#endif

