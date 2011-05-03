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
#include <errno.h>

#include "globalregistry.h"
#include "timetracker.h"
#include "packetsource.h"
#include "pollable.h"
#include "ipc_remote.h"
#include "kis_pktproto.h"

/*
 * Core of the packet tracking subsystem
 *
 * Packet source types are registered by passing a "weak" variant of the class 
 * (instantiated packetsource without bindings to the actual source or polling
 * functions) which provides the necessary info for deriving "strong" packet sources
 * which are bound to interfaces and operate normally.
 *
 * Initial config parsing (sources and channels) is done by the user system.
 *
 * Root packet sources are handled by a spawned root binary which passes packets and
 * state back via IPC frames.  Root sources must be communicated to the IPC system,
 * and state changes pushed across.
 *
 * All packetsource ops should be non-fatal, and return error conditions.  
 * PST will decide if the operation is fatal (config file source type doesn't exist,
 * etc) or non-fatal (dynamically added sources get a pass for being broken)
 *
 */

// Maximum number of consecutive errors setting a channel before we consider this
// to be a failure condition
#define MAX_CONSEC_CHAN_ERR		5

// Channel record
struct pst_channel {
	// Control options; phy/source dependent, ex. HT20, HT40+/-
	int control_flags;

	// are we a range
	int range;

	union {
		// Frequency/dwell pair
		struct {
			unsigned int channel;
			unsigned int dwell;
		} chan_t;

		// Range defintion plus local counter
		struct {
			unsigned int start;
			unsigned int end;
			unsigned int width;
			unsigned int iter;
		} range_t;
	} u;
};

struct pst_channellist {
	// Channel list ID (for ipc)
	uint16_t channel_id;

	string name;

	int auto_generated;

	vector<pst_channel> channel_vec;
};

struct pst_protosource {
	string type;
	KisPacketSource *weak_source;
	string default_channelset;
	int require_root;
};

// Packetsource tracking record
struct pst_packetsource {
	// Source ID for IPC
	uint16_t source_id;
	
	// We need this if we don't have a strong source
	string interface;

	// Should we not go over IPC?  Most things should.
	int local_only;

	// Source definition
	string sourceline;

	// Prototype we were built from
	pst_protosource *proto_source;

	// Local strong packet source (even for remote sources, we need a process-local
	// strong source which has interpreted all the options for us
	KisPacketSource *strong_source;

	// Channel list we've assigned
	uint16_t channel_list;

	// Pointer to channel list
	pst_channellist *channel_ptr;

	// Specific channel if we're not hopping
	uint16_t channel;

	// Per-source hop, dwell, and rate
	int channel_hop;
	int channel_dwell;
	int channel_rate;
	int channel_split;

	int dwell_timer;
	int rate_timer;

	// Position in list, initialized by source splitting
	int channel_position;
	int range_position;

	// Number of consec channel set errors
	int consec_channel_err;

	struct timeval tm_hop_start;

	struct timeval tm_hop_time;

	// Are we in error state?
	int error;

	// Do we re-open on error?
	int reopen;

	// How many zero-polls have we had in a row?
	int zeropoll;

	// Do we have a PST-tracker level warning?
	string warning;
};

// Callback for actions on sources.  Gives the source and action type, flags,
// and an arbitrary pointer.
#define SOURCEACT_PARMS GlobalRegistry *globalreg, pst_packetsource *src, \
	int action, int flags, void *auxptr
typedef void (*SourceActCallback)(SOURCEACT_PARMS);

// Various actions.  Adding, deleting, hop setting, vector setting
#define SOURCEACT_ADDSOURCE 	0
#define SOURCEACT_DELSOURCE		1
#define SOURCEACT_HOPENABLE		2
#define SOURCEACT_HOPDISABLE	3
#define SOURCEACT_CHVECTOR		4
#define SOURCEACT_CHHOPDWELL	5

class Packetsourcetracker : public Pollable {
public:
	Packetsourcetracker(GlobalRegistry *in_globalreg);
	virtual ~Packetsourcetracker();

	// Bind an IPC helper (as parent or child)
	void RegisterIPC(IPCRemote *in_ipc, int in_as_ipc);

	// Help
	static void Usage(char *name);

	// Pollable system handlers
	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
	virtual int Poll(fd_set &in_rset, fd_set& in_wset);

	// Register a packet source type (pass a weak source)
	int RegisterPacketSource(KisPacketSource *in_weak);

	// Register a packet prototype (called by source registration)
	int RegisterPacketProto(string in_type, KisPacketSource *in_weak,
							string in_defaultchan, int in_root);

	// Add a packet source, get back a reference ID
	// ncsource=interface,[opt=val]+
	// ie ncsource=wlan0,name=foobar,type=iwl4965
	//
	// The packet source will be sent immediately upon parsing to the IPC process.
	// If a strong source is passed (instead of NULL) the type matching will be
	// bypassed and the strong source assigned.  This should only be used for
	// dynamic sources added locally (such as the drone code)
	int AddPacketSource(string in_source, KisPacketSource *in_strong,
						uint16_t *source_id);

	int RemovePacketSource(pst_packetsource *in_source);

	// Add a run-time packet source & wrap the internal AddPacketsource to return
	// an error code instead of an internal sourcenum. The optional strong source will
	// be used instead of resolving the source from the list of source types, and
	// the source will be activated (locally if a strong source is passed, remotely
	// if not)
	int AddLivePacketSource(string in_source, KisPacketSource *in_strong);

	//  Manipulate sources based on strong pointers
	int RemoveLivePacketSource(KisPacketSource *in_strong);
	pst_packetsource *FindLivePacketSource(KisPacketSource *in_strong);
	pst_packetsource *FindLivePacketSourceUUID(uuid in_uuid);
	KisPacketSource *FindKisPacketSourceUUID(uuid in_uuid);

	// Find source by name
	pst_packetsource *FindLivePacketSourceName(string name);

	// Actually load the configuration
	int LoadConfiguration();

	// Create IPC-local data from IPC setup frames
	int IpcAddChannelList(ipc_source_add_chanlist *in_ipc);
	int IpcAddPacketsource(ipc_source_add *in_ipc);
	int IpcChannelSet(ipc_source_chanset *in_ipc);
	int IpcSourceReport(ipc_source_report *in_ipc);
	int IpcSourceRun(ipc_source_run *in_ipc);
	int IpcSourceRemove(ipc_source_remove *in_ipc);
	int IpcPacket(ipc_source_packet *in_ipc);
	int IpcChannelReport(ipc_source_chanreport *in_ipc);

	int StartSource(uint16_t in_source_id);
	int StopSource(uint16_t in_source_id);

	// Add a callback for notifying external elements when a packet source is added
	int RegisterSourceActCallback(SourceActCallback in_cb, void *in_aux);
	int RemoveSourceActCallback(SourceActCallback in_cb);

	// Change a source between hopping and non-hopping (within the same channel set)
	int SetSourceHopping(uuid in_uuid, int in_hopping, uint16_t in_channel);
	// Change a source to a newly defined channel list
	int SetSourceNewChannellist(uuid in_uuid, string in_channellist);
	// Change a source hop/dwell settings
	int SetSourceHopDwell(uuid in_uuid, int in_rate, int in_dwell);

	// Low-level hook to dig into all the packet sources, for stuff like Drone
	// to function properly
	vector<pst_packetsource *> *FetchSourceVec() { return &packetsource_vec; }

	pst_channellist *FetchSourceChannelList(pst_packetsource *in_src);

	void ChannelTimer();
	void OpenTimer();

	// Packet chain to IPC / DLT demangle
	void ChainHandler(kis_packet *in_pack);

	typedef struct {
		SourceActCallback cb;
		void *auxdata;
	} sourceactcb_rec;

	// Network protocol stuff
	void BlitSources(int in_fd);
	void BlitProtoSources(int in_fd);

	// Network commands
	int cmd_ADDSOURCE(int, KisNetFramework *, char *, string, 
					  vector<smart_word_token> *);
	int cmd_DELSOURCE(int, KisNetFramework *, char *, string, 
					  vector<smart_word_token> *);
	int cmd_RESTARTSOURCE(int, KisNetFramework *, char *, string, 
						  vector<smart_word_token> *);
	int cmd_HOPSOURCE(int, KisNetFramework *, char *, string, 
					  vector<smart_word_token> *);
	int cmd_CHANLIST(int, KisNetFramework *, char *, string,
					 vector<smart_word_token> *);

	// Fetch and clear the channel time map
	map<uint32_t, int> *FetchChannelTickMap() {
		return &channel_tick_map;
	}

	void ClearChannelTickMap() {
		channel_tick_map.clear();
	}

	// Add a channel list, get back a reference ID (ie, for IPC)
	// channels=name,chan[:dwell]+
	// ie channels=dot11g,1:5,2,3,4,5,6:5,7,8,9,10,11:5
	//
	// The channel list will be sent immediately upon parsing to the IPC process
	uint16_t AddChannelList(string in_chanlist);

	// Generate a channel list from a vector (ie hw channel from the protosource);
	// Compare with other autogenerated channel lists and figure out if we have
	// an overlap and return the overlapped sources if we do
	uint16_t GenChannelList(vector<unsigned int> in_channellist);

protected:
	void SendIPCSourceAdd(pst_packetsource *in_source);
	void SendIPCChannellist(pst_channellist *in_list);
	void SendIPCReport(pst_packetsource *in_source);
	void SendIPCStart(pst_packetsource *in_source);
	void SendIPCStop(pst_packetsource *in_source);
	void SendIPCChanset(pst_packetsource *in_source);
	void SendIPCRemove(pst_packetsource *in_source);
	void SendIPCPacket(kis_packet *in_packet, kis_datachunk *in_linkchunk);
	void SendIPCChanreport();

	GlobalRegistry *globalreg;
	IPCRemote *rootipc;

	int source_ipc_id, channellist_ipc_id, channel_ipc_id,
		report_ipc_id, run_ipc_id, remove_ipc_id, sync_ipc_id,
		packet_ipc_id, chanreport_ipc_id, stop_ipc_id;

	int cmd_addsource_id, cmd_delsource_id, cmd_restartsource_id,
		cmd_hopsource_id, cmd_channellist_id;

	int running_as_ipc;

	uint16_t next_source_id;
	uint16_t next_channel_id;

	// Values before they are overridden by the local hop
	int default_channel_rate;
	int default_channel_dwell;

	int channel_time_id, proto_source_time_id, open_time_id;
	int source_protoref;

	int timer_counter;

	// List of prototype source, we don't need a map (saves on ram and binary,
	// to some extent)
	vector<pst_protosource *> protosource_vec;
	pst_protosource *broken_proto;

	// Map of ID to strong packet sources we've made
	map<uint16_t, pst_packetsource *> packetsource_map;
	// Because iterating maps is super slow
	vector<pst_packetsource *> packetsource_vec;

	vector<string> named_vec;

	// Map of channel IDs
	map<uint16_t, pst_channellist *> channellist_map;

	// Callbacks for adding a source
	vector<Packetsourcetracker::sourceactcb_rec *> cb_vec;

	// Number of ticks we've spent per channel in the past second
	map<uint32_t, int> channel_tick_map;

	// Preferred channels
	vector<unsigned int> preferred_channels;
};

#endif

