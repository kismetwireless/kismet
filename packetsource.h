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

#ifndef __PACKETSOURCE_H__
#define __PACKETSOURCE_H__

#include "config.h"

#include <string>
#include <errno.h>

#include "util.h"
#include "uuid.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "packet.h"
#include "timetracker.h"
#include "gpsdclient.h"
#include "configfile.h"
#include "packetchain.h"
#include "getopt.h"

// Packet capture source superclass
// This defines the methods used to go in and out of monitor mode, channel 
// control, and manages the lists of channels this source will hop to.
//
// This class will become somewhat absurdly subclassed at times.  This is
// a necessary evil, and better than the previous method of having tons of
// random C function pointers to do work with no coherent ties to the class
// itself.
//
// The constructor is passed the type, name, and device from the source=
// line (or is manually built).
//
// Packet sources are not themselves pollable items.  They are monitored and
// called via the packetsourcetracker.
//
// Packet sources can exist in multiple processes:  A defined but not opened
// source is created before the fork() for IPC controls.
//
// Packet sources are registered as a new object w/ no parameters, which is
// used to later generate the real packetsource via CreateSource(...)
//
// What that boils down to is:
// 1. A subclass should provide the CreateSource(...) function, which returns
//    a new Subclass(...);
// 2. A class should blow up on the new() operator and assign GlobalReg on the
//    new(GlobalRegistry *) opertor
// 3. A class should provide the RegisterSources(...) function in such a way
//    that it works on a generic/weak instance
// 4. A class should provide the AutotypeProbe(...) function in such a way
//    that it can be called on a generic instance (ie, one made with new() )
//    It should return 1 or 0 for "claimed as this type" or "not claimed"

// Forward definition of sourcetracker for the RegisterPacketSource function
class Packetsourcetracker;

// Return code definitions for DisableMonitor (since we want to tell the 
// sourcetracker how to report errors.  Negative returns are always an error.)

// Say nothing -- we don't do anything to a source that requires the warning
// (like pcapfile)
#define PACKSOURCE_UNMONITOR_RET_SILENCE		0
// We unmonitored OK but print a friendly warning anyhow
#define PACKSOURCE_UNMONITOR_RET_OKWITHWARN		1
// We can't unmonitor this source, but it isn't a fatal error
#define PACKSOURCE_UNMONITOR_RET_CANTUNMON		2

// Parmeters to the packet info.  These get set by the packet source controller
// so they need to go here.  Every packet source shares these generic types, but
// they may have more specifc types of their own as well.  Only generic types
// can be used by other components
typedef struct packet_parm {
	packet_parm() {
		fuzzy_crypt = 0;
		weak_dissect = 0;
		legal_paranoia = 0;
	}

    int fuzzy_crypt;
	int weak_dissect;
	int legal_paranoia;
};

class KisPacketSource {
public:
	// This is still bad, even for weak sources
	KisPacketSource() {
		fprintf(stderr, "FATAL OOPS:  KisPacketSource() with no parameters\n");
		exit(1);
	}

	// ------------ WEAK PACKETSOURCE -----------------
	KisPacketSource(GlobalRegistry *in_globalreg) {
		// Nothing happens here.  This just lets us new() a weak packetsource
		// used for calling CreateSource(...) and RegisterSources(...)
		// We just grab globalreg so that we can generate messages
		globalreg = in_globalreg;
	}

	// This should return a new object of its own subclass type
	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_type, string in_name, 
										  string in_dev) = 0;

	virtual int RegisterSources(Packetsourcetracker *tracker) = 0;
	virtual int AutotypeProbe(string in_device) = 0;

	// ------------ STRONG PACKETSOURCE -----------------
	// (all of these assume globalreg exists, type name etc filled in
	
    KisPacketSource(GlobalRegistry *in_globalreg, string in_type, 
					string in_name, string in_dev) {
        name = in_name;

		/*
		vector<string> ifv = StrTokenize(in_dev, ":");
		if (ifv.size() < 2) {
			interface = in_dev;
			interface2 = "";
		} else {
			interface = ifv[0];
			interface2 = ifv[1];
		}
		*/

		interface = in_dev;
		type = in_type;
		
        globalreg = in_globalreg;

		// This is mostly just crap.  Hash the type and name, then
		// hash the device, and make a 6 byte field out of it to seed
		// the device attribute.  If a subclass wants to seed this with the MAC 
		// of the capture source in the future, thats fine too
		uint8_t unode[6];
		uint32_t unode_hash;
		string combo = in_type + in_name;
		unode_hash = Adler32Checksum(combo.c_str(), combo.length());
		memcpy(unode, &unode_hash, 4);
		unode_hash = Adler32Checksum(in_dev.c_str(), in_dev.length());
		memcpy(&(unode[4]), &unode_hash, 2);
		src_uuid.GenerateTimeUUID(unode);
        
        fcsbytes = 0;
		validate_fcs = 0;
		crc32_table = NULL;
		carrier_set = 0;

		channel_hop = 0;
		channel_pos = 0;
		consec_error = 0;
		initial_channel = 0;

		num_packets = 0;

		const int soc = globalreg->getopt_long_num++;
		static struct option kissource_long_options[] = {
			{ "source-options", required_argument, 0, soc },
			{ 0, 0, 0, 0 }
		};
		int option_idx = 0;

		// It seems like a bad idea to put this much into a function in a 
		// header file, but it would have to change anyhow to update the
		// struct
		// Grab the raw options from the config file
		vector<string> rawopts = globalreg->kismet_config->FetchOptVec("sourceopts");
		// Grab the command line options
		optind = 0;
		while (1) {
			int r = getopt_long(globalreg->argc, globalreg->argv,
								"-", kissource_long_options,
								&option_idx);
			if (r < 0) break;
			if (r == soc) {
				rawopts.push_back(string(optarg));
				break;
			}
		}

		for (unsigned int x = 0; x < rawopts.size(); x++) {
			vector<string> subopts = StrTokenize(rawopts[x], ":");
			if (subopts.size() != 2)
				continue;
			if (StrLower(subopts[0]) != StrLower(in_name) && subopts[0] != "*")
				continue;
			subopts = StrTokenize(subopts[1], ",", 1);
			for (unsigned y = 0; y < subopts.size(); y++) {
				subopts[y] = StrLower(subopts[y]);
				optargs.push_back(subopts[y]);

				if (subopts[y] == "fuzzycrypt") {
					genericparms.fuzzy_crypt = 1;
					_MSG("Enabling fuzzy encryption detection on packet "
						 "source '" + in_name + "'", MSGFLAG_INFO);
				} else if (subopts[y] == "nofuzzycrypt") {
					genericparms.fuzzy_crypt = 0;
					_MSG("Forced disabling of fuzzy encryption detection on packet "
						 "source '" + in_name + "'", MSGFLAG_INFO);
				} else if (subopts[y] == "weakvalidate") {
					genericparms.weak_dissect = 1;
					_MSG("Enabling weak frame validation on packet "
						 "source '" + in_name + "'", MSGFLAG_INFO);
				} else if (subopts[y] == "noweakvalidate") {
					genericparms.weak_dissect = 0;
					_MSG("Forced disabling of weak frame validation on packet "
						 "source '" + in_name + "'", MSGFLAG_INFO);
				}
			}
		}
    }

    virtual ~KisPacketSource() { }

	// Fetch the UUID
	virtual uuid FetchUUID() {
		return src_uuid;
	}
	
	// Manage the interface
	virtual int EnableMonitor() = 0;
	virtual int DisableMonitor() = 0;

	// Are we channel capable at all?
	virtual int FetchChannelCapable() = 0;

	// Set default behavior
	virtual int SetInitialChannel(int in_ch) {
		initial_channel = in_ch;
		return 1;
	}
	virtual int FetchInitialChannel() {
		return initial_channel;
	}
	virtual int SetChannelHop(int in_hop) {
		channel_hop = in_hop;
		return 1;
	}
	virtual int FetchChannelHop() {
		return channel_hop;
	}
	// Channel hop is performed locally (true for most)
	virtual int FetchLocalChannelHop() {
		return 1;
	}

	// Is the device controllable by the child IPC process?
	virtual int ChildIPCControl() = 0;

	virtual int SetChannel(unsigned int in_ch) = 0;
	// These can be overridden if special stuff needs to happen
	virtual int SetChannelSequence(vector<unsigned int> in_seq) {
		channel_list = in_seq;
		return 1;
	}
	virtual vector<unsigned int> FetchChannelSequence() {
		return channel_list;
	}
	// Jump to a specific offset in the channel list (used during creation,
	// primarily)
	virtual int SetChannelSeqPos(unsigned int in_offt) {
		channel_pos = in_offt;
		return 1;
	}

	// A little convoluted, we need to return the next channel to the caller
	// instead of setting it ourselves because it needs to go through the
	// IPC games
	virtual unsigned int FetchNextChannel() {
		if (channel_hop == 0)
			return 0;

		channel_pos++;

		if (channel_pos >= channel_list.size())
			channel_pos = 0;

		return channel_list[channel_pos];
	}

    // Open the packet source
    virtual int OpenSource() = 0;
    virtual int CloseSource() = 0;

    // Get the channel
    virtual int FetchChannel() { return 0; }

	// Get a pollable file descriptor
    virtual int FetchDescriptor() = 0;

	// Trigger a fetch of a pending packet and inject it into the packet chain
	virtual int Poll() = 0;

	// Fetch info about how we were built
    virtual string FetchName() { return name; }
    virtual string FetchInterface() { return interface; }
	virtual string FetchType() { return type; }

    // Fetch number of packets
    virtual int FetchNumPackets() { return num_packets; } 

	// Pause/resume listening to this source (what this means depends on 
	// the implementation of polling)
    void Pause() { paused = 1; };
    void Resume() { paused = 0; };

	virtual void SetFCSBytes(int in_bytes) { fcsbytes = in_bytes; }
	virtual unsigned int FetchFCSBytes() { return fcsbytes; }

	virtual void SetValidateCRC(int in_validate) {
		if (in_validate && crc32_table == NULL) {
			crc32_table = new unsigned int[256];
			crc32_init_table_80211(crc32_table);
		}

		if (in_validate && crc32_table != NULL) {
			delete[] crc32_table;
			crc32_table = NULL;
		}

		validate_fcs = in_validate;
	}
	virtual unsigned int FetchValidateCRC() { return validate_fcs; }

	// Set and fetch the carriers this source understands
	virtual void SetCarrierSet(int in_set) { carrier_set = in_set; }
	virtual int FetchCarrierSet() { return carrier_set; }

	// Generic-level per packet parameters
	virtual packet_parm FetchGenericParms() { return genericparms; }

protected:
	virtual void FetchRadioData(kis_packet *in_packet) = 0;

    GlobalRegistry *globalreg;

    int paused;

    // Name, interface
    string name;
    string interface;
	string type;

	// Unique identifier for this capture source
	uuid src_uuid;

    // Bytes in the FCS
    unsigned int fcsbytes;

	// Are the FCS bytes coming from this source valid? 
	// (ie, do we validate FCS and log FCS bytes?)
	unsigned int validate_fcs;
	unsigned int *crc32_table;

    // Total packets
    unsigned int num_packets;

    // Current channel, if we don't fetch it live.  This really means
	// "last channel we set"
    int channel;
	int initial_channel;

	// Do we hop, where are we in hopping, what channels do we hop to
	int channel_hop;
	unsigned int channel_pos;
	vector<unsigned int> channel_list;
	int consec_error;

	// Set of carrier types
	int carrier_set;

	// Generic packetsource optional parameters
	packet_parm genericparms;

	// Optional parameters from the config file which apply to this source
	vector<string> optargs;
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

#endif

