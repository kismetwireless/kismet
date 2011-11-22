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
struct packet_parm {
	packet_parm() {
		fuzzy_crypt = 0;
		weak_dissect = 0;
		legal_paranoia = 0;
	}

    int fuzzy_crypt;
	int weak_dissect;
	int legal_paranoia;
};

// parsed option
struct packetsource_option {
	string opt;
	string val;
};

// We don't do anything smart with this yet but plan ahead
enum packetsource_channel_mod {
	channel_mod_none = 0,
	channel_mod_11b = 1,
	channel_mod_11g = 2,
	channel_mod_11a = 3,
	channel_mod_11n = 4,
	channel_mod_40mhz = 5
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
		source_id = 0;
	}

	// This should call our own constructor and return a packet source of our
	// own type, for each subclass
	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface, 
										  vector<opt_pair> *in_opts) = 0;

	virtual int RegisterSources(Packetsourcetracker *tracker) = 0;
	virtual int AutotypeProbe(string in_device) = 0;

	// Create a strong packet source
    KisPacketSource(GlobalRegistry *in_globalreg, string in_interface,
					vector<opt_pair> *in_opts) {
        name = in_interface;
		interface = in_interface;

		source_id = 0;

		type = "auto";

        globalreg = in_globalreg;

		// Invalidate the UUID to begin with
		src_uuid.error = 1;
       
		dlt_mangle = 0;

        fcsbytes = 0;
		validate_fcs = 0;
		crc32_table = NULL;
		carrier_set = 0;

		consec_error = 0;

		num_packets = 0;
		num_error_packets = 0;

		error = 0;

		if (ParseOptions(in_opts) < 0)
			error = 1;
    }

    virtual ~KisPacketSource() { }

	// Parse the options -- override any existing options we have
	virtual int ParseOptions(vector<opt_pair> *in_opts) {
		if (FetchOpt("name", in_opts) != "") 
			name = FetchOpt("name", in_opts);

		if (FetchOpt("type", in_opts) != "")
			type = FetchOpt("type", in_opts);

		// Get the UUID from options if we have it, otherwise generate one
		// TODO: Pull from cache
		if (FetchOpt("uuid", in_opts) != "") {
			src_uuid = uuid(FetchOpt("uuid", in_opts));

			if (src_uuid.error)
				_MSG("Invalid UUID=... on packet source " + interface + ".  "
					 "A new UUID will be generated.", MSGFLAG_ERROR);
		}

		if (src_uuid.error) {
			// Generate a UUID if we don't have one 
			// This is mostly just crap.  Hash the type and name, then
			// hash the device, and make a 6 byte field out of it to seed
			// the device attribute.  If a subclass wants to seed this with the MAC 
			// of the capture source in the future, thats fine too
			uint8_t unode[6];
			uint32_t unode_hash;
			string combo = type + name;
			unode_hash = Adler32Checksum(combo.c_str(), combo.length());
			memcpy(unode, &unode_hash, 4);
			unode_hash = Adler32Checksum(interface.c_str(), interface.length());
			memcpy(&(unode[4]), &unode_hash, 2);

			src_uuid.GenerateTimeUUID(unode);
		}

		// if (StrLower(FetchOpt("weakvalidate", in_opts)) == "true") {
		if (FetchOptBoolean("weakvalidate", in_opts, 0)) {
			genericparms.weak_dissect = 1;
			_MSG("Enabling weak frame validation on packet source '" + 
				 interface + "'", MSGFLAG_INFO);
		}

		// if (StrLower(FetchOpt("validatefcs", in_opts)) == "true") {
		if (FetchOptBoolean("validatefcs", in_opts, 0)) {
			SetValidateCRC(1);
			_MSG("Enabling FCS frame validation on packet source '" +
				 interface + "'", MSGFLAG_INFO);
		}

		// if (FetchOpt("fcs", in_opts) == "true") {
		if (FetchOptBoolean("fcs", in_opts, 0)) {
			_MSG("Forcing assumption that source '" + interface + "' contains "
				 "four trailing bytes of FCS checksum data", MSGFLAG_INFO);
			SetFCSBytes(4);
		}

		return 1;
	}

	// Fetch the UUID
	virtual uuid FetchUUID() {
		return src_uuid;
	}

	// Data placeholder for the packet source tracker to record who we are for
	// much faster per-packet handling (per-frame map lookups = bad)
	virtual void SetSourceID(uint16_t in_id) { source_id = in_id; }
	virtual uint16_t FetchSourceID() { return source_id; }

	// Set DLT de-mangling
	virtual void SetDLTMangle(int in_mangle) { dlt_mangle = in_mangle; }
	// Mangle a packet from capture to 80211 pure + chain elements
	virtual int ManglePacket(kis_packet *packet, kis_datachunk *linkchunk) { return 0; }
	
	// Manage the interface
	virtual int EnableMonitor() = 0;
	virtual int DisableMonitor() = 0;

	// Set the card to a channel w/ a given modulation
	virtual int SetChannel(unsigned int in_ch) = 0;

	// Fetch supported channels from hardware, if we can
	virtual vector<unsigned int> FetchSupportedChannels(string in_interface) { 
		vector<unsigned int> ret; 
		return ret; 
	}

    // Open the packet source
    virtual int OpenSource() = 0;
    virtual int CloseSource() = 0;

	// Get the last channel we know we set
    virtual int FetchChannel() { return last_channel; }
	virtual int FetchChannelMod() { return last_mod; }

	// Get the hardware channel
	virtual int FetchHardwareChannel() { return 0; }

	// Get a pollable file descriptor (usually from pcap)
    virtual int FetchDescriptor() = 0;

	// Trigger a fetch of a pending packet(s) and inject it into 
	// the packet chain, may inject multiple packets for one call
	virtual int Poll() = 0;

	// Fetch info about how we were built
    virtual string FetchName() { return name; }
    virtual string FetchInterface() { return interface; }
	virtual string FetchType() { return type; }

    // Fetch number of packets we've processed
    virtual int FetchNumPackets() { return num_packets; } 
	virtual int FetchNumErrorPackets() { return num_error_packets; }

	// Add a packet to the count (for packetsourcetracker to increment us for IPC
	// packets)
	virtual void AddPacketCount() { num_packets++; }
	virtual void AddErrorPacketCount() { num_error_packets++; }

	// Pause/resume listening to this source (what this means depends on 
	// the implementation of polling)
    void Pause() { paused = 1; };
    void Resume() { paused = 0; };

	virtual void SetFCSBytes(int in_bytes) { fcsbytes = in_bytes; }
	virtual unsigned int FetchFCSBytes() { return fcsbytes; }

	virtual void SetValidateCRC(int in_validate) {
		validate_fcs = in_validate;
	}
	virtual unsigned int FetchValidateCRC() { return validate_fcs; }

	// Set and fetch the carriers this source understands
	virtual void SetCarrierSet(int in_set) { carrier_set = in_set; }
	virtual int FetchCarrierSet() { return carrier_set; }

	// Generic-level per packet parameters
	virtual packet_parm FetchGenericParms() { return genericparms; }

	// Return if we're channel capable or not, used for deriving hop
	virtual int FetchChannelCapable() { return channel_capable; }

	// Return the maximum hop velocity we support (if the source is known
	// to have problems at higher velocities, this can be used to limit it)
	// By default all sources can hop as fast as the Kismet timer, 10x a second
	virtual int FetchChannelMaxVelocity() { return 10; }

	virtual int FetchSkipChanhop() { return 0; }

	virtual int FetchError() { return error; }

	virtual string FetchWarning() { return warning; }

protected:
	virtual void FetchRadioData(kis_packet *in_packet) = 0;

    GlobalRegistry *globalreg;

	int die_on_fatal;

    int paused;

	int error;

	uint16_t source_id;

    // Name, interface
    string name;
    string interface;
	string type;

	// Unique identifier for this capture source
	uuid src_uuid;

	int dlt_mangle;

    // Bytes in the FCS
    unsigned int fcsbytes;

	// Are we channel capable?
	int channel_capable;

	// Are the FCS bytes coming from this source valid? 
	// (ie, do we validate FCS and log FCS bytes?)
	unsigned int validate_fcs;
	unsigned int *crc32_table;

    // Total packets
    unsigned int num_packets;
	unsigned int num_error_packets;

	// Last channel & mod we set
	int last_channel;
	packetsource_channel_mod last_mod;

	int consec_error;

	// Set of carrier types
	int carrier_set;

	// Generic packetsource optional parameters
	packet_parm genericparms;

	// Warning state
	string warning;
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

