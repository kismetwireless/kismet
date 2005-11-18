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

#include "globalregistry.h"
#include "messagebus.h"
#include "packet.h"
#include "timetracker.h"
#include "gpsdclient.h"
#include "configfile.h"

/*
 * How packet sources, helper functions, and packetsourcetrackers work:
 *
 * The packet source is responsible for getting packets from (foo) and
 * injecting them into the packet stream.
 *
 * The packetsourcetracker is responsible for parsing the config file,
 * registering packet sources, controlling channel hopping, etc.
 *
 * The helper functions are needed for entering monitor mode (or whatever
 * other configuration the source needs equivalent to monitor mode) and for
 * changing channel.
 *
 * Channel control may be done via IPC with the channel-control process 
 * running as root, which will not have a copy of the full packet source
 * class, which is why they're not integrated.
 *
 * meta_packsource records are completed with the relevant information for
 * channel and monitor control for the channel control client
 *
 */

// Forward definitions of ourselves and the meta info from the source tracker
// We need to track the meta info so that things that hook the source out of
// the packetchain can get access to the meta state of hopping, etc
class KisPacketSource;
class meta_packsource;

#define AUTOPROBE_PARMS GlobalRegistry *globalreg, string in_name, \
	string in_device, string in_driver, string in_version, string in_fwversion
typedef int (*packsource_autoprobe)(AUTOPROBE_PARMS);

#define REGISTRANT_PARMS GlobalRegistry *globalreg, meta_packsource *in_meta, \
	string in_name, string in_device
typedef KisPacketSource *(*packsource_registrant)(REGISTRANT_PARMS);

#define CHCONTROL_PARMS GlobalRegistry *globalreg, const char *in_dev, \
	int in_ch, void *in_ext
typedef int (*packsource_chcontrol)(CHCONTROL_PARMS);

#define MONITOR_PARMS GlobalRegistry *globalreg, const char *in_dev, \
	int initch, void **in_if, void *in_ext
typedef int (*packsource_monitor)(MONITOR_PARMS);

// Parmeters to the packet info.  These get set by the packet source controller
// so they need to go here
typedef struct packet_parm {
	packet_parm() {
		fuzzy_crypt = 0;
		weak_dissect = 0;
	}

    int fuzzy_crypt;
	int weak_dissect;
};

// Packet capture source superclass ...  Not part of Pollable, because the
// packetsourcetracker aggregates us into the descriptors and handles actual
// polling.
//
// We need the meta source separate from the name and device here and in the
// constructor because at this point we don't know the format of meta, it's an
// empty forward definition.
class KisPacketSource {
public:
    KisPacketSource(GlobalRegistry *in_globalreg, meta_packsource *in_meta, 
					string in_name, string in_dev) {
        name = in_name;
        interface = in_dev;

        globalreg = in_globalreg;
		metasource = in_meta;
        
        fcsbytes = 0;
		carrier_set = 0;

		// It seems like a bad idea to put this much into a function in a 
		// header file, but it would have to change anyhow to update the
		// struct
		vector<string> rawopts = globalreg->kismet_config->FetchOptVec("sourceopts");
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

    // Open the packet source
    virtual int OpenSource() = 0;

    virtual int CloseSource() = 0;

    // Get the channel
    virtual int FetchChannel() { return 0; }

	// Get a pollable file descriptor
    virtual int FetchDescriptor() = 0;

	// Trigger a fetch of a pending packet and inject it into the packet chain
	virtual int Poll() = 0;
	
    // Get the name
    const char *FetchName() { return(name.c_str()); }

    // Get the interface
    const char *FetchInterface() { return(interface.c_str()); }

    // Fetch number of packets
    int FetchNumPackets() { return num_packets; }

    // Ignore incoming packets
    void Pause() { paused = 1; };

    // Stop ignoring incoming packets
    void Resume() { paused = 0; };

	virtual void SetFCSBytes(int in_bytes) { fcsbytes = in_bytes; }

	int FetchCarrierSet() { return carrier_set; }

	void SetCarrierSet(int in_set) { carrier_set = in_set; }

	virtual meta_packsource *FetchMetasource() { return metasource; }

	virtual packet_parm FetchGenericParms() { return genericparms; }

protected:
	virtual void FetchRadioData(kis_packet *in_packet) = 0;

    GlobalRegistry *globalreg;
	meta_packsource *metasource;

    int paused;

    // Name, interface
    string name;
    string interface;

    // Bytes in the FCS
    unsigned int fcsbytes;

    // Total packets
    unsigned int num_packets;

    // Current channel, if we don't fetch it live.  This really means
	// "last channel we set"
    int channel;

	// Set of carrier types
	int carrier_set;

	// Generic packetsource optional parameters
	packet_parm genericparms;

	// Optional parameters from the config file which apply to this source
	vector<string> optargs;
};

#endif

