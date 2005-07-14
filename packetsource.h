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

class KisPacketSource;

#define REGISTRANT_PARMS GlobalRegistry *globalreg, string in_name, string in_device
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
	}

    int fuzzy_crypt;
};

// Packet capture source superclass ...  Not part of Pollable, because the
// packetsourcetracker aggregates us into the descriptors and handles actual
// polling
class KisPacketSource {
public:
    KisPacketSource(GlobalRegistry *in_globalreg, string in_name, string in_dev) {
        name = in_name;
        interface = in_dev;

        globalreg = in_globalreg;
        
        fcsbytes = 0;
		carrier_set = 0;
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

	void SetFCSBytes(int in_bytes) { fcsbytes = in_bytes; }

	int FetchCarrierSet() { return carrier_set; }

	void SetCarrierSet(int in_set) { carrier_set = in_set; }

protected:
	virtual void FetchRadioData(kis_packet *in_packet) = 0;

    GlobalRegistry *globalreg;

    int paused;

    // Name, interface
    string name;
    string interface;

    // Bytes in the FCS - public so monitor can write it
    int fcsbytes;

    // Total packets
    unsigned int num_packets;

    // Current channel, if we don't fetch it live.  This really means
	// "last channel we set"
    int channel;

	// Set of carrier types
	int carrier_set;
	
};

#endif

