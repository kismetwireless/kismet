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
#include "gpsd.h"

// All packetsources need to provide out-of-class functions for the 
// packetsourcetracker class

// Non-class helper functions for each packet source type to handle allocating the
// class instance of KisPacketSource and to handle changing the channel outside of
// the instantiated object
//
// meta packsources are completed and filled with all relevant information for channel
// changing before the child process is spawned, eliminating the need to communicate
// the setup information for the sources over IPC.  There are no non-fatal conditions
// which would prevent a metasource from having a real correlation.
class KisPacketSource;

#define REGISTRANT_PARMS GlobalRegistry *globalreg, string in_name, string in_device
typedef KisPacketSource *(*packsource_registrant)(REGISTRANT_PARMS);

#define CHCONTROL_PARMS GlobalRegistry *globalreg, const char *in_dev, \
                            int in_ch, void *in_ext
typedef int (*packsource_chcontrol)(CHCONTROL_PARMS);

#define MONITOR_PARMS GlobalRegistry *globalreg, const char *in_dev, \
                            int initch, void **in_if, void *in_ext
typedef int (*packsource_monitor)(MONITOR_PARMS);

// Packet capture source superclass
class KisPacketSource {
public:
    KisPacketSource(GlobalRegistry *in_globalreg, string in_name, string in_dev) {
        name = in_name;
        interface = in_dev;

        globalreg = in_globalreg;
        
        fcsbytes = 0;
    }

    virtual ~KisPacketSource() { };

    // Open the packet source
    virtual int OpenSource() = 0;

    virtual int CloseSource() = 0;

    // Get the channel
    virtual int FetchChannel() = 0;

    // Get the FD of our packet source
    virtual int FetchDescriptor() = 0;

    // Get a packet from the medium
    virtual int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) = 0;

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

    // Set packet parameters
    void SetPackparm(packet_parm in_parameters) {
        parameters = in_parameters;
    }

    // Get packet parameters
    packet_parm GetPackparm() {
        return parameters;
    }

    // Bytes in the FCS - public so monitor can write it
    int fcsbytes;
protected:
    // Get the bytes in the fcs
    virtual int FCSBytes() {
        return fcsbytes;
    }

    GlobalRegistry *globalreg;

    int paused;

    // Name, interface
    string name;
    string interface;

    // Various parameters we track
    packet_parm parameters;

    // Total packets
    unsigned int num_packets;

    // Current channel, if we don't fetch it live
    int channel;
};


#endif
