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

#include "packet.h"
#include "timetracker.h"
#include "gpsd.h"

// All packetsources need to provide out-of-class functions for the 
// packetsourcetracker class
//
// typedef KisPacketSource *(*packsource_registrant)(string, string);
// typedef int (*packsource_chcontrol)(char *, int, char *);
// typedef int (*packsource_monitor)(char *, int, char *);

// Packet capture source superclass
class KisPacketSource {
public:
    KisPacketSource(string in_name, string in_dev) {
        name = in_name;
        interface = in_dev;

        gpsd = NULL;
        timetracker = NULL;

        fcsbytes = 0;

		parameters.fuzzy_crypt = 0;
		parameters.fuzzy_decode = 0;
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

    // Register a timer event handler for us to use
    void AddTimetracker(Timetracker *in_tracker) { timetracker = in_tracker; }

    // Register the GPS server for us to use
    void AddGpstracker(GPSD *in_gpsd) { gpsd = in_gpsd; }

    // Get the error
    char *FetchError() { return(errstr); }

    // Get the name
    const char *FetchName() { return(name.c_str()); }

    // Get the interface
    const char *FetchInterface() { return(interface.c_str()); }
	// Set the interface
	void SetInterface(string in_if) { interface = in_if; }

    // Fetch number of packets
    int FetchNumPackets() { return num_packets; }

    // Ignore incoming packets
    void Pause() { paused = 1; };

    // Stop ignoring incoming packets
    void Resume() { paused = 0; };

    // Set packet parameters
    void SetPackparm(packet_parm in_parameters) {
		if (in_parameters.fuzzy_crypt != -1)
			parameters.fuzzy_crypt = in_parameters.fuzzy_crypt;
		if (in_parameters.fuzzy_decode != -1)
			parameters.fuzzy_decode = in_parameters.fuzzy_decode;
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

    // Global tracking pointers
    Timetracker *timetracker;
    GPSD *gpsd;

    char errstr[1024];

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
