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

#ifndef __DUMPFILE_H__
#define __DUMPFILE_H__

#include "config.h"

#include <string>
#include <map>

#include "packet.h"

// Packet capture source superclass
class DumpFile {
public:
    virtual ~DumpFile() { }

    // Open the packet source
    virtual int OpenDump(const char *file) = 0;

    virtual int CloseDump() = 0;

    // Get a packet from the medium
    virtual int DumpPacket(const packet_info *in_info, const pkthdr *in_header,
                           const u_char *in_data) = 0;

    // Do we log beacons?
    void SetBeaconLog(int in_log) { beacon_log = in_log; };
    // Do we log phy-layer stuff?
    void SetPhyLog(int in_log) { phy_log = in_log; };

    // Get the number of packets
    int FetchDumped() { return(num_dumped); };

    // Say what we are
    char *FetchType() { return(type); };

    // Get the error
    char *FetchError() { return(errstr); };

    // Get the file name
    char *FetchFilename() { return(filename); };

protected:
    char errstr[1024];
    char type[64];
    char filename[1024];

    int num_dumped;
    int beacon_log;
    int phy_log;

    map<mac_addr, string> beacon_logged_map;

};

#endif
