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

#include "packet.h"

// Card type, for some capture sources which require it
enum card_type {
    card_unspecified,
    card_cisco,
    card_cisco_cvs,
    card_cisco_bsd,
    card_prism2,
    card_prism2_legacy,
    card_prism2_bsd,
    card_prism2_hostap,
    card_orinoco,
    card_orinoco_bsd,
    card_generic,
    card_wsp100,
    card_wtapfile
};

// Packet capture source superclass
class PacketSource {
public:
    // Open the packet source
    virtual int OpenSource(const char *dev, card_type ctype) = 0;

    virtual int CloseSource() = 0;

    // Get the FD of our packet source
    virtual int FetchDescriptor() = 0;

    // Get a packet from the medium
    virtual int FetchPacket(pkthdr *in_header, u_char *in_data) = 0;

    // Say what we are
    char *FetchType() { return(type); };

    // Get the error
    char *FetchError() { return(errstr); };

    // Ignore incoming packets
    void Pause() { paused = 1; };

    // Stop ignoring incoming packets
    void Resume() { paused = 0; };

protected:
    char errstr[1024];
    pkthdr header;
    u_char data[MAX_PACKET_LEN];
    int paused;

    char type[64];

    card_type cardtype;

};

#endif
