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

#ifndef __WSP100SOURCE_H__
#define __WSP100SOURCE_H__

#ifdef HAVE_WSP100

#include "packetsource.h"

class Wsp100Source : public PacketSource {
public:
    // Open the packet source
    int OpenSource(const char *dev, card_type ctype);

    int CloseSource();

    // We don't really have a FD that can be monitored, so we tell the server to
    // fake it
    int FetchDescriptor() { return -1; }

    // Get a packet from the medium
    int FetchPacket(pkthdr *in_header, u_char *in_data);

protected:

};

#endif

#endif
