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

#ifndef __WTAPFILESOURCE_H__
#define __WTAPFILESOURCE_H__

#include "config.h"

#ifdef HAVE_LIBWIRETAP

#include "packet.h"
#include "packetsource.h"

extern "C" {
#include "wtap.h"
}

class WtapFileSource : public PacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);
    int CloseSource();

    int FetchDescriptor() { return wtap_fd(packfile); }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

    static void Callback(u_char *bp, const struct pcap_pkthdr *header,
                         const u_char *data);

protected:
    int Wtap2Common(pkthdr *in_header, u_char *in_data);

    struct wtap *packfile;
    const struct wtap_pkthdr *packet_header;
    const u_char *packet_data;

};

#endif

#endif
