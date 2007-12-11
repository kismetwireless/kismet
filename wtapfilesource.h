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
#include <wireshark/wtap.h>
}

class WtapFileSource : public KisPacketSource {
public:
    WtapFileSource(string in_name, string in_dev) : KisPacketSource(in_name, in_dev) { }

    int OpenSource();
    int CloseSource();

    int FetchDescriptor() { return wtap_fd(packfile); }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    static void Callback(u_char *bp, const struct pcap_pkthdr *header,
                         const u_char *data);

    int FetchChannel() { return 0; }

protected:
    int Wtap2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    struct wtap *packfile;
    const struct wtap_pkthdr *packet_header;
    const uint8_t *packet_data;

};

// Registrant only.  There aren't any channel or monitor controls.
KisPacketSource *wtapfilesource_registrant(string in_name, string in_device, 
                                           char *in_err);

#endif

#endif
