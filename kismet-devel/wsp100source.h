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

#include <netdb.h>

// Copy this from wtap for our own records
#define KWTAP_ENCAP_IEEE_802_11          18

// Cribbed from packet-tzsp ethereal code by Chris Waters
#define WSP100_TAG_PAD            0x00   // Null
#define WSP100_TAG_END            0x01   // End of list
#define WSP100_TAG_RADIO_SIGNAL   0x0a   // Signal strength in dbm, signed
#define WSP100_TAG_RADIO_NOISE    0x0b   // Noise level in dbm, signed
#define WSP100_TAG_RADIO_RATE     0x0c   // Data rate
#define WSP100_TAG_RADIO_TIME     0x0d   // timestamp
#define WSP100_TAG_RADIO_MSG      0x0e   // packet type, unsigned byte
#define WSP100_TAG_RADIO_CF       0x0f   // Arrived during CF
#define WSP100_TAG_RADIO_UNDECR   0x10   // Remote sensor couldn't decrypt the packet
#define WSP100_TAG_RADIO_FCSERR   0x11   // FCS error in packet
#define WSP100_TAG_RADIO_CHANNEL  0x12   // Channel, unsigned

class Wsp100Source : public KisPacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);

    int CloseSource();

    int FetchDescriptor() { return udp_sock; }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

protected:

    int Wsp2Common(pkthdr *in_header, u_char *in_data);

    short int port;
    int udp_sock;
    int valid;
    int read_len;

    struct sockaddr_in serv_sockaddr;
    in_addr filter_addr;

};

// wsp100
#endif

// ifdef
#endif
