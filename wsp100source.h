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
#include "timetracker.h"
#include "server_plugin.h"

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

#define TZSP_NULL_PACKET          0x01C40000 // for TZSP v1 at least
#define TZSP_NULL_PACKET_SLICE    15 * SERVER_TIMESLICES_SEC  // must be less than 32, and consists of timer slices (100000us)

int Wsp100PokeSensor(Timetracker::timer_event *evt, void *call_parm);

class Wsp100Source : public KisPacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);

    int CloseSource();

    int FetchDescriptor() { return udp_sock; }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    void PokeSensor();

protected:

    int Wsp2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    short int port;
    int udp_sock;
    int valid;
    int read_len;

    struct sockaddr_in serv_sockaddr;
    in_addr filter_addr;

    uint8_t data[MAX_PACKET_LEN];

    // For when we need to revoke this
    int poke_event_id;

};

// wsp100
#endif

// ifdef
#endif
