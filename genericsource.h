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

#ifndef __GENERICSOURCE_H__
#define __GENERICSOURCE_H__

/* This is so ugly.
 Wavelans, and other linux-wireless cards that don't have RF monitoring
 ability, can still be used to get SSID's via the standard linux wireless
 extentions.  This isn't as reliable as RF monitoring based capture, and it
 takes a few more packets to detect a network.  It also can't do true
 sniffing, only ssid detection.

 We set our ssid to nil and let the firmware seek out new ones.  Then, when
 we find one, we build a fake beacon packet around it, and send it on its
 merry way.

 Method lifted from gtkskan.
 */

#include "config.h"

#ifdef HAVE_LINUX_WIRELESS

#include "packet.h"
#include "packetsource.h"

#include <linux/wireless.h>

class GenericSource : public PacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);
    int CloseSource();

    // We don't really have a FD that can be monitored, so we tell the server to
    // fake it
    int FetchDescriptor() { return -1; }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

protected:
    int Generic2Common(pkthdr *in_header, u_char *in_data);
    // Set the cards ssid
    int SetGenericEssid(const char *essid_in);

    // Fetch the current info stored in the card
    int GetGenericInfo();

    char interface[64];

    char essid[IW_ESSID_MAX_SIZE+1];

    uint8_t mac[MAC_LEN];

    int wep;
    int mode;

    int sock;

    timeval ts;

};

#endif

#endif

