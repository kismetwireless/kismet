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

#ifndef __VIHASOURCE_H__
#define __VIHASOURCE_H__

#ifdef HAVE_VIHAHEADERS

#include "packetsource.h"

#include <WiFi/WLPacketSource.h>
#include <WiFi/WLFrame.h>
#include <WiFi/IEEE80211Frame.h>
#include <WiFi/WFException.h>

class VihaSource : public KisPacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);

    int CloseSource();

    int FetchDescriptor() { return udp_sock; }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

protected:
    WLPacketSource *wlsource;

    int Viha2Common(pkthdr *in_header, u_char *in_data);

};

#endif

// ifdef
#endif
