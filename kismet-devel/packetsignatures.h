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

#ifndef __PACKETSIGNATURES_H__

#include "config.h"
#ifdef HAVE_STDINT
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

const uint8_t LOR_MAC[] = {0x01, 0x00, 0x00, 0x00, 0x20, 0xF6};
const uint8_t NUL_MAC[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t NETS_MAC[] = {0x01, 0x60, 0x1d, 0x00, 0x01, 0x00};

// LLC packets with control field U func UI (we handle a lot of things with these headers)
const uint8_t LLC_UI_SIGNATURE[] = {0xAA, 0xAA, 0x03};

// Offset for the start of the LLC frame
const int LLC_OFFSET = 0;

// Offset for all LLC-fragment protocols
const int LLC_UI_OFFSET = 3;

// LLC packets that look like netstumbler
const uint8_t NETSTUMBLER_LLC_SIGNATURE[] = {0x00, 0x60, 0x1D};
// "All" is all we need to match at this offset.  We matched the LLC already so
// we can use a very small fragment
// This catches "All your 802.11b are belong to us"
const uint8_t NETSTUMBLER_323_SIGNATURE[] = {0x41, 0x6C, 0x6C};
// "Flu" again is all we need to match at this offset.
// This catches "Flurble gronk bloopit, bnip Frundletrune"
const uint8_t NETSTUMBLER_322_SIGNATURE[] = {0x46, 0x6C, 0x65};
const uint8_t NETSTUMBER_OFFSET = 12;

const uint8_t CISCO_SIGNATURE[] = {0x00, 0x00, 0x0C, 0x20, 0x00};

const uint8_t ARP_SIGNATURE[] = {0x08, 0x06};
const int ARP_OFFSET = 6;

const uint8_t DHCPD_SIGNATURE[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x43, 0x00, 0x44};
const int DHCPD_OFFSET = 24;

const int IP_OFFSET = 17;

const uint8_t UDP_SIGNATURE[] = {0x11};
const int UDP_OFFSET = 28;

const uint8_t TCP_SIGNATURE[] = {0x06};
const int TCP_OFFSET = 28;

const uint8_t NETBIOS_TCP_OFFSET = 204;
const uint8_t NETBIOS_OFFSET = 133;

// netbios LLC signature
const uint8_t NETBIOS_SIGNATURE[] = {0xF0, 0xF0, 0x03};

// IPX LLC signature
const uint8_t IPX_SIGNATURE[] = {0xE0, 0xE0, 0x03};


#endif
