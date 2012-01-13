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
#define __PACKETSIGNATURES_H__

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
const unsigned int LLC_OFFSET = 0;

// Offset for all LLC-fragment protocols
const unsigned int LLC_UI_OFFSET = 3;

// LLC packets that look like probe info (netstumbler and lucent)
const uint8_t PROBE_LLC_SIGNATURE[] = {0x00, 0x60, 0x1D};

// "All" is all we need to match at this offset.  We matched the LLC already so
// we can use a very small fragment
// This catches "All your 802.11b are belong to us"
const uint8_t NETSTUMBLER_323_SIGNATURE[] = {0x41, 0x6C, 0x6C};
// "Flu" again is all we need to match at this offset.
// This catches "Flurble gronk bloopit, bnip Frundletrune"
const uint8_t NETSTUMBLER_322_SIGNATURE[] = {0x46, 0x6C, 0x75};
// "   " is the beginning of the .30
// "          Intentionally blank"
const uint8_t NETSTUMBLER_330_SIGNATURE[] = {0x20, 0x20, 0x20};
const uint8_t NETSTUMBLER_OFFSET = 12;

// Lucent link test signatures
const uint8_t LUCENT_TEST_SIGNATURE[] = {0x00, 0x01, 0x02, 0x03};
const uint8_t LUCENT_OFFSET = 12;

const uint8_t CISCO_SIGNATURE[] = {0x00, 0x00, 0x0C, 0x20, 0x00};
const unsigned int CDP_ELEMENT_LEN = 5;

const uint8_t FORTRESS_SIGNATURE[] = {0x00, 0x00, 0x00, 0x88, 0x95};

// WPA/WPA2 identifiers
const uint8_t WPA_OUI[] = {0x00, 0x50, 0xF2};
const uint8_t RSN_OUI[] = {0x00, 0x0F, 0xAC};
const uint8_t MSF_OUI[] = {0x00, 0x50, 0xF2};

const uint8_t WPS_VERSION[] = {0x10, 0x4a, 0x00, 0x01, 0x10};
const uint8_t WPS_CONFIGURED[] = {0x10, 0x44, 0x00, 0x01, 0x02};

const uint8_t DOT1X_PROTO[] = {0x88, 0x8e};
const uint8_t DOT1X_OFFSET = LLC_UI_OFFSET + 5;
const uint8_t DOT1X_HEADER_SIZE = 4;

const uint8_t EAP_OFFSET = 4;
const uint8_t EAP_PACKET_SIZE = 5;

const uint8_t EAP_CODE_REQUEST = 1;
const uint8_t EAP_CODE_RESPONSE = 2;
const uint8_t EAP_CODE_SUCCESS = 3;
const uint8_t EAP_CODE_FAILURE = 4;
const uint8_t EAP_TYPE_IDENTITY = 1;
const uint8_t EAP_TYPE_TLS  = 13;
const uint8_t EAP_TYPE_LEAP = 17;
const uint8_t EAP_TYPE_TTLS = 21;
const uint8_t EAP_TYPE_PEAP = 25;


const uint8_t ARP_SIGNATURE[] = {0x08, 0x06};
const unsigned int ARP_OFFSET = 6;
const uint8_t ARP_PACKET_SIZE = 30;

const uint8_t DHCPD_SIGNATURE[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x43, 0x00, 0x44};
const unsigned int DHCPD_OFFSET = 24;

const unsigned int IP_OFFSET = 17;
const uint8_t IP_HEADER_SIZE = 11;

const uint8_t UDP_SIGNATURE[] = {0x11};
const unsigned int UDP_OFFSET = 28;

const uint8_t TCP_SIGNATURE[] = {0x06};
const unsigned int TCP_OFFSET = 28;
const unsigned int TCP_HEADER_SIZE = 11;

const uint8_t NETBIOS_TCP_OFFSET = 204;
const uint8_t NETBIOS_OFFSET = 133;

// netbios LLC signature
const uint8_t NETBIOS_SIGNATURE[] = {0xF0, 0xF0, 0x03};

// IPX LLC signature
const uint8_t IPX_SIGNATURE[] = {0xE0, 0xE0, 0x03};

// IAPP
const unsigned int IAPP_OFFSET = 36;
const uint8_t IAPP_HEADER_SIZE = 2;
const uint8_t IAPP_PDUHEADER_SIZE = 3;

const uint16_t IAPP_PORT = 2313;

const uint16_t ISAKMP_PORT = 500;
const uint8_t ISAKMP_OFFSET = UDP_OFFSET + 8;
const unsigned int ISAKMP_PACKET_SIZE = 14;
const uint8_t ISAKMP_EXCH_NONE = 0;
const uint8_t ISAKMP_EXCH_BASE = 1;
const uint8_t ISAKMP_EXCH_IDPROT = 2;
const uint8_t ISAKMP_EXCH_AUTHONLY = 3;
const uint8_t ISAKMP_EXCH_AGGRESS = 4;
const uint8_t ISAKMP_EXCH_INFORM = 5;
const uint8_t ISAKMP_EXCH_TRANS = 6;
const uint8_t ISAKMP_EXCH_QUICK = 32;
const uint8_t ISAKMP_EXCH_NEWGRP = 33;

// PPTP
const uint16_t PPTP_PORT = 1723;

const mac_addr msfopcode_mac = mac_addr("90:E9:75:00:00:00/FF:FF:FF:00:00:00");

#endif
