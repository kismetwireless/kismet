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
#include <stdint.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "macaddr.h"

// Offset for all LLC-fragment protocols
const unsigned int LLC_UI_OFFSET = 3;

const uint8_t DOT1X_PROTO[] = {0x88, 0x8e};
const uint8_t DOT1X_OFFSET = LLC_UI_OFFSET + 5;

const uint8_t EAP_OFFSET = 4;
const uint8_t EAP_PACKET_SIZE = 5;

const uint8_t EAP_CODE_RESPONSE = 2;
const uint8_t EAP_TYPE_IDENTITY = 1;
const uint8_t EAP_TYPE_TLS  = 13;
const uint8_t EAP_TYPE_LEAP = 17;
const uint8_t EAP_TYPE_TTLS = 21;
const uint8_t EAP_TYPE_PEAP = 25;

const mac_addr msfopcode_mac = mac_addr("90:E9:75:00:00:00/FF:FF:FF:00:00:00");

#endif
