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

#ifndef __PACKETDISSECTORS_H__
#define __PACKETDISSECTORS_H__

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "packetchain.h"

// Various packetchain dissectors that need to do magic

// 802.11 frame dissector
int kis_80211_dissector(CHAINCALL_PARMS);
// Karlnet/turbocell dissector
int kis_turbocell_dissector(CHAINCALL_PARMS);
// Data frame dissector
int kis_data_dissector(CHAINCALL_PARMS);
// String extractor
int kis_data_string_dissector(CHAINCALL_PARMS);

// Packet decoders

// Standard RC4 WEP decoder
int kis_wep_decoder(CHAINCALL_PARMS);
// WEP->Normal mangler
int kis_wep_mangler(CHAINCALL_PARMS);
// Fuzzy-detected->Normal mangler
int kis_fuzzy_mangler(CHAINCALL_PARMS);

#endif

