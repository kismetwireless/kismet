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

#include <vector>
#include <string>
#include <map>

#include "globalregistry.h"
#include "packetchain.h"
#include "macaddr.h"

/*
 * Basic built-in Kismet dissectors that handle ieee80211 dissection and
 * data dissection.  This should be instantiated from main() and left alone
 * for the most part, we're just wrapped in a class so that we can easily track
 * our alert references and so that main() isn't making a pile of random 
 * links
 */

// Basic dissector hooks
int kis_80211_dissector(CHAINCALL_PARMS);
int kis_turbocell_dissector(CHAINCALL_PARMS);
int kis_data_dissector(CHAINCALL_PARMS);

// Basic decryptor hooks
int kis_wep_decryptor(CHAINCALL_PARMS);

// Basic mangler hooks
int kis_wep_mangler(CHAINCALL_PARMS);

// Wep keys
typedef struct {
    int fragile;
    mac_addr bssid;
    unsigned char key[WEPKEY_MAX];
    unsigned int len;
    unsigned int decrypted;
    unsigned int failed;
} wep_key_info;

class KisBuiltinDissector {
public:
	KisBuiltinDissector();
	KisBuiltinDissector(GlobalRegistry *in_globalreg);
	~KisBuiltinDissector();

	int ieee80211_dissector(kis_packet *in_pack);
	int basicdata_dissector(kis_packet *in_pack);

	int wep_data_decryptor(kis_packet *in_pack);
	int wep_data_mangler(kis_packet *in_pack);

	int GetIEEETagOffsets(unsigned int init_offset, kis_datachunk *in_chunk,
						  map<int, vector<int> > *tag_cache_map);

	int WPACipherConv(uint8_t cipher_index);
	int WPAKeyMgtConv(uint8_t mgt_index);
	
protected:
	GlobalRegistry *globalreg;

	int netstumbler_aref;
	int nullproberesp_aref;
	int lucenttest_aref;

	int client_wepkey_allowed;
	macmap<wep_key_info *> wepkeys;
};

#endif

