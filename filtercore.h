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

#ifndef __FILTERCORE_H__
#define __FILTERCORE_H__

// Core filter functions
//
// Basic filtering class used as a "smart struct" more than anything.  Handle
// parsing, comparing, etc.

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

#include "globalregistry.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_netframe.h"

class FilterCore {
public:

#ifdef HAVE_LIBPCRE
	typedef struct {
		pcre *re;
		pcre_extra *study;
		string filter;
	} pcre_filter;
#endif

	FilterCore();
	FilterCore(GlobalRegistry *in_globalreg);

	// Add a filter line to a block
	int AddFilterLine(string filter_str);

	// Run a set of addresses through the filter.  We extract this to the
	// generic layer here so that we're not necessarily tied to the
	// packinfo_80211
	int RunFilter(mac_addr bssidmac, mac_addr sourcemac,
				  mac_addr destmac);
	// Run the PCRE filters against the incoming text.  This isn't an ifdef since
	// we'll catch it in the implementation.  We don't want to have to ifdef every
	// filter call.
	int RunPcreFilter(string in_text);

	int FetchBSSIDHit() { return bssid_hit; }
	int FetchSourceHit() { return source_hit; }
	int FetchDestHit() { return dest_hit; }
	int FetchHits() { return bssid_hit + source_hit + dest_hit; }
	int FetchPCREHits();

protected:
	GlobalRegistry *globalreg;

	macmap<int> bssid_map;
	macmap<int> source_map;
	macmap<int> dest_map;
	int bssid_invert;
	int source_invert;
	int dest_invert;

	int bssid_hit;
	int source_hit;
	int dest_hit;

#ifdef HAVE_LIBPCRE
	vector<FilterCore::pcre_filter *> pcre_vec;
	int pcre_invert;
	int pcre_hit;
#endif
};

#endif
