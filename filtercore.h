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

#include "globalregistry.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_netframe.h"

class FilterCore {
public:
	FilterCore();
	FilterCore(GlobalRegistry *in_globalreg);

	// Add a filter line to a block
	int AddFilterLine(string filter_str);

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
};

#endif
