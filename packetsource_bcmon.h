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

/* bcmon uses a hacked up firmware on Android to get monitor mode, the interface
 * doesn't react as normal.  This ignores its quirks. */

#ifndef __PACKETSOURCE_BCMON_H__
#define __PACKETSOURCE_BCMON_H__

#include "config.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

#include "packetsource_wext.h"

#define USE_PACKETSOURCE_BCMON

class PacketSource_Bcmon : public PacketSource_Wext {
public:
	PacketSource_Bcmon() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Bcmon() called\n");
		exit(1);
	}

	PacketSource_Bcmon(GlobalRegistry *in_globalreg) :
		PacketSource_Wext(in_globalreg) {
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Bcmon(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_Bcmon(GlobalRegistry *in_globalreg, string in_interface,
						 vector<opt_pair> *in_opts);
	virtual ~PacketSource_Bcmon() { }

	virtual int EnableMonitor();
	virtual int DisableMonitor();

    virtual int DatalinkType();
};

#endif
#endif

