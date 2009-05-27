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

/*
 * WEXT is the linux wireless extensions tools subset of pcap capture devices.
 * Anything controlled by the standard wireless extensions will live here.
 */

#ifndef __PACKETSOURCE_IPWLIVE_H__
#define __PACKETSOURCE_IPWLIVE_H__

#include "config.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "packetsource_pcap.h"
#include "ifcontrol.h"
#include "iwcontrol.h"

#ifdef HAVE_LINUX_SYS_RADIOTAP
#include <net/ieee80211_radiotap.h>
#endif

#ifdef HAVE_LOCALRADIOTAP
#include "local_ieee80211_radiotap.h"
#endif

#define USE_PACKETSOURCE_IPWLIVE

// Another pcap variant: ipwlivetap, for doing rfmon+managed
// For ipw2200 and ipw3945
class PacketSource_Ipwlive : public PacketSource_Pcap {
public:
	// HANDLED PACKET SOURCES:
	// ipwlivetap
	PacketSource_Ipwlive() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Ipwlive() called\n");
		exit(1);
	}

	PacketSource_Ipwlive(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Ipwlive(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_Ipwlive(GlobalRegistry *in_globalreg, string in_interface,
						 vector<opt_pair> *in_opts) :
		PacketSource_Pcap(in_globalreg, in_interface, in_opts) { 
			// foo
		}
	virtual ~PacketSource_Ipwlive() { }

	// Should be, something can override if it needs
	virtual int FetchChannelCapable() { return 0; }

	// Generic-level functions
	virtual int EnableMonitor();
	virtual int DisableMonitor();
	virtual int SetChannel(unsigned int in_ch);
	virtual int FetchChannel();

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };
};	


#endif /* have_libpcap && sys_linux */

#endif

