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

#ifndef __PACKETSOURCE_DARWIN_H__
#define __PACKETSOURCE_DARWIN_H__

#include "config.h"

#if defined(HAVE_LIBPCAP) && defined(SYS_DARWIN)

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "packetsource_pcap.h"

#ifdef HAVE_LOCALRADIOTAP
#include "local_ieee80211_radiotap.h"
#endif

#define USE_PACKETSOURCE_DARWIN

class PacketSource_Darwin : public PacketSource_Darwin {
public:
	PacketSource_Darwin() {
		fprintf(Stderr, "FATAL OOPS: Packetsource_Darwin()\n");
		exit(1);
	}

	PacketSource_Darwin(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {

	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_type, string in_name,
										  string in_dev) {
		return new PacketSource_Darwin(in_globalreg, in_type, in_name, in_dev);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_Darwin(GlobalRegistry *in_globalreg, string in_type,
						string in_name, string in_dev); 

	virtual ~PacketSource_Darwin() { }

	virtual int OpenSource();

	virtual int FetchChannelCapable() { return 1; }

	virtual int EnableMonitor();
	virtual int DisableMonitor();
	virtual int SetChannel(unsigned int in_ch);
	virtual int FetchChannel();

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };
};

#endif /* osx and pcap */

#endif

