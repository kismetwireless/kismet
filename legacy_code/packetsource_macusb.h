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

#ifndef __PACKETSOURCE_MACUSB_H__
#define __PACKETSOURCE_MACUSB_H__

#include "config.h"

#if defined(HAVE_LIBPCAP) && defined(SYS_DARWIN)

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "ifcontrol.h"
#include "packetsource_pcap.h"

#include "kis_ppi.h"

#define USE_PACKETSOURCE_MACUSB

class PacketSource_MacUSB : public PacketSource_Pcap {
public:
	PacketSource_MacUSB() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_MacUSB() called\n");
		exit(1);
	}

	PacketSource_MacUSB(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {
	}

	// This should return a new object of its own subclass type
	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_MacUSB(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);

	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_MacUSB(GlobalRegistry *in_globalreg, string in_interface,
						  vector<opt_pair> *in_opts);
	virtual ~PacketSource_MacUSB() { }

	// virtual int OpenSource();
	// virtual int Poll();

	virtual int FetchChannelCapable() { return 1; }
	// In the future maybe we'll start the source automatically?
	virtual int EnableMonitor() { return 0; }
	virtual int DisableMonitor() { return PACKSOURCE_UNMONITOR_RET_SILENCE; }

	// In the future we'll have a channel control mechanism
	virtual int SetChannel(unsigned int in_ch) { return 0; }
	virtual int HopNextChannel() { return 0; }

protected:
	// Do nothing here, we don't have an independent radio data fetch,
	// we're just filling in the virtual
	virtual void FetchRadioData(kis_packet *in_packet) { };
};

#endif 

#endif

