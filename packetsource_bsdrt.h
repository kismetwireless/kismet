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
 * BSD is the generic BSD layer for capturing packets and controlling interfaces
 *
 */

#ifndef __PACKETSOURCE_BSD_H__
#define __PACKETSOURCE_BSD_H__

#include "config.h"

#if (defined(HAVE_LIBPCAP) && (defined(SYS_OPENBSD) || defined(SYS_NETBSD) || \
							   defined(SYS_FREEBSD)))

#include <string>
#include <errno.h>

#include "globalregistry.h"
#include "messagebus.h"

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "packetsource_pcap.h"

#define USE_PACKETSOURCE_BSDRT

#define KDLT_BSD802_11			-100
#define KDLT_IEEE802_11_RADIO	127

// BSD packet source controller class, handles all the mode, channel, etc setting.
// Thanks to Sam Leffler and Pedro la Peu for the original variant and OpenBSD 
// updates of this
class Radiotap_BSD_Controller {
public:
	Radiotap_BSD_Controller(GlobalRegistry *in_globalreg, string in_dev);
	~Radiotap_BSD_Controller();

	int MonitorEnable();
	int MonitorReset();
	int ChangeChannel(int in_ch);

	int GetMediaOpt(int& options, int& mode);
	int SetMediaOpt(int options, int mode);
	int GetIfFlags(int &flags);
	int SetIfFlags(int value);
	int Get80211(int type, int& val, int len, uint8_t *data);
	int Set80211(int type, int val, int len, uint8_t *data);

protected:
	GlobalRegistry *globalreg;

	int CheckSocket();

	int sock;
	int prev_flags;
	int prev_options;
	int prev_mode;
	int prev_chan;

	string dev;
};

// BSD radiotap
class PacketSource_BSDRT : public PacketSource_Pcap {
public:
	// HANDLED PACKET SOURCES:
	// radiotap_bsd_ag
	// radiotap_bsd_a
	// radiotap_bsd_g
	// radiotap_bsd_b
	PacketSource_BSDRT() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_BSDRT() called\n");
		exit(1);
	}

	PacketSource_BSDRT(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {
			bsdcon = NULL;
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_BSDRT(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	virtual int OpenSource();

	PacketSource_BSDRT(GlobalRegistry *in_globalreg, string in_interface,
					   vector<opt_pair> *in_opts) :
		PacketSource_Pcap(in_globalreg, in_interface, in_opts) {
			bsdcon = new Radiotap_BSD_Controller(in_globalreg, in_interface.c_str());
		}
	virtual ~PacketSource_BSDRT() { }

	virtual int FetchChannelCapable() { return 1; }

	virtual int EnableMonitor();
	virtual int DisableMonitor();
	virtual int SetChannel(unsigned int in_ch);
	virtual int FetchHardwareChannel();
	
protected:
	Radiotap_BSD_Controller *bsdcon;

	// Override data link type to handle bsd funky bits
	virtual int DatalinkType();

	// BSD radio fetch
	virtual void FetchRadioData(kis_packet *in_packet);

	// Check that we support the dlt we need
	virtual int CheckDLT(int dlt);
};	

#endif /* have_libpcap && BSD */

#endif

