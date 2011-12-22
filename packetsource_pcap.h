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
 * pcapsource handes the largest number of card types.  ideally, everything
 * should be part of pcapsource so that different tools can use them 
 * besides kismet.
 *
 * pcapsource encompasses multiple methods of entering monitor mode and
 * multiple link encapsulation types, the only underlying consistency
 * is the use of libpcap to fetch frames.
 * 
 */

#ifndef __PACKETSOURCE_PCAP_H__
#define __PACKETSOURCE_PCAP_H__

#include "config.h"

#ifdef HAVE_LIBPCAP

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "ifcontrol.h"

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
}

#include "kis_ppi.h"

// Include the various variations of BSD radiotap headers from the system if
// we can get them, incidentally pull in other stuff but I'm not sure whats
// needed so we'll leave the extra headers for now
#ifdef HAVE_BSD_SYS_RADIOTAP

#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/if_wi_ieee.h>

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif // Open/Net

#ifdef SYS_FREEBSD
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif // FreeBSD

#endif // BSD radiotap

// We provide the pcap packet sources
#define USE_PACKETSOURCE_PCAPFILE

// Maximum SSID length for storing
#define MAX_STORED_SSID		32

#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11		105
#endif

// Define kluged local linktype for BSD lame-mode
#define KDLT_BSD802_11		-100

#ifndef IEEE80211_IOC_CHANNEL
#define IEEE80211_IOC_CHANNEL 0
#endif

class PacketSource_Pcap : public KisPacketSource {
public:
	PacketSource_Pcap() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Pcap() called\n");
		exit(1);
	}

	PacketSource_Pcap(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {
	}

	// No creation or probe for this high-level metasource
	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) = 0;

	virtual int AutotypeProbe(string in_device) = 0;
	virtual int RegisterSources(Packetsourcetracker *tracker) = 0;

	PacketSource_Pcap(GlobalRegistry *in_globalreg, string in_interface,
					  vector<opt_pair> *in_opts) :
		KisPacketSource(in_globalreg, in_interface, in_opts) { 
			pd = NULL;
			override_dlt = -1;
		}
	virtual ~PacketSource_Pcap() { }

	// No management functions at this level
	virtual int EnableMonitor() = 0;
	virtual int DisableMonitor() = 0;
	virtual int FetchChannelCapable() = 0;
	virtual int SetChannel(unsigned int in_ch) = 0;

	// We expect to be drive by the child IPC
	virtual int ChildIPCControl() { return 1; }

	virtual int OpenSource();
	virtual int CloseSource();

	virtual int FetchDescriptor();

	virtual int Poll();

	static void Pcap_Callback(u_char *bp, const struct pcap_pkthdr *header,
							  const u_char *in_data);

	virtual int FetchHardwareChannel();

	// Mangle linkheaders off a frame, etc
	virtual int ManglePacket(kis_packet *packet, kis_datachunk *linkchunk);

protected:

	// Parse the data link type
    virtual int DatalinkType();

	// If we're just a straight up frame
	int Eight2KisPack(kis_packet *packet, kis_datachunk *linkchunk);

	pcap_t *pd;
	int datalink_type;
	int override_dlt;
};	

class PacketSource_Pcapfile : public PacketSource_Pcap {
public:
	PacketSource_Pcapfile() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Pcapfile() called\n");
		exit(1);
	}

	PacketSource_Pcapfile(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {
	}

	// This should return a new object of its own subclass type
	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Pcapfile(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);

	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_Pcapfile(GlobalRegistry *in_globalreg, 
						  string in_interface,
						  vector<opt_pair> *in_opts) :
		PacketSource_Pcap(in_globalreg, in_interface, in_opts) { 
			// Foo
		}
	virtual ~PacketSource_Pcapfile() { }

	virtual int OpenSource();
	virtual int Poll();

	virtual int FetchChannelCapable() { return 0; }
	// Basically do nothing because they have no meaning
	virtual int EnableMonitor() { return 0; }
	virtual int DisableMonitor() { return PACKSOURCE_UNMONITOR_RET_SILENCE; }
	virtual int SetChannel(unsigned int in_ch) { return 0; }
	virtual int HopNextChannel() { return 0; }

protected:
	// Do nothing here, we don't have an independent radio data fetch,
	// we're just filling in the virtual
	virtual void FetchRadioData(kis_packet *in_packet) { };
};

#endif /* have_libpcap */

#endif

