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

// Include the BSD radiotap headers... This may be including other bits we
// don't really need to include here, but I don't know what inter-dependencies
// they have
#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/if_wi_ieee.h>

#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif

#endif // Sys/NetBSD

#ifdef SYS_FREEBSD
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>

#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif

#endif // FreeBSD

// Include the linux radiotap headers either from local or system copies
#if (defined(SYS_LINUX) && defined(HAVE_LINUX_SYS_RADIOTAP))
#include <net/ieee80211_radiotap.h>
#elif (defined(SYS_LINUX) && defined(HAVE_RADIOTAP))
#include "linux_ieee80211_radiotap.h"
#endif

// Maximum SSID length for storing
#define MAX_STORED_SSID		32

// for DLT_PRISM_HEADER
#define WLAN_DEVNAMELEN_MAX	16

// Define linktype headers if we don't have them in our includes for some
// reason
#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER	119
#endif

#ifndef DLT_IEEE802_11_RADIO	
#define DLT_IEEE802_11_RADIO 127
#endif

// Define kluged local linktype for BSD lame-mode
#define KDLT_BSD802_11		-100

// Extension to radiotap header not yet included in all BSD's
#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif

#ifndef IEEE80211_IOC_CHANNEL
#define IEEE80211_IOC_CHANNEL 0
#endif

// Prism 802.11 headers from wlan-ng tacked on to the beginning of a
// pcap packet... Snagged from the wlan-ng source
typedef struct {
	uint32_t did __attribute__ ((packed));
	uint16_t status __attribute__ ((packed));
	uint16_t len __attribute__ ((packed));
	uint32_t data __attribute__ ((packed));
} p80211item_uint32_t;

typedef struct {
	uint32_t msgcode __attribute__ ((packed));
	uint32_t msglen __attribute__ ((packed));
	uint8_t devname[WLAN_DEVNAMELEN_MAX] __attribute__ ((packed));
	p80211item_uint32_t hosttime __attribute__ ((packed));
	p80211item_uint32_t mactime __attribute__ ((packed));
	p80211item_uint32_t channel __attribute__ ((packed));
	p80211item_uint32_t rssi __attribute__ ((packed));
	p80211item_uint32_t sq __attribute__ ((packed));
	p80211item_uint32_t signal __attribute__ ((packed));
	p80211item_uint32_t noise __attribute__ ((packed));
	p80211item_uint32_t rate __attribute__ ((packed));
	p80211item_uint32_t istx __attribute__ ((packed));
	p80211item_uint32_t frmlen __attribute__ ((packed));
} wlan_ng_prism2_header;

// Prism 802.11 headers from the openbsd Hermes drivers, even though they don't return
// a valid linktype yet.  Structure lifted from bsd_airtools by dachb0den labs.
typedef struct {
	u_int16_t wi_status;
	u_int16_t wi_ts0;
	u_int16_t wi_ts1;
	u_int8_t  wi_silence;
	u_int8_t  wi_signal;
	u_int8_t  wi_rate;
	u_int8_t  wi_rx_flow;
	u_int16_t wi_rsvd0;
	u_int16_t wi_rsvd1;
} bsd_80211_header;

// wlan-ng (and hopefully others) AVS header, version one.  Fields in
// network byte order.
typedef struct {
	uint32_t version;
	uint32_t length;
	uint64_t mactime;
	uint64_t hosttime;
	uint32_t phytype;
	uint32_t channel;
	uint32_t datarate;
	uint32_t antenna;
	uint32_t priority;
	uint32_t ssi_type;
	int32_t ssi_signal;
	int32_t ssi_noise;
	uint32_t preamble;
	uint32_t encoding;
} avs_80211_1_header;

class PacketSource_Pcap : public KisPacketSource {
public:
	// Standard interface for capturesource
	PacketSource_Pcap(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
		KisPacketSource(in_globalreg, in_name, in_dev) { 
			// Nothing special here
		}

	virtual int OpenSource();
	virtual int CloseSource();

	virtual int FetchDescriptor();

	virtual int Poll();

	static void Pcap_Callback(u_char *bp, const struct pcap_pkthdr *header,
							  const u_char *in_data);

	virtual int FetchChannel();

protected:
	// Mangle linkheaders off a frame, etc
	virtual int ManglePacket(kis_packet *packet);

	// Parse the data link type
    virtual int DatalinkType();

	// Mangle Prism2 and AVS frames
	int Prism2KisPack(kis_packet *packet);
	// If we have radiotap headers, mangle those into kis packets
	int Radiotap2KisPack(kis_packet *packet);

	pcap_t *pd;
	int datalink_type;
};	

class PacketSource_Pcapfile : public PacketSource_Pcap {
public:
	PacketSource_Pcapfile(GlobalRegistry *in_globalreg, string in_name, 
						  string in_dev) :
		PacketSource_Pcap(in_globalreg, in_name, in_dev) { }
	virtual int OpenSource();
	virtual int Poll();
protected:
	// Do nothing here, we don't have an independent radio data fetch,
	// we're just filling in the virtual
	virtual void FetchRadioData(kis_packet *in_packet) { };
};

// Pcapfile registrant and 0-return unmonitor function
KisPacketSource *packetsource_pcapfile_registrant(REGISTRANT_PARMS);
int unmonitor_pcapfile(MONITOR_PARMS);

#endif /* have_libpcap */

#endif

