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

#include "config.h"

#ifdef SYS_NETBSD
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#endif

#if (defined(HAVE_LIBPCAP) && (defined(SYS_OPENBSD) || defined(SYS_NETBSD) || \
							   defined(SYS_FREEBSD)))

#include <string>
#include <sstream>
#include <errno.h>

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "packetsource_pcap.h"
#include "packetsource_bsdrt.h"

#include "packetsourcetracker.h"

Radiotap_BSD_Controller::Radiotap_BSD_Controller(GlobalRegistry *in_globalreg,
												 string in_dev) {
	globalreg = in_globalreg;
	dev = in_dev;
	sock = -1;
}

Radiotap_BSD_Controller::~Radiotap_BSD_Controller() {
	if (sock >= 0)
		close(sock);
}

int Radiotap_BSD_Controller::MonitorEnable() {
	// Get current state 
	(void) GetMediaOpt(prev_options, prev_mode);
	(void) Get80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
	(void) GetIfFlags(prev_flags);

	// Enter monitor mode, set the specified channel, enable promisc
	// reception, force the interface up, set bpf
	if (SetMediaOpt(IFM_IEEE80211_MONITOR, IFM_AUTO) == 0) {
		_MSG("BSD interface set media command failed.  The drivers for this device "
			 "may not support radiotap operation.", MSGFLAG_FATAL);
		return 0;
	}

#if 0
	if (Set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL) < 0) {
		_MSG("BSD interface set channel operation failed, attempting to restore "
			 "previous operation mode and terminate", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		(void) SetMediaOpt(prev_options, prev_mode);
		return 0;
	}
#endif

#if defined(SYS_FREEBSD)
	if (SetIfFlags(prev_flags | IFF_PPROMISC | IFF_UP) == 0) {
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
	if (SetIfFlags(prev_flags | IFF_PROMISC | IFF_UP) == 0) {
#endif
		_MSG("BSD interface set promisc operation failed, attempting to restore "
			 "previous operation mode and terminate", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		(void) Set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
		(void) SetMediaOpt(prev_options, prev_mode);
		return 0;
	}

	return 1;
}

int Radiotap_BSD_Controller::MonitorReset() {
	(void) SetIfFlags(prev_flags);
	// Reset the channel before switching modes
	// (void) Set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
	(void) SetMediaOpt(prev_options, prev_mode);
	return 1;
}

int Radiotap_BSD_Controller::ChangeChannel(int in_ch) {
	if (Set80211(IEEE80211_IOC_CHANNEL, in_ch, 0, NULL) == 0) {
		_MSG("BSD interface control failed to set channel on '" + dev + "': " +
			 strerror(errno), MSGFLAG_ERROR);
		return 0;
	} 

	return 1;
}

int Radiotap_BSD_Controller::GetMediaOpt(int& options, int& mode) {
	struct ifmediareq ifmr;

	if (CheckSocket() == 0)
		return false;

	memset(&ifmr, 0, sizeof(ifmr));
	strncpy(ifmr.ifm_name, dev.c_str(), sizeof(ifmr.ifm_name));

	// Go through the motions of reading all supported media because
	// we need to know both the current and top-level media types
	if (ioctl(sock, SIOCGIFMEDIA, (caddr_t) &ifmr) < 0) {
		_MSG("BSD interface control failed to get media for '" + dev + 
			 "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	options = IFM_OPTIONS(ifmr.ifm_current);
	mode = IFM_MODE(ifmr.ifm_current);

	return 1;
}

int Radiotap_BSD_Controller::SetMediaOpt(int options, int mode) {
	struct ifmediareq ifmr;
	struct ifreq ifr;
	int *mwords;

	if (CheckSocket() == 0)
		return 0;

	memset(&ifmr, 0, sizeof(ifmr));
	strncpy(ifmr.ifm_name, dev.c_str(), sizeof(ifmr.ifm_name));

	// Go through to motions of reading all the media to get current and 
	// top-level types
	if (ioctl(sock, SIOCGIFMEDIA, (caddr_t) &ifmr) < 0) {
		_MSG("BSD interface control failed to get media for '" + dev +
			 "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	if (ifmr.ifm_count == 0) {
		_MSG("BSD interface control failed to get media (no media types?) "
			 "for '" + dev + "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	mwords = new int[ifmr.ifm_count];
	if (mwords == NULL) {
		_MSG("BSD interface control cannot malloc interface array, out of "
			 "memory or other badness.", MSGFLAG_PRINTERROR);
		return 0;
	}

	ifmr.ifm_ulist = mwords;
	if (ioctl(sock, SIOCGIFMEDIA, (caddr_t) &ifmr) < 0) {
		_MSG("BSD interface control failed to get media "
			 "for '" + dev + "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	delete[] mwords;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev.c_str(), sizeof(ifr.ifr_name));
	ifr.ifr_media = (ifmr.ifm_current &~ IFM_OMASK) | options;
	ifr.ifr_media = (ifr.ifr_media &~ IFM_MMASK) | IFM_MAKEMODE(mode);

	if (ioctl(sock, SIOCSIFMEDIA, (caddr_t) &ifr) < 0) {
		_MSG("BSD interface control failed to set media "
			 "for '" + dev + "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	return 1;
}

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)

// Simple 802.11 ioctl replacement for open/net, only used for channsel set/get.
// This should be rewritten to be *BSD agnostic

int Radiotap_BSD_Controller::Get80211(int type, int& val, int len, uint8_t *data) {
	struct ieee80211chanreq channel;

	if (CheckSocket() == 0)
		return 0;

	memset(&channel, 0, sizeof(channel));
	strlcpy(channel.i_name, dev.c_str(), sizeof(channel.i_name));
	if (ioctl(sock, SIOCG80211CHANNEL, (caddr_t) &channel) < 0) {
		_MSG("BSD interface control failed to get channel info for '" + dev + 
			 "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	val = channel.i_channel;
	return 1;
}

int Radiotap_BSD_Controller::Set80211(int type, int val, int len, uint8_t *data) {
	struct ieee80211chanreq channel;

	if (CheckSocket() == 0)
		return 0;

	strlcpy(channel.i_name, dev.c_str(), sizeof(channel.i_name));
	channel.i_channel = (uint16_t) val;
	if (ioctl(sock, SIOCS80211CHANNEL, (caddr_t) &channel) == -1) {
		ostringstream osstr;
		osstr << "BSD interface control failed to set channel " << val << " for "
			"interface '" << dev << "': " << strerror(errno);
		_MSG(osstr.str(), MSGFLAG_ERROR);
		return 0;
	}

	return 1;
}

#elif defined(SYS_FREEBSD) /* Freebsd has a generic 802.11 ioctl */

int Radiotap_BSD_Controller::Get80211(int type, int& val, int len, uint8_t *data) {
	struct ieee80211req ireq;

	if (CheckSocket() == 0)
		return 0;

	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, dev.c_str(), sizeof(ireq.i_name));
	ireq.i_type = type;
	ireq.i_len = len;
	ireq.i_data = data;
	if (ioctl(sock, SIOCG80211, &ireq) < 0) {
		_MSG("BSD interface control failed to get 80211 info for '" + dev + "': " +
			 strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

	val = ireq.i_val;
	return 1;
}

int Radiotap_BSD_Controller::Set80211(int type, int val, int len, uint8_t *data) {
	struct ieee80211req ireq;

	if (CheckSocket() == 0) 
		return 0;

	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, dev.c_str(), sizeof(ireq.i_name));
	ireq.i_type = type;
	ireq.i_val = val;
	ireq.i_len = len;
	ireq.i_data = data;
	if (ioctl(sock, SIOCS80211, &ireq) < 0) {
		_MSG("BSD interface control failed to set 80211 info for '" + dev + "': " +
			 strerror(errno), MSGFLAG_ERROR);
	}

	return 1;
}
#endif

int Radiotap_BSD_Controller::GetIfFlags(int& flags) {
	struct ifreq ifr;

	if (CheckSocket() == 0)
		return 0;

	strncpy(ifr.ifr_name, dev.c_str(), sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		_MSG("BSD interface control failed to get interface flags for '" + dev + 
			 "': " + strerror(errno), MSGFLAG_ERROR);
		return 0;
	}

#if defined(SYS_FREEBSD)
	flags = (ifr.ifr_flags & 0xFFFF) | (ifr.ifr_flagshigh << 16);
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
	flags = ifr.ifr_flags;
#endif

	return 1;
}

int Radiotap_BSD_Controller::SetIfFlags(int flags) {
	struct ifreq ifr;

	if (CheckSocket() == 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev.c_str(), sizeof (ifr.ifr_name));
#if defined(SYS_FREEBSD)
	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = flags >> 16;
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
	ifr.ifr_flags = flags;
#endif
	if (ioctl(sock, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		_MSG("BSD interface control failed to set interface flags for '" + dev + 
			 "': " + strerror(errno), MSGFLAG_PRINTERROR);
		return 0;
	}   

	return 1;
}

int Radiotap_BSD_Controller::CheckSocket() {
	if (sock < 0) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) {
			_MSG("BSD interface control failed to create AF_INET socket",
				 MSGFLAG_ERROR);
			return 0;
		}
	}
	
	return 1;
}

int PacketSource_BSDRT::AutotypeProbe(string in_device) {
	return 0;
}

int PacketSource_BSDRT::OpenSource() {
	int r = PacketSource_Pcap::OpenSource();

	if (r < 0)
		return r;

	// Anything but windows and linux
    #if defined (SYS_OPENBSD) || defined(SYS_NETBSD) || defined(SYS_FREEBSD) \
		|| defined(SYS_DARWIN)
	// Set the DLT in the order of what we want least, since the last one we
	// set will stick
	pcap_set_datalink(pd, DLT_IEEE802_11);
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO_AVS);
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	// Hack to re-enable promisc mode since changing the DLT seems to make it
	// drop it on some bsd pcap implementations
	ioctl(pcap_get_selectable_fd(pd), BIOCPROMISC, NULL);
	// Hack to set the fd to IOIMMEDIATE, to solve problems with select() on bpf
	// devices on BSD
	int v = 1;
	ioctl(pcap_get_selectable_fd(pd), BIOCIMMEDIATE, &v);
	#endif

	if (DatalinkType() < 0) {
		pcap_close(pd);
		return -1;
	}

	return 1;
}

int PacketSource_BSDRT::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("radiotap_bsd_ag", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("radiotap_bsd_a", this, "IEEE80211a", 1);
	tracker->RegisterPacketProto("radiotap_bsd_g", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("radiotap_bsd", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("bsd", this, "IEEE80211b", 1);
	return 1;
}

int PacketSource_BSDRT::EnableMonitor() {
	if (bsdcon->MonitorEnable() == 0) {
		delete bsdcon;
		_MSG("Unable to enable monitor mode on '" + interface + "'.", 
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	return 0;
}

int PacketSource_BSDRT::DisableMonitor() {
	if (bsdcon == NULL) {
		_MSG("BSD interface controller left in unknown mode for " + interface + 
			 ".  Interface cannot be cleanly returned to previous settings and "
			 "may be left in an unusable state.", MSGFLAG_PRINTERROR);
		return -1;
	}

	if (bsdcon->MonitorReset() == 0) {
		delete bsdcon;
		bsdcon = NULL;
		_MSG("Failed to reset wireless mode of '" + interface + 
			 "' to stored values. " "It may be left in an unusable state.", 
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	delete bsdcon;
	bsdcon = NULL;

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_BSDRT::SetChannel(unsigned int in_ch) {
	if (bsdcon == NULL) {
		_MSG("PacketSource_BSD channel set called while bsdcon controller is NULL",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	if (bsdcon->ChangeChannel(in_ch) == 0) {
		consec_error++;

		if (consec_error > 5) {
			return -1;
		}
		
		return 0;
	}

	consec_error = 0;

	return 1;
}

int PacketSource_BSDRT::CheckDLT(int dlt) {
	int found = 0;
	int i, n, *dl;

	n = pcap_list_datalinks(pd, &dl);

	for (i = 0; i < n; i++) {
		if (dl[i] == dlt) {
			found = 1;
			break;
		}
	}

	free(dl);
	return found;
}

int PacketSource_BSDRT::FetchHardwareChannel() {
	int chan;

	Radiotap_BSD_Controller bsdcon(globalreg, interface);

	if (bsdcon.Get80211(IEEE80211_IOC_CHANNEL, chan, 0, NULL) == 0) {
		return -1;
	}

	return chan;
}

void PacketSource_BSDRT::FetchRadioData(kis_packet *in_packet) {
	// Nothing to do here
	return;
}

int PacketSource_BSDRT::DatalinkType() {
    char errstr[STATUS_MAX] = "";

    datalink_type = pcap_datalink(pd);

	// Known good pcap generic header types
	if (datalink_type == DLT_PRISM_HEADER ||
		datalink_type == DLT_IEEE802_11_RADIO ||
		datalink_type == DLT_IEEE802_11_RADIO_AVS ||
		datalink_type == DLT_IEEE802_11 ||
		datalink_type == DLT_PPI)
		return 1;

    // Blow up if we're not valid 802.11 headers
	// Need to not blow up on en10mb?  Override.
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, STATUS_MAX, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", interface.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
    } else {
        snprintf(errstr, STATUS_MAX, "Unknown link type %d reported.  Continuing on "
                 "blindly and hoping we get something useful...  This is ALMOST "
				 "CERTIANLY NOT GOING TO WORK RIGHT", datalink_type);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
    }

	return 1;
}

#endif

