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

#ifndef __PACKETSOURCE_WEXT_H__
#define __PACKETSOURCE_WEXT_H__

#include "config.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

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

#define USE_PACKETSOURCE_WEXT
#define USE_PACKETSOURCE_MADWIFI
#define USE_PACKETSOURCE_WRT54PRISM

// Another tier of subclassing.  In some respects this is sort of silly, but it's
// fairly logical as far as progression of functionality goes.
//
// Wext is both an actual class and a virtual layer.  Some wext code needs
// special hooks for monitor, channel, etc, and can subclass this.  Otherwise,
// Wext handles it internally w/ the standard commands
class PacketSource_Wext : public PacketSource_Pcap {
public:
	PacketSource_Wext() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Wext() called\n");
		exit(1);
	}

	PacketSource_Wext(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Wext(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	virtual int OpenSource();

	PacketSource_Wext(GlobalRegistry *in_globalreg, string in_interface,
					  vector<opt_pair> *in_opts); 
	virtual ~PacketSource_Wext();

	virtual int ParseOptions(vector<opt_pair> *in_opts);

	// Should be, something can override if it needs
	virtual int FetchChannelCapable() { return 1; }

	// Generic-level functions
	virtual int EnableMonitor();
	virtual int DisableMonitor();
	virtual int SetChannel(unsigned int in_ch);
	virtual int FetchHardwareChannel();

	virtual vector<unsigned int> FetchSupportedChannels(string in_interface);

	virtual int ScanWpaSupplicant();

protected:
	// Stuff we need to track to restore later
	struct linux_ifparm {
		short flags;
		char essid[MAX_SSID_LEN + 1];
		int channel;
		int mode;
		int privmode;
		int prismhdr;
	};

	int stored_flags;
	string stored_essid;
	int stored_channel;
	int stored_mode;
	int stored_privmode;

	string vap, parent;
	int use_mac80211, opp_vap, force_vap;
	vector<unsigned int> mac80211_flag_vec;
	void *nlcache, *nlfamily;
	bool ignore_primary_state;

	virtual void FetchRadioData(kis_packet *in_packet);

	virtual void OpenWpaSupplicant();

	int scan_wpa;
	int wpa_sock;
	string wpa_path;
	string wpa_local_path;
	struct sockaddr_un wpa_local, wpa_dest;
	int wpa_timer_id;
};	

// Madwifi subclass
// Implements local detection of the subtype (madwifi_a, madwifi_bg, etc)
class PacketSource_Madwifi : public PacketSource_Wext {
public:
	PacketSource_Madwifi() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Madwifi() called\n");
		exit(1);
	}

	PacketSource_Madwifi(GlobalRegistry *in_globalreg) :
		PacketSource_Wext(in_globalreg) {
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Madwifi(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	virtual int OpenSource();

	PacketSource_Madwifi(GlobalRegistry *in_globalreg, string in_interface,
						 vector<opt_pair> *in_opts);
	virtual ~PacketSource_Madwifi() { }

	virtual int EnableMonitor();
	virtual int DisableMonitor();

protected:
	// 1 - madwifi_a
	// 2 - madwifi_b
	// 3 - madwifi_g
	// 0 - madwifi_ag
	int madwifi_type;

	int vapdestroy;
	int driver_ng;
	int shutdowndestroy;
	string parent;
};

// Wrt54prism subclass
// Implements the wrt54prism source for openwrt
class PacketSource_Wrt54Prism : public PacketSource_Wext { public:
	// HANDLED PACKET SOURCES:
	// wrt54prism
	PacketSource_Wrt54Prism() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Wrt54prism() called\n");
		exit(1);
	}

	PacketSource_Wrt54Prism(GlobalRegistry *in_globalreg) :
		PacketSource_Wext(in_globalreg) {
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg, 
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Wrt54Prism(in_globalreg, in_interface, in_opts);
	}

	// We don't do autotype scanning
	virtual int AutotypeProbe(string in_device) { return 0; }

	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_Wrt54Prism(GlobalRegistry *in_globalreg, string in_interface,
							vector<opt_pair> *in_opts);
							
	virtual ~PacketSource_Wrt54Prism() { }

	virtual int OpenSource();
};

#endif /* have_libpcap && sys_linux */

#endif

