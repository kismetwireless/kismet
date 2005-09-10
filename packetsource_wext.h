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
 * Anything controlled by the standard wireless extensions live here
 *
 */

#ifndef __PACKETSOURCE_WEXT_H__
#define __PACKETSOURCE_WEXT_H__

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
#else
#include "linux_ieee80211_radiotap.h"
#endif

// Stuff we need to track to restore later
typedef struct linux_ifparm {
    short flags;
    char essid[MAX_SSID_LEN + 1];
    int channel;
    int mode;
    int privmode;
    int prismhdr;
};

class PacketSource_Wext : public PacketSource_Pcap {
public:
	// Standard interface for capturesource
	PacketSource_Wext(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
		PacketSource_Pcap(in_globalreg, in_name, in_dev) { 
			// Zero out the modern chan stuff
			modern_chancontrol = -1;
		}

	virtual int FetchChannel();

	// Tacker val to tell us if we have modern channel control functions
	int modern_chancontrol;

protected:
	// Inherited from grandparent 
	virtual void FetchRadioData(kis_packet *in_packet);
};	

// ---------- Registrant Functions

// Standard wireless extension based registrant
KisPacketSource *packetsource_wext_registrant(REGISTRANT_PARMS);
// Standard wireless extension with FCS footers
KisPacketSource *packetsource_wext_fcs_registrant(REGISTRANT_PARMS);
// Split-source eth1:wifix style registrant
KisPacketSource *packetsource_wext_split_registrant(REGISTRANT_PARMS);
// Split-source eth1:wifix style registrant with fcs
KisPacketSource *packetsource_wext_splitfcs_registrant(REGISTRANT_PARMS);

// ---------- Monitor enter/exit Functions

// Standard wext monitor/unmonitor functions that get called by others
int monitor_wext_core(MONITOR_PARMS, char *errstr);
int unmonitor_wext_core(MONITOR_PARMS, char *errstr);

// Basic 'mode monitor' functions that should be used for all the modern
// drivers now.
int monitor_wext_std(MONITOR_PARMS);
int unmonitor_wext_std(MONITOR_PARMS);

// Madwifi core and individual monitor hooks
int monitor_madwifi_core(MONITOR_PARMS, char *errstr, int mode);
int unmonitor_madwifi(MONITOR_PARMS);
int monitor_madwifi_a(MONITOR_PARMS);
int monitor_madwifi_b(MONITOR_PARMS);
int monitor_madwifi_g(MONITOR_PARMS);
int monitor_madwifi_ag(MONITOR_PARMS);


// ---------- Channel Manipulation Functions

int chancontrol_wext_core(CHCONTROL_PARMS, char *errstr);

int chancontrol_wext_std(CHCONTROL_PARMS);

// ---------- Automatic Registration Functions
int autoprobe_ipw2200(AUTOPROBE_PARMS);
int autoprobe_madwifi(AUTOPROBE_PARMS);

#endif /* have_libpcap && sys_linux */

#endif

