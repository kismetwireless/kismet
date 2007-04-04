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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef HAVE_LINUX_WIRELESS
// Some kernels include ethtool headers in wireless.h and seem to break
// terribly if these aren't defined
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#endif

#include "util.h"
#include "packetsourcetracker.h"
#include "packetsource_wext.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

PacketSource_Wext::PacketSource_Wext(GlobalRegistry *in_globalreg, string in_type, 
									 string in_name, string in_dev) :
	PacketSource_Pcap(in_globalreg, in_type, in_name, in_dev) { 

	if (in_type == "nokia770") {
		SetValidateCRC(1);
	}
}

int PacketSource_Wext::AutotypeProbe(string in_device) {
	ethtool_drvinfo drvinfo;
	char errstr[1024];

	if (Linux_GetDrvInfo(in_device.c_str(), errstr, &drvinfo) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to get ethtool information from device '" + in_device + "'. "
			 "This information is needed to detect the capture type for 'auto' "
			 "sources.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// 2100 has supported rfmon for so long we can just take it
	if (string(drvinfo.driver) == "ipw2100") {
		return 1;
	}
	// We're going to assume a 3945 will just work as well
	if (string(drvinfo.driver) == "ipw3945") {
		return 1;
	}

	if (string(drvinfo.driver) == "ipw2200") {
		int major, minor, tiny;
		if (sscanf(drvinfo.version, "%d.%d.%d", &major, &minor, &tiny) != 3) {
			_MSG("IPW2200 Autoprobe for interface '" + in_device + "' looks "
				 "like an ipw2200 driver, but couldn't parse driver version "
				 "string.", MSGFLAG_ERROR);
			return 0;
		}

		if (major == 1 && minor == 0 && tiny < 4) {
			_MSG("IPW2200 Autoprobe for interface '" + in_device + "' looks "
				 "like an ipw2200 driver, but is reporting a version of the "
				 "driver which is too old to support monitor mode.  "
				 "ipw2200-1.0.4 or newer is required, version seen was '" +
				 string(drvinfo.version) + "'", MSGFLAG_ERROR);
			return -1;
		}

		return 1;
	}

	return 0;
}

int PacketSource_Wext::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketsource("acx100", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("admtek", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("atmel_usb", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("bcm43xx", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("hostap", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("ipw2100", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("ipw2200", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("ipw2915", this, 1, "IEEE80211ab", 6);
	tracker->RegisterPacketsource("ipw3945", this, 1, "IEEE80211ab", 6);
	tracker->RegisterPacketsource("nokia770", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("prism54g", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("rt2400", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("rt2500", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("rt73", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("rt8180", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("zd1211", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("zd1211rw", this, 1, "IEEE80211b", 6);
	return 1;
}

int PacketSource_Wext::EnableMonitor() {
	char errstr[STATUS_MAX];

	// Pull the hardware address from the device and use it to re-seed 
	// the UUID
	uint8_t hwnode[6];
	if (Ifconfig_Get_Hwaddr(interface.c_str(), errstr, hwnode) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to fetch interface hardware address for '" + interface + ", "
			 "this will probably fully fail in a moment when we try to configure "
			 "the interface, but we'll keep going.", MSGFLAG_ERROR);
	}
	src_uuid.GenerateTimeUUID(hwnode);

	if (Ifconfig_Get_Flags(interface.c_str(), errstr, &stored_flags) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to get interface flags for '" + interface + "', "
			 "this will probably fully fail in a moment when we try to configure "
			 "the interface, but we'll keep going.", MSGFLAG_ERROR);
	}

	// Bring the interface up, zero its IP, etc
	if (Ifconfig_Delta_Flags(interface.c_str(), errstr, 
							 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to bring up interface '" + interface + "', check your "
			 "permissions and configuration, and consult the Kismet README file",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Try to grab the channel
	if ((stored_channel = Iwconfig_Get_Channel(interface.c_str(), errstr)) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to get the current channel for interface '" + interface + 
			 "'.  This may be a fatal problem, but we'll keep going in case "
			 "the drivers are reporting incorrectly.", MSGFLAG_ERROR);
		stored_channel = -1;
	}

	// Try to grab the wireless mode
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &stored_mode) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to get current wireless mode for interface '" + interface + 
			 "', check your configuration and consult the Kismet README file",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (stored_mode != LINUX_WLEXT_MONITOR) {
		if (Iwconfig_Set_Mode(interface.c_str(), errstr, LINUX_WLEXT_MONITOR) < 0) {
			_MSG(errstr, MSGFLAG_FATAL);
			_MSG("Failed to set monitor mode on interface '" + interface + "'.  "
				 "This usually means your drivers either do not support monitor "
				 "mode, use a different mechanism than Kismet expected to "
				 "set monitor mode, or that the user which started Kismet does "
				 "not have permission to change the mode.  Make sure you have "
				 "the required version and have applied any patches needed to "
				 "your drivers, and tht you have configured the proper source "
				 "type for Kismet.  See the troubleshooting section of the Kismet "
				 "README for more information.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}
	} else {
		_MSG("Interface '" + interface + "' is already marked as being in "
			 "monitor mode, leaving it as it is.", MSGFLAG_INFO);
	}

	// Try to set the monitor header mode, nonfatal if it doesn't work
	if (Iwconfig_Set_IntPriv(interface.c_str(), "monitor_type", 2, 0, errstr) < 0) {
		_MSG("Capture source '" + interface + "' doesn't appear to use the "
			 "monitor_type iwpriv control.", MSGFLAG_INFO);
	}

	// Try to set the monitor header another way, nonfatal if it doesn't work
	if (Iwconfig_Set_IntPriv(interface.c_str(), "set_prismhdr", 1, 0, errstr) < 0) {
		_MSG("Capture source '" + interface + "' doesn't appear to use the "
			 "set_prismhdr iwpriv control", MSGFLAG_INFO);
	}
	
	// Set the initial channel
	if (SetChannel(initial_channel) < 0) {
		return -2;
	}

	return 0;
}

int PacketSource_Wext::DisableMonitor() {
	char errstr[STATUS_MAX];

	// We don't really care if any of these things fail.  Keep trying.
	SetChannel(stored_channel);
	
	// We do care if this fails
	if (Iwconfig_Set_Mode(interface.c_str(), errstr, stored_mode) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to restore previous wireless mode for interface '" +
			 interface + "'.  It may be left in an unknown or unusable state.",
			 MSGFLAG_ERROR);
		return -1;
	}

	if (Ifconfig_Set_Flags(interface.c_str(), errstr, stored_flags) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to restore previous interface settings for '" + interface + "'. "
			 "It may be left in an unknown or unusable state.", MSGFLAG_ERROR);
		return -1;
	}

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_Wext::SetChannelSequence(vector<unsigned int> in_seq) {
	return PacketSource_Pcap::SetChannelSequence(in_seq);
}

int PacketSource_Wext::SetChannel(unsigned int in_ch) {
	char errstr[STATUS_MAX];

	// Set and exit if we're ok
    if (Iwconfig_Set_Channel(interface.c_str(), in_ch, errstr) >= 0) {
		consec_error = 0;
        return 1;
    }

	if (consec_error > 5) {
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
	} else {
		_MSG(errstr, MSGFLAG_ERROR);
	}

	int curmode;
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &curmode) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to change channel on interface '" + interface + "' and "
			 "failed to fetch current interface state when determining the "
			 "cause of the error.  It is likely that the drivers are in a "
			 "broken or unavailable state.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (curmode != LINUX_WLEXT_MONITOR) {
		_MSG("Failed to change channel on interface '" + interface + "'. " 
			 "It appears to no longer be in monitor mode.  This can happen if "
			 "the drivers enter an unknown or broken state, but usually indicate "
			 "that an external program has changed the device mode.  Make sure no "
			 "network management tools (such as networkmanager) are running "
			 "before starting Kismet.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}

int PacketSource_Wext::FetchChannel() {
    char errstr[STATUS_MAX] = "";
	int chan = 0;

    // Failure to fetch a channel isn't necessarily a fatal error
	// and if we blow up badly enough that we can't get channels, we'll
	// blow up definitively on something else soon enough
    if ((chan = Iwconfig_Get_Channel(interface.c_str(), errstr)) < 0) {
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    return chan;
}

void PacketSource_Wext::FetchRadioData(kis_packet *in_packet) {
	// Don't fetch non-packetheader data since it's not likely to be
	// useful info.
	return;
#if 0
	// Build a signal layer record if we don't have one from the builtin headers.
	// These are less accurate.
	char errstr[STATUS_MAX] = "";
	int ret;
	
	kis_layer1_packinfo *radiodata = (kis_layer1_packinfo *) 
		in_packet->fetch(_PCM(PACK_COMP_RADIODATA));

	// We don't do anything if we have a signal layer from anywhere else
	if (radiodata == NULL)
		radiodata = new kis_layer1_packinfo;
	else
		return;

	// Fetch the signal levels if we know how and it hasn't been already.
	// Blow up if we can't, but do so sanely
	if ((ret = Iwconfig_Get_Levels(interface.c_str(), errstr,
								   &(radiodata->signal), &(radiodata->noise))) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		delete radiodata;
		return;
	}

	// Fetch the channel if we know how and it hasn't been filled in already
	radiodata->channel = FetchChannel();

	// Low accuracy
	radiodata->accuracy = 1;

	// If we didn't get anything good, destroy it
	if (radiodata->signal == 0 && radiodata->noise == 0 && radiodata->channel == 0) {
		delete radiodata;
		return;
	}

	in_packet->insert(_PCM(PACK_COMP_RADIODATA), radiodata);
#endif
}

PacketSource_Madwifi::PacketSource_Madwifi(GlobalRegistry *in_globalreg, 
										   string in_type, string in_name,
										   string in_dev) : 
	PacketSource_Wext(in_globalreg, in_type, in_name, in_dev) {

	if (in_type == "madwifi_a") {
		madwifi_type = 1;
	} else if (in_type == "madwifi_b") {
		madwifi_type = 2;
	} else if (in_type == "madwifi_g") {
		madwifi_type = 3;
	} else if (in_type == "madwifi_ag") {
		madwifi_type = 0;
	} else {
		_MSG("Packetsource::MadWifi - Unknown source type '" + in_type + "'.  "
			 "Will treat it as auto radio type", MSGFLAG_ERROR);
		madwifi_type = 0;
	}
}

int PacketSource_Madwifi::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketsource("madwifi_a", this, 1, "IEEE80211a", 36);
	tracker->RegisterPacketsource("madwifi_b", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("madwifi_g", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("madwifi_ag", this, 1, "IEEE80211ab", 6);
	return 1;
}

int PacketSource_Madwifi::EnableMonitor() {
	if (PacketSource_Wext::EnableMonitor() < 0) {
		return -1;
	}

	char errstr[1024];

	if (Iwconfig_Get_IntPriv(interface.c_str(), "get_mode", &stored_privmode,
							 errstr) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to get the current radio mode of interface '" + 
			 interface + "'", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (Iwconfig_Set_IntPriv(interface.c_str(), "mode", madwifi_type, 
							 0, errstr) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to set the radio mode of interface '" + interface + "'.  This "
			 "is needed to set the a/b/g radio mode", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}

int PacketSource_Madwifi::DisableMonitor() {
	char errstr[1024];
	if (Iwconfig_Set_IntPriv(interface.c_str(), "mode", stored_privmode,
							 0, errstr) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to restore the stored radio mode for interface '" +
			 interface + "'.  The device may be left in an unknown or unusable "
			 "state.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (PacketSource_Wext::DisableMonitor() < 0) {
		return -1;
	}

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_Madwifi::AutotypeProbe(string in_device) {
	ethtool_drvinfo drvinfo;
	char errstr[1024];

	if (Linux_GetDrvInfo(in_device.c_str(), errstr, &drvinfo) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to get ethtool information from device '" + in_device + "'. "
			 "This information is needed to detect the capture type for 'auto' "
			 "sources.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (string(drvinfo.driver) == "ath_pci") {
		return 1;
	}

	return 0;
}

int PacketSource_Madwifi::SetChannelSequence(vector<unsigned int> in_seq) {
	return PacketSource_Wext::SetChannelSequence(in_seq);
}

/* Madwifi NG ioctls from net80211 */
#define	SIOC80211IFCREATE		(SIOCDEVPRIVATE+7)
#define	SIOC80211IFDESTROY	 	(SIOCDEVPRIVATE+8)
PacketSource_MadwifiNG::PacketSource_MadwifiNG(GlobalRegistry *in_globalreg, 
											   string in_type, string in_name,
											   string in_dev) : 
	PacketSource_Wext(in_globalreg, in_type, in_name, in_dev) {

	// Copy the core interface
	core_interface = in_dev;

	if (in_type == "madwifing_a") {
		madwifi_type = 1;
	} else if (in_type == "madwifing_b") {
		madwifi_type = 2;
	} else if (in_type == "madwifing_g") {
		madwifi_type = 3;
	} else if (in_type == "madwifing_ag") {
		madwifi_type = 0;
	} else {
		_MSG("Packetsource::MadWifiNG - Unknown source type '" + in_type + "'.  "
			 "Will treat it as auto radio type", MSGFLAG_ERROR);
		madwifi_type = 0;
	}
}

int PacketSource_MadwifiNG::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketsource("madwifing_a", this, 1, "IEEE80211a", 36);
	tracker->RegisterPacketsource("madwifing_b", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("madwifing_g", this, 1, "IEEE80211b", 6);
	tracker->RegisterPacketsource("madwifing_ag", this, 1, "IEEE80211ab", 6);
	return 1;
}

int PacketSource_MadwifiNG::EnableMonitor() {
	/* from net80211 headers */
	struct ieee80211_clone_params {
		char		icp_name[IFNAMSIZ];
		u_int16_t	icp_opmode;
		u_int16_t	icp_flags;
#define	IEEE80211_CLONE_BSSID	0x0001
#define	IEEE80211_NO_STABEACONS	0x0002
#define IEEE80211_M_MONITOR 	8
	};
	struct ieee80211_clone_params cp;
	struct ifreq ifr;
	char newdev[IFNAMSIZ];
	int s;

	memset(&ifr, 0, sizeof(ifr));
	memset(&cp, 0, sizeof(cp));

	strncpy(cp.icp_name, "kis", IFNAMSIZ);
	cp.icp_opmode = (u_int16_t) IEEE80211_M_MONITOR;
	cp.icp_flags = IEEE80211_CLONE_BSSID;

	strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);
	ifr.ifr_data = (caddr_t) &cp;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		_MSG("Failed to create monitor mode virtual interface on "
			 "madwifi-ng interface '" + interface +"'.  Could not create "
			 "a control socket (" + string(strerror(errno)) + ").  Make "
		 	 "sure that you have the latest version of the madwifi-ng "
			 "drivers, that you specified the correct control interface, "
			 "and that you are running with the correct permissions (root). "
			 "See the 'Troubleshooting' section of the Kismet README for more "
			 "information.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (ioctl(s, SIOC80211IFCREATE, &ifr) < 0) {
		_MSG("Failed to create monitor mode virtual interface on "
			 "madwifi-ng interface '" + interface +"'.  Could not issue "
			 "the create ioctl (" + string(strerror(errno)) + ").  Make "
		 	 "sure that you have the latest version of the madwifi-ng "
			 "drivers, that you specified the correct control interface, "
			 "and that you are running with the correct permissions (root). "
			 "See the 'Troubleshooting' section of the Kismet README for more "
			 "information.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		close(s);
		return -1;
	}

	// Extract the interface name we got back */
	strncpy(newdev, ifr.ifr_name, IFNAMSIZ);
	core_interface = interface;
	interface = newdev;

	_MSG("Created Madwifi-NG virtual monitor interface '" + interface + "' "
		 "from base interface '" + core_interface +"'", MSGFLAG_INFO);

	close(s);

	if (PacketSource_Wext::EnableMonitor() < 0) {
		return -1;
	}

# if 0
	// Don't set the mode for now.  How does this affect channel hopping?
	// This might be the wrong behavior.  Hope it does auto properly
	char errstr[1024];

	if (Iwconfig_Set_IntPriv(interface.c_str(), "mode", madwifi_type, 
							 0, errstr) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to set the radio mode of interface '" + interface + "'.  This "
			 "is needed to set the a/b/g radio mode", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}
#endif

	return 1;
}

int PacketSource_MadwifiNG::DisableMonitor() {
	struct ifreq ifr;
	int s;

	// Just destroy our dynamic interface
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		_MSG("Failed to destroy monitor mode virtual interface '" + interface + "'"
			 "on madwifi-ng interface '" + interface +"'.  Could not create "
			 "a control socket (" + string(strerror(errno)) + ").  The virtual "
			 "monitor interface will be left up, try to manually destroy it "
			 "with wlanconfig", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ);
	if (ioctl(s, SIOC80211IFDESTROY, &ifr) < 0) {
		_MSG("Failed to destroy monitor mode virtual interface '" + interface + "'"
			 "on madwifi-ng interface '" + interface +"'.  Could not issue "
			 "the destroy ioctl (" + string(strerror(errno)) + ").  The virtual "
			 "monitor interface will be left up, try to manually destroy it "
			 "with wlanconfig", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		close(s);
		return -1;
	}

	close(s);

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_MadwifiNG::AutotypeProbe(string in_device) {
	ethtool_drvinfo drvinfo;
	char errstr[1024];

	if (Linux_GetDrvInfo(in_device.c_str(), errstr, &drvinfo) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to get ethtool information from device '" + in_device + "'. "
			 "This information is needed to detect the capture type for 'auto' "
			 "sources.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (string(drvinfo.driver) == "ath_pci") {
		return 1;
	}

	return 0;
}

int PacketSource_MadwifiNG::SetChannelSequence(vector<unsigned int> in_seq) {
	return PacketSource_Wext::SetChannelSequence(in_seq);
}

PacketSource_Wrt54Prism::PacketSource_Wrt54Prism(GlobalRegistry *in_globalreg,
												 string in_type, string in_name,
												 string in_dev) :
	PacketSource_Wext(in_globalreg, in_type, in_name, in_dev) {
	// We get FCS bytes
	SetFCSBytes(4);
}

int PacketSource_Wrt54Prism::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketsource("wrt54prism", this, 1, "IEEE80211b", 6);
	return 1;
}

int PacketSource_Wrt54Prism::OpenSource() {
	// Store the interface
	string realsrc = interface;

	// Fake the prism0 interface
	interface = "prism0";
	// Open using prism0
	int ret = PacketSource_Wext::OpenSource();
	// Restore
	interface = realsrc;

	return ret;
}

int PacketSource_Wrt54Prism::SetChannelSequence(vector<unsigned int> in_seq) {
	return PacketSource_Wext::SetChannelSequence(in_seq);
}

#endif

