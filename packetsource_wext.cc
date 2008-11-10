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

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

#include "packetsourcetracker.h"
#include "packetsource_wext.h"
#include "madwifing_control.h"

PacketSource_Wext::PacketSource_Wext(GlobalRegistry *in_globalreg, 
									 string in_interface,
									 vector<opt_pair> *in_opts) :
	PacketSource_Pcap(in_globalreg, in_interface, in_opts) { 

	// Type derived by our higher parent
	if (type == "nokia770") {
		SetValidateCRC(1);
	}
}

int PacketSource_Wext::AutotypeProbe(string in_device) {
	string sysdriver;

	// Examine the /sys filesystem to try to figure out what kind of driver
	// we have here
	sysdriver = Linux_GetSysDrv(in_device.c_str());

	// Most of the linux drivers now behave sanely
	if (sysdriver == "iwl4965" || sysdriver == "iwl3945" ||
		sysdriver == "adm8211" || sysdriver == "ath5k" ||
		sysdriver == "ath9k" || sysdriver == "b43" ||
		sysdriver == "ath5k_pci" || sysdriver == "ath9k_pci" ||
		sysdriver == "b43legacy" || sysdriver == "hostap" ||
		sysdriver == "libertas" || sysdriver == "p54" ||
		sysdriver == "prism54" || sysdriver == "rndis_wlan" ||
		sysdriver == "rt2500pci" || sysdriver == "rt73usb" ||
		sysdriver == "rt2x00pci" || sysdriver == "rt61pci" ||
		sysdriver == "rt2400pci" || sysdriver == "rt2x00usb" ||
		sysdriver == "rt2400pci" || sysdriver == "rt61pci" ||
		sysdriver == "rtl8180"  || sysdriver == "zd1201" ||
		sysdriver == "rtl8187" || sysdriver == "zd1211rw") {
		
		// Set the weaksource type to what we derived
		type = sysdriver;
		return 1;
	}

	if (sysdriver == "wl") {
		type = sysdriver;
		_MSG("Detected 'wl' binary-only broadcom driver for interface " + in_device +
			 "; This driver does not provide monitor-mode support (which is required " 
			 "by Kismet)  Try the in-kernel open source drivers for the Broadcom "
			 "cards.  Kismet will continue to attempt to use this card incase "
			 "the drivers have recently added support, but this will probably "
			 "fail.", MSGFLAG_PRINTERROR);
		return 1;
	}

	return 0;
}

int PacketSource_Wext::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("adm8211", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("acx100", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("admtek", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("atmel_usb", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("ath5k", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("ath5k_pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("ath9k", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("ath9k_pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("bcm43xx", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("b43", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("b43legacy", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("hostap", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("ipw2100", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("ipw2200", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("ipw2915", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("ipw3945", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("iwl3945", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("iwl4965", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("libertas", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("nokia770", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("prism54", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("p54", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rndis_wlan", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2400", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2500", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2400pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2500pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2x00pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt61pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt73", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt73usb", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt8180", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt8187", this, "IEEE80211g", 1);
	tracker->RegisterPacketProto("rtl8180", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rtl8187", this, "IEEE80211g", 1);
	tracker->RegisterPacketProto("wl", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("zd1211", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("zd1201", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("zd1211rw", this, "IEEE80211b", 1);

	return 1;
}

int PacketSource_Wext::EnableMonitor() {
	char errstr[STATUS_MAX];

	if (type == "rtl8187") {
		_MSG("Enabling monitor on a RTL8187 device.  Some driver versions appear to take "
			 "a VERY long time for the device to wake up while enabling monitor (10-30 "
			 "seconds).  While this is happening, Kismet may appear to have locked up.",
			 MSGFLAG_PRINTERROR);
	}

	if (Ifconfig_Get_Flags(interface.c_str(), errstr, &stored_flags) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to get interface flags for '" + interface + "', "
			 "this will probably fully fail in a moment when we try to configure "
			 "the interface, but we'll keep going.", MSGFLAG_PRINTERROR);
	}

	// Bring the interface up, zero its IP, etc
	if (Ifconfig_Delta_Flags(interface.c_str(), errstr, 
							 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to bring up interface '" + interface + "', check your "
			 "permissions and configuration, and consult the Kismet README file",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	// Try to grab the channel
	if ((stored_channel = Iwconfig_Get_Channel(interface.c_str(), errstr)) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to get the current channel for interface '" + interface + 
			 "'.  This may be a fatal problem, but we'll keep going in case "
			 "the drivers are reporting incorrectly.", MSGFLAG_PRINTERROR);
		stored_channel = -1;
	}

	// Try to grab the wireless mode
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &stored_mode) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to get current wireless mode for interface '" + interface + 
			 "', check your configuration and consult the Kismet README file",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	if (stored_mode != LINUX_WLEXT_MONITOR) {
		if (Iwconfig_Set_Mode(interface.c_str(), errstr, LINUX_WLEXT_MONITOR) < 0) {
			/* Bring the interface down and try again */
			_MSG("Failed to set monitor mode on interface '" + interface + "' "
				 "while up, bringing interface down and trying again.",
				 MSGFLAG_ERROR);

			int oldflags;
			Ifconfig_Get_Flags(interface.c_str(), errstr, &oldflags);

			if (Ifconfig_Set_Flags(interface.c_str(), errstr,
								   oldflags & ~(IFF_UP | IFF_RUNNING)) < 0) {
				_MSG("Failed to bring down interface '" + interface + "' to "
					 "configure monitor mode: " + string(errstr),
					 MSGFLAG_PRINTERROR);
				return -1;
			}

			if (Iwconfig_Set_Mode(interface.c_str(), errstr, 
								  LINUX_WLEXT_MONITOR) < 0) {
				_MSG(errstr, MSGFLAG_PRINTERROR);
				_MSG("Failed to set monitor mode on interface '" + interface + "', "
					 "even after bringing interface into a down state.  This "
					 "usually means your drivers either do not report monitor "
					 "mode, use a different mechanism than Kismet expected "
					 "to configure monitor mode, or that the user which started "
					 "Kismet does not have permission to change the driver mode. "
					 "Make sure you have the required version and have applied "
					 "any patches needed to your drivers, and that you have "
					 "configured the proper source type for Kismet.  See the "
					 "troubleshooting section of the Kismet README for more "
					 "information.", MSGFLAG_PRINTERROR);
				Ifconfig_Set_Flags(interface.c_str(), errstr, oldflags);
				return -1;
			}

			if (Ifconfig_Delta_Flags(interface.c_str(), errstr, 
									 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
				_MSG(errstr, MSGFLAG_FATAL);
				_MSG("Failed to bring up interface '" + interface + "' after "
					 "bringing it down to set monitor mode, check the "
					 "output of `dmesg'.  This usually means there is some "
					 "problem with the driver.", MSGFLAG_PRINTERROR);
				return -1;
			}

		}
	} else {
		_MSG("Interface '" + interface + "' is already marked as being in "
			 "monitor mode, leaving it as it is.", MSGFLAG_INFO);

		return 0;
	}

	// Don't try this if we have a working rfmon interface, someone else 
	// probably wants the headers to stay as they are

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
	
	return 0;
}

int PacketSource_Wext::DisableMonitor() {
	char errstr[STATUS_MAX];

	// We don't really care if any of these things fail.  Keep trying.
	SetChannel(stored_channel);
	
	// We do care if this fails
	if (Iwconfig_Set_Mode(interface.c_str(), errstr, stored_mode) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to restore previous wireless mode for interface '" +
			 interface + "'.  It may be left in an unknown or unusable state.",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	if (Ifconfig_Set_Flags(interface.c_str(), errstr, stored_flags) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to restore previous interface settings for '" + interface + "'. "
			 "It may be left in an unknown or unusable state.", MSGFLAG_PRINTERROR);
		return -1;
	}

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_Wext::SetChannel(unsigned int in_ch) {
	char errstr[STATUS_MAX];

	// Set and exit if we're ok
    if (Iwconfig_Set_Channel(interface.c_str(), in_ch, errstr) >= 0) {
		consec_error = 0;
        return 1;
    }

	_MSG(errstr, MSGFLAG_PRINTERROR);

	int curmode;
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &curmode) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to change channel on interface '" + interface + "' and "
			 "failed to fetch current interface state when determining the "
			 "cause of the error.  It is likely that the drivers are in a "
			 "broken or unavailable state.", MSGFLAG_PRINTERROR);
		return -1;
	}

	if (curmode != LINUX_WLEXT_MONITOR) {
		_MSG("Failed to change channel on interface '" + interface + "'. " 
			 "It appears to no longer be in monitor mode.  This can happen if "
			 "the drivers enter an unknown or broken state, but usually indicate "
			 "that an external program has changed the device mode.  Make sure no "
			 "network management tools (such as networkmanager) are running "
			 "before starting Kismet.", MSGFLAG_PRINTERROR);
		return -1;
	}

	return 1;
}

int PacketSource_Wext::FetchHardwareChannel() {
    char errstr[STATUS_MAX] = "";
	int chan = 0;

    // Failure to fetch a channel isn't necessarily a fatal error
	// and if we blow up badly enough that we can't get channels, we'll
	// blow up definitively on something else soon enough
    if ((chan = Iwconfig_Get_Channel(interface.c_str(), errstr)) < 0) {
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_PRINTERROR);
        return -1;
    }

    return chan;
}

void PacketSource_Wext::FetchRadioData(kis_packet *in_packet) {
	// Don't fetch non-packetheader data since it's not likely to be
	// useful info.
	return;
}

PacketSource_Madwifi::PacketSource_Madwifi(GlobalRegistry *in_globalreg, 
										   string in_interface,
										   vector<opt_pair> *in_opts) :
	PacketSource_Wext(in_globalreg, in_interface, in_opts) {

	if (type == "madwifi_a" || type == "madwifing_a") {
		madwifi_type = 1;
	} else if (type == "madwifi_b" || type == "madwifing_g") {
		madwifi_type = 2;
	} else if (type == "madwifi_g" || type == "madwifing_g") {
		madwifi_type = 3;
	} else if (type == "madwifi_ag" || type == "madwifing_ag" || type == "madwifi") {
		madwifi_type = 0;
	} else {
		_MSG("Packetsource::MadWifi - Unknown source type '" + type + "'.  "
			 "Will treat it as auto radio type", MSGFLAG_PRINTERROR);
		madwifi_type = 0;
	}

	SetFCSBytes(4);
	vapdestroy = 1;

	if (FetchOpt("vapkill", in_opts) != "" && FetchOpt("vapkill", in_opts) != "true") {
		vapdestroy = 0;
		_MSG("Madwifi-NG source " + name + " " + interface + ": Disabling destruction "
			 "of non-monitor VAPS because vapkill was not set to true in source "
			 "options.  This may cause capture problems with some driver versions.",
			 MSGFLAG_INFO);
	}
}

int PacketSource_Madwifi::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("madwifi", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("madwifi_a", this, "IEEE80211a", 1);
	tracker->RegisterPacketProto("madwifi_b", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("madwifi_g", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("madwifi_ag", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("madwifing_a", this, "IEEE80211a", 1);
	tracker->RegisterPacketProto("madwifing_b", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("madwifing_g", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("madwifing_ag", this, "IEEE80211ab", 1);
	return 1;
}

int PacketSource_Madwifi::EnableMonitor() {
	// Try to get the vap list, if that succeeds we know we have a madwifi_ng
	// implementation
	char newdev[IFNAMSIZ];
	vector<string> vaplist;
	string monvap = "";
	char errstr[1024];
	int nvaps;

	shutdowndestroy = 1;
	nvaps = madwifing_list_vaps(interface.c_str(), &vaplist);

	for (unsigned int x = 0; x < vaplist.size(); x++) {
		int iwmode;

		if (Iwconfig_Get_Mode(vaplist[x].c_str(), errstr, &iwmode) < 0) {
			_MSG("Madwifi source " + name + ": Could not get mode of VAP " + 
				 interface + "::" +
				 vaplist[x] + ".  Madwifi has historically had problems with "
				 "normal mode and monitor mode VAPs operating at the same time. "
				 "You may need to manually remove them.", MSGFLAG_PRINTERROR);
			sleep(1);
			break;
		}

		if (iwmode == LINUX_WLEXT_MASTER) {
			_MSG("Madwifi source " + name + ": Found master-mode VAP " + 
				 interface + "::" + vaplist[x] + 
				 ".  While Madwifi has historically had problems with normal "
				 "and master mode VAPs operating at the same time, it will not "
				 "be removed on the assumption you really want this.  High packet "
				 "loss may occur however, so you may want to remove this VAP "
				 "manually.", MSGFLAG_PRINTERROR);
			sleep(1);
			break;
		}

		if (iwmode != LINUX_WLEXT_MONITOR && vapdestroy) {
			_MSG("Madwifi source " + name + ": Found non-monitor-mode VAP " + 
				 interface + "::" + vaplist[x] +
				 ".  Because madwifi-ng has problems with normal and monitor "
				 "vaps operating on the same device, this will be removed.  If "
				 "you want Kismet to ignore non-monitor-mode VAPs and not "
				 "remove them, edit your config file to set the \"novapkill\" "
				 "option: 'sourceopts=" + name + ":novapkill'",
				 MSGFLAG_PRINTERROR);
			if (madwifing_destroy_vap(vaplist[x].c_str(), errstr) < 0) {
				_MSG("Madwifi source " + name + ": Failed to destroy vap " +
					 interface + "::" + vaplist[x] + ": " +
					 string(errstr), MSGFLAG_PRINTERROR);
				return -1;
				break;
			}

			sleep(1);
			continue;
		} else if (iwmode != LINUX_WLEXT_MONITOR && vapdestroy == 0) {
			_MSG("Madwifi source " + name + ": Found non-monitor-mode VAP " + 
				 interface + "::" + vaplist[x] +
				 ".  Because the sourceopt \"novapkill\" is set for this "
				 "source, it will not be removed.  THIS MAY CAUSE PROBLEMS.  "
				 "Do not enable novapkill unless you know you want it.",
				 MSGFLAG_PRINTERROR);
			continue;
		}

		// We have a monitor vap, set it
		if (iwmode == LINUX_WLEXT_MONITOR) {
			_MSG("Madwifi source " + name + ": Found monitor-mode VAP " + 
				 interface + "::" + vaplist[x] + 
				 ".  We'll use that instead of making a new one.",
				 MSGFLAG_INFO);
			sleep(1);
			monvap = vaplist[x];
			interface = vaplist[x];
		}
	}

	// If we're in a madwifi-ng model, build a vap.  Don't build one if
	// we already have one, and dont change the mode on an existing monitor
	// vap.
	if (monvap == "") {
		if (madwifing_build_vap(interface.c_str(), errstr, "kis", newdev,
								IEEE80211_M_MONITOR, IEEE80211_CLONE_BSSID) >= 0) {
			_MSG("Madwifi source " + name + " created monitor-mode VAP " +
				 interface + "::" + newdev + ".", MSGFLAG_INFO);

			FILE *controlf;
			string cpath = "/proc/sys/net/" + string(newdev) + "/dev_type";

			if ((controlf = fopen(cpath.c_str(), "w")) == NULL) {
				_MSG("Madwifi source " + name + ": Failed to open /proc/sys/net "
					 "madwifi control interface to set radiotap mode.  This may "
					 "indicate a deeper problem, but it is not in itself a fatal "
					 "error.", MSGFLAG_PRINTERROR);
			} else {
				fprintf(controlf, "803\n");
				fclose(controlf);
			}

			interface = newdev;
			driver_ng = 1;
		} else {
			_MSG("Madwifi source " + name + ": Failed to create monitor VAP: " +
				 string(errstr), MSGFLAG_PRINTERROR);
		}
	} else if (monvap != "") {
		driver_ng = 1;
		shutdowndestroy = 0;
		interface = monvap;
	}

	if (driver_ng && nvaps < 0) {
		_MSG("Madwifi source " + name + ": Able to build rfmon VAP, but unable "
			 "to get a list of existing VAPs.  This means something strange is "
			 "happening with your system, or that you're running on an old "
			 "kernel (2.4.x) which does not provide Controller to VAP mapping.  "
			 "Performance will likely be VERY poor if you do not remove non-rfmon "
			 "vaps manually (if any exist) using wlanconfig.", MSGFLAG_PRINTERROR);
		sleep(1);
	}

	if (PacketSource_Wext::EnableMonitor() < 0) {
		return -1;
	}

	if (driver_ng)
		return 1;

	_MSG("Madwifi source " + name + ": Could not get a VAP list from madwifi-ng, "
		 "assuming this is a madwifi-old source.  If you are running madwifi-ng "
		 "you MUST pass the wifiX control interface, NOT an athX VAP.",
		 MSGFLAG_INFO);
	sleep(1);


	if (Iwconfig_Get_IntPriv(interface.c_str(), "get_mode", &stored_privmode,
							 errstr) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to get the current radio mode of interface '" + 
			 interface + "'", MSGFLAG_PRINTERROR);
		return -1;
	}

	if (Iwconfig_Set_IntPriv(interface.c_str(), "mode", madwifi_type, 
							 0, errstr) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed to set the radio mode of interface '" + interface + "'.  This "
			 "is needed to set the a/b/g radio mode", MSGFLAG_PRINTERROR);
		return -1;
	}

	return 1;
}

int PacketSource_Madwifi::DisableMonitor() {
	char errstr[1024];

	if (driver_ng && shutdowndestroy) {
		if (madwifing_destroy_vap(interface.c_str(), errstr) < 0) {
			_MSG("Madwifi source " + name + ": Failed to destroy vap " +
				 interface + " on shutdown: " +
				 string(errstr), MSGFLAG_PRINTERROR);
			return -1;
		}

		return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
	}

	if (Iwconfig_Set_IntPriv(interface.c_str(), "mode", stored_privmode,
							 0, errstr) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to restore the stored radio mode for interface '" +
			 interface + "'.  The device may be left in an unknown or unusable "
			 "state.", MSGFLAG_PRINTERROR);
		return -1;
	}

	if (PacketSource_Wext::DisableMonitor() < 0) {
		return -1;
	}

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_Madwifi::AutotypeProbe(string in_device) {
#if 0
	// Madwifi doesn't seem to sanely report this on the wifi0 device...
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

#endif

	return 0;
}

PacketSource_Wrt54Prism::PacketSource_Wrt54Prism(GlobalRegistry *in_globalreg,
												 string in_interface,
												 vector<opt_pair> *in_opts) :
	PacketSource_Wext(in_globalreg, in_interface, in_opts) {
	// We get FCS bytes
	SetFCSBytes(4);
}

int PacketSource_Wrt54Prism::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("wrt54prism", this, "IEEE80211b", 1);
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

#endif

