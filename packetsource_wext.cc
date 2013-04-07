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

#include "psutils.h"

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
#include "nl80211_control.h"

PacketSource_Wext::PacketSource_Wext(GlobalRegistry *in_globalreg, 
									 string in_interface,
									 vector<opt_pair> *in_opts) :
	PacketSource_Pcap(in_globalreg, in_interface, in_opts) { 

	scan_wpa = 0;
	wpa_timer_id = -1;
	wpa_sock = -1;
	memset(&wpa_local, 0, sizeof(struct sockaddr_un));
	memset(&wpa_dest, 0, sizeof(struct sockaddr_un));

	use_mac80211 = 0;
	opp_vap = 0;
	force_vap = 0;
	nlcache = nlfamily = NULL;
	ignore_primary_state = false;

	stored_channel = stored_mode = stored_privmode = stored_flags = -1;

	// Type derived by our higher parent
	if (type == "nokia770" || type == "nokia800" || 
		type == "nokia810" || type == "nokiaitt") {
		SetValidateCRC(1);
		SetFCSBytes(4);
	}

	// Catch warning states
	if (type == "wl") {
		warning = 
			"Detected 'wl' binary-only broadcom driver for interface " + interface +
			"; This driver does not provide monitor-mode support (which is "
			"required by Kismet)  Try the in-kernel open source drivers for "
			"the Broadcom cards.  Kismet will continue to attempt to use "
			"this card incase the drivers have recently added support, but "
			"this will probably fail.";
		_MSG(warning, MSGFLAG_PRINTERROR);
	}

	if (type == "orinoco_cs") {
		warning =
			"Detected 'orinoco_cs' driver for interface " + interface + 
			"; This driver will not report packets in rfmon under many firmware "
			"versions.  Kismet will continue trying to use it, however if you don't "
			"see any packets check `dmesg' and consider changing firmware on your "
			"card.";
		_MSG(warning, MSGFLAG_PRINTERROR);
	}

	ParseOptions(in_opts);

	// Don't warn about wpa_supplicant if we're going to use it
	string processes;

	if (scan_wpa == 0) {
		if (FindProcess("wpa_action", interface))
			processes += "wpa_action ";
		if (FindProcess("wpa_supplicant", interface))
			processes += "wpa_supplicant ";
		if (FindProcess("wpa_cli", interface))
			processes += "wpa_cli ";

		vector<string> look_procs = 
			StrTokenize("dhclient,ifplugd,dhcpbd,dhcpcd,NetworkManager,knetworkmanager,"
						"avahi-daemon,wlanassistant,wifibox", ",");

		for (unsigned int x = 0; x < look_procs.size(); x++) 
			if (FindProcess(look_procs[x], interface))
				processes += look_procs[x] + string(" ");
	}

	processes = processes.substr(0, processes.length() - 1);

	if (processes != "" && warning == "") {
		warning =
			"Detected the following processes that appear to be using the "
			"interface " + interface + ", which can cause problems with Kismet "
			"by changing the configuration of the network device: " + processes +
			".  If  Kismet stops running or stops capturing packets, try killing "
			"one (or all) of these processes or stopping the network for this "
			"interface.";
		_MSG(warning, MSGFLAG_PRINTERROR);
	}
}

PacketSource_Wext::~PacketSource_Wext() {
	if (wpa_sock >= 0)
		close(wpa_sock);

	if (wpa_timer_id >= 0)
		globalreg->timetracker->RemoveTimer(wpa_timer_id);

	if (wpa_local_path != "")
		unlink(wpa_local_path.c_str());
}

int PacketSource_Wext::OpenSource() {
	int r = PacketSource_Pcap::OpenSource();

	if (r < 0)
		return r;

	if (DatalinkType() < 0) {
		if (pd != NULL)
			pcap_close(pd);
		return -1;
	}

	return 1;
}

int PacketSource_Wext::ParseOptions(vector<opt_pair> *in_opts) {
	PacketSource_Pcap::ParseOptions(in_opts);

	// Force us to keep the primary interface still running
	if (FetchOptBoolean("ignoreprimary", in_opts, false)) {
		ignore_primary_state = true;
		_MSG("Source '" + interface + "' will ignore the primary interface "
			 "up.  This may cause conflicts with wpasupplicant / networkmanager",
			 MSGFLAG_INFO);
	}

	if (FetchOpt("vap", in_opts) != "") {
		vap = FetchOpt("vap", in_opts);
		_MSG("Source '" + interface + "' create a monitor-only "
			 "VAP '" + vap + "' instead of changing " + interface, 
			 MSGFLAG_INFO);
		// Opportunistic VAP off when specified
		opp_vap = 0;
	}

	// Record if the VAP is absolutely forced (no passive blank option)
	// if (StrLower(FetchOpt("forcevap", in_opts)) == "true")
	if (FetchOptBoolean("forcevap", in_opts, 0))
		force_vap = 1;

	// Turn on VAP by default
	// if (vap == "" && (FetchOpt("forcevap", in_opts) == "" || 
	// 				  StrLower(FetchOpt("forcevap", in_opts)) == "true")) {
	if (vap == "" && FetchOptBoolean("forcevap", in_opts, 1)) {
		if (vap == "") {
			// Only set a vap when we're not targetting a vap
			if (mac80211_find_parent(string(interface + "mon").c_str()) == "") {
				_MSG("Source '" + interface + "' will attempt to create and use a "
					 "monitor-only VAP instead of reconfiguring the main interface",
					 MSGFLAG_INFO);
				vap = interface + "mon";
			}

			// Opportunistic VAP on
			opp_vap = 1;
		}
	} else if (vap == "") {
		_MSG("Source '" + interface + "' forced into non-vap mode, this will "
			 "modify the provided interface.", MSGFLAG_INFO);
	}

	// if (FetchOpt("fcsfail", in_opts) == "true") {
	if (FetchOptBoolean("fcsfail", in_opts, 0)) {
		if (vap == "") {
			_MSG("Source '" + interface + "': 'fcsfail' enabled to tell "
				 "mac80211 to report invalid packets, but not using a VAP. "
				 "A vap must be specified with 'vap=' BEFORE the 'fcsfail' "
				 "option.", MSGFLAG_PRINTERROR);
		} else {
			_MSG("Source '" + interface + "::" + vap + "': Telling mac80211 to report "
				 "invalid packets which fail the FCS check.  Forcing FCS "
				 "validation on as well.", MSGFLAG_INFO);
			mac80211_flag_vec.push_back(nl80211_mntr_flag_fcsfail);
			validate_fcs = 1;
		}
	}

	// if (FetchOpt("plcpfail", in_opts) == "true") {
	if (FetchOptBoolean("plcpfail", in_opts, 0)) {
		if (vap == "") {
			_MSG("Source '" + interface + "': 'plcpfail' enabled to tell "
				 "mac80211 to report invalid packets, but not using a VAP. "
				 "A vap must be specified with 'vap=' BEFORE the 'plcpfail' "
				 "option.", MSGFLAG_PRINTERROR);
		} else {
			_MSG("Source '" + interface + "::" + vap + "': Telling mac80211 to report "
				 "invalid packets which fail the PLCP check.  Forcing FCS "
				 "validation on as well.", MSGFLAG_INFO);
			mac80211_flag_vec.push_back(nl80211_mntr_flag_plcpfail);
			validate_fcs = 1;
		}
	}

	wpa_path = FetchOpt("wpa_ctrl_path", in_opts);

	if (FetchOpt("wpa_scan", in_opts) != "") {
		if (wpa_path == "") 
			_MSG("Source '" + interface + "' - requested wpa_scan assist from "
				 "wpa_supplicant but no wpa_ctrl_path option, we'll use "
				 "the defaults, set this path if your wpa_supplicant uses "
				 "something else for the control socket", MSGFLAG_ERROR);

		// if (FetchOpt("hop", in_opts) == "" || FetchOpt("hop", in_opts) == "true") {
		if (FetchOptBoolean("hop", in_opts, 1)) {
			_MSG("Source '" + interface + "' - wpa_scan assist from wpa_supplicant "
				 "requested but hopping not disabled, wpa_scan is meaningless on "
				 "a hopping interface, so it will not be enabled.", MSGFLAG_ERROR);
			scan_wpa = 0;
		} else if (sscanf(FetchOpt("wpa_scan", in_opts).c_str(), "%d", &scan_wpa) != 1) {
			_MSG("Source '" + interface + "' - invalid wpa_scan interval, expected "
				 "number (of seconds) between each scan", MSGFLAG_ERROR);
			scan_wpa = 0;
		} else {
			_MSG("Source '" + interface + "' - using wpa_supplicant to assist with "
				 "non-disruptive hopping", MSGFLAG_INFO);
			scan_wpa = 1;
		}

		if (wpa_path == "")
			wpa_path = "/var/run/wpa_supplicant";
	}

	return 1;
}

int PacketSource_Wext::AutotypeProbe(string in_device) {
	string sysdriver;

	// Examine the /sys filesystem to try to figure out what kind of driver
	// we have here
	sysdriver = Linux_GetSysDrv(in_device.c_str());

	// Most of the linux drivers now behave sanely
	if (sysdriver == "iwl4965" || sysdriver == "iwl3945" || sysdriver == "iwlagn" ||
		sysdriver == "adm8211" || sysdriver == "ath5k" ||
		sysdriver == "ath9k" || sysdriver == "b43" ||
		sysdriver == "ath5k_pci" || sysdriver == "ath9k_pci" ||
		sysdriver == "ath9k_htc" || 
		sysdriver == "b43legacy" || sysdriver == "hostap" ||
		sysdriver == "libertas" || sysdriver == "p54" ||
		sysdriver == "libertas_usb" || sysdriver == "libertas_tf" ||
		sysdriver == "prism54" || sysdriver == "rndis_wlan" ||
		sysdriver == "rt2500pci" || sysdriver == "rt73usb" ||
		sysdriver == "rt2860" || sysdriver == "rt2800usb" ||
		sysdriver == "rt2x00pci" || sysdriver == "rt61pci" ||
		sysdriver == "rt2400pci" || sysdriver == "rt2x00usb" ||
		sysdriver == "rt2400pci" || sysdriver == "rt61pci" ||
		sysdriver == "rtl8180"  || sysdriver == "zd1201" ||
		sysdriver == "rtl8187" || sysdriver == "zd1211rw" ||
		sysdriver == "iwlwifi" || 
		// These don't seem to work but i'll autodet anyhow
		sysdriver == "rt2870sta" ||
		//  These drivers don't behave sanely but throw errors when we open them
		sysdriver == "wl" || sysdriver == "orinoco" || 
		sysdriver == "orinoco_cs") {
		
		// Set the weaksource type to what we derived
		warning = "";
		type = sysdriver;
		return 1;
	}

	// Detect unknown mac80211 devices, ask for help, assume wext
	if (Linux_GetSysDrvAttr(in_device.c_str(), "phy80211")) {
		type = "mac80211";
		warning = "Didn't understand driver '" + sysdriver + "' for interface '" +
			 in_device + "', but it looks like a mac80211 device so Kismet "
			 "will use the generic options for it.  Please post on the Kismet "
			 "forum or stop by the IRC channel and report what driver it was.";
		_MSG(warning, MSGFLAG_PRINTERROR);
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
	tracker->RegisterPacketProto("ath9k_htc", this, "IEEE80211b", 1);
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
	tracker->RegisterPacketProto("iwlagn", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("iwlwifi", this, "IEEE80211ab", 1);
	tracker->RegisterPacketProto("libertas", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("libertas_usb", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("libertas_tf", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("nokia770", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("nokia800", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("nokia810", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("nokiaitt", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("orinoco", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("orinoco_cs", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("prism54", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("p54", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rndis_wlan", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2400", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2500", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2400pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2500pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2x00pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2800usb", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt61pci", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt73", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt73usb", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2860", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2860sta", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt2870sta", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt8180", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rt8187", this, "IEEE80211g", 1);
	tracker->RegisterPacketProto("rtl8180", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("rtl8187", this, "IEEE80211g", 1);
	tracker->RegisterPacketProto("wl", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("zd1211", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("zd1201", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("zd1211rw", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("wext", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("wl12xx", this, "IEEE80211b", 1);
	tracker->RegisterPacketProto("mac80211", this, "IEEE80211b", 1);

	return 1;
}

int wext_ping_wpasup_event(TIMEEVENT_PARMS) {
	return ((PacketSource_Wext *) auxptr)->ScanWpaSupplicant();
}

void PacketSource_Wext::OpenWpaSupplicant() {
	wpa_local_path = "/tmp/kis_wpa_ctrl_" + parent + "_" + IntToString(getpid());

	// Register the timer now so it can try to reconnect us
	if (scan_wpa && wpa_timer_id < 0) 
		wpa_timer_id = 
			globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * scan_wpa,
												  NULL, 1, wext_ping_wpasup_event, this);
	if (scan_wpa && wpa_sock < 0) {

		wpa_sock = socket(PF_UNIX, SOCK_DGRAM, 0);

		wpa_local.sun_family = AF_UNIX;
		snprintf(wpa_local.sun_path, sizeof(wpa_local.sun_path), 
				 "%s", wpa_local_path.c_str());
		if (bind(wpa_sock, (struct sockaddr *) &wpa_local, sizeof(wpa_local)) < 0) {
			_MSG("Source '" + parent + "' failed to bind local socket for "
				 "wpa_supplicant, disabling scan_wpa: " + string(strerror(errno)),
				 MSGFLAG_PRINTERROR);
			close(wpa_sock);
			return;
		} else {
			wpa_dest.sun_family = AF_UNIX;
			snprintf(wpa_dest.sun_path, sizeof(wpa_dest.sun_path), "%s", 
					 (wpa_path + "/" + parent).c_str());
			if (connect(wpa_sock, (struct sockaddr *) &wpa_dest, sizeof(wpa_dest)) < 0) {
				_MSG("Source '" + parent + "' failed to connect to wpa_supplicant "
					 "control socket " + wpa_path + "/" + parent + ".  Make sure "
					 "that the wpa_ctrl_path option is set correctly.", 
					 MSGFLAG_PRINTERROR);
				close(wpa_sock);
				return;
			}
		}

		// Set it nonblocking, and we'll just check that our whole command
		// got written each time, not going to bother making a real queue
		fcntl(wpa_sock, F_SETFL, fcntl(wpa_sock, F_GETFL, 0) | O_NONBLOCK);
		unlink(wpa_local_path.c_str());
	}
}

int PacketSource_Wext::ScanWpaSupplicant() {
	// If we're in error state, don't do anything (and shut down anything we had)
	if (FetchError() && wpa_sock >= 0) {
		close(wpa_sock);
		wpa_sock = -1;
		return 0;
	}

	// Otherwise if our sock is broken, open it (and next time we come back 
	// we'll do something with it)
	if (wpa_sock < 0) {
		OpenWpaSupplicant();
		return 1;
	}

	const char scan[] = "SCAN";

	if (write(wpa_sock, scan, sizeof(scan)) != sizeof(scan)) {
		_MSG("Source '" + parent + "' error writing to wpa_supplicant socket, "
			 "reopening connection: " + string(strerror(errno)), MSGFLAG_ERROR);
		close(wpa_sock);
		wpa_sock = -1;
		// We failed, try to open it as we go away
		OpenWpaSupplicant();
	}

	return 1;
}

int PacketSource_Wext::EnableMonitor() {
	char errstr[STATUS_MAX];
	int ret;

	if (Linux_GetSysDrvAttr(interface.c_str(), "phy80211")) {
#ifdef HAVE_LINUX_NETLINK
		use_mac80211 = 1;
		if (mac80211_connect(interface.c_str(), &(globalreg->nlhandle), &nlcache, 
							 &nlfamily, errstr) < 0) {
			_MSG("Source '" + interface + "' failed to connect nl80211: " + errstr, 
				 MSGFLAG_PRINTERROR);
			return -1;
		}

		// always enable crc on phy80211 since they seem to report bogus
		// crap fairly often
		SetValidateCRC(1);
#else
		warning =
			"Source '" + interface + "' uses phy80211/mac80211 drivers, but "
			 "Kismet was not compiled with LibNL.  This will almost definitely not "
			 "work right, but continuing for now.  Expect bad behavior.";
		_MSG(warning, MSGFLAG_PRINTERROR);

		use_mac80211 = 0;
#endif
	} else {
		use_mac80211 = 0;
	}

	if (type == "ipw2200" || type == "ipw2100") {
		warning =
			"Detected 'ipw2200' or 'ipw2100' for interface " + interface +
			"; This driver will not change channel using mac80211 commands in most "
			"cases.  Kismet will use legacy channel control commands.";
		_MSG(warning, MSGFLAG_PRINTERROR);
		use_mac80211 = 0;
	}

	if (vap != "" && opp_vap == 1 && use_mac80211 == 0) {
		_MSG("Source '" + interface + "' doesn't have mac80211 support, disabling "
			 "VAP creation of default monitor mode VAP", MSGFLAG_PRINTERROR);
		vap = "";
	} else if (vap != "" && opp_vap == 0 && use_mac80211 == 0) {
		_MSG("Source '" + interface + "' doesn't have mac80211 support, unable to "
			 "create a VAP for capturing, specify the main device instead.",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	// If we don't already have a parent interface, it's whatever was specified
	// as our interface; we'll make the vap if we need to and use this for
	// reconnect
	if (parent == "")
		parent = interface;

	// Try to grab the wireless mode before we go making vaps - don't make
	// a vap for an interface that is already in monitor mode.  ignore failures
	// and set a bogus stored mode so that we don't bypass the vap creation.  If
	// for some reason an interface doesn't exist but a vap can still be created
	// from it, we don't want to fall down
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &stored_mode) < 0) {
		stored_mode = IW_MODE_AUTO;
	}

	OpenWpaSupplicant();

	// Defer the vap creation to here so we're sure we're root
	if (vap != "" && use_mac80211 && stored_mode == IW_MODE_MONITOR && force_vap == 0) {
		_MSG("Not creating a VAP for " + interface + " even though one was "
			 "requested, since the interface is already in monitor mode.  "
			 "Perhaps an existing monitor mode VAP was specified.  To override "
			 "this and create a new monitor mode vap no matter what, use the "
			 "forcevap=true source option", MSGFLAG_PRINTERROR);
	} else if (vap != "" && use_mac80211) {
		// If we're ignoring the primary state do nothing, otherwise shut it down
		if (!ignore_primary_state) {
			int fl;

			_MSG("Bringing down primary interface '" + parent + "' to prevent "
				 "wpa_supplicant and NetworkManager from trying to configure it",
				 MSGFLAG_INFO);

			if ((ret = Ifconfig_Get_Flags(parent.c_str(), errstr, &fl)) == 0) {
				fl &= ~IFF_UP;
			
				ret = Ifconfig_Set_Flags(parent.c_str(), errstr, fl);
			}

			if (ret < 0) {
				_MSG(errstr, MSGFLAG_PRINTERROR);
				if (ret == ENODEV) {
					warning = "Failed to find interface '" + parent + "', it may not be "
						"present at this time, it may not exist at all, or there may "
						"be a problem with the driver (such as missing firmware)";

				} else {
					warning = "Failed to bring up interface '" + parent + "', this "
						"often means there is a problem with the driver (such as "
						"missing firmware), check the output of `dmesg'.";
				}

				_MSG(warning, MSGFLAG_PRINTERROR);

				return -1;
			}
		}

		if (mac80211_createvap(parent.c_str(), vap.c_str(), errstr) < 0) {
			_MSG("Source '" + parent + "' failed to create mac80211 VAP: " +
				 string(errstr), MSGFLAG_PRINTERROR);

			if (opp_vap)
				goto end_vap;

			return -1;
		}

		// Switch our main processing interface to the vap
		interface = vap;

		// Set the flags if we have any, vap must be down to do so
		if (mac80211_flag_vec.size() > 0) {
			int oldflags;
			Ifconfig_Get_Flags(interface.c_str(), errstr, &oldflags);
			if (Ifconfig_Set_Flags(interface.c_str(), errstr,
								   oldflags & ~(IFF_UP | IFF_RUNNING)) < 0) {
				_MSG("Failed to bring down interface '" + interface + "' to "
					 "configure monitor flags: " + string(errstr), MSGFLAG_PRINTERROR);
			}

			if (mac80211_setvapflag(interface.c_str(), mac80211_flag_vec, errstr) < 0) {
				_MSG("Source '" + parent + "' failed to set flags on VAP '" +
					 interface + "': " + string(errstr), MSGFLAG_PRINTERROR);
			}
		}
	}

	// Yes, gotos suck.  Yes, go away
end_vap:

	// Try to grab the wireless mode
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &stored_mode) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to get current wireless mode for interface '" + interface + 
			 "', check your configuration and consult the Kismet README file",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	if (use_mac80211) {
		int oldflags;
		Ifconfig_Get_Flags(interface.c_str(), errstr, &oldflags);
		if (Ifconfig_Set_Flags(interface.c_str(), errstr,
							   oldflags & ~(IFF_UP | IFF_RUNNING)) < 0) {
			_MSG("Failed to bring down interface '" + interface + "' to "
				 "configure monitor: " + string(errstr), MSGFLAG_PRINTERROR);
			return -1;
		}

		// Force rfmon and vap flags, set mode with nl80211
		mac80211_flag_vec.push_back(nl80211_mntr_flag_control);
		mac80211_flag_vec.push_back(nl80211_mntr_flag_otherbss);

		if (mac80211_setvapflag(interface.c_str(), mac80211_flag_vec, errstr) < 0) {
			_MSG("Source '" + parent + "' failed to set flags on VAP '" +
				 interface + "': " + string(errstr), MSGFLAG_PRINTERROR);
		}

		if (Ifconfig_Delta_Flags(interface.c_str(), errstr, 
								 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
			_MSG("Failed to bring up interface '" + interface + "' after "
				 "configuring flags, something is weird (probably with your driver) "
				 "or your driver is missing firmware, check the output of 'dmesg': " +
				 string(errstr), MSGFLAG_PRINTERROR);
			return -1;
		}

		return 0;
	}

	// If it's already in monitor, make sure it's up and we're done
	if (stored_mode == LINUX_WLEXT_MONITOR) {
		_MSG("Interface '" + interface + "' is already marked as being in "
			 "monitor mode, leaving it as it is.", MSGFLAG_INFO);

		if (Ifconfig_Delta_Flags(interface.c_str(), errstr, 
								 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
			_MSG(errstr, MSGFLAG_PRINTERROR);
			_MSG("Failed to bring up interface '" + interface + "', this "
				 "often means there is a problem with the driver (such as "
				 "missing firmware), check the output of `dmesg'.",
				 MSGFLAG_PRINTERROR);
			return -1;
		}

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
	
	if (Iwconfig_Set_Mode(interface.c_str(), errstr, LINUX_WLEXT_MONITOR) < 0) {
		/* Bring the interface down and try again */
		_MSG("Failed to set monitor mode on interface '" + interface + "' "
			 "in current state, bringing interface down and trying again",
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

	}

	// Make sure it's up if nothing else
	if (Ifconfig_Delta_Flags(interface.c_str(), errstr, 
							 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to bring up interface '" + interface + "', this "
			 "often means there is a problem with the driver (such as "
			 "missing firmware), check the output of `dmesg'.",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	return 0;
}

int PacketSource_Wext::DisableMonitor() {
	char errstr[STATUS_MAX];

	if (wpa_local_path != "")
		unlink(wpa_local_path.c_str());

	// We don't really care if any of these things fail.  Keep trying.
	if (stored_channel > 0)
		SetChannel(stored_channel);

	// We do care if this fails; reset the wireless mode if we need to and we're 
	// not a VAP (those get left, we don't care)
	if (stored_mode > 0 && stored_mode != LINUX_WLEXT_MONITOR && vap == "") {
		if (Iwconfig_Set_Mode(interface.c_str(), errstr, stored_mode) < 0) {
			int oldflags;
			Ifconfig_Get_Flags(interface.c_str(), errstr, &oldflags);

			if (Ifconfig_Set_Flags(interface.c_str(), errstr,
								   oldflags & ~(IFF_UP | IFF_RUNNING)) < 0) {
				_MSG("Failed to restore previous wireless mode for interface '" +
					 interface + "'.  It may be left in an unknown or unusable state.",
					 MSGFLAG_PRINTERROR);
				return -1;
			}

			if (Iwconfig_Set_Mode(interface.c_str(), errstr, stored_mode) < 0) {
				_MSG("Failed to restore previous wireless mode for interface '" +
					 interface + "'.  It may be left in an unknown or unusable state.",
					 MSGFLAG_PRINTERROR);
				return -1;
			}
		}
	}

	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_Wext::SetChannel(unsigned int in_ch) {
	char errstr[STATUS_MAX];
	int err = 0;

	// printf("debug - wext - setting channel - %u\n", in_ch);

	// Set and exit if we're ok
	if (use_mac80211) {
		if ((err = mac80211_setchannel_cache(interface.c_str(), globalreg->nlhandle, 
											 nlfamily, in_ch, 0, errstr)) >= 0) {
			last_channel = in_ch;
			consec_error = 0;
			return 1;
		}
	} else {
		if ((err = Iwconfig_Set_Channel(interface.c_str(), in_ch, errstr)) >= 0) {
			last_channel = in_ch;
			consec_error = 0;
			return 1;
		}
	}

	_MSG("Packet source '" + name + "' failed to set channel " + IntToString(in_ch) + 
		 ": " + errstr, MSGFLAG_PRINTERROR);

	if (err == -22 && use_mac80211) {
		_MSG("Failed to change channel on source '" + name +"' and it looks "
			 "like the device is mac80211 based but does not accept channel control "
			 "over nl80211.  Kismet will fall back to using the IW* channel "
			 "methods.", MSGFLAG_PRINTERROR);
		use_mac80211 = 0;
		return SetChannel(in_ch);
	}

	if (err == -2) {
		_MSG("Failed to change channel on source '" + name +"' and it looks "
			 "like the device has been removed (or the drivers have lost track of "
			 "it somehow)", MSGFLAG_ERROR);
		error = 1;
		return -1;
	}

	int curmode;
	if (Iwconfig_Get_Mode(interface.c_str(), errstr, &curmode) < 0) {
		_MSG(errstr, MSGFLAG_PRINTERROR);
		_MSG("Failed to change channel on source '" + name + "' and "
			 "failed to fetch current interface state when determining the "
			 "cause of the error.  It is likely that the drivers are in a "
			 "broken or unavailable state.", MSGFLAG_PRINTERROR);
		error = 1;
		return -1;
	}

	if (curmode != LINUX_WLEXT_MONITOR) {
		_MSG("Failed to change channel on source '" + name + "'. " 
			 "It appears to no longer be in monitor mode.  This can happen if "
			 "the drivers enter an unknown or broken state, but usually indicate "
			 "that an external program has changed the device mode.  Make sure no "
			 "network management tools (such as networkmanager) are running "
			 "before starting Kismet.", MSGFLAG_PRINTERROR);
		error = 1;
		return -1;
	}

	return 1;
}

vector<unsigned int> PacketSource_Wext::FetchSupportedChannels(string in_interface) {
	vector<unsigned int> ret;
	char errstr[STATUS_MAX];

	/* If we couldn't figure out what we are with mac80211, or if we don't
	 * have mac80211, go on to iwcontrol */
	if (mac80211_get_chanlist(in_interface.c_str(), &ret, errstr) <= 0 ||
		ret.size() == 0) {
		/* I guess we don't really care about the return code here either */
		Iwconfig_Get_Chanlist(in_interface.c_str(), errstr, &ret);
	}

	return ret;
}

int PacketSource_Wext::FetchHardwareChannel() {
    char errstr[STATUS_MAX] = "";
	int chan = 0;

    // Failure to fetch a channel isn't necessarily a fatal error
	// and if we blow up badly enough that we can't get channels, we'll
	// blow up definitively on something else soon enough
    if ((chan = Iwconfig_Get_Channel(interface.c_str(), errstr)) < 0) {
        // globalreg->messagebus->InjectMessage("Source '" + name + "': " + errstr, 
		//									 MSGFLAG_PRINTERROR);
        return -1;
    }

	last_channel = chan;

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

	// if (FetchOpt("vapkill", in_opts) != "" && FetchOpt("vapkill", in_opts) != "true") {
	if (FetchOptBoolean("vapkill", in_opts, 1)) {
		vapdestroy = 0;
		_MSG("Madwifi-NG source " + name + " " + interface + ": Disabling destruction "
			 "of non-monitor VAPS because vapkill was not set to true in source "
			 "options.  This may cause capture problems with some driver versions.",
			 MSGFLAG_INFO);
	}
}

int PacketSource_Madwifi::OpenSource() {
	int r = PacketSource_Pcap::OpenSource();

	if (r < 0)
		return r;

	if (DatalinkType() < 0) {
		if (pd != NULL)
			pcap_close(pd);
		return -1;
	}

	return 1;
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

		// Don't bother looking at devices that look like the parent
		if (vaplist[x].find("wifi") != string::npos)
			continue;

		if (Iwconfig_Get_Mode(vaplist[x].c_str(), errstr, &iwmode) < 0) {
			_MSG("Madwifi source " + name + ": Could not get mode of VAP " + 
				 interface + "::" +
				 vaplist[x] + ".  Madwifi has historically had problems with "
				 "normal mode and monitor mode VAPs operating at the same time. "
				 "You may need to manually remove them.", MSGFLAG_PRINTERROR);
			sleep(1);
			continue;
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
			continue;
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
				continue;
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
		} else if (iwmode == LINUX_WLEXT_MONITOR) {
			_MSG("Madwifi source " + name + ": Found monitor-mode VAP " + 
				 interface + "::" + vaplist[x] + 
				 ".  We'll use that instead of making a new one.",
				 MSGFLAG_INFO);
			sleep(1);
			monvap = vaplist[x];
			interface = vaplist[x];
			continue;
		}
	}

	// If we're in a madwifi-ng model, build a vap.  Don't build one if
	// we already have one, and dont change the mode on an existing monitor
	// vap.
	if (monvap == "") {
		// Find the parent device
		if (parent == "") {
			int p = madwifing_find_parent(&vaplist);

			// Just use the interface if we can't find a parent?  This will
			// probably fail soon after, but whatever
			if (p < 0)
				parent = interface;
			else
				parent = vaplist[p];
		}

		if (madwifing_build_vap(parent.c_str(), errstr, "kis", newdev,
								IEEE80211_M_MONITOR, IEEE80211_CLONE_BSSID) >= 0) {
			_MSG("Madwifi source " + name + " created monitor-mode VAP " +
				 parent + "::" + newdev + ".", MSGFLAG_INFO);

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
		_MSG(errstr, MSGFLAG_PRINTERROR);
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
	// See if it looks like a madwifi-ng device if we can't match anything else
	vector<string> mwngvaps;
	if (madwifing_list_vaps(in_device.c_str(), &mwngvaps) > 0) {
		type = "madwifi";
		return 1;
	}

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
	error = 0;

	// Store the interface
	string realsrc = interface;

	// Fake the prism0 interface
	interface = "prism0";
	// Open using prism0
	int ret = PacketSource_Wext::OpenSource();
	// Restore
	interface = realsrc;

	if (ret < 0)
		return ret;

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
		if (pd != NULL)
			pcap_close(pd);
		return -1;
	}

	return 1;
}

#endif

