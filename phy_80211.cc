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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <limits.h>

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gpstracker.h"
#include "packet.h"
#include "uuid.h"
#include "alertracker.h"
#include "manuf.h"
#include "configfile.h"

#include "base64.h"

#include "devicetracker.h"
#include "phy_80211.h"

#include "structured.h"
#include "msgpack_adapter.h"
#include "kismet_json.h"

#include "kis_httpd_registry.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
}

static int packetnum = 0;

// Convert the beacon interval to # of packets per second
unsigned int Ieee80211Interval2NSecs(int in_interval) {
	double interval_per_sec;

	interval_per_sec = (double) in_interval * 1024 / 1000000;
	
	return (unsigned int) ceil(1.0f / interval_per_sec);
}

void dot11_tracked_eapol::register_fields() {
    tracker_component::register_fields();

    RegisterField("dot11.eapol.timestamp", TrackerDouble, 
            "packet timestamp (second.usecond)", &eapol_time);
    
    RegisterField("dot11.eapol.direction", TrackerUInt8,
            "packet direction (fromds/tods)", &eapol_dir);

    RegisterField("dot11.eapol.message_num", TrackerUInt8,
            "handshake message number", &eapol_msg_num);

    RegisterField("dot11.eapol.replay_counter", TrackerUInt64,
            "eapol frame replay counter", &eapol_replay_counter);

    RegisterField("dot11.eapol.install", TrackerUInt8,
            "eapol rsn key install", &eapol_install);

    RegisterField("dot11.eapol.nonce", TrackerByteArray,
            "eapol rsn nonce", &eapol_nonce);

    __RegisterComplexField(kis_tracked_packet, eapol_packet_id,
            "dot11.eapol.packet", "EAPOL handshake");
}

void dot11_tracked_eapol::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    if (e != NULL) {
        eapol_packet.reset(new kis_tracked_packet(globalreg, eapol_packet_id,
                    e->get_map_value(eapol_packet_id)));
    } else {
        eapol_packet.reset(new kis_tracked_packet(globalreg, eapol_packet_id));
    }

    add_map(eapol_packet);
}

void dot11_tracked_ssid_alert::register_fields() {
    tracker_component::register_fields();

    RegisterField("dot11.ssidalert.name", TrackerString,
            "Unique name of alert group", &ssid_group_name);
    RegisterField("dot11.ssidalert.regex", TrackerString,
            "Matching regex for SSID", &ssid_regex);
    RegisterField("dot11.ssidalert.allowed_macs", TrackerVector,
            "Allowed MAC addresses", &allowed_macs_vec);

    allowed_mac_id =
        RegisterField("dot11.ssidalert.allowed_mac", TrackerMac,
                "mac address");

}

void dot11_tracked_ssid_alert::set_regex(std::string s) {
#ifdef HAVE_LIBPCRE
    local_locker lock(&ssid_mutex);

    const char *compile_error, *study_error;
    int erroroffset;
    std::ostringstream errordesc;

    if (ssid_re)
        pcre_free(ssid_re);
    if (ssid_study)
        pcre_free(ssid_study);

    ssid_regex->set(s);

    ssid_re = pcre_compile(s.c_str(), 0, &compile_error, &erroroffset, NULL);

    if (ssid_re == NULL) {
        errordesc << "Could not parse PCRE: " << compile_error << 
            "at character " << erroroffset;
        throw std::runtime_error(errordesc.str());
    }

    ssid_study = pcre_study(ssid_re, 0, &study_error);

    if (study_error != NULL) {
        errordesc << "Could not parse PCRE, optimization failure: " << study_error;
        throw std::runtime_error(errordesc.str());
    } 
#endif
}

void dot11_tracked_ssid_alert::set_allowed_macs(std::vector<mac_addr> mvec) {
    local_locker lock(&ssid_mutex);

    TrackerElementVector v(allowed_macs_vec);

    v.clear();

    for (auto i : mvec) {
        SharedTrackerElement e(new TrackerElement(TrackerMac, allowed_mac_id));
        e->set(i);

        v.push_back(e);
    }
}

bool dot11_tracked_ssid_alert::compare_ssid(std::string ssid, mac_addr mac) {
    local_locker lock(&ssid_mutex);

#ifdef HAVE_LIBPCRE
    int rc;
    int ovector[128];

    rc = pcre_exec(ssid_re, ssid_study, ssid.c_str(), ssid.length(), 0, 0, ovector, 128);

    if (rc > 0) {
        TrackerElementVector v(allowed_macs_vec);

        // Look for a mac address which isn't in the allowed list
        for (auto m : v) {
            if (m->get_mac() != mac)
                return true;
        }
    }
#endif

    return false;

}

void dot11_tracked_nonce::register_fields() {
    tracker_component::register_fields();

    RegisterField("dot11.eapol.nonce.timestamp", TrackerDouble, 
            "packet timestamp (second.usecond)", &eapol_time);
    
    RegisterField("dot11.eapol.nonce.message_num", TrackerUInt8,
            "handshake message number", &eapol_msg_num);

    RegisterField("dot11.eapol.nonce.replay_counter", TrackerUInt64,
            "eapol frame replay counter", &eapol_replay_counter);

    RegisterField("dot11.eapol.nonce.install", TrackerUInt8,
            "eapol rsn key install", &eapol_install);

    RegisterField("dot11.eapol.nonce.nonce", TrackerByteArray,
            "eapol rsn nonce", &eapol_nonce);
}

void dot11_tracked_nonce::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);
}

void dot11_tracked_nonce::set_from_eapol(SharedTrackerElement in_tracked_eapol) {
    std::shared_ptr<dot11_tracked_eapol> e =
        std::static_pointer_cast<dot11_tracked_eapol>(in_tracked_eapol);

    set_eapol_time(e->get_eapol_time());
    set_eapol_msg_num(e->get_eapol_msg_num());
    set_eapol_replay_counter(e->get_eapol_replay_counter());


    set_eapol_install(e->get_eapol_install());
    set_eapol_nonce(e->get_eapol_nonce());
}

int phydot11_packethook_wep(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketWepDecryptor(in_pack);
}

int phydot11_packethook_dot11(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketDot11dissector(in_pack);
}

Kis_80211_Phy::Kis_80211_Phy(GlobalRegistry *in_globalreg, 
		Devicetracker *in_tracker, int in_phyid) : 
	Kis_Phy_Handler(in_globalreg, in_tracker, in_phyid),
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

    alertracker =
        Globalreg::FetchGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");

    packetchain =
        Globalreg::FetchGlobalAs<Packetchain>(globalreg, "PACKETCHAIN");

    timetracker =
        Globalreg::FetchGlobalAs<Timetracker>(globalreg, "TIMETRACKER");

	// Initialize the crc tables
	crc32_init_table_80211(globalreg->crc32_table);

    SetPhyName("IEEE802.11");

    std::shared_ptr<dot11_tracked_device> dot11_builder(new dot11_tracked_device(globalreg, 0));
    dot11_device_entry_id =
        entrytracker->RegisterField("dot11.device", dot11_builder, 
                "IEEE802.11 device");

	// Packet classifier - makes basic records plus dot11 data
	packetchain->RegisterHandler(&CommonClassifierDot11, this,
            CHAINPOS_CLASSIFIER, -100);
	packetchain->RegisterHandler(&phydot11_packethook_wep, this,
            CHAINPOS_DECRYPT, -100);
	packetchain->RegisterHandler(&phydot11_packethook_dot11, this,
            CHAINPOS_LLCDISSECT, -100);

	// If we haven't registered packet components yet, do so.  We have to
	// co-exist with the old tracker core for some time
	pack_comp_80211 = _PCM(PACK_COMP_80211) =
		packetchain->RegisterPacketComponent("PHY80211");

	pack_comp_basicdata = 
		packetchain->RegisterPacketComponent("BASICDATA");

	pack_comp_mangleframe = 
		packetchain->RegisterPacketComponent("MANGLEDATA");

	pack_comp_checksum =
		packetchain->RegisterPacketComponent("CHECKSUM");

	pack_comp_linkframe = 
		packetchain->RegisterPacketComponent("LINKFRAME");

	pack_comp_decap =
		packetchain->RegisterPacketComponent("DECAP");

	pack_comp_common = 
		packetchain->RegisterPacketComponent("COMMON");

	pack_comp_datapayload =
		packetchain->RegisterPacketComponent("DATAPAYLOAD");

	pack_comp_gps =
		packetchain->RegisterPacketComponent("GPS");

    pack_comp_l1info =
        packetchain->RegisterPacketComponent("RADIODATA");

    ssid_regex_vec =
        entrytracker->RegisterAndGetField("phy80211.ssid_alerts", TrackerVector,
                "Regex SSID alert configuration");
    ssid_regex_vec_element_id =
        entrytracker->RegisterField("phy80211.ssid_alert", 
                std::shared_ptr<dot11_tracked_ssid_alert>(new dot11_tracked_ssid_alert(globalreg, 0)),
                "ssid alert");

	// Register the dissector alerts
	alert_netstumbler_ref = 
		alertracker->ActivateConfiguredAlert("NETSTUMBLER", 
                "Netstumbler (and similar older Windows tools) may generate unique "
                "beacons which can be used to identify these tools in use.  These "
                "tools and the cards which generate these frames are uncommon.",
                phyid);
	alert_nullproberesp_ref =
		alertracker->ActivateConfiguredAlert("NULLPROBERESP", 
                "A probe response with a SSID length of 0 can be used to crash the "
                "firmware in specific older Orinoco cards.  These cards are "
                "unlikely to be in use in modern systems.",
                phyid);
	alert_lucenttest_ref =
		alertracker->ActivateConfiguredAlert("LUCENTTEST", 
                "Specific Lucent Orinoco test tools generate identifiable frames, "
                "which can indicate these tools are in use.  These tools and the "
                "cards which generate these frames are uncommon.",
                phyid);
	alert_msfbcomssid_ref =
		alertracker->ActivateConfiguredAlert("MSFBCOMSSID", 
                "Old versions of the Broadcom Windows drivers (and Linux NDIS drivers) "
                "are vulnerable to overflow exploits.  The Metasploit framework "
                "can attack these vulnerabilities.  These drivers are unlikely to "
                "be found in modern systems, but seeing these malformed frames "
                "indicates an attempted attack is occurring.",
                phyid);
	alert_msfdlinkrate_ref =
		alertracker->ActivateConfiguredAlert("MSFDLINKRATE", 
                "Old versions of the D-Link Windows drivers are vulnerable to "
                "malformed rate fields.  The Metasploit framework can attack these "
                "vulnerabilities.  These drivers are unlikely to be found in "
                "modern systems, but seeing these malformed frames indicates an "
                "attempted attack is occurring.",
                phyid);
	alert_msfnetgearbeacon_ref =
		alertracker->ActivateConfiguredAlert("MSFNETGEARBEACON", 
                "Old versions of the Netgear windows drivers are vulnerable to "
                "malformed beacons.  The Metasploit framework can attack these "
                "vulnerabilities.  These drivers are unlikely to be found in "
                "modern systems, but seeing these malformed frames indicates an "
                "attempted attack is occurring.",
                phyid);
	alert_longssid_ref =
		alertracker->ActivateConfiguredAlert("LONGSSID", 
                "The Wi-Fi standard allows for 32 characters in a SSID. "
                "Historically, some drivers have had vulnerabilities related to "
                "invalid over-long SSID fields.  Seeing these frames indicates that "
                "significant corruption or an attempted attack is occurring.",
                phyid);
	alert_disconinvalid_ref =
		alertracker->ActivateConfiguredAlert("DISCONCODEINVALID", 
                "The 802.11 specification defines reason codes for disconnect "
                "and deauthentication events.  Historically, various drivers "
                "have been reported to improperly handle invalid reason codes.  "
                "An invalid reason code indicates an improperly behaving device or "
                "an attempted attack.",
                phyid);
	alert_deauthinvalid_ref =
		alertracker->ActivateConfiguredAlert("DEAUTHCODEINVALID", 
                "The 802.11 specification defines reason codes for disconnect "
                "and deauthentication events.  Historically, various drivers "
                "have been reported to improperly handle invalid reason codes.  "
                "An invalid reason code indicates an improperly behaving device or "
                "an attempted attack.",
                phyid);
    alert_wmm_ref =
        alertracker->ActivateConfiguredAlert("WMMOVERFLOW",
                "The Wi-Fi standard specifies 24 bytes for WMM IE tags.  Over-sized "
                "WMM fields may indicate an attempt to exploit bugs in Broadcom chipsets "
                "using the Broadpwn attack",
                phyid);
#if 0
	alert_dhcpclient_ref =
		alertracker->ActivateConfiguredAlert("DHCPCLIENTID", phyid);
#endif

	// Register the tracker alerts
	alert_chan_ref =
		alertracker->ActivateConfiguredAlert("CHANCHANGE", 
                "An access point has changed channel.  This may occur on "
                "enterprise equipment or on personal equipment with automatic "
                "channel selection, but may also indicate a spoofed or "
                "'evil twin' network.",
                phyid);
	alert_dhcpcon_ref =
		alertracker->ActivateConfiguredAlert("DHCPCONFLICT", 
                "A DHCP exchange was observed and a client was given an IP via "
                "DHCP, but is not using the assigned IP.  This may be a "
                "mis-configured client device, or may indicate client spoofing.",
                phyid);
	alert_bcastdcon_ref =
		alertracker->ActivateConfiguredAlert("BCASTDISCON", 
                "A broadcast disconnect packet forces all clients on a network "
                "to disconnect.  While these may rarely occur in some environments, "
                "typically a broadcast disconnect indicates a denial of service "
                "attack or an attempt to attack the network encryption by forcing "
                "clients to reconnect.",
                phyid);
	alert_airjackssid_ref = 
		alertracker->ActivateConfiguredAlert("AIRJACKSSID", 
                "Very old wireless tools used the SSID 'Airjack' while configuring "
                "card state.  It is very unlikely to see these tools in operation "
                "in modern environments.",
                phyid);
	alert_wepflap_ref =
		alertracker->ActivateConfiguredAlert("CRYPTODROP", 
                "A previously encrypted SSID has stopped advertising encryption.  "
                "This may rarely occur when a network is reconfigured to an open "
                "state, but more likely indicates some form of network spoofing or "
                "'evil twin' attack.",
                phyid);
	alert_dhcpname_ref =
		alertracker->ActivateConfiguredAlert("DHCPNAMECHANGE", 
                "The DHCP protocol allows clients to put the host name and "
                "DHCP client / vendor / operating system details in the DHCP "
                "Discovery packet.  These values should old change if the client "
                "has changed drastically (such as a dual-boot system with multiple "
                "operating systems).  Changing values can often indicate a client "
                "spoofing or MAC cloning attempt.",
                phyid);
	alert_dhcpos_ref =
		alertracker->ActivateConfiguredAlert("DHCPOSCHANGE", 
                "The DHCP protocol allows clients to put the host name and "
                "DHCP client / vendor / operating system details in the DHCP "
                "Discovery packet.  These values should old change if the client "
                "has changed drastically (such as a dual-boot system with multiple "
                "operating systems).  Changing values can often indicate a client "
                "spoofing or MAC cloning attempt.",
                phyid);
	alert_adhoc_ref =
		alertracker->ActivateConfiguredAlert("ADHOCCONFLICT", 
                "The same SSID is being advertised as an access point and as an "
                "ad-hoc network.  This may indicate a misconfigured or misbehaving "
                "device, or could indicate an attempt at spoofing or an 'evil twin' "
                "attack.",
                phyid);
	alert_ssidmatch_ref =
		alertracker->ActivateConfiguredAlert("APSPOOF", 
                "Kismet may be given a list of authorized MAC addresses for "
                "a SSID.  If a beacon or probe response is seen from a MAC address "
                "not listed in the authorized list, this alert will be raised.",
                phyid);
	alert_dot11d_ref =
		alertracker->ActivateConfiguredAlert("DOT11D", 
                "Conflicting 802.11d (country code) data has been advertised by the "
                "same SSID.  It is unlikely this is a normal configuration change, "
                "and can indicate a spoofed or 'evil twin' network, or an attempt "
                "to perform a denial of service on clients by restricting their "
                "frequencies.  802.11d has been phased out and is unlikely to be "
                "seen on modern devices, but it is still supported by many systems.",
                phyid);
	alert_beaconrate_ref =
		alertracker->ActivateConfiguredAlert("BEACONRATE", 
                "The advertised beacon rate of a SSID has changed.  In an "
                "enterprise or multi-SSID environment this may indicate a normal "
                "configuration change, but can also indicate a spoofed or "
                "'evil twin' network.",
                phyid);
	alert_cryptchange_ref =
		alertracker->ActivateConfiguredAlert("ADVCRYPTCHANGE", 
                "A SSID has changed the advertised supported encryption standards.  "
                "This may be a normal change when reconfiguring an access point, "
                "but can also indicate a spoofed or 'evil twin' attack.",
                phyid);
	alert_malformmgmt_ref =
		alertracker->ActivateConfiguredAlert("MALFORMMGMT", 
                "Malformed management frames may indicate errors in the capture "
                "source driver (such as not discarding corrupted packets), but can "
                "also be indicative of an attempted attack against drivers which may "
                "not properly handle malformed frames.",
                phyid);
	alert_wpsbrute_ref =
		alertracker->ActivateConfiguredAlert("WPSBRUTE", 
                "Excessive WPS events may indicate a malformed client, or an "
                "attack on the WPS system by a tool such as Reaver.",
                phyid);
    alert_l33t_ref = 
        alertracker->ActivateConfiguredAlert("KARMAOUI",
                "Probe responses from MAC addresses with an OUI of 00:13:37 often "
                "indicate an Karma AP impersonation attack.",
                phyid);
    alert_tooloud_ref =
        alertracker->ActivateConfiguredAlert("OVERPOWERED",
                "Signal levels are abnormally high, when using an external amplifier "
                "this could indicate that the gain is too high.  Over-amplified signals "
                "may miss packets entirely.",
                phyid);
    alert_nonce_zero_ref =
        alertracker->ActivateConfiguredAlert("NONCEDEGRADE",
                "A WPA handshake with an empty NONCE was observed; this could indicate "
                "a WPA degradation attack such as the vanhoefm attack against BSD "
                "(https://github.com/vanhoefm/blackhat17-pocs/tree/master/openbsd)",
                phyid);
    alert_nonce_duplicate_ref =
        alertracker->ActivateConfiguredAlert("NONCEREUSE",
                "A WPA handshake has attempted to re-use a previous nonce value; this may "
                "indicate an attack against the WPA keystream such as the vanhoefm "
                "KRACK attack (https://www.krackattacks.com/)");
    alert_atheros_wmmtspec_ref =
        alertracker->ActivateConfiguredAlert("WMMTSPEC",
                "Too many WMMTSPEC options were seen in a probe response; this "
                "may be triggered by CVE-2017-11013 as described at "
                "https://pleasestopnamingvulnerabilities.com/");
    alert_atheros_rsnloop_ref =
        alertracker->ActivateConfiguredAlert("RSNLOOP",
                "Invalid RSN (802.11i) tags in beacon frames can be used to cause "
                "loops in some Atheros drivers, as described in "
                "CVE-2017-9714 and https://pleasestopnamingvulnerabilities.com/");
    alert_11kneighborchan_ref =
        alertracker->ActivateConfiguredAlert("BCOM11KCHAN",
                "Invalid channels in 802.11k neighbor report frames "
                "can be used to exploit certain Broadcom HardMAC implementations, typically used "
                "in mobile devices, as described in "
                "https://bugs.chromium.org/p/project-zero/issues/detail?id=1289");

    // Threshold
    signal_too_loud_threshold = 
        globalreg->kismet_config->FetchOptInt("dot11_max_signal", -10);

	// Do we process the whole data packet?
    if (globalreg->kismet_config->FetchOptBoolean("hidedata", 0) ||
		globalreg->kismet_config->FetchOptBoolean("dontbeevil", 0)) {
		_MSG("hidedata= set in Kismet config.  Kismet will ignore the contents "
			 "of data packets entirely", MSGFLAG_INFO);
		dissect_data = 0;
	} else {
		dissect_data = 1;
	}

    // Do we process phy and control frames?  They seem to be the glitchiest
    // on many cards including the ath9k which is otherwise excellent
    if (globalreg->kismet_config->FetchOptBoolean("dot11_process_phy", 0)) {
        _MSG("PHY802.11 will process Wi-Fi 'phy' and 'control' type frames, which "
                "gives the most complete view of device traffic but may result in "
                "false devices due to driver and firmware quirks.", MSGFLAG_INFO);
        process_ctl_phy = true;
    } else {
        _MSG("PHY802.11 will not process Wi-Fi 'phy' and 'control' frames; these "
                "typically are the most susceptible to corruption resulting in "
                "false devices.  This can be re-enabled with dot11_process_phy=true",
                MSGFLAG_INFO);
        process_ctl_phy = false;
    }

	dissect_strings = 0;
	dissect_all_strings = 0;

	// Load the wep keys from the config file
	if (LoadWepkeys() < 0) {
		globalreg->fatal_condition = 1;
		return;
	}

    // TODO turn into REST endpoint
    if (globalreg->kismet_config->FetchOptBoolean("allowkeytransmit", 0)) {
        _MSG("Allowing Kismet clients to view WEP keys", MSGFLAG_INFO);
        client_wepkey_allowed = 1;
    } else {
		client_wepkey_allowed = 0;
	}

	// Build the wep identity
	for (unsigned int wi = 0; wi < 256; wi++)
		wep_identity[wi] = wi;

	string_filter = new FilterCore(globalreg);
	std::vector<std::string> filterlines = 
		globalreg->kismet_config->FetchOptVec("filter_string");
	for (unsigned int fl = 0; fl < filterlines.size(); fl++) {
		if (string_filter->AddFilterLine(filterlines[fl]) < 0) {
			_MSG("Failed to add filter_string config line from the Kismet config "
				 "file.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
	}

    // Set up the device timeout
    device_idle_expiration =
        globalreg->kismet_config->FetchOptInt("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        device_idle_min_packets =
            globalreg->kismet_config->FetchOptUInt("tracker_device_packets", 0);

        std::stringstream ss;
        ss << "Removing 802.11 device info which has been inactive for more than " <<
            device_idle_expiration << " seconds";

        if (device_idle_min_packets > 2) 
            ss << " and references fewer than " << device_idle_min_packets << " packets";

        _MSG(ss.str(), MSGFLAG_INFO);

        device_idle_timer =
            timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 60, NULL, 
                1, this);
    } else {
        device_idle_timer = -1;
    }

	conf_save = globalreg->timestamp.tv_sec;

	ssid_conf = new ConfigFile(globalreg);
	ssid_conf->ParseConfig(ssid_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "ssid_map.conf", "", "", 0, 1).c_str());
	globalreg->InsertGlobal("SSID_CONF_FILE", std::shared_ptr<ConfigFile>(ssid_conf));

    httpd_pcap.reset(new Phy_80211_Httpd_Pcap(globalreg));

    // Register js module for UI
    std::shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_dot11", "/js/kismet.ui.dot11.js");

    // Set up the de-duplication list
    recent_packet_checksums_sz = 
        globalreg->kismet_config->FetchOptUInt("packet_dedup_size", 2048);
    recent_packet_checksums = new uint32_t[recent_packet_checksums_sz];
    for (unsigned int x = 0; x < recent_packet_checksums_sz; x++) {
        recent_packet_checksums[x] = 0;
    }
    recent_packet_checksum_pos = 0;

    // Parse the ssid regex options
    auto apspoof_lines = globalreg->kismet_config->FetchOptVec("apspoof");

    TrackerElementVector apv(ssid_regex_vec);

    for (auto l : apspoof_lines) {
        size_t cpos = l.find(':');
        
        if (cpos == std::string::npos) {
            _MSG("Invalid 'apspoof' configuration line, expected 'name:ssid=\"...\","  
                    "validmacs=\"...\" but got '" + l + "'", MSGFLAG_ERROR);
            continue;
        }

        std::string name = l.substr(0, cpos);

        std::vector<opt_pair> optvec;
        StringToOpts(l.substr(cpos + 1, l.length()), ",", &optvec);

        std::string ssid = FetchOpt("ssid", &optvec);

        if (ssid == "") {
            _MSG("Invalid 'apspoof' configuration line, expected 'name:ssid=\"...\","  
                    "validmacs=\"...\" but got '" + l + "'", MSGFLAG_ERROR);
            continue;
        }

        std::vector<mac_addr> macvec;
        for (auto m : StrTokenize(FetchOpt("validmacs", &optvec), ",", true)) {
            mac_addr ma(m);

            if (ma.error) {
                macvec.clear();
                break;
            }

            macvec.push_back(ma);
        }

        if (macvec.size() == 0) {
            _MSG("Invalid 'apspoof' configuration line, expected 'name:ssid=\"...\","  
                    "validmacs=\"...\" but got '" + l + "'", MSGFLAG_ERROR);
            continue;
        }

        std::shared_ptr<dot11_tracked_ssid_alert> 
            ssida(new dot11_tracked_ssid_alert(globalreg, ssid_regex_vec_element_id));

        try {
            ssida->set_group_name(name);
            ssida->set_regex(ssid);
            ssida->set_allowed_macs(macvec);
        } catch (std::runtime_error &e) {
            _MSG("Invalid 'apspoof' configuration line '" + l + "': " + e.what(),
                    MSGFLAG_ERROR);
            continue;
        }

        apv.push_back(ssida);

    }

}

Kis_80211_Phy::~Kis_80211_Phy() {
	packetchain->RemoveHandler(&phydot11_packethook_wep, CHAINPOS_DECRYPT);
	packetchain->RemoveHandler(&phydot11_packethook_dot11, 
										  CHAINPOS_LLCDISSECT);
	/*
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11data, 
										  CHAINPOS_DATADISSECT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11string,
										  CHAINPOS_DATADISSECT);
										  */
	packetchain->RemoveHandler(&CommonClassifierDot11,
            CHAINPOS_CLASSIFIER);

    timetracker->RemoveTimer(device_idle_timer);

    delete[] recent_packet_checksums;
}

int Kis_80211_Phy::LoadWepkeys() {
    // Convert the WEP mappings to our real map
    std::vector<std::string> raw_wepmap_vec;
    raw_wepmap_vec = globalreg->kismet_config->FetchOptVec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        std::string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == std::string::npos) {
            _MSG("Malformed 'wepkey' option in the config file", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.error == 1) {
            _MSG("Malformed 'wepkey' option in the config file", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
        }

        std::string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = Hex2UChar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
			_MSG("Invalid key '" + rawkey + "' length " + IntToString(len) + 
				 " in a wepkey= config file entry", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
        }

        dot11_wep_key *keyinfo = new dot11_wep_key;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->decrypted = 0;
        keyinfo->failed = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        wepkeys.insert(bssid_mac, keyinfo);

		_MSG("Using key '" + rawkey + "' for BSSID " + bssid_mac.Mac2String(),
			 MSGFLAG_INFO);
    }

	return 1;
}

// Common classifier responsible for generating the common devices & mapping wifi packets
// to those devices
int Kis_80211_Phy::CommonClassifierDot11(CHAINCALL_PARMS) {
    packetnum++;

    Kis_80211_Phy *d11phy = (Kis_80211_Phy *) auxdata;

    // Don't process errors, blocked, or dupes
    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    // Get the 802.11 info
    dot11_packinfo *dot11info = 
        (dot11_packinfo *) in_pack->fetch(d11phy->pack_comp_80211);
    if (dot11info == NULL)
        return 0;

    kis_common_info *commoninfo = 
        (kis_common_info *) in_pack->fetch(d11phy->pack_comp_common);

    if (commoninfo == NULL) {
        fprintf(stderr, "debug - packet made it to dot11 classifier with dot11info but no common info\n");
        return 0;
    }

	kis_layer1_packinfo *pack_l1info =
		(kis_layer1_packinfo *) in_pack->fetch(d11phy->pack_comp_l1info);


    if (pack_l1info != NULL && pack_l1info->signal_dbm > d11phy->signal_too_loud_threshold
            && pack_l1info->signal_dbm < 0 && 
            d11phy->alertracker->PotentialAlert(d11phy->alert_tooloud_ref)) {

        std::stringstream ss;

        ss << "Saw packet with a reported signal level of " <<
            pack_l1info->signal_dbm << " which is above the threshold of " <<
            d11phy->signal_too_loud_threshold << ".  Excessively high signal levels can " <<
            "be caused by misconfigured external amplifiers and lead to lost " <<
            "packets.";

        d11phy->alertracker->RaiseAlert(d11phy->alert_tooloud_ref, in_pack, 
                dot11info->bssid_mac, dot11info->source_mac, 
                dot11info->dest_mac, dot11info->other_mac, 
                dot11info->channel, ss.str());
    }

    // Do nothing if it's corrupt
    if (dot11info->type == packet_noise || dot11info->corrupt ||
            in_pack->error || dot11info->type == packet_unknown ||
            dot11info->subtype == packet_sub_unknown) {
        in_pack->error = 1;
        return 0;
    }

    // Get the checksum info; 
    //
    // We don't do anything if the packet is invalid;  in the future we might want
    // to try to attach it to an existing network if we can understand that much
    // of the frame and then treat it as an error, but that artificially inflates 
    // the error condition on a network when FCS errors are pretty normal.
    //
    // By never creating a common info record we should prevent any handling of this
    // nonsense;  So far investigation doesn't show much useful in FCS corrupted data.
    kis_packet_checksum *fcs =
        (kis_packet_checksum *) in_pack->fetch(d11phy->pack_comp_checksum);

    if (fcs != NULL && fcs->checksum_valid == 0) {
        return 0;
    }

	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(d11phy->pack_comp_gps);

	kis_data_packinfo *pack_datainfo =
		(kis_data_packinfo *) in_pack->fetch(d11phy->pack_comp_basicdata);

    std::shared_ptr<kis_tracked_device_base> source_dev;
    std::shared_ptr<kis_tracked_device_base> dest_dev;
    std::shared_ptr<kis_tracked_device_base> bssid_dev;
    std::shared_ptr<kis_tracked_device_base> other_dev;

    std::shared_ptr<dot11_tracked_device> source_dot11;
    std::shared_ptr<dot11_tracked_device> dest_dot11;
    std::shared_ptr<dot11_tracked_device> bssid_dot11;
    std::shared_ptr<dot11_tracked_device> other_dot11;

    if (dot11info->type == packet_management) {
        // Resolve the common structures of management frames; this is a lot of code
        // copy and paste, but because this happens *every single packet* we probably 
        // don't want to do much more complex object creation
        commoninfo->type = packet_basic_mgmt;
        
        if (dot11info->bssid_mac != globalreg->empty_mac && 
                !(dot11info->bssid_mac.bitwise_and(globalreg->multicast_mac)) ) {

            bssid_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo, 
                        dot11info->bssid_mac, d11phy, in_pack, 
                        (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                         UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));
        }

        if (dot11info->source_mac != dot11info->bssid_mac &&
                dot11info->source_mac != globalreg->empty_mac && 
                !(dot11info->source_mac.bitwise_and(globalreg->multicast_mac)) ) {
            source_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo, 
                        dot11info->source_mac, d11phy, in_pack, 
                        (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                         UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));
        }

        if (dot11info->dest_mac != dot11info->source_mac &&
                dot11info->dest_mac != dot11info->bssid_mac &&
                dot11info->dest_mac != globalreg->empty_mac && 
                !(dot11info->dest_mac.bitwise_and(globalreg->multicast_mac)) ) {
            dest_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo, 
                        dot11info->dest_mac, d11phy, in_pack, 
                        (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                         UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));
        }

        if (bssid_dev != NULL) {
            local_locker bssidlocker(&(bssid_dev->device_mutex));

            bssid_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(bssid_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (bssid_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi access point " << 
                    bssid_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                bssid_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(bssid_dot11, bssid_dev);

                dot11info->new_device = true;
            }

            // Detect if we're an adhoc bssid
            if (dot11info->ibss) {
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                bssid_dev->set_type_string("Wi-Fi Adhoc");
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_ADHOC);
            } else {
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
                bssid_dev->set_type_string("Wi-Fi AP");
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_BEACON_AP);
            }

            // Do some maintenance on the bssid device if we're a beacon or other ssid-carrying
            // packet...

            if (dot11info->subtype == packet_sub_beacon) {
                bssid_dot11->set_last_beacon_timestamp(in_pack->ts.tv_sec);
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_BEACON_AP);
            }

            if (dot11info->subtype == packet_sub_beacon ||
                    dot11info->subtype == packet_sub_probe_resp) {
                d11phy->HandleSSID(bssid_dev, bssid_dot11, in_pack, dot11info, pack_gpsinfo);
            }
        }

        if (source_dev != NULL) {
            local_locker sourcelocker(&(source_dev->device_mutex));

            source_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(source_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (source_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi device " << 
                    source_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                source_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(source_dot11, source_dev);

                dot11info->new_device = true;
            }

            // If it's sending ibss-flagged packets it's got to be adoc
            if (dot11info->ibss) {
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                source_dev->set_type_string("Wi-Fi Adhoc");
                source_dot11->bitset_type_set(DOT11_DEVICE_TYPE_ADHOC);
            } else {
                // If it's the source of a mgmt packet, it's got to be a wifi device of 
                // some sort and not just bridged
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);
                source_dev->set_type_string_ifnot("Wi-Fi Client", KIS_DEVICE_BASICTYPE_CLIENT);
            }

            if (dot11info->subtype == packet_sub_probe_req ||
                    dot11info->subtype == packet_sub_reassociation_req) {
                d11phy->HandleProbedSSID(source_dev, source_dot11, in_pack, dot11info, pack_gpsinfo);
            }
        }

        if (dest_dev != NULL) {
            local_locker destlocker(&(dest_dev->device_mutex));

            dest_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(dest_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (dest_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi device " << 
                    dest_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                dest_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(dest_dot11, dest_dev);
                
                dot11info->new_device = true;
            }

            // If it's receiving a management packet, it must be a wifi device
            dest_dev->bitclear_basic_type_set(KIS_DEVICE_BASICTYPE_WIRED);
            dest_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);
            dest_dev->set_type_string_ifnot("Wi-Fi Client", KIS_DEVICE_BASICTYPE_AP);
        }

        // Safety check that our BSSID device exists
        if (bssid_dev != NULL) {
            // Now we've instantiated and mapped all the possible devices and dot11 devices; now
            // populate the per-client records for any which have mgmt communication
            
            // Don't map blind req's as being a client
            if (source_dev != NULL && 
                    (dot11info->subtype != packet_sub_probe_req &&
                     dot11info->subtype != packet_sub_association_req &&
                     dot11info->subtype != packet_sub_reassociation_req))
                d11phy->ProcessClient(bssid_dev, bssid_dot11, source_dev, source_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);

            // Don't map probe respsonses as clients
            if (dest_dev != NULL && dot11info->subtype != packet_sub_probe_resp)
                d11phy->ProcessClient(bssid_dev, bssid_dot11, dest_dev, dest_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);

            // alerts on broadcast deauths
            if  ((dot11info->subtype == packet_sub_disassociation ||
                        dot11info->subtype == packet_sub_deauthentication) &&
                    dot11info->dest_mac == globalreg->broadcast_mac &&
                    d11phy->alertracker->PotentialAlert(d11phy->alert_bcastdcon_ref)) {

                std::string al = "IEEE80211 Access Point BSSID " +
                    bssid_dev->get_macaddr().Mac2String() + " broadcast deauthentication or "
                    "disassociation of all clients; Either the  AP is shutting down or there "
                    "is a possible denial of service.";

                d11phy->alertracker->RaiseAlert(d11phy->alert_bcastdcon_ref, in_pack, 
                        dot11info->bssid_mac, dot11info->source_mac, 
                        dot11info->dest_mac, dot11info->other_mac, 
                        dot11info->channel, al);
            }
        }
    } else if (dot11info->type == packet_phy) {
        // Phy packets are so often bogus that we just ignore them for now; if we enable
        // creating devices from them, even on "good" cards like the ath9k we get a flood of
        // garbage
        //
        // If we WERE going to process them, it would go here, and we'd start looking for 
        // source and dest where we could find them
        commoninfo->type = packet_basic_phy;
    } else if (dot11info->type == packet_data) {
        commoninfo->type = packet_basic_data;

        unsigned int update_flags = 0;

        // Don't create devices from null/qosnull packets, they seem to often be
        // corrupt and produce bogus devices
        if (dot11info->subtype == packet_sub_data_null ||
                dot11info->subtype == packet_sub_data_qos_null) {
            update_flags = UCD_UPDATE_EXISTING_ONLY;
        }

        if (dot11info->bssid_mac != globalreg->empty_mac && 
                !(dot11info->bssid_mac.bitwise_and(globalreg->multicast_mac)) ) {
            bssid_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo, 
                        dot11info->bssid_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                         UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));
        }

        if (dot11info->source_mac != dot11info->bssid_mac &&
                dot11info->source_mac != globalreg->empty_mac && 
                !(dot11info->source_mac.bitwise_and(globalreg->multicast_mac)) ) {
            source_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo, 
                        dot11info->source_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                         UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));
        }

        if (dot11info->dest_mac != dot11info->source_mac &&
                dot11info->dest_mac != dot11info->bssid_mac &&
                dot11info->dest_mac != globalreg->empty_mac && 
                !(dot11info->dest_mac.bitwise_and(globalreg->multicast_mac)) ) {
            // Only update signal and location if we have no other record
            dest_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo,
                        dot11info->dest_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION | 
                         UCD_UPDATE_EMPTY_SIGNAL | UCD_UPDATE_EMPTY_LOCATION));
        }

        if (dot11info->other_mac != dot11info->source_mac &&
                dot11info->other_mac != dot11info->dest_mac &&
                dot11info->other_mac != dot11info->bssid_mac &&
                dot11info->other_mac != globalreg->empty_mac && 
                !(dot11info->other_mac.bitwise_and(globalreg->multicast_mac)) ) {
            other_dev =
                d11phy->devicetracker->UpdateCommonDevice(commoninfo, 
                        dot11info->other_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                         UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));
        }

        if (bssid_dev != NULL) {
            local_locker bssidlocker(&(bssid_dev->device_mutex));

            bssid_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(bssid_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (bssid_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi device " << 
                    bssid_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                bssid_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(bssid_dot11, bssid_dev);

                dot11info->new_device = true;
            }

            if (dot11info->distrib == distrib_adhoc) {
                // Otherwise, we're some sort of adhoc device
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                bssid_dev->set_type_string("Wi-Fi Ad-Hoc");
            } else {
                // If we're the bssid, sending an ess data frame, we must be an access point
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
                bssid_dev->set_type_string("Wi-Fi AP");

                // Throw alert if device changes between bss and adhoc
                if (bssid_dev->bitcheck_basic_type_set(DOT11_DEVICE_TYPE_ADHOC) &&
                        !bssid_dev->bitcheck_basic_type_set(DOT11_DEVICE_TYPE_BEACON_AP) &&
                        d11phy->alertracker->PotentialAlert(d11phy->alert_adhoc_ref)) {
                    std::string al = "IEEE80211 Network BSSID " + 
                        dot11info->bssid_mac.Mac2String() + 
                        " previously advertised as AP network, now advertising as "
                        "Ad-Hoc/WDS which may indicate AP spoofing/impersonation";

                    d11phy->alertracker->RaiseAlert(d11phy->alert_adhoc_ref, in_pack,
                            dot11info->bssid_mac, dot11info->source_mac,
                            dot11info->dest_mac, dot11info->other_mac,
                            dot11info->channel, al);
                }
            }

            bssid_dot11->inc_datasize(dot11info->datasize);

            if (dot11info->fragmented) {
                bssid_dot11->inc_num_fragments(1);
            }

            if (dot11info->retry) {
                bssid_dot11->inc_num_retries(1);
                bssid_dot11->inc_datasize_retry(dot11info->datasize);
            }

        }

        // If we have a source device, we know it's not originating from the same radio as the AP,
        // since source != bssid
        if (source_dev != NULL) {
            local_locker sourcelocker(&(source_dev->device_mutex));

            source_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(source_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (source_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi device " << 
                    source_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                source_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(source_dot11, source_dev);

                dot11info->new_device = true;
            }

            if (dot11info->subtype == packet_sub_data_null ||
                    dot11info->subtype == packet_sub_data_qos_null) {
                // Only wireless devices can send null function data
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);
                source_dev->set_type_string_ifnot("Wi-Fi Client", KIS_DEVICE_BASICTYPE_AP);
            } else if (dot11info->distrib == distrib_inter) {
                // If it's from the ess, we're some sort of wired device; set the type
                // accordingly
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

                source_dev->set_type_string_ifonly("Wi-Fi WDS",
                        KIS_DEVICE_BASICTYPE_PEER | KIS_DEVICE_BASICTYPE_DEVICE);
            } else if (dot11info->distrib == distrib_adhoc && dot11info->ibss) {
                // We're some sort of adhoc device
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                source_dev->set_type_string("Wi-Fi Ad-Hoc");
            } else if (dot11info->distrib == distrib_from) {
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_WIRED);
                source_dev->set_type_string_ifnot("Wi-Fi Bridged",
                        KIS_DEVICE_BASICTYPE_CLIENT | KIS_DEVICE_BASICTYPE_AP);
            } else {
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);

                source_dev->set_type_string_ifnot("Wi-Fi Client",
                        KIS_DEVICE_BASICTYPE_AP);
            }

            source_dot11->inc_datasize(dot11info->datasize);

            if (dot11info->fragmented) {
                source_dot11->inc_num_fragments(1);
            }

            if (dot11info->retry) {
                source_dot11->inc_num_retries(1);
                source_dot11->inc_datasize_retry(dot11info->datasize);
            }

            // Look for WPS floods
            int wps = d11phy->PacketDot11WPSM3(in_pack);

            if (wps) {
                // if we're w/in time of the last one, update, otherwise clear
                if (globalreg->timestamp.tv_sec - source_dot11->get_wps_m3_last() > (60 * 5))
                    source_dot11->set_wps_m3_count(1);
                else
                    source_dot11->inc_wps_m3_count(1);

                source_dot11->set_wps_m3_last(globalreg->timestamp.tv_sec);

                if (source_dot11->get_wps_m3_count() > 5) {
                    if (d11phy->alertracker->PotentialAlert(d11phy->alert_wpsbrute_ref)) {
                        std::string al = "IEEE80211 AP " + dot11info->bssid_mac.Mac2String() +
                            " sending excessive number of WPS messages which may "
                            "indicate a WPS brute force attack such as Reaver";

                        d11phy->alertracker->RaiseAlert(d11phy->alert_wpsbrute_ref, 
                                in_pack, 
                                dot11info->bssid_mac, dot11info->source_mac, 
                                dot11info->dest_mac, dot11info->other_mac, 
                                dot11info->channel, al);
                    }

                    source_dot11->set_wps_m3_count(1);
                }
            }
        }

        if (dest_dev != NULL) {
            local_locker destlocker(&(dest_dev->device_mutex));

            dest_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(dest_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (dest_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi device " << 
                    dest_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                dest_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(dest_dot11, dest_dev);

                dot11info->new_device = true;
            }

            // If it's from the ess, we're some sort of wired device; set the type
            // accordingly
            if (dot11info->distrib == distrib_inter) {
                dest_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

                dest_dev->set_type_string_ifonly("Wi-Fi WDS",
                        KIS_DEVICE_BASICTYPE_PEER | KIS_DEVICE_BASICTYPE_DEVICE);
            } else if (dot11info->distrib == distrib_adhoc) {
                // Otherwise, we're some sort of adhoc device
                dest_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                dest_dev->set_type_string("Wi-Fi Ad-Hoc");
            } else {
                // We can't define the type with only a destination device; we can't
                // call it wired or wireless until it talks itself
                dest_dev->set_type_string_ifonly("Wi-Fi Device", KIS_DEVICE_BASICTYPE_DEVICE);
            }

            dest_dot11->inc_datasize(dot11info->datasize);

            if (dot11info->fragmented) {
                dest_dot11->inc_num_fragments(1);
            }

            if (dot11info->retry) {
                dest_dot11->inc_num_retries(1);
                dest_dot11->inc_datasize_retry(dot11info->datasize);
            }
        }

        if (other_dev != NULL) {
            local_locker otherlocker(&(other_dev->device_mutex));

            other_dot11 =
                std::static_pointer_cast<dot11_tracked_device>(other_dev->get_map_value(d11phy->dot11_device_entry_id));
            std::stringstream newdevstr;

            if (other_dot11 == NULL) {
                newdevstr << "Detected new 802.11 Wi-Fi device " << 
                    other_dev->get_macaddr().Mac2String() << " packet " << packetnum;
                _MSG(newdevstr.str(), MSGFLAG_INFO);

                dest_dot11.reset(new dot11_tracked_device(globalreg, d11phy->dot11_device_entry_id));
                dot11_tracked_device::attach_base_parent(dest_dot11, other_dev);

                dot11info->new_device = true;
            }

            other_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP | KIS_DEVICE_BASICTYPE_PEER);
            other_dev->set_type_string("Wi-Fi WDS AP");

            other_dot11->inc_datasize(dot11info->datasize);

            if (dot11info->fragmented) {
                other_dot11->inc_num_fragments(1);
            }

            if (dot11info->retry) {
                other_dot11->inc_num_retries(1);
                other_dot11->inc_datasize_retry(dot11info->datasize);
            }
        }

        if (bssid_dev != NULL) {
            // Map clients
            if (source_dev != NULL) {
                d11phy->ProcessClient(bssid_dev, bssid_dot11, source_dev, source_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);
                d11phy->ProcessWPAHandshake(bssid_dev, bssid_dot11, source_dev, source_dot11,
                        in_pack, dot11info);
            }

            if (dest_dev != NULL) {
                d11phy->ProcessClient(bssid_dev, bssid_dot11, dest_dev, dest_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);
                d11phy->ProcessWPAHandshake(bssid_dev, bssid_dot11, dest_dev, dest_dot11,
                        in_pack, dot11info);
            }
        }

        if (other_dev != NULL) {
            if (bssid_dev != NULL)
                d11phy->ProcessClient(other_dev, other_dot11, bssid_dev, bssid_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);

            if (source_dev != NULL)
                d11phy->ProcessClient(other_dev, other_dot11, source_dev, source_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);

            if (dest_dev != NULL)
                d11phy->ProcessClient(other_dev, other_dot11, dest_dev, dest_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);
        }
    }


    return 1;
}

void Kis_80211_Phy::SetStringExtract(int in_extr) {
	if (in_extr == 0 && dissect_strings == 2) {
		_MSG("SetStringExtract(): String dissection cannot be disabled because "
			 "it is required by another active component.", MSGFLAG_ERROR);
		return;
	}

	// If we're setting the extract here, we have to turn it on for all BSSIDs
	dissect_strings = in_extr;
	dissect_all_strings = in_extr;
}

void Kis_80211_Phy::AddWepKey(mac_addr bssid, uint8_t *key, unsigned int len, 
							  int temp) {
	if (len > WEPKEY_MAX)
		return;

    dot11_wep_key *winfo = new dot11_wep_key;

	winfo->decrypted = 0;
	winfo->failed = 0;
    winfo->bssid = bssid;
	winfo->fragile = temp;
    winfo->len = len;

    memcpy(winfo->key, key, len);

    // Replace exiting ones
	if (wepkeys.find(winfo->bssid) != wepkeys.end()) {
		delete wepkeys[winfo->bssid];
		wepkeys[winfo->bssid] = winfo;
		return;
	}

	wepkeys.insert(winfo->bssid, winfo);
}

void Kis_80211_Phy::HandleSSID(std::shared_ptr<kis_tracked_device_base> basedev,
        std::shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    SharedTrackerElement adv_ssid_map = dot11dev->get_advertised_ssid_map();

    std::shared_ptr<dot11_advertised_ssid> ssid;

    TrackerElement::map_iterator ssid_itr;

    if (adv_ssid_map == NULL) {
        fprintf(stderr, "debug - dot11phy::HandleSSID can't find the adv_ssid_map or probe_ssid_map struct, something is wrong\n");
        return;
    }

    if (dot11info->subtype != packet_sub_beacon && dot11info->subtype != packet_sub_probe_resp) {
        return;
    }

    // If we've processed an identical ssid, don't waste time parsing again, just tweak
    // the few fields we need to update
    if (dot11dev->get_last_adv_ie_csum() == dot11info->ietag_csum) {
        ssid = dot11dev->get_last_adv_ssid();

        if (ssid != NULL) {
            if (ssid->get_last_time() < in_pack->ts.tv_sec)
                ssid->set_last_time(in_pack->ts.tv_sec);

            if (dot11info->subtype == packet_sub_beacon) {
                ssid->inc_beacons_sec();
            }
        }

        return;
    }

    dot11dev->set_last_adv_ie_csum(dot11info->ietag_csum);

    // If we fail parsing...
    if (PacketDot11IEdissector(in_pack, dot11info) < 0) {
        return;
    }

    if (dot11info->channel != "0")
        basedev->set_channel(dot11info->channel);

    ssid_itr = adv_ssid_map->find((int32_t) dot11info->ssid_csum);

    if (ssid_itr == adv_ssid_map->end()) {
        // fprintf(stderr, "debug - packet %d new ssid - type %d %s\n", packetnum, dot11info->subtype, dot11info->ssid.c_str());
        dot11info->new_adv_ssid = true;
        
        ssid = dot11dev->new_advertised_ssid();
        adv_ssid_map->add_intmap((int32_t) dot11info->ssid_csum, ssid);

        ssid->set_crypt_set(dot11info->cryptset);
        ssid->set_first_time(in_pack->ts.tv_sec);

        // TODO handle loading SSID from the stored file
        ssid->set_ssid(dot11info->ssid);
        if (dot11info->ssid_len == 0 || dot11info->ssid_blank) 
            ssid->set_ssid_cloaked(true);
        ssid->set_ssid_len(dot11info->ssid_len);

        std::string ssidstr;
        if (ssid->get_ssid_cloaked()) {
            ssidstr = "a cloaked SSID";
        } else {
            ssidstr = "SSID '" + ssid->get_ssid() + "'";
        }

        _MSG("802.11 Wi-Fi device " + basedev->get_macaddr().Mac2String() + 
                " advertising " + ssidstr, MSGFLAG_INFO);

        if (alertracker->PotentialAlert(alert_airjackssid_ref) &&
                ssid->get_ssid() == "AirJack" ) {

            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().Mac2String() + " broadcasting SSID "
                "\"AirJack\" which implies an attempt to disrupt "
                "networks.";

            alertracker->RaiseAlert(alert_airjackssid_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }

        if (ssid->get_ssid() != "") {
            basedev->set_devicename(ssid->get_ssid());
        } else {
            basedev->set_devicename(basedev->get_macaddr().Mac2String());
        }

        // If we have a new ssid and we can consider raising an alert, do the 
        // regex compares to see if we trigger apspoof
        if (dot11info->ssid_len != 0 &&
                globalreg->alertracker->PotentialAlert(alert_ssidmatch_ref)) {
            TrackerElementVector sv(ssid_regex_vec);

            for (auto s : sv) {
                std::shared_ptr<dot11_tracked_ssid_alert> sa =
                    std::static_pointer_cast<dot11_tracked_ssid_alert>(s);

                if (sa->compare_ssid(dot11info->ssid, dot11info->source_mac)) {
                    std::string ntype = 
                        dot11info->subtype == packet_sub_beacon ? std::string("advertising") :
                        std::string("responding for");

                    std::string al = "IEEE80211 Unauthorized device (" + 
                        dot11info->source_mac.Mac2String() + std::string(") ") + ntype + 
                        " for SSID '" + dot11info->ssid + "', matching APSPOOF "
                        "rule " + sa->get_group_name() + 
                        std::string(" which may indicate spoofing or impersonation.");

                    globalreg->alertracker->RaiseAlert(alert_ssidmatch_ref, in_pack, 
                            dot11info->bssid_mac, 
                            dot11info->source_mac, 
                            dot11info->dest_mac, 
                            dot11info->other_mac, 
                            dot11info->channel, al);
                    break;
                }
            }
        }
    } else {
        ssid = std::static_pointer_cast<dot11_advertised_ssid>(ssid_itr->second);
        if (ssid->get_last_time() < in_pack->ts.tv_sec)
            ssid->set_last_time(in_pack->ts.tv_sec);
    }

    dot11dev->set_last_adv_ssid(ssid);

    ssid->set_ietag_checksum(dot11info->ietag_csum);

    // Update the base device records
    dot11dev->set_last_beaconed_ssid(ssid->get_ssid());
    dot11dev->set_last_beaconed_ssid_csum(dot11info->ssid_csum);

    if (ssid->get_last_time() < in_pack->ts.tv_sec)
        ssid->set_last_time(in_pack->ts.tv_sec);


    if (dot11info->subtype == packet_sub_beacon) {
        ssid->inc_beacons_sec();

        // Set the type
        ssid->set_ssid_beacon(true);

        // Update beacon info, if any
        if (dot11info->beacon_info.length() > 0) 
            ssid->set_beacon_info(dot11info->beacon_info);

        // Set the mobility
        if (dot11info->dot11r_mobility != NULL) {
            ssid->set_dot11r_mobility(true);
            ssid->set_dot11r_mobility_domain_id(dot11info->dot11r_mobility->mobility_domain());
        }

        // Set QBSS
        if (dot11info->qbss != NULL) {
            ssid->set_dot11e_qbss(true);
            ssid->set_dot11e_qbss_stations(dot11info->qbss->station_count());

            // Percentage is value / max (1 byte, 255)
            double chperc = (double) ((double) dot11info->qbss->channel_utilization() / 
                    (double) 255.0f) * 100.0f;
            ssid->set_dot11e_qbss_channel_load(chperc);
        }

        // Do we have HT or VHT data?  I don't think we can have one
        // without the other
        if (dot11info->dot11vht != NULL && dot11info->dot11ht != NULL) {
            // Grab the primary channel from the HT data
            ssid->set_channel(IntToString(dot11info->dot11ht->primary_channel()));

            if (dot11info->dot11vht->channel_width() == dot11_ie_192_vht_op::ch_80) {
                ssid->set_ht_mode("HT80");
                ssid->set_ht_center_1(5000 + (5 * dot11info->dot11vht->center1()));
                ssid->set_ht_center_2(0);
            } else if (dot11info->dot11vht->channel_width() == dot11_ie_192_vht_op::ch_160) {
                ssid->set_ht_mode("HT160");
                ssid->set_ht_center_1(5000 + (5 * dot11info->dot11vht->center1()));
                ssid->set_ht_center_2(0);
            } else if (dot11info->dot11vht->channel_width() == dot11_ie_192_vht_op::ch_80_80) {
                ssid->set_ht_mode("HT80+80");
                ssid->set_ht_center_1(5000 + (5 * dot11info->dot11vht->center1()));
                ssid->set_ht_center_2(5000 + (5 * dot11info->dot11vht->center2()));
            } else if (dot11info->dot11vht->channel_width() == dot11_ie_192_vht_op::ch_20_40) {
                if (dot11info->dot11ht->ht_info_chan_offset_none()) {
                    ssid->set_ht_mode("HT20");
                } else if (dot11info->dot11ht->ht_info_chan_offset_above()) {
                    ssid->set_ht_mode("HT40+");
                } else if (dot11info->dot11ht->ht_info_chan_offset_below()) {
                    ssid->set_ht_mode("HT40-");
                }

                ssid->set_ht_center_1(0);
                ssid->set_ht_center_2(0);

            } 
        } else if (dot11info->dot11ht != NULL) {
            // Only HT info no VHT
            if (dot11info->dot11ht->ht_info_chan_offset_none()) {
                ssid->set_ht_mode("HT20");
            } else if (dot11info->dot11ht->ht_info_chan_offset_above()) {
                ssid->set_ht_mode("HT40+");
            } else if (dot11info->dot11ht->ht_info_chan_offset_below()) {
                ssid->set_ht_mode("HT40-");
            }

            ssid->set_ht_center_1(0);
            ssid->set_ht_center_2(0);
            ssid->set_channel(IntToString(dot11info->dot11ht->primary_channel()));
        }


    } else if (dot11info->subtype == packet_sub_probe_resp) {
        if (mac_addr((uint8_t *) "\x00\x13\x37\x00\x00\x00", 6, 24) == 
                dot11info->source_mac) {

            if (alertracker->PotentialAlert(alert_l33t_ref)) {
                std::string al = "IEEE80211 probe response from OUI 00:13:37 seen, "
                    "which typically implies a Karma AP impersonation attack.";

                alertracker->RaiseAlert(alert_l33t_ref, in_pack, 
                        dot11info->bssid_mac, dot11info->source_mac, 
                        dot11info->dest_mac, dot11info->other_mac, 
                        dot11info->channel, al);
            }

        }

        ssid->set_ssid_probe_response(true);
    }

    if (ssid->get_crypt_set() != dot11info->cryptset) {
        if (ssid->get_crypt_set() && dot11info->cryptset == crypt_none &&
                alertracker->PotentialAlert(alert_wepflap_ref)) {

            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().Mac2String() + " SSID \"" +
                ssid->get_ssid() + "\" changed advertised encryption from " +
                CryptToString(ssid->get_crypt_set()) + " to Open which may "
                "indicate AP spoofing/impersonation";

            alertracker->RaiseAlert(alert_wepflap_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        } else if (ssid->get_crypt_set() != dot11info->cryptset &&
                alertracker->PotentialAlert(alert_cryptchange_ref)) {

            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().Mac2String() + " SSID \"" +
                ssid->get_ssid() + "\" changed advertised encryption from " +
                CryptToString(ssid->get_crypt_set()) + " to " + 
                CryptToString(dot11info->cryptset) + " which may indicate "
                "AP spoofing/impersonation";

            alertracker->RaiseAlert(alert_cryptchange_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }

        ssid->set_crypt_set(dot11info->cryptset);
    }

    if (ssid->get_channel().length() > 0 &&
            ssid->get_channel() != dot11info->channel && dot11info->channel != "0") {
        std::string al = "IEEE80211 Access Point BSSID " +
            basedev->get_macaddr().Mac2String() + " SSID \"" +
            ssid->get_ssid() + "\" changed advertised channel from " +
            ssid->get_channel() + " to " + 
            dot11info->channel + " which may "
            "indicate AP spoofing/impersonation";

        alertracker->RaiseAlert(alert_chan_ref, in_pack, 
                dot11info->bssid_mac, dot11info->source_mac, 
                dot11info->dest_mac, dot11info->other_mac, 
                dot11info->channel, al);

        ssid->set_channel(dot11info->channel); 
    }

    // Only process dot11 from beacons
    if (dot11info->subtype == packet_sub_beacon) {
        bool dot11dmismatch = false;

        if (ssid->get_dot11d_country().length() > 0 &&
                ssid->get_dot11d_country() != dot11info->dot11d_country) {
            dot11dmismatch = true;
        }

        TrackerElementVector dot11dvec(ssid->get_dot11d_vec());
        for (unsigned int vc = 0; 
                vc < dot11dvec.size() && vc < dot11info->dot11d_vec.size(); vc++) {
            std::shared_ptr<dot11_11d_tracked_range_info> ri =
                std::static_pointer_cast<dot11_11d_tracked_range_info>(dot11dvec[vc]);

            if (ri->get_startchan() != dot11info->dot11d_vec[vc].startchan ||
                    ri->get_numchan() != dot11info->dot11d_vec[vc].numchan ||
                    ri->get_txpower() != dot11info->dot11d_vec[vc].txpower) {
                dot11dmismatch = true;
                break;
            }

        }

        if (dot11dmismatch) {
            if (alertracker->PotentialAlert(alert_dot11d_ref)) {

                std::string al = "IEEE80211 Access Point BSSID " +
                    basedev->get_macaddr().Mac2String() + " SSID \"" +
                    ssid->get_ssid() + "\" advertised conflicting 802.11d "
                    "information which may indicate AP spoofing/impersonation";

                alertracker->RaiseAlert(alert_dot11d_ref, in_pack, 
                        dot11info->bssid_mac, dot11info->source_mac, 
                        dot11info->dest_mac, dot11info->other_mac, 
                        dot11info->channel, al);

            }
        }

        ssid->set_dot11d_country(dot11info->dot11d_country);
        ssid->set_dot11d_vec(dot11info->dot11d_vec);

    }

    ssid->set_wps_state(dot11info->wps);
    if (dot11info->wps_manuf != "")
        ssid->set_wps_manuf(dot11info->wps_manuf);
    if (dot11info->wps_model_name != "") {
        ssid->set_wps_model_name(dot11info->wps_model_name);
    }
    if (dot11info->wps_model_number != "") 
        ssid->set_wps_model_number(dot11info->wps_model_number);
    if (dot11info->wps_serial_number != "")
        ssid->set_wps_serial_number(dot11info->wps_serial_number);

    // Do we not know the basedev manuf?
    if (basedev->get_manuf() == "" && dot11info->wps_manuf != "")
        basedev->set_manuf(dot11info->wps_manuf);

    if (dot11info->beacon_interval && ssid->get_beaconrate() != 
            Ieee80211Interval2NSecs(dot11info->beacon_interval)) {

        if (ssid->get_beaconrate() != 0 && 
                alertracker->PotentialAlert(alert_beaconrate_ref)) {
            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().Mac2String() + " SSID \"" +
                ssid->get_ssid() + "\" changed beacon rate from " +
                IntToString(ssid->get_beaconrate()) + " to " + 
                IntToString(Ieee80211Interval2NSecs(dot11info->beacon_interval)) + 
                " which may indicate AP spoofing/impersonation";

            alertracker->RaiseAlert(alert_beaconrate_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }

        ssid->set_beaconrate(Ieee80211Interval2NSecs(dot11info->beacon_interval));
    }

    ssid->set_maxrate(dot11info->maxrate);

    // Add the location data, if any
    if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
        ssid->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);

    }

}

void Kis_80211_Phy::HandleProbedSSID(std::shared_ptr<kis_tracked_device_base> basedev,
        std::shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    TrackerElementIntMap probemap(dot11dev->get_probed_ssid_map());

    std::shared_ptr<dot11_probed_ssid> probessid = NULL;
    TrackerElement::int_map_iterator ssid_itr;

    // Always re-parse the IEs on a probe
    if (PacketDot11IEdissector(in_pack, dot11info) < 0) {
        return;
    }

    if (dot11info->subtype == packet_sub_probe_req ||
            dot11info->subtype == packet_sub_reassociation_req) {

        ssid_itr = probemap.find(dot11info->ssid_csum);

        if (ssid_itr == probemap.end() || ssid_itr->second == NULL) {
            probessid = dot11dev->new_probed_ssid();
            TrackerElement::int_map_pair p(dot11info->ssid_csum, probessid);
            probemap.insert(p);

            probessid->set_ssid(dot11info->ssid);
            probessid->set_ssid_len(dot11info->ssid_len);
            probessid->set_first_time(in_pack->ts.tv_sec);
        } else {
            probessid = std::static_pointer_cast<dot11_probed_ssid>(ssid_itr->second);
        }

        if (probessid->get_last_time() < in_pack->ts.tv_sec)
            probessid->set_last_time(in_pack->ts.tv_sec);

        // Add the location data, if any
        if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
            probessid->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                    pack_gpsinfo->alt, pack_gpsinfo->fix);

        }

        if (dot11info->dot11r_mobility != NULL) {
            probessid->set_dot11r_mobility(true);
            probessid->set_dot11r_mobility_domain_id(dot11info->dot11r_mobility->mobility_domain());
        }

        dot11dev->set_last_probed_ssid(probessid->get_ssid());
        dot11dev->set_last_probed_ssid_csum(dot11info->ssid_csum);
    }

}

// Associate a client device and a dot11 access point
void Kis_80211_Phy::ProcessClient(std::shared_ptr<kis_tracked_device_base> bssiddev,
        std::shared_ptr<dot11_tracked_device> bssiddot11,
        std::shared_ptr<kis_tracked_device_base> clientdev,
        std::shared_ptr<dot11_tracked_device> clientdot11,
        kis_packet *in_pack, 
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo,
        kis_data_packinfo *pack_datainfo) {

    local_locker bssidlock(&(bssiddev->device_mutex));
    local_locker clientlock(&(clientdev->device_mutex));

    // Create and map the client behavior record for this BSSID
    TrackerElementMacMap client_map(clientdot11->get_client_map());
    std::shared_ptr<dot11_client> client_record;

    auto cmi = client_map.find(bssiddev->get_macaddr());
    bool new_client_record = false;

    if (cmi == client_map.end()) {
        client_record = clientdot11->new_client();
        TrackerElement::mac_map_pair cp(bssiddev->get_macaddr(), client_record);
        client_map.insert(cp);
        new_client_record = true;
    } else {
        client_record = 
            std::static_pointer_cast<dot11_client>(cmi->second);
    }

    if (new_client_record) {
        client_record->set_bssid(bssiddev->get_macaddr());
        client_record->set_first_time(in_pack->ts.tv_sec);
    }

    if (client_record->get_last_time() < in_pack->ts.tv_sec) {
        client_record->set_last_time(in_pack->ts.tv_sec);
    }

    // Handle the data records for this client association, we're not just a 
    // management link
    if (dot11info->type == packet_data) {
        if (dot11info->fragmented)
            client_record->inc_num_fragments(1);

        if (dot11info->retry) {
            client_record->inc_num_retries(1);
            client_record->inc_datasize_retry(dot11info->datasize);
        }

        if (pack_datainfo != NULL && pack_datainfo->proto == proto_eap) {
            if (pack_datainfo->auxstring != "") {
                client_record->set_eap_identity(pack_datainfo->auxstring);
            }

            if (pack_datainfo->discover_vendor != "") {
                if (client_record->get_dhcp_vendor() != "" &&
                        client_record->get_dhcp_vendor() != pack_datainfo->discover_vendor &&
                        alertracker->PotentialAlert(alert_dhcpos_ref)) {
                    std::string al = "IEEE80211 network BSSID " + 
                        client_record->get_bssid().Mac2String() +
                        " client " + 
                        clientdev->get_macaddr().Mac2String() + 
                        "changed advertised DHCP vendor from '" +
                        client_record->get_dhcp_vendor() + "' to '" +
                        pack_datainfo->discover_vendor + "' which may indicate "
                        "client spoofing or impersonation";

                    alertracker->RaiseAlert(alert_dhcpos_ref, in_pack,
                            dot11info->bssid_mac, dot11info->source_mac,
                            dot11info->dest_mac, dot11info->other_mac,
                            dot11info->channel, al);
                }

                client_record->set_dhcp_vendor(pack_datainfo->discover_vendor);
            }

            if (pack_datainfo->discover_host != "") {
                if (client_record->get_dhcp_host() != "" &&
                        client_record->get_dhcp_host() != pack_datainfo->discover_host &&
                        alertracker->PotentialAlert(alert_dhcpname_ref)) {
						std::string al = "IEEE80211 network BSSID " + 
							client_record->get_bssid().Mac2String() +
							" client " + 
							clientdev->get_macaddr().Mac2String() + 
							"changed advertised DHCP hostname from '" +
							client_record->get_dhcp_host() + "' to '" +
							pack_datainfo->discover_host + "' which may indicate "
							"client spoofing or impersonation";

                        alertracker->RaiseAlert(alert_dhcpname_ref, in_pack,
                                dot11info->bssid_mac, dot11info->source_mac,
                                dot11info->dest_mac, dot11info->other_mac,
                                dot11info->channel, al);
                }

                client_record->set_dhcp_host(pack_datainfo->discover_host);
            }

            if (pack_datainfo->cdp_dev_id != "") {
                client_record->set_cdp_device(pack_datainfo->cdp_dev_id);
            }

            if (pack_datainfo->cdp_port_id != "") {
                client_record->set_cdp_port(pack_datainfo->cdp_port_id);
            }
        }

    }

    // Update the GPS info
    if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
        client_record->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);
    }

    // Update the forward map to the bssid
    client_record->set_bssid_key(bssiddev->get_key());

    // Update the backwards map to the client
    if (bssiddot11->get_associated_client_map()->mac_find(clientdev->get_macaddr()) ==
            bssiddot11->get_associated_client_map()->mac_end()) {
        bssiddot11->get_associated_client_map()->add_macmap(clientdev->get_macaddr(),
                clientdev->get_tracker_key());
    }
}

void Kis_80211_Phy::ProcessWPAHandshake(std::shared_ptr<kis_tracked_device_base> bssid_dev,
        std::shared_ptr<dot11_tracked_device> bssid_dot11,
        std::shared_ptr<kis_tracked_device_base> dest_dev,
        std::shared_ptr<dot11_tracked_device> dest_dot11,
        kis_packet *in_pack,
        dot11_packinfo *dot11info) {

    std::shared_ptr<dot11_tracked_eapol> eapol = PacketDot11EapolHandshake(in_pack, bssid_dot11);

    if (eapol == NULL)
        return;

    local_locker bssid_locker(&(bssid_dev->device_mutex));
    local_locker dest_locker(&(dest_dev->device_mutex));

    TrackerElementVector bssid_vec(bssid_dot11->get_wpa_key_vec());

    // Start doing something smart here about eliminating
    // records - we want to do our best to keep a 1, 2, 3, 4
    // handshake sequence, so find out what duplicates we have
    // and eliminate the oldest one of them if we need to
    uint8_t keymask = 0;

    if (bssid_vec.size() > 16) {
        for (TrackerElementVector::iterator kvi = bssid_vec.begin();
                kvi != bssid_vec.end(); ++kvi) {
            std::shared_ptr<dot11_tracked_eapol> ke = std::static_pointer_cast<dot11_tracked_eapol>(*kvi);

            uint8_t knum = (1 << ke->get_eapol_msg_num());

            // If this is a duplicate handshake number, we can get
            // rid of this one
            if ((keymask & knum) == knum) {
                bssid_vec.erase(kvi);
                break;
            }

            // Otherwise put this key in the keymask
            keymask |= knum;
        }
    }

    bssid_vec.push_back(eapol);

    // Calculate the key mask of seen handshake keys
    keymask = 0;
    for (TrackerElementVector::iterator kvi = bssid_vec.begin(); kvi != bssid_vec.end(); ++kvi) {
        std::shared_ptr<dot11_tracked_eapol> ke =
            std::static_pointer_cast<dot11_tracked_eapol>(*kvi);

        keymask |= (1 << ke->get_eapol_msg_num());
    }
    bssid_dot11->set_wpa_present_handshake(keymask);

    // Look for replays against the target (which might be the bssid, or might
    // be a client, depending on the direction); we track the EAPOL records per
    // destination in the destination device record
    bool dupe_nonce = false;
    bool new_nonce = true;

    // Look for replay attacks; only compare non-zero nonces
    if (eapol->get_eapol_msg_num() == 3 &&
            eapol->get_eapol_nonce().find_first_not_of(std::string("\x00", 1)) != std::string::npos) {
        TrackerElementVector ev(dest_dot11->get_wpa_nonce_vec());
        dupe_nonce = false;
        new_nonce = true;

        for (auto i : ev) {
            std::shared_ptr<dot11_tracked_nonce> nonce =
                std::static_pointer_cast<dot11_tracked_nonce>(i);

            // If the nonce strings match
            if (nonce->get_eapol_nonce() == eapol->get_eapol_nonce()) {
                new_nonce = false;

                if (eapol->get_eapol_replay_counter() <=
                        nonce->get_eapol_replay_counter()) {

                    // Is it an earlier (or equal) replay counter? Then we
                    // have a problem; inspect the timestamp
                    double tdif = 
                        eapol->get_eapol_time() - 
                        nonce->get_eapol_time();

                    // Retries should fall w/in this range 
                    if (tdif > 1.0f || tdif < -1.0f)
                        dupe_nonce = true;
                } else {
                    // Otherwise increment the replay counter we record
                    // for this nonce
                    nonce->set_eapol_replay_counter(eapol->get_eapol_replay_counter());
                }
                break;
            }
        }

        if (!dupe_nonce) {
            if (new_nonce) {
                std::shared_ptr<dot11_tracked_nonce> n = 
                    dest_dot11->create_tracked_nonce();

                n->set_from_eapol(eapol);

                // Limit the size of stored nonces
                if (ev.size() > 128)
                    ev.erase(ev.begin());

                ev.push_back(n);
            }
        } else {
            std::stringstream ss;
            std::string nonce = eapol->get_eapol_nonce();

            for (size_t b = 0; b < nonce.length(); b++) {
                ss << std::uppercase << std::setfill('0') << std::setw(2) <<
                    std::hex << (int) (nonce[b] & 0xFF);
            }

            alertracker->RaiseAlert(alert_nonce_duplicate_ref, in_pack,
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac,
                    dot11info->channel,
                    "WPA EAPOL RSN frame seen with a previously used nonce; "
                    "this may indicate a KRACK-style WPA attack (nonce: " + 
                    ss.str() + ")");
        }
    } else if (eapol->get_eapol_msg_num() == 1 &&
            eapol->get_eapol_nonce().find_first_not_of(std::string("\x00", 1)) != std::string::npos) {
        // Don't compare zero nonces
        TrackerElementVector eav(dest_dot11->get_wpa_anonce_vec());
        dupe_nonce = false;
        new_nonce = true;

        for (auto i : eav) {
            std::shared_ptr<dot11_tracked_nonce> nonce =
                std::static_pointer_cast<dot11_tracked_nonce>(i);

            // If the nonce strings match
            if (nonce->get_eapol_nonce() == eapol->get_eapol_nonce()) {
                new_nonce = false;

                if (eapol->get_eapol_replay_counter() <=
                        nonce->get_eapol_replay_counter()) {
                    // Is it an earlier (or equal) replay counter? Then we
                    // have a problem; inspect the retry and timestamp
                    if (dot11info->retry) {
                        double tdif = 
                            eapol->get_eapol_time() - 
                            nonce->get_eapol_time();

                        // Retries should fall w/in this range 
                        if (tdif > 1.0f || tdif < -1.0f)
                            dupe_nonce = true;
                    } else {
                        // Otherwise duplicate w/ out retry is immediately bad
                        dupe_nonce = true;
                    }
                } else {
                    // Otherwise increment the replay counter
                    nonce->set_eapol_replay_counter(eapol->get_eapol_replay_counter());
                }
                break;
            }
        }

        if (!dupe_nonce) {
            if (new_nonce) {
                std::shared_ptr<dot11_tracked_nonce> n = 
                    dest_dot11->create_tracked_nonce();

                n->set_from_eapol(eapol);

                // Limit the size of stored nonces
                if (eav.size() > 128)
                    eav.erase(eav.begin());

                eav.push_back(n);
            }
        } else {
            std::stringstream ss;
            std::string nonce = eapol->get_eapol_nonce();

            for (size_t b = 0; b < nonce.length(); b++) {
                ss << std::uppercase << std::setfill('0') << std::setw(2) <<
                    std::hex << (int) (nonce[b] & 0xFF);
            }

            alertracker->RaiseAlert(alert_nonce_duplicate_ref, in_pack,
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac,
                    dot11info->channel,
                    "WPA EAPOL RSN frame seen with a previously used anonce; "
                    "this may indicate a KRACK-style WPA attack (anonce: " +
                    ss.str() + ")");
        }
    }
}

std::string Kis_80211_Phy::CryptToString(uint64_t cryptset) {
	std::string ret;

	if (cryptset == crypt_none)
		return "none";

	if (cryptset == crypt_unknown)
		return "unknown";

	if (cryptset & crypt_wps)
		ret = "WPS";

	if ((cryptset & crypt_protectmask) == crypt_wep)
		return StringAppend(ret, "WEP");

	if (cryptset & crypt_wpa)
		ret = StringAppend(ret, "WPA");

	if (cryptset & crypt_psk)
		ret = StringAppend(ret, "WPA-PSK");

	if (cryptset & crypt_eap)
		ret = StringAppend(ret, "EAP");

	if (cryptset & crypt_peap)
		ret = StringAppend(ret, "WPA-PEAP");
	if (cryptset & crypt_leap)
		ret = StringAppend(ret, "WPA-LEAP");
	if (cryptset & crypt_ttls)
		ret = StringAppend(ret, "WPA-TTLS");
	if (cryptset & crypt_tls)
		ret = StringAppend(ret, "WPA-TLS");

	if (cryptset & crypt_wpa_migmode)
		ret = StringAppend(ret, "WPA-MIGRATION");

	if (cryptset & crypt_wep40)
		ret = StringAppend(ret, "WEP40");
	if (cryptset & crypt_wep104)
		ret = StringAppend(ret, "WEP104");
	if (cryptset & crypt_tkip)
		ret = StringAppend(ret, "TKIP");
	if (cryptset & crypt_aes_ocb)
		ret = StringAppend(ret, "AES-OCB");
	if (cryptset & crypt_aes_ccm)
		ret = StringAppend(ret, "AES-CCMP");

	if (cryptset & crypt_layer3)
		ret = StringAppend(ret, "Layer 3");

	if (cryptset & crypt_isakmp)
		ret = StringAppend(ret, "ISA KMP");

	if (cryptset & crypt_pptp)
		ret = StringAppend(ret, "PPTP");

	if (cryptset & crypt_fortress)
		ret = StringAppend(ret, "Fortress");

	if (cryptset & crypt_keyguard)
		ret = StringAppend(ret, "Keyguard");

	if (cryptset & crypt_unknown_protected)
		ret = StringAppend(ret, "L3/Unknown");

	if (cryptset & crypt_unknown_nonwep)
		ret = StringAppend(ret, "Non-WEP/Unknown");

	return ret;
}


bool Kis_80211_Phy::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        std::vector<std::string> tokenurl = StrTokenize(path, "/");

        // we care about
        // /phy/phy80211/by-key/[key]/pcap/[mac]-handshake.pcap
        if (tokenurl.size() < 7)
            return false;

        if (tokenurl[1] != "phy")
            return false;

        if (tokenurl[2] != "phy80211")
            return false;

        if (tokenurl[3] != "by-key")
            return false;

        TrackedDeviceKey key(tokenurl[4]);
        if (key.get_error())
            return false;

        if (tokenurl[5] != "pcap")
            return false;

        // Valid requested file?
        if (tokenurl[6] != tokenurl[4] + "-handshake.pcap")
            return false;

        // Does it exist?
        if (devicetracker->FetchDevice(key) != NULL)
            return true;
    }

    return false;
}

void Kis_80211_Phy::GenerateHandshakePcap(std::shared_ptr<kis_tracked_device_base> dev, 
        Kis_Net_Httpd_Connection *connection, std::stringstream &stream) {
    // We need to make a temp file and then use that to make the pcap log
    int pcapfd, readfd;
    FILE *pcapw;

    pcap_t *pcaplogger;
    pcap_dumper_t *dumper;

    // Packet header
    struct pcap_pkthdr hdr;

    // Temp file name
    char tmpfname[PATH_MAX];

    snprintf(tmpfname, PATH_MAX, "/tmp/kismet_wpa_handshake_XXXXXX");

    // Can't do anything if we fail to make a pipe
    if ((pcapfd = mkstemp(tmpfname)) < 0) {
        _MSG("Failed to create a temporary handshake pcap file: " +
                kis_strerror_r(errno), MSGFLAG_ERROR);
        return;
    }

    // Open the tmp file
    readfd = open(tmpfname, O_RDONLY);
    // Immediately unlink it
    unlink(tmpfname);

    if ((pcapw = fdopen(pcapfd, "wb")) == NULL) {
        _MSG("Failed to open temp file for handshake pcap file: " +
                kis_strerror_r(errno), MSGFLAG_ERROR);
        close(readfd);
        return;
    }

    // We always open as 802.11 DLT because that's how we save the handshakes
    pcaplogger = pcap_open_dead(KDLT_IEEE802_11, 2000);
    dumper = pcap_dump_fopen(pcaplogger, pcapw);

    if (dev != NULL) {
        std::shared_ptr<dot11_tracked_device> dot11dev =
            std::static_pointer_cast<dot11_tracked_device>(dev->get_map_value(dot11_device_entry_id));

        if (dot11dev != NULL) {
            // Make a filename
            std::string dmac = dev->get_macaddr().Mac2String();
            std::replace(dmac.begin(), dmac.end(), ':', '-');

            std::string ssid = "";

            if (dot11dev->get_last_beaconed_ssid().length() != 0) 
                ssid = " " + dot11dev->get_last_beaconed_ssid();

            connection->optional_filename = "handshake " + dmac + ssid + ".pcap";

            TrackerElementVector hsvec(dot11dev->get_wpa_key_vec());

            for (TrackerElementVector::iterator i = hsvec.begin(); 
                    i != hsvec.end(); ++i) {
                std::shared_ptr<dot11_tracked_eapol> eapol = 
                    std::static_pointer_cast<dot11_tracked_eapol>(*i);

                std::shared_ptr<kis_tracked_packet> packet = eapol->get_eapol_packet();

                // Make a pcap header
                hdr.ts.tv_sec = packet->get_ts_sec();
                hdr.ts.tv_usec = packet->get_ts_usec();
                
                hdr.len = packet->get_data()->get_bytearray_size();
                hdr.caplen = hdr.len;

                // Dump the raw data
                pcap_dump((u_char *) dumper, &hdr, 
                        packet->get_data()->get_bytearray().get());
            }

        }

    }

    // Close the dumper
    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);

    // Read our buffered stuff out into the stream
    char buf[128];
    ssize_t len;
    int total = 0;

    while ((len = read(readfd, buf, 128)) >= 0) {
        if (len == 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
                continue;
            break;
        }

        total += len;

        stream.write(buf, len);
    }

    // Pcapw and write pipe is already closed so just close read descriptor
    close(readfd);
}

void Kis_80211_Phy::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    std::vector<std::string> tokenurl = StrTokenize(url, "/");

    // /phy/phy80211/by-key/[key]/pcap/[mac]-handshake.pcap
    if (tokenurl.size() < 7)
        return;

    if (tokenurl[1] != "phy")
        return;

    if (tokenurl[2] != "phy80211")
        return;

    if (tokenurl[3] != "by-key")
        return;

    TrackedDeviceKey key(tokenurl[4]);
    if (key.get_error()) {
        stream << "invalid mac";
        return;
    }

    if (tokenurl[5] != "pcap")
        return;

    // Valid requested file?
    if (tokenurl[6] != tokenurl[4] + "-handshake.pcap") {
        stream << "invalid file";
        return;
    }

    // Does it exist?
    auto dev = devicetracker->FetchDevice(key);

    if (dev == NULL) {
        stream << "unknown device";
        return;
    }

    // Validate the session and return a basic auth prompt
    if (httpd->HasValidSession(connection, true)) {
        // It should exist and we'll handle if it doesn't in the stream
        // handler
        local_locker devlocker(&(dev->device_mutex));
        GenerateHandshakePcap(devicetracker->FetchDevice(key), connection, stream);
    } else {
        stream << "Login required";
        return;
    }

    return;
}

int Kis_80211_Phy::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    bool handled = false;

    std::string stripped = Httpd_StripSuffix(concls->url);

    // If we didn't handle it and got here, we don't know what it is, throw an
    // error.
    if (!handled) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
    } else {
        // Return a generic OK.  msgpack returns shouldn't get to here.
        concls->response_stream << "OK";
    }

    return 1;
}

class phy80211_devicetracker_expire_worker : public DevicetrackerFilterWorker {
public:
    phy80211_devicetracker_expire_worker(GlobalRegistry *in_globalreg, 
            int in_timeout, unsigned int in_packets, int entry_id) {
        globalreg = in_globalreg;
        dot11_device_entry_id = entry_id;
        timeout = in_timeout;
        packets = in_packets;
    }

    virtual ~phy80211_devicetracker_expire_worker() { }

    virtual bool MatchDevice(Devicetracker *devicetracker, std::shared_ptr<kis_tracked_device_base> device) {
        std::shared_ptr<dot11_tracked_device> dot11dev =
            std::static_pointer_cast<dot11_tracked_device>(device->get_map_value(dot11_device_entry_id));

        // Not 802.11?  nothing we can do
        if (dot11dev == NULL) {
            return false;
        }

        // Iterate over all the SSID records
        TrackerElementIntMap adv_ssid_map(dot11dev->get_advertised_ssid_map());
        std::shared_ptr<dot11_advertised_ssid> ssid = NULL;
        TrackerElementIntMap::iterator int_itr;

        for (int_itr = adv_ssid_map.begin(); int_itr != adv_ssid_map.end(); ++int_itr) {
            // Always leave one
            if (adv_ssid_map.size() <= 1)
                break;

            ssid = std::static_pointer_cast<dot11_advertised_ssid>(int_itr->second);

            if (globalreg->timestamp.tv_sec - ssid->get_last_time() > timeout &&
                    device->get_packets() < packets) {
                if (dot11dev->get_last_adv_ssid() == ssid) {
                    dot11dev->set_last_adv_ssid(NULL);
                    dot11dev->set_last_adv_ie_csum(0);
                }

                adv_ssid_map.erase(int_itr);
                int_itr = adv_ssid_map.begin();
                devicetracker->UpdateFullRefresh();
            }
        }

        TrackerElementIntMap probe_map(dot11dev->get_probed_ssid_map());
        std::shared_ptr<dot11_probed_ssid> pssid = NULL;

        for (int_itr = probe_map.begin(); int_itr != probe_map.end(); ++int_itr) {
            // Always leave one
            if (probe_map.size() <= 1)
                break;

            pssid = std::static_pointer_cast<dot11_probed_ssid>(int_itr->second);

            if (globalreg->timestamp.tv_sec - pssid->get_last_time() > timeout &&
                    device->get_packets() < packets) {
                probe_map.erase(int_itr);
                int_itr = probe_map.begin();
                devicetracker->UpdateFullRefresh();
            }
        }

        TrackerElementMacMap client_map(dot11dev->get_client_map());
        std::shared_ptr<dot11_client> client = NULL;
        TrackerElementMacMap::iterator mac_itr;

        for (mac_itr = client_map.begin(); mac_itr != client_map.end(); ++mac_itr) {
            // Always leave one
            if (client_map.size() <= 1)
                break;

            client = std::static_pointer_cast<dot11_client>(mac_itr->second);

            if (globalreg->timestamp.tv_sec - client->get_last_time() > timeout &&
                    device->get_packets() < packets) {
                client_map.erase(mac_itr);
                mac_itr = client_map.begin();
                devicetracker->UpdateFullRefresh();
            }
        }

        return false;
    }

protected:
    GlobalRegistry *globalreg;
    int dot11_device_entry_id;
    int timeout;
    unsigned int packets;
};

int Kis_80211_Phy::timetracker_event(int eventid) {
    // Spawn a worker to handle this
    if (eventid == device_idle_timer) {
        phy80211_devicetracker_expire_worker worker(globalreg,
                device_idle_expiration, device_idle_min_packets, dot11_device_entry_id);
        devicetracker->MatchOnDevices(&worker);
    }

    // Loop
    return 1;
}

void Kis_80211_Phy::LoadPhyStorage(SharedTrackerElement in_storage,
        SharedTrackerElement in_device) {
    if (in_storage == NULL || in_device == NULL)
        return;

    // Does the imported record have dot11?
    auto d11devi = in_storage->find(dot11_device_entry_id);

    // Adopt it into a dot11
    if (d11devi != in_storage->end()) {
        std::shared_ptr<dot11_tracked_device> d11dev(new dot11_tracked_device(globalreg, dot11_device_entry_id, d11devi->second));
        in_device->add_map(d11dev);
    }
}

