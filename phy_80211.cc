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

// Convert the beacon interval to # of packets per second
unsigned int Ieee80211Interval2NSecs(int in_interval) {
	double interval_per_sec;

	interval_per_sec = (double) in_interval * 1024 / 1000000;
	
	return (unsigned int) ceil(1.0f / interval_per_sec);
}

void dot11_tracked_eapol::register_fields() {
    tracker_component::register_fields();

    eapol_time_id = 
        RegisterField("dot11.eapol.timestamp", TrackerUInt64, 
                "packet timestamp (second)", &eapol_time);
    
    eapol_dir_id =
        RegisterField("dot11.eapol.direction", TrackerUInt8,
                "packet direction (fromds/tods)", &eapol_dir);

    eapol_msg_num_id =
        RegisterField("dot11.eapol.message_num", TrackerUInt8,
                "handshake message number", &eapol_msg_num);

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

int phydot11_packethook_wep(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketWepDecryptor(in_pack);
}

int phydot11_packethook_dot11(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->PacketDot11dissector(in_pack);
}

int phydot11_packethook_dot11tracker(CHAINCALL_PARMS) {
	return ((Kis_80211_Phy *) auxdata)->TrackerDot11(in_pack);
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

	phyname = "IEEE802.11";

    shared_ptr<dot11_tracked_device> dot11_builder(new dot11_tracked_device(globalreg, 0));
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
#if 0
	packetchain->RegisterHandler(&phydot11_packethook_dot11data, this,
            CHAINPOS_DATADISSECT, -100);
	packetchain->RegisterHandler(&phydot11_packethook_dot11string, this,
            CHAINPOS_DATADISSECT, -99);
#endif

	packetchain->RegisterHandler(&phydot11_packethook_dot11tracker, this,
											CHAINPOS_TRACKER, 100);

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
	vector<string> filterlines = 
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
        stringstream ss;
        ss << "Removing dot11 device info which has been inactive for "
            "more than " << device_idle_expiration << " seconds.";
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
	globalreg->InsertGlobal("SSID_CONF_FILE", shared_ptr<ConfigFile>(ssid_conf));

    httpd_pcap.reset(new Phy_80211_Httpd_Pcap(globalreg));

    // Register js module for UI
    shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchGlobalAs<Kis_Httpd_Registry>(globalreg, "WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_dot11", 
            "/js/kismet.ui.dot11.js");

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

	packetchain->RemoveHandler(&phydot11_packethook_dot11tracker, 
            CHAINPOS_TRACKER);

    timetracker->RemoveTimer(device_idle_timer);
}

int Kis_80211_Phy::LoadWepkeys() {
    // Convert the WEP mappings to our real map
    vector<string> raw_wepmap_vec;
    raw_wepmap_vec = globalreg->kismet_config->FetchOptVec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == string::npos) {
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

        string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

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

// Classifier is responsible for processing a dot11 packet and filling in enough
// of the common info for the system to make a device out of it.
int Kis_80211_Phy::CommonClassifierDot11(CHAINCALL_PARMS) {
    Kis_80211_Phy *d11phy = (Kis_80211_Phy *) auxdata;

    // Get the 802.11 info
    dot11_packinfo *dot11info = 
        (dot11_packinfo *) in_pack->fetch(d11phy->pack_comp_80211);

	kis_layer1_packinfo *pack_l1info =
		(kis_layer1_packinfo *) in_pack->fetch(d11phy->pack_comp_l1info);

    if (dot11info == NULL)
        return 0;

    if (pack_l1info != NULL && pack_l1info->signal_dbm > d11phy->signal_too_loud_threshold
            && pack_l1info->signal_dbm < 0 && 
            d11phy->alertracker->PotentialAlert(d11phy->alert_tooloud_ref)) {

        stringstream ss;

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

    // Get the checksum info
    kis_packet_checksum *fcs =
        (kis_packet_checksum *) in_pack->fetch(d11phy->pack_comp_checksum);

    // We don't do anything if the packet is invalid;  in the future we might want
    // to try to attach it to an existing network if we can understand that much
    // of the frame and then treat it as an error, but that artificially inflates 
    // the error condition on a network when FCS errors are pretty normal.
    // By never creating a common info record we should prevent any handling of this
    // nonsense.
    if (fcs != NULL && fcs->checksum_valid == 0) {
        return 0;
    }

    kis_common_info *ci = 
        (kis_common_info *) in_pack->fetch(d11phy->pack_comp_common);

    if (ci == NULL) {
        ci = new kis_common_info;
        in_pack->insert(d11phy->pack_comp_common, ci);
    } 

    ci->phyid = d11phy->phyid;

    if (dot11info->type == packet_management) {
        ci->type = packet_basic_mgmt;

        // We track devices/nets/clients by source mac, bssid if source
        // is impossible
        if (dot11info->source_mac == globalreg->empty_mac) {
            if (dot11info->bssid_mac == globalreg->empty_mac) {
                fprintf(stderr, "debug - dot11info bssid and src are empty and mgmt\n");
                ci->error = 1;
            }

            ci->device = dot11info->bssid_mac;
        } else {
            ci->device = dot11info->source_mac;
        }

        ci->source = dot11info->source_mac;

        ci->dest = dot11info->dest_mac;

        ci->transmitter = dot11info->bssid_mac;
    } else if (dot11info->type == packet_phy) {
        if (dot11info->subtype == packet_sub_ack || dot11info->subtype == packet_sub_cts) {
            // map some phys as a device since we know they're being talked to
            ci->device = dot11info->dest_mac;
        } else if (dot11info->source_mac == globalreg->empty_mac) {
            ci->error = 1;
        } else {
            ci->device = dot11info->source_mac;
        }

        ci->type = packet_basic_phy;

        ci->transmitter = ci->device;

    } else if (dot11info->type == packet_data) {
        // Data packets come from the source address.  Wired devices bridged
        // from an AP are considered wired clients of that AP and classified as
        // clients normally
        ci->type = packet_basic_data;

        ci->device = dot11info->source_mac;
        ci->source = dot11info->source_mac;

        ci->dest = dot11info->dest_mac;

        ci->transmitter = dot11info->bssid_mac;

        // Something is broken with the data frame
        if (dot11info->bssid_mac == globalreg->empty_mac ||
                dot11info->source_mac == globalreg->empty_mac ||
                dot11info->dest_mac == globalreg->empty_mac) {
            fprintf(stderr, "debug - dot11info macs are empty and data\n");
            ci->error = 1;
        }
    } 

    if (dot11info->type == packet_noise || dot11info->corrupt ||
            in_pack->error || dot11info->type == packet_unknown ||
            dot11info->subtype == packet_sub_unknown) {
        fprintf(stderr, "debug - noise, corrupt, error, etc %d %d %d %d %d\n", dot11info->type == packet_noise, dot11info->corrupt, in_pack->error, dot11info->type == packet_unknown, dot11info->subtype == packet_sub_unknown);
        ci->error = 1;
    }

    ci->channel = dot11info->channel;

    ci->datasize = dot11info->datasize;

    if (dot11info->cryptset == crypt_none) {
        ci->basic_crypt_set = KIS_DEVICE_BASICCRYPT_NONE;
    } else {
        ci->basic_crypt_set = KIS_DEVICE_BASICCRYPT_ENCRYPTED;
    }

    // Fill in basic l2 and l3 encryption
    if (dot11info->cryptset & crypt_l2_mask) {
        ci->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_L2;
    } if (dot11info->cryptset & crypt_l3_mask) {
        ci->basic_crypt_set |= KIS_DEVICE_BASICCRYPT_L3;
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

void Kis_80211_Phy::HandleSSID(shared_ptr<kis_tracked_device_base> basedev,
        shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    SharedTrackerElement adv_ssid_map = dot11dev->get_advertised_ssid_map();

    shared_ptr<dot11_advertised_ssid> ssid;

    TrackerElement::map_iterator ssid_itr;

    if (adv_ssid_map == NULL) {
        fprintf(stderr, "debug - dot11phy::HandleSSID can't find the adv_ssid_map or probe_ssid_map struct, something is wrong\n");
        return;
    }

    if (dot11info->subtype == packet_sub_beacon ||
            dot11info->subtype == packet_sub_probe_resp) {
        ssid_itr = adv_ssid_map->find((int32_t) dot11info->ssid_csum);

        if (ssid_itr == adv_ssid_map->end()) {
            ssid = dot11dev->new_advertised_ssid();
            adv_ssid_map->add_intmap((int32_t) dot11info->ssid_csum, ssid);

            ssid->set_crypt_set(dot11info->cryptset);
            ssid->set_first_time(in_pack->ts.tv_sec);
            ssid->set_ietag_checksum(dot11info->ietag_csum);
            ssid->set_channel(dot11info->channel);

            ssid->set_dot11d_country(dot11info->dot11d_country);
            ssid->set_dot11d_vec(dot11info->dot11d_vec);

            // TODO handle loading SSID from the stored file
            ssid->set_ssid(dot11info->ssid);
            if (dot11info->ssid_len == 0 || dot11info->ssid_blank) {
                ssid->set_ssid_cloaked(true);
            }
            ssid->set_ssid_len(dot11info->ssid_len);

            ssid->set_crypt_set(dot11info->cryptset);

            ssid->set_beacon_info(dot11info->beacon_info);

            ssid->set_wps_state(dot11info->wps);
            ssid->set_wps_manuf(dot11info->wps_manuf);
            ssid->set_wps_model_name(dot11info->wps_model_name);
            ssid->set_wps_model_number(dot11info->wps_model_number);

            // Do we not know the basedev manuf?
            if (basedev->get_manuf() == "" && dot11info->wps_manuf != "")
                basedev->set_manuf(dot11info->wps_manuf);

            if (ssid->get_last_time() < in_pack->ts.tv_sec)
                ssid->set_last_time(in_pack->ts.tv_sec);
            ssid->inc_beacons_sec();
        } else {
            ssid = static_pointer_cast<dot11_advertised_ssid>(ssid_itr->second);
            if (ssid->get_last_time() < in_pack->ts.tv_sec)
                ssid->set_last_time(in_pack->ts.tv_sec);
        }

        if (dot11info->subtype == packet_sub_beacon) {
            // Update the base device records
            dot11dev->set_last_beaconed_ssid(ssid->get_ssid());
            dot11dev->set_last_beaconed_ssid_csum(dot11info->ssid_csum);

            if (alertracker->PotentialAlert(alert_airjackssid_ref) &&
                        ssid->get_ssid() == "AirJack" ) {

                string al = "IEEE80211 Access Point BSSID " +
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

            // Set the type
            ssid->set_ssid_beacon(true);
        } else if (dot11info->subtype == packet_sub_probe_resp) {
            if (mac_addr((uint8_t *) "\x00\x13\x37\x00\x00\x00", 6, 24) == 
                    dot11info->source_mac) {

                if (alertracker->PotentialAlert(alert_l33t_ref)) {
                    string al = "IEEE80211 probe response from OUI 00:13:37 seen, "
                        "which typically implies a Karma AP impersonation attack.";

                    alertracker->RaiseAlert(alert_l33t_ref, in_pack, 
                            dot11info->bssid_mac, dot11info->source_mac, 
                            dot11info->dest_mac, dot11info->other_mac, 
                            dot11info->channel, al);
                }

            }

            ssid->set_ssid_probe_response(true);
            dot11dev->set_last_probed_ssid(ssid->get_ssid());
            dot11dev->set_last_probed_ssid_csum(dot11info->ssid_csum);
        }
    }

    // TODO alert on change on SSID IE tags?
    if (ssid->get_ietag_checksum() != dot11info->ietag_csum) {
        // fprintf(stderr, "debug - dot11phy:HandleSSID %s ietag checksum changed\n", basedev->get_macaddr().Mac2String().c_str());

        // Things to check:
        // dot11d values
        // channel
        // WPS
        // Cryptset
        

        if (ssid->get_crypt_set() != dot11info->cryptset) {
            if (ssid->get_crypt_set() && dot11info->cryptset == crypt_none &&
                    alertracker->PotentialAlert(alert_wepflap_ref)) {

                string al = "IEEE80211 Access Point BSSID " +
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

                string al = "IEEE80211 Access Point BSSID " +
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

        if (ssid->get_channel() != dot11info->channel) {
            if (ssid->get_channel() != dot11info->channel &&
                    alertracker->PotentialAlert(alert_chan_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						basedev->get_macaddr().Mac2String() + " SSID \"" +
						ssid->get_ssid() + "\" changed advertised channel from " +
						ssid->get_channel() + " to " + 
						dot11info->channel + " which may "
						"indicate AP spoofing/impersonation";

					alertracker->RaiseAlert(alert_chan_ref, in_pack, 
                            dot11info->bssid_mac, dot11info->source_mac, 
                            dot11info->dest_mac, dot11info->other_mac, 
                            dot11info->channel, al);
            }


            ssid->set_channel(dot11info->channel); 
        }

        if (ssid->get_dot11d_country() != dot11info->dot11d_country) {
            fprintf(stderr, "debug - dot11phy:HandleSSID %s dot11d country changed\n", basedev->get_macaddr().Mac2String().c_str());

            ssid->set_dot11d_country(dot11info->dot11d_country);

            // TODO raise alert
        }

        bool dot11dmismatch = false;

        TrackerElementVector dot11dvec(ssid->get_dot11d_vec());
        for (unsigned int vc = 0; 
                vc < dot11dvec.size() && vc < dot11info->dot11d_vec.size(); vc++) {
            shared_ptr<dot11_11d_tracked_range_info> ri =
                static_pointer_cast<dot11_11d_tracked_range_info>(dot11dvec[vc]);

            if (ri->get_startchan() != dot11info->dot11d_vec[vc].startchan ||
                    ri->get_numchan() != dot11info->dot11d_vec[vc].numchan ||
                    ri->get_txpower() != dot11info->dot11d_vec[vc].txpower) {
                dot11dmismatch = true;
                break;
            }

        }

        if (dot11dmismatch) {
            ssid->set_dot11d_vec(dot11info->dot11d_vec);

            if (alertracker->PotentialAlert(alert_dot11d_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						basedev->get_macaddr().Mac2String() + " SSID \"" +
						ssid->get_ssid() + "\" advertised conflicting 802.11d "
                        "information which may indicate AP spoofing/impersonation";

					alertracker->RaiseAlert(alert_dot11d_ref, in_pack, 
                            dot11info->bssid_mac, dot11info->source_mac, 
                            dot11info->dest_mac, dot11info->other_mac, 
                            dot11info->channel, al);

            }
        }

        if (ssid->get_wps_state() != dot11info->wps) {
            ssid->set_wps_state(dot11info->wps);

        }

        if (dot11info->beacon_interval && ssid->get_beaconrate() != 
                Ieee80211Interval2NSecs(dot11info->beacon_interval)) {

            if (ssid->get_beaconrate() != 0 && 
                    alertracker->PotentialAlert(alert_beaconrate_ref)) {
                string al = "IEEE80211 Access Point BSSID " +
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

        ssid->set_ietag_checksum(dot11info->ietag_csum);
    }

    // Add the location data, if any
    if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
        ssid->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);

    }


    // TODO restore AP spoof protection
#if 0
	// If it's a probe response record it in the SSID cache, we only record
	// one per BSSID for now and only if we have a cloaked SSID on this record.
	// While we're at it, also figure out if we're responding for SSIDs we've never
	// been advertising (in a non-cloaked way), that's probably not a good
	// thing.
	if (packinfo->type == packet_management &&
		packinfo->subtype == packet_sub_probe_resp &&
		(packinfo->ssid_len || packinfo->ssid_blank == 0)) {

		dev = devicetracker->FetchDevice(packinfo->bssid_mac);

		if (dev != NULL) {
			net = (dot11_device *) dev->fetch(dev_comp_dot11);

			if (net != NULL) {
				for (map<uint32_t, dot11_ssid *>::iterator asi = 
					 net->ssid_map.begin(); asi != net->ssid_map.end(); ++asi) {

					// Catch beacon, cloaked situation
					if (asi->second->type == dot11_ssid_beacon &&
						asi->second->ssid_cloaked) {
						// Remember the revealed SSID
						ssid_conf->SetOpt(packinfo->bssid_mac.Mac2String(), 
										  packinfo->ssid, 
										  in_pack->ts.tv_sec);
					}

				}
			}
		}
	}

	if (packinfo->type == packet_management &&
		(packinfo->subtype == packet_sub_probe_resp || 
		 packinfo->subtype == packet_sub_beacon)) {

		// Run it through the AP spoof protection system
		for (unsigned int x = 0; x < apspoof_vec.size(); x++) {
			// Shortcut to checking the mac address first, if it's one we 
			// have then we don't have to do the expensive operation of pcre or
			// string matching
			if (apspoof_vec[x]->allow_mac_map.find(packinfo->source_mac) !=
				apspoof_vec[x]->allow_mac_map.end()) {
				continue;
			}

			int match = 0, matched = 0;
			string match_type;

#ifdef HAVE_LIBPCRE
			if (apspoof_vec[x]->ssid_re != NULL) {
				int ovector[128];

				match = (pcre_exec(apspoof_vec[x]->ssid_re, apspoof_vec[x]->ssid_study,
								   packinfo->ssid.c_str(), packinfo->ssid.length(),
								   0, 0, ovector, 128) >= 0);

				match_type = "regular expression";
				matched = 1;
			}
#endif

			if (matched == 0) {
				match = (apspoof_vec[x]->ssid == packinfo->ssid);
				match_type = "SSID";
				matched = 1;
			}

			if (match && globalreg->alertracker->PotentialAlert(alert_adhoc_ref)) {
				string ntype = 
					packinfo->subtype == packet_sub_beacon ? string("advertising") :
					string("responding for");

				string al = "IEEE80211 Unauthorized device (" + 
					packinfo->source_mac.Mac2String() + string(") ") + ntype + 
					" for SSID '" + packinfo->ssid + "', matching APSPOOF "
					"rule " + apspoof_vec[x]->name + string(" with ") + match_type + 
					string(" which may indicate spoofing or impersonation.");

				globalreg->alertracker->RaiseAlert(alert_ssidmatch_ref, in_pack, 
												   packinfo->bssid_mac, 
												   packinfo->source_mac, 
												   packinfo->dest_mac, 
												   packinfo->other_mac, 
												   packinfo->channel, al);
				break;
			}
		}
	}

#endif

}

void Kis_80211_Phy::HandleProbedSSID(shared_ptr<kis_tracked_device_base> basedev,
        shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    TrackerElementIntMap probemap(dot11dev->get_probed_ssid_map());

    shared_ptr<dot11_probed_ssid> probessid = NULL;
    TrackerElement::int_map_iterator ssid_itr;

    if (dot11info->subtype == packet_sub_probe_req) {
        ssid_itr = probemap.find(dot11info->ssid_csum);

        if (ssid_itr == probemap.end()) {
            probessid = dot11dev->new_probed_ssid();
            TrackerElement::int_map_pair p(dot11info->ssid_csum, probessid);
            probemap.insert(p);

            probessid->set_ssid(dot11info->ssid);
            probessid->set_ssid_len(dot11info->ssid_len);
            probessid->set_first_time(in_pack->ts.tv_sec);
        }

        if (probessid != NULL) {
            if (probessid->get_last_time() < in_pack->ts.tv_sec)
                probessid->set_last_time(in_pack->ts.tv_sec);

            // Add the location data, if any
            if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
                probessid->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                        pack_gpsinfo->alt, pack_gpsinfo->fix);

            }
        }
    }

}

void Kis_80211_Phy::HandleClient(shared_ptr<kis_tracked_device_base> basedev,
        shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo,
        kis_data_packinfo *pack_datainfo) {

    // If we can't map to a bssid then we can't associate this as a client
    if (dot11info->bssid_mac == globalreg->empty_mac)
        return;

    // We don't link broadcasts
    if (dot11info->bssid_mac == globalreg->broadcast_mac)
        return;

    TrackerElementMacMap client_map(dot11dev->get_client_map());

    shared_ptr<dot11_client> client = NULL;

    TrackerElement::mac_map_iterator client_itr;

    client_itr = client_map.find(dot11info->bssid_mac);

    bool new_client = false;
    if (client_itr == client_map.end()) {
        client = dot11dev->new_client();
        TrackerElement::mac_map_pair cp(dot11info->bssid_mac, client);
        client_map.insert(cp);
        new_client = true;
    } else {
        client = static_pointer_cast<dot11_client>(client_itr->second);
    }

    if (new_client) {
        client->set_bssid(dot11info->bssid_mac);
        client->set_first_time(in_pack->ts.tv_sec);
    }

    if (client->get_last_time() < in_pack->ts.tv_sec)
        client->set_last_time(in_pack->ts.tv_sec);

    if (dot11info->type == packet_data) {
        client->inc_datasize(dot11info->datasize);

        if (dot11info->fragmented) {
            client->inc_num_fragments(1);
        }

        if (dot11info->retry) {
            client->inc_num_retries(1);
            client->inc_datasize_retry(dot11info->datasize);
        }

        if (pack_datainfo != NULL) {
            if (pack_datainfo->proto == proto_eap) {
                if (pack_datainfo->auxstring != "") {
                    client->set_eap_identity(pack_datainfo->auxstring);
                }
            }

            if (pack_datainfo->discover_vendor != "") {
                if (client->get_dhcp_vendor() != "" &&
                        client->get_dhcp_vendor() != pack_datainfo->discover_vendor &&
						alertracker->PotentialAlert(alert_dhcpos_ref)) {
						string al = "IEEE80211 network BSSID " + 
							client->get_bssid().Mac2String() +
							" client " + 
							basedev->get_macaddr().Mac2String() + 
							"changed advertised DHCP vendor from '" +
							client->get_dhcp_vendor() + "' to '" +
							pack_datainfo->discover_vendor + "' which may indicate "
							"client spoofing or impersonation";

                        alertracker->RaiseAlert(alert_dhcpos_ref, in_pack,
                                dot11info->bssid_mac, dot11info->source_mac,
                                dot11info->dest_mac, dot11info->other_mac,
                                dot11info->channel, al);
                }

                client->set_dhcp_vendor(pack_datainfo->discover_vendor);
            }

            if (pack_datainfo->discover_host != "") {
                if (client->get_dhcp_host() != "" &&
                        client->get_dhcp_host() != pack_datainfo->discover_host &&
						alertracker->PotentialAlert(alert_dhcpname_ref)) {
						string al = "IEEE80211 network BSSID " + 
							client->get_bssid().Mac2String() +
							" client " + 
							basedev->get_macaddr().Mac2String() + 
							"changed advertised DHCP hostname from '" +
							client->get_dhcp_host() + "' to '" +
							pack_datainfo->discover_host + "' which may indicate "
							"client spoofing or impersonation";

                        alertracker->RaiseAlert(alert_dhcpname_ref, in_pack,
                                dot11info->bssid_mac, dot11info->source_mac,
                                dot11info->dest_mac, dot11info->other_mac,
                                dot11info->channel, al);
                }

                client->set_dhcp_host(pack_datainfo->discover_host);
            }

            if (pack_datainfo->cdp_dev_id != "") {
                client->set_cdp_device(pack_datainfo->cdp_dev_id);
            }

            if (pack_datainfo->cdp_port_id != "") {
                client->set_cdp_port(pack_datainfo->cdp_port_id);
            }
        }
    }

    if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
        client->get_location()->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                pack_gpsinfo->alt, pack_gpsinfo->fix);
    }

    // Try to make the back-record of us in the device we're a client OF
    shared_ptr<kis_tracked_device_base> backdev =
        devicetracker->FetchDevice(dot11info->bssid_mac, phyid);
    if (backdev != NULL) {
        client->set_bssid_key(backdev->get_key());

        shared_ptr<dot11_tracked_device> backdot11 = 
            static_pointer_cast<dot11_tracked_device>(backdev->get_map_value(dot11_device_entry_id));

        if (backdot11 != NULL) {
            if (backdot11->get_associated_client_map()->mac_find(basedev->get_macaddr()) ==
                    backdot11->get_associated_client_map()->mac_end()) {

                backdot11->get_associated_client_map()->add_macmap(basedev->get_macaddr(), basedev->get_tracker_key());
            }
        }
    }
}

static int packetnum = 0;

int Kis_80211_Phy::TrackerDot11(kis_packet *in_pack) {
    packetnum++;

    devicelist_scope_locker dlocker(devicetracker);

	// We can't do anything w/ it from the packet layer
	if (in_pack->error || in_pack->filtered) {
        // fprintf(stderr, "debug - error packet\n");
		return 0;
	}

	// Fetch what we already know about the packet.  
	dot11_packinfo *dot11info =
		(dot11_packinfo *) in_pack->fetch(pack_comp_80211);

	// Got nothing to do
	if (dot11info == NULL) {
        // fprintf(stderr, "debug - no dot11info\n");
		return 0;
    }

	kis_common_info *commoninfo =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	if (commoninfo == NULL) {
        // fprintf(stderr, "debug - no commoninfo\n");
		return 0;
    }

	if (commoninfo->error) {
        // fprintf(stderr, "debug - common error\n");
		return 0;
    }

    // There's nothing we can sensibly do with completely corrupt packets, 
    // so we just get rid of them.
    // TODO make sure phy corrupt packets are handled for statistics
    if (dot11info->corrupt)  {
        return 0;
    }

    // If we don't process phys...
    if (commoninfo->type == packet_basic_phy && !process_ctl_phy)
        return 0;

    // Find & update the common attributes of our base record.
    // We want to update signal, frequency, location, packet counts, devices,
    // and encryption, because this is the core record for everything we do.
    // We do this early on because we want to track things even if they're unknown
    // or broken.
    shared_ptr<kis_tracked_device_base> basedev =
        devicetracker->UpdateCommonDevice(commoninfo->device, commoninfo->phyid,
                in_pack, 
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION));

	kis_data_packinfo *pack_datainfo =
		(kis_data_packinfo *) in_pack->fetch(pack_comp_basicdata);

	// We can't do anything useful
	if (dot11info->corrupt || dot11info->type == packet_noise ||
		dot11info->type == packet_unknown || 
		dot11info->subtype == packet_sub_unknown) {
        // fprintf(stderr, "debug - unknown or noise packet\n");
		return 0;
    }

	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);

    // Something bad has happened if we can't find our device
    if (basedev == NULL) {
        fprintf(stderr, "debug - phydot11 got to tracking stage with no devicetracker device for %s.  Something is wrong?\n", commoninfo->device.Mac2String().c_str());
        return 0;
    }

    shared_ptr<dot11_tracked_device> dot11dev =
        static_pointer_cast<dot11_tracked_device>(basedev->get_map_value(dot11_device_entry_id));

    if (dot11dev == NULL) {
        stringstream ss;
        ss << "Detected new 802.11 Wi-Fi device " << commoninfo->device.Mac2String() << " packet " << packetnum;
        _MSG(ss.str(), MSGFLAG_INFO);

        dot11dev.reset(new dot11_tracked_device(globalreg, dot11_device_entry_id));
        dot11_tracked_device::attach_base_parent(dot11dev, basedev);
    }

    // Update the last beacon timestamp
    if (dot11info->type == packet_management && dot11info->subtype == packet_sub_beacon) {
        dot11dev->set_last_beacon_timestamp(in_pack->ts.tv_sec);
    }

    // Handle beacons and SSID responses from the AP.  This is still all the same
    // basic device
    if (dot11info->type == packet_management && 
            (dot11info->subtype == packet_sub_beacon ||
             dot11info->subtype == packet_sub_probe_resp)) {
        HandleSSID(basedev, dot11dev, in_pack, dot11info, pack_gpsinfo);
    }

    // Handle probe reqs
    if (dot11info->type == packet_management &&
            dot11info->subtype == packet_sub_probe_req) {
        HandleProbedSSID(basedev, dot11dev, in_pack, dot11info, pack_gpsinfo);
    }

    // Increase data size for ourselves, if we're a data packet
    if (dot11info->type == packet_data) {
        dot11dev->inc_datasize(dot11info->datasize);

        if (dot11info->fragmented) {
            dot11dev->inc_num_fragments(1);
        }

        if (dot11info->retry) {
            dot11dev->inc_num_retries(1);
            dot11dev->inc_datasize_retry(dot11info->datasize);
        }
    }

    if (dot11info->distrib == distrib_inter) {
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

        // If we're /only/ a IBSS peer
        if (basedev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_PEER) {
            basedev->set_type_string("Wi-Fi Peer");
            basedev->set_devicename(basedev->get_macaddr().Mac2String());
        }
    }

	if (dot11info->type == packet_phy) {
        // Phy to a known device mac, we know it's a wifi device
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);

        // If we're /only/ a client, set the type name and device name
        if (basedev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_CLIENT) {
            basedev->set_type_string("Wi-Fi Client");
            basedev->set_devicename(basedev->get_macaddr().Mac2String());
        }
    } else if (dot11info->ess) { 
        // ESS from-ap packets mean we must be an AP
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);

        // If we're an AP always set the type and name because that's the
        // "most important" thing we can be
        basedev->set_type_string("Wi-Fi AP");

		// Throw alert if device changes between bss and adhoc
        if (dot11dev->bitcheck_type_set(DOT11_DEVICE_TYPE_ADHOC) &&
                !dot11dev->bitcheck_type_set(DOT11_DEVICE_TYPE_BEACON_AP) &&
                alertracker->PotentialAlert(alert_adhoc_ref)) {
				string al = "IEEE80211 Network BSSID " + 
					dot11info->bssid_mac.Mac2String() + 
					" previously advertised as AP network, now advertising as "
					"Ad-Hoc/WDS which may indicate AP spoofing/impersonation";

                alertracker->RaiseAlert(alert_adhoc_ref, in_pack,
                        dot11info->bssid_mac, dot11info->source_mac,
                        dot11info->dest_mac, dot11info->other_mac,
                        dot11info->channel, al);
        }

        dot11dev->bitset_type_set(DOT11_DEVICE_TYPE_BEACON_AP);
    } else if (dot11info->distrib == distrib_inter) {
        // Adhoc
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

        if (basedev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_PEER)
            basedev->set_type_string("Wi-Fi Ad-hoc / WDS ");

		// Throw alert if device changes to adhoc
        if (!dot11dev->bitcheck_type_set(DOT11_DEVICE_TYPE_ADHOC) &&
                dot11dev->bitcheck_type_set(DOT11_DEVICE_TYPE_BEACON_AP) &&
                alertracker->PotentialAlert(alert_adhoc_ref)) {
				string al = "IEEE80211 Network BSSID " + 
					dot11info->bssid_mac.Mac2String() + 
					" previously advertised as AP network, now advertising as "
					"Ad-Hoc/WDS which may indicate AP spoofing/impersonation";

                alertracker->RaiseAlert(alert_adhoc_ref, in_pack,
                        dot11info->bssid_mac, dot11info->source_mac,
                        dot11info->dest_mac, dot11info->other_mac,
                        dot11info->channel, al);
        }

        dot11dev->bitset_type_set(DOT11_DEVICE_TYPE_ADHOC);
    } 
   
    // Sent by ap, data, not from AP, means it's bridged from somewhere else
    if (dot11info->distrib == distrib_from &&
            dot11info->bssid_mac != basedev->get_macaddr() &&
            dot11info->type == packet_data) {
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_WIRED);

        // Set the typename and device name if we've only been seen as wired
        if (basedev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_WIRED) {
            basedev->set_type_string("Wi-Fi Bridged Device");
            basedev->set_devicename(basedev->get_macaddr().Mac2String());
        }

        dot11dev->bitset_type_set(DOT11_DEVICE_TYPE_WIRED);

        basedev->set_devicename(basedev->get_macaddr().Mac2String());

        HandleClient(basedev, dot11dev, in_pack, dot11info,
                pack_gpsinfo, pack_datainfo);
    } else if (dot11info->bssid_mac != basedev->get_macaddr() &&
            dot11info->distrib == distrib_to) {

        if (dot11info->bssid_mac != globalreg->broadcast_mac)
            dot11dev->set_last_bssid(dot11info->bssid_mac);

        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);

        // If we're only a client, set the type name and device name
        if (basedev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_CLIENT) {
            basedev->set_type_string("Wi-Fi Client");
            basedev->set_devicename(basedev->get_macaddr().Mac2String());
        }

        HandleClient(basedev, dot11dev, in_pack, dot11info,
                pack_gpsinfo, pack_datainfo);
    }

    // Look for WPA handshakes
    if (dot11info->type == packet_data) {
        shared_ptr<dot11_tracked_eapol> eapol =
            PacketDot11EapolHandshake(in_pack, dot11dev);

        if (eapol != NULL) {
            shared_ptr<kis_tracked_device_base> eapolbase =
                devicetracker->FetchDevice(dot11info->bssid_mac, phyid);

            if (eapolbase != NULL) {
                shared_ptr<dot11_tracked_device> eapoldot11 = 
                    static_pointer_cast<dot11_tracked_device>(eapolbase->get_map_value(dot11_device_entry_id));

                if (eapoldot11 != NULL) {
                    TrackerElementVector vec(eapoldot11->get_wpa_key_vec());

                    // Start doing something smart here about eliminating
                    // records - we want to do our best to keep a 1, 2, 3, 4
                    // handshake sequence, so find out what duplicates we have
                    // and eliminate the oldest one of them if we need to
                    uint8_t keymask = 0;

                    if (vec.size() > 16) {
                        for (TrackerElementVector::iterator kvi = vec.begin();
                                kvi != vec.end(); ++kvi) {
                            shared_ptr<dot11_tracked_eapol> ke =
                                static_pointer_cast<dot11_tracked_eapol>(*kvi);

                            uint8_t knum = (1 << ke->get_eapol_msg_num());

                            // If this is a duplicate handshake number, we can get
                            // rid of this one
                            if ((keymask & knum) == knum) {
                                vec.erase(kvi);
                                break;
                            }

                            // Otherwise put this key in the keymask
                            keymask |= knum;
                        }
                    }

                    vec.push_back(eapol);

                    // Calculate the key mask of seen handshake keys
                    keymask = 0;
                    for (TrackerElementVector::iterator kvi = vec.begin(); 
                            kvi != vec.end(); ++kvi) {
                        shared_ptr<dot11_tracked_eapol> ke =
                            static_pointer_cast<dot11_tracked_eapol>(*kvi);

                        keymask |= (1 << ke->get_eapol_msg_num());
                    }

                    eapoldot11->set_wpa_present_handshake(keymask);
                }
            }
        }
    }

	if (dot11info->type == packet_data &&
		dot11info->source_mac == dot11info->bssid_mac) {
		int wps = 0;
		string ssidchan = "0";
		string ssidtxt = "<Unknown>";
        TrackerElementIntMap ssidmap(dot11dev->get_advertised_ssid_map());

        for (TrackerElementIntMap::iterator si = ssidmap.begin();
                si != ssidmap.end(); ++si) {
            shared_ptr<dot11_advertised_ssid> ssid = 
                static_pointer_cast<dot11_advertised_ssid>(si->second);
            if (ssid->get_crypt_set() & crypt_wps) {
                ssidchan = ssid->get_channel();
                ssidtxt = ssid->get_ssid();
                break;
            }
        }

        wps = PacketDot11WPSM3(in_pack);

        if (wps) {
            // if we're w/in time of the last one, update, otherwise clear
            if (globalreg->timestamp.tv_sec - 
                    dot11dev->get_wps_m3_last() > (60 * 5))
                dot11dev->set_wps_m3_count(1);
            else
                dot11dev->inc_wps_m3_count(1);

            dot11dev->set_wps_m3_last(globalreg->timestamp.tv_sec);

            if (dot11dev->get_wps_m3_count() > 5) {
                if (alertracker->PotentialAlert(alert_wpsbrute_ref)) {
                    string al = "IEEE80211 AP '" + ssidtxt + "' (" + 
                        dot11info->bssid_mac.Mac2String() +
                        ") sending excessive number of WPS messages which may "
                        "indicate a WPS brute force attack such as Reaver";

                    alertracker->RaiseAlert(alert_wpsbrute_ref, 
                            in_pack, 
                            dot11info->bssid_mac, dot11info->source_mac, 
                            dot11info->dest_mac, dot11info->other_mac, 
                            ssidchan, al);
                }

                dot11dev->set_wps_m3_count(1);
            }
        }
    }

	if (dot11info->type == packet_management &&
		(dot11info->subtype == packet_sub_disassociation ||
		 dot11info->subtype == packet_sub_deauthentication) &&
		dot11info->dest_mac == globalreg->broadcast_mac &&
		alertracker->PotentialAlert(alert_bcastdcon_ref)) {

		string al = "IEEE80211 Access Point BSSID " +
			basedev->get_macaddr().Mac2String() + " broadcast deauthentication or "
			"disassociation of all clients, probable denial of service";
			
        alertracker->RaiseAlert(alert_bcastdcon_ref, in_pack, 
                dot11info->bssid_mac, dot11info->source_mac, 
                dot11info->dest_mac, dot11info->other_mac, 
                dot11info->channel, al);
    }

    if (basedev->get_type_string().length() == 0) {
        fprintf(stderr, "debug - unclassed device as of packet %d typeset %lu\n", packetnum, basedev->get_basic_type_set());
    }


#if 0


	if (ssid_new) {
		string printssid;
		string printssidext;
		string printcrypt;
		string printtype;
		string printdev;
		string printchan;
		string printmanuf;

		printssid = ssid->ssid;

		if (ssid->ssid_len == 0 || ssid->ssid == "") {
			if (ssid->type == dot11_ssid_probereq)  {
				printssid = "<Broadcast>";
				printssidext = " (probing for any SSID)";
			} else {
				printssid = "<Hidden SSID>";
			}
		}

		// commondev->name = printssid;

		if (ssid->ssid_cloaked) {
			printssidext = " (cloaked)";
		}

		if (ssid->type == dot11_ssid_beacon) {
			// commondev->name = printssid;

			printtype = "AP";

			if (ssid->cryptset) {
				printcrypt = "encrypted (" + CryptToString(ssid->cryptset) + ")";
			} else {
				printcrypt = "unencrypted";
			}

			printdev = "BSSID " + dot11info->bssid_mac.Mac2String();

			printchan = ", channel " + IntToString(ssid->channel);
		} else if (ssid->type == dot11_ssid_probereq) {
			printtype = "probing client";
			
			if (ssid->cryptset)
				printcrypt = "encrypted";
			else
				printcrypt = "unencrypted";

			printdev = "client " + dot11info->source_mac.Mac2String();
		} else if (ssid->type == dot11_ssid_proberesp) {
			printtype = "responding AP";

			if (ssid->cryptset)
				printcrypt = "encrypted";
			else
				printcrypt = "unencrypted";

			printdev = "BSSID " + dot11info->bssid_mac.Mac2String();
		} else {
			printtype = "unknown " + IntToString(ssid->type);
			printdev = "BSSID " + dot11info->bssid_mac.Mac2String();
		}

		if (commondev->manuf != "")
			printmanuf = " (" + commondev->manuf + ")";

		_MSG("Detected new 802.11 " + printtype + " SSID \"" + printssid + "\"" + 
			 printssidext + ", " + printdev + printmanuf + ", " + printcrypt + 
			 printchan,
			 MSGFLAG_INFO);

	} else if (net_new) {
		// If we didn't find a new SSID, and we found a network, talk about that
		string printcrypt;

		if (dot11info->cryptset)
			printcrypt = "encrypted";
		else
			printcrypt = "unencrypted";

		_MSG("Detected new 802.11 network BSSID " + dot11info->bssid_mac.Mac2String() +
			 ", " + printcrypt + ", no beacons seen yet", MSGFLAG_INFO);
	}

	if (dot11info->type == packet_management &&
		(dot11info->subtype == packet_sub_disassociation ||
		 dot11info->subtype == packet_sub_deauthentication) &&
		dot11info->dest_mac == globalreg->broadcast_mac &&
		globalreg->alertracker->PotentialAlert(alert_bcastdcon_ref) &&
		apdev != NULL) {

		string al = "IEEE80211 Access Point BSSID " +
			apdev->key.Mac2String() + " broadcast deauthentication or "
			"disassociation of all clients, probable denial of service";
			
		globalreg->alertracker->RaiseAlert(alert_bcastdcon_ref, in_pack, 
										   dot11info->bssid_mac, 
										   dot11info->source_mac, 
										   dot11info->dest_mac, 
										   dot11info->other_mac, 
										   dot11info->channel, al);
	}
#endif

	return 1;
}

string Kis_80211_Phy::CryptToString(uint64_t cryptset) {
	string ret;

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
    // Always return that the URL exists, but throw an error during post
    // handling if we don't have PCRE.  Less weird behavior for clients.
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/phy/phy80211/ssid_regex.cmd") == 0 ||
            strcmp(path, "/phy/phy80211/ssid_regex.jcmd") == 0)
            return true;
        if (strcmp(path, "/phy/phy80211/probe_regex.cmd") == 0 ||
            strcmp(path, "/phy/phy80211/probe_regex.jcmd") == 0)
            return true;
    }

    if (strcmp(method, "GET") == 0) {
        vector<string> tokenurl = StrTokenize(path, "/");

        // we care about
        // /phy/phy80211/by-bssid/[mac]/pcap/[mac]-handshake.pcap
        if (tokenurl.size() < 7)
            return false;

        if (tokenurl[1] != "phy")
            return false;

        if (tokenurl[2] != "phy80211")
            return false;

        if (tokenurl[3] != "by-bssid")
            return false;

        mac_addr dmac(tokenurl[4]);
        if (dmac.error)
            return false;

        if (tokenurl[5] != "pcap")
            return false;

        // Valid requested file?
        if (tokenurl[6] != tokenurl[4] + "-handshake.pcap")
            return false;

        // Does it exist?
        devicelist_scope_locker dlocker(devicetracker);
        if (devicetracker->FetchDevice(dmac, phyid) != NULL)
            return true;
    }

    return false;
}

void Kis_80211_Phy::GenerateHandshakePcap(shared_ptr<kis_tracked_device_base> dev, 
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
        shared_ptr<dot11_tracked_device> dot11dev =
            static_pointer_cast<dot11_tracked_device>(dev->get_map_value(dot11_device_entry_id));

        if (dot11dev != NULL) {
            // Make a filename
            string dmac = dev->get_macaddr().Mac2String();
            std::replace(dmac.begin(), dmac.end(), ':', '-');

            string ssid = "";

            if (dot11dev->get_last_beaconed_ssid().length() != 0) 
                ssid = " " + dot11dev->get_last_beaconed_ssid();

            connection->optional_filename = "handshake " + dmac + ssid + ".pcap";

            TrackerElementVector hsvec(dot11dev->get_wpa_key_vec());

            for (TrackerElementVector::iterator i = hsvec.begin(); 
                    i != hsvec.end(); ++i) {
                shared_ptr<dot11_tracked_eapol> eapol = 
                    static_pointer_cast<dot11_tracked_eapol>(*i);

                shared_ptr<kis_tracked_packet> packet = eapol->get_eapol_packet();

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
    size_t len;
    int total = 0;

    while ((len = read(readfd, buf, 128)) >= 0) {
        if (len == 0) {
            if (errno == EAGAIN || errno == EINTR)
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

    vector<string> tokenurl = StrTokenize(url, "/");

    // /phy/phy80211/by-bssid/[mac]/pcap/[mac]-handshake.pcap
    if (tokenurl.size() < 7)
        return;

    if (tokenurl[1] != "phy")
        return;

    if (tokenurl[2] != "phy80211")
        return;

    if (tokenurl[3] != "by-bssid")
        return;

    mac_addr dmac(tokenurl[4]);
    if (dmac.error) {
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
    devicelist_scope_locker dlocker(devicetracker);
    if (devicetracker->FetchDevice(dmac, phyid) == NULL) {
        stream << "unknown device";
        return;
    }

    // Validate the session and return a basic auth prompt
    if (httpd->HasValidSession(connection, true)) {
        // It should exist and we'll handle if it doesn't in the stream
        // handler
        devicelist_scope_locker dlocker(devicetracker);
        GenerateHandshakePcap(devicetracker->FetchDevice(dmac, phyid), connection, stream);
    } else {
        stream << "Login required";
        return;
    }

    return;
}

int Kis_80211_Phy::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    bool handled = false;

    string stripped = Httpd_StripSuffix(concls->url);
   
    if (!Httpd_CanSerialize(concls->url) ||
            (stripped != "/phy/phy80211/ssid_regex" &&
             stripped != "/phy/phy80211/probe_regex")) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
        return 1;
    }

#ifdef HAVE_LIBPCRE
    // Common API
    SharedStructured structdata;

    vector<SharedElementSummary> summary_vec;

    // Make sure we can extract the parameters
    try {
        if (concls->variable_cache.find("msgpack") != concls->variable_cache.end()) {
            structdata.reset(new StructuredMsgpack(Base64::decode(concls->variable_cache["msgpack"]->str())));
        } else if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            // fprintf(stderr, "debug - missing data\n");
            throw StructuredDataException("Missing data");
        }

        // Look for a vector named 'essid', we need it for the worker
        SharedStructured essid_list = structdata->getStructuredByKey("essid");

        // Parse the fields, if we have them
        SharedStructured field_list;

        if (structdata->hasKey("fields"))
            field_list = structdata->getStructuredByKey("fields");

        if (field_list != NULL) {
            StructuredData::structured_vec fvec = field_list->getStructuredArray();
            for (StructuredData::structured_vec::iterator i = fvec.begin(); 
                    i != fvec.end(); ++i) {
                if ((*i)->isString()) {
                    SharedElementSummary s(new TrackerElementSummary((*i)->getString(), 
                                entrytracker));
                    summary_vec.push_back(s);
                } else if ((*i)->isArray()) {
                    StructuredData::string_vec mapvec = (*i)->getStringVec();

                    if (mapvec.size() != 2) {
                        concls->response_stream << "Invalid request: "
                            "Expected field, rename";
                        concls->httpcode = 400;
                        return 1;
                    }

                    SharedElementSummary s(new TrackerElementSummary(mapvec[0], 
                                mapvec[1], entrytracker));
                    summary_vec.push_back(s);
                }
            }
        }

        // Make a worker instance

        if (stripped == "/phy/phy80211/ssid_regex") {
            SharedTrackerElement devices(new TrackerElement(TrackerVector));
            shared_ptr<TrackerElementVector> 
                devices_vec(new TrackerElementVector(devices));

            devicetracker_pcre_worker worker(globalreg,
                "dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid",
                essid_list, devices);

            // Tell devicetracker to do the work
            devicetracker->MatchOnDevices(&worker);

            devicetracker->httpd_device_summary(concls->url, concls->response_stream,
                    devices_vec, summary_vec);

        } else if (stripped == "/phy/phy80211/probe_regex") {
            SharedTrackerElement devices(new TrackerElement(TrackerVector));
            shared_ptr<TrackerElementVector> 
                devices_vec(new TrackerElementVector(devices));

            devicetracker_pcre_worker worker(globalreg,
                "dot11.device/dot11.device.probed_ssid_map/dot11.probedssid.ssid",
                essid_list, devices);

            // Tell devicetracker to do the work
            devicetracker->MatchOnDevices(&worker);

            devicetracker->httpd_device_summary(concls->url, concls->response_stream,
                    devices_vec, summary_vec);
        }

        return 1;
    } catch(const std::exception& e) {
        // Exceptions can be caused by missing fields, or fields which
        // aren't the format we expected.  Throw it all out with an
        // error.
        concls->response_stream << "Invalid request " << e.what();
        concls->httpcode = 400;

        return 1;
    }

#else
    concls->response_stream << "Unable to process: Kismet not compiled with PCRE";
    concls->httpcode = 501;
    return 1;
#endif

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
            unsigned int in_timeout, int entry_id) {
        globalreg = in_globalreg;
        dot11_device_entry_id = entry_id;
        timeout = in_timeout;
    }

    virtual ~phy80211_devicetracker_expire_worker() { }

    // Compare against our PCRE and export msgpack objects if we match
    virtual void MatchDevice(Devicetracker *devicetracker, 
            shared_ptr<kis_tracked_device_base> device) {

        shared_ptr<dot11_tracked_device> dot11dev =
            static_pointer_cast<dot11_tracked_device>(device->get_map_value(dot11_device_entry_id));

        // Not 802.11?  nothing we can do
        if (dot11dev == NULL) {
            return;
        }

        // Iterate over all the SSID records
        TrackerElementIntMap adv_ssid_map(dot11dev->get_advertised_ssid_map());
        shared_ptr<dot11_advertised_ssid> ssid = NULL;
        TrackerElementIntMap::iterator int_itr;

        for (int_itr = adv_ssid_map.begin(); int_itr != adv_ssid_map.end(); ++int_itr) {
            // Always leave one
            if (adv_ssid_map.size() <= 1)
                break;

            ssid = static_pointer_cast<dot11_advertised_ssid>(int_itr->second);

            if (globalreg->timestamp.tv_sec - ssid->get_last_time() > timeout) {
                fprintf(stderr, "debug - forgetting dot11ssid %s expiration %d\n", ssid->get_ssid().c_str(), timeout);
                adv_ssid_map.erase(int_itr);
                int_itr = adv_ssid_map.begin();
                devicetracker->UpdateFullRefresh();
            }
        }

        TrackerElementIntMap probe_map(dot11dev->get_probed_ssid_map());
        shared_ptr<dot11_probed_ssid> pssid = NULL;

        for (int_itr = probe_map.begin(); int_itr != probe_map.end(); ++int_itr) {
            // Always leave one
            if (probe_map.size() <= 1)
                break;

            pssid = static_pointer_cast<dot11_probed_ssid>(int_itr->second);

            if (globalreg->timestamp.tv_sec - pssid->get_last_time() > timeout) {
                fprintf(stderr, "debug - forgetting dot11probessid %s expiration %d\n", pssid->get_ssid().c_str(), timeout);
                probe_map.erase(int_itr);
                int_itr = probe_map.begin();
                devicetracker->UpdateFullRefresh();
            }
        }

        TrackerElementMacMap client_map(dot11dev->get_client_map());
        shared_ptr<dot11_client> client = NULL;
        TrackerElementMacMap::iterator mac_itr;

        for (mac_itr = client_map.begin(); mac_itr != client_map.end(); ++mac_itr) {
            // Always leave one
            if (client_map.size() <= 1)
                break;

            client = static_pointer_cast<dot11_client>(mac_itr->second);

            if (globalreg->timestamp.tv_sec - client->get_last_time() > timeout) {
                fprintf(stderr, "debug - forgetting client link from %s to %s expiration %d\n", device->get_macaddr().Mac2String().c_str(), mac_itr->first.Mac2String().c_str(), timeout);
                client_map.erase(mac_itr);
                mac_itr = client_map.begin();
                devicetracker->UpdateFullRefresh();
            }
        }
    }

protected:
    GlobalRegistry *globalreg;
    int dot11_device_entry_id;
    unsigned int timeout;
};

int Kis_80211_Phy::timetracker_event(int eventid) {
    // Spawn a worker to handle this
    if (eventid == device_idle_timer) {
        phy80211_devicetracker_expire_worker worker(globalreg,
                device_idle_expiration, dot11_device_entry_id);
        devicetracker->MatchOnDevices(&worker);
    }

    // Loop
    return 1;
}

