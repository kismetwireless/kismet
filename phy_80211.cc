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
#include "gpstracker.h"
#include "packet.h"
#include "uuid.h"
#include "alertracker.h"
#include "manuf.h"
#include "configfile.h"

#include "base64.h"

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "phy_80211.h"

#include "kis_httpd_registry.h"

#include "boost_like_hash.h"

#include "pcapng_stream_futurebuf.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

// static std::atomic<int> packetnum {0};

// Convert the beacon interval to # of packets per second
unsigned int Ieee80211Interval2NSecs(int in_interval) {
    double interval_per_sec;

    interval_per_sec = (double) in_interval * 1024 / 1000000;

    return (unsigned int) ceil(1.0f / interval_per_sec);
}

int phydot11_packethook_wep(CHAINCALL_PARMS) {
    return ((kis_80211_phy *) auxdata)->packet_wep_decryptor(in_pack);
}

int phydot11_packethook_dot11(CHAINCALL_PARMS) {
    return ((kis_80211_phy *) auxdata)->packet_dot11_dissector(in_pack);
}

kis_80211_phy::kis_80211_phy(global_registry *in_globalreg, int in_phyid) : 
    kis_phy_handler(in_globalreg, in_phyid) {
        alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
        packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
        timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
        devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();
        eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();
        entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();
        streamtracker = Globalreg::fetch_mandatory_global_as<stream_tracker>();

        // Initialize the crc tables
        crc32_init_table_80211(Globalreg::globalreg->crc32_table);

        set_phy_name("IEEE802.11");

        dot11_device_entry_id =
            Globalreg::globalreg->entrytracker->register_field("dot11.device",
                    tracker_element_factory<dot11_tracked_device>(),
                    "IEEE802.11 device");

        // Packet classifier - makes basic records plus dot11 data
        packetchain->register_handler(&packet_dot11_common_classifier, this,
                CHAINPOS_CLASSIFIER, -100);
        packetchain->register_handler(&packet_dot11_scan_json_classifier, this,
                CHAINPOS_CLASSIFIER, -99);
        packetchain->register_handler(&phydot11_packethook_wep, this,
                CHAINPOS_DECRYPT, -100);
        packetchain->register_handler(&phydot11_packethook_dot11, this,
                CHAINPOS_LLCDISSECT, -100);

        // If we haven't registered packet components yet, do so.  We have to
        // co-exist with the old tracker core for some time
        pack_comp_80211 =
            packetchain->register_packet_component("PHY80211");

        pack_comp_basicdata = 
            packetchain->register_packet_component("BASICDATA");

        pack_comp_mangleframe = 
            packetchain->register_packet_component("MANGLEDATA");

        pack_comp_checksum =
            packetchain->register_packet_component("CHECKSUM");

        pack_comp_linkframe = 
            packetchain->register_packet_component("LINKFRAME");

        pack_comp_decap =
            packetchain->register_packet_component("DECAP");

        pack_comp_common = 
            packetchain->register_packet_component("COMMON");

        pack_comp_datapayload =
            packetchain->register_packet_component("DATAPAYLOAD");

        pack_comp_gps =
            packetchain->register_packet_component("GPS");

        pack_comp_l1info =
            packetchain->register_packet_component("RADIODATA");

        pack_comp_json =
            packetchain->register_packet_component("JSON");

        ssid_regex_vec =
            Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_vector>("phy80211.ssid_alerts", 
                    tracker_element_factory<tracker_element_vector>(),
                    "Regex SSID alert configuration");

        ssid_regex_vec_element_id =
            Globalreg::globalreg->entrytracker->register_field("phy80211.ssid_alert", 
                    tracker_element_factory<dot11_tracked_ssid_alert>(),
                    "ssid alert");

        // Register the dissector alerts
        alert_netstumbler_ref = 
            alertracker->activate_configured_alert("NETSTUMBLER", 
                    "Netstumbler (and similar older Windows tools) may generate unique "
                    "beacons which can be used to identify these tools in use.  These "
                    "tools and the cards which generate these frames are uncommon.",
                    phyid);
        alert_nullproberesp_ref =
            alertracker->activate_configured_alert("NULLPROBERESP", 
                    "A probe response with a SSID length of 0 can be used to crash the "
                    "firmware in specific older Orinoco cards.  These cards are "
                    "unlikely to be in use in modern systems.",
                    phyid);
        alert_lucenttest_ref =
            alertracker->activate_configured_alert("LUCENTTEST", 
                    "Specific Lucent Orinoco test tools generate identifiable frames, "
                    "which can indicate these tools are in use.  These tools and the "
                    "cards which generate these frames are uncommon.",
                    phyid);
        alert_msfbcomssid_ref =
            alertracker->activate_configured_alert("MSFBCOMSSID", 
                    "Old versions of the Broadcom Windows drivers (and Linux NDIS drivers) "
                    "are vulnerable to overflow exploits.  The Metasploit framework "
                    "can attack these vulnerabilities.  These drivers are unlikely to "
                    "be found in modern systems, but seeing these malformed frames "
                    "indicates an attempted attack is occurring.",
                    phyid);
        alert_msfdlinkrate_ref =
            alertracker->activate_configured_alert("MSFDLINKRATE", 
                    "Old versions of the D-Link Windows drivers are vulnerable to "
                    "malformed rate fields.  The Metasploit framework can attack these "
                    "vulnerabilities.  These drivers are unlikely to be found in "
                    "modern systems, but seeing these malformed frames indicates an "
                    "attempted attack is occurring.",
                    phyid);
        alert_msfnetgearbeacon_ref =
            alertracker->activate_configured_alert("MSFNETGEARBEACON", 
                    "Old versions of the Netgear windows drivers are vulnerable to "
                    "malformed beacons.  The Metasploit framework can attack these "
                    "vulnerabilities.  These drivers are unlikely to be found in "
                "modern systems, but seeing these malformed frames indicates an "
                "attempted attack is occurring.",
                phyid);
    alert_longssid_ref =
        alertracker->activate_configured_alert("LONGSSID", 
                "The Wi-Fi standard allows for 32 characters in a SSID. "
                "Historically, some drivers have had vulnerabilities related to "
                "invalid over-long SSID fields.  Seeing these frames indicates that "
                "significant corruption or an attempted attack is occurring.",
                phyid);
    alert_disconinvalid_ref =
        alertracker->activate_configured_alert("DISCONCODEINVALID", 
                "The 802.11 specification defines reason codes for disconnect "
                "and deauthentication events.  Historically, various drivers "
                "have been reported to improperly handle invalid reason codes.  "
                "An invalid reason code indicates an improperly behaving device or "
                "an attempted attack.",
                phyid);
    alert_deauthinvalid_ref =
        alertracker->activate_configured_alert("DEAUTHCODEINVALID", 
                "The 802.11 specification defines reason codes for disconnect "
                "and deauthentication events.  Historically, various drivers "
                "have been reported to improperly handle invalid reason codes.  "
                "An invalid reason code indicates an improperly behaving device or "
                "an attempted attack.",
                phyid);
    alert_wmm_ref =
        alertracker->activate_configured_alert("WMMOVERFLOW",
                "The Wi-Fi standard specifies 24 bytes for WMM IE tags.  Over-sized "
                "WMM fields may indicate an attempt to exploit bugs in Broadcom chipsets "
                "using the Broadpwn attack",
                phyid);
#if 0
    alert_dhcpclient_ref =
        alertracker->activate_configured_alert("DHCPCLIENTID", phyid);
#endif
    alert_chan_ref =
        alertracker->activate_configured_alert("CHANCHANGE", 
                "An access point has changed channel.  This may occur on "
                "enterprise equipment or on personal equipment with automatic "
                "channel selection, but may also indicate a spoofed or "
                "'evil twin' network.",
                phyid);
	alert_dhcpcon_ref =
		alertracker->activate_configured_alert("DHCPCONFLICT", 
                "A DHCP exchange was observed and a client was given an IP via "
                "DHCP, but is not using the assigned IP.  This may be a "
                "mis-configured client device, or may indicate client spoofing.",
                phyid);
	alert_bcastdcon_ref =
		alertracker->activate_configured_alert("BCASTDISCON", 
                "A broadcast disconnect packet forces all clients on a network "
                "to disconnect.  While these may rarely occur in some environments, "
                "typically a broadcast disconnect indicates a denial of service "
                "attack or an attempt to attack the network encryption by forcing "
                "clients to reconnect.",
                phyid);
	alert_airjackssid_ref = 
		alertracker->activate_configured_alert("AIRJACKSSID", 
                "Very old wireless tools used the SSID 'Airjack' while configuring "
                "card state.  It is very unlikely to see these tools in operation "
                "in modern environments.",
                phyid);
	alert_wepflap_ref =
		alertracker->activate_configured_alert("CRYPTODROP", 
                "A previously encrypted SSID has stopped advertising encryption.  "
                "This may rarely occur when a network is reconfigured to an open "
                "state, but more likely indicates some form of network spoofing or "
                "'evil twin' attack.",
                phyid);
	alert_dhcpname_ref =
		alertracker->activate_configured_alert("DHCPNAMECHANGE", 
                "The DHCP protocol allows clients to put the host name and "
                "DHCP client / vendor / operating system details in the DHCP "
                "Discovery packet.  These values should old change if the client "
                "has changed drastically (such as a dual-boot system with multiple "
                "operating systems).  Changing values can often indicate a client "
                "spoofing or MAC cloning attempt.",
                phyid);
	alert_dhcpos_ref =
		alertracker->activate_configured_alert("DHCPOSCHANGE", 
                "The DHCP protocol allows clients to put the host name and "
                "DHCP client / vendor / operating system details in the DHCP "
                "Discovery packet.  These values should old change if the client "
                "has changed drastically (such as a dual-boot system with multiple "
                "operating systems).  Changing values can often indicate a client "
                "spoofing or MAC cloning attempt.",
                phyid);
	alert_adhoc_ref =
		alertracker->activate_configured_alert("ADHOCCONFLICT", 
                "The same SSID is being advertised as an access point and as an "
                "ad-hoc network.  This may indicate a misconfigured or misbehaving "
                "device, or could indicate an attempt at spoofing or an 'evil twin' "
                "attack.",
                phyid);
	alert_ssidmatch_ref =
		alertracker->activate_configured_alert("APSPOOF", 
                "Kismet may be given a list of authorized MAC addresses for "
                "a SSID.  If a beacon or probe response is seen from a MAC address "
                "not listed in the authorized list, this alert will be raised.",
                phyid);
	alert_dot11d_ref =
		alertracker->activate_configured_alert("DOT11D", 
                "Conflicting 802.11d (country code) data has been advertised by the "
                "same SSID.  It is unlikely this is a normal configuration change, "
                "and can indicate a spoofed or 'evil twin' network, or an attempt "
                "to perform a denial of service on clients by restricting their "
                "frequencies.  802.11d has been phased out and is unlikely to be "
                "seen on modern devices, but it is still supported by many systems.",
                phyid);
	alert_beaconrate_ref =
		alertracker->activate_configured_alert("BEACONRATE", 
                "The advertised beacon rate of a SSID has changed.  In an "
                "enterprise or multi-SSID environment this may indicate a normal "
                "configuration change, but can also indicate a spoofed or "
                "'evil twin' network.",
                phyid);
	alert_cryptchange_ref =
		alertracker->activate_configured_alert("ADVCRYPTCHANGE", 
                "A SSID has changed the advertised supported encryption standards.  "
                "This may be a normal change when reconfiguring an access point, "
                "but can also indicate a spoofed or 'evil twin' attack.",
                phyid);
	alert_malformmgmt_ref =
		alertracker->activate_configured_alert("MALFORMMGMT", 
                "Malformed management frames may indicate errors in the capture "
                "source driver (such as not discarding corrupted packets), but can "
                "also be indicative of an attempted attack against drivers which may "
                "not properly handle malformed frames.",
                phyid);
	alert_wpsbrute_ref =
		alertracker->activate_configured_alert("WPSBRUTE", 
                "Excessive WPS events may indicate a malformed client, or an "
                "attack on the WPS system by a tool such as Reaver.",
                phyid);
    alert_l33t_ref = 
        alertracker->activate_configured_alert("KARMAOUI",
                "Probe responses from MAC addresses with an OUI of 00:13:37 often "
                "indicate an Karma AP impersonation attack.",
                phyid);
    alert_tooloud_ref =
        alertracker->activate_configured_alert("OVERPOWERED",
                "Signal levels are abnormally high, when using an external amplifier "
                "this could indicate that the gain is too high.  Over-amplified signals "
                "may miss packets entirely.",
                phyid);
    alert_nonce_zero_ref =
        alertracker->activate_configured_alert("NONCEDEGRADE",
                "A WPA handshake with an empty NONCE was observed; this could indicate "
                "a WPA degradation attack such as the vanhoefm attack against BSD "
                "(https://github.com/vanhoefm/blackhat17-pocs/tree/master/openbsd)",
                phyid);
    alert_nonce_duplicate_ref =
        alertracker->activate_configured_alert("NONCEREUSE",
                "A WPA handshake has attempted to re-use a previous nonce value; this may "
                "indicate an attack against the WPA keystream such as the vanhoefm "
                "KRACK attack (https://www.krackattacks.com/)");
    alert_atheros_wmmtspec_ref =
        alertracker->activate_configured_alert("WMMTSPEC",
                "Too many WMMTSPEC options were seen in a probe response; this "
                "may be triggered by CVE-2017-11013 as described at "
                "https://pleasestopnamingvulnerabilities.com/");
    alert_atheros_rsnloop_ref =
        alertracker->activate_configured_alert("RSNLOOP",
                "Invalid RSN (802.11i) tags in beacon frames can be used to cause "
                "loops in some Atheros drivers, as described in "
                "CVE-2017-9714 and https://pleasestopnamingvulnerabilities.com/");
    alert_11kneighborchan_ref =
        alertracker->activate_configured_alert("BCOM11KCHAN",
                "Invalid channels in 802.11k neighbor report frames "
                "can be used to exploit certain Broadcom HardMAC implementations, typically used "
                "in mobile devices, as described in "
                "https://bugs.chromium.org/p/project-zero/issues/detail?id=1289");
    alert_bssts_ref =
        alertracker->activate_configured_alert("BSSTIMESTAMP",
                "Access points transmit a high-precision millisecond timestamp to "
                "coordinate power saving and other time-sensitive events.  Out-of-sequence "
                "timestamps may indicate spoofing or an 'evil twin' style attack.");
    alert_probechan_ref =
        alertracker->activate_configured_alert("PROBECHAN",
                "Probe responses may include the Wi-Fi channel; this ought to be "
                "identical to the channel advertised in the beacon.  Incorrect channels "
                "in the probe response may indicate a spoofing or 'evil twin' style attack, "
                "but can also be indicative of a misbehaving access point or repeater.");
    alert_qcom_extended_ref =
        alertracker->activate_configured_alert("QCOMEXTENDED",
                "IE 127 Extended Capabilities tags should always be 8 bytes; Some versions "
                "of the Qualcomm drivers are vulnerable to a buffer overflow resulting in "
                "execution on the host, as detailed in CVE-2019-10539.");
    alert_bad_fixlen_ie =
        alertracker->activate_configured_alert("BADFIXLENIE",
                "IE tags contain nested information in beacon and other management frames. "
                "Some IE tags have constant fixed lengths; a tag advertising with the "
                "incorrect length may indicate an attempted buffer overflow attack.  "
                "Specific attacks have their own alerts; this indicates a general, but "
                "otherwise unknown, malformed tag.");
    alert_rtlwifi_p2p_ref =
        alertracker->activate_configured_alert("RTLWIFIP2P",
                "A bug in the Linux RTLWIFI P2P parsers could result in a crash "
                "or potential code execution due to malformed notification of "
                "absence records, as detailed in CVE-2019-17666");
    alert_deauthflood_ref =
        alertracker->activate_configured_alert("DEAUTHFLOOD",
                "By spoofing disassociate or deauthenticate packets, an attacker "
                "may disconnect clients from a network which does not support "
                "management frame protection (MFP); This can be used to cause a "
                "denial of service or to disconnect clients in an attempt to "
                "capture handshakes for attacking WPA.",
                phyid);
    alert_noclientmfp_ref =
        alertracker->activate_configured_alert("NOCLIENTMFP",
                "Client does not support management frame protection (MFP); By spoofing "
                "disassociate or deauthenticate packets, an attacker may disconnect it "
                "from a network. This can be used to cause a denial of service or to "
                "disconnect it in an attempt to capture handshakes for attacking WPA.",
                phyid);

    alert_rtl8195_vdoo_ref =
        alertracker->activate_configured_alert("RTL8195VD1406",
                "Realtek 8195 devices have multiple vulnerabilities in how EAPOL packets "
                "are processed, leading to code execution as the kernel on the device, as "
                "detailed in CVE-2020-9395 and VD-1406 and VD-1407");


    // Threshold
    signal_too_loud_threshold = 
        Globalreg::globalreg->kismet_config->fetch_opt_int("dot11_max_signal", -10);

    // Do we process the whole data packet?
    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("hidedata", 0) ||
            Globalreg::globalreg->kismet_config->fetch_opt_bool("dontbeevil", 0)) {
        _MSG("hidedata= set in Kismet config.  Kismet will ignore the contents "
                "of data packets entirely", MSGFLAG_INFO);
        dissect_data = 0;
    } else {
        dissect_data = 1;
    }

    // Do we process phy and control frames?  They seem to be the glitchiest
    // on many cards including the ath9k which is otherwise excellent
    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_process_phy", 0)) {
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

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_ap_signal_from_beacon", true)) {
        _MSG_INFO("PHY80211 will only process AP signal levels from beacons");
    } 

	dissect_strings = 0;
	dissect_all_strings = 0;

	// Load the wep keys from the config file
	if (load_wepkeys() < 0) {
        Globalreg::globalreg->fatal_condition = 1;
		return;
	}

    // TODO turn into REST endpoint
    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("allowkeytransmit", 0)) {
        _MSG("Allowing Kismet clients to view WEP keys", MSGFLAG_INFO);
        client_wepkey_allowed = 1;
    } else {
		client_wepkey_allowed = 0;
	}

	// Build the wep identity
	for (unsigned int wi = 0; wi < 256; wi++)
		wep_identity[wi] = wi;

    // Set up the device timeout
    device_idle_expiration =
        Globalreg::globalreg->kismet_config->fetch_opt_int("tracker_device_timeout", 0);

    if (device_idle_expiration != 0) {
        device_idle_min_packets =
            Globalreg::globalreg->kismet_config->fetch_opt_uint("tracker_device_packets", 0);

        std::stringstream ss;
        ss << "Removing 802.11 device info which has been inactive for more than " <<
            device_idle_expiration << " seconds";

        if (device_idle_min_packets > 2) 
            ss << " and references fewer than " << device_idle_min_packets << " packets";

        _MSG(ss.str(), MSGFLAG_INFO);

        device_idle_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 60, NULL, 1, this);
    } else {
        device_idle_timer = -1;
    }

    ssidtracker = phy_80211_ssid_tracker::create_dot11_ssidtracker();

    // Set up the de-duplication list
    recent_packet_checksums_sz = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("packet_dedup_size", 2048);
    recent_packet_checksums = new std::atomic<uint32_t>[recent_packet_checksums_sz];
    for (unsigned int x = 0; x < recent_packet_checksums_sz; x++) {
        recent_packet_checksums[x] = 0;
    }
    recent_packet_checksum_pos = 0;

    // Parse the ssid regex options
    auto apspoof_lines = Globalreg::globalreg->kismet_config->fetch_opt_vec("apspoof");

    for (const auto& l : apspoof_lines) {
        size_t cpos = l.find(':');
        
        if (cpos == std::string::npos) {
            _MSG("Invalid 'apspoof' configuration line, expected 'name:ssid=\"...\","  
                    "validmacs=\"...\" but got '" + l + "'", MSGFLAG_ERROR);
            continue;
        }

        std::string name = l.substr(0, cpos);

        std::vector<opt_pair> optvec;
        string_to_opts(l.substr(cpos + 1, l.length()), ",", &optvec);

        std::string ssid = fetch_opt("ssid", &optvec);

        if (ssid == "") {
            _MSG("Invalid 'apspoof' configuration line, expected 'name:ssid=\"...\","  
                    "validmacs=\"...\" but got '" + l + "'", MSGFLAG_ERROR);
            continue;
        }

        std::vector<mac_addr> macvec;
        for (const auto& m : str_tokenize(fetch_opt("validmacs", &optvec), ",", true)) {
            mac_addr ma(m);

            if (ma.state.error) {
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

        auto ssida =
            entrytracker->get_shared_instance_as<dot11_tracked_ssid_alert>(ssid_regex_vec_element_id);

        try {
            ssida->set_group_name(name);
            ssida->set_regex(ssid);
            ssida->set_allowed_macs(macvec);
        } catch (std::runtime_error &e) {
            _MSG("Invalid 'apspoof' configuration line '" + l + "': " + e.what(),
                    MSGFLAG_ERROR);
            continue;
        }

        ssid_regex_vec->push_back(ssida);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_fingerprint_devices", true)) {
        auto fingerprint_s = 
            Globalreg::globalreg->kismet_config->fetch_opt_dfl("dot11_beacon_ie_fingerprint",
                    "0,1,45,48,50,61,74,127,191,195,221-00156D-00,221-0050F2-2,221-001018-2,221-506F9A-28");
        auto fingerprint_v = quote_str_tokenize(fingerprint_s, ",");

        unsigned int t1, t2, t3;

        for (const auto& i : fingerprint_v) {
            if (sscanf(i.c_str(), "%u-%x-%u", &t1, &t2, &t3) == 3) {
                auto tp = std::tuple<uint8_t, uint32_t, uint8_t>{t1, t2, t3};
                beacon_ie_fingerprint_list.push_back(tp);
            } else {
                if (sscanf(i.c_str(), "%u", &t1) == 1) {
                    if (t1 > 255) {
                        _MSG_ERROR("Invalid IE tag number (>255) in dot11_beacon_ie_fingerprint, skipping.  This "
                                "may cause errors in device fingerprinting.");
                        continue;
                    }

                    auto tp = std::tuple<uint8_t, uint32_t, uint8_t>{t1, 0, 0};
                    beacon_ie_fingerprint_list.push_back(tp);
                } else {
                    _MSG_ERROR("Invalid IE tag entry in dot11_beacon_ie_fingerprint, skipping.  This "
                            "may cause errors in device fingerprinting.");
                    continue;
                }
            }
        }

        auto pfingerprint_s = 
            Globalreg::globalreg->kismet_config->fetch_opt_dfl("dot11_probe_ie_fingerprint",
                    "1,50,59,107,127,221-001018-2,221-00904c-51");
        auto pfingerprint_v = quote_str_tokenize(pfingerprint_s, ",");

        for (const auto& i : pfingerprint_v) {
            if (sscanf(i.c_str(), "%u-%x-%u", &t1, &t2, &t3) == 3) {
                auto tp = std::tuple<uint8_t, uint32_t, uint8_t>{t1, t2, t3};
                probe_ie_fingerprint_list.push_back(tp);
            } else {
                if (sscanf(i.c_str(), "%u", &t1) == 1) {
                    auto tp = std::tuple<uint8_t, uint32_t, uint8_t>{t1, 0, 0};
                    probe_ie_fingerprint_list.push_back(tp);
                } else {
                    _MSG_ERROR("Invalid IE tag entry in dot11_probe_ie_fingerprint config, skipping.  This "
                            "may cause errors in device fingerpriting.");
                    continue;
                }
            }
        }
    }

    keep_ie_tags_per_bssid = 
        Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_keep_ietags", false);
    if (keep_ie_tags_per_bssid)
        _MSG_INFO("Keeping a copy of advertised IE tags for each SSID; this can use more CPU and RAM.");


    keep_eapol_packets =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_keep_eapol", true);
    if (keep_eapol_packets)
        _MSG_INFO("Keeping EAPOL packets in memory for easy download and WIDS functionality; this can use "
                "more RAM.");
    else
        _MSG_INFO("Not keeping EAPOL packets in memory, EAP replay WIDS and handshake downloads will not "
                "be available.");

    // access-point view
    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("dot11_view_accesspoints", true)) {
        ap_view = 
            std::make_shared<device_tracker_view>("phydot11_accesspoints", 
                    "IEEE802.11 Access Points",
                    [this](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                    auto dot11 =
                        dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                    if (dot11 == nullptr)
                        return false;

                    if (dot11->get_type_set() & (DOT11_DEVICE_TYPE_BEACON_AP | DOT11_DEVICE_TYPE_PROBE_AP |
                                DOT11_DEVICE_TYPE_ADHOC))
                        return true;

                    return false;
                    },
                    [this](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                    auto dot11 =
                        dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                    if (dot11 == nullptr)
                        return false;

                    if (dot11->get_type_set() & (DOT11_DEVICE_TYPE_BEACON_AP | DOT11_DEVICE_TYPE_PROBE_AP |
                                DOT11_DEVICE_TYPE_ADHOC))
                        return true;

                    return false;
                    });
        devicetracker->add_view(ap_view);

        bss_ts_group_usec = Globalreg::globalreg->kismet_config->fetch_opt_ulong("dot11_related_bss_window", 10'000'000);
    } else {
        _MSG_INFO("Phy80211 access point views are turned off; this will prevent matching related devices by timestamp "
                "and other features.");
    }

    // Register js module for UI
    std::shared_ptr<kis_httpd_registry> httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>();
    httpregistry->register_js_module("kismet_ui_dot11", "js/kismet.ui.dot11.js");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/phy/phy80211/clients-of/:key/clients", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto cl = std::make_shared<tracker_element_vector>();
                    auto key = string_to_n<device_key>(con->uri_params()[":key"]);

                    if (key.get_error())
                        throw std::runtime_error("invalid key");

                    auto dev = devicetracker->fetch_device(key);

                    if (dev == nullptr)
                        return cl;

                    auto dot11 = dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                    if (dot11 == nullptr)
                        return cl;

                    for (const auto& ci : *dot11->get_associated_client_map()) {
                        auto dk = std::static_pointer_cast<tracker_element_device_key>(ci.second);
                        auto d = devicetracker->fetch_device(dk->get());
                        if (d != nullptr)
                            cl->push_back(d);
                    }

                    return cl;
                }));

    httpd->register_route("/phy/phy80211/related-to/:key/devices", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto cl = std::make_shared<tracker_element_vector>();
                    auto key = string_to_n<device_key>(con->uri_params()[":key"]);

                    if (key.get_error())
                        throw std::runtime_error("invalid key");

                    auto dev = devicetracker->fetch_device(key);

                    if (dev == nullptr)
                        return cl;

                    auto dot11 = dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                    if (dot11 == nullptr)
                        return cl;

                    // Make a map of devices we've already looked at
                    std::map<device_key, bool> seen_nodes;

                    std::function<void (std::shared_ptr<kis_tracked_device_base>)> find_clients = 
                        [&](std::shared_ptr<kis_tracked_device_base> dev) {

                        /*
                        kis_unique_lock<kis_mutex> lk_list(devicetracker->get_devicelist_mutex(),
                                std::defer_lock, "/phy/phy80211/related-to/devices find_clients");
                        kis_unique_lock<kis_mutex> lk_device(dev->device_mutex,
                                std::defer_lock, "/phy/phy80211/related-to/devices find_clients");
                        std::lock(lk_list, lk_device);
                        */

                        kis_unique_lock<kis_mutex> lk_device(dev->device_mutex,
                                "/phy/phy80211/related-to/devices find_clients");

                        // Don't add non-dot11 devices
                        auto dot11 =
                            dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                        if (dot11 == nullptr)
                            return;

                        // Don't add devices we've already added
                        if (seen_nodes.find(dev->get_key()) != seen_nodes.end())
                            return;

                        // Add this device
                        seen_nodes[dev->get_key()] = true;
                        cl->push_back(dev);

                        // For every client, repeat, looking for associated clients and shard APs
                        for (const auto& ci : *dot11->get_associated_client_map()) {
                            auto dk = std::static_pointer_cast<tracker_element_device_key>(ci.second);
                            auto d = devicetracker->fetch_device(dk->get());

                            if (d != nullptr)
                                find_clients(d);
                        }
                    };

                    find_clients(dev);

                    return cl;
                }));

    httpd->register_route("/phy/phy80211/by-key/:key/pcap/handshake", {"GET"}, httpd->RO_ROLE, {"pcap"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto key = string_to_n<device_key>(con->uri_params()[":key"]);

                    if (key.get_error())
                        throw std::runtime_error("invalid key");

                    auto dev = devicetracker->fetch_device(key);

                    if (dev == nullptr)
                        throw std::runtime_error("unknown device");

                    auto dot11 = dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                    if (dot11 == nullptr)
                        throw std::runtime_error("not an 802.11 device");

                    con->set_target_file(fmt::format("{}-handshake.pcap", dev->get_macaddr()));

                    return generate_handshake_pcap(con, dev, dot11, "handshake");
                }));

    httpd->register_route("/phy/phy80211/by-key/:key/pcap/handshake-pmkid", {"GET"}, httpd->RO_ROLE, {"pcap"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto key = string_to_n<device_key>(con->uri_params()[":key"]);

                    if (key.get_error())
                        throw std::runtime_error("invalid key");

                    auto dev = devicetracker->fetch_device(key);

                    if (dev == nullptr)
                        throw std::runtime_error("unknown device");

                    auto dot11 = dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                    if (dot11 == nullptr)
                        throw std::runtime_error("not an 802.11 device");

                    con->set_target_file(fmt::format("{}-pmkid.pcap", dev->get_macaddr()));
                    return generate_handshake_pcap(con, dev, dot11, "pmkid");
                }));

    httpd->register_route("/phy/phy80211/pcap/by-bssid/:mac/packets.pcapng", {"GET"}, httpd->RO_ROLE, {"pcapng"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto mac = string_to_n<mac_addr>(con->uri_params()[":mac"]);

                    if (mac.error())
                        throw std::runtime_error("invalid mac");

                    auto pcapng = std::make_shared<pcapng_stream_packetchain>(con->response_stream(),
                            [this, mac](kis_packet *packet) -> bool {
                                auto dot11info = packet->fetch<dot11_packinfo>(pack_comp_80211);

                                if (dot11info == nullptr)
                                    return false;

                                if (dot11info->bssid_mac == mac)
                                    return true;

                                return true;
                            },
                            nullptr,
                            1024*512);
        
                    con->clear_timeout();
                    con->set_target_file(fmt::format("kismet-80211-bssid-{}.pcapng", mac));
                    con->set_closure_cb([pcapng]() { pcapng->stop_stream("http connection lost"); });

                    auto sid = 
                        streamtracker->register_streamer(pcapng, fmt::format("kismet-80211-bssid{}.pcapng", mac),
                            "pcapng", "httpd", 
                            fmt::format("pcapng of packets for phy80211 bssid  {}", mac));

                    pcapng->start_stream();
                    pcapng->block_until_stream_done();

                    streamtracker->remove_streamer(sid);
                }));

}

kis_80211_phy::~kis_80211_phy() {
	packetchain->remove_handler(&phydot11_packethook_wep, CHAINPOS_DECRYPT);
	packetchain->remove_handler(&phydot11_packethook_dot11, CHAINPOS_LLCDISSECT);
	packetchain->remove_handler(&packet_dot11_common_classifier, CHAINPOS_CLASSIFIER);

    timetracker->remove_timer(device_idle_timer);

    delete[] recent_packet_checksums;
}

const std::string kis_80211_phy::khz_to_channel(const double in_khz) {
    if (in_khz == 0)
        throw std::runtime_error("invalid freq");

    int mhz = in_khz / 1000;

    if (mhz == 2484)
        return "14";
    else if (mhz < 2484)
        return fmt::format("{}", (mhz - 2407) / 5);
    else if (mhz >= 4910 && mhz <= 4980)
        return fmt::format("{}", (mhz - 4000) / 5);
    else if (mhz <= 45000)
        return fmt::format("{}", (mhz - 5000) / 5);
    else if (mhz >= 58320 && mhz <= 64800)
        return fmt::format("{}", (mhz - 56160) / 2160);
    else
        return fmt::format("{}", mhz);
}

int kis_80211_phy::load_wepkeys() {
    // Convert the WEP mappings to our real map
    std::vector<std::string> raw_wepmap_vec;
    raw_wepmap_vec = Globalreg::globalreg->kismet_config->fetch_opt_vec("wepkey");
    for (size_t rwvi = 0; rwvi < raw_wepmap_vec.size(); rwvi++) {
        std::string wepline = raw_wepmap_vec[rwvi];

        size_t rwsplit = wepline.find(",");
        if (rwsplit == std::string::npos) {
            _MSG("Malformed 'wepkey' option in the config file", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
			return -1;
        }

        mac_addr bssid_mac = wepline.substr(0, rwsplit).c_str();

        if (bssid_mac.state.error == 1) {
            _MSG("Malformed 'wepkey' option in the config file", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
			return -1;
        }

        std::string rawkey = wepline.substr(rwsplit + 1, wepline.length() - (rwsplit + 1));

        unsigned char key[WEPKEY_MAX];
        int len = hex_to_uchar((unsigned char *) rawkey.c_str(), key);

        if (len != 5 && len != 13 && len != 16) {
			_MSG("Invalid key '" + rawkey + "' length " + int_to_string(len) + 
				 " in a wepkey= config file entry", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
			return -1;
        }

        dot11_wep_key *keyinfo = new dot11_wep_key;
        keyinfo->bssid = bssid_mac;
        keyinfo->fragile = 0;
        keyinfo->decrypted = 0;
        keyinfo->failed = 0;
        keyinfo->len = len;
        memcpy(keyinfo->key, key, sizeof(unsigned char) * WEPKEY_MAX);

        wepkeys.insert(std::make_pair(bssid_mac, keyinfo));

        _MSG_INFO("Using key '{}' for BSSID '{}'", rawkey, bssid_mac);
    }

	return 1;
}

// Common classifier responsible for generating the common devices & mapping wifi packets
// to those devices
int kis_80211_phy::packet_dot11_common_classifier(CHAINCALL_PARMS) {
    // packetnum++;

    kis_80211_phy *d11phy = (kis_80211_phy *) auxdata;

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


    if (pack_l1info != NULL && pack_l1info->signal_dbm > d11phy->signal_too_loud_threshold && 
            pack_l1info->signal_dbm < 0 && 
            d11phy->alertracker->potential_alert(d11phy->alert_tooloud_ref)) {

        std::stringstream ss;

        ss << "Saw packet with a reported signal level of " <<
            pack_l1info->signal_dbm << " which is above the threshold of " <<
            d11phy->signal_too_loud_threshold << ".  Excessively high signal levels can " <<
            "be caused by misconfigured external amplifiers and lead to lost " <<
            "packets.";

        d11phy->alertracker->raise_alert(d11phy->alert_tooloud_ref, in_pack, 
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
    std::shared_ptr<kis_tracked_device_base> receive_dev;
    std::shared_ptr<kis_tracked_device_base> transmit_dev;

    std::shared_ptr<dot11_tracked_device> source_dot11;
    std::shared_ptr<dot11_tracked_device> dest_dot11;
    std::shared_ptr<dot11_tracked_device> bssid_dot11;
    std::shared_ptr<dot11_tracked_device> receive_dot11;
    std::shared_ptr<dot11_tracked_device> transmit_dot11;

    if (dot11info->type == packet_management) {
        // Resolve the common structures of management frames; this is a lot of code
        // copy and paste, but because this happens *every single packet* we probably 
        // don't want to do much more complex object creation
        commoninfo->type = packet_basic_mgmt;
        
        if (dot11info->bssid_mac != Globalreg::globalreg->empty_mac && 
                !(dot11info->bssid_mac.bitwise_and(globalreg->multicast_mac)) ) {

            unsigned int bflags = UCD_UPDATE_SEENBY;

            if (dot11info->source_mac == dot11info->bssid_mac) {
                bflags |= (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | 
                        UCD_UPDATE_LOCATION | UCD_UPDATE_ENCRYPTION);

                if ((d11phy->signal_from_beacon && dot11info->subtype == packet_sub_beacon) ||
                        !d11phy->signal_from_beacon)
                    bflags |= UCD_UPDATE_SIGNAL;
            }

            bssid_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->bssid_mac, d11phy, in_pack, 
                        bflags,
                        "Wi-Fi Device");
        }

        if (dot11info->source_mac != dot11info->bssid_mac &&
                dot11info->source_mac != globalreg->empty_mac && 
                !(dot11info->source_mac.bitwise_and(globalreg->multicast_mac)) ) {

            unsigned int bflags = 
                (UCD_UPDATE_PACKETS | UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION);

            // Only update source signal info if it's TO the AP, don't inherit the AP
            // resending bridged packets
            if (dot11info->distrib == distrib_to)
                bflags |= (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                        UCD_UPDATE_LOCATION);

            source_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->source_mac, d11phy, in_pack, 
                        bflags, "Wi-Fi Device");
        }

        if (dot11info->dest_mac != dot11info->source_mac &&
                dot11info->dest_mac != dot11info->bssid_mac &&
                dot11info->dest_mac != globalreg->empty_mac && 
                !(dot11info->dest_mac.bitwise_and(globalreg->multicast_mac)) ) {

            dest_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->dest_mac, d11phy, in_pack, 
                        (UCD_UPDATE_SEENBY),
                        "Wi-Fi Device (Inferred)");
        }

        auto list_locker = 
            kis_unique_lock<kis_mutex>(d11phy->devicetracker->get_devicelist_mutex(), std::defer_lock);

        // Do we have a worker we have to call later?  We must defer workers until we release the locks
        // on devices
        bool associate_bssts = false;
        bool handle_probed_ssid = false;
        std::function<void ()> handle_probed_ssid_f;

        if (bssid_dev != NULL) {
            kis_lock_guard bssid_lk(bssid_dev->device_mutex, "phy80211 common_classifier");

            bssid_dot11 =
                bssid_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (bssid_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi access point {}",
                        bssid_dev->get_macaddr().mac_to_string());

                bssid_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                dot11_tracked_device::attach_base_parent(bssid_dot11, bssid_dev);

                dot11info->new_device = true;
            }

            bssid_dot11->set_last_bssid(bssid_dev->get_macaddr());

            if (dot11info->channel != "0" && dot11info->channel != "") {
                bssid_dev->set_channel(dot11info->channel);
            } else if (pack_l1info != NULL && (pack_l1info->freq_khz != bssid_dev->get_frequency() ||
                    bssid_dev->get_channel() == "")) {
                try {
                    bssid_dev->set_channel(khz_to_channel(pack_l1info->freq_khz));
                } catch (const std::runtime_error& e) {
                    ;
                }
            }

            // Look at the BSS TS
            if (dot11info->subtype == packet_sub_beacon && dot11info->distrib != distrib_adhoc) {
                auto bsts = bssid_dot11->get_bss_timestamp();
                bssid_dot11->set_bss_timestamp(dot11info->timestamp);

                // If we have a new device, look for related devices; use the apview to search other APs
                if ((bsts == 0 || dot11info->new_device) && d11phy->ap_view != nullptr) {
                    associate_bssts = true;
                }

                uint64_t diff = 0;

                if (dot11info->timestamp < bsts) {
                    diff = bsts - dot11info->timestamp;
                } else {
                    diff = dot11info->timestamp - bsts;
                }

                uint64_t bss_ts_wobble_s = 10;

                if ((uint64_t) bssid_dev->get_last_time() < in_pack->ts.tv_sec - bss_ts_wobble_s) {
                    if (bssid_dot11->last_bss_invalid == 0) {
                        bssid_dot11->last_bss_invalid = time(0);
                        bssid_dot11->bss_invalid_count = 1;
                    } else if (bssid_dot11->last_bss_invalid - time(0) > 5) {
                        bssid_dot11->last_bss_invalid = time(0);
                        bssid_dot11->bss_invalid_count = 1;
                    } else {
                        bssid_dot11->last_bss_invalid = time(0);
                        bssid_dot11->bss_invalid_count++;
                    }

                    if (diff > bss_ts_wobble_s * 1000000L && bssid_dot11->bss_invalid_count > 5) {
                        d11phy->alertracker->raise_alert(d11phy->alert_bssts_ref,
                                in_pack,
                                dot11info->bssid_mac, dot11info->source_mac,
                                dot11info->dest_mac, dot11info->other_mac,
                                dot11info->channel,
                                fmt::format("Network {} BSS timestamp fluctuating.  This may indicate "
                                    "an 'evil twin' style attack where the BSSID of a legitimate AP "
                                    "is being spoofed.", bssid_dev->get_macaddr()));
                    }
                }
            }

            // Detect if we're an adhoc bssid
            if (dot11info->ibss) {
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                bssid_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi Ad-Hoc"));
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_ADHOC);
            } else {
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
                bssid_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi AP"));
            }

            // Do some maintenance on the bssid device if we're a beacon or other ssid-carrying
            // packet...

            if (dot11info->subtype == packet_sub_beacon) {
                d11phy->handle_ssid(bssid_dev, bssid_dot11, in_pack, dot11info, pack_gpsinfo);
                bssid_dot11->set_last_beacon_timestamp(in_pack->ts.tv_sec);
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_BEACON_AP);
            } else if (dot11info->subtype == packet_sub_probe_resp) {
                d11phy->handle_ssid(bssid_dev, bssid_dot11, in_pack, dot11info, pack_gpsinfo);
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_PROBE_AP);
            }

            d11phy->devicetracker->update_view_device(bssid_dev);
        }

        if (source_dev != NULL) {
            kis_lock_guard source_lk(source_dev->device_mutex, "phy80211 common_classifier");

            source_dot11 =
                source_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (source_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}",
                        source_dev->get_macaddr().mac_to_string());

                source_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                dot11_tracked_device::attach_base_parent(source_dot11, source_dev);

                dot11info->new_device = true;
            }

            if (bssid_dev != nullptr) {
                source_dot11->set_last_bssid(bssid_dev->get_macaddr());
            } else {
                source_dot11->set_last_bssid(mac_addr());
            }

            if (dot11info->channel != "0" && dot11info->channel != "") {
                source_dev->set_channel(dot11info->channel);
            } else if (pack_l1info != NULL && (pack_l1info->freq_khz != source_dev->get_frequency() ||
                    source_dev->get_channel() == "")) {
                try {
                    source_dev->set_channel(khz_to_channel(pack_l1info->freq_khz));
                } catch (const std::runtime_error& e) {
                    ;
                }
            }

            // If it's sending ibss-flagged packets it's got to be adoc
            if (dot11info->ibss) {
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                source_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi Ad-Hoc"));
                source_dot11->bitset_type_set(DOT11_DEVICE_TYPE_ADHOC);
            } else {
                // If it's the source of a mgmt packet, it's got to be a wifi device of 
                // some sort and not just bridged
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);
                source_dev->set_type_string_ifnot([d11phy]() { 
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi Client"); 
                        }, KIS_DEVICE_BASICTYPE_CLIENT);
            }

            if (dot11info->subtype == packet_sub_probe_req ||
                    dot11info->subtype == packet_sub_association_req ||
                    dot11info->subtype == packet_sub_reassociation_req) {
                handle_probed_ssid = true;
                // d11phy->handle_probed_ssid(source_dev, source_dot11, in_pack, dot11info, pack_gpsinfo);
            }

            d11phy->devicetracker->update_view_device(source_dev);
        }

        if (dest_dev != NULL) {
            kis_lock_guard dest_lk(dest_dev->device_mutex, "phy80211 common_classifier");

            dest_dot11 =
                dest_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (dest_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}", dest_dev->get_macaddr());

                dest_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                dot11_tracked_device::attach_base_parent(dest_dot11, dest_dev);
                
                dot11info->new_device = true;
            }

            // If it's receiving a management packet, it must be a wifi device
            dest_dev->bitclear_basic_type_set(KIS_DEVICE_BASICTYPE_WIRED);
            dest_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);
            dest_dev->set_type_string_ifnot([d11phy]() {
                    return d11phy->devicetracker->get_cached_devicetype("Wi-Fi Client");
                    }, KIS_DEVICE_BASICTYPE_AP);

            d11phy->devicetracker->update_view_device(dest_dev);
        }

        // Safety check that our BSSID device exists
        if (bssid_dev != NULL) {
            // Perform multi-device correlation under devicelist lock
            
            list_locker.lock();
            // Now we've instantiated and mapped all the possible devices and dot11 devices; now
            // populate the per-client records for any which have mgmt communication
            
            if (source_dev != NULL)
                d11phy->process_client(bssid_dev, bssid_dot11, source_dev, source_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);

            if (dest_dev != NULL) {
                if (dot11info->type == packet_management && 
                        dot11info->subtype == packet_sub_probe_resp) {
                    // Don't map probe respsonses as clients
                } else {
                    d11phy->process_client(bssid_dev, bssid_dot11, dest_dev, dest_dot11, 
                            in_pack, dot11info, pack_gpsinfo, pack_datainfo);
                }
            }

            // Look for DEAUTH floods
            if (bssid_dot11 != NULL && (dot11info->subtype == packet_sub_disassociation ||
                    dot11info->subtype == packet_sub_deauthentication)) {
                // if we're w/in time of the last one, update, otherwise clear
                if (globalreg->timestamp.tv_sec - bssid_dot11->get_client_disconnects_last() > 1)
                    bssid_dot11->set_client_disconnects(1);
                else
                    bssid_dot11->inc_client_disconnects(1);

                bssid_dot11->set_client_disconnects_last(globalreg->timestamp.tv_sec);

                if (bssid_dot11->get_client_disconnects() > 10) {
                    if (d11phy->alertracker->potential_alert(d11phy->alert_deauthflood_ref)) {
                        std::string al = "Deauth/Disassociate flood on " + dot11info->bssid_mac.mac_to_string();

                        d11phy->alertracker->raise_alert(d11phy->alert_deauthflood_ref, in_pack,
                            dot11info->bssid_mac, dot11info->source_mac,
                            dot11info->dest_mac, dot11info->other_mac,
                            dot11info->channel, al);
                    }

                    bssid_dot11->set_client_disconnects(1);
                }
            }

            // alerts on broadcast deauths
            if  ((dot11info->subtype == packet_sub_disassociation ||
                        dot11info->subtype == packet_sub_deauthentication) &&
                    dot11info->dest_mac == globalreg->broadcast_mac &&
                    d11phy->alertracker->potential_alert(d11phy->alert_bcastdcon_ref)) {

                std::string al = "IEEE80211 Access Point BSSID " +
                    bssid_dev->get_macaddr().mac_to_string() + " broadcast deauthentication or "
                    "disassociation of all clients; Either the  AP is shutting down or there "
                    "is a possible denial of service.";

                d11phy->alertracker->raise_alert(d11phy->alert_bcastdcon_ref, in_pack, 
                        dot11info->bssid_mac, dot11info->source_mac, 
                        dot11info->dest_mac, dot11info->other_mac, 
                        dot11info->channel, al);
            }

            list_locker.unlock();
        }

        // BSSTS relationship worker
        if (associate_bssts) {
            auto bss_worker = 
                device_tracker_view_function_worker([in_pack, dot11info, d11phy, bssid_dev](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                        auto bssid_dot11 =
                            dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                        if (bssid_dot11 == nullptr)
                            return false;

                        if (dev->get_key() == bssid_dev->get_key())
                            return false;

                        auto bsts = bssid_dot11->get_bss_timestamp();
                        auto last_time = dev->get_last_time();

                        // Guesstimate the time shift from the last time we saw the AP to now, at
                        // second precision
                        if (last_time < in_pack->ts.tv_sec)
                            bsts += (in_pack->ts.tv_sec - last_time) * 1'000'000;
                        else
                            bsts -= (last_time - in_pack->ts.tv_sec) * 1'000'000;

                        uint64_t diff;

                        if (dot11info->timestamp < bsts)
                            diff = bsts - dot11info->timestamp;
                        else
                            diff = dot11info->timestamp - bsts;

                        return diff < d11phy->bss_ts_group_usec;
                });

            // We have to do write work because we're still holding the device list 
            // write state 
            d11phy->ap_view->do_device_work(bss_worker);

            // Lock the bssid device and set all the relationships
            kis_unique_lock bssid_lk(bssid_dev->device_mutex, std::defer_lock, "phy80211 common_classifier bssts agg");
            bssid_lk.lock();
            for (const auto& ri : *(bss_worker.getMatchedDevices())) {
                auto rdev = std::static_pointer_cast<kis_tracked_device_base>(ri);
                bssid_dev->add_related_device("dot11_bssts_similar", rdev->get_key());
            }
            bssid_lk.unlock();

            // Assign the reverse map for each device under individual lock
            for (const auto& ri : *(bss_worker.getMatchedDevices())) {
                auto rdev = std::static_pointer_cast<kis_tracked_device_base>(ri);

                kis_lock_guard<kis_mutex> lg(rdev->device_mutex);
                rdev->add_related_device("dot11_bssts_similar", bssid_dev->get_key());
            }
        }

        // Reap the async ssid probe outside of lock
        if (handle_probed_ssid)
            d11phy->handle_probed_ssid(source_dev, source_dot11, in_pack, dot11info, pack_gpsinfo);

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

            unsigned int bflags = UCD_UPDATE_SEENBY;

            if (dot11info->source_mac == dot11info->bssid_mac) {
                bflags |= (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | 
                        UCD_UPDATE_LOCATION | UCD_UPDATE_ENCRYPTION | UCD_UPDATE_SEENBY);

                if (!d11phy->signal_from_beacon)
                    bflags |= UCD_UPDATE_SIGNAL;
            }

            bssid_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->bssid_mac, d11phy, in_pack, 
                        (update_flags | bflags),
                        "Wi-Fi Device");
        }

        if (dot11info->source_mac != dot11info->bssid_mac &&
                dot11info->source_mac != globalreg->empty_mac && 
                !(dot11info->source_mac.bitwise_and(globalreg->multicast_mac)) ) {

            unsigned int bflags = 
                (UCD_UPDATE_PACKETS | UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION);

            // Only update source signal info if it's TO the AP, don't inherit the AP
            // resending bridged packets
            if (dot11info->distrib == distrib_to)
                bflags |= (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                        UCD_UPDATE_LOCATION);

            source_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->source_mac, d11phy, in_pack, 
                        (update_flags | bflags), "Wi-Fi Device");
        }

        if (dot11info->dest_mac != dot11info->source_mac &&
                dot11info->dest_mac != dot11info->bssid_mac &&
                dot11info->dest_mac != globalreg->empty_mac && 
                !(dot11info->dest_mac.bitwise_and(globalreg->multicast_mac)) ) {

            dest_dev =
                d11phy->devicetracker->update_common_device(commoninfo,
                        dot11info->dest_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_SEENBY | UCD_UPDATE_PACKETS),
                        "Wi-Fi Device (Inferred)");
        }

        // WDS transmitter acts like a BSSID, update its signal and location
        if (dot11info->transmit_mac != dot11info->source_mac &&
                dot11info->transmit_mac != dot11info->dest_mac &&
                dot11info->transmit_mac != dot11info->bssid_mac &&
                dot11info->transmit_mac != globalreg->empty_mac && 
                !(dot11info->transmit_mac.bitwise_and(globalreg->multicast_mac)) ) {

            transmit_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->transmit_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_FREQUENCIES | UCD_UPDATE_LOCATION |
                         UCD_UPDATE_ENCRYPTION | UCD_UPDATE_SEENBY | UCD_UPDATE_PACKETS),
                        "Wi-Fi Device");
        }

        if (dot11info->receive_mac != dot11info->source_mac &&
                dot11info->receive_mac != dot11info->dest_mac &&
                dot11info->receive_mac != dot11info->bssid_mac &&
                dot11info->receive_mac != globalreg->empty_mac && 
                !(dot11info->receive_mac.bitwise_and(globalreg->multicast_mac)) ) {

            receive_dev =
                d11phy->devicetracker->update_common_device(commoninfo, 
                        dot11info->receive_mac, d11phy, in_pack, 
                        (update_flags | UCD_UPDATE_SEENBY | UCD_UPDATE_PACKETS),
                        "Wi-Fi Device");
        }

        auto list_locker = 
            kis_unique_lock<kis_mutex>(d11phy->devicetracker->get_devicelist_mutex(), std::defer_lock,
                    "phy80211 common_classifier");

        if (bssid_dev != NULL) {
            kis_lock_guard bssid_lk(bssid_dev->device_mutex, "phy80211 common_classifier");

            bssid_dot11 =
                bssid_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

            std::stringstream newdevstr;

            if (bssid_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}",
                        bssid_dev->get_macaddr().mac_to_string());

                bssid_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                dot11_tracked_device::attach_base_parent(bssid_dot11, bssid_dev);

                dot11info->new_device = true;
            }

            bssid_dot11->set_last_bssid(bssid_dev->get_macaddr());

            if (dot11info->channel != "0" && dot11info->channel != "") {
                bssid_dev->set_channel(dot11info->channel);
            } else if (pack_l1info != NULL && (pack_l1info->freq_khz != bssid_dev->get_frequency() ||
                    bssid_dev->get_channel() == "")) {
                try {
                    bssid_dev->set_channel(khz_to_channel(pack_l1info->freq_khz));
                } catch (const std::runtime_error& e) {
                    ;
                }
            }

            if (dot11info->distrib == distrib_adhoc) {
                // Otherwise, we're some sort of adhoc device
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                bssid_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi Ad-Hoc"));
            } else if (dot11info->distrib == distrib_inter) {
                // We don't change the type of the presumed bssid device here because it's not an AP; 
                // not entirely sure how to record this relationship currently
            } else {
                // If we're the bssid, sending an ess data frame, we must be an access point
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
                bssid_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi AP"));

                // Throw alert if device changes between bss and adhoc
                if (bssid_dev->bitcheck_basic_type_set(DOT11_DEVICE_TYPE_ADHOC) &&
                        !bssid_dev->bitcheck_basic_type_set(DOT11_DEVICE_TYPE_BEACON_AP) &&
                        d11phy->alertracker->potential_alert(d11phy->alert_adhoc_ref)) {
                    std::string al = "IEEE80211 Network BSSID " + 
                        dot11info->bssid_mac.mac_to_string() + 
                        " previously advertised as AP network, now advertising as "
                        "Ad-Hoc/WDS which may indicate AP spoofing/impersonation";

                    d11phy->alertracker->raise_alert(d11phy->alert_adhoc_ref, in_pack,
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
            kis_lock_guard source_lk(source_dev->device_mutex, "phy80211 common_classifier");

            source_dot11 =
                source_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (source_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}",
                        source_dev->get_macaddr().mac_to_string());

                source_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                dot11_tracked_device::attach_base_parent(source_dot11, source_dev);

                dot11info->new_device = true;
            }

            if (bssid_dev != nullptr)
                source_dot11->set_last_bssid(bssid_dev->get_macaddr());

            if (dot11info->channel != "0" && dot11info->channel != "") {
                source_dev->set_channel(dot11info->channel);
            } else if (pack_l1info != NULL && (pack_l1info->freq_khz != source_dev->get_frequency() ||
                    source_dev->get_channel() == "")) {
                try {
                    source_dev->set_channel(khz_to_channel(pack_l1info->freq_khz));
                } catch (const std::runtime_error& e) {
                    ;
                }
            }

            if (dot11info->subtype == packet_sub_data_null ||
                    dot11info->subtype == packet_sub_data_qos_null) {
                // Only wireless devices can send null function data
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);
                source_dev->set_type_string_ifnot([d11phy]() {
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi Client");
                        }, KIS_DEVICE_BASICTYPE_AP);
            } else if (dot11info->distrib == distrib_inter) {
                // If it's from the ess, we're some sort of wired device; set the type
                // accordingly
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

                source_dev->set_type_string_ifonly([d11phy]() {
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi WDS Device");
                        }, KIS_DEVICE_BASICTYPE_PEER | KIS_DEVICE_BASICTYPE_DEVICE);
            } else if (dot11info->distrib == distrib_adhoc && dot11info->ibss) {
                // We're some sort of adhoc device
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                source_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi Ad-Hoc"));
            } else if (dot11info->distrib == distrib_from) {
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_WIRED);
                source_dev->set_type_string_ifnot([d11phy]() {
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi Bridged");
                        }, KIS_DEVICE_BASICTYPE_CLIENT | KIS_DEVICE_BASICTYPE_AP);
            } else {
                source_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);

                source_dev->set_type_string_ifnot([d11phy]() {
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi Client");
                        }, KIS_DEVICE_BASICTYPE_AP);
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
            int wps = d11phy->packet_dot11_wps_m3(in_pack);

            if (wps) {
                // if we're w/in time of the last one, update, otherwise clear
                if (globalreg->timestamp.tv_sec - source_dot11->get_wps_m3_last() > (60 * 5))
                    source_dot11->set_wps_m3_count(1);
                else
                    source_dot11->inc_wps_m3_count(1);

                source_dot11->set_wps_m3_last(globalreg->timestamp.tv_sec);

                if (source_dot11->get_wps_m3_count() > 5) {
                    if (d11phy->alertracker->potential_alert(d11phy->alert_wpsbrute_ref)) {
                        std::string al = "IEEE80211 AP " + dot11info->bssid_mac.mac_to_string() +
                            " sending excessive number of WPS messages which may "
                            "indicate a WPS brute force attack such as Reaver";

                        d11phy->alertracker->raise_alert(d11phy->alert_wpsbrute_ref, 
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
            kis_lock_guard dest_lk(dest_dev->device_mutex, "phy80211 common_classifier");

            dest_dot11 =
                dest_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (dest_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}", dest_dev->get_macaddr());

                dest_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

                dot11_tracked_device::attach_base_parent(dest_dot11, dest_dev);

                dot11info->new_device = true;
            }

            // If it's from the ess, we're some sort of wired device; set the type
            // accordingly
            if (dot11info->distrib == distrib_inter) {
                dest_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

                dest_dev->set_type_string_ifonly([d11phy]() {
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi WDS");
                        }, KIS_DEVICE_BASICTYPE_PEER | KIS_DEVICE_BASICTYPE_DEVICE);
            } else if (dot11info->distrib == distrib_adhoc) {
                // Otherwise, we're some sort of adhoc device
                dest_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                dest_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi Ad-Hoc"));
            } else {
                // We can't define the type with only a destination device; we can't
                // call it wired or wireless until it talks itself
                dest_dev->set_type_string_ifonly([d11phy]() {
                        return d11phy->devicetracker->get_cached_devicetype("Wi-Fi Device");
                        }, KIS_DEVICE_BASICTYPE_DEVICE);
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

        // WDS transmitter must be a wifi device, and an AP peer
        if (transmit_dev != NULL) {
            kis_lock_guard transmit_lk(transmit_dev->device_mutex, "phy80211 common_classifier");

            transmit_dot11 =
                transmit_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (transmit_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}", transmit_dev->get_macaddr());

                transmit_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
                
                dot11_tracked_device::attach_base_parent(transmit_dot11, transmit_dev);

                dot11info->new_device = true;
            }

            if (dot11info->channel != "0" && dot11info->channel != "") {
                transmit_dev->set_channel(dot11info->channel);
            } else if (pack_l1info != NULL && (pack_l1info->freq_khz != transmit_dev->get_frequency() ||
                    transmit_dev->get_channel() == "")) {
                try {
                    transmit_dev->set_channel(khz_to_channel(pack_l1info->freq_khz));
                } catch (const std::runtime_error& e) {
                    ;
                }
            }

            transmit_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP | KIS_DEVICE_BASICTYPE_PEER);
            transmit_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi WDS AP"));

            transmit_dot11->inc_datasize(dot11info->datasize);

            if (dot11info->fragmented) {
                transmit_dot11->inc_num_fragments(1);
            }

            if (dot11info->retry) {
                transmit_dot11->inc_num_retries(1);
                transmit_dot11->inc_datasize_retry(dot11info->datasize);
            }
        }

        // WDS receiver must also be a wifi device, and an AP peer
        if (receive_dev != NULL) {
            kis_lock_guard receive_lk(receive_dev->device_mutex, "phy80211 common_classifier");

            receive_dot11 =
                receive_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
            std::stringstream newdevstr;

            if (receive_dot11 == NULL) {
                _MSG_INFO("Detected new 802.11 Wi-Fi device {}", receive_dev->get_macaddr());

                receive_dot11 =
                    d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
                
                dot11_tracked_device::attach_base_parent(receive_dot11, receive_dev);

                dot11info->new_device = true;
            }

            receive_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP | KIS_DEVICE_BASICTYPE_PEER);
            receive_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi WDS AP"));

            receive_dot11->inc_datasize(dot11info->datasize);

            if (dot11info->fragmented) {
                receive_dot11->inc_num_fragments(1);
            }

            if (dot11info->retry) {
                receive_dot11->inc_num_retries(1);
                receive_dot11->inc_datasize_retry(dot11info->datasize);
            }
        }

        if (bssid_dev != NULL) {
            list_locker.lock();

            // Map clients
            if (source_dev != NULL) {
                d11phy->process_client(bssid_dev, bssid_dot11, source_dev, source_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);
                d11phy->process_wpa_handshake(bssid_dev, bssid_dot11, source_dev, source_dot11,
                        in_pack, dot11info);
            }

            if (dest_dev != NULL) {
                d11phy->process_client(bssid_dev, bssid_dot11, dest_dev, dest_dot11, 
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);
                d11phy->process_wpa_handshake(bssid_dev, bssid_dot11, dest_dev, dest_dot11,
                        in_pack, dot11info);
            }

            list_locker.unlock();
        }

        // If we're WDS, link source and dest devices as clients of the transmitting WDS AP
        if (transmit_dev != NULL) {
            list_locker.lock();

            if (source_dev != NULL) 
                d11phy->process_client(transmit_dev, transmit_dot11, source_dev, source_dot11,
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);
            if (dest_dev != NULL)
                d11phy->process_client(transmit_dev, transmit_dot11, source_dev, source_dot11,
                        in_pack, dot11info, pack_gpsinfo, pack_datainfo);

            list_locker.unlock();
        }
    }

    return 1;
}

int kis_80211_phy::packet_dot11_scan_json_classifier(CHAINCALL_PARMS) {
    kis_80211_phy *d11phy = (kis_80211_phy *) auxdata;

    if (in_pack->error || in_pack->filtered || in_pack->duplicate)
        return 0;

    auto pack_json =
        in_pack->fetch<kis_json_packinfo>(d11phy->pack_comp_json);

    if (pack_json == nullptr)
        return 0;

    if (pack_json->type != "DOT11SCAN")
        return 0;

    auto pack_l1info =
        in_pack->fetch<kis_layer1_packinfo>(d11phy->pack_comp_l1info);

    auto commoninfo =
        in_pack->fetch<kis_common_info>(d11phy->pack_comp_common);

    if (commoninfo != nullptr || pack_l1info == nullptr)
        return 0;

    // dot11 json fields - in addition to generic report fields translated into l1/gps/etc
    // "ssid": ssid
    // "bssid": bssid
    // "ietags": tag bytes if available
    // "chanwidth": Channel width as '20', '40', '80', '160', '80+80'
    // "capabilities": Android-style scanresult capabilities description
    // "centerfreq0": Center frequency 0
    // "centerfreq1": Center frequency 1

    try {
        std::stringstream ss(pack_json->json_string);
        Json::Value json;
        ss >> json;

        auto bssid_j = json["bssid"];
        auto ssid_j = json["ssid"];
        auto ietags_j = json["ietags"];
        auto chanwidth_j = json["chanwidth"];
        auto capabilities_j = json["capabilities"];
        auto centerfreq0_j = json["centerfreq0"];
        auto centerfreq1_j = json["centerfreq1"];

        if (bssid_j.isNull()) {
            _MSG_ERROR("Phy80211/Wi-Fi scan report with no BSSID, dropping.");
            in_pack->error = true;
            return 0;
        }

        auto bssid_mac = mac_addr(bssid_j.asString());
        if (bssid_mac.state.error) {
            _MSG_ERROR("Phy80211/Wi-Fi scan report with invalid BSSID, dropping.");
            in_pack->error = true;
            return 0;
        }

        auto ssid_str = std::string();

        if (!ssid_j.isNull())
            ssid_str = munge_to_printable(ssid_j.asString());

        auto ssid_csum = ssid_hash(ssid_str.data(), ssid_str.length());

        commoninfo = new kis_common_info();

        commoninfo->type = packet_basic_mgmt;
        commoninfo->direction = packet_direction_from;
        commoninfo->phyid = d11phy->fetch_phy_id();

        commoninfo->channel = pack_l1info->channel;
        commoninfo->freq_khz = pack_l1info->freq_khz;

        commoninfo->source = bssid_mac;
        commoninfo->network = bssid_mac;
        commoninfo->transmitter = bssid_mac;
        commoninfo->dest = Globalreg::globalreg->broadcast_mac;

        in_pack->insert(d11phy->pack_comp_common, commoninfo);

        auto bssid_dev =
            d11phy->devicetracker->update_common_device(commoninfo, 
                    bssid_mac, d11phy, in_pack, 
                    (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                     UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                     UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                    "Wi-Fi Device");

        /*
        kis_unique_lock lk_list(d11phy->devicetracker->get_devicelist_mutex(), std::defer_lock, "dot11_scan_json_classifier");
        kis_unique_lock lk_device(bssid_dev->device_mutex, std::defer_lock, "dot11_scan_json_classifier");
        std::lock(lk_list, lk_device);
        */
        kis_unique_lock lk_device(bssid_dev->device_mutex, "dot11_scan_json_classifier");

        auto bssid_dot11 =
            bssid_dev->get_sub_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);
        std::stringstream newdevstr;

        if (bssid_dot11 == NULL) {
            _MSG_INFO("Detected new 802.11 Wi-Fi access point {}",
                    bssid_dev->get_macaddr().mac_to_string());

            bssid_dot11 =
                d11phy->entrytracker->get_shared_instance_as<dot11_tracked_device>(d11phy->dot11_device_entry_id);

            dot11_tracked_device::attach_base_parent(bssid_dot11, bssid_dev);
        }

        bssid_dot11->set_last_bssid(bssid_dev->get_macaddr());

        if (pack_l1info->channel != "" && pack_l1info->channel != "0") {
            bssid_dev->set_channel(pack_l1info->channel);
        } else if (pack_l1info->freq_khz != bssid_dev->get_frequency() ||
                bssid_dev->get_channel() == "") {
            try {
                bssid_dev->set_channel(khz_to_channel(pack_l1info->freq_khz));
            } catch (const std::runtime_error& e) {
                ;
            }
        }

        // TODO - handle raw IE tag data once we get some examples of that coming from
        // wpasupplicant scanning mode, ought to be able to reuse the beacon processing
        // system with some modifications, but for now just handle the android capabilities

        uint64_t cryptset = 0;

        if (!capabilities_j.isNull()) {
            auto capabilities = capabilities_j.asString();

            if (capabilities.find("IBSS") != std::string::npos) {
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);
                bssid_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi Ad-Hoc"));
                bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_ADHOC);
            } else {
                bssid_dev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_AP);
                bssid_dev->set_tracker_type_string(d11phy->devicetracker->get_cached_devicetype("Wi-Fi AP"));
            }

            if (capabilities.find("WPS") != std::string::npos) {
                cryptset |= crypt_wps;
            }

            if (capabilities.find("WEP") != std::string::npos) {
                cryptset |= crypt_wep;
            }

            auto caps_list = str_tokenize(capabilities, "[");

            for (const auto& c : caps_list) {
                if (c.find("PSK") != std::string::npos) {
                    if (c.find("WPA2") != std::string::npos)
                        cryptset |= crypt_wpa + crypt_psk + crypt_version_wpa2;
                    else
                        cryptset |= crypt_wpa + crypt_psk + crypt_version_wpa;
                }

                if (c.find("EAP") != std::string::npos) {
                    if (c.find("WPA2") != std::string::npos)
                        cryptset |= crypt_wpa + crypt_eap + crypt_version_wpa2;
                    else
                        cryptset |= crypt_wpa + crypt_eap + crypt_version_wpa;

                    if (c.find("PEAP") != std::string::npos)
                        cryptset |= crypt_peap;

                    if (c.find("TLS") != std::string::npos)
                        cryptset |= crypt_tls;

                    if (c.find("TTLS") != std::string::npos)
                        cryptset |= crypt_ttls;

                    if (c.find("SAE") != std::string::npos)
                        cryptset |= crypt_sae;
                }

                // Not sure if this is actually a valid option
                if (c.find("OWE") != std::string::npos) {
                    cryptset |= crypt_wpa_owe;
                }
            }

        }

        // We can only get beaconing APs from scan results
        bssid_dot11->bitset_type_set(DOT11_DEVICE_TYPE_BEACON_AP);

        auto adv_ssid_map = bssid_dot11->get_advertised_ssid_map();

        std::shared_ptr<dot11_advertised_ssid> ssid;

        if (adv_ssid_map == NULL) {
            fprintf(stderr, "debug - dot11phy::HandleSSID can't find the adv_ssid_map or probe_ssid_map struct, something is wrong\n");
            return 0;
        }

        // Either calculate the actual checksums from the ietags or fake one from the capabilities
        uint32_t ietag_csum = 0;

        if (!ietags_j.isNull()) 
            ietag_csum = adler32_checksum(ietags_j.asString());
        else if (!capabilities_j.isNull())
            ietag_csum = adler32_checksum(ssid_str + capabilities_j.asString());


        if (bssid_dot11->get_last_adv_ie_csum() == ietag_csum) {
            ssid = bssid_dot11->get_last_adv_ssid();

            if (ssid != nullptr) {
                if (ssid->get_last_time() < in_pack->ts.tv_sec)
                    ssid->set_last_time(in_pack->ts.tv_sec);
            }

            return 1;
        }

        bssid_dot11->set_last_adv_ie_csum(ietag_csum);

        // We can only report advertised SSIDs from a scan report, so we only have to look
        // in the advertised map.

        auto ssid_itr = adv_ssid_map->find(ssid_csum);

        if (ssid_itr == adv_ssid_map->end()) {
            ssid = bssid_dot11->new_advertised_ssid();
            adv_ssid_map->insert(ssid_csum, ssid);

            ssid->set_ssid_hash(ssid_csum);
            ssid->set_crypt_set(cryptset);
            ssid->set_first_time(in_pack->ts.tv_sec);
            ssid->set_last_time(in_pack->ts.tv_sec);

            bssid_dev->set_crypt_string(crypt_to_simple_string(cryptset));

            ssid->set_ssid(ssid_str);

            if (ssid_str.length() == 0)
                ssid->set_ssid_cloaked(true);

            ssid->set_ssid_len(ssid_str.length());

            _MSG_INFO("802.11 Wi-Fi device {} advertising SSID '{}'", 
                    bssid_dev->get_macaddr(), ssid_str);

            if (d11phy->alertracker->potential_alert(d11phy->alert_airjackssid_ref) &&
                    ssid->get_ssid() == "AirJack" ) {

                std::string al = "IEEE80211 Access Point BSSID " +
                    bssid_dev->get_macaddr().mac_to_string() + " broadcasting SSID "
                    "\"AirJack\" which implies an attempt to disrupt "
                    "networks.";

                d11phy->alertracker->raise_alert(d11phy->alert_airjackssid_ref, in_pack, 
                        commoninfo->network, commoninfo->source,
                        commoninfo->dest, commoninfo->transmitter,
                        commoninfo->channel, al);
            }

            if (ssid->get_ssid() != "") {
                bssid_dev->set_devicename(ssid->get_ssid());
            } else {
                bssid_dev->set_devicename(bssid_dev->get_macaddr().mac_to_string());
            }

            // If we have a new ssid and we can consider raising an alert, do the 
            // regex compares to see if we trigger apspoof
            if (ssid_str.length() != 0 &&
                    d11phy->alertracker->potential_alert(d11phy->alert_ssidmatch_ref)) {
                for (const auto& s : *d11phy->ssid_regex_vec) {
                    std::shared_ptr<dot11_tracked_ssid_alert> sa =
                        std::static_pointer_cast<dot11_tracked_ssid_alert>(s);

                    if (sa->compare_ssid(ssid_str, commoninfo->source)) {
                        auto al = fmt::format("IEEE80211 Unauthorized device ({}) advertising  "
                                "for SSID '{}', matching APSPOOF rule {} which may indicate "
                                "spoofing or impersonation.", commoninfo->source, 
                                ssid_str, sa->get_group_name());

                        d11phy->alertracker->raise_alert(d11phy->alert_ssidmatch_ref, in_pack, 
                                commoninfo->network,
                                commoninfo->source,
                                commoninfo->dest,
                                commoninfo->transmitter,
                                commoninfo->channel, al);
                        break;
                    }
                }
            }
        } else {
            ssid = std::static_pointer_cast<dot11_advertised_ssid>(ssid_itr->second);
            if (ssid->get_last_time() < in_pack->ts.tv_sec)
                ssid->set_last_time(in_pack->ts.tv_sec);
        }

        d11phy->ssidtracker->handle_broadcast_ssid(ssid->get_ssid(), ssid->get_ssid_len(),
                ssid->get_crypt_set(), bssid_dev);

        bssid_dot11->set_last_adv_ssid(ssid);

        // Alias the last ssid snapshot
        auto lbr = bssid_dot11->get_last_beaconed_ssid_record();
        lbr->set(ssid);

        ssid->set_ietag_checksum(ietag_csum);

        if (ssid->get_crypt_set() != cryptset) {
            if (ssid->get_crypt_set() && cryptset == crypt_none &&
                    d11phy->alertracker->potential_alert(d11phy->alert_wepflap_ref)) {

                std::string al = "IEEE80211 Access Point BSSID " +
                    bssid_dev->get_macaddr().mac_to_string() + " SSID \"" +
                    ssid->get_ssid() + "\" changed advertised encryption from " +
                    crypt_to_string(ssid->get_crypt_set()) + " to Open which may "
                    "indicate AP spoofing/impersonation";

                d11phy->alertracker->raise_alert(d11phy->alert_wepflap_ref, in_pack, 
                        commoninfo->network, commoninfo->source, 
                        commoninfo->dest, commoninfo->transmitter, 
                        commoninfo->channel, al);
            } else if (ssid->get_crypt_set() != cryptset &&
                    d11phy->alertracker->potential_alert(d11phy->alert_cryptchange_ref)) {

                auto al = fmt::format("IEEE80211 Access Point BSSID {} SSID \"{}\" changed advertised "
                        "encryption from {} to {} which may indicate AP spoofing/impersonation",
                        bssid_dev->get_macaddr(), ssid->get_ssid(), 
                        crypt_to_string(ssid->get_crypt_set()),
                        crypt_to_string(cryptset));

                d11phy->alertracker->raise_alert(d11phy->alert_cryptchange_ref, in_pack, 
                        commoninfo->network, commoninfo->source, 
                        commoninfo->dest, commoninfo->transmitter, 
                        commoninfo->channel, al);
            }

            ssid->set_crypt_set(cryptset);
            bssid_dev->set_crypt_string(crypt_to_simple_string(cryptset));
        }

        if (ssid->get_channel().length() > 0 &&
                ssid->get_channel() != commoninfo->channel && commoninfo->channel != "0") {

            auto al = 
                fmt::format("IEEE80211 Access Point BSSID {} SSID \"{}\" changed advertised "
                        "channel from {} to {}, which may indicate spoofing or impersonation.  "
                        "This may also be a normal event where the AP seeks a less congested channel.",
                        bssid_dev->get_macaddr(), ssid->get_ssid(), ssid->get_channel(), 
                        commoninfo->channel);

            d11phy->alertracker->raise_alert(d11phy->alert_chan_ref, in_pack, 
                        commoninfo->network, commoninfo->source, 
                        commoninfo->dest, commoninfo->transmitter, 
                        commoninfo->channel, al);

            ssid->set_channel(commoninfo->channel); 
        }

        d11phy->devicetracker->update_view_device(bssid_dev);

    } catch (const std::exception& e) {
        _MSG_ERROR("Invalid phy80211/Wi-Fi scan report: {}", e.what());
        in_pack->error = true;
        return 0;
    }

    return 1;
}

void kis_80211_phy::set_string_extract(int in_extr) {
    if (in_extr == 0 && dissect_strings == 2) {
        _MSG("set_string_extract(): String dissection cannot be disabled because "
                "it is required by another active component.", MSGFLAG_ERROR);
        return;
    }

    // If we're setting the extract here, we have to turn it on for all BSSIDs
    dissect_strings = in_extr;
    dissect_all_strings = in_extr;
}

void kis_80211_phy::add_wep_key(mac_addr bssid, uint8_t *key, unsigned int len, 
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

    wepkeys.insert(std::make_pair(winfo->bssid, winfo));
}

void kis_80211_phy::handle_ssid(std::shared_ptr<kis_tracked_device_base> basedev,
        std::shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    std::shared_ptr<dot11_advertised_ssid> ssid;

    if (dot11info->subtype != packet_sub_beacon && dot11info->subtype != packet_sub_probe_resp) {
        return;
    }

    // If we've processed an identical ssid, don't waste time parsing again, just tweak
    // the few fields we need to update
    if (dot11dev->get_last_adv_ie_csum() == dot11info->ietag_csum) {
        ssid = dot11dev->get_last_adv_ssid();

        if (ssid != nullptr) {
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
    if (packet_dot11_ie_dissector(in_pack, dot11info) < 0) {
        return;
    }

    // If we're looking for the beacon, snapshot it
    if (dot11info->subtype == packet_sub_beacon &&
            dot11dev->get_snap_next_beacon()) {

        // Grab the 80211 frame, if that doesn't exist, grab the link frame
        kis_datachunk *chunk = in_pack->fetch<kis_datachunk>(pack_comp_decap);

        if (chunk == nullptr)
            chunk = (kis_datachunk *) in_pack->fetch<kis_datachunk>(pack_comp_linkframe);

        if (chunk != nullptr) {
            auto beacon_packet = dot11dev->get_ssid_beacon_packet();

            beacon_packet->set_ts_sec(in_pack->ts.tv_sec);
            beacon_packet->set_ts_usec(in_pack->ts.tv_usec);

            beacon_packet->set_dlt(chunk->dlt);
            beacon_packet->set_source(chunk->source_id);

            beacon_packet->get_data()->set(chunk->data, chunk->length);
        }

    }

    if (dot11info->channel != "0" && dot11info->channel != "") {
        basedev->set_channel(dot11info->channel);
    }

    bool new_ssid = false;

    if (dot11info->subtype == packet_sub_probe_resp) {
        auto resp_ssid_map = dot11dev->get_responded_ssid_map();

        if (resp_ssid_map == NULL) {
            fprintf(stderr, "debug - dot11phy::HandleSSID can't find the responded_ssid_map, something is wrong\n");
            return;
        }

        auto ssid_itr = resp_ssid_map->find(dot11info->ssid_csum);

        if (ssid_itr == resp_ssid_map->end()) {
            dot11info->new_adv_ssid = true;

            ssid = dot11dev->new_responded_ssid();

            new_ssid = true;
        } else {
            ssid = std::static_pointer_cast<dot11_advertised_ssid>(ssid_itr->second);
        }
    } else {
        auto adv_ssid_map = dot11dev->get_advertised_ssid_map();

        if (adv_ssid_map == NULL) {
            fprintf(stderr, "debug - dot11phy::HandleSSID can't find the adv_ssid_map or probe_ssid_map struct, something is wrong\n");
            return;
        }

        auto ssid_itr = adv_ssid_map->find(dot11info->ssid_csum);

        if (ssid_itr == adv_ssid_map->end()) {
            dot11info->new_adv_ssid = true;

            ssid = dot11dev->new_advertised_ssid();

            new_ssid = true;
        } else {
            ssid = std::static_pointer_cast<dot11_advertised_ssid>(ssid_itr->second);
        }
    }

    if (new_ssid) {
        ssid->set_ssid_hash(dot11info->ssid_csum);

        ssid->set_crypt_set(dot11info->cryptset);
        ssid->set_first_time(in_pack->ts.tv_sec);
        ssid->set_last_time(in_pack->ts.tv_sec);

        basedev->set_crypt_string(crypt_to_simple_string(dot11info->cryptset));

        // TODO handle loading SSID from the stored file
        ssid->set_ssid(dot11info->ssid);
        if (dot11info->ssid_len == 0 || dot11info->ssid_blank) 
            ssid->set_ssid_cloaked(true);

        ssid->set_ssid_len(dot11info->ssid_len);

        if (dot11info->owe_transition != nullptr) {
            ssid->set_owe_bssid(dot11info->owe_transition->bssid());
            ssid->set_owe_ssid_len(dot11info->owe_transition->ssid().length());
            ssid->set_owe_ssid(munge_to_printable(dot11info->owe_transition->ssid()));
        }

        // Look for 221 IE tags if we don't know the manuf
        if (Globalreg::globalreg->manufdb->is_unknown_manuf(basedev->get_manuf())) {
            auto taglist = PacketDot11IElist(in_pack, dot11info);
            bool matched = false;

            // Match priority tags we know take precedence
            for (const auto& t : taglist) {
                if (std::get<0>(t) == 221) {
                    // Pick up the primary manuf tags with priority; ubnt, cisco, etc
                    bool priority = false;
                    switch (std::get<1>(t)) {
                        case 0x004096: // cisco
                        case 0x00156d: // ubnt
                        case 0x000b86: // aruba
                            priority = true;
                            break;
                        default:
                            break;
                    }

                    if (!priority)
                        continue;

                    auto manuf = Globalreg::globalreg->manufdb->lookup_oui(std::get<1>(t));
                    if (!Globalreg::globalreg->manufdb->is_unknown_manuf(manuf)) {
                        basedev->set_manuf(manuf);
                        matched = true;
                        break;
                    }
                }
            }

            if (!matched) {
                for (const auto& t : taglist) {
                    if (std::get<0>(t) == 221) {
                        // Exclude known generic 221 OUIs, and exclude anything where we don't know
                        // the manuf from the tag OUI, either.

                        bool exclude = false;

                        switch (std::get<1>(t)) {
                            case 0x0050f2: // microsoft
                            case 0x00037f: // atheros generic tag
                            case 0x001018: // broadcom generic
                            case 0x8cfdf0: // qualcomm generic
                            case 0x506f9a: // wifi alliance
                                exclude = true;
                                break;
                            default:
                                break;
                        }

                        if (exclude)
                            continue;

                        auto manuf = Globalreg::globalreg->manufdb->lookup_oui(std::get<1>(t));
                        if (!Globalreg::globalreg->manufdb->is_unknown_manuf(manuf)) {
                            basedev->set_manuf(manuf);
                            break;
                        }
                    }
                }
            }

        }

        std::string ssidstr;
        if (ssid->get_ssid_cloaked()) {
            // Use the OWE SSID if we can
            if (dot11info->owe_transition != nullptr) {
                if (dot11info->owe_transition->ssid().length() != 0)
                    ssidstr = fmt::format("an OWE SSID '{}' for BSSID {}", 
                            munge_to_printable(dot11info->owe_transition->ssid()),
                            dot11info->owe_transition->bssid());
                else
                {} {}                    ssidstr = "a cloaked SSID";
            } else {
                ssidstr = "a cloaked SSID";
            }
        } else {
            ssidstr = fmt::format("SSID '{}'", ssid->get_ssid());
        }

        _MSG_INFO("802.11 Wi-Fi device {} advertising {}", basedev->get_macaddr(), ssidstr);

        if (alertracker->potential_alert(alert_airjackssid_ref) &&
                ssid->get_ssid() == "AirJack" ) {

            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().mac_to_string() + " broadcasting SSID "
                "\"AirJack\" which implies an attempt to disrupt "
                "networks.";

            alertracker->raise_alert(alert_airjackssid_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }

        if (ssid->get_ssid() != "") {
            basedev->set_devicename(ssid->get_ssid());
        } else {
            basedev->set_devicename(basedev->get_macaddr().mac_to_string());
        }

        // If we have a new ssid and we can consider raising an alert, do the 
        // regex compares to see if we trigger apspoof
        if (dot11info->ssid_len != 0 &&
                alertracker->potential_alert(alert_ssidmatch_ref)) {
            for (const auto& s : *ssid_regex_vec) {
                std::shared_ptr<dot11_tracked_ssid_alert> sa =
                    std::static_pointer_cast<dot11_tracked_ssid_alert>(s);

                if (sa->compare_ssid(dot11info->ssid, dot11info->source_mac)) {
                    std::string ntype = 
                        dot11info->subtype == packet_sub_beacon ? std::string("advertising") :
                        std::string("responding for");

                    std::string al = "IEEE80211 Unauthorized device (" + 
                        dot11info->source_mac.mac_to_string() + std::string(") ") + ntype + 
                        " for SSID '" + dot11info->ssid + "', matching APSPOOF "
                        "rule " + sa->get_group_name() + 
                        std::string(" which may indicate spoofing or impersonation.");

                    alertracker->raise_alert(alert_ssidmatch_ref, in_pack, 
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
        if (ssid->get_last_time() < in_pack->ts.tv_sec)
            ssid->set_last_time(in_pack->ts.tv_sec);
    }

    dot11dev->set_last_adv_ssid(ssid);

    ssid->set_ietag_checksum(dot11info->ietag_csum);

    if (keep_ie_tags_per_bssid) {
        auto taglist = PacketDot11IElist(in_pack, dot11info);
        ssid->get_ie_tag_list()->clear();
        for (const auto& ti : taglist) 
            ssid->get_ie_tag_list()->push_back(std::get<0>(ti));

        // If we snapshot the ie tags, do so
        ssid->set_ietag_content_from_packet(dot11info->ie_tags);
    }

    // Alias the last ssid snapshot
    auto lbr = dot11dev->get_last_beaconed_ssid_record();
    lbr->set(ssid);

    if (ssid->get_last_time() < in_pack->ts.tv_sec)
        ssid->set_last_time(in_pack->ts.tv_sec);

    // Update MFP
    if (dot11info->rsn != nullptr) {
        ssid->set_wpa_mfp_required(dot11info->rsn->rsn_capability_mfp_required());
        ssid->set_wpa_mfp_supported(dot11info->rsn->rsn_capability_mfp_supported());
    } else {
        ssid->set_wpa_mfp_required(false);
        ssid->set_wpa_mfp_supported(false);
    }

    if (dot11info->subtype == packet_sub_beacon) {
        auto tag_hash = xx_hash_cpp{};

        for (const auto& i : beacon_ie_fingerprint_list) {
            const auto& te = dot11info->ietag_hash_map.find(i);

            if (te == dot11info->ietag_hash_map.end())
                continue;

            // Combine the hashes of duplicate tags
            auto t = dot11info->ietag_hash_map.equal_range(i);

            for (auto ti = t.first; ti != t.second; ++ti) 
                boost_like::hash_combine(tag_hash, (uint32_t) ti->second);

        }

        // xxhash32 says hashes are canoically represented as little-endian
        dot11dev->set_beacon_fingerprint(htole32(tag_hash.hash()));

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

        // Set tx power
        ssid->set_ccx_txpower(dot11info->ccx_txpower);

        // Set client mfp
        ssid->set_cisco_client_mfp(dot11info->cisco_client_mfp);

        // Set QBSS
        if (dot11info->qbss != NULL) {
            ssid->set_dot11e_qbss(true);
            ssid->set_dot11e_qbss_stations(dot11info->qbss->station_count());

            // Percentage is value / max (1 byte, 255)
            double chperc = (double) ((double) dot11info->qbss->channel_utilization() / 
                    (double) 255.0f) * 100.0f;
            ssid->set_dot11e_qbss_channel_load(chperc);
        }

        // Set the HT and VHT info.  If we have VHT, we assume we must have HT; I've never
        // seen VHT without HT.  We handle HT only later on.
        if (dot11info->dot11vht != nullptr && dot11info->dot11ht != nullptr) {
            // Grab the primary channel from the HT data
            ssid->set_channel(int_to_string(dot11info->dot11ht->primary_channel()));

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
        } else if (dot11info->dot11ht != nullptr) {
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
            ssid->set_channel(int_to_string(dot11info->dot11ht->primary_channel()));
        }

        // Update OWE
        if (dot11info->owe_transition != nullptr) {
            ssid->set_owe_bssid(dot11info->owe_transition->bssid());
            ssid->set_owe_ssid_len(dot11info->owe_transition->ssid().length());
            ssid->set_owe_ssid(munge_to_printable(dot11info->owe_transition->ssid()));
        }

    } else if (dot11info->subtype == packet_sub_probe_resp) {
        if (mac_addr((uint8_t *) "\x00\x13\x37\x00\x00\x00", 6, 24) == 
                dot11info->source_mac) {

            if (alertracker->potential_alert(alert_l33t_ref)) {
                std::string al = "IEEE80211 probe response from OUI 00:13:37 seen, "
                    "which typically implies a Karma AP impersonation attack.";

                alertracker->raise_alert(alert_l33t_ref, in_pack, 
                        dot11info->bssid_mac, dot11info->source_mac, 
                        dot11info->dest_mac, dot11info->other_mac, 
                        dot11info->channel, al);
            }

        }

        ssid->set_ssid_probe_response(true);
    }

    if (ssid->get_crypt_set() != dot11info->cryptset) {
        if (ssid->get_crypt_set() && dot11info->cryptset == crypt_none &&
                alertracker->potential_alert(alert_wepflap_ref)) {

            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().mac_to_string() + " SSID \"" +
                ssid->get_ssid() + "\" changed advertised encryption from " +
                crypt_to_string(ssid->get_crypt_set()) + " to Open which may "
                "indicate AP spoofing/impersonation";

            alertracker->raise_alert(alert_wepflap_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        } else if (ssid->get_crypt_set() != dot11info->cryptset &&
                alertracker->potential_alert(alert_cryptchange_ref)) {

            auto al = fmt::format("IEEE80211 Access Point BSSID {} SSID \"{}\" changed advertised "
                    "encryption from {} to {} which may indicate AP spoofing/impersonation",
                    basedev->get_macaddr(), ssid->get_ssid(), crypt_to_string(ssid->get_crypt_set()),
                    crypt_to_string(dot11info->cryptset));

            alertracker->raise_alert(alert_cryptchange_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }

        ssid->set_crypt_set(dot11info->cryptset);
        basedev->set_crypt_string(crypt_to_simple_string(dot11info->cryptset));
    }

    if (ssid->get_channel().length() > 0 &&
            ssid->get_channel() != dot11info->channel && dot11info->channel != "0") {

        if (dot11info->subtype == packet_sub_beacon) {
            auto al = 
                fmt::format("IEEE80211 Access Point BSSID {} SSID \"{}\" changed advertised channel "
                        "from {} to {}, which may indicate spoofing or impersonation.  This may also be a "
                        "normal event where the AP seeks a less congested channel.",
                        basedev->get_macaddr(), ssid->get_ssid(), ssid->get_channel(), dot11info->channel);

            alertracker->raise_alert(alert_chan_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);

            ssid->set_channel(dot11info->channel); 
        } else if (dot11info->subtype == packet_sub_probe_resp) {
            auto al =
                fmt::format("IEEE80211 Access Point BSSID {} SSID \"{}\" sent a probe response with "
                        "channel {} while advertising channel {}.  This may indicate spoofing or "
                        "impersonation, or may indicate a misconfigured or misbehaving access "
                        "point or repeater.",
                        basedev->get_macaddr(), ssid->get_ssid(), dot11info->channel, ssid->get_channel());
            alertracker->raise_alert(alert_probechan_ref, in_pack,
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }
    }

    // Only process dot11d from beacons
    if (dot11info->subtype == packet_sub_beacon) {
        bool dot11dmismatch = false;

        if (ssid->get_dot11d_country().length() > 0 &&
                ssid->get_dot11d_country() != dot11info->dot11d_country) {
            dot11dmismatch = true;
        }

        if (ssid->has_dot11d_vec()) {
            auto dot11dvec(ssid->get_dot11d_vec());

            if (dot11dvec->size() != dot11info->dot11d_vec.size()) {
                dot11dmismatch = true; 
            } else {
                for (unsigned int vc = 0; 
                        vc < dot11dvec->size() && vc < dot11info->dot11d_vec.size(); vc++) {
                    std::shared_ptr<dot11_11d_tracked_range_info> ri =
                        std::static_pointer_cast<dot11_11d_tracked_range_info>(*(dot11dvec->begin() + vc));

                    if (ri->get_startchan() != dot11info->dot11d_vec[vc].startchan ||
                            ri->get_numchan() != dot11info->dot11d_vec[vc].numchan ||
                            ri->get_txpower() != dot11info->dot11d_vec[vc].txpower) {
                        dot11dmismatch = true;
                        break;
                    }
                }
            }
        }

        if (dot11dmismatch) {
            if (alertracker->potential_alert(alert_dot11d_ref)) {

                std::string al = "IEEE80211 Access Point BSSID " +
                    basedev->get_macaddr().mac_to_string() + " SSID \"" +
                    ssid->get_ssid() + "\" advertised conflicting 802.11d "
                    "information which may indicate AP spoofing/impersonation";

                alertracker->raise_alert(alert_dot11d_ref, in_pack, 
                        dot11info->bssid_mac, dot11info->source_mac, 
                        dot11info->dest_mac, dot11info->other_mac, 
                        dot11info->channel, al);

            }
        }

        ssid->set_dot11d_country(dot11info->dot11d_country);

        if (dot11info->dot11d_vec.size() > 0 && ssid->has_dot11d_vec())
            ssid->set_dot11d_vec(dot11info->dot11d_vec);
        else if (dot11info->dot11d_vec.size() == 0 && ssid->has_dot11d_vec())
            ssid->clear_dot11d_vec();
    }

    ssid->set_wps_version(dot11info->wps_version);
    ssid->set_wps_state(dot11info->wps);
    ssid->set_wps_config_methods(dot11info->wps_config_methods);
    if (dot11info->wps_device_name != "")
        ssid->set_wps_device_name(dot11info->wps_device_name);
    if (dot11info->wps_manuf != "")
        ssid->set_wps_manuf(dot11info->wps_manuf);
    if (dot11info->wps_model_name != "") {
        ssid->set_wps_model_name(dot11info->wps_model_name);
    }
    if (dot11info->wps_model_number != "") 
        ssid->set_wps_model_number(dot11info->wps_model_number);
    if (dot11info->wps_serial_number != "")
        ssid->set_wps_serial_number(dot11info->wps_serial_number);

    if (dot11info->wps_uuid_e != "") 
        ssid->set_wps_uuid_e(dot11info->wps_uuid_e);

    if (dot11info->beacon_interval && ssid->get_beaconrate() != 
            Ieee80211Interval2NSecs(dot11info->beacon_interval)) {

        if (ssid->get_beaconrate() != 0 && 
                alertracker->potential_alert(alert_beaconrate_ref)) {
            std::string al = "IEEE80211 Access Point BSSID " +
                basedev->get_macaddr().mac_to_string() + " SSID \"" +
                ssid->get_ssid() + "\" changed beacon rate from " +
                int_to_string(ssid->get_beaconrate()) + " to " + 
                int_to_string(Ieee80211Interval2NSecs(dot11info->beacon_interval)) + 
                " which may indicate AP spoofing/impersonation";

            alertracker->raise_alert(alert_beaconrate_ref, in_pack, 
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac, 
                    dot11info->channel, al);
        }

        ssid->set_beaconrate(Ieee80211Interval2NSecs(dot11info->beacon_interval));
    }

    ssid->set_maxrate(dot11info->maxrate);

    // Add the location data, if any
    if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
        auto loc = ssid->get_location();

        if (loc->get_last_location_time() != time(0)) {
            loc->set_last_location_time(time(0));
            loc->add_loc_with_avg(pack_gpsinfo->lat, pack_gpsinfo->lon,
                    pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                    pack_gpsinfo->heading);
        } else {
            loc->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                    pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                    pack_gpsinfo->heading);
        }

    }

    // Finalize processing and add it to the maps
    if (dot11info->subtype == packet_sub_probe_resp) {
        auto resp_ssid_map = dot11dev->get_responded_ssid_map();
            resp_ssid_map->insert(dot11info->ssid_csum, ssid);

        ssidtracker->handle_response_ssid(ssid->get_ssid(), ssid->get_ssid_len(),
                ssid->get_crypt_set(), basedev);
    } else {
        auto adv_ssid_map = dot11dev->get_advertised_ssid_map();
        adv_ssid_map->insert(dot11info->ssid_csum, ssid);

        ssidtracker->handle_broadcast_ssid(ssid->get_ssid(), ssid->get_ssid_len(),
                ssid->get_crypt_set(), basedev);
    }
}

void kis_80211_phy::handle_probed_ssid(std::shared_ptr<kis_tracked_device_base> basedev,
        std::shared_ptr<dot11_tracked_device> dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    // We're called under device list lock so we only lock the device we're interacting with

    if (dot11info == nullptr)
        throw std::runtime_error("handle_probed_ssid with null dot11dev");

    if (basedev == nullptr) 
        throw std::runtime_error("handle_probed_ssid with null basedev");

    if (dot11dev == nullptr)
        throw std::runtime_error("handle_probed_ssid with null dot11dev");

    std::shared_ptr<dot11_probed_ssid> probessid;

    // Parse IE tags on probe req, assoc, reassoc
    if (packet_dot11_ie_dissector(in_pack, dot11info) < 0) {
        return;
    }

    if (dot11info->subtype == packet_sub_probe_req ||
            dot11info->subtype == packet_sub_association_req ||
            dot11info->subtype == packet_sub_reassociation_req) {
        kis_unique_lock<kis_mutex> lk(basedev->device_mutex, "handle_probed_ssid");

        auto probemap(dot11dev->get_probed_ssid_map());

        auto ssid_itr = probemap->find(dot11info->ssid_csum);

        if (ssid_itr == probemap->end() || ssid_itr->second == nullptr) {
            probessid = dot11dev->new_probed_ssid();

            probessid->set_ssid(dot11info->ssid);
            probessid->set_ssid_len(dot11info->ssid_len);
            probessid->set_first_time(in_pack->ts.tv_sec);

            probemap->insert(dot11info->ssid_csum, probessid);
        } else {
            probessid = std::static_pointer_cast<dot11_probed_ssid>(ssid_itr->second);
        }

        if (probessid->get_last_time() < in_pack->ts.tv_sec)
            probessid->set_last_time(in_pack->ts.tv_sec);

        // Add the location data, if any
        if (pack_gpsinfo != nullptr && pack_gpsinfo->fix > 1) {
            auto loc = probessid->get_location();

            if (loc->get_last_location_time() != time(0)) {
                loc->set_last_location_time(time(0));
                loc->add_loc_with_avg(pack_gpsinfo->lat, pack_gpsinfo->lon,
                        pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                        pack_gpsinfo->heading);
            } else {
                loc->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                        pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                        pack_gpsinfo->heading);
            }
        }

        if (dot11info->dot11r_mobility != nullptr) {
            probessid->set_dot11r_mobility(true);
            probessid->set_dot11r_mobility_domain_id(dot11info->dot11r_mobility->mobility_domain());
        }

        // Alias the last ssid snapshot
        auto lpr = dot11dev->get_last_probed_ssid_record();
        lpr->set(probessid);

        // Update MFP
        if (dot11info->rsn != nullptr) {
            probessid->set_wpa_mfp_required(dot11info->rsn->rsn_capability_mfp_required());
            probessid->set_wpa_mfp_supported(dot11info->rsn->rsn_capability_mfp_supported());
        } else {
            probessid->set_wpa_mfp_required(false);
            probessid->set_wpa_mfp_supported(false);
        }

        // Update the crypt set if any
        probessid->set_crypt_set(dot11info->cryptset);

        probessid->set_wps_version(dot11info->wps_version);
        probessid->set_wps_state(dot11info->wps);
        probessid->set_wps_config_methods(dot11info->wps_config_methods);
        if (dot11info->wps_manuf != "")
            probessid->set_wps_manuf(dot11info->wps_manuf);
        if (dot11info->wps_model_name != "") {
            probessid->set_wps_model_name(dot11info->wps_model_name);
        }
        if (dot11info->wps_model_number != "") 
            probessid->set_wps_model_number(dot11info->wps_model_number);
        if (dot11info->wps_serial_number != "")
            probessid->set_wps_serial_number(dot11info->wps_serial_number);

        // Update the IE listing at the device level
        if (keep_ie_tags_per_bssid) {
            auto taglist = PacketDot11IElist(in_pack, dot11info);
            probessid->get_ie_tag_list()->clear();
            for (const auto& ti : taglist) 
                probessid->get_ie_tag_list()->push_back(std::get<0>(ti));
        }

        auto tag_hash = xx_hash_cpp{};

        for (const auto& i : probe_ie_fingerprint_list) {
            auto te = dot11info->ietag_hash_map.find(i);

            if (te == dot11info->ietag_hash_map.end())
                continue;

            // Combine the hashes of duplicate tags
            auto t = dot11info->ietag_hash_map.equal_range(i);

            for (auto ti = t.first; ti != t.second; ++ti) 
                boost_like::hash_combine(tag_hash, (uint32_t) ti->second);
        }

        // XXHash32 says the canonical representation of the hash is little-endian
        dot11dev->set_probe_fingerprint(htole32(tag_hash.hash()));

        if (dot11info->wps_uuid_e != "") {
            if (probessid->get_wps_uuid_e() != dot11info->wps_uuid_e) {
                lk.unlock();

                device_tracker_view_function_worker dev_worker(
                        [this, dot11info, basedev, dot11dev](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                            auto bssid_dot11 =
                                dev->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

                            if (bssid_dot11 == nullptr) {
                                return false;
                            }

                            if (bssid_dot11->has_probed_ssid_map()) {
                                for (const auto& pi : *bssid_dot11->probed_ssid_map) {
                                    auto ps = std::static_pointer_cast<dot11_probed_ssid>(pi.second);

                                    if (ps->get_wps_uuid_e() == dot11info->wps_uuid_e)
                                        return true;
                                }
                            }

                        return false;
                        });
                devicetracker->do_device_work(dev_worker);

                // Update main device under lock
                lk.lock();
                probessid->set_wps_uuid_e(dot11info->wps_uuid_e);
                // Set a bidirectional relationship
                for (const auto& ri : *(dev_worker.getMatchedDevices())) {
                    auto rdev = std::static_pointer_cast<kis_tracked_device_base>(ri);
                    basedev->add_related_device("dot11_uuid_e", rdev->get_key());
                }
                lk.unlock();

                // Update associated devices under single device lock
                for (const auto& ri : *(dev_worker.getMatchedDevices())) {
                    auto rdev = std::static_pointer_cast<kis_tracked_device_base>(ri);
                    kis_lock_guard<kis_mutex> lk(rdev->device_mutex, "handle_probed_ssid wps correlation");
                    rdev->add_related_device("dot11_uuid_e", basedev->get_key());
                }
            }
        }

        // Enter it in the ssid tracker
        ssidtracker->handle_probe_ssid(probessid->get_ssid(), probessid->get_ssid_len(),
                probessid->get_crypt_set(), basedev);
    }

}

// Associate a client device and a dot11 access point
void kis_80211_phy::process_client(std::shared_ptr<kis_tracked_device_base> bssiddev,
        std::shared_ptr<dot11_tracked_device> bssiddot11,
        std::shared_ptr<kis_tracked_device_base> clientdev,
        std::shared_ptr<dot11_tracked_device> clientdot11,
        kis_packet *in_pack, 
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo,
        kis_data_packinfo *pack_datainfo) {

    // Sanity check
    if (bssiddev == nullptr)
        return;

    // Create the client-side record of association to a given bssid
    auto client_map(clientdot11->get_client_map());
    std::shared_ptr<dot11_client> client_record;

    auto cmi = client_map->find(bssiddev->get_macaddr());
    bool new_client_record = false;

    if (cmi == client_map->end()) {
        client_record = clientdot11->new_client();
        new_client_record = true;
        client_map->insert(bssiddev->get_macaddr(), client_record);
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

    clientdot11->set_last_bssid(bssiddev->get_macaddr());

    if (dot11info->type == packet_management) {
        // Client-level assoc req advertisements
        if (dot11info->subtype == packet_sub_association_req) {
            if (dot11info->tx_power != nullptr) {
                clientdot11->set_min_tx_power(dot11info->tx_power->min_power());
                clientdot11->set_max_tx_power(dot11info->tx_power->max_power());
            }

            if (dot11info->supported_channels != nullptr) {
                auto clichannels = clientdot11->get_supported_channels();
                clichannels->clear();

                for (const auto& c : dot11info->supported_channels->supported_channels()) 
                    clichannels->push_back(c);
            }

            if ((dot11info->rsn == nullptr || !dot11info->rsn->rsn_capability_mfp_supported()) &&
                    alertracker->potential_alert(alert_noclientmfp_ref)) {
                std::string al = "IEEE80211 network BSSID " +
                    client_record->get_bssid().mac_to_string() +
                    " client " +
                    clientdev->get_macaddr().mac_to_string() +
                    " does not support management frame protection (MFP) which "
                    "may ease client disassocation or deauthentication";

                alertracker->raise_alert(alert_noclientmfp_ref, in_pack,
                        dot11info->bssid_mac, dot11info->source_mac,
                        dot11info->dest_mac, dot11info->other_mac,
                        dot11info->channel, al);
            }
        }

    } else if (dot11info->type == packet_data) {
        // Handle the data records for this client association, we're not just a management link

        if (dot11info->fragmented)
            client_record->inc_num_fragments(1);

        if (dot11info->retry) {
            client_record->inc_num_retries(1);
            client_record->inc_datasize_retry(dot11info->datasize);
        }

        if (pack_datainfo != NULL) {
            if (pack_datainfo->proto == proto_eap && pack_datainfo->auxstring != "") {
                client_record->set_eap_identity(pack_datainfo->auxstring);
            }

            if (pack_datainfo->discover_vendor != "") {
                if (client_record->get_dhcp_vendor() != "" &&
                        client_record->get_dhcp_vendor() != pack_datainfo->discover_vendor &&
                        alertracker->potential_alert(alert_dhcpos_ref)) {
                    std::string al = "IEEE80211 network BSSID " + 
                        client_record->get_bssid().mac_to_string() +
                        " client " + 
                        clientdev->get_macaddr().mac_to_string() + 
                        "changed advertised DHCP vendor from '" +
                        client_record->get_dhcp_vendor() + "' to '" +
                        pack_datainfo->discover_vendor + "' which may indicate "
                        "client spoofing or impersonation";

                    alertracker->raise_alert(alert_dhcpos_ref, in_pack,
                            dot11info->bssid_mac, dot11info->source_mac,
                            dot11info->dest_mac, dot11info->other_mac,
                            dot11info->channel, al);
                }

                client_record->set_dhcp_vendor(pack_datainfo->discover_vendor);
            }

            if (pack_datainfo->discover_host != "") {
                if (client_record->get_dhcp_host() != "" &&
                        client_record->get_dhcp_host() != pack_datainfo->discover_host &&
                        alertracker->potential_alert(alert_dhcpname_ref)) {
                    std::string al = "IEEE80211 network BSSID " + 
                        client_record->get_bssid().mac_to_string() +
                        " client " + 
                        clientdev->get_macaddr().mac_to_string() + 
                        "changed advertised DHCP hostname from '" +
                        client_record->get_dhcp_host() + "' to '" +
                        pack_datainfo->discover_host + "' which may indicate "
                        "client spoofing or impersonation";

                    alertracker->raise_alert(alert_dhcpname_ref, in_pack,
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

            switch(pack_datainfo->proto) {
                case proto_arp:
                    if (dot11info->source_mac == clientdev->get_macaddr()) {
                        client_record->get_ipdata()->set_ip_addr(pack_datainfo->ip_source_addr.s_addr);
                        client_record->get_ipdata()->set_ip_type(ipdata_arp);
                    }
                    break;
                case proto_dhcp_offer:
                    if (dot11info->dest_mac == clientdev->get_macaddr()) {
                        client_record->get_ipdata()->set_ip_addr(pack_datainfo->ip_dest_addr.s_addr);
                        client_record->get_ipdata()->set_ip_netmask(pack_datainfo->ip_netmask_addr.s_addr);
                        client_record->get_ipdata()->set_ip_gateway(pack_datainfo->ip_gateway_addr.s_addr);
                        client_record->get_ipdata()->set_ip_type(ipdata_dhcp);
                    }
                    break;
                case proto_tcp:
                case proto_udp:
                    if (dot11info->source_mac == clientdev->get_macaddr())
                        client_record->get_ipdata()->set_ip_addr(pack_datainfo->ip_source_addr.s_addr);
                    if (dot11info->dest_mac == clientdev->get_macaddr())
                        client_record->get_ipdata()->set_ip_addr(pack_datainfo->ip_dest_addr.s_addr);
                    client_record->get_ipdata()->set_ip_type(ipdata_udptcp);
                    break;
                default:
                    break;
            }
        }

        // Update the GPS info
        if (pack_gpsinfo != NULL && pack_gpsinfo->fix > 1) {
            auto loc = client_record->get_location();
            if (loc->get_last_location_time() != time(0)) {
                loc->set_last_location_time(time(0));
                loc->add_loc_with_avg(pack_gpsinfo->lat, pack_gpsinfo->lon,
                        pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                        pack_gpsinfo->heading);
            } else {
                loc->add_loc(pack_gpsinfo->lat, pack_gpsinfo->lon,
                        pack_gpsinfo->alt, pack_gpsinfo->fix, pack_gpsinfo->speed,
                        pack_gpsinfo->heading);
            }
        }

        // Update the forward map to the bssid
        client_record->set_bssid_key(bssiddev->get_key());
    }

    // Update the backwards map to the client
    if (bssiddot11->get_associated_client_map()->find(clientdev->get_macaddr()) ==
            bssiddot11->get_associated_client_map()->end()) {
        bssiddot11->get_associated_client_map()->insert(clientdev->get_macaddr(),
                clientdev->get_tracker_key());
    }
}

void kis_80211_phy::process_wpa_handshake(std::shared_ptr<kis_tracked_device_base> bssid_dev,
        std::shared_ptr<dot11_tracked_device> bssid_dot11,
        std::shared_ptr<kis_tracked_device_base> dest_dev,
        std::shared_ptr<dot11_tracked_device> dest_dot11,
        kis_packet *in_pack,
        dot11_packinfo *dot11info) {

    std::shared_ptr<dot11_tracked_eapol> eapol = packet_dot11_eapol_handshake(in_pack, bssid_dot11);

    if (eapol == NULL)
        return;

    if (!keep_eapol_packets)
        return;

    if (bssid_dev == nullptr || dest_dev == nullptr)
        return;

    // We want to start looking for the next advertised ssid
    bssid_dot11->set_snap_next_beacon(true);

    auto bssid_vec(bssid_dot11->get_wpa_key_vec());

    // Do we have a pmkid and need one?  set the pmkid packet.
    if (bssid_dot11->get_pmkid_needed() && eapol->get_rsnpmkid_bytes().length() != 0) {
        auto pmkid_packet = bssid_dot11->get_pmkid_packet();
        pmkid_packet->copy_packet(eapol->get_eapol_packet());
    }

    // Start doing something smart here about eliminating
    // records - we want to do our best to keep a 1, 2, 3, 4
    // handshake sequence, so find out what duplicates we have
    // and eliminate the oldest one of them if we need to
    uint8_t keymask = 0;

    if (bssid_vec->size() > 16) {
        for (tracker_element_vector::iterator kvi = bssid_vec->begin();
                kvi != bssid_vec->end(); ++kvi) {
            auto ke = std::static_pointer_cast<dot11_tracked_eapol>(*kvi);

            uint8_t knum = (1 << ke->get_eapol_msg_num());

            // If this is a duplicate handshake number, we can get
            // rid of this one
            if ((keymask & knum) == knum) {
                bssid_vec->erase(kvi);
                break;
            }

            // Otherwise put this key in the keymask
            keymask |= knum;
        }
    }

    bssid_vec->push_back(eapol);

    // Calculate the key mask of seen handshake keys
    keymask = 0;
    for (const auto& kvi : *bssid_vec) {
        keymask |= (1 << std::static_pointer_cast<dot11_tracked_eapol>(kvi)->get_eapol_msg_num());
    }

    bssid_dot11->set_wpa_present_handshake(keymask);

    auto evt = eventbus->get_eventbus_event(dot11_wpa_handshake_event);
    evt->get_event_content()->insert(dot11_wpa_handshake_event_base, bssid_dev);
    evt->get_event_content()->insert(dot11_wpa_handshake_event_dot11, bssid_dot11);
    eventbus->publish(evt);

    // Look for replays against the target (which might be the bssid, or might
    // be a client, depending on the direction); we track the EAPOL records per
    // destination in the destination device record
    bool dupe_nonce = false;
    bool new_nonce = true;

    // Look for replay attacks; only compare non-zero nonces
    if (eapol->get_eapol_msg_num() == 3 &&
            eapol->get_eapol_nonce_bytes().find_first_not_of(std::string("\x00", 1)) != 
            std::string::npos) {
        dupe_nonce = false;
        new_nonce = true;

        for (const auto& i : *(dest_dot11->get_wpa_nonce_vec())) {
            std::shared_ptr<dot11_tracked_nonce> nonce =
                std::static_pointer_cast<dot11_tracked_nonce>(i);

            // If the nonce strings match
            if (nonce->get_eapol_nonce_bytes() == eapol->get_eapol_nonce_bytes()) {
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

                auto ev = dest_dot11->get_wpa_nonce_vec();

                // Limit the size of stored nonces
                if (ev->size() > 128)
                    ev->erase(ev->begin());

                ev->push_back(n);
            }
        } else {
            std::stringstream ss;
            std::string nonce = eapol->get_eapol_nonce_bytes();

            for (size_t b = 0; b < nonce.length(); b++) {
                ss << std::uppercase << std::setfill('0') << std::setw(2) <<
                    std::hex << (int) (nonce[b] & 0xFF);
            }

            alertracker->raise_alert(alert_nonce_duplicate_ref, in_pack,
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac,
                    dot11info->channel,
                    "WPA EAPOL RSN frame seen with a previously used nonce; "
                    "this may indicate a KRACK-style WPA attack (nonce: " + 
                    ss.str() + ")");
        }
    } else if (eapol->get_eapol_msg_num() == 1 &&
            eapol->get_eapol_nonce_bytes().find_first_not_of(std::string("\x00", 1)) != std::string::npos) {
        // Don't compare zero nonces
        auto eav = dest_dot11->get_wpa_anonce_vec();
        dupe_nonce = false;
        new_nonce = true;

        for (const auto& i : *eav) {
            std::shared_ptr<dot11_tracked_nonce> nonce =
                std::static_pointer_cast<dot11_tracked_nonce>(i);

            // If the nonce strings match
            if (nonce->get_eapol_nonce_bytes() == eapol->get_eapol_nonce_bytes()) {
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
                if (eav->size() > 128)
                    eav->erase(eav->begin());

                eav->push_back(n);
            }
        } else {
            std::stringstream ss;
            std::string nonce = eapol->get_eapol_nonce_bytes();

            for (size_t b = 0; b < nonce.length(); b++) {
                ss << std::uppercase << std::setfill('0') << std::setw(2) <<
                    std::hex << (int) (nonce[b] & 0xFF);
            }

            alertracker->raise_alert(alert_nonce_duplicate_ref, in_pack,
                    dot11info->bssid_mac, dot11info->source_mac, 
                    dot11info->dest_mac, dot11info->other_mac,
                    dot11info->channel,
                    "WPA EAPOL RSN frame seen with a previously used anonce; "
                    "this may indicate a KRACK-style WPA attack (anonce: " +
                    ss.str() + ")");
        }
    }
}

std::string kis_80211_phy::crypt_to_string(uint64_t cryptset) {
    std::string ret;

    if (cryptset == crypt_none)
        return "none";

    if (cryptset == crypt_unknown)
        return "unknown";

    if (cryptset & crypt_wps)
        ret = "WPS";

    if ((cryptset & crypt_protectmask) == crypt_wep)
        return string_append(ret, "WEP");

    if (cryptset & crypt_wpa_owe)
        return "OWE";

    std::string WPAVER = "WPA";

    if (cryptset & crypt_version_wpa2)
        WPAVER = "WPA2";

    if (cryptset & crypt_version_wpa3)
        WPAVER = "WPA3";

    if (cryptset & crypt_wpa)
        ret = string_append(ret, WPAVER);

    if (cryptset & crypt_psk)
        ret = string_append(ret, fmt::format("{}-PSK", WPAVER));

    if (cryptset & crypt_sae)
        ret = string_append(ret, fmt::format("{}-SAE", WPAVER));

    if (cryptset & crypt_eap)
        ret = string_append(ret, "EAP");

    if (cryptset & crypt_peap)
        ret = string_append(ret, fmt::format("{}-PEAP", WPAVER));
    if (cryptset & crypt_leap)
        ret = string_append(ret, fmt::format("{}-LEAP", WPAVER));
    if (cryptset & crypt_ttls)
        ret = string_append(ret, fmt::format("{}-TTLS", WPAVER));
    if (cryptset & crypt_tls)
        ret = string_append(ret, fmt::format("{}-TLS", WPAVER));

    if (cryptset & crypt_wpa_migmode)
        ret = string_append(ret, "WPA-MIGRATION");

    if (cryptset & crypt_wep40)
        ret = string_append(ret, "WEP40");
    if (cryptset & crypt_wep104)
        ret = string_append(ret, "WEP104");
    if (cryptset & crypt_tkip)
        ret = string_append(ret, "TKIP");
    if (cryptset & crypt_aes_ocb)
        ret = string_append(ret, "AES-OCB");
    if (cryptset & crypt_aes_ccm)
        ret = string_append(ret, "AES-CCMP");

    if (cryptset & crypt_layer3)
        ret = string_append(ret, "Layer 3");

    if (cryptset & crypt_isakmp)
        ret = string_append(ret, "ISA KMP");

    if (cryptset & crypt_pptp)
        ret = string_append(ret, "PPTP");

    if (cryptset & crypt_fortress)
        ret = string_append(ret, "Fortress");

    if (cryptset & crypt_keyguard)
        ret = string_append(ret, "Keyguard");

    if (cryptset & crypt_unknown_protected)
        ret = string_append(ret, "L3/Unknown");

    if (cryptset & crypt_unknown_nonwep)
        ret = string_append(ret, "Non-WEP/Unknown");

    return ret;
}

std::string kis_80211_phy::crypt_to_simple_string(uint64_t cryptset) {
    std::string ret;

    if (cryptset == crypt_none)
        return "Open";

    if (cryptset == crypt_unknown)
        return "Unknown";

    if (cryptset == crypt_wpa_owe)
        return "Open (OWE)";

    if (cryptset & crypt_wpa_owe)
        return "OWE";

    std::string WPAVER = "WPA";

    if (cryptset & crypt_version_wpa2)
        WPAVER = "WPA2";

    if (cryptset & crypt_version_wpa3)
        WPAVER = "WPA3";

    if ((cryptset & crypt_version_wpa3) && (cryptset & crypt_psk) && (cryptset & crypt_sae))
        return fmt::format("WPA3-TRANSITION");

    if ((cryptset & crypt_version_wpa3) && (cryptset & crypt_sae))
        return fmt::format("{}-SAE", WPAVER);

    if (cryptset & crypt_psk)
        return fmt::format("{}-PSK", WPAVER);

    if (cryptset & crypt_peap)
        return fmt::format("{}-PEAP", WPAVER);
    if (cryptset & crypt_leap)
        return fmt::format("{}-LEAP", WPAVER);
    if (cryptset & crypt_ttls)
        return fmt::format("{}-TTLS", WPAVER);
    if (cryptset & crypt_tls)
        return fmt::format("{}-TLS", WPAVER);

    if (cryptset & crypt_wep40)
        return "WEP40";

    if (cryptset & crypt_wep104)
        return "WEP104";

    if (cryptset & crypt_tkip)
        return fmt::format("{}-TKIP", WPAVER);

    if (cryptset & crypt_aes_ocb)
        return fmt::format("{}-OCB", WPAVER);

    if (cryptset & crypt_aes_ccm)
        return fmt::format("{}-CCMP", WPAVER);

    if (cryptset & crypt_wpa)
        return WPAVER;

    if (cryptset & crypt_wep)
        return "WEP";

    return "Other";
}


void kis_80211_phy::generate_handshake_pcap(std::shared_ptr<kis_net_beast_httpd_connection> con, 
        std::shared_ptr<kis_tracked_device_base> dev, 
        std::shared_ptr<dot11_tracked_device> dot11dev, std::string mode) {

    // Hardcode the pcap header
    struct pcap_header {
        uint32_t magic = 0xa1b2c3d4;
        uint16_t vmajor = 2;
        uint16_t vminor = 4;
        int32_t offset = 0;
        uint32_t sigfigs = 0;
        uint32_t len = 8192;
        uint32_t dlt = KDLT_IEEE802_11;
    } hdr;

    // Hardcode the pcap packet header
    struct pcap_packet_header {
        uint32_t timeval_s;
        uint32_t timeval_us;
        uint32_t len;
        uint32_t caplen;
    } pkt_hdr;

    std::ostream stream(&con->response_stream());

    stream.write((const char *) &hdr, sizeof(hdr));

    /*
    kis_unique_lock lk_list(devicetracker->get_devicelist_mutex(), std::defer_lock, "generate_handshake_pcap");
    kis_unique_lock lk_device(dev->device_mutex, std::defer_lock, "generate_handshake_pcap");
    std::lock(lk_list, lk_device);
    */
    kis_unique_lock lk_device(dev->device_mutex, "generate_handshake_pcap");

    /* Write the beacon */
    if (dot11dev->get_beacon_packet_present()) {
        auto packet = dot11dev->get_ssid_beacon_packet();

        pkt_hdr.timeval_s = packet->get_ts_sec();
        pkt_hdr.timeval_us = packet->get_ts_usec();

        pkt_hdr.len = packet->get_data()->length();
        pkt_hdr.caplen = pkt_hdr.len;

        stream.write((const char *) &pkt_hdr, sizeof(pkt_hdr));
        stream.write((const char *) packet->get_data()->get().data(), pkt_hdr.len);
    }

    if (mode == "handshake") {
        // Write all the handshakes
        if (dot11dev->has_wpa_key_vec()) {
            for (const auto& i : *(dot11dev->get_wpa_key_vec())) {
                auto eapol =
                    std::static_pointer_cast<dot11_tracked_eapol>(i);

                auto packet = eapol->get_eapol_packet();

                // Make a pcap header
                pkt_hdr.timeval_s = packet->get_ts_sec();
                pkt_hdr.timeval_us = packet->get_ts_usec();

                pkt_hdr.len = packet->get_data()->length();
                pkt_hdr.caplen = pkt_hdr.len;

                stream.write((const char *) &pkt_hdr, sizeof(pkt_hdr));
                stream.write((const char *) packet->get_data()->get().data(), pkt_hdr.len);
            }
        }
    } else if (mode == "pmkid") {
        // Write just the pmkid
        if (dot11dev->get_pmkid_present()) {
            auto packet = dot11dev->get_pmkid_packet();

            pkt_hdr.timeval_s = packet->get_ts_sec();
            pkt_hdr.timeval_us = packet->get_ts_usec();

            pkt_hdr.len = packet->get_data()->length();
            pkt_hdr.caplen = pkt_hdr.len;

            stream.write((const char *) &pkt_hdr, sizeof(pkt_hdr));
            stream.write((const char *) packet->get_data()->get().data(), pkt_hdr.len);
        }
    }
}

class phy80211_devicetracker_expire_worker : public device_tracker_view_worker {
public:
    phy80211_devicetracker_expire_worker(int in_timeout, unsigned int in_packets, int entry_id) {
        dot11_device_entry_id = entry_id;
        timeout = in_timeout;
        packets = in_packets;
        devicetracker =
            Globalreg::fetch_mandatory_global_as<device_tracker>();
    }

    virtual ~phy80211_devicetracker_expire_worker() { }

    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override {
        auto dot11dev =
            device->get_sub_as<dot11_tracked_device>(dot11_device_entry_id);

        if (dot11dev == NULL) {
            return false;
        }

        if (dot11dev->has_advertised_ssid_map()) {
            auto adv_ssid_map = dot11dev->get_advertised_ssid_map();
            std::shared_ptr<dot11_advertised_ssid> ssid = NULL;

            for (auto itr = adv_ssid_map->begin(); itr != adv_ssid_map->end(); ++itr) {
                // Always leave one
                if (adv_ssid_map->size() <= 1)
                    break;

                ssid = std::static_pointer_cast<dot11_advertised_ssid>(itr->second);

                if (time(0) - ssid->get_last_time() > timeout && device->get_packets() < packets) {
                    if (dot11dev->get_last_adv_ssid() == ssid) {
                        dot11dev->set_last_adv_ssid(NULL);
                        dot11dev->set_last_adv_ie_csum(0);
                    }

                    adv_ssid_map->erase(itr);
                    itr = adv_ssid_map->begin();
                    devicetracker->update_full_refresh();
                }
            }
        }

        if (dot11dev->has_responded_ssid_map()) {
            auto resp_ssid_map = dot11dev->get_responded_ssid_map();
            std::shared_ptr<dot11_advertised_ssid> ssid = NULL;

            for (auto itr = resp_ssid_map->begin(); itr != resp_ssid_map->end(); ++itr) {
                // Always leave one
                if (resp_ssid_map->size() <= 1)
                    break;

                ssid = std::static_pointer_cast<dot11_advertised_ssid>(itr->second);

                if (time(0) - ssid->get_last_time() > timeout && device->get_packets() < packets) {
                    if (dot11dev->get_last_adv_ssid() == ssid) {
                        dot11dev->set_last_adv_ssid(NULL);
                        dot11dev->set_last_adv_ie_csum(0);
                    }

                    resp_ssid_map->erase(itr);
                    itr = resp_ssid_map->begin();
                    devicetracker->update_full_refresh();
                }
            }
        }

        if (dot11dev->has_probed_ssid_map()) {
            auto probe_map = dot11dev->get_probed_ssid_map();
            std::shared_ptr<dot11_probed_ssid> pssid = NULL;

            for (auto itr = probe_map->begin(); itr != probe_map->end(); ++itr) {
                // Always leave one
                if (probe_map->size() <= 1)
                    break;

                pssid = std::static_pointer_cast<dot11_probed_ssid>(itr->second);

                if (time(0) - pssid->get_last_time() > timeout && device->get_packets() < packets) {
                    probe_map->erase(itr);
                    itr = probe_map->begin();
                    devicetracker->update_full_refresh();
                }
            }
        }

        if (dot11dev->has_client_map()) {
            auto client_map = dot11dev->get_client_map();
            std::shared_ptr<dot11_client> client = NULL;
            tracker_element_mac_map::iterator mac_itr;

            for (mac_itr = client_map->begin(); mac_itr != client_map->end(); ++mac_itr) {
                // Always leave one
                if (client_map->size() <= 1)
                    break;

                client = std::static_pointer_cast<dot11_client>(mac_itr->second);

                if (time(0) - client->get_last_time() > timeout && device->get_packets() < packets) {
                    client_map->erase(mac_itr);
                    mac_itr = client_map->begin();
                    devicetracker->update_full_refresh();
                }
            }
        }

        return false;
    }

protected:
    std::shared_ptr<device_tracker> devicetracker;
    int dot11_device_entry_id;
    int timeout;
    unsigned int packets;
};

int kis_80211_phy::timetracker_event(int eventid) {
    // Spawn a worker to handle this
    if (eventid == device_idle_timer) {
        phy80211_devicetracker_expire_worker worker(device_idle_expiration, 
                device_idle_min_packets, dot11_device_entry_id);
        devicetracker->do_device_work(worker);
    }

    // Loop
    return 1;
}

void kis_80211_phy::load_phy_storage(shared_tracker_element in_storage, shared_tracker_element in_device) {
    if (in_storage == NULL || in_device == NULL)
        return;

    if (in_storage->get_type() != tracker_type::tracker_map)
        return;

    auto in_map =
        std::static_pointer_cast<tracker_element_map>(in_storage);

    // Does the imported record have dot11?
    auto d11devi = in_map->find(dot11_device_entry_id);

    // Adopt it into a dot11
    if (d11devi != in_map->end()) {
        if (d11devi->second->get_type() != tracker_type::tracker_map)
            return;

        auto d11dev =
            entrytracker->get_shared_instance_as<dot11_tracked_device>(dot11_device_entry_id);

        in_map->insert(d11dev);
    }
}

