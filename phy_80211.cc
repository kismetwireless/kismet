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

#include "globalregistry.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "timetracker.h"
#include "filtercore.h"
#include "gps_manager.h"
#include "packet.h"
#include "uuid.h"
#include "alertracker.h"
#include "manuf.h"
#include "configfile.h"
#include "packetsource.h"

#include "base64.h"

#include "devicetracker.h"
#include "phy_80211.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

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
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {

	globalreg->InsertGlobal("PHY_80211", this);

	// Initialize the crc tables
	crc32_init_table_80211(globalreg->crc32_table);

	phyname = "IEEE802.11";

    dot11_tracked_device *dot11_builder = 
        new dot11_tracked_device(globalreg, 0);
    dot11_device_entry_id =
        globalreg->entrytracker->RegisterField("dot11.device", dot11_builder, 
                "IEEE802.11 device");

	// Packet classifier - makes basic records plus dot11 data
	globalreg->packetchain->RegisterHandler(&CommonClassifierDot11, this,
											CHAINPOS_CLASSIFIER, -100);

	globalreg->packetchain->RegisterHandler(&phydot11_packethook_wep, this,
											CHAINPOS_DECRYPT, -100);
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11, this,
											CHAINPOS_LLCDISSECT, -100);
#if 0
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11data, this,
											CHAINPOS_DATADISSECT, -100);
	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11string, this,
											CHAINPOS_DATADISSECT, -99);
#endif

	globalreg->packetchain->RegisterHandler(&phydot11_packethook_dot11tracker, this,
											CHAINPOS_TRACKER, 100);

	// dot11 device comp
	dev_comp_dot11 = devicetracker->RegisterDeviceComponent("DOT11_DEVICE");
	dev_comp_common = devicetracker->RegisterDeviceComponent("COMMON");

	// If we haven't registered packet components yet, do so.  We have to
	// co-exist with the old tracker core for some time
	pack_comp_80211 = _PCM(PACK_COMP_80211) =
		globalreg->packetchain->RegisterPacketComponent("PHY80211");

	pack_comp_basicdata = 
		globalreg->packetchain->RegisterPacketComponent("BASICDATA");

	pack_comp_mangleframe = 
		globalreg->packetchain->RegisterPacketComponent("MANGLEDATA");

	pack_comp_checksum =
		globalreg->packetchain->RegisterPacketComponent("CHECKSUM");

	pack_comp_linkframe = 
		globalreg->packetchain->RegisterPacketComponent("LINKFRAME");

	pack_comp_decap =
		globalreg->packetchain->RegisterPacketComponent("DECAP");

	pack_comp_common = 
		globalreg->packetchain->RegisterPacketComponent("COMMON");

	pack_comp_datapayload =
		globalreg->packetchain->RegisterPacketComponent("DATAPAYLOAD");

	pack_comp_gps =
		globalreg->packetchain->RegisterPacketComponent("GPS");

	// Register the dissector alerts
	alert_netstumbler_ref = 
		globalreg->alertracker->ActivateConfiguredAlert("NETSTUMBLER", phyid);
	alert_nullproberesp_ref =
		globalreg->alertracker->ActivateConfiguredAlert("NULLPROBERESP", phyid);
	alert_lucenttest_ref =
		globalreg->alertracker->ActivateConfiguredAlert("LUCENTTEST", phyid);
	alert_msfbcomssid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MSFBCOMSSID", phyid);
	alert_msfdlinkrate_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MSFDLINKRATE", phyid);
	alert_msfnetgearbeacon_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MSFNETGEARBEACON", phyid);
	alert_longssid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("LONGSSID", phyid);
	alert_disconinvalid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DISCONCODEINVALID", phyid);
	alert_deauthinvalid_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DEAUTHCODEINVALID", phyid);
#if 0
	alert_dhcpclient_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPCLIENTID", phyid);
#endif

	// Register the tracker alerts
	alert_chan_ref =
		globalreg->alertracker->ActivateConfiguredAlert("CHANCHANGE", phyid);
	alert_dhcpcon_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPCONFLICT", phyid);
	alert_bcastdcon_ref =
		globalreg->alertracker->ActivateConfiguredAlert("BCASTDISCON", phyid);
	alert_airjackssid_ref = 
		globalreg->alertracker->ActivateConfiguredAlert("AIRJACKSSID", phyid);
	alert_wepflap_ref =
		globalreg->alertracker->ActivateConfiguredAlert("CRYPTODROP", phyid);
	alert_dhcpname_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPNAMECHANGE", phyid);
	alert_dhcpos_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DHCPOSCHANGE", phyid);
	alert_adhoc_ref =
		globalreg->alertracker->ActivateConfiguredAlert("ADHOCCONFLICT", phyid);
	alert_ssidmatch_ref =
		globalreg->alertracker->ActivateConfiguredAlert("APSPOOF", phyid);
	alert_dot11d_ref =
		globalreg->alertracker->ActivateConfiguredAlert("DOT11D", phyid);
	alert_beaconrate_ref =
		globalreg->alertracker->ActivateConfiguredAlert("BEACONRATE", phyid);
	alert_cryptchange_ref =
		globalreg->alertracker->ActivateConfiguredAlert("ADVCRYPTCHANGE", phyid);
	alert_malformmgmt_ref =
		globalreg->alertracker->ActivateConfiguredAlert("MALFORMMGMT", phyid);
	alert_wpsbrute_ref =
		globalreg->alertracker->ActivateConfiguredAlert("WPSBRUTE", phyid);

	// Do we process the whole data packet?
    if (globalreg->kismet_config->FetchOptBoolean("hidedata", 0) ||
		globalreg->kismet_config->FetchOptBoolean("dontbeevil", 0)) {
		_MSG("hidedata= set in Kismet config.  Kismet will ignore the contents "
			 "of data packets entirely", MSGFLAG_INFO);
		dissect_data = 0;
	} else {
		dissect_data = 1;
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

	conf_save = globalreg->timestamp.tv_sec;

	ssid_conf = new ConfigFile(globalreg);
	ssid_conf->ParseConfig(ssid_conf->ExpandLogPath(globalreg->kismet_config->FetchOpt("configdir") + "/" + "ssid_map.conf", "", "", 0, 1).c_str());
	globalreg->InsertGlobal("SSID_CONF_FILE", ssid_conf);

}

Kis_80211_Phy::~Kis_80211_Phy() {
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_wep, CHAINPOS_DECRYPT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11, 
										  CHAINPOS_LLCDISSECT);
	/*
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11data, 
										  CHAINPOS_DATADISSECT);
	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11string,
										  CHAINPOS_DATADISSECT);
										  */
	globalreg->packetchain->RemoveHandler(&CommonClassifierDot11,
										  CHAINPOS_CLASSIFIER);

	globalreg->packetchain->RemoveHandler(&phydot11_packethook_dot11tracker, 
										  CHAINPOS_TRACKER);

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

	if (dot11info == NULL)
		return 0;

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
        if (dot11info->subtype == packet_sub_ack ||
                dot11info->subtype == packet_sub_cts) {
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
            ci->error = 1;
        }
	} 

	if (dot11info->type == packet_noise || dot11info->corrupt ||
			   in_pack->error || dot11info->type == packet_unknown ||
			   dot11info->subtype == packet_sub_unknown) {
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

void Kis_80211_Phy::HandleSSID(kis_tracked_device_base *basedev,
        dot11_tracked_device *dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    TrackerElement *adv_ssid_map = dot11dev->get_advertised_ssid_map();

    dot11_advertised_ssid *ssid = NULL;

    TrackerElement::map_iterator ssid_itr;

    if (adv_ssid_map == NULL) {
        fprintf(stderr, "debug - dot11phy::HandleSSID can't find the adv_ssid_map or probe_ssid_map struct, something is wrong\n");
        return;
    }

    bool ssid_new = false;

    if (dot11info->subtype == packet_sub_beacon ||
            dot11info->subtype == packet_sub_probe_resp) {
        ssid_itr = adv_ssid_map->find((int32_t) dot11info->ssid_csum);

        if (ssid_itr == adv_ssid_map->end()) {
            ssid = dot11dev->new_advertised_ssid();
            adv_ssid_map->add_intmap((int32_t) dot11info->ssid_csum, ssid);

            ssid_new = true;
        } else {
            ssid = (dot11_advertised_ssid *) ssid_itr->second;

        }

        if (dot11info->subtype == packet_sub_beacon) {
            // Update the base device records
            dot11dev->set_last_beaconed_ssid(ssid->get_ssid());
            dot11dev->set_last_beaconed_ssid_csum(dot11info->ssid_csum);

            basedev->set_devicename(ssid->get_ssid());

            // Set the type
            ssid->set_ssid_beacon(true);
        } else if (dot11info->subtype == packet_sub_probe_resp) {
            ssid->set_ssid_probe_response(true);
            dot11dev->set_last_probed_ssid(ssid->get_ssid());
            dot11dev->set_last_probed_ssid_csum(dot11info->ssid_csum);
        }
    }

    if (ssid_new) {
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

        ssid->set_last_time(in_pack->ts.tv_sec);
        ssid->inc_beacons_sec();
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
            fprintf(stderr, "debug - dot11phy::HandleSSID %s cryptset changed\n", basedev->get_macaddr().Mac2String().c_str());

            ssid->set_crypt_set(dot11info->cryptset);
        }

        if (ssid->get_channel() != dot11info->channel) {
            fprintf(stderr, "debug - dot11phy:HandleSSID %s channel changed\n", basedev->get_macaddr().Mac2String().c_str());

            ssid->set_channel(dot11info->channel); 

            // TODO raise alert
        }

        if (ssid->get_dot11d_country() != dot11info->dot11d_country) {
            fprintf(stderr, "debug - dot11phy:HandleSSID %s dot11d country changed\n", basedev->get_macaddr().Mac2String().c_str());

            ssid->set_dot11d_country(dot11info->dot11d_country);

            // TODO raise alert
        }

        vector<TrackerElement *> *dot11dvec =
            ssid->get_dot11d_vec()->get_vector();
        bool dot11dmismatch = false;
        for (unsigned int vc = 0; 
                vc < dot11dvec->size() && vc < dot11info->dot11d_vec.size(); 
                vc++) {
            dot11_11d_tracked_range_info *ri = 
                (dot11_11d_tracked_range_info *)(*dot11dvec)[vc];

            if (ri->get_startchan() != dot11info->dot11d_vec[vc].startchan ||
                    ri->get_numchan() != dot11info->dot11d_vec[vc].numchan ||
                    ri->get_txpower() != dot11info->dot11d_vec[vc].txpower) {
                dot11dmismatch = true;
                break;
            }
        }

        if (dot11dmismatch) {
            fprintf(stderr, "debug - dot11phy:HandleSSID %s dot11d channels changed\n", basedev->get_macaddr().Mac2String().c_str());

            ssid->set_dot11d_vec(dot11info->dot11d_vec);

            // TODO raise alert
        }

        if (ssid->get_wps_state() != dot11info->wps) {
            fprintf(stderr, "debug - dot11phy:HandleSSID %s wps state changed %u to %u\n", basedev->get_macaddr().Mac2String().c_str(), ssid->get_wps_state(), dot11info->wps);
            ssid->set_wps_state(dot11info->wps);

            // TODO raise alert?
        }

        ssid->set_ietag_checksum(dot11info->ietag_csum);
    }

    // TODO alert on cryptset degrade/change?
    if (ssid->get_crypt_set() != dot11info->cryptset) {
        fprintf(stderr, "debug - dot11phy:HandleSSID cryptset changed\n");
    }

    ssid->set_crypt_set(dot11info->cryptset);

    ssid->set_maxrate(dot11info->maxrate);
    ssid->set_beaconrate(Ieee80211Interval2NSecs(dot11info->beacon_interval));

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

void Kis_80211_Phy::HandleProbedSSID(kis_tracked_device_base *basedev,
        dot11_tracked_device *dot11dev,
        kis_packet *in_pack,
        dot11_packinfo *dot11info,
        kis_gps_packinfo *pack_gpsinfo) {

    TrackerElement *adv_ssid_map = dot11dev->get_advertised_ssid_map();

}

void Kis_80211_Phy::HandleClient(kis_tracked_device_base *basedev,
        dot11_tracked_device *dot11dev,
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

    // Get a client record for us behaving AS a client
    TrackerElement *client_map = dot11dev->get_client_map();

    dot11_client *client = NULL;

    TrackerElement::mac_map_iterator client_itr;

    if (client_map == NULL) {
        fprintf(stderr, "debug - dot11phy::HandleClient can't find the client_map struct, something is wrong\n");
        return;
    }

    client_itr = client_map->mac_find(dot11info->bssid_mac);

    bool new_client = false;
    if (client_itr == client_map->mac_end()) {
        client = dot11dev->new_client();
        fprintf(stderr, "debug - associating client %s with %s\n", basedev->get_macaddr().Mac2String().c_str(), dot11info->bssid_mac.Mac2String().c_str());
        client_map->add_macmap(dot11info->bssid_mac, client);
        new_client = true;
    } else {
        client = (dot11_client *) client_itr->second;
    }

    if (new_client) {
        client->set_bssid(dot11info->bssid_mac);
        client->set_first_time(in_pack->ts.tv_sec);
    }

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
                        client->get_dhcp_vendor() != pack_datainfo->discover_vendor) {
                    // TODO alert, DHCP vendor changed
                }

                client->set_dhcp_vendor(pack_datainfo->discover_vendor);
            }

            if (pack_datainfo->discover_host != "") {
                if (client->get_dhcp_host() != "" &&
                        client->get_dhcp_host() != pack_datainfo->discover_host) {
                    // TODO alert, DHCP host changed
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

}

static int packetnum = 0;

int Kis_80211_Phy::TrackerDot11(kis_packet *in_pack) {
    packetnum++;

	// We can't do anything w/ it from the packet layer
	if (in_pack->error || in_pack->filtered) {
		return 0;
	}

	// Fetch what we already know about the packet.  
	dot11_packinfo *dot11info =
		(dot11_packinfo *) in_pack->fetch(pack_comp_80211);

	// Got nothing to do
	if (dot11info == NULL)
		return 0;

	kis_common_info *commoninfo =
		(kis_common_info *) in_pack->fetch(pack_comp_common);

	if (commoninfo == NULL)
		return 0;

	if (commoninfo->error)
		return 0;

    // There's nothing we can sensibly do with completely corrupt packets, 
    // so we just get rid of them.
    // TODO make sure phy corrupt packets are handled for statistics
    if (dot11info->corrupt) 
        return 0;

    // Find & update the common attributes of our base record.
    // We want to update signal, frequency, location, packet counts, devices,
    // and encryption, because this is the core record for everything we do.
    // We do this early on because we want to track things even if they're unknown
    // or broken.
    kis_tracked_device_base *basedev =
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
		dot11info->subtype == packet_sub_unknown)
		return 0;

	kis_gps_packinfo *pack_gpsinfo =
		(kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);

    // Something bad has happened if we can't find our device
    if (basedev == NULL) {
        fprintf(stderr, "debug - phydot11 got to tracking stage with no devicetracker device for %s.  Something is wrong?\n", commoninfo->device.Mac2String().c_str());
        return 0;
    }

    // Lock the basedev
    tracker_component_locker base_locker(basedev);

    dot11_tracked_device *dot11dev =
        (dot11_tracked_device *) basedev->get_map_value(dot11_device_entry_id);

    if (dot11dev == NULL) {
        printf("debug - phydot11 making new 802.11 device record for '%s'\n",
                commoninfo->device.Mac2String().c_str());

        dot11dev = new dot11_tracked_device(globalreg, dot11_device_entry_id);
        basedev->add_map(dot11dev);
    }

    // Handle beacons and SSID responses from the AP.  This is still all the same
    // basic device
    if (dot11info->type == packet_management && 
            (dot11info->subtype == packet_sub_beacon ||
             dot11info->subtype == packet_sub_probe_resp)) {
        HandleSSID(basedev, dot11dev, in_pack, dot11info, pack_gpsinfo);
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

	if (dot11info->type == packet_phy) {
        // Phy to a known device mac, we know it's a wifi device
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_CLIENT);

        // If we're only a client, set the type name and device name
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

        dot11dev->bitset_type_set(DOT11_DEVICE_TYPE_BEACON_AP);
    } else if (dot11info->distrib == distrib_inter) {
        // Adhoc
        basedev->bitset_basic_type_set(KIS_DEVICE_BASICTYPE_PEER);

        if (basedev->get_basic_type_set() == KIS_DEVICE_BASICTYPE_PEER)
            basedev->set_type_string("Wi-Fi Ad-hoc Device");

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
    } else if (dot11info->bssid_mac != basedev->get_macaddr() &&
            dot11info->distrib == distrib_to) {

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

    if (basedev->get_type_string() == "") {
        printf("unclassed device as of packet %d\n", packetnum);
    }


#if 0

	if (dot11info->ess) {
		dot11dev->type_set |= dot11_network_ap;
		commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_AP;
		commondev->type_string = "AP";
	} else if (dot11info->distrib == distrib_from &&
			   dot11info->type == packet_data) {
		commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_WIRED;
		dot11dev->type_set |= dot11_network_wired;

		if (!(commondev->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) 
			commondev->type_string = "Wired";
	} else if (dot11info->distrib == distrib_to &&
			   dot11info->type == packet_data) {
		dot11dev->type_set |= dot11_network_client;

		if (!(commondev->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) {
			commondev->type_string = "Client";
			commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_CLIENT;
		}
	} else if (dot11info->distrib == distrib_inter) {
		dot11dev->type_set |= dot11_network_wds;
		commondev->type_string = "WDS";
	} else if (dot11info->type == packet_management &&
			   dot11info->subtype == packet_sub_probe_req) {
		dot11dev->type_set |= dot11_network_client;

		if (!(commondev->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) {
			commondev->type_string = "Client";
			commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_CLIENT;
		}
	} else if (dot11info->distrib == distrib_adhoc) {
		// Throw alert if device changes to adhoc
		if (!(dot11dev->type_set & dot11_network_adhoc)) {
			if (dot11info->distrib == distrib_adhoc && 
				(dot11dev->type_set & dot11_network_ap)) {
				string al = "IEEE80211 Network BSSID " + 
					dot11info->bssid_mac.Mac2String() + 
					" previously advertised as AP network, now advertising as "
					"Ad-Hoc which may indicate AP spoofing/impersonation";

				globalreg->alertracker->RaiseAlert(alert_adhoc_ref, in_pack,
												   dot11info->bssid_mac,
												   dot11info->source_mac,
												   dot11info->dest_mac,
												   dot11info->other_mac,
												   dot11info->channel, al);
			}
		}

		dot11dev->type_set |= dot11_network_adhoc;

		// printf("debug - setting type peer on network because we saw an explicit adhoc packet\n");
		commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_PEER |
			KIS_DEVICE_BASICTYPE_CLIENT;

		if (!(commondev->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) 
			commondev->type_string = "Ad-Hoc";

	} else if (dot11info->type == packet_management) {
		if (dot11info->subtype == packet_sub_disassociation ||
			dot11info->subtype == packet_sub_deauthentication)
			dot11dev->type_set |= dot11_network_ap;

		commondev->type_string = "AP";

		if (dot11info->subtype == packet_sub_authentication &&
			dot11info->source_mac == dot11info->bssid_mac) {

			commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_AP;
			dot11dev->type_set |= dot11_network_ap;
			commondev->type_string = "AP";

		} else {
			commondev->basic_type_set |= KIS_DEVICE_BASICTYPE_CLIENT;
			dot11dev->type_set |= dot11_network_client;
			commondev->type_string = "Client";
		}
	}

	if (dot11dev->type_set == dot11_network_none) {
		printf("debug - unknown net typeset for bs %s sr %s dt %s type %u sub %u\n", dot11info->bssid_mac.Mac2String().c_str(), dot11info->source_mac.Mac2String().c_str(), dot11info->dest_mac.Mac2String().c_str(), dot11info->type, dot11info->subtype);
		if (commondev->type_string == "")
			commondev->type_string = "Unknown";
	}

	if (dot11dev->type_set & dot11_network_inferred) {
		// printf("debug - net %s no longer inferred, saw a packet from it\n", dev->key.Mac2String().c_str());
		dot11dev->type_set &= ~dot11_network_inferred;
	}

	// we need to figure out the access point that this is happening with;
	// if we're acting as an AP already, it's us
	kis_tracked_device *apdev = NULL;

	// Don't map to a bssid device if we're broadcast or we're ourselves
	if (dot11info->bssid_mac == dot11info->source_mac) {
		net = dot11dev;
		apdev = dev;
		build_net = false;
	} else if (dot11info->bssid_mac == globalreg->broadcast_mac) {
		apdev = devicetracker->MapToDevice(dot11info->source_mac, in_pack);
		build_net = false;
	} else if (dot11info->bssid_mac != globalreg->broadcast_mac) {
		apdev = devicetracker->MapToDevice(dot11info->bssid_mac, in_pack);
		if (apdev != NULL)
			net = (dot11_device *) apdev->fetch(dev_comp_dot11);
	} else {
		build_net = false;
	}

#if 0
	if (apdev == NULL)
		printf("debug - apdev null bssid %s source %s dest %s type %d sub %d\n", dot11info->bssid_mac.Mac2String().c_str(), dot11info->source_mac.Mac2String().c_str(), dot11info->dest_mac.Mac2String().c_str(), dot11info->type, dot11info->subtype);
#endif

	// Flag the AP as an AP
	if (apdev != NULL) {
		apcommon = 
			(kis_device_common *) apdev->fetch(dev_comp_common);

		// Add to the counters for the AP record
		if (apdev != dev)
			devicetracker->PopulateCommon(apdev, in_pack);

		if (apcommon != NULL) {
			apcommon->basic_type_set |= KIS_DEVICE_BASICTYPE_AP;

			if (dot11info->distrib == distrib_adhoc) {
				// printf("debug - apdev null, distrib is distrib adhoc\n");
				apcommon->basic_type_set |= KIS_DEVICE_BASICTYPE_PEER;
				apcommon->type_string = "Ad-Hoc";
			}
		}
	}

	// If we need to make a network, it's because we're talking to a bssid
	// that isn't visible/hasn't yet been seen.  We make it as an inferred
	// device.
	if (net == NULL && build_net) {
		net = new dot11_device();

		// printf("debug - making inferred net for bs %s sr %s dt %s type %u sub %u\n", dot11info->bssid_mac.Mac2String().c_str(), dot11info->source_mac.Mac2String().c_str(), dot11info->dest_mac.Mac2String().c_str(), dot11info->type, dot11info->subtype);
		net_new = true;

		net->type_set |= dot11_network_inferred;
		
		// If it's not IBSS or WDS they must be talking to an AP...
		if (dot11info->distrib == distrib_adhoc)
			net->type_set |= dot11_network_adhoc;
		else if (dot11info->distrib == distrib_inter)
			net->type_set |= dot11_network_wds;
		else
			net->type_set |= dot11_network_ap;

		if (apdev != NULL) {
			apdev->insert(dev_comp_dot11, net);
		}
	}

	if (net != NULL) {
		// We have a net record, update it.
		// It may be the only record (packet came from AP), we'll
		// test that later to make sure we aren't double counting

		// Cryptset changes
		uint64_t cryptset_old = net->tx_cryptset;

		// Flag distribution
		if (dot11info->type == packet_data) {
			if (dot11info->distrib == distrib_from) {
				net->tx_cryptset |= dot11info->cryptset;
				net->tx_datasize += dot11info->datasize;
			} else if (dot11info->distrib == distrib_to) {
				net->rx_cryptset |= dot11info->cryptset;
				net->rx_datasize += dot11info->datasize;
			} else if (dot11info->distrib == distrib_adhoc ||
					   dot11info->distrib == distrib_inter) {
				net->tx_cryptset |= dot11info->cryptset;
				net->rx_cryptset |= dot11info->cryptset;
				net->tx_datasize += dot11info->datasize;
				net->rx_datasize += dot11info->datasize;
			}
		}

		bool new_decrypted = false;
		if (dot11info->decrypted && !net->decrypted) {
			new_decrypted = true;
			net->decrypted = 1;
		}

		if (dot11info->fragmented)
			net->fragments++;

		if (dot11info->retry)
			net->retries++;

		if (dot11info->type == packet_management &&
			(dot11info->subtype == packet_sub_disassociation ||
			 dot11info->subtype == packet_sub_deauthentication))
			net->client_disconnects++;

		string crypt_update;

		if (cryptset_old != net->tx_cryptset) {
			crypt_update = StringAppend(crypt_update, 
										"updated observed data encryption to " + 
										CryptToString(net->tx_cryptset));

			if (net->tx_cryptset & crypt_wps)
				apcommon->crypt_string = "WPS";
			else if (net->tx_cryptset & crypt_wpa) 
				apcommon->crypt_string = "WPA";
			else if (net->tx_cryptset & crypt_wep)
				apcommon->crypt_string = "WEP";
		}

		if (new_decrypted) {
			crypt_update = StringAppend(crypt_update,
										"began decrypting data",
										"and");
		}

		if (crypt_update != "")
			_MSG("IEEE80211 BSSID " + dot11info->bssid_mac.Mac2String() + " " +
				 crypt_update, MSGFLAG_INFO);

		net->dirty = 1;
	} 
	
	if (dot11dev == net) {
		// This is a packet from the AP, update stuff that we only update
		// when the AP says it...

		// printf("debug - self = ap, %p\n", dot11dev);

		// Only update these when sources from the AP
		net->bss_timestamp = dot11info->timestamp;
		net->last_sequence = dot11info->sequence_number;

		if (datainfo != NULL) {
			if (datainfo->cdp_dev_id != "") {
				net->cdp_dev_id = datainfo->cdp_dev_id;
			}

			if (datainfo->cdp_port_id != "") {
				net->cdp_port_id = datainfo->cdp_port_id;
			}
		}
	} else if (dot11dev != net) {
		// We're a client packet
		if (datainfo != NULL) {
			if (datainfo->proto == proto_eap) {
				if (datainfo->auxstring != "") {
					dot11dev->eap_id = datainfo->auxstring;
				}
			}

			if (datainfo->cdp_dev_id != "") {
				dot11dev->cdp_dev_id = datainfo->cdp_dev_id;
			}

			if (datainfo->cdp_port_id != "") {
				dot11dev->cdp_port_id = datainfo->cdp_port_id;
			}

			if (datainfo->discover_vendor != "") {
				dot11dev->dhcp_vendor = datainfo->discover_vendor;
			}

			if (datainfo->discover_host != "") {
				dot11dev->dhcp_host = datainfo->discover_host;
			}
		}

		if (dot11info->bssid_mac != globalreg->broadcast_mac)
			dot11dev->last_bssid = dot11info->bssid_mac;

		if (net != NULL) {
			// we're a client; find a client record, if we know what the network is
			map<mac_addr, dot11_client *>::iterator ci =
				net->client_map.find(dot11info->source_mac);

			if (ci == net->client_map.end()) {
				cli = new dot11_client;

				cli_new = true;

				cli->first_time = in_pack->ts.tv_sec;

				cli->mac = dot11info->source_mac;
				cli->bssid = dot11dev->mac;

				if (globalreg->manufdb != NULL)
					cli->manuf = globalreg->manufdb->LookupOUI(cli->mac);

				net->client_map.insert(pair<mac_addr, 
									   dot11_client *>(dot11info->source_mac, cli));

				// printf("debug - new client %s on %s\n", dot11info->source_mac.Mac2String().c_str(), dot11info->bssid_mac.Mac2String().c_str());
			} else {
				cli = ci->second;
			}

			cli->dirty = 1;

			cli->last_time = in_pack->ts.tv_sec;

			if (dot11info->ess) {
				cli->type = dot11_network_ap;
			} else if (dot11info->distrib == distrib_from &&
					   dot11info->type == packet_data) {
				cli->type = dot11_network_wired;
			} else if (dot11info->distrib == distrib_to &&
					   dot11info->type == packet_data) {
				cli->type = dot11_network_client;
			} else if (dot11info->distrib == distrib_inter) {
				cli->type = dot11_network_wds;
			} else if (dot11info->type == packet_management &&
					   dot11info->subtype == packet_sub_probe_req) {
				cli->type = dot11_network_client;
			} else if (dot11info->distrib == distrib_adhoc) {
				cli->type = dot11_network_adhoc;
			}

			if (dot11info->decrypted)
				cli->decrypted = 1;

			cli->last_sequence = dot11info->sequence_number;

			if (datainfo != NULL) {
				if (datainfo->proto == proto_eap) {
					if (datainfo->auxstring != "") {
						// printf("debug - client %s on %s got EAP ID %s\n", dot11info->source_mac.Mac2String().c_str(), dot11info->bssid_mac.Mac2String().c_str(), datainfo->auxstring.c_str());
						cli->eap_id = datainfo->auxstring;
					}
				}

				if (datainfo->cdp_dev_id != "") {
					cli->cdp_dev_id = datainfo->cdp_dev_id;
				}

				if (datainfo->cdp_port_id != "") {
					cli->cdp_port_id = datainfo->cdp_port_id;
				}

				if (datainfo->discover_vendor != "") {
					if (cli->dhcp_vendor != "" &&
						cli->dhcp_vendor != datainfo->discover_vendor &&
						globalreg->alertracker->PotentialAlert(alert_dhcpos_ref)) {
						string al = "IEEE80211 network BSSID " + 
							apdev->key.Mac2String() +
							" client " + 
							cli->mac.Mac2String() + 
							"changed advertised DHCP vendor from '" +
							dot11dev->dhcp_vendor + "' to '" +
							datainfo->discover_vendor + "' which may indicate "
							"client spoofing or impersonation";

						globalreg->alertracker->RaiseAlert(alert_dhcpos_ref, in_pack,
														   dot11info->bssid_mac,
														   dot11info->source_mac,
														   dot11info->dest_mac,
														   dot11info->other_mac,
														   dot11info->channel, al);
					}

					cli->dhcp_vendor = datainfo->discover_vendor;
				}

				if (datainfo->discover_host != "") {
					if (cli->dhcp_host != "" &&
						cli->dhcp_host != datainfo->discover_host &&
						globalreg->alertracker->PotentialAlert(alert_dhcpname_ref)) {
						string al = "IEEE80211 network BSSID " + 
							apdev->key.Mac2String() +
							" client " + 
							cli->mac.Mac2String() + 
							"changed advertised DHCP hostname from '" +
							dot11dev->dhcp_host + "' to '" +
							datainfo->discover_host + "' which may indicate "
							"client spoofing or impersonation";

						globalreg->alertracker->RaiseAlert(alert_dhcpname_ref, in_pack,
														   dot11info->bssid_mac,
														   dot11info->source_mac,
														   dot11info->dest_mac,
														   dot11info->other_mac,
														   dot11info->channel, al);
					}

					cli->dhcp_host = datainfo->discover_host;
				}
			}

			if (dot11info->type == packet_data) {
				if (dot11info->distrib == distrib_from) {
					cli->tx_cryptset |= dot11info->cryptset;
					cli->tx_datasize += dot11info->datasize;
				} else if (dot11info->distrib == distrib_to) {
					cli->rx_cryptset |= dot11info->cryptset;
					cli->rx_datasize += dot11info->datasize;
				} else if (dot11info->distrib == distrib_adhoc ||
						   dot11info->distrib == distrib_inter) {
					cli->tx_cryptset |= dot11info->cryptset;
					cli->rx_cryptset |= dot11info->cryptset;
					cli->tx_datasize += dot11info->datasize;
					cli->rx_datasize += dot11info->datasize;
				}
			}

		}

	}

	// Track the SSID data if we're a ssid-bearing packet
	if (dot11info->type == packet_management &&
		(dot11info->subtype == packet_sub_beacon || 
		 dot11info->subtype == packet_sub_probe_resp ||
		 dot11info->subtype == packet_sub_probe_req)) {

		string ptype;

		if (dot11info->subtype == packet_sub_probe_req)
			ptype = "P";
		else
			ptype = "B";

		string ssidkey = dot11info->ssid + IntToString(dot11info->ssid_len) + ptype;

		uint32_t ssidhash = Adler32Checksum(ssidkey.c_str(), ssidkey.length());

		if (net != NULL && (dot11info->subtype == packet_sub_beacon ||
							dot11info->subtype == packet_sub_probe_resp)) {
			// Should never be possible to have a null net and be a beacon/proberesp
			// but lets not make assumptions
			map<uint32_t, dot11_ssid *>::iterator si = net->ssid_map.find(ssidhash);
			if (si == net->ssid_map.end()) {
				ssid = BuildSSID(ssidhash, dot11info, in_pack);
				ssid_new = true;

				net->ssid_map[ssidhash] = ssid;

			} else {
				ssid = si->second;
			}

		} else if (dot11info->subtype == packet_sub_probe_req) {
			// If we're a probe, make a probe record
			map<uint32_t, dot11_ssid *>::iterator si = 
				dot11dev->ssid_map.find(ssidhash);
			if (si == dot11dev->ssid_map.end()) {
				ssid = BuildSSID(ssidhash, dot11info, in_pack);
				ssid_new = true;

				dot11dev->ssid_map[ssidhash] = ssid;
			} else {
				ssid = si->second;
			}
		}

		if (ssid != NULL) {
			// TODO alert for degraded crypto on probe_resp

			if (net != NULL)
				net->lastssid = ssid;

			if (cli != NULL)
				cli->lastssid = ssid;

			if (dot11info->subtype == packet_sub_beacon ||
				dot11info->subtype == packet_sub_probe_resp) {
				if (ssid->ssid == "") 
					commondev->name = "<Hidden SSID>";
				else if (ssid->ssid_cloaked)
					commondev->name = "<" + ssid->ssid + ">";
				else
					commondev->name = ssid->ssid;

				// Update the network record if it's a beacon
				// or probe resp
				if (net != NULL) {
					kis_device_common *apcommon = 
						(kis_device_common *) apdev->fetch(dev_comp_common);
					if (apcommon != NULL) {
						if (ssid->ssid == "") 
							apcommon->name = "<Hidden SSID>";
						else if (ssid->ssid_cloaked)
							apcommon->name = "<" + ssid->ssid + ">";
						else
							apcommon->name = ssid->ssid;
					}
					net->lastssid = ssid;
				}
			}

			ssid->dirty = 1;

			if (dot11info->subtype == packet_sub_beacon) {
				if (net->ssid_map.size() == 1) {
					if (ssid->cryptset & crypt_wps)
						commondev->crypt_string = "WPS";
					else if (ssid->cryptset & crypt_wpa) 
						commondev->crypt_string = "WPA";
					else if (ssid->cryptset & crypt_wep)
						commondev->crypt_string = "WEP";
				}

				unsigned int ieeerate = 
					Ieee80211Interval2NSecs(dot11info->beacon_interval);

				ssid->beacons++;

				// If we're changing from something else to a beacon...
				if (ssid->type != dot11_ssid_beacon) {
					ssid->type = dot11_ssid_beacon;
					ssid->cryptset = dot11info->cryptset;
					ssid->beaconrate = ieeerate;
					ssid->channel = dot11info->channel;
				}

				if (ssid->channel != dot11info->channel &&
					globalreg->alertracker->PotentialAlert(alert_chan_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						apdev->key.Mac2String() + " SSID \"" +
						ssid->ssid + "\" changed advertised channel from " +
						IntToString(ssid->channel) + " to " + 
						IntToString(dot11info->channel) + " which may "
						"indicate AP spoofing/impersonation";

					globalreg->alertracker->RaiseAlert(alert_chan_ref, in_pack, 
													   dot11info->bssid_mac, 
													   dot11info->source_mac, 
													   dot11info->dest_mac, 
													   dot11info->other_mac, 
													   dot11info->channel, al);

				}
				dot11info->channel = ssid->channel;

				if (ssid->ssid == "AirJack" &&
					globalreg->alertracker->PotentialAlert(alert_airjackssid_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						apdev->key.Mac2String() + " broadcasting SSID "
						"\"AirJack\" which implies an attempt to disrupt "
						"networks.";

					globalreg->alertracker->RaiseAlert(alert_airjackssid_ref, in_pack, 
													   dot11info->bssid_mac, 
													   dot11info->source_mac, 
													   dot11info->dest_mac, 
													   dot11info->other_mac, 
													   dot11info->channel, al);
				}

				if (ssid->cryptset && dot11info->cryptset == crypt_none &&
					globalreg->alertracker->PotentialAlert(alert_wepflap_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						apdev->key.Mac2String() + " SSID \"" +
						ssid->ssid + "\" changed advertised encryption from " +
						CryptToString(ssid->cryptset) + " to Open which may "
						"indicate AP spoofing/impersonation";

					globalreg->alertracker->RaiseAlert(alert_wepflap_ref, in_pack, 
													   dot11info->bssid_mac, 
													   dot11info->source_mac, 
													   dot11info->dest_mac, 
													   dot11info->other_mac, 
													   dot11info->channel, al);
				} else if (ssid->cryptset != dot11info->cryptset &&
					globalreg->alertracker->PotentialAlert(alert_cryptchange_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						apdev->key.Mac2String() + " SSID \"" +
						ssid->ssid + "\" changed advertised encryption from " +
						CryptToString(ssid->cryptset) + " to " + 
						CryptToString(dot11info->cryptset) + " which may indicate "
						"AP spoofing/impersonation";

					globalreg->alertracker->RaiseAlert(alert_cryptchange_ref, in_pack, 
													   dot11info->bssid_mac, 
													   dot11info->source_mac, 
													   dot11info->dest_mac, 
													   dot11info->other_mac, 
													   dot11info->channel, al);
				}

				ssid->cryptset = dot11info->cryptset;

				if (ssid->beaconrate != ieeerate &&
					globalreg->alertracker->PotentialAlert(alert_beaconrate_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						apdev->key.Mac2String() + " SSID \"" +
						ssid->ssid + "\" changed beacon rate from " +
						IntToString(ssid->beaconrate) + " to " + 
						IntToString(ieeerate) + " which may indicate "
						"AP spoofing/impersonation";

					globalreg->alertracker->RaiseAlert(alert_beaconrate_ref, in_pack, 
													   dot11info->bssid_mac, 
													   dot11info->source_mac, 
													   dot11info->dest_mac, 
													   dot11info->other_mac, 
													   dot11info->channel, al);
				}

				ssid->beaconrate = ieeerate;

				bool dot11dfail = false;
				string dot11dfailreason;

				if (ssid->dot11d_country != dot11info->dot11d_country &&
					ssid->dot11d_country != "") {
					dot11dfail = true;
					dot11dfailreason = "changed 802.11d country from \"" + 
						ssid->dot11d_country + "\" to \"" +
						dot11info->dot11d_country + "\"";
				}

				if (ssid->dot11d_vec.size() > 0) {
					for (unsigned int x = 0; x < ssid->dot11d_vec.size() && 
						 x < dot11info->dot11d_vec.size(); x++) {
						if (ssid->dot11d_vec[x].startchan !=
							dot11info->dot11d_vec[x].startchan)
							dot11dfail = true;
						if (ssid->dot11d_vec[x].numchan !=
							dot11info->dot11d_vec[x].numchan)
							dot11dfail = true;
						if (ssid->dot11d_vec[x].txpower !=
							dot11info->dot11d_vec[x].txpower)
							dot11dfail = true;

						if (dot11dfail) {
							dot11dfailreason = "changed 802.11d channel restrictions";
							break;
						}
					}

					if (!dot11dfail)
						if (ssid->dot11d_vec.size() !=
							dot11info->dot11d_vec.size()) {
							dot11dfail = true;
							dot11dfailreason = "changed 802.11d channel restrictions";
						}

					if (dot11dfail &&
						globalreg->alertracker->PotentialAlert(alert_dot11d_ref)) {

					string al = "IEEE80211 Access Point BSSID " +
						apdev->key.Mac2String() + " SSID \"" +
						ssid->ssid + "\" " + dot11dfailreason +
						IntToString(ieeerate) + " which may indicate "
						"AP spoofing/impersonation";

					globalreg->alertracker->RaiseAlert(alert_dot11d_ref, in_pack, 
													   dot11info->bssid_mac, 
													   dot11info->source_mac, 
													   dot11info->dest_mac, 
													   dot11info->other_mac, 
													   dot11info->channel, al);

					}

					ssid->dot11d_country = dot11info->dot11d_country;
					ssid->dot11d_vec = dot11info->dot11d_vec;

				}
			} 

			ssid->last_time = in_pack->ts.tv_sec;
		}
	}

	if (dot11info->type == packet_data &&
		dot11info->source_mac == dot11info->bssid_mac) {
		int wps = 0;
		int ssidchan = 0;
		string ssidtxt="<Unknown>";

		for (map<uint32_t, dot11_ssid *>::iterator si = net->ssid_map.begin();
			 si != net->ssid_map.end(); ++si) {
			if (si->second->cryptset & crypt_wps) {
				wps = 1;
				ssidchan = si->second->channel;
				ssidtxt = si->second->ssid;
				break;
			}
		}

		if (wps) {
			wps = PacketDot11WPSM3(in_pack);

			if (wps) {
				// if we're w/in time of the last one, update, otherwise clear
				if (globalreg->timestamp.tv_sec - net->last_wps_m3 > (60 * 5))
					net->wps_m3_count = 1;
				else
					net->wps_m3_count++;

				net->last_wps_m3 = globalreg->timestamp.tv_sec;

				if (net->wps_m3_count > 5) {
					if (globalreg->alertracker->PotentialAlert(alert_wpsbrute_ref)) {
						string al = "IEEE80211 AP '" + ssidtxt + "' (" + 
							dot11info->bssid_mac.Mac2String() +
							") sending excessive number of WPS messages which may "
							"indicate a WPS brute force attack such as Reaver";

						globalreg->alertracker->RaiseAlert(alert_wpsbrute_ref, 
														   in_pack, 
														   dot11info->bssid_mac, 
														   dot11info->source_mac, 
														   dot11info->dest_mac, 
														   dot11info->other_mac, 
														   ssidchan, al);
					}

					net->wps_m3_count = 1;
				}
			}

		}
	}

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

void Kis_80211_Phy::ExportLogRecord(kis_tracked_device_base *in_device, 
        string in_logtype, FILE *in_logfile, int in_lineindent) {
	return;
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
    if (strcmp(method, "POST") == 0 &&
            strcmp(path, "/phy/phy80211/ssid_regex.cmd") == 0)
        return true;

    return false;
}

void Kis_80211_Phy::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        struct MHD_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    return;
}

#ifdef HAVE_LIBPCRE
typedef struct {
    pcre *re;
    pcre_extra *study;
} phy80211_pcre_filter;

// Worker class.  We build a list of devices which match the PCRE filters
// and then export it as a device summary vector.
// This all happens inside the thread lock of the devicetracker worker, 
// so it's safe to build a list of devices
class phy80211_devicetracker_worker : public DevicetrackerFilterWorker {
public:
    phy80211_devicetracker_worker(GlobalRegistry *in_globalreg, 
            std::stringstream *outstream, 
            vector<phy80211_pcre_filter *> *filtervec, int entry_id) {
        globalreg = in_globalreg;
        this->outstream = outstream;
        this->filter_vec = filtervec;
        dot11_device_entry_id = entry_id;
        error = false;

        // get the summary id
        device_summary_base_id =
            globalreg->entrytracker->RegisterField("kismet.device.list", TrackerVector,
                    "list of devices");
    }

    bool get_error() { return error; }

    // Compare against our PCRE and export msgpack objects if we match
    virtual void MatchDevice(Devicetracker *devicetracker, 
            kis_tracked_device_base *device) {

        dot11_tracked_device *dot11dev =
            (dot11_tracked_device *) device->get_map_value(dot11_device_entry_id);

        // Not 802.11?  nothing we can do
        if (dot11dev == NULL) {
            return;
        }

        // Iterate over all the SSIDs
        TrackerElement *adv_ssid_map = dot11dev->get_advertised_ssid_map();
        dot11_advertised_ssid *ssid = NULL;
        TrackerElement::int_map_const_iterator ssid_itr;

        for (ssid_itr = adv_ssid_map->int_begin(); 
                ssid_itr != adv_ssid_map->int_end(); ++ssid_itr) {
            ssid = (dot11_advertised_ssid *) ssid_itr->second;
            bool device_handled = false;

            for (unsigned int i = 0; i < filter_vec->size(); i++) {
                int rc;
                int ovector[128];

                rc = pcre_exec((*filter_vec)[i]->re,
                        (*filter_vec)[i]->study,
                        ssid->get_ssid().c_str(),
                        ssid->get_ssid_len(),
                        0, 0, ovector, 128);

                // Export the device msgpack
                if (rc >= 0) {
                    device_handled = true;
                    devices.push_back(device);
                    break;
                }
            }

            // Don't match more than once on a device
            if (device_handled)
                break;
        }

    }

    virtual void Finalize(Devicetracker *devicetracker) {
        // Push the summary of devices
        devicetracker->httpd_msgpack_device_summary(*outstream, &devices);
    }

protected:
    GlobalRegistry *globalreg;
    std::stringstream *outstream;
    vector<phy80211_pcre_filter *> *filter_vec;
    bool error;
    int dot11_device_entry_id;
    int device_summary_base_id;
    vector<kis_tracked_device_base *> devices;
};

#endif

int Kis_80211_Phy::Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    Kis_Net_Httpd_Connection *concls = (Kis_Net_Httpd_Connection *) coninfo_cls;

    bool handled = false;

    if (concls->url == "/phy/phy80211/ssid_regex.cmd" &&
            strcmp(key, "msgpack") == 0 && size > 0) {
#ifdef HAVE_LIBPCRE
        MsgpackAdapter::MsgpackStrMap::iterator obj_iter;

        string decode = Base64::decode(string(data));

        vector<phy80211_pcre_filter *> filter_vec;
        std::vector<std::string> regex_vec;

        // Get the dictionary
        MsgpackAdapter::MsgpackStrMap params;
        msgpack::unpacked result;

        try {
            msgpack::unpack(result, decode.data(), decode.size());
            msgpack::object deserialized = result.get();
            params = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

            obj_iter = params.find("essid");
            if (obj_iter == params.end())
                throw std::runtime_error("expected 'essid' list");

            // Get the array of regexes
            MsgpackAdapter::AsStringVector(obj_iter->second, regex_vec);

            // Parse the PCREs we've been passed
            for (unsigned int i = 0; i < regex_vec.size(); i++) {
                phy80211_pcre_filter *filt = new phy80211_pcre_filter;
                const char *error, *study_err;
                int erroffset;
                ostringstream osstr;

                // Compile all the PCREs we got
                filt->re =
                    pcre_compile(regex_vec[i].c_str(), 0, &error, &erroffset, NULL);
                if (filt->re == NULL) {
                    delete(filt);
                    osstr << "Could not parse PCRE expression: " << error << 
                        " at " << erroffset;
                    throw std::runtime_error(osstr.str());
                }

                filt->study = pcre_study(filt->re, 0, &study_err);
                if (filt->study == NULL) {
                    osstr << "Could not parse PCRE expression, study/optimization " 
                        "failure: " << study_err;
                    pcre_free(filt->re);
                    delete(filt);
                    throw std::runtime_error(osstr.str());
                }

                filter_vec.push_back(filt);
            }

            // Make a worker instance
            phy80211_devicetracker_worker worker(globalreg,
                    &(concls->response_stream),
                    &filter_vec, dot11_device_entry_id);

            // Tell devicetracker to do the work
            devicetracker->MatchOnDevices(&worker);
            
            for (unsigned int i = 0; i < filter_vec.size(); i++) {
                pcre_free(filter_vec[i]->re);
                pcre_free(filter_vec[i]->study);
                delete filter_vec[i];
            }
            filter_vec.clear();

            return 1;

        } catch(const std::exception& e) {
            // Exceptions can be caused by missing fields, or fields which
            // aren't the format we expected.  Throw it all out with an
            // error.
            concls->response_stream << "Invalid request " << e.what();
            concls->httpcode = 400;

            for (unsigned int i = 0; i < filter_vec.size(); i++) {
                pcre_free(filter_vec[i]->re);
                pcre_free(filter_vec[i]->study);
                delete filter_vec[i];
            }
            filter_vec.clear();

            return 1;
        }

#else
        concls->response_stream << "Unable to process: Kismet not compiled with PCRE";
        concls->httpcode = 501;
        return 1;
#endif

    }

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

