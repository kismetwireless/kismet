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
#include "phy_80211.h"
#include "phy_80211_components.h"

void dot11_tracked_eapol::register_fields() {
    tracker_component::register_fields();

    RegisterField("dot11.eapol.timestamp", "packet timestamp (second.usecond)", &eapol_time);
    RegisterField("dot11.eapol.direction", "packet direction (fromds/tods)", &eapol_dir);
    RegisterField("dot11.eapol.message_num", "handshake message number", &eapol_msg_num);
    RegisterField("dot11.eapol.replay_counter", "eapol frame replay counter", &eapol_replay_counter);
    RegisterField("dot11.eapol.install", "eapol rsn key install", &eapol_install);
    RegisterField("dot11.eapol.nonce", "eapol rsn nonce", &eapol_nonce);
    RegisterField("dot11.eapol.rsn_pmkid", "eapol pmkid", &eapol_rsn_pmkid);
    RegisterField("dot11.eapol.packet", "EAPOL handshake", &eapol_packet);
}

void dot11_tracked_ssid_alert::register_fields() {
    tracker_component::register_fields();

    RegisterField("dot11.ssidalert.name", "Unique name of alert group", &ssid_group_name);
    RegisterField("dot11.ssidalert.regex", "Matching regex for SSID", &ssid_regex);
    RegisterField("dot11.ssidalert.allowed_macs", "Allowed MAC addresses", &allowed_macs_vec);

    allowed_mac_id =
        RegisterField("dot11.ssidalert.allowed_mac", 
                TrackerElementFactory<TrackerElementMacAddr>(),
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

    allowed_macs_vec->clear();

    for (auto i : mvec) {
        auto e =
            std::make_shared<TrackerElementMacAddr>(allowed_mac_id, i);
        allowed_macs_vec->push_back(e);
    }
}

bool dot11_tracked_ssid_alert::compare_ssid(std::string ssid, mac_addr mac) {
    local_locker lock(&ssid_mutex);

#ifdef HAVE_LIBPCRE
    int rc;
    int ovector[128];

    rc = pcre_exec(ssid_re, ssid_study, ssid.c_str(), ssid.length(), 0, 0, ovector, 128);

    if (rc > 0) {
        for (auto m : *allowed_macs_vec) {
            if (GetTrackerValue<mac_addr>(m) != mac)
                return true;
        }
    }
#endif

    return false;

}

void dot11_tracked_nonce::register_fields() {
    tracker_component::register_fields();

    RegisterField("dot11.eapol.nonce.timestamp", "packet timestamp (second.usecond)", &eapol_time);
    RegisterField("dot11.eapol.nonce.message_num", "handshake message number", &eapol_msg_num);
    RegisterField("dot11.eapol.nonce.replay_counter", 
            "eapol frame replay counter", &eapol_replay_counter);
    RegisterField("dot11.eapol.nonce.install", "eapol rsn key install", &eapol_install);
    RegisterField("dot11.eapol.nonce.nonce", "eapol rsn nonce", &eapol_nonce);
}

void dot11_tracked_nonce::set_from_eapol(SharedTrackerElement in_tracked_eapol) {
    std::shared_ptr<dot11_tracked_eapol> e =
        std::static_pointer_cast<dot11_tracked_eapol>(in_tracked_eapol);

    set_eapol_time(e->get_eapol_time());
    set_eapol_msg_num(e->get_eapol_msg_num());
    set_eapol_replay_counter(e->get_eapol_replay_counter());


    set_eapol_install(e->get_eapol_install());
    set_eapol_nonce_bytes(e->get_eapol_nonce_bytes());
}

void dot11_probed_ssid::register_fields() {
    RegisterField("dot11.probedssid.ssid", "probed ssid string (sanitized)", &ssid);
    RegisterField("dot11.probedssid.ssidlen", 
            "probed ssid string length (original bytes)", &ssid_len);
    RegisterField("dot11.probedssid.bssid", "probed ssid BSSID", &bssid);
    RegisterField("dot11.probedssid.first_time", "first time probed", &first_time);
    RegisterField("dot11.probedssid.last_time", "last time probed", &last_time);

    location_id = 
        RegisterDynamicField("dot11.probedssid.location", "location", &location);

    RegisterField("dot11.probedssid.dot11r_mobility", 
            "advertised dot11r mobility support", &dot11r_mobility);
    RegisterField("dot11.probedssid.dot11r_mobility_domain_id", 
            "advertised dot11r mobility domain id", &dot11r_mobility_domain_id);

    RegisterField("dot11.probedssid.crypt_set", "Requested encryption set", &crypt_set);

    RegisterField("dot11.probedssid.wpa_mfp_required",
            "WPA management protection required", &wpa_mfp_required);
    RegisterField("dot11.probedssid.wpa_mfp_supported",
            "WPA management protection supported", &wpa_mfp_supported);

    RegisterField("dot11.probedssid.ie_tag_list",
            "802.11 IE tag list in beacon", &ie_tag_list);

    wps_state_id =
        RegisterDynamicField("dot11.probedssid.wps_state", "WPS state bitfield", &wps_state);
    wps_manuf_id =
        RegisterDynamicField("dot11.probedssid.wps_manuf", "WPS manufacturer", &wps_manuf);
    wps_device_name_id =
        RegisterDynamicField("dot11.probedssid.wps_device_name", "wps device name", &wps_device_name);
    wps_model_name_id =
        RegisterDynamicField("dot11.probedssid.wps_model_name", "wps model name", &wps_model_name);
    wps_model_number_id =
        RegisterDynamicField("dot11.probedssid.wps_model_number", "wps model number", &wps_model_number);
    wps_serial_number_id = 
        RegisterDynamicField("dot11.probedssid.wps_serial_number", "wps serial number", &wps_serial_number);
    wps_uuid_e_id =
        RegisterDynamicField("dot11.probedssid.wps_uuid_e", "wps euuid", &wps_uuid_e);
}

void dot11_advertised_ssid::register_fields() {
    RegisterField("dot11.advertisedssid.ssid", "beaconed ssid string (sanitized)", &ssid);
    RegisterField("dot11.advertisedssid.ssidlen", 
            "beaconed ssid string length (original bytes)", &ssid_len);

    owe_ssid_id =
        RegisterDynamicField("dot11.advertisedssid.owe_ssid",
                "Opportunistic Wireless Encryption (OWE) linked companion SSID", &owe_ssid);
    owe_ssid_len_id =
        RegisterDynamicField("dot11.advertisedssid.owe_ssid_len",
                "Opportunistic Wireless Encryption (OWE) SSID length (original bytes)", &owe_ssid_len);
    owe_bssid_id =
        RegisterDynamicField("dot11.advertisedssid.owe_bssid",
                "Opportunistic Wireless Encryption (OWE) companion BSSID", &owe_bssid);

    RegisterField("dot11.advertisedssid.beacon", "ssid advertised via beacon", &ssid_beacon);
    RegisterField("dot11.advertisedssid.probe_response", "ssid advertised via probe response", 
            &ssid_probe_response);

    RegisterField("dot11.advertisedssid.channel", "channel", &channel);
    RegisterField("dot11.advertisedssid.ht_mode", "HT (11n or 11ac) mode", &ht_mode);
    RegisterField("dot11.advertisedssid.ht_center_1", 
            "HT/VHT Center Frequency (primary)", &ht_center_1);
    RegisterField("dot11.advertisedssid.ht_center_2", 
            "HT/VHT Center Frequency (secondary, for 80+80 Wave2)",
            &ht_center_2);

    RegisterField("dot11.advertisedssid.first_time", "first time seen", &first_time);
    RegisterField("dot11.advertisedssid.last_time", "last time seen", &last_time);
    RegisterField("dot11.advertisedssid.beacon_info", 
            "beacon info / vendor description", &beacon_info);
    RegisterField("dot11.advertisedssid.cloaked", "SSID is hidden / cloaked", &ssid_cloaked);
    RegisterField("dot11.advertisedssid.crypt_set", "bitfield of encryption options", &crypt_set);
    RegisterField("dot11.advertisedssid.maxrate", "advertised maximum rate", &maxrate);
    RegisterField("dot11.advertisedssid.beaconrate", "beacon rate", &beaconrate);
    RegisterField("dot11.advertisedssid.beacons_sec", "beacons seen in past second", &beacons_sec);
    RegisterField("dot11.advertisedssid.ietag_checksum", 
            "checksum of all ie tags", &ietag_checksum);

    RegisterField("dot11.advertisedssid.wpa_mfp_required",
            "WPA management protection required", &wpa_mfp_required);
    RegisterField("dot11.advertisedssid.wpa_mfp_supported",
            "WPA management protection supported", &wpa_mfp_supported);

    dot11d_country_id = 
        RegisterDynamicField("dot11.advertisedssid.dot11d_country", "802.11d country", 
                &dot11d_country);
    RegisterField("dot11.advertisedssid.dot11d_list", "802.11d channel list", &dot11d_vec);

    dot11d_country_entry_id =
        RegisterField("dot11.advertisedssid.dot11d_entry", 
                TrackerElementFactory<dot11_11d_tracked_range_info>(0),
                "dot11d entry");

    wps_state_id =
        RegisterDynamicField("dot11.advertisedssid.wps_state", "bitfield wps state", &wps_state);
    wps_manuf_id =
        RegisterDynamicField("dot11.advertisedssid.wps_manuf", "WPS manufacturer", &wps_manuf);
    wps_device_name_id =
        RegisterDynamicField("dot11.advertisedssid.wps_device_name", "wps device name", 
                &wps_device_name);
    wps_model_name_id =
        RegisterDynamicField("dot11.advertisedssid.wps_model_name", "wps model name", 
                &wps_model_name);
    wps_model_number_id =
        RegisterDynamicField("dot11.advertisedssid.wps_model_number", "wps model number", 
                &wps_model_number);
    wps_serial_number_id = 
        RegisterDynamicField("dot11.advertisedssid.wps_serial_number", 
                "wps serial number", &wps_serial_number);
    wps_uuid_e_id =
        RegisterDynamicField("dot11.advertisedssid.wps_uuid_e", "wps euuid",
                &wps_uuid_e);

    location_id = 
        RegisterDynamicField("dot11.advertisedssid.location", "location", &location);

    RegisterField("dot11.advertisedssid.dot11r_mobility", 
            "advertised dot11r mobility support", &dot11r_mobility);
    RegisterField("dot11.advertisedssid.dot11r_mobility_domain_id", 
            "advertised dot11r mobility domain id", &dot11r_mobility_domain_id);

    RegisterField("dot11.advertisedssid.dot11e_qbss", 
            "SSID advertises 802.11e QBSS", &dot11e_qbss);
    RegisterField("dot11.advertisedssid.dot11e_qbss_stations", 
            "802.11e QBSS station count", &dot11e_qbss_stations);
    RegisterField("dot11.advertisedssid.dot11e_channel_utilization_perc", 
            "802.11e QBSS reported channel utilization, as percentage", 
            &dot11e_qbss_channel_load);

    RegisterField("dot11.advertisedssid.ccx_txpower",
            "Cisco CCX advertised TX power (dBm)", &ccx_txpower);

    RegisterField("dot11.advertisedssid.cisco_client_mfp",
            "Cisco client management frame protection", &cisco_client_mfp);

    RegisterField("dot11.advertisedssid.ie_tag_list",
            "802.11 IE tag list in beacon", &ie_tag_list);
}

void dot11_advertised_ssid::set_dot11d_vec(std::vector<dot11_packinfo_dot11d_entry> vec) {
    dot11d_vec->clear();

    for (auto x : vec) {
        auto ri = 
            std::make_shared<dot11_11d_tracked_range_info>(dot11d_country_entry_id);
        ri->set_startchan(x.startchan);
        ri->set_numchan(x.numchan);
        ri->set_txpower(x.txpower);
    }
}
