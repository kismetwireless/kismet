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

   CODE IN BOTH phy_80211.cc AND phy_80211_dissectors.cc
   */

#ifndef __PHY_80211_H__
#define __PHY_80211_H__

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

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "boost_like_hash.h"
#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"
#include "streamtracker.h"
#include "macaddr.h"

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "kis_net_beast_httpd.h"
#include "phy_80211_components.h"
#include "phy_80211_ssidtracker.h"

#include "datasource_dot11_scan.h"

#include "kaitai/kaitaistream.h"
#include "dot11_parsers/dot11_wpa_eap.h"
#include "dot11_parsers/dot11_ie_11_qbss.h"
#include "dot11_parsers/dot11_ie_33_power.h"
#include "dot11_parsers/dot11_ie_36_supported_channels.h"
#include "dot11_parsers/dot11_ie_48_rsn.h"
#include "dot11_parsers/dot11_ie_54_mobility.h"
#include "dot11_parsers/dot11_ie_61_ht_op.h"
#include "dot11_parsers/dot11_ie_192_vht_op.h"
#include "dot11_parsers/dot11_ie_221_dji_droneid.h"
#include "dot11_parsers/dot11_ie_221_wpa_transition.h"
#include "dot11_parsers/dot11_ie_221_wfa_wpa.h"

#define PHY80211_MAC_LEN	6
// Dot11 SSID max len
#define DOT11_PROTO_SSID_LEN	32

// Wep keys
#define DOT11_WEPKEY_MAX		32
#define DOT11_WEPKEY_STRMAX		((DOT11_WEPKEY_MAX * 2) + DOT11_WEPKEY_MAX)

class dot11_wep_key {
    public:
        int fragile;
        mac_addr bssid;
        unsigned char key[DOT11_WEPKEY_MAX];
        unsigned int len;
        unsigned int decrypted;
        unsigned int failed;
};

// dot11 packet components

class dot11_packinfo_dot11d_entry {
    public:
        uint32_t startchan;
        uint32_t numchan;
        int32_t txpower;
};

// WPS state bitfield
#define DOT11_WPS_NO_WPS            0
#define DOT11_WPS_CONFIGURED        1
#define DOT11_WPS_NOT_CONFIGURED    (1 << 1)
#define DOT11_WPS_LOCKED            (1 << 2)

// SSID type bitfield
#define DOT11_SSID_NONE             0
#define DOT11_SSID_BEACON           1
#define DOT11_SSID_PROBERESP        (1 << 1)
#define DOT11_SSID_PROBEREQ         (1 << 2)
#define DOT11_SSID_FILE             (1 << 3)

// Packet info decoded by the dot11 phy decoder
// 
// Injected into the packet chain and processed later into the device records
class dot11_packinfo : public packet_component {
    public:
        dot11_packinfo() {
            reset();
        }

        void reset() {
            corrupt = 0;
            header_offset = 0;
            type = packet_unknown;
            subtype = packet_sub_unknown;
            mgt_reason_code= 0;
            ssid = "";
            ssid_len = 0;
            ssid_blank = 0;
            source_mac = mac_addr(0);
            dest_mac = mac_addr(0);
            transmit_mac = mac_addr(0);
            receive_mac = mac_addr(0);
            bssid_mac = mac_addr(0);
            other_mac = mac_addr(0);
            distrib = distrib_unknown;
            cryptset = 0;
            decrypted = 0;
            fuzzywep = 0;
            fmsweak = 0;
            ess = 0;
            ibss = 0;
            channel = "0";
            encrypted = 0;
            qos = 0;
            timestamp = 0;
            sequence_number = 0;
            frag_number = 0;
            fragmented = 0;
            retry = 0;
            duration = 0;
            datasize = 0;
            qos = 0;

            maxrate = 0;

            // Many of these will not be available until the IE tags are parsed
            ietag_csum = 0;

            dot11d_country = "";

            wps_version = 0; 
            wps = DOT11_WPS_NO_WPS;
            wps_config_methods = 0;
            wps_manuf = "";
            wps_device_name = "";
            wps_model_name = "";
            wps_model_number = "";
            wps_serial_number = "";
            wps_uuid_e = "";

            mgt_reason_code = 0;

            ssid_len = 0;
            ssid_blank = 0;
            ssid_csum = 0;

            beacon_interval = 0;

            beacon_info = "";

            ccx_txpower = 0;
            cisco_client_mfp = false;

            new_device = false;
            new_adv_ssid = false;

            ietag_hash_map.clear();
            dot11d_country = "";
            ie_tags.reset();
            ie_tags_listed.reset();
            dot11d_vec.clear();

            qbss.reset();
            tx_power.reset();
            supported_channels.reset();
            dot11r_mobility.reset();
            dot11vht.reset();
            dot11ht.reset();
            owe_transition.reset();
            rsn.reset();
            droneid.reset();

            basic_rates.clear();
            extended_rates.clear();
            mcs_rates.clear();

            bssid_dev.reset();
            source_dev.reset();
            dest_dev.reset();
            receive_dev.reset();
            transmit_dev.reset();

            bssid_dot11.reset();
            source_dot11.reset();
            dest_dot11.reset();
            receive_dot11.reset();
            transmit_dot11.reset();
        }

        // Corrupt 802.11 frame
        int corrupt;

        // Offset to data components in frame
        unsigned int header_offset;

        ieee_80211_type type;
        ieee_80211_subtype subtype;

        uint8_t mgt_reason_code;

        // Raw SSID
        std::string ssid;
        // Length of the SSID header field
        int ssid_len;
        // Is the SSID empty spaces?
        int ssid_blank;

        // Address set
        mac_addr source_mac;
        mac_addr dest_mac;
        mac_addr transmit_mac;
        mac_addr receive_mac;
        mac_addr bssid_mac;
        mac_addr other_mac;

        ieee_80211_disttype distrib;

        uint64_t cryptset;
        int decrypted; // Might as well put this in here?
        int fuzzywep;
        int fmsweak;

        // Was it flagged as ess? (ap)
        int ess;
        int ibss;

        // What channel does it report
        std::string channel;

        // Is this encrypted?
        int encrypted;
        int beacon_interval;

        uint16_t qos;

        // Some cisco APs seem to fill in this info field
        std::string beacon_info;

        uint64_t timestamp;
        int sequence_number;
        int frag_number;
        int fragmented;
        int retry;

        int duration;

        int datasize;

        uint32_t ssid_csum;
        uint32_t ietag_csum;

        // Tupled hash map
        std::multimap<std::tuple<uint8_t, uint32_t, uint8_t>, size_t> ietag_hash_map;

        // Parsed IE tags, if we've parsed them
        std::shared_ptr<dot11_ie> ie_tags;

        using ie_tag_tuple = std::tuple<uint8_t, uint32_t, uint8_t>;
        std::shared_ptr<std::vector<ie_tag_tuple>> ie_tags_listed;

        std::string dot11d_country;
        std::vector<dot11_packinfo_dot11d_entry> dot11d_vec;

        // WPS information
        uint8_t wps_version;
        uint8_t wps;
        uint16_t wps_config_methods;
        // The field below is useful because some APs use
        // a MAC address with 'Unknown' OUI but will
        // tell their manufacturer in this field:
        std::string wps_manuf;
        // Some APs give out bogus information on these fields
        std::string wps_device_name;
        std::string wps_model_name;
        std::string wps_model_number;
        std::string wps_serial_number;
        std::string wps_uuid_e;

        // Direct kaitai structs pulled from the beacon
        std::shared_ptr<dot11_ie_11_qbss> qbss;
        std::shared_ptr<dot11_ie_33_power> tx_power;
        std::shared_ptr<dot11_ie_36_supported_channels> supported_channels;
        std::shared_ptr<dot11_ie_54_mobility> dot11r_mobility;
        std::shared_ptr<dot11_ie_61_ht_op> dot11ht;
        std::shared_ptr<dot11_ie_192_vht_op> dot11vht;
        std::shared_ptr<dot11_ie_221_owe_transition> owe_transition;
        std::shared_ptr<dot11_ie_48_rsn> rsn;

        std::shared_ptr<dot11_ie_221_dji_droneid> droneid;

        double maxrate;
        // 11g rates
        std::vector<std::string> basic_rates;
        std::vector<std::string> extended_rates;

        // 11n MCS rates
        std::vector<std::string> mcs_rates;

        unsigned int ccx_txpower;
        bool cisco_client_mfp;

        // Did we just create records for these?
        bool new_device;
        bool new_adv_ssid;

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
};

class dot11_ssid_alert {
    public:
        dot11_ssid_alert() {
#if defined(HAVE_LIBPCRE1)
            ssid_re = NULL;
            ssid_study = NULL;
#elif defined(HAVE_LIBPCRE2)
            ssid_re = NULL;
            ssid_match_data = NULL;
#endif
        }

        ~dot11_ssid_alert() {
#if defined(HAVE_LIBPCRE1)
            if (ssid_re != NULL)
                pcre_free(ssid_re);
            if (ssid_study != NULL)
                pcre_free(study);
#elif defined(HAVE_LIBPCRE2)
            if (ssid_match_data != NULL)
                pcre2_match_data_free(ssid_match_data);
            if (ssid_re != NULL)
                pcre2_code_free(ssid_re);
#endif
        }

        std::string name;

#if defined(HAVE_LIBPCRE1)
        pcre *ssid_re;
        pcre_extra *ssid_study;
        std::string filter;
#elif defined(HAVE_LIBPCRE2)
        pcre2_code *ssid_re;
        pcre2_match_data *ssid_match_data;
        std::string filter;
#endif
        std::string ssid;

        std::map<mac_addr, int> allow_mac_map;
};

class kis_80211_phy : public kis_phy_handler, public time_tracker_event {
public:
    using ie_tag_tuple = std::tuple<uint8_t, uint32_t, uint8_t>;

    using ie48_rsn_cipher = dot11_ie_48_rsn::dot11_ie_48_rsn_rsn_cipher::rsn_cipher_type;
    using ie48_rsn_mgmt = dot11_ie_48_rsn::dot11_ie_48_rsn_rsn_management::rsn_management;
    using ie221_wfa_cipher = dot11_ie_221_wfa_wpa::wpa_v1_cipher::wfa_wpa_cipher_e;
    using ie221_wfa_mgmt = dot11_ie_221_wfa_wpa::wpa_v1_cipher::wfa_wpa_mgmt_e;

    // Stub
    ~kis_80211_phy();

    // Inherited functionality
    kis_80211_phy() :
        kis_phy_handler() { };

    // Build a strong version of ourselves
    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_80211_phy(in_phyid);
    }

    // Strong constructor
    kis_80211_phy(int in_phyid);

    static uint64_t wpa_rsn_pairwise_conv(ie48_rsn_cipher cipher);
    static uint64_t wpa_rsn_group_conv(ie48_rsn_cipher cipher);
    static uint64_t wpa_rsn_auth_conv(ie48_rsn_mgmt cipher);

    static uint64_t wfa_pairwise_conv(ie221_wfa_cipher cipher);
    static uint64_t wfa_group_conv(ie221_wfa_cipher cipher);
    static uint64_t wfa_auth_conv(ie221_wfa_mgmt cipher);


    // Dot11 decoders, wep decryptors, etc
    int packet_wep_decryptor(const std::shared_ptr<kis_packet>& in_pack);
    // Top-level dissector; decodes basic type and populates the dot11 packet
    int packet_dot11_dissector(const std::shared_ptr<kis_packet>& in_pack);
    // Expects an existing dot11 packet with the basic type intact, interprets
    // IE tags to the best of our ability
    int packet_dot11_ie_dissector(const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_packinfo>& in_dot11info);
    // Generate a list of IE tag numbers
    std::shared_ptr<std::vector<ie_tag_tuple>> packet_dot11_ie_list(const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_packinfo>& in_dot11info);

    // Special decoders, not called as part of a chain

    // Is packet a WPS M3 message?  Used to detect Reaver, etc
    int packet_dot11_wps_m3(const std::shared_ptr<kis_packet>& in_pack);

    // Is the packet a WPA handshake?  Return an eapol tracker element if so
    std::shared_ptr<dot11_tracked_eapol> packet_dot11_eapol_handshake(const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_tracked_device>& dot11device);

    // static in case some other component wants to use it
    static std::shared_ptr<kis_datachunk> DecryptWEP(const std::shared_ptr<dot11_packinfo>& in_packinfo,
            const std::shared_ptr<kis_datachunk>& in_chunk,
            unsigned char *in_key, int in_key_len,
            unsigned char *in_id);

    // TODO - what do we do with the strings?  Can we make them phy-neutral?
    // int packet_dot11string_dissector(kis_packet *in_pack);

    // 802.11 packet classifier to common for the devicetracker layer
    static int packet_dot11_common_classifier(CHAINCALL_PARMS);

    // 802.11 virtual source scan classifier
    static int packet_dot11_scan_json_classifier(CHAINCALL_PARMS);

    // Dot11 tracker for building phy-specific elements
    int tracker_dot11(const std::shared_ptr<kis_packet>& in_pack);

    int add_filter(std::string in_filter);
    int add_netcli_filter(std::string in_filter);

    void set_string_extract(int in_extr);

    void add_wep_key(mac_addr bssid, uint8_t *key, unsigned int len, int temp);

    static std::string crypt_to_string(uint64_t cryptset);
    static std::string crypt_to_simple_string(uint64_t cryptset);
    static uint64_t crypt_to_legacy_bitset(uint64_t cryptset);

    // time_tracker event handler
    virtual int timetracker_event(int eventid) override;

    // Restore stored dot11 records
    virtual void load_phy_storage(shared_tracker_element in_storage,
            shared_tracker_element in_device) override;

    // Convert a frequency in KHz to an IEEE 80211 channel name; MAY THROW AN EXCEPTION
    // if this cannot be converted or is an invalid frequency
    static std::string khz_to_channel(const double in_khz);

    const std::string dot11_wpa_handshake_event = "DOT11_WPA_HANDSHAKE";
    const std::string dot11_wpa_handshake_event_base = "DOT11_WPA_HANDSHAKE_BASEDEV";
    const std::string dot11_wpa_handshake_event_dot11 = "DOT11_WPA_HANDSHAKE_DOT11";

    const std::string dot11_new_ssid_device = "DOT11_NEW_SSID_BASEDEV";
    const std::string dot11_new_advertised_ssid = "DOT11_ADVERTISED_SSID";
    const std::string dot11_new_probed_ssid = "DOT11_PROBED_SSID";
    const std::string dot11_new_response_ssid = "DOT11_RESPONSE_SSID";

    static size_t ssid_hash(const std::string& ssid, unsigned int ssid_len) {
        auto hash = xx_hash_cpp{};

        boost_like::hash_combine(hash, ssid);
        boost_like::hash_combine(hash, ssid_len);

        return hash.hash();
    }

    virtual bool device_is_a(const std::shared_ptr<kis_tracked_device_base>& dev) override;

    std::shared_ptr<dot11_tracked_device> fetch_dot11_record(const std::shared_ptr<kis_tracked_device_base>& dev);

protected:
    std::shared_ptr<alert_tracker> alertracker;
    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<event_bus> eventbus;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<stream_tracker> streamtracker;

    // Handle advertised SSIDs
    void handle_ssid(const std::shared_ptr<kis_tracked_device_base>& basedev,
            const std::shared_ptr<dot11_tracked_device>& dot11dev,
            const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_packinfo>& dot11info,
            const std::shared_ptr<kis_gps_packinfo>& pack_gpsinfo);

    // Handle probed SSIDs
    void handle_probed_ssid(const std::shared_ptr<kis_tracked_device_base>& basedev,
            const std::shared_ptr<dot11_tracked_device>& dot11dev,
            const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_packinfo>& dot11info,
            const std::shared_ptr<kis_gps_packinfo>& pack_gpsinfo);

    // Map a device as a client of an acceess point, fill in any data in the
    // per-client records
    void process_client(const std::shared_ptr<kis_tracked_device_base>& bssiddev,
            const std::shared_ptr<dot11_tracked_device>& bssiddot11,
            const std::shared_ptr<kis_tracked_device_base>& clientdev,
            const std::shared_ptr<dot11_tracked_device>& clientdot11,
            const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_packinfo>& dot11info,
            const std::shared_ptr<kis_gps_packinfo>& pack_gpsinfo,
            const std::shared_ptr<kis_data_packinfo>& pack_datainfo);

    void process_wpa_handshake(const std::shared_ptr<kis_tracked_device_base>& bssid_dev,
            const std::shared_ptr<dot11_tracked_device>& bssid_dot11,
            const std::shared_ptr<kis_tracked_device_base>& dest_dev,
            const std::shared_ptr<dot11_tracked_device>& dest_dot11,
            const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<dot11_packinfo>& dot11info);

    void generate_handshake_pcap(std::shared_ptr<kis_net_beast_httpd_connection> con,
            const std::shared_ptr<kis_tracked_device_base>& dev,
            const std::shared_ptr<dot11_tracked_device>& dot11dev,
            mac_addr target_mac, std::string mode);

    int dot11_device_entry_id;

    int load_wepkeys();

    std::map<mac_addr, std::string> bssid_cloak_map;

    std::string ssid_cache_path, ip_cache_path;
    int ssid_cache_track, ip_cache_track;

    // Device components
    int dev_comp_dot11, dev_comp_common;

    // Packet components
    int pack_comp_80211, pack_comp_basicdata, pack_comp_mangleframe,
        pack_comp_strings, pack_comp_checksum, pack_comp_linkframe,
        pack_comp_decap, pack_comp_common, pack_comp_datapayload,
        pack_comp_gps, pack_comp_l1info, pack_comp_json;

    // Do we do any data dissection or do we hide it all (legal safety
    // cutout)
    int dissect_data;

    // Do we pull strings?
    int dissect_strings, dissect_all_strings;

    // SSID regex filter
    std::shared_ptr<tracker_element_vector> ssid_regex_vec;
    int ssid_regex_vec_element_id;

    // AP canary filter; this is only called on a new ssid event so we can afford
    // to compile the SSID each time and only map it as a raw string
    std::shared_ptr<tracker_element_string_map> ssidcanary_map;
    int ssidcanary_map_element_id;

    // Dissector alert references
    int alert_netstumbler_ref, alert_nullproberesp_ref, alert_lucenttest_ref,
        alert_msfbcomssid_ref, alert_msfdlinkrate_ref, alert_msfnetgearbeacon_ref,
        alert_longssid_ref, alert_disconinvalid_ref, alert_deauthinvalid_ref,
        alert_dhcpclient_ref, alert_wmm_ref, alert_nonce_zero_ref, 
        alert_nonce_duplicate_ref, alert_11kneighborchan_ref, alert_probechan_ref,
        alert_rtlwifi_p2p_ref, alert_deauthflood_ref, alert_noclientmfp_ref,
        alert_rtl8195_vdoo_ref, alert_vdoo_2020_27301_ref, alert_vdoo_2020_27302_ref;

    // Are we allowed to send wepkeys to the client (server config)
    int client_wepkey_allowed;
    // Map of wepkeys to BSSID (or bssid masks)
    std::map<mac_addr, dot11_wep_key *> wepkeys;

    // Generated WEP identity / base
    unsigned char wep_identity[256];

    // Tracker alert references
    int alert_chan_ref, alert_dhcpcon_ref, alert_bcastdcon_ref, alert_airjackssid_ref,
        alert_wepflap_ref, alert_dhcpname_ref, alert_dhcpos_ref, alert_adhoc_ref,
        alert_ssidmatch_ref, alert_ssidcanary_ref, alert_dot11d_ref, alert_beaconrate_ref,
        alert_cryptchange_ref, alert_malformmgmt_ref, alert_wpsbrute_ref, 
        alert_l33t_ref, alert_tooloud_ref, alert_atheros_wmmtspec_ref,
        alert_atheros_rsnloop_ref, alert_bssts_ref, alert_qcom_extended_ref,
        alert_bad_fixlen_ie, alert_formatstring_ref;

    int signal_too_loud_threshold;

    // Command refs
    int addfiltercmd_ref, addnetclifiltercmd_ref;

    int proto_ref_ssid, proto_ref_device, proto_ref_client;

    // SSID cloak file as a config file
    config_file *ssid_conf;
    time_t conf_save;

    // probe assoc to owning network
    std::map<mac_addr, kis_tracked_device_base *> probe_assoc_map;

    // Do we time out components of devices?
    int device_idle_expiration;
    int device_idle_timer;
    unsigned int device_idle_min_packets;

    // Do we process control and phy frames?
    bool process_ctl_phy;

    // Do we track non-AP devices?
    bool filter_survey_only;

    // Do we process 11d country vectors?
    bool process_11d_country_list;

    // IE fingerprinting lists
    std::vector<ie_tag_tuple> beacon_ie_fingerprint_list;
    std::vector<ie_tag_tuple> probe_ie_fingerprint_list;

    // AP view
    std::shared_ptr<device_tracker_view> ap_view;

    // SSID tracker subsystem
    std::shared_ptr<phy_80211_ssid_tracker> ssidtracker; 

    // bssts time for grouping, in usec
    uint64_t bss_ts_group_usec;

    // Do we store the last beaconed tags in the ssid record?
    bool keep_ie_tags_per_bssid;

    // Do we keep WPA packets?
    bool keep_eapol_packets;

    // Do we only get signal from beacons?
    bool signal_from_beacon;

    // Do we associate devices by bssts?
    bool associate_by_bssts;

    std::shared_ptr<tracker_element_string> devtype_adhoc;
    std::shared_ptr<tracker_element_string> devtype_ap;
    std::shared_ptr<tracker_element_string> devtype_client;
    std::shared_ptr<tracker_element_string> devtype_wds_dev;
    std::shared_ptr<tracker_element_string> devtype_wds;
    std::shared_ptr<tracker_element_string> devtype_wds_ap;
    std::shared_ptr<tracker_element_string> devtype_bridged;
    std::shared_ptr<tracker_element_string> devtype_device;

    std::shared_ptr<dot11_tracked_device> dot11_builder;
};

struct pcapng_phy80211_accept_ftor {
    pcapng_phy80211_accept_ftor(mac_addr in_mac) :
		mac{in_mac} {
            const auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
			pack_comp_80211 = packetchain->register_packet_component("PHY80211");
        }

    bool operator()(const std::shared_ptr<kis_packet>& in_pack) {
		const auto dot11info = in_pack->fetch<dot11_packinfo>(pack_comp_80211);

		if (dot11info == nullptr)
			return false;

		if (dot11info->bssid_mac == mac)
			return true;

		return false;
    }

	int pack_comp_80211;
	mac_addr mac;
};


#endif
