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

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "packet.h"
#include "gpstracker.h"
#include "uuid.h"

#include "devicetracker.h"
#include "devicetracker_component.h"
#include "kis_net_microhttpd.h"
#include "phy_80211_components.h"
#include "phy_80211_httpd_pcap.h"

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

/*
 * 802.11 PHY handlers
 * Uses new devicetracker code
 *
 * Re-implements networktracker, packetdissectors
 * Ultimately all 802.11 related code will live here, such as alerts, etc.
 *
 * 802.11 data represents multiple tiers of data:
 *  - Device (could be client or AP)
 *      - AP
 *          - SSIDs (possibly multiple per BSSID)
 *          - AP Client
 *      - Client
 *          - SSIDs client has probed or connected to
 *          - BSSIDs of devices client has been observed joining/communicating
 */

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
            self_destruct = 1; // Our delete() handles this
            corrupt = 0;
            header_offset = 0;
            type = packet_unknown;
            subtype = packet_sub_unknown;
            source_mac = mac_addr(0);
            dest_mac = mac_addr(0);
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
            timestamp = 0;
            sequence_number = 0;
            frag_number = 0;
            fragmented = 0;
            retry = 0;
            duration = 0;
            datasize = 0;
            qos = 0;

            maxrate = 0;

            // Many of thse will not be available until the IE tags are parsed
            ietag_csum = 0;

            dot11d_country = "";

            wps = DOT11_WPS_NO_WPS;
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

            ccx_txpower = 0;
            cisco_client_mfp = false;

            new_device = false;
            new_adv_ssid = false;
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

        std::string dot11d_country;
        std::vector<dot11_packinfo_dot11d_entry> dot11d_vec;

        // WPS information
        uint8_t wps;
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
};

class dot11_ssid_alert {
    public:
        dot11_ssid_alert() {
#ifdef HAVE_LIBPCRE
            ssid_re = NULL;
            ssid_study = NULL;
#endif
        }
        std::string name;

#ifdef HAVE_LIBPCRE
        pcre *ssid_re;
        pcre_extra *ssid_study;
        std::string filter;
#endif
        std::string ssid;

        std::map<mac_addr, int> allow_mac_map;
};

class Kis_80211_Phy : public Kis_Phy_Handler, 
    public Kis_Net_Httpd_CPPStream_Handler, public TimetrackerEvent {

public:
    using ie_tag_tuple = std::tuple<uint8_t, uint32_t, uint8_t>;

    // Stub
    ~Kis_80211_Phy();

    // Inherited functionality
    Kis_80211_Phy(GlobalRegistry *in_globalreg) :
        Kis_Phy_Handler(in_globalreg) { };

    // Build a strong version of ourselves
    virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg, int in_phyid) override {
        return new Kis_80211_Phy(in_globalreg, in_phyid);
    }

    // Strong constructor
    Kis_80211_Phy(GlobalRegistry *in_globalreg, int in_phyid);

    int WPACipherConv(uint8_t cipher_index);
    int WPAKeyMgtConv(uint8_t mgt_index);

    // Dot11 decoders, wep decryptors, etc
    int PacketWepDecryptor(kis_packet *in_pack);
    // Top-level dissector; decodes basic type and populates the dot11 packet
    int PacketDot11dissector(kis_packet *in_pack);
    // Expects an existing dot11 packet with the basic type intact, interprets
    // IE tags to the best of our ability
    int PacketDot11IEdissector(kis_packet *in_pack, dot11_packinfo *in_dot11info);
    // Generate a list of IE tag numbers
    std::vector<ie_tag_tuple> PacketDot11IElist(kis_packet *in_pack, dot11_packinfo *in_dot11info);

    // Special decoders, not called as part of a chain

    // Is packet a WPS M3 message?  Used to detect Reaver, etc
    int PacketDot11WPSM3(kis_packet *in_pack);

    // Is the packet a WPA handshake?  Return an eapol tracker element if so
    std::shared_ptr<dot11_tracked_eapol> PacketDot11EapolHandshake(kis_packet *in_pack,
            std::shared_ptr<dot11_tracked_device> dot11device);

    // static incase some other component wants to use it
    static kis_datachunk *DecryptWEP(dot11_packinfo *in_packinfo,
            kis_datachunk *in_chunk, 
            unsigned char *in_key, int in_key_len,
            unsigned char *in_id);

    // TODO - what do we do with the strings?  Can we make them phy-neutral?
    // int packet_dot11string_dissector(kis_packet *in_pack);

    // 802.11 packet classifier to common for the devicetracker layer
    static int CommonClassifierDot11(CHAINCALL_PARMS);

    // Dot11 tracker for building phy-specific elements
    int TrackerDot11(kis_packet *in_pack);

    int AddFilter(std::string in_filter);
    int AddNetcliFilter(std::string in_filter);

    void SetStringExtract(int in_extr);

    void AddWepKey(mac_addr bssid, uint8_t *key, unsigned int len, int temp);

    static std::string CryptToString(uint64_t cryptset);
    static std::string CryptToSimpleString(uint64_t cryptset);

    // HTTPD API
    virtual bool Httpd_VerifyPath(const char *path, const char *method) override;

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) override;

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) override;

    // Timetracker event handler
    virtual int timetracker_event(int eventid) override;

    // Restore stored dot11 records
    virtual void LoadPhyStorage(SharedTrackerElement in_storage,
            SharedTrackerElement in_device) override;

    // Convert a frequency in KHz to an IEEE 80211 channel name; MAY THROW AN EXCEPTION
    // if this cannot be converted or is an invalid frequency
    static const std::string KhzToChannel(const double in_khz);

protected:
    std::shared_ptr<Alertracker> alertracker;
    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<Timetracker> timetracker;
    std::shared_ptr<Devicetracker> devicetracker;

    // Checksum of recent packets for duplication filtering
    uint32_t *recent_packet_checksums;
    size_t recent_packet_checksums_sz;
    unsigned int recent_packet_checksum_pos;

    // Handle advertised SSIDs
    void HandleSSID(std::shared_ptr<kis_tracked_device_base> basedev, 
            std::shared_ptr<dot11_tracked_device> dot11dev,
            kis_packet *in_pack,
            dot11_packinfo *dot11info,
            kis_gps_packinfo *pack_gpsinfo);

    // Handle probed SSIDs
    void HandleProbedSSID(std::shared_ptr<kis_tracked_device_base> basedev, 
            std::shared_ptr<dot11_tracked_device> dot11dev,
            kis_packet *in_pack,
            dot11_packinfo *dot11info,
            kis_gps_packinfo *pack_gpsinfo);

    // Map a device as a client of an acceess point, fill in any data in the
    // per-client records
    void ProcessClient(std::shared_ptr<kis_tracked_device_base> bssiddev,
            std::shared_ptr<dot11_tracked_device> bssiddot11,
            std::shared_ptr<kis_tracked_device_base> clientdev,
            std::shared_ptr<dot11_tracked_device> clientdot11,
            kis_packet *in_pack,
            dot11_packinfo *dot11info,
            kis_gps_packinfo *pack_gpsinfo,
            kis_data_packinfo *pack_datainfo);

    void ProcessWPAHandshake(std::shared_ptr<kis_tracked_device_base> bssid_dev,
            std::shared_ptr<dot11_tracked_device> bssid_dot11,
            std::shared_ptr<kis_tracked_device_base> dest_dev,
            std::shared_ptr<dot11_tracked_device> dest_dot11,
            kis_packet *in_pack, dot11_packinfo *dot11info);

    void GenerateHandshakePcap(std::shared_ptr<kis_tracked_device_base> dev, 
            Kis_Net_Httpd_Connection *connection,
            std::stringstream &stream);

    int dot11_device_entry_id;

    int LoadWepkeys();

    std::map<mac_addr, std::string> bssid_cloak_map;

    std::string ssid_cache_path, ip_cache_path;
    int ssid_cache_track, ip_cache_track;

    // Device components
    int dev_comp_dot11, dev_comp_common;

    // Packet components
    int pack_comp_80211, pack_comp_basicdata, pack_comp_mangleframe,
        pack_comp_strings, pack_comp_checksum, pack_comp_linkframe,
        pack_comp_decap, pack_comp_common, pack_comp_datapayload,
        pack_comp_gps, pack_comp_l1info;

    // Do we do any data dissection or do we hide it all (legal safety
    // cutout)
    int dissect_data;

    // Do we pull strings?
    int dissect_strings, dissect_all_strings;

    // SSID regex filter
    std::shared_ptr<TrackerElementVector> ssid_regex_vec;
    int ssid_regex_vec_element_id;

    // Dissector alert references
    int alert_netstumbler_ref, alert_nullproberesp_ref, alert_lucenttest_ref,
        alert_msfbcomssid_ref, alert_msfdlinkrate_ref, alert_msfnetgearbeacon_ref,
        alert_longssid_ref, alert_disconinvalid_ref, alert_deauthinvalid_ref,
        alert_dhcpclient_ref, alert_wmm_ref, alert_nonce_zero_ref, 
        alert_nonce_duplicate_ref, alert_11kneighborchan_ref;

    // Are we allowed to send wepkeys to the client (server config)
    int client_wepkey_allowed;
    // Map of wepkeys to BSSID (or bssid masks)
    std::map<mac_addr, dot11_wep_key *> wepkeys;

    // Generated WEP identity / base
    unsigned char wep_identity[256];

    // Tracker alert references
    int alert_chan_ref, alert_dhcpcon_ref, alert_bcastdcon_ref, alert_airjackssid_ref,
        alert_wepflap_ref, alert_dhcpname_ref, alert_dhcpos_ref, alert_adhoc_ref,
        alert_ssidmatch_ref, alert_dot11d_ref, alert_beaconrate_ref,
        alert_cryptchange_ref, alert_malformmgmt_ref, alert_wpsbrute_ref, 
        alert_l33t_ref, alert_tooloud_ref, alert_atheros_wmmtspec_ref,
        alert_atheros_rsnloop_ref, alert_bssts_ref;

    int signal_too_loud_threshold;

    // Command refs
    int addfiltercmd_ref, addnetclifiltercmd_ref;

    int proto_ref_ssid, proto_ref_device, proto_ref_client;

    // SSID cloak file as a config file
    ConfigFile *ssid_conf;
    time_t conf_save;

    // probe assoc to owning network
    std::map<mac_addr, kis_tracked_device_base *> probe_assoc_map;

    // Do we time out components of devices?
    int device_idle_expiration;
    int device_idle_timer;
    unsigned int device_idle_min_packets;

    // Pcap handlers
    std::unique_ptr<Phy_80211_Httpd_Pcap> httpd_pcap;

    // Do we process control and phy frames?
    bool process_ctl_phy;

    // IE fingerprinting lists
    std::vector<ie_tag_tuple> beacon_ie_fingerprint_list;
    std::vector<ie_tag_tuple> probe_ie_fingerprint_list;

    // New endpoints as we migrate to the simplified API
    std::shared_ptr<Kis_Net_Httpd_Path_Tracked_Endpoint> clients_of_endp;

    // Related-by API
    std::shared_ptr<Kis_Net_Httpd_Path_Tracked_Endpoint> related_to_key_endp;
};

#endif
