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
#include "phy_80211_httpd_pcap.h"

#include "kaitai/kaitaistream.h"
#include "dot11_parsers/dot11_wpa_eap.h"
#include "dot11_parsers/dot11_ie_11_qbss.h"
#include "dot11_parsers/dot11_ie_33_power.h"
#include "dot11_parsers/dot11_ie_36_supported_channels.h"
#include "dot11_parsers/dot11_ie_54_mobility.h"
#include "dot11_parsers/dot11_ie_61_ht_op.h"
#include "dot11_parsers/dot11_ie_192_vht_op.h"
#include "dot11_parsers/dot11_ie_221_dji_droneid.h"

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

        // Direct kaitai structs pulled from the beacon
        std::shared_ptr<dot11_ie_11_qbss> qbss;
        std::shared_ptr<dot11_ie_33_power> tx_power;
        std::shared_ptr<dot11_ie_36_supported_channels> supported_channels;
        std::shared_ptr<dot11_ie_54_mobility> dot11r_mobility;
        std::shared_ptr<dot11_ie_61_ht_op> dot11ht;
        std::shared_ptr<dot11_ie_192_vht_op> dot11vht;

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

class dot11_tracked_eapol : public tracker_component {
public:
    dot11_tracked_eapol() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_eapol(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    dot11_tracked_eapol(int in_id, std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_tracked_eapol");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    __Proxy(eapol_time, double, double, double, eapol_time);
    __Proxy(eapol_dir, uint8_t, uint8_t, uint8_t, eapol_dir);
    __Proxy(eapol_replay_counter, uint64_t, uint64_t, uint64_t, eapol_replay_counter);
    __Proxy(eapol_msg_num, uint8_t, uint8_t, uint8_t, eapol_msg_num);
    __Proxy(eapol_install, uint8_t, bool, bool, eapol_install);

    __ProxyTrackable(eapol_nonce, TrackerElementByteArray, eapol_nonce);

    void set_eapol_nonce_bytes(const std::string& in_n) {
        eapol_nonce->set(in_n);
    }

    std::string get_eapol_nonce_bytes() {
        return eapol_nonce->get();
    }

    __ProxyTrackable(eapol_packet, kis_tracked_packet, eapol_packet);

protected:
    virtual void register_fields() override;

    std::shared_ptr<TrackerElementDouble> eapol_time;
    std::shared_ptr<TrackerElementUInt8> eapol_dir;
    std::shared_ptr<TrackerElementUInt64> eapol_replay_counter;
    std::shared_ptr<TrackerElementUInt8> eapol_msg_num;
    std::shared_ptr<TrackerElementUInt8> eapol_install;
    std::shared_ptr<TrackerElementByteArray> eapol_nonce;

    std::shared_ptr<kis_tracked_packet> eapol_packet;
    int eapol_packet_id;
};

class dot11_tracked_nonce : public tracker_component {
public:
    dot11_tracked_nonce() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_nonce(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_nonce(int in_id, std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_tracked_nonce");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(eapol_time, double, double, double, eapol_time);
    __Proxy(eapol_msg_num, uint8_t, uint8_t, uint8_t, eapol_msg_num);
    __Proxy(eapol_install, uint8_t, bool, bool, eapol_install);
    __Proxy(eapol_replay_counter, uint64_t, uint64_t, uint64_t, eapol_replay_counter);

    void set_eapol_nonce_bytes(std::string in_n) {
        eapol_nonce->set(in_n);
    }

    std::string get_eapol_nonce_bytes() {
        return eapol_nonce->get();
    }

    void set_from_eapol(SharedTrackerElement in_tracked_eapol);

protected:
    virtual void register_fields() override;

    std::shared_ptr<TrackerElementDouble> eapol_time;
    std::shared_ptr<TrackerElementUInt8> eapol_msg_num;
    std::shared_ptr<TrackerElementUInt8> eapol_install;
    std::shared_ptr<TrackerElementByteArray> eapol_nonce;
    std::shared_ptr<TrackerElementUInt64> eapol_replay_counter;
};

class dot11_tracked_ssid_alert : public tracker_component {
public:
    dot11_tracked_ssid_alert() :
        tracker_component() {
#ifdef HAVE_LIBPCRE
        ssid_re = NULL;
        ssid_study = NULL;
#endif

        register_fields();
        reserve_fields(NULL);
    };

    dot11_tracked_ssid_alert(int in_id) :
        tracker_component(in_id) {

#ifdef HAVE_LIBPCRE
            ssid_re = NULL;
            ssid_study = NULL;
#endif

            register_fields();
            reserve_fields(NULL);
        }

    dot11_tracked_ssid_alert(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
#ifdef HAVE_LIBCPRE
        ssid_re = NULL;
        ssid_study = NULL;
#endif

        register_fields();
        reserve_fields(e);
    }

    virtual ~dot11_tracked_ssid_alert() {
#ifdef HAVE_LIBCPRE
        if (ssid_re != NULL)
            pcre_free(ssid_re);
        if (ssid_study != NULL)
            pcre_free(ssid_study);
#endif
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_tracked_ssid_alert");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(group_name, std::string, std::string, std::string, ssid_group_name);

    // Control the regex.  MAY THROW std::runtime_error if the regex is invalid
    __ProxyGet(regex, std::string, std::string, ssid_regex);
    void set_regex(std::string s);

    __ProxyTrackable(allowed_macs_vec, TrackerElementVector, allowed_macs_vec);

    void set_allowed_macs(std::vector<mac_addr> mvec);

    bool compare_ssid(std::string ssid, mac_addr mac);

protected:
    kis_recursive_timed_mutex ssid_mutex;

    virtual void register_fields() override;

    std::shared_ptr<TrackerElementString> ssid_group_name;
    std::shared_ptr<TrackerElementString> ssid_regex;
    std::shared_ptr<TrackerElementVector> allowed_macs_vec;
    int allowed_mac_id;

#ifdef HAVE_LIBPCRE
    pcre *ssid_re;
    pcre_extra *ssid_study;
#endif
};

class dot11_11d_tracked_range_info : public tracker_component {
public:
    dot11_11d_tracked_range_info() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_11d_tracked_range_info(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_11d_tracked_range_info(int in_id, std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_11d_tracked_range_info");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(startchan, uint32_t, uint32_t, uint32_t, startchan);
    __Proxy(numchan, uint32_t, unsigned int, unsigned int, numchan);
    __Proxy(txpower, int32_t, int, int, txpower);

protected:
    virtual void register_fields() override {
        RegisterField("dot11.11d.start_channel", "Starting channel of 11d range", &startchan);
        RegisterField("dot11.11d.num_channels", "Number of channels covered by range", &numchan);
        RegisterField("dot11.11d.tx_power", "Maximum allowed transmit power", &txpower);
    }

    std::shared_ptr<TrackerElementUInt32> startchan;
    std::shared_ptr<TrackerElementUInt32> numchan;
    std::shared_ptr<TrackerElementInt32> txpower;
};

class dot11_probed_ssid : public tracker_component {
public:
    dot11_probed_ssid() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_probed_ssid(int in_id) : 
        tracker_component(in_id) { 
            register_fields();
            reserve_fields(NULL);
        } 

    dot11_probed_ssid(int in_id, std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_probed_ssid");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(ssid, std::string, std::string, std::string, ssid);
    __Proxy(ssid_len, uint32_t, unsigned int, unsigned int, ssid_len);
    __Proxy(bssid, mac_addr, mac_addr, mac_addr, bssid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __ProxyDynamicTrackable(location, kis_tracked_location, location, location_id);

    __Proxy(dot11r_mobility, uint8_t, bool, bool, dot11r_mobility);
    __Proxy(dot11r_mobility_domain_id, uint16_t, uint16_t, uint16_t, 
            dot11r_mobility_domain_id);

    __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, crypt_set);

    __ProxyTrackable(ie_tag_list, TrackerElementVectorDouble, ie_tag_list);

protected:
    virtual void register_fields() override {
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

        RegisterField("dot11.probessid.crypt_set", "Requested encryption set", &crypt_set);

        RegisterField("dot11.probessid.ie_tag_list",
                "802.11 IE tag list in beacon", &ie_tag_list);
    }

    std::shared_ptr<TrackerElementString> ssid;
    std::shared_ptr<TrackerElementUInt32> ssid_len;
    std::shared_ptr<TrackerElementMacAddr> bssid;
    std::shared_ptr<TrackerElementUInt64> first_time;
    std::shared_ptr<TrackerElementUInt64> last_time;

    std::shared_ptr<TrackerElementUInt8> dot11r_mobility;
    std::shared_ptr<TrackerElementUInt16> dot11r_mobility_domain_id;

    std::shared_ptr<kis_tracked_location> location;
    int location_id;

    std::shared_ptr<TrackerElementUInt64> crypt_set;

    std::shared_ptr<TrackerElementVectorDouble> ie_tag_list;
};

/* Advertised SSID
 *
 * SSID advertised by a device via beacon or probe response
 */
class dot11_advertised_ssid : public tracker_component {
public:
    dot11_advertised_ssid() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_advertised_ssid(int in_id) : 
        tracker_component(in_id) { 
            register_fields();
            reserve_fields(NULL);
        } 

    dot11_advertised_ssid(int in_id, std::shared_ptr<TrackerElementMap> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_advertised_ssid");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(ssid, std::string, std::string, std::string, ssid);
    __Proxy(ssid_len, uint32_t, unsigned int, unsigned int, ssid_len);

    __Proxy(ssid_beacon, uint8_t, bool, bool, ssid_beacon);
    __Proxy(ssid_probe_response, uint8_t, bool, bool, ssid_probe_response);

    __Proxy(channel, std::string, std::string, std::string, channel);
    __Proxy(ht_mode, std::string, std::string, std::string, ht_mode);
    __Proxy(ht_center_1, uint64_t, uint64_t, uint64_t, ht_center_1);
    __Proxy(ht_center_2, uint64_t, uint64_t, uint64_t, ht_center_2);

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __Proxy(beacon_info, std::string, std::string, std::string, beacon_info);

    __Proxy(ssid_cloaked, uint8_t, bool, bool, ssid_cloaked);

    __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, crypt_set);

    __Proxy(maxrate, double, double, double, maxrate);

    __Proxy(beaconrate, uint32_t, uint32_t, uint32_t, beaconrate);
    __Proxy(beacons_sec, uint32_t, uint32_t, uint32_t, beacons_sec);
    __ProxyIncDec(beacons_sec, uint32_t, uint32_t, beacons_sec);

    __Proxy(ietag_checksum, uint32_t, uint32_t, uint32_t, ietag_checksum);

    __ProxyDynamic(dot11d_country, std::string, std::string, std::string, dot11d_country, 
            dot11d_country_id);

    __ProxyTrackable(dot11d_vec, TrackerElementVector, dot11d_vec);

    void set_dot11d_vec(std::vector<dot11_packinfo_dot11d_entry> vec) {
        dot11d_vec->clear();

        for (auto x : vec) {
            auto ri = 
                std::make_shared<dot11_11d_tracked_range_info>(dot11d_country_entry_id);
            ri->set_startchan(x.startchan);
            ri->set_numchan(x.numchan);
            ri->set_txpower(x.txpower);
        }
    }

    __ProxyDynamic(wps_state, uint32_t, uint32_t, uint32_t, wps_state, wps_state_id);
    __ProxyDynamic(wps_manuf, std::string, std::string, std::string, wps_manuf, wps_manuf_id);
    __ProxyDynamic(wps_device_name, std::string, std::string, std::string, wps_device_name, 
            wps_device_name_id);
    __ProxyDynamic(wps_model_name, std::string, std::string, std::string, wps_model_name, 
            wps_model_name_id);
    __ProxyDynamic(wps_model_number, std::string, std::string, std::string, wps_model_number,
            wps_model_number_id);
    __ProxyDynamic(wps_serial_number, std::string, std::string, std::string, wps_serial_number,
            wps_serial_number_id);

    __ProxyDynamicTrackable(location, kis_tracked_location, location, location_id);

    __Proxy(dot11r_mobility, uint8_t, bool, bool, dot11r_mobility);
    __Proxy(dot11r_mobility_domain_id, uint16_t, uint16_t, uint16_t, 
            dot11r_mobility_domain_id);

    __Proxy(dot11e_qbss, uint8_t, bool, bool, dot11e_qbss);
    __Proxy(dot11e_qbss_stations, uint16_t, uint16_t, uint16_t, dot11e_qbss_stations);
    __Proxy(dot11e_qbss_channel_load, double, double, double, dot11e_qbss_channel_load);

    __Proxy(ccx_txpower, uint8_t, unsigned int, unsigned int, ccx_txpower);
    __Proxy(cisco_client_mfp, uint8_t, bool, bool, cisco_client_mfp);

    __ProxyTrackable(ie_tag_list, TrackerElementVectorDouble, ie_tag_list);

protected:

    virtual void register_fields() override {
        RegisterField("dot11.advertisedssid.ssid", "probed ssid string (sanitized)", &ssid);
        RegisterField("dot11.advertisedssid.ssidlen", 
                "probed ssid string length (original bytes)", &ssid_len);
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

    virtual void reserve_fields(std::shared_ptr<TrackerElementMap> e) override {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            // If we're inheriting, it's our responsibility to kick submaps and vectors with
            // complex types as well; since they're not themselves complex objects
            for (auto d = dot11d_vec->begin(); d != dot11d_vec->end(); ++d) {
                auto din =
                    std::make_shared<dot11_11d_tracked_range_info>(dot11d_country_entry_id,
                            std::static_pointer_cast<TrackerElementMap>(*d));

                // And assign it over the same key
                *d = std::static_pointer_cast<TrackerElement>(din);
            }
        }
    }

    std::shared_ptr<TrackerElementString> ssid;
    std::shared_ptr<TrackerElementUInt32> ssid_len;
    std::shared_ptr<TrackerElementUInt8> ssid_beacon;
    std::shared_ptr<TrackerElementUInt8> ssid_probe_response;

    // Channel and optional HT center/second center
    std::shared_ptr<TrackerElementString> channel;
    std::shared_ptr<TrackerElementString> ht_mode;
    std::shared_ptr<TrackerElementUInt64> ht_center_1;
    std::shared_ptr<TrackerElementUInt64> ht_center_2;

    std::shared_ptr<TrackerElementUInt64> first_time;
    std::shared_ptr<TrackerElementUInt64> last_time;

    std::shared_ptr<TrackerElementString> beacon_info;
    std::shared_ptr<TrackerElementUInt8> ssid_cloaked;
    std::shared_ptr<TrackerElementUInt64> crypt_set;
    std::shared_ptr<TrackerElementDouble> maxrate;
    std::shared_ptr<TrackerElementUInt32> beaconrate;
    std::shared_ptr<TrackerElementUInt32> beacons_sec;
    std::shared_ptr<TrackerElementUInt32> ietag_checksum;

    // IE tag dot11d country / power restrictions from 802.11d; 
    // deprecated but still in use
    std::shared_ptr<TrackerElementString> dot11d_country;
    int dot11d_country_id;

    std::shared_ptr<TrackerElementVector> dot11d_vec;
    int dot11d_country_entry_id;

    // WPS components
    std::shared_ptr<TrackerElementUInt32> wps_state;
    int wps_state_id;

    std::shared_ptr<TrackerElementString> wps_manuf;
    int wps_manuf_id;

    std::shared_ptr<TrackerElementString> wps_device_name;
    int wps_device_name_id;

    std::shared_ptr<TrackerElementString> wps_model_name;
    int wps_model_name_id;

    std::shared_ptr<TrackerElementString> wps_model_number;
    int wps_model_number_id;

    std::shared_ptr<TrackerElementString> wps_serial_number;
    int wps_serial_number_id;

    std::shared_ptr<kis_tracked_location> location;
    int location_id;

    // 802.11r mobility/fast roaming advertisements
    std::shared_ptr<TrackerElementUInt8> dot11r_mobility;
    std::shared_ptr<TrackerElementUInt16> dot11r_mobility_domain_id;

    // 802.11e QBSS
    std::shared_ptr<TrackerElementUInt8> dot11e_qbss;
    std::shared_ptr<TrackerElementUInt16> dot11e_qbss_stations;
    std::shared_ptr<TrackerElementDouble> dot11e_qbss_channel_load;

    // Cisco CCX
    std::shared_ptr<TrackerElementUInt8> ccx_txpower;
    // Cisco frame protection
    std::shared_ptr<TrackerElementUInt8> cisco_client_mfp;

    // IE tags present, and order
    std::shared_ptr<TrackerElementVectorDouble> ie_tag_list;
};

/* dot11 client
 *
 * Observed behavior as a client of a bssid.  Multiple records may exist
 * if this device has behaved as a client for multiple BSSIDs
 *
 */
class dot11_client : public tracker_component {
public:
    dot11_client() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_client(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(NULL);
        }

    dot11_client(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_client");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(bssid, mac_addr, mac_addr, mac_addr, bssid);
    __Proxy(bssid_key, device_key, device_key, device_key, bssid_key);
    __Proxy(client_type, uint32_t, uint32_t, uint32_t, client_type);

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);

    __ProxyDynamic(dhcp_host, std::string, std::string, std::string, dhcp_host, dhcp_host_id);
    __ProxyDynamic(dhcp_vendor, std::string, std::string, std::string, dhcp_vendor, dhcp_vendor_id);

    __Proxy(tx_cryptset, uint64_t, uint64_t, uint64_t, tx_cryptset);
    __Proxy(rx_cryptset, uint64_t, uint64_t, uint64_t, rx_cryptset);

    __ProxyDynamic(eap_identity, std::string, std::string, std::string, eap_identity, eap_identity_id);

    __ProxyDynamic(cdp_device, std::string, std::string, std::string, cdp_device, cdp_device_id);
    __ProxyDynamic(cdp_port, std::string, std::string, std::string, cdp_port, cdp_port_id);

    __Proxy(decrypted, uint8_t, bool, bool, decrypted);

    __ProxyDynamicTrackable(ipdata, kis_tracked_ip_data, ipdata, ipdata_id);

    __Proxy(datasize, uint64_t, uint64_t, uint64_t, datasize);
    __ProxyIncDec(datasize, uint64_t, uint64_t, datasize);

    __Proxy(datasize_retry, uint64_t, uint64_t, uint64_t, datasize_retry);
    __ProxyIncDec(datasize_retry, uint64_t, uint64_t, datasize_retry);

    __Proxy(num_fragments, uint64_t, uint64_t, uint64_t, num_fragments);
    __ProxyIncDec(num_fragments, uint64_t, uint64_t, num_fragments);

    __Proxy(num_retries, uint64_t, uint64_t, uint64_t, num_retries);
    __ProxyIncDec(num_retries, uint64_t, uint64_t, num_retries);

    __ProxyDynamicTrackable(location, kis_tracked_location, location, location_id);

protected:
    virtual void register_fields() override {
        RegisterField("dot11.client.bssid", "bssid", &bssid);
        RegisterField("dot11.client.bssid_key", "key of BSSID record", &bssid_key);
        RegisterField("dot11.client.first_time", "first time seen", &first_time);
        RegisterField("dot11.client.last_time", "last time seen", &last_time);
        RegisterField("dot11.client.type", "type of client", &client_type);
        dhcp_host_id =
            RegisterDynamicField("dot11.client.dhcp_host", "dhcp host", &dhcp_host);
        dhcp_vendor_id =
            RegisterDynamicField("dot11.client.dhcp_vendor", "dhcp vendor", &dhcp_vendor);
        RegisterField("dot11.client.tx_cryptset", "bitset of transmitted encryption", &tx_cryptset);
        RegisterField("dot11.client.rx_cryptset", "bitset of received enryption", &rx_cryptset);
        eap_identity_id = 
            RegisterDynamicField("dot11.client.eap_identity", "EAP identity", &eap_identity);
        cdp_device_id = 
            RegisterDynamicField("dot11.client.cdp_device", "CDP device", &cdp_device);
        cdp_port_id =
            RegisterDynamicField("dot11.client.cdp_port", "CDP port", &cdp_port);
        RegisterField("dot11.client.decrypted", "client decrypted", &decrypted);
        
        ipdata_id =
            RegisterDynamicField("dot11.client.ipdata", "IPv4 information", &ipdata);

        RegisterField("dot11.client.datasize", "data in bytes", &datasize);
        RegisterField("dot11.client.datasize_retry", "retry data in bytes", &datasize_retry);
        RegisterField("dot11.client.num_fragments", "number of fragmented packets", &num_fragments);
        RegisterField("dot11.client.num_retries", "number of retried packets", &num_retries);

        location_id =
            RegisterDynamicField("dot11.client.location", "location", &location);

    }

    std::shared_ptr<TrackerElementMacAddr> bssid;
    std::shared_ptr<TrackerElementDeviceKey> bssid_key;

    std::shared_ptr<TrackerElementUInt64> first_time;
    std::shared_ptr<TrackerElementUInt64> last_time;

    std::shared_ptr<TrackerElementUInt32> client_type;

    std::shared_ptr<TrackerElementString> dhcp_host;
    int dhcp_host_id;

    std::shared_ptr<TrackerElementString> dhcp_vendor;
    int dhcp_vendor_id;

    std::shared_ptr<TrackerElementUInt64> tx_cryptset;
    std::shared_ptr<TrackerElementUInt64> rx_cryptset;

    std::shared_ptr<TrackerElementString> eap_identity;
    int eap_identity_id;

    std::shared_ptr<TrackerElementString> cdp_device;
    int cdp_device_id;

    std::shared_ptr<TrackerElementString> cdp_port;
    int cdp_port_id;

    std::shared_ptr<TrackerElementUInt8> decrypted;

    std::shared_ptr<kis_tracked_ip_data> ipdata;
    int ipdata_id;

    std::shared_ptr<TrackerElementUInt64> datasize;
    std::shared_ptr<TrackerElementUInt64> datasize_retry;
    std::shared_ptr<TrackerElementUInt64> num_fragments;
    std::shared_ptr<TrackerElementUInt64> num_retries;

    std::shared_ptr<kis_tracked_location> location;
    int location_id;
};

// Bitset of top-level device types for easy sorting/browsing
#define DOT11_DEVICE_TYPE_UNKNOWN           0
// This device has beaconed
#define DOT11_DEVICE_TYPE_BEACON_AP         (1 << 0)
// This device has acted like an adhoc device
#define DOT11_DEVICE_TYPE_ADHOC             (1 << 1)
// This device has acted like a client
#define DOT11_DEVICE_TYPE_CLIENT            (1 << 2)
// This device appears to be a wired device bridged to wifi
#define DOT11_DEVICE_TYPE_WIRED             (1 << 3)
// WDS distribution network
#define DOT11_DEVICE_TYPE_WDS               (1 << 4)
// Old-school turbocell
#define DOT11_DEVICE_TYPE_TURBOCELL         (1 << 5)
// We haven't seen this device directly but we're guessing it's there
// because something has talked to it over wireless (ie, cts or ack to it)
#define DOT11_DEVICE_TYPE_INFERRED_WIRELESS (1 << 6)
// We haven't seen this device directly but we've seen something talking to it
#define DOT11_DEVICE_TYPE_INFERRED_WIRED    (1 << 7)
// Device has responded to probes, looking like an AP
#define DOT11_DEVICE_TYPE_PROBE_AP          (1 << 8)

// Dot11 device
//
// Device-level data, additional data stored in the client and ssid arrays
class dot11_tracked_device : public tracker_component {
    friend class Kis_80211_Phy;
public:
    dot11_tracked_device() :
        tracker_component() {

        last_adv_ie_csum = 0;
        last_bss_invalid = 0;
        bss_invalid_count = 0;

        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_device(int in_id) :
        tracker_component(in_id) { 

        last_adv_ie_csum = 0;
        last_bss_invalid = 0;
        bss_invalid_count = 0;

        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_device(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {

        last_adv_ie_csum = 0;
        last_bss_invalid = 0;
        bss_invalid_count = 0;

        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("dot11_tracked_device");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    static void attach_base_parent(std::shared_ptr<dot11_tracked_device> self, 
            std::shared_ptr<kis_tracked_device_base> parent) {
        parent->insert(self);
    }

    __Proxy(type_set, uint64_t, uint64_t, uint64_t, type_set);
    __ProxyBitset(type_set, uint64_t, type_set);

    __ProxyTrackable(client_map, TrackerElementMacMap, client_map);

    std::shared_ptr<dot11_client> new_client() {
        return std::make_shared<dot11_client>(client_map_entry_id);
    }
    __Proxy(num_client_aps, uint64_t, uint64_t, uint64_t, num_client_aps);


    __ProxyTrackable(advertised_ssid_map, TrackerElementIntMap, advertised_ssid_map);
    std::shared_ptr<dot11_advertised_ssid> new_advertised_ssid() {
        return std::make_shared<dot11_advertised_ssid>(advertised_ssid_map_entry_id);
    }
    __Proxy(num_advertised_ssids, uint64_t, uint64_t, uint64_t, num_advertised_ssids);

    __ProxyTrackable(probed_ssid_map, TrackerElementIntMap, probed_ssid_map);
    std::shared_ptr<dot11_probed_ssid> new_probed_ssid() {
        return std::make_shared<dot11_probed_ssid>(probed_ssid_map_entry_id);
    }
    __Proxy(num_probed_ssids, uint64_t, uint64_t, uint64_t, num_probed_ssids);

    __ProxyTrackable(associated_client_map, TrackerElementMacMap, associated_client_map);
    __Proxy(num_associated_clients, uint64_t, uint64_t, uint64_t, num_associated_clients);

    __Proxy(client_disconnects, uint64_t, uint64_t, uint64_t, client_disconnects);
    __ProxyIncDec(client_disconnects, uint64_t, uint64_t, client_disconnects);

    __Proxy(last_sequence, uint64_t, uint64_t, uint64_t, last_sequence);
    __Proxy(bss_timestamp, uint64_t, uint64_t, uint64_t, bss_timestamp);
    time_t last_bss_invalid;
    unsigned int bss_invalid_count;

    __Proxy(num_fragments, uint64_t, uint64_t, uint64_t, num_fragments);
    __ProxyIncDec(num_fragments, uint64_t, uint64_t, num_fragments);

    __Proxy(num_retries, uint64_t, uint64_t, uint64_t, num_retries);
    __ProxyIncDec(num_retries, uint64_t, uint64_t, num_retries);

    __Proxy(datasize, uint64_t, uint64_t, uint64_t, datasize);
    __ProxyIncDec(datasize, uint64_t, uint64_t, datasize);

    __Proxy(datasize_retry, uint64_t, uint64_t, uint64_t, datasize_retry);
    __ProxyIncDec(datasize_retry, uint64_t, uint64_t, datasize_retry);

    __ProxyDynamic(last_bssid, mac_addr, mac_addr, mac_addr, last_bssid, last_bssid_id);

    __ProxyDynamic(last_probed_ssid, std::string, std::string, std::string, last_probed_ssid,
            last_probed_ssid_id);
    __Proxy(last_probed_ssid_csum, uint32_t, uint32_t, 
            uint32_t, last_probed_ssid_csum);

    __ProxyDynamic(last_beaconed_ssid, std::string, std::string, std::string, last_beaconed_ssid,
            last_beaconed_ssid_id);
    __Proxy(last_beaconed_ssid_csum, uint32_t, uint32_t, 
            uint32_t, last_beaconed_ssid_csum);

    __Proxy(last_beacon_timestamp, uint64_t, time_t, 
            time_t, last_beacon_timestamp);

    __Proxy(wps_m3_count, uint64_t, uint64_t, uint64_t, wps_m3_count);
    __ProxyIncDec(wps_m3_count, uint64_t, uint64_t, wps_m3_count);

    __Proxy(wps_m3_last, uint64_t, uint64_t, uint64_t, wps_m3_last);

    __ProxyTrackable(wpa_key_vec, TrackerElementVector, wpa_key_vec);
    std::shared_ptr<dot11_tracked_eapol> create_eapol_packet() {
        return std::make_shared<dot11_tracked_eapol>(wpa_key_entry_id);
    }

    __Proxy(wpa_present_handshake, uint8_t, uint8_t, uint8_t, wpa_present_handshake);

    __ProxyTrackable(wpa_nonce_vec, TrackerElementVector, wpa_nonce_vec);
    __ProxyTrackable(wpa_anonce_vec, TrackerElementVector, wpa_anonce_vec);
    std::shared_ptr<dot11_tracked_nonce> create_tracked_nonce() {
        return std::make_shared<dot11_tracked_nonce>(wpa_nonce_entry_id);
    }

    uint32_t get_last_adv_ie_csum() { return last_adv_ie_csum; }
    void set_last_adv_ie_csum(uint32_t csum) { last_adv_ie_csum = csum; }
    std::shared_ptr<dot11_advertised_ssid> get_last_adv_ssid() {
        return last_adv_ssid;
    }
    void set_last_adv_ssid(std::shared_ptr<dot11_advertised_ssid> adv_ssid) {
        last_adv_ssid = adv_ssid;
    }

    virtual void pre_serialize() override {
        set_num_client_aps(client_map->size());
        set_num_advertised_ssids(advertised_ssid_map->size());
        set_num_probed_ssids(probed_ssid_map->size());
        set_num_associated_clients(associated_client_map->size());
    }

    __Proxy(min_tx_power, uint8_t, unsigned int, unsigned int, min_tx_power);
    __Proxy(max_tx_power, uint8_t, unsigned int, unsigned int, max_tx_power);
    __ProxyTrackable(supported_channels, TrackerElementVectorDouble, supported_channels);

    __Proxy(link_measurement_capable, uint8_t, bool, bool, link_measurement_capable);
    __Proxy(neighbor_report_capable, uint8_t, bool, bool, neighbor_report_capable);
    __ProxyTrackable(extended_capabilities_list, TrackerElementVectorString, extended_capabilities_list);

    __Proxy(beacon_fingerprint, uint32_t, uint32_t, uint32_t, beacon_fingerprint);
    __Proxy(probe_fingerprint, uint32_t, uint32_t, uint32_t, probe_fingerprint);
    __Proxy(response_fingerprint, uint32_t, uint32_t, uint32_t, response_fingerprint);

protected:

    virtual void register_fields() override {
        RegisterField("dot11.device.typeset", "bitset of device type", &type_set);
        RegisterField("dot11.device.client_map", "client behavior", &client_map);

        client_map_entry_id =
            RegisterField("dot11.device.client",
                    TrackerElementFactory<dot11_client>(),
                    "client behavior record");

        RegisterField("dot11.device.num_client_aps", "number of APs connected to", &num_client_aps);

        // Advertised SSIDs keyed by ssid checksum
        RegisterField("dot11.device.advertised_ssid_map", "advertised SSIDs", &advertised_ssid_map);

        advertised_ssid_map_entry_id =
            RegisterField("dot11.device.advertised_ssid",
                    TrackerElementFactory<dot11_advertised_ssid>(),
                    "advertised SSID");

        RegisterField("dot11.device.num_advertised_ssids", 
                "number of advertised SSIDs", &num_advertised_ssids);

        // Probed SSIDs keyed by int checksum
        RegisterField("dot11.device.probed_ssid_map", "probed SSIDs", &probed_ssid_map);

        probed_ssid_map_entry_id =
            RegisterField("dot11.device.probed_ssid",
                    TrackerElementFactory<dot11_probed_ssid>(),
                    "probed ssid");

        RegisterField("dot11.device.num_probed_ssids", "number of probed SSIDs", &num_probed_ssids);

        RegisterField("dot11.device.associated_client_map",
                "associated clients", &associated_client_map);

        // Key of associated device, indexed by mac address
        associated_client_map_entry_id =
            RegisterField("dot11.device.associated_client", 
                    TrackerElementFactory<TrackerElementDeviceKey>(), "associated client");

        RegisterField("dot11.device.num_associated_clients", 
                "number of associated clients", &num_associated_clients);

        RegisterField("dot11.device.client_disconnects", 
                "client disconnects in last second", 
                &client_disconnects);

        RegisterField("dot11.device.last_sequence", "last sequence number", &last_sequence);
        RegisterField("dot11.device.bss_timestamp", "last BSS timestamp", &bss_timestamp);

        RegisterField("dot11.device.num_fragments", "number of fragmented packets", &num_fragments);
        RegisterField("dot11.device.num_retries", "number of retried packets", &num_retries);

        RegisterField("dot11.device.datasize", "data in bytes", &datasize);
        RegisterField("dot11.device.datasize_retry", "retried data in bytes", &datasize_retry);

        last_probed_ssid_id =
            RegisterDynamicField("dot11.device.last_probed_ssid", "last probed ssid", &last_probed_ssid);
        RegisterField("dot11.device.last_probed_ssid_csum", 
                "last probed ssid checksum", &last_probed_ssid_csum);

        last_beaconed_ssid_id =
            RegisterDynamicField("dot11.device.last_beaconed_ssid", 
                    "last beaconed ssid", &last_beaconed_ssid);
        RegisterField("dot11.device.last_beaconed_ssid_checksum", 
                "last beaconed ssid checksum", &last_beaconed_ssid_csum);

        last_bssid_id =
            RegisterDynamicField("dot11.device.last_bssid", "last BSSID", &last_bssid);

        RegisterField("dot11.device.last_beacon_timestamp",
                "unix timestamp of last beacon frame", 
                &last_beacon_timestamp);

        RegisterField("dot11.device.wps_m3_count", "WPS M3 message count", &wps_m3_count);
        RegisterField("dot11.device.wps_m3_last", "WPS M3 last message", &wps_m3_last);

        RegisterField("dot11.device.wpa_handshake_list", "WPA handshakes", &wpa_key_vec);

        wpa_key_entry_id =
            RegisterField("dot11.eapol.key",
                    TrackerElementFactory<dot11_tracked_eapol>(),
                    "WPA handshake key");

        RegisterField("dot11.device.wpa_nonce_list", "Previous WPA Nonces", &wpa_nonce_vec);

        RegisterField("dot11.device.wpa_anonce_list", "Previous WPA ANonces", &wpa_anonce_vec);

        RegisterField("dot11.device.wpa_present_handshake", 
                "handshake sequences seen (bitmask)", &wpa_present_handshake);

        wpa_nonce_entry_id =
            RegisterField("dot11.device.wpa_nonce",
                    TrackerElementFactory<dot11_tracked_nonce>(),
                    "WPA nonce exchange");

        RegisterField("dot11.device.min_tx_power", "Minimum advertised TX power", &min_tx_power);
        RegisterField("dot11.device.max_tx_power", "Maximum advertised TX power", &max_tx_power);

        RegisterField("dot11.device.supported_channels", "Advertised supported channels", 
                &supported_channels);

        RegisterField("dot11.device.link_measurement_capable", 
                "Advertised link measurement client capability", &link_measurement_capable);
        RegisterField("dot11.device.neighbor_report_capable",
                "Advertised neighbor report capability", &neighbor_report_capable);
        RegisterField("dot11.device.extended_capabilities", 
                "Advertised extended capabilities list", &extended_capabilities_list);

        RegisterField("dot11.device.beacon_fingerprint", "Beacon fingerprint", &beacon_fingerprint);
        RegisterField("dot11.device.probe_fingerprint", "Probe (Client->AP) fingerprint", &probe_fingerprint);
        RegisterField("dot11.device.response_fingerprint", "Respose (AP->Client) fingerprint", 
                &response_fingerprint);
    }

    virtual void reserve_fields(std::shared_ptr<TrackerElementMap> e) override {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            // If we're inheriting, it's our responsibility to kick submap and vecs with
            // complex types as well; since they're not themselves complex objects
            for (auto as : *advertised_ssid_map) {
                auto assid =
                    std::make_shared<dot11_advertised_ssid>(advertised_ssid_map_entry_id, 
                            std::static_pointer_cast<TrackerElementMap>(as.second));
                as.second = assid;
            }

            for (auto ps : *probed_ssid_map) {
                auto pssid =
                    std::make_shared<dot11_probed_ssid>(probed_ssid_map_entry_id, 
                            std::static_pointer_cast<TrackerElementMap>(ps.second));
                ps.second = pssid;
            }

            for (auto ci : *client_map) {
                auto cli =
                    std::make_shared<dot11_client>(client_map_entry_id, 
                            std::static_pointer_cast<TrackerElementMap>(ci.second));
                ci.second = cli;
            }

            // We don't have to deal with the client map because it's a map of
            // simplistic types

            for (auto k = wpa_key_vec->begin(); k != wpa_key_vec->end(); ++k) {
                auto eap =
                    std::make_shared<dot11_tracked_eapol>(wpa_key_entry_id, 
                            std::static_pointer_cast<TrackerElementMap>(*k));
                *k = eap;
            }

            for (auto k = wpa_nonce_vec->begin(); k != wpa_nonce_vec->end(); ++k) {
                auto nonce =
                    std::make_shared<dot11_tracked_nonce>(wpa_nonce_entry_id, 
                            std::static_pointer_cast<TrackerElementMap>(*k));
                *k = nonce;
            }

            for (auto k = wpa_anonce_vec->begin(); k != wpa_anonce_vec->end(); ++k) {
                auto anonce =
                    std::make_shared<dot11_tracked_nonce>(wpa_nonce_entry_id, 
                            std::static_pointer_cast<TrackerElementMap>(*k));
                *k = anonce;
            }
        }
    }

    std::shared_ptr<TrackerElementUInt64> type_set;

    std::shared_ptr<TrackerElementMacMap> client_map;
    int client_map_entry_id;
    std::shared_ptr<TrackerElementUInt64> num_client_aps;

    std::shared_ptr<TrackerElementIntMap> advertised_ssid_map;
    int advertised_ssid_map_entry_id;
    std::shared_ptr<TrackerElementUInt64> num_advertised_ssids;

    std::shared_ptr<TrackerElementIntMap> probed_ssid_map;
    int probed_ssid_map_entry_id;
    std::shared_ptr<TrackerElementUInt64> num_probed_ssids;

    std::shared_ptr<TrackerElementMacMap> associated_client_map;
    int associated_client_map_entry_id;
    std::shared_ptr<TrackerElementUInt64> num_associated_clients;
    std::shared_ptr<TrackerElementUInt64> client_disconnects;

    std::shared_ptr<TrackerElementUInt64> last_sequence;
    std::shared_ptr<TrackerElementUInt64> bss_timestamp;

    std::shared_ptr<TrackerElementUInt64> num_fragments;
    std::shared_ptr<TrackerElementUInt64> num_retries;

    std::shared_ptr<TrackerElementUInt64> datasize;
    std::shared_ptr<TrackerElementUInt64> datasize_retry;

    std::shared_ptr<TrackerElementString> last_probed_ssid;
    int last_probed_ssid_id;

    std::shared_ptr<TrackerElementUInt32> last_probed_ssid_csum;

    std::shared_ptr<TrackerElementString> last_beaconed_ssid;
    int last_beaconed_ssid_id;

    std::shared_ptr<TrackerElementUInt32> last_beaconed_ssid_csum;

    std::shared_ptr<TrackerElementMacAddr> last_bssid;
    int last_bssid_id;

    std::shared_ptr<TrackerElementUInt64> last_beacon_timestamp;

    std::shared_ptr<TrackerElementUInt64> wps_m3_count;
    std::shared_ptr<TrackerElementUInt64> wps_m3_last;

    std::shared_ptr<TrackerElementVector> wpa_key_vec;
    int wpa_key_entry_id;
    std::shared_ptr<TrackerElementVector> wpa_nonce_vec;
    std::shared_ptr<TrackerElementVector> wpa_anonce_vec;
    std::shared_ptr<TrackerElementUInt8> wpa_present_handshake;
    int wpa_nonce_entry_id;

    // Un-exposed internal tracking options
    uint32_t last_adv_ie_csum;
    std::shared_ptr<dot11_advertised_ssid> last_adv_ssid;

    // Advertised in association requests but device-centric
    std::shared_ptr<TrackerElementUInt8> min_tx_power;
    std::shared_ptr<TrackerElementUInt8> max_tx_power;

    std::shared_ptr<TrackerElementVectorDouble> supported_channels;

    std::shared_ptr<TrackerElementUInt8> link_measurement_capable;
    std::shared_ptr<TrackerElementUInt8> neighbor_report_capable;

    std::shared_ptr<TrackerElementVectorString> extended_capabilities_list;

    std::shared_ptr<TrackerElementUInt32> beacon_fingerprint;
    std::shared_ptr<TrackerElementUInt32> probe_fingerprint;
    std::shared_ptr<TrackerElementUInt32> response_fingerprint;
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
};

#endif
