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

#ifndef __PHY_80211_COMPONENTS_V2__
#define __PHY_80211_COMPONENTS_V2__

#include "config.h"

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "base64.h"
#include "devicetracker_component_v2.h"
#include "globalregistry.h"
#include "json_adapter_v2.h"
#include "macaddr.h"
#include "packet.h"
#include "packinfo_signal.h"
#include "rrd_v2.h"
#include "trackedlocation_v2.h"

#include "dot11_parsers/dot11_ie.h"
#include "dot11_parsers/dot11_ie_221_vendor.h"
#include "dot11_parsers/dot11_ie_255_ext_tag.h"

class dot11_tracked_eapol_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_eapol_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_tracked_eapol_v2& operator =(const dot11_tracked_eapol_v2& e) {
        eapol_time_ = e.eapol_time_;
        eapol_dir_ = e.eapol_dir_;
        eapol_replay_counter_ = e.eapol_replay_counter_;
        eapol_msg_num_ = e.eapol_msg_num_;
        eapol_install_ = e.eapol_install_;
        eapol_nonce_ = e.eapol_nonce_;
        eapol_rsn_pmkid_ = e.eapol_rsn_pmkid_;
        packet_ = e.packet_;
        return *this;
    }

    void reset() {
        eapol_time_ = 0;
        eapol_dir_ = 0;
        eapol_replay_counter_ = 0;
        eapol_msg_num_ = 0;
        eapol_install_ = 0;
        eapol_nonce_ = {};
        eapol_rsn_pmkid_ = {};
        packet_ = {};
    }

    auto eapol_time() const { return eapol_time_; }
    void set_eapol_time(auto time) { eapol_time_ = time; }

    auto eapol_dir() const { return eapol_dir_; };
    void set_eapol_dir(auto dir) { eapol_dir_ = dir; }

    auto eapol_replay_counter() const { return eapol_replay_counter_; }
    void set_eapol_replay_counter(auto c) { eapol_replay_counter_ = c; }

    auto eapol_msg_num() const { return eapol_msg_num_; }
    void set_eapol_msg_num(auto num) { eapol_msg_num_ = num; }

    auto eapol_install() const { return eapol_install_; }
    void set_eapol_install(auto i) { eapol_install_ = i; }

    const auto& eapol_nonce() const { return eapol_nonce_; }
    void set_eapol_nonce(const auto& nonce) { eapol_nonce_ = base64::encode(nonce); }

    const auto& eapol_rsn_pmkid() const { return eapol_rsn_pmkid_; }
    void set_eapol_rsn_pmkid(const auto& pmk) { eapol_rsn_pmkid_ = base64::encode(pmk); }

    auto& packet() const { return packet_; }
    void set_packet(const auto& packet) { packet_ = packet; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    double eapol_time_;
    uint8_t eapol_dir_;
    uint64_t eapol_replay_counter_;
    uint8_t eapol_msg_num_;
    uint8_t eapol_install_;
    std::string eapol_nonce_;
    std::string eapol_rsn_pmkid_;
    kis_tracked_packet_v2 packet_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_eapol_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class dot11_tracked_nonce_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_nonce_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_tracked_nonce_v2& operator =(const dot11_tracked_nonce_v2& e) {
        eapol_time_ = e.eapol_time_;
        eapol_replay_counter_ = e.eapol_replay_counter_;
        eapol_msg_num_ = e.eapol_msg_num_;
        eapol_install_ = e.eapol_install_;
        eapol_nonce_ = e.eapol_nonce_;
        return *this;
    }

    void reset() {
        eapol_time_ = 0;
        eapol_replay_counter_ = 0;
        eapol_msg_num_ = 0;
        eapol_install_ = 0;
        eapol_nonce_ = {};
    }

    auto eapol_time() const { return eapol_time_; }
    void set_eapol_time(auto time) { eapol_time_ = time; }

    auto eapol_replay_counter() const { return eapol_replay_counter_; }
    void set_eapol_replay_counter(auto c) { eapol_replay_counter_ = c; }

    auto eapol_msg_num() const { return eapol_msg_num_; }
    void set_eapol_msg_num(auto num) { eapol_msg_num_ = num; }

    auto eapol_install() const { return eapol_install_; }
    void set_eapol_install(auto i) { eapol_install_ = i; }

    const auto& eapol_nonce() const { return eapol_nonce_; }
    void set_eapol_nonce(const auto& nonce) { eapol_nonce_ = base64::encode(nonce); }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    double eapol_time_;
    uint8_t eapol_msg_num_;
    uint8_t eapol_install_;
    std::string eapol_nonce_;
    uint64_t eapol_replay_counter_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_nonce_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

// v2 does not include an internal mutex; safe access & comparison should be handled by the
// enclosing api
class dot11_tracked_ssid_alert_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_ssid_alert_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_tracked_ssid_alert_v2() {
        reset();
    }

    void reset() {
#if defined(HAVE_LIBPCRE1)
        if (ssid_re_ != NULL)
            pcre_free(ssid_re_);
        if (ssid_study_ != NULL)
            pcre_free(ssid_study_);

        ssid_re_ = NULL;
        ssid_study_ = NULL;
#elif defined(HAVE_LIBPCRE2)
        if (ssid_match_data_ != NULL)
            pcre2_match_data_free(ssid_match_data_);
        if (ssid_re_ != NULL)
            pcre2_code_free(ssid_re_);

        ssid_match_data_ = NULL;
        ssid_re_ = NULL;
#endif

        ssid_group_name_ = {};
        ssid_regex_ = {};
        allowed_macs_vec_ = {};
    }

    const auto ssid_group_name() { return ssid_group_name_; }
    void set_ssid_group_name(auto name) { ssid_group_name_ = name; }

    const auto ssid_regex() { return ssid_regex_; }
    void set_ssid_regex(const std::string& regex);

    auto& allowed_macs() { return allowed_macs_vec_; }
    void set_allowed_macs(const auto& macs) { allowed_macs_vec_ = macs; }

    bool compare_ssid(const std::string& ssid, const mac_addr& mac);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    std::string ssid_group_name_;
    std::string ssid_regex_;

    using allowed_macs_vec_iter_t_ = std::vector<mac_addr>::iterator;
    std::vector<mac_addr> allowed_macs_vec_;

#if defined(HAVE_LIBPCRE1)
    pcre *ssid_re_;
    pcre_extra *ssid_study_;
#elif defined(HAVE_LIBPCRE2)
    pcre2_code *ssid_re_;
    pcre2_match_data *ssid_match_data_;
#endif
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_ssid_alert_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};


class dot11_11d_tracked_range_info_v2 : public json_adapter_v2::jsonable {
public:
    dot11_11d_tracked_range_info_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_11d_tracked_range_info_v2(const dot11_11d_tracked_range_info_v2& d) {
        startchan_ = d.startchan_;
        numchan_ = d.numchan_;
        txpower_ = d.txpower_;
    }

    dot11_11d_tracked_range_info_v2& operator=(const dot11_11d_tracked_range_info_v2& d) {
        startchan_ = d.startchan_;
        numchan_ = d.numchan_;
        txpower_ = d.txpower_;
        return *this;
    }

    void reset() {
        startchan_ = 0;
        numchan_ = 0;
        txpower_ = 0;
    }

    auto startchan() { return startchan_; }
    void set_startchan(auto start) { startchan_ = start; }

    auto numchan() { return numchan_; }
    void set_numchan(auto num) { numchan_ = num; }

    auto txpower() { return txpower_; }
    void set_txpower(auto pow) { txpower_ = pow; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    uint32_t startchan_;
    uint32_t numchan_;
    int32_t txpower_;
};

template<> struct json_adapter_v2::json_encode<dot11_11d_tracked_range_info_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};


class dot11_tracked_ietag_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_ietag_v2() :
        json_adapter_v2::jsonable() { }

    dot11_tracked_ietag_v2& operator=(const dot11_tracked_ietag_v2& t) {
        unique_tag_id_ = t.unique_tag_id_;
        tag_number_ = t.tag_number_;
        tag_oui_ = t.tag_oui_;
        tag_oui_manuf_ = t.tag_oui_manuf_;
        tag_vendor_ = t.tag_vendor_;
        tag_data_ = t.tag_data_;

        return *this;
    }

    void reset() {
        unique_tag_id_ = 0;
        tag_number_ = 0;
        tag_oui_ = 0;
        tag_oui_manuf_ = {};
        tag_vendor_ = 0;
        tag_data_ = {};
    }

    auto unique_tag_id() { return unique_tag_id_; }
    void set_unique_tag_id(auto id) { unique_tag_id_ = id; }

    auto tag_number() { return tag_number_; }
    void set_tag_number(auto num) { tag_number_ = num; }

    auto tag_oui() { return tag_oui_; }
    void set_tag_oui(auto oui) { tag_oui_ = oui; }

    const auto& tag_oui_manuf() { return tag_oui_manuf_; }
    void set_tag_oui_manuf(const auto& manuf) { tag_oui_manuf_ = manuf; }

    auto tag_vendor() { return tag_vendor_; }
    void set_tag_vendor(auto v) { tag_vendor_ = v; }

    const auto& tag_data() { return tag_data_; }
    void set_tag_data(const auto& d) { tag_data_ = base64::encode(d); }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    uint32_t unique_tag_id_;
    uint8_t tag_number_;
    uint32_t tag_oui_;
    std::string_view tag_oui_manuf_;
    uint16_t tag_vendor_;
    std::string tag_data_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_ietag_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class dot11_probed_ssid_v2 : public json_adapter_v2::jsonable {
public:
    dot11_probed_ssid_v2() :
    json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_probed_ssid_v2() { }

    void reset() {
        ssid_ = {};
        ssid_len_ = 0;

        bssid_ = {};

        first_time_ = 0;
        last_time_ = 0;

        location_ = {};

        dot11r_mobility_ = 0;
        dot11r_mobility_domain_ = 0;

        crypt_set_ = 0;
        crypt_string_ = {};

        wpa_mfp_required_ = 0;
        wpa_mfp_supported_ = 0;

        ie_tag_list_ = {};

        wps_version_ = 0;
        wps_state_ = 0;
        wps_config_methods_ = 0;
        wps_manuf_ = {};
        wps_device_name_ = {};
        wps_model_name_ = {};
        wps_model_number_ = {};
        wps_serial_number_ = {};
        wps_uuid_e_ = {};
    }

    const auto first_time() { return first_time_; }
    void set_first_time(auto time) { first_time_ = time; }
    void set_first_time_ifless(auto time) {
        if (time < first_time_) {
            first_time_ = time;
        }
    }

    const auto last_time() { return last_time_; }
    void set_last_time(auto time) { last_time_ = time; }
    void set_last_time_ifgreater(auto time) {
        if (last_time_ < time) {
            last_time_ = time;
        }
    }

    const auto& ssid() const { return ssid_; }
    void set_ssid(const auto& ssid) { ssid_ = ssid; }

    auto ssid_len() const { return ssid_len_; }
    void set_ssid_len(auto len) { ssid_len_ = len; }

    const auto& bssid() const { return bssid_; }
    void set_bssid(const auto& bssid) { bssid_ = bssid; }

    auto& location() const { return location_; }
    void set_location(const auto& loc) { location_ = loc; }

    auto dot11r_mobility() const { return dot11r_mobility_; }
    void set_dot11r_mobility(auto m) { dot11r_mobility_ = m; }

    auto dot11r_mobility_domain() const { return dot11r_mobility_domain_; }
    void set_dot11r_mobility_domain(auto d) { dot11r_mobility_domain_ = d; }

    auto crypt_set() const { return crypt_set_; }
    void set_crypt_set(auto s) { crypt_set_ = s; }

    const auto& crypt_string() const { return crypt_string_; }
    void set_crypt_string(const auto& c) { crypt_string_ = c; }

    auto wpa_mfp_required() const { return wpa_mfp_required_; }
    void set_wpa_mfp_required(auto r) { wpa_mfp_required_ = r; }

    auto wpa_mfp_supported() const { return wpa_mfp_supported_; }
    void set_wpa_mfp_supported(auto v) { wpa_mfp_supported_ = v; }

    auto& ie_tag_list() { return ie_tag_list_; }
    void set_ie_tag_list(const auto& v) { ie_tag_list_ = v; }

    auto wps_version() const { return wps_version_; }
    void set_wps_version(auto v) { wps_version_ = v; }

    auto wps_state() const { return wps_state_; }
    void set_wps_state(auto v) { wps_state_ = v; }

    auto wps_config_methods() const { return wps_config_methods_; }
    void set_wps_config_methods(auto v) { wps_config_methods_ = v; }

    const auto& wps_manuf() const { return wps_manuf_; }
    void set_wps_manuf(const auto& v) { wps_manuf_ = v; }

    const auto& wps_device_name() const { return wps_device_name_; }
    void set_wps_device_name(const auto& v) { wps_device_name_ = v; }

    const auto& wps_model_name() const { return wps_model_name_; }
    void set_wps_model_name(const auto& v) { wps_model_name_ = v; }

    const auto& wps_uuid_e() const { return wps_uuid_e_; }
    void set_wps_uuid_e(const auto& v) { wps_uuid_e_ = v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    std::string ssid_;
    uint8_t ssid_len_;

    mac_addr bssid_;

    uint64_t first_time_;
    uint64_t last_time_;

    kis_tracked_location_v2 location_;

    uint8_t dot11r_mobility_;
    uint16_t dot11r_mobility_domain_;

    uint64_t crypt_set_;
    std::string crypt_string_;

    uint8_t wpa_mfp_required_;
    uint8_t wpa_mfp_supported_;

    using ie_tag_list_iter_t_ = std::vector<dot11_tracked_ietag_v2>::iterator;
    std::vector<dot11_tracked_ietag_v2> ie_tag_list_;

    uint8_t wps_version_;
    uint32_t wps_state_;
    uint16_t wps_config_methods_;
    std::string wps_manuf_;
    std::string wps_device_name_;
    std::string wps_model_name_;
    std::string wps_model_number_;
    std::string wps_serial_number_;
    std::string wps_uuid_e_;
};

template<> struct json_adapter_v2::json_encode<dot11_probed_ssid_v2> {
     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2& e) {
         e.as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2 *e) {
         e->as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2& e,
             json_adapter_v2::field_group_map& fields) {
         e.filtered_as_json(os, opts, fields);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2 *e,
             json_adapter_v2::field_group_map& fields) {
         e->filtered_as_json(os, opts, fields);
     }
};


class dot11_advertised_ssid_v2 : public json_adapter_v2::jsonable {
public:
    dot11_advertised_ssid_v2() :
    json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_advertised_ssid_v2() { }

    void reset() {

        location_ = {};
        ssid_ = {};
        ssid_len_ = 0;
        ssid_cloaked_ = false;
        ssid_hash_ = 0;
        ssid_crc32_hash_ = 0;

        owe_ssid_ = {};
        owe_ssid_len_ = 0;
        owe_bssid_ = {};

        ssid_beacon_ = false;
        ssid_probe_response_ = false;

        channel_ = {};
        ht_mode_ = {};
        ht_center_1_ = 0;
        ht_center_2_ = 0;
        channel_width_ = 0;

        first_time_ = 0;
        last_time_ = 0;

        beacon_info_ = {};
        crypt_set_ = 0;
        crypt_string_ = {};

        wpa_mfp_required_ = 0;
        wpa_mfp_supported_ = 0;

        maxrate_ = 0;

        beaconrate_ = 0;
        beacons_seen_ = 0;
        beacons_seen_sec_ = 0;

        ie_tag_list_ = {};
        ie_tag_checksum_ = 0;

        dot11d_country_ = {};
        dot11d_vec_ = {};

        wps_version_ = 0;
        wps_state_ = 0;
        wps_config_methods_ = 0;
        wps_manuf_ = {};
        wps_device_name_ = {};
        wps_model_name_ = {};
        wps_model_number_ = {};
        wps_serial_number_ = {};
        wps_uuid_e_ = {};

        dot11r_mobility_ = 0;
        dot11r_mobility_domain_ = 0;

        dot11e_qbss_ = false;
        dot11e_qbss_stations_ = 0;
        dot11e_qbss_load_ = 0;

        ccx_txpower_ = 0;
        cisco_client_mfp_ = false;

        meshid_ = {};
        mesh_gateway_ = false;
        mesh_peerings_ = 0;
        mesh_forwarding_ = 0;

        adv_tx_power_ = 0;
    }

    const auto& ssid() const { return ssid_; }
    void set_ssid(const auto& v) { ssid_ = v; }

    auto ssid_len() const { return ssid_len_; }
    void set_ssid_len(auto v) { ssid_len_ = v; }

    auto ssid_hash() const { return ssid_hash_; }
    void set_ssid_hash(auto v) { ssid_hash_ = v; }

    auto ssid_cloaked() const { return ssid_cloaked_; }
    void set_ssid_cloaked(auto v) { ssid_cloaked_ = v; }

    auto ssid_crc32_hash() const { return ssid_crc32_hash_; }
    void set_ssid_crc32_hash(auto v) { ssid_crc32_hash_ = v; }

    const auto& owe_ssid() const { return owe_ssid_; }
    void set_owe_ssid(const auto& v) { owe_ssid_ = v; }

    auto owe_ssid_len() const { return owe_ssid_len_; }
    void set_owe_ssid_len(auto v) { owe_ssid_len_ = v; }

    const auto& owe_bssid() const { return owe_bssid_; }
    void set_owe_bssid(const auto& v) { owe_bssid_ = v; }

    auto ssid_beacon() const { return ssid_beacon_; }
    void set_ssid_beacon(auto v) { ssid_beacon_ = v; }

    auto ssid_probe_response() const { return ssid_probe_response_; }
    void set_ssid_probe_response(auto v) { ssid_probe_response_ = v; }

    const auto& channel() const { return channel_; }
    void set_channel(const auto& v) { channel_ = v; }

    const auto& ht_mode() const { return ht_mode_; }
    void set_ht_mode(const auto& v) { ht_mode_ = v; }

    auto ht_center_1() const { return ht_center_1_; }
    void set_ht_center_1(auto v) { ht_center_1_ = v; }

    auto ht_center_2() const { return ht_center_2_; }
    void set_ht_center_2(auto v) { ht_center_2_ = v; }

    auto channel_width() const { return channel_width_; }
    void set_channel_width(auto v) { channel_width_ = v; }

    const auto first_time() { return first_time_; }
    void set_first_time(auto time) { first_time_ = time; }
    void set_first_time_ifless(auto time) {
        if (time < first_time_) {
            first_time_ = time;
        }
    }

    const auto last_time() { return last_time_; }
    void set_last_time(auto time) { last_time_ = time; }
    void set_last_time_ifgreater(auto time) {
        if (last_time_ < time) {
            last_time_ = time;
        }
    }

    auto& location() const { return location_; }
    void set_location(const auto& v) { location_ = v; }

    const auto& beacon_info() const { return beacon_info_; }
    void set_beacon_info(const auto& v) { beacon_info_ = v; }

    auto crypt_set() const { return crypt_set_; }
    void set_crypt_set(auto v) { crypt_set_ = v; }

    const auto& crypt_string() const { return crypt_string_; }
    void set_crypt_string(const auto& v) { crypt_string_ = v; }

    auto wpa_mfp_required() const { return wpa_mfp_required_; }
    void set_wpa_mfp_required(auto v) { wpa_mfp_required_ = v; }

    auto wpa_mfp_supported() const { return wpa_mfp_supported_; }
    void set_wpa_mfp_supported(auto v) { wpa_mfp_supported_ = v; }

    auto maxrate() const { return maxrate_; }
    void set_maxrate(auto v) { maxrate_ = v; }

    auto beaconrate() const { return beaconrate_; }
    void set_beaconrate(auto v) { beaconrate_ = v; }

    auto beacons_seen() const { return beacons_seen_; }
    void set_beacons_seen(auto v) { beacons_seen_ = v; }
    void inc_beacons_seen(unsigned int seen, time_t time) {
        if (beacons_seen_sec_ != time) {
            beacons_seen_sec_ = time;
            beacons_seen_ = seen;
        } else {
            beacons_seen_ += seen;
        }
    }

    const auto& ie_tag_list() const { return ie_tag_list_; }
    void set_ie_tag_list(const auto& v) { ie_tag_list_ = v; }

    auto ie_tag_checksum() const { return ie_tag_checksum_; }
    void set_ie_tag_checksum(auto v) { ie_tag_checksum_ = v; }

    const auto& dot11d_country() const { return dot11d_country_; }
    void set_dot11d_country(const auto& v) { dot11d_country_ = v; }

    const auto& dot11d_vec() const { return dot11d_vec_; }
    void set_dot11d_vec(const auto& v) { dot11d_vec_ = v; }

    auto wps_version() const { return wps_version_; }
    void set_wps_version(auto v) { wps_version_ = v; }

    auto wps_state() const { return wps_state_; }
    void set_wps_state(auto v) { wps_state_ = v; }

    auto wps_config_methods() const { return wps_config_methods_; }
    void set_wps_config_methods(auto v) { wps_config_methods_ = v; }

    const auto& wps_manuf() const { return wps_manuf_; }
    void set_wps_manuf(const auto& v) { wps_manuf_ = v; }

    const auto& wps_device_name() const { return wps_device_name_; }
    void set_wps_device_name(const auto& v) { wps_device_name_ = v; }

    const auto& wps_model_name() const { return wps_model_name_; }
    void set_wps_model_name(const auto& v) { wps_model_name_ = v; }

    const auto& wps_uuid_e() const { return wps_uuid_e_; }
    void set_wps_uuid_e(const auto& v) { wps_uuid_e_ = v; }

    auto dot11r_mobility() const { return dot11r_mobility_; }
    void set_dot11r_mobility(auto v) { dot11r_mobility_ = v; }

    auto dot11r_mobility_domain() const { return dot11r_mobility_domain_; }
    void set_dot11r_mobility_domain(auto v) { dot11r_mobility_domain_ = v; }

    auto dot11e_qbss() const { return dot11e_qbss_; }
    void set_dot11e_qbss(auto v) { dot11e_qbss_ = v; }

    auto dot11e_qbss_stations() const { return dot11e_qbss_stations_; }
    void set_dot11e_qbss_stations(auto v) { dot11e_qbss_stations_ = v; }

    auto dot11e_qbss_load() const { return dot11e_qbss_load_; }
    void set_dot11e_qbss_load(auto v) { dot11e_qbss_load_ = v; }

    auto ccx_txpower() const { return ccx_txpower_; }
    void set_ccx_txpower(auto v) { ccx_txpower_ = v; }

    auto cisco_client_mfp() const { return cisco_client_mfp_; }
    void set_cisco_client_mfp(auto v) { cisco_client_mfp_ = v; }

    const auto& meshid() const { return meshid_; }
    void set_meshid(const auto& v) { meshid_ = v; }

    auto mesh_gateway() const { return mesh_gateway_; }
    void set_mesh_gateway(auto v) { mesh_gateway_ = v; }

    auto mesh_peerings() const { return mesh_peerings_; }
    void set_mesh_peerings(auto v) { mesh_peerings_ = v; }

    auto mesh_forwarding() const { return mesh_forwarding_; }
    void set_mesh_forwarding(auto v) { mesh_forwarding_ = v; }

    auto adv_tx_power() const { return adv_tx_power_; }
    void set_adv_tx_power(auto v) { adv_tx_power_ = v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    kis_tracked_location_v2 location_;

    std::string ssid_;
    uint8_t ssid_len_;
    bool ssid_cloaked_;
    uint64_t ssid_hash_;
    uint32_t ssid_crc32_hash_;

    std::string owe_ssid_;
    uint8_t owe_ssid_len_;
    mac_addr owe_bssid_;

    bool ssid_beacon_;
    bool ssid_probe_response_;

    std::string channel_;
    std::string ht_mode_;
    uint64_t ht_center_1_;
    uint64_t ht_center_2_;
    uint64_t channel_width_;

    uint64_t first_time_;
    uint64_t last_time_;

    std::string beacon_info_;

    uint64_t crypt_set_;
    std::string crypt_string_;

    bool wpa_mfp_required_;
    bool wpa_mfp_supported_;

    double maxrate_;

    uint32_t beaconrate_;
    uint32_t beacons_seen_;
    time_t beacons_seen_sec_;

    using ie_tag_list_iter_t_ = std::vector<dot11_tracked_ietag_v2>::iterator;
    std::vector<dot11_tracked_ietag_v2> ie_tag_list_;
    uint32_t ie_tag_checksum_;

    std::string dot11d_country_;
    using dot11d_vector_iter_t_ = std::vector<dot11_11d_tracked_range_info_v2>::iterator;
    std::vector<dot11_11d_tracked_range_info_v2> dot11d_vec_;

    uint8_t wps_version_;
    uint32_t wps_state_;
    uint16_t wps_config_methods_;
    std::string wps_manuf_;
    std::string wps_device_name_;
    std::string wps_model_name_;
    std::string wps_model_number_;
    std::string wps_serial_number_;
    std::string wps_uuid_e_;

    bool dot11r_mobility_;
    uint16_t dot11r_mobility_domain_;

    bool dot11e_qbss_;
    uint16_t dot11e_qbss_stations_;
    double dot11e_qbss_load_;

    uint8_t ccx_txpower_;
    bool cisco_client_mfp_;

    std::string meshid_;
    bool mesh_gateway_;
    uint8_t mesh_peerings_;
    bool mesh_forwarding_;

    uint8_t adv_tx_power_;
};

template<> struct json_adapter_v2::json_encode<dot11_advertised_ssid_v2> {
     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2& e) {
         e.as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2 *e) {
         e->as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2& e,
             json_adapter_v2::field_group_map& fields) {
         e.filtered_as_json(os, opts, fields);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2 *e,
             json_adapter_v2::field_group_map& fields) {
         e->filtered_as_json(os, opts, fields);
     }
};

class dot11_client_v2 : public json_adapter_v2::jsonable {
public:
    dot11_client_v2() :
    json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_client_v2() { }

    void reset() {
        client_type_ = 0;

        location_ = {};

        bssid_ = {};
        bssid_key_ = {};

        first_time_ = 0;
        last_time_ = 0;

        dhcp_host_ = {};
        dhcp_vendor_ = {};

        eap_identity_ = {};

        cdp_device_ = {};
        cdp_port_ = {};

        decrypted_ = false;

        datasize_ = 0;
        datasize_retry_ = 0;
        num_fragments_ = 0;
        num_retries_ = 0;
    }

    auto client_type() const { return client_type_; }
    void set_client_type(auto v) { client_type_ = v; }

    auto& location() const { return location_; }
    void set_location(const auto& v) { location_ = v; }

    const auto& bssid() const { return bssid_; }
    void set_bssid(const auto& v) { bssid_ = v; }

    const auto& bssid_key() const { return bssid_key_; }
    void set_bssid_key(const auto& v) { bssid_key_ = v; }

    const auto first_time() { return first_time_; }
    void set_first_time(auto time) { first_time_ = time; }
    void set_first_time_ifless(auto time) {
        if (time < first_time_) {
            first_time_ = time;
        }
    }

    const auto last_time() { return last_time_; }
    void set_last_time(auto time) { last_time_ = time; }
    void set_last_time_ifgreater(auto time) {
        if (last_time_ < time) {
            last_time_ = time;
        }
    }

    const auto& dhcp_host() const { return dhcp_host_; }
    void set_dhcp_host(const auto& v) { dhcp_host_ = v; }

    const auto& dhcp_vendor() const { return dhcp_vendor_; }
    void set_dhcp_vendor(const auto& v) { dhcp_vendor_ = v; }

    const auto& eap_identity() const { return eap_identity_; }
    void set_eap_identity(const auto& v) { eap_identity_ = v; }

    const auto& cdp_device() const { return cdp_device_; }
    void set_cdp_device(const auto& v) { cdp_device_ = v; }

    const auto& cdp_port() const { return cdp_port_; }
    void set_cdp_port(const auto& v) { cdp_port_ = v; }

    auto& ip_v4() const { return ip_v4_; }
    void set_ip_v4(const auto& v) { ip_v4_ = v; }

    constexpr auto decrypted() const { return decrypted_; }
    void set_decrypted(auto v) { decrypted_ = v; }

    constexpr auto datasize() const { return datasize_; }
    void set_datasize(auto v) { datasize_ = v; }
    void inc_datasize(auto v) { datasize_ += v; }

    constexpr auto datasize_retry() const { return datasize_retry_; }
    void set_datasize_retry(auto v) { datasize_retry_ = v; }
    void inc_datasize_retry(auto v) { datasize_retry_ += v; }

    constexpr auto num_fragments() const { return num_fragments_; }
    void set_num_fragments(auto v) { num_fragments_ = v; }
    void inc_num_fragments(auto v) { num_fragments_ += v; }

    constexpr auto num_retries() const { return num_retries_; }
    void set_num_retries(auto v) { num_retries_ = v; }
    void inc_num_retries(auto v) { num_retries_ += v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    uint32_t client_type_;

    kis_tracked_location_v2 location_;

    mac_addr bssid_;
    device_key_v2 bssid_key_;

    uint64_t first_time_;
    uint64_t last_time_;

    std::string dhcp_host_;
    std::string dhcp_vendor_;

    std::string eap_identity_;

    std::string cdp_device_;
    std::string cdp_port_;

    kis_tracked_ip_v4_data_v2 ip_v4_;

    bool decrypted_;

    uint64_t datasize_;
    uint64_t datasize_retry_;
    uint64_t num_fragments_;
    uint64_t num_retries_;
};

template<> struct json_adapter_v2::json_encode<dot11_client_v2> {
     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_client_v2& e) {
         e.as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_client_v2 *e) {
         e->as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_client_v2& e,
             json_adapter_v2::field_group_map& fields) {
         e.filtered_as_json(os, opts, fields);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_client_v2 *e,
             json_adapter_v2::field_group_map& fields) {
         e->filtered_as_json(os, opts, fields);
     }
};


class dot11_tracked_device_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_device_v2() :
    json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_tracked_device_v2() { }

    void reset() {
        snapshot_next_beacon_ = false;

        type_set_ = 0;

        client_map_ = {};

        advertised_ssid_map_ = {};
        responded_ssid_map_ = {};
        probed_ssid_map_ = {};

        associated_client_map_ = {};

        client_disconnects_ = 0;
        client_disconnect_last_time_ = 0;

        bss_timestamp_ = 0;

        num_fragments_ = 0;
        num_retries_ = 0;

        datasize_ = 0;
        datasize_retry_ = 0;

        last_bssid_ = {};

        last_beacon_time_ = 0;

        wpa_m3_count_ = 0;
        wpa_m3_last_time_ = 0;

        wpa_key_map_ = {};
        wpa_nonce_vec_ = {};
        wpa_anonce_vec_ = {};

        beacon_packet_ = {};
        pmkid_packet_ = {};

        last_adv_ie_checksum_ = 0;
        last_advertised_ssid_ = nullptr;
        last_probed_ssid_ = nullptr;

        min_tx_power_ = 0;
        max_tx_power_ = 0;

        supported_channels_vec_ = {};

        link_measurement_capable_ = false;
        neighbor_report_capable_ = false;

        extended_capabilities_vec_ = {};

        beacon_fingerprint_ = 0;
        probe_fingerprint_ = 0;
        response_fingerprint_ = 0;
    }

    constexpr auto type_set() const { return type_set_; }
    void set_type_set(auto v) { type_set_ = v; }

    constexpr auto snapshot_next_beacon() const { return snapshot_next_beacon_; }
    void set_snapshot_next_beacon(auto v) { snapshot_next_beacon_ = v; }

    auto& client_map() const { return client_map_; }
    void set_client_map(auto& v) { client_map_ = v; }

    auto& advertised_ssid_map() const { return advertised_ssid_map_; }
    void set_advertised_ssid_map(auto& v) { advertised_ssid_map_ = v; }

    auto& responded_ssid_map() const { return responded_ssid_map_; }
    void set_responded_ssid_map(auto& v) { responded_ssid_map_ = v; }

    auto& probed_ssid_map() const { return probed_ssid_map_; }
    void set_probed_ssid_map(auto& v) { probed_ssid_map_ = v; }

    auto& associated_client_map() const { return associated_client_map_; }
    void set_associated_client_map(auto& v) { associated_client_map_ = v; }

    constexpr auto client_disconnects() const { return client_disconnects_; }
    void set_client_disconnects(auto v) { client_disconnects_ = v; }
    void inc_client_disconnects(unsigned int d, time_t time) {
        if (client_disconnect_last_time_ != time) {
            client_disconnect_last_time_ = time;
            client_disconnects_ = d;
        } else {
            client_disconnects_ += d;
        }
    }

    constexpr auto bss_timestamp() const { return bss_timestamp_; }
    void set_bss_timestamp(auto v) { bss_timestamp_ = v; }

    constexpr auto num_fragments() const { return num_fragments_; }
    void set_num_fragments(auto v) { num_fragments_ = v; }
    void inc_num_fragments(auto v) { num_fragments_ += v; }

    constexpr auto num_retries() const { return num_retries_; }
    void set_num_retries(auto v) { num_retries_ = v; }
    void inc_num_retries(auto r) { num_retries_ += r; }

    constexpr auto datasize() const { return datasize_; }
    void set_datasize(auto v) { datasize_ = v; }
    void inc_datasize(auto v) { datasize_ += v; }

    constexpr auto datasize_retry() const { return datasize_retry_; }
    void set_datasize_retry(auto v) { datasize_retry_ = v; }
    void inc_datasize_retry(auto v) { datasize_retry_ += v; }

    constexpr auto last_bssid() const { return last_bssid_; }
    void set_last_bssid(auto v) { last_bssid_ = v; }

    constexpr auto last_beacon_time() const { return last_beacon_time_; }
    void set_last_beacon_time(auto v) { last_beacon_time_ = v; }

    constexpr auto wpa_m3_count() const { return wpa_m3_count_; }
    void set_wpa_m3_count(auto v) { wpa_m3_count_ = v; }
    void inc_wpa_m3_count(unsigned int d, time_t time) {
        if (wpa_m3_last_time_ != time) {
            wpa_m3_last_time_ = time;
            wpa_m3_count_ = d;
        } else {
            wpa_m3_count_ += d;
        }
    }

	constexpr auto csa_count() const { return csa_count_; }
	void set_csa_count(auto v) { csa_count_ = v; }
	void inc_csa_count(unsigned int d, time_t time, unsigned int time_window) {
		if (time - csa_last_time_ <= time_window) {
			csa_count_ += d;
		} else {
			csa_last_time_ = time;
			csa_count_ = d;
		}
	}

    auto& wpa_key_map() const { return wpa_key_map_; }
    void set_wpa_key_map(auto& v) { wpa_key_map_ = v; }

    auto& wpa_nonce_vec() const { return wpa_nonce_vec_; }
    void set_wpa_nonce_vec(auto& v) { wpa_nonce_vec_ = v; }

    auto& wpa_anonce_vec() const { return wpa_nonce_vec_; }
    void set_wpa_anonce_vec(auto& v) { wpa_nonce_vec_ = v; }

    auto& beacon_packet() const { return beacon_packet_; }
    void set_beacon_packet(auto& v) { beacon_packet_ = v; }

    auto& pmkid_packet() const { return pmkid_packet_; }
    void set_pmkid_packet(auto& v) { pmkid_packet_ = v; }

    constexpr auto last_adv_ie_checksum() const { return last_adv_ie_checksum_; }
    void set_last_adv_ie_checksum(auto v) { last_adv_ie_checksum_ = v; }

    auto last_advertised_ssid() const { return last_advertised_ssid_; }
    void set_last_advertised_ssid(auto v) { last_advertised_ssid_ = v; }

    auto last_probed_ssid() const { return last_probed_ssid_; }
    void set_last_probed_ssid(auto v) { last_probed_ssid_ = v; }

    constexpr auto min_tx_power() const { return min_tx_power_; }
    void set_min_tx_power(auto v) { min_tx_power_ = v; }

    constexpr auto max_tx_power() const { return max_tx_power_; }
    void set_max_tx_power(auto v) { max_tx_power_ = v; }

    auto& supported_channels_vec() const { return supported_channels_vec_; }
    void set_supported_channels_vec(auto& v) { supported_channels_vec_ = v; }

    constexpr auto link_measurement_capable() const { return link_measurement_capable_; }
    void set_link_measurement_capable(auto v) { link_measurement_capable_ = v; }

    constexpr auto neighbor_report_capable() const { return neighbor_report_capable_; }
    void set_neighbor_report_capable(auto v) { neighbor_report_capable_ = v; }

    auto& extended_capabilities_vec() const { return extended_capabilities_vec_; }
    void set_extended_capabilities_vec(auto& v) { extended_capabilities_vec_ = v; }

    constexpr auto beacon_fingerprint() const { return beacon_fingerprint_; }
    void set_beacon_fingerprint(auto v) { beacon_fingerprint_ = v; }

    constexpr auto probe_fingerprint() const { return probe_fingerprint_; }
    void set_probe_fingerprint(auto v) { probe_fingerprint_ = v; }

    constexpr auto response_fingerprint() const { return response_fingerprint_; }
    void set_response_fingerprint(auto v) { response_fingerprint_ = v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    // do we need to snapshot the next beacon so we can record it for eapol or pmkid?
    bool snapshot_next_beacon_;

    uint64_t type_set_;

    // client state of what this device is associated to
    using client_map_iter_t_ = std::unordered_map<mac_addr, dot11_client_v2>::iterator;
    std::unordered_map<mac_addr, dot11_client_v2> client_map_;

    // advertised SSIDs indexed by SSID hash
    using advertised_ssid_map_iter_t_ = std::unordered_map<size_t, dot11_advertised_ssid_v2>::iterator;
    std::unordered_map<size_t, dot11_advertised_ssid_v2> advertised_ssid_map_;

    // responded SSIDs indexed by SSID hash
    using responded_ssid_map_iter_t_ = advertised_ssid_map_iter_t_;
    std::unordered_map<size_t, dot11_advertised_ssid_v2> responded_ssid_map_;

    // probed SSIDs indexed by hash
    using probed_ssid_map_iter_t_ = std::unordered_map<size_t, dot11_probed_ssid_v2>::iterator;
    std::unordered_map<size_t, dot11_probed_ssid_v2> probed_ssid_map_;

    // clients associated to this device, if this is an AP
    using associated_client_map_iter_t_ = std::unordered_map<mac_addr, device_key_v2>::iterator;
    std::unordered_map<mac_addr, device_key_v2> associated_client_map_;

    // client disconnects in the past second
    uint64_t client_disconnects_;
    time_t client_disconnect_last_time_;

    uint64_t bss_timestamp_;

    uint64_t num_fragments_;
    uint64_t num_retries_;

    uint64_t datasize_;
    uint64_t datasize_retry_;

    // last BSSID this device was connected to, if a client
    mac_addr last_bssid_;

    // time of last beacon, if an AP
    uint64_t last_beacon_time_;

    // wpa m3 messages in the past second
    uint64_t wpa_m3_count_;
    time_t wpa_m3_last_time_;

    using wpa_key_map_iter_t_ = std::unordered_map<mac_addr, dot11_tracked_eapol_v2>::iterator;
    std::unordered_map<mac_addr, dot11_tracked_eapol_v2> wpa_key_map_;

    using wpa_nonce_vec_iter_t_ = std::vector<dot11_tracked_nonce_v2>::iterator;
    std::vector<dot11_tracked_nonce_v2> wpa_nonce_vec_;

    using wpa_anonce_vec_iter_t_ = wpa_nonce_vec_iter_t_;
    std::vector<dot11_tracked_nonce_v2> wpa_anonce_vec_;

    kis_tracked_packet_v2 beacon_packet_;

    kis_tracked_packet_v2 pmkid_packet_;

    uint32_t last_adv_ie_checksum_;
    dot11_advertised_ssid_v2 *last_advertised_ssid_;

    dot11_probed_ssid_v2 *last_probed_ssid_;

    uint8_t min_tx_power_;
    uint8_t max_tx_power_;

    using supported_channels_vec_iter_t_ = std::vector<double>::iterator;
    std::vector<double> supported_channels_vec_;

    bool link_measurement_capable_;
    bool neighbor_report_capable_;

    using extended_capabilities_vec_iter_t_ = std::vector<std::string>::iterator;
    std::vector<std::string> extended_capabilities_vec_;

    uint32_t beacon_fingerprint_;
    uint32_t probe_fingerprint_;
    uint32_t response_fingerprint_;

	uint64_t csa_count_;
	time_t csa_last_time_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_device_v2> {
     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_device_v2& e) {
         e.as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_device_v2 *e) {
         e->as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_device_v2& e,
             json_adapter_v2::field_group_map& fields) {
         e.filtered_as_json(os, opts, fields);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_device_v2 *e,
             json_adapter_v2::field_group_map& fields) {
         e->filtered_as_json(os, opts, fields);
     }
};

#endif /* __PHY_80211_COMPONENTS_V2__ */
