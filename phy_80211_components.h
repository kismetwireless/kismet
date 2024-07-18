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

#ifndef __PHY_80211_COMPONENTS_H__
#define __PHY_80211_COMPONENTS_H__

#include "config.h"

#include <time.h>

#include <algorithm>
#include <list>
#include <map>
#include <string>
#include <utility>
#include <vector>

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "devicetracker_component.h"
#include "entrytracker.h"
#include "globalregistry.h"
#include "trackedcomponent.h"

#include "dot11_parsers/dot11_ie.h"
#include "dot11_parsers/dot11_ie_221_vendor.h"
#include "dot11_parsers/dot11_ie_255_ext_tag.h"

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

    dot11_tracked_eapol(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    dot11_tracked_eapol(const dot11_tracked_eapol *p) :
        tracker_component{p} {

            __ImportField(eapol_time, p);
            __ImportField(eapol_dir, p);
            __ImportField(eapol_replay_counter, p);
            __ImportField(eapol_msg_num, p);
            __ImportField(eapol_install, p);
            __ImportField(eapol_nonce, p);
            __ImportField(eapol_rsn_pmkid, p);

            __ImportField(eapol_packet, p);
            __ImportId(eapol_packet_id, p);

            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_eapol");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(eapol_time, double, double, double, eapol_time);
    __Proxy(eapol_dir, uint8_t, uint8_t, uint8_t, eapol_dir);
    __Proxy(eapol_replay_counter, uint64_t, uint64_t, uint64_t, eapol_replay_counter);
    __Proxy(eapol_msg_num, uint8_t, uint8_t, uint8_t, eapol_msg_num);
    __Proxy(eapol_install, uint8_t, bool, bool, eapol_install);

    __ProxyTrackable(eapol_nonce, tracker_element_byte_array, eapol_nonce);
    void set_eapol_nonce_bytes(const std::string& in_n) { eapol_nonce->set(in_n); }
    std::string get_eapol_nonce_bytes() { return eapol_nonce->get(); }

    __ProxyTrackable(eapol_rsn_pmkid, tracker_element_byte_array, eapol_rsn_pmkid);
    void set_rsnpmkid_bytes(const std::string& in_n) { eapol_rsn_pmkid->set(in_n); }
    std::string get_rsnpmkid_bytes() { return eapol_rsn_pmkid->get(); }

    __ProxyTrackable(eapol_packet, kis_tracked_packet, eapol_packet);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_double> eapol_time;
    std::shared_ptr<tracker_element_uint8> eapol_dir;
    std::shared_ptr<tracker_element_uint64> eapol_replay_counter;
    std::shared_ptr<tracker_element_uint8> eapol_msg_num;
    std::shared_ptr<tracker_element_uint8> eapol_install;
    std::shared_ptr<tracker_element_byte_array> eapol_nonce;
    std::shared_ptr<tracker_element_byte_array> eapol_rsn_pmkid;

    std::shared_ptr<kis_tracked_packet> eapol_packet;
    uint16_t eapol_packet_id;
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

    dot11_tracked_nonce(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    dot11_tracked_nonce(const dot11_tracked_nonce *p) :
        tracker_component{p} {
            __ImportField(eapol_time, p);
            __ImportField(eapol_msg_num, p);
            __ImportField(eapol_install, p);
            __ImportField(eapol_nonce, p);
            __ImportField(eapol_replay_counter, p);
            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_nonce");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
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

    void set_from_eapol(shared_tracker_element in_tracked_eapol);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_double> eapol_time;
    std::shared_ptr<tracker_element_uint8> eapol_msg_num;
    std::shared_ptr<tracker_element_uint8> eapol_install;
    std::shared_ptr<tracker_element_byte_array> eapol_nonce;
    std::shared_ptr<tracker_element_uint64> eapol_replay_counter;
};

class dot11_tracked_ssid_alert : public tracker_component {
public:
    dot11_tracked_ssid_alert() :
        tracker_component() {
#if defined(HAVE_LIBPCRE1)
        ssid_re = NULL;
        ssid_study = NULL;
#elif defined(HAVE_LIBPCRE2)
        ssid_re = NULL;
        ssid_match_data = NULL;
#endif

        register_fields();
        reserve_fields(NULL);
    };

    dot11_tracked_ssid_alert(int in_id) :
        tracker_component(in_id) {

#if defined(HAVE_LIBPCRE1)
            ssid_re = NULL;
            ssid_study = NULL;
#elif defined(HAVE_LIBPCRE2)
            ssid_re = NULL;
            ssid_match_data = NULL;
#endif

            register_fields();
            reserve_fields(NULL);
        }

    dot11_tracked_ssid_alert(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
#if defined(HAVE_LIBPCRE1)
        ssid_re = NULL;
        ssid_study = NULL;
#elif defined(HAVE_LIBPCRE2)
        ssid_re = NULL;
        ssid_match_data = NULL;
#endif

        register_fields();
        reserve_fields(e);
    }

    virtual ~dot11_tracked_ssid_alert() {
#if defined(HAVE_LIBPCRE1)
        if (ssid_re != NULL)
            pcre_free(ssid_re);
        if (ssid_study != NULL)
            pcre_free(ssid_study);
#elif defined(HAVE_LIBPCRE2)
        if (ssid_match_data != NULL)
            pcre2_match_data_free(ssid_match_data);
        if (ssid_re != NULL)
            pcre2_code_free(ssid_re);
#endif
    }

    dot11_tracked_ssid_alert(const dot11_tracked_ssid_alert *p) :
        tracker_component{p} {
#if defined(HAVE_LIBPCRE1)
            ssid_re = NULL;
            ssid_study = NULL;
#elif defined(HAVE_LIBPCRE2)
            ssid_re = NULL;
            ssid_match_data = NULL;
#endif
            __ImportField(ssid_group_name, p);
            __ImportField(ssid_regex, p);
            __ImportField(allowed_macs_vec, p);
            __ImportId(allowed_mac_id, p);

            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_ssid_alert");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(group_name, std::string, std::string, std::string, ssid_group_name);

    // Control the regex.  MAY THROW std::runtime_error if the regex is invalid
    __ProxyGet(regex, std::string, std::string, ssid_regex);
    void set_regex(std::string s);

    __ProxyTrackable(allowed_macs_vec, tracker_element_vector, allowed_macs_vec);

    void set_allowed_macs(std::vector<mac_addr> mvec);

    bool compare_ssid(const std::string& ssid, mac_addr mac);

protected:
    kis_mutex ssid_mutex;

    virtual void register_fields() override;

    std::shared_ptr<tracker_element_string> ssid_group_name;
    std::shared_ptr<tracker_element_string> ssid_regex;
    std::shared_ptr<tracker_element_vector> allowed_macs_vec;
    uint16_t allowed_mac_id;

#if defined(HAVE_LIBPCRE1)
    pcre *ssid_re;
    pcre_extra *ssid_study;
#elif defined(HAVE_LIBPCRE2)
    pcre2_code *ssid_re;
    pcre2_match_data *ssid_match_data;
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

    dot11_11d_tracked_range_info(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    dot11_11d_tracked_range_info(const dot11_11d_tracked_range_info *p) :
        tracker_component{p} {

            __ImportField(startchan, p);
            __ImportField(numchan, p);
            __ImportField(txpower, p);

            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_11d_tracked_range_info");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(startchan, uint32_t, uint32_t, uint32_t, startchan);
    __Proxy(numchan, uint32_t, unsigned int, unsigned int, numchan);
    __Proxy(txpower, int32_t, int, int, txpower);

protected:
    virtual void register_fields() override {
        register_field("dot11.11d.start_channel", "Starting channel of 11d range", &startchan);
        register_field("dot11.11d.num_channels", "Number of channels covered by range", &numchan);
        register_field("dot11.11d.tx_power", "Maximum allowed transmit power", &txpower);
    }

    std::shared_ptr<tracker_element_uint32> startchan;
    std::shared_ptr<tracker_element_uint32> numchan;
    std::shared_ptr<tracker_element_int32> txpower;
};

class dot11_tracked_ietag : public tracker_component {
public:
    dot11_tracked_ietag() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_ietag(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_ietag(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    dot11_tracked_ietag(const dot11_tracked_ietag *p) :
        tracker_component{p} {
        __ImportField(unique_tag_id, p);
        __ImportField(tag_number, p);
        __ImportField(tag_oui, p);
        __ImportField(tag_oui_manuf, p);
        __ImportField(tag_vendor_or_sub, p);
        __ImportField(complete_tag_data, p);

        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_ietag");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(unique_tag_id, uint32_t, uint32_t, uint32_t, unique_tag_id);
    __Proxy(tag_number, uint8_t, uint8_t, uint8_t, tag_number);
    __Proxy(tag_oui, uint32_t, uint32_t, uint32_t, tag_oui);
    __Proxy(tag_oui_manuf, std::string, std::string, std::string, tag_oui_manuf);
    __Proxy(tag_vendor_or_sub, int16_t, int16_t, int16_t, tag_vendor_or_sub);
    __Proxy(complete_tag_data, std::string, std::string, std::string, complete_tag_data);

    void set_from_tag(std::shared_ptr<dot11_ie::dot11_ie_tag> ie);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_uint32> unique_tag_id;
    std::shared_ptr<tracker_element_uint8> tag_number;
    std::shared_ptr<tracker_element_uint32> tag_oui;
    std::shared_ptr<tracker_element_string> tag_oui_manuf;
    std::shared_ptr<tracker_element_int16> tag_vendor_or_sub;
    std::shared_ptr<tracker_element_byte_array> complete_tag_data;
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

    dot11_probed_ssid(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    dot11_probed_ssid(const dot11_probed_ssid *p) :
        tracker_component{p} {
            __ImportField(ssid, p);
            __ImportField(ssid_len, p);
            __ImportField(bssid, p);
            __ImportField(first_time, p);
            __ImportField(last_time, p);

            __ImportId(dot11r_mobility_id, p);
            __ImportId(dot11r_mobility_domain_id_id, p);

            __ImportId(location_id, p);

            __ImportField(crypt_set, p);
            __ImportField(crypt_set_old, p);
            __ImportField(crypt_string, p);
            __ImportField(wpa_mfp_required, p);
            __ImportField(wpa_mfp_supported, p);

            __ImportId(ie_tag_list_id, p);

            __ImportId(wps_version_id, p);
            __ImportId(wps_state_id, p);
            __ImportId(wps_config_methods_id, p);
            __ImportId(wps_manuf_id, p);
            __ImportId(wps_device_name_id, p);
            __ImportId(wps_model_name_id, p);
            __ImportId(wps_model_number_id, p);
            __ImportId(wps_serial_number_id, p);
            __ImportId(wps_uuid_e_id, p);

            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_probed_ssid");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    const std::string get_ssid() const {
        if (ssid->get() == nullptr)
            return "";

        return std::string(*(ssid->get()));
    }
  
    void set_ssid(const std::string& string) {
        ssid->set(Globalreg::cache_string(string));
    }

    void set_ssid(const char *string) {
        ssid->set(Globalreg::cache_string(string));
    }

    __Proxy(ssid_len, uint32_t, unsigned int, unsigned int, ssid_len);
    __Proxy(bssid, mac_addr, mac_addr, mac_addr, bssid);
    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __ProxySetIfLess(first_time, uint64_t, uint64_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __ProxySetIfLess(last_time, uint64_t, uint64_t, last_time);

    __ProxyFullyDynamicTrackable(location, kis_tracked_location, location_id);

    __ProxyFullyDynamic(dot11r_mobility, uint8_t, bool, bool, tracker_element_uint8, dot11r_mobility_id);
    __ProxyFullyDynamic(dot11r_mobility_domain_id, uint16_t, uint16_t, uint16_t, tracker_element_uint16, 
                        dot11r_mobility_domain_id_id);

    __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, crypt_set);
    __Proxy(crypt_set_old, uint64_t, uint64_t, uint64_t, crypt_set_old);
	
    const std::string get_crypt_string() const {
        if (crypt_string->get() == nullptr)
            return "";

        return std::string(*(crypt_string->get()));
    }
  
    void set_crypt_string(const std::string& string) {
        crypt_string->set(Globalreg::cache_string(string));
    }

    void set_crypt_string(const char *string) {
        crypt_string->set(Globalreg::cache_string(string));
    }

    __Proxy(wpa_mfp_required, uint8_t, bool, bool, wpa_mfp_required);
    __Proxy(wpa_mfp_supported, uint8_t, bool, bool, wpa_mfp_supported);

    __ProxyFullyDynamicTrackable(ie_tag_list, tracker_element_vector_double, ie_tag_list_id);

    __ProxyFullyDynamic(wps_version, uint8_t, uint8_t, uint8_t, tracker_element_uint8, wps_version_id);
    __ProxyFullyDynamic(wps_state, uint32_t, uint32_t, uint32_t, tracker_element_uint32, wps_state_id);
    __ProxyFullyDynamic(wps_config_methods, uint16_t, uint16_t, uint16_t, tracker_element_uint16, wps_config_methods_id);
    __ProxyFullyDynamic(wps_manuf, std::string, std::string, std::string, tracker_element_string, wps_manuf_id);
    __ProxyFullyDynamic(wps_device_name, std::string, std::string, std::string, tracker_element_string, wps_device_name_id);
    __ProxyFullyDynamic(wps_model_name, std::string, std::string, std::string, tracker_element_string, wps_model_name_id);
    __ProxyFullyDynamic(wps_model_number, std::string, std::string, std::string, tracker_element_string, wps_model_number_id);
    __ProxyFullyDynamic(wps_serial_number, std::string, std::string, std::string, tracker_element_string, wps_serial_number_id);
    __ProxyFullyDynamic(wps_uuid_e, std::string, std::string, std::string, tracker_element_byte_array, wps_uuid_e_id);

protected:
    virtual void register_fields() override;

    std::shared_ptr<tracker_element_string_ptr> ssid;

    std::shared_ptr<tracker_element_uint32> ssid_len;
    std::shared_ptr<tracker_element_mac_addr> bssid;
    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;

    uint16_t dot11r_mobility_id;
    uint16_t dot11r_mobility_domain_id_id;

    uint16_t location_id;

    std::shared_ptr<tracker_element_uint64> crypt_set_old;
    std::shared_ptr<tracker_element_uint64> crypt_set;
    
    std::shared_ptr<tracker_element_string_ptr> crypt_string;

    std::shared_ptr<tracker_element_uint8> wpa_mfp_required;
    std::shared_ptr<tracker_element_uint8> wpa_mfp_supported;

    uint16_t ie_tag_list_id;

    // WPS components
    uint16_t wps_version_id;
    uint16_t wps_state_id;
    uint16_t wps_config_methods_id;
    uint16_t wps_manuf_id;
    uint16_t wps_device_name_id;
    uint16_t wps_model_name_id;
    uint16_t wps_model_number_id;
    uint16_t wps_serial_number_id;
    uint16_t wps_uuid_e_id;
};

/* Advertised SSID
 *
 * SSID advertised by a device via beacon or probe response
 */
class dot11_packinfo_dot11d_entry;

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

    dot11_advertised_ssid(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    dot11_advertised_ssid(const dot11_advertised_ssid *p) :
        tracker_component{p} {
            __ImportField(ssid, p);
            __ImportField(ssid_len, p);

            __ImportField(ssid_hash, p);

            __ImportId(owe_ssid_id, p);
            __ImportId(owe_ssid_len_id, p);
            __ImportId(owe_bssid_id, p);

            __ImportField(ssid_beacon, p);
            __ImportField(ssid_probe_response, p);

            __ImportField(channel, p);
            __ImportField(ht_mode, p);
            __ImportField(ht_center_1, p);
            __ImportField(ht_center_2, p);

            __ImportField(first_time, p);
            __ImportField(last_time, p);

            __ImportId(beacon_info_id, p);

            __ImportField(ssid_cloaked, p);
            __ImportField(crypt_set, p);
            __ImportField(crypt_set_old, p);
            __ImportField(crypt_string, p);
            __ImportField(wpa_mfp_required, p);
            __ImportField(wpa_mfp_supported, p);
            __ImportField(maxrate, p);
            __ImportField(beaconrate, p);
            __ImportField(beacons_sec, p);
            __ImportField(ietag_checksum, p);

            __ImportId(dot11d_country_id, p);
            __ImportId(dot11d_vec_id, p);
            __ImportId(dot11d_country_entry_id, p);

            __ImportId(wps_version_id, p);
            __ImportId(wps_state_id, p);
            __ImportId(wps_config_methods_id, p);
            __ImportId(wps_manuf_id, p);
            __ImportId(wps_device_name_id, p);
            __ImportId(wps_model_name_id, p);
            __ImportId(wps_model_number_id, p);
            __ImportId(wps_serial_number_id, p);
            __ImportId(wps_uuid_e_id, p);

            __ImportId(location_id, p);

            __ImportField(dot11r_mobility, p);
            __ImportField(dot11r_mobility_domain_id, p);

            __ImportField(dot11e_qbss, p);
            __ImportField(dot11e_qbss_stations, p);
            __ImportField(dot11e_qbss_channel_load, p);

            __ImportField(ccx_txpower, p);
            __ImportField(cisco_client_mfp, p);

            __ImportField(ie_tag_builder, p);
            __ImportId(ie_tag_list_id, p);
            __ImportId(ie_tag_content_id, p);
            __ImportId(ie_tag_content_element_id, p);


            __ImportId(meshid_id, p);
            __ImportId(mesh_gateway_id, p);
            __ImportId(mesh_peerings_id, p);
            __ImportId(mesh_forwarding_id, p);

            __ImportField(adv_tx_power, p);

            reserve_fields(nullptr);
        }
        

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_advertised_ssid");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }


    const std::string get_ssid() const {
        if (ssid->get() == nullptr)
            return "";

        return std::string(*(ssid->get()));
    }
  
    void set_ssid(const std::string& string) {
        ssid->set(Globalreg::cache_string(string));
    }

    void set_ssid(const char *string) {
        ssid->set(Globalreg::cache_string(string));
    }

    __Proxy(ssid_len, uint32_t, unsigned int, unsigned int, ssid_len);

    __Proxy(ssid_hash, uint64_t, uint64_t, uint64_t, ssid_hash);

    __ProxyFullyDynamic(owe_ssid, std::string, std::string, std::string, tracker_element_string, owe_ssid_id);
    __ProxyFullyDynamic(owe_ssid_len, uint32_t, unsigned int, unsigned int, tracker_element_uint8, owe_ssid_len_id);
    __ProxyFullyDynamic(owe_bssid, mac_addr, mac_addr, mac_addr, tracker_element_mac_addr, owe_bssid_id);

    __Proxy(ssid_beacon, uint8_t, bool, bool, ssid_beacon);
    __Proxy(ssid_probe_response, uint8_t, bool, bool, ssid_probe_response);

    __Proxy(channel, std::string, std::string, std::string, channel);
    __Proxy(ht_mode, std::string, std::string, std::string, ht_mode);
    __Proxy(ht_center_1, uint64_t, uint64_t, uint64_t, ht_center_1);
    __Proxy(ht_center_2, uint64_t, uint64_t, uint64_t, ht_center_2);

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __ProxySetIfLess(first_time, uint64_t, uint64_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __ProxySetIfLess(last_time, uint64_t, uint64_t, last_time);

    __ProxyFullyDynamic(beacon_info, std::string, std::string, std::string, tracker_element_string, beacon_info_id);

    __Proxy(ssid_cloaked, uint8_t, bool, bool, ssid_cloaked);

    __Proxy(crypt_set, uint64_t, uint64_t, uint64_t, crypt_set);
    __Proxy(crypt_set_old, uint64_t, uint64_t, uint64_t, crypt_set_old);

    const std::string get_crypt_string() const {
        if (crypt_string->get() == nullptr)
            return "";

        return std::string(*(crypt_string->get()));
    }
  
    void set_crypt_string(const std::string& string) {
        crypt_string->set(Globalreg::cache_string(string));
    }

    void set_crypt_string(const char *string) {
        crypt_string->set(Globalreg::cache_string(string));
    }

    // WPA MFP
    __Proxy(wpa_mfp_required, uint8_t, bool, bool, wpa_mfp_required);
    __Proxy(wpa_mfp_supported, uint8_t, bool, bool, wpa_mfp_supported);

    __Proxy(maxrate, double, double, double, maxrate);

    __Proxy(beaconrate, uint32_t, uint32_t, uint32_t, beaconrate);
    __Proxy(beacons_sec, uint32_t, uint32_t, uint32_t, beacons_sec);
    __ProxyIncDec(beacons_sec, uint32_t, uint32_t, beacons_sec);

    __Proxy(ietag_checksum, uint32_t, uint32_t, uint32_t, ietag_checksum);

    __ProxyFullyDynamic(dot11d_country, std::string, std::string, std::string, tracker_element_string, 
            dot11d_country_id);

    __ProxyFullyDynamicTrackable(dot11d_vec, tracker_element_vector, dot11d_vec_id);
    void set_dot11d_vec(std::vector<dot11_packinfo_dot11d_entry> vec);

    __ProxyFullyDynamic(wps_version, uint8_t, uint8_t, uint8_t, tracker_element_uint8, wps_version_id);
    __ProxyFullyDynamic(wps_state, uint32_t, uint32_t, uint32_t, tracker_element_uint32, wps_state_id);
    __ProxyFullyDynamic(wps_config_methods, uint16_t, uint16_t, uint16_t, tracker_element_uint16,
            wps_config_methods_id);
    __ProxyFullyDynamic(wps_manuf, std::string, std::string, std::string, tracker_element_string, wps_manuf_id);
    __ProxyFullyDynamic(wps_device_name, std::string, std::string, std::string, tracker_element_string, 
            wps_device_name_id);
    __ProxyFullyDynamic(wps_model_name, std::string, std::string, std::string, tracker_element_string,
            wps_model_name_id);
    __ProxyFullyDynamic(wps_model_number, std::string, std::string, std::string, tracker_element_string,
            wps_model_number_id);
    __ProxyFullyDynamic(wps_serial_number, std::string, std::string, std::string, tracker_element_string,
            wps_serial_number_id);
    __ProxyFullyDynamic(wps_uuid_e, std::string, std::string, std::string, tracker_element_string,
            wps_uuid_e_id);

    __ProxyFullyDynamicTrackable(location, kis_tracked_location, location_id);

    __Proxy(dot11r_mobility, uint8_t, bool, bool, dot11r_mobility);
    __Proxy(dot11r_mobility_domain_id, uint16_t, uint16_t, uint16_t, 
            dot11r_mobility_domain_id);

    __Proxy(dot11e_qbss, uint8_t, bool, bool, dot11e_qbss);
    __Proxy(dot11e_qbss_stations, uint16_t, uint16_t, uint16_t, dot11e_qbss_stations);
    __Proxy(dot11e_qbss_channel_load, double, double, double, dot11e_qbss_channel_load);

    __Proxy(ccx_txpower, uint8_t, unsigned int, unsigned int, ccx_txpower);
    __Proxy(cisco_client_mfp, uint8_t, bool, bool, cisco_client_mfp);

    __ProxyFullyDynamicTrackable(ie_tag_list, tracker_element_vector_double, ie_tag_list_id);
    __ProxyFullyDynamicTrackable(ie_tag_content, tracker_element_int_map, ie_tag_content_id);

    void set_ietag_content_from_packet(std::shared_ptr<dot11_ie> tags);

    __ProxyFullyDynamic(meshid, std::string, std::string, std::string, tracker_element_string, meshid_id);
	__ProxyFullyDynamic(mesh_gateway, uint8_t, bool, bool, tracker_element_uint8, mesh_gateway_id);
	__ProxyFullyDynamic(mesh_peerings, uint8_t, uint8_t, uint8_t, tracker_element_uint8, mesh_peerings_id);
	__ProxyFullyDynamic(mesh_forwarding, uint8_t, bool, bool, tracker_element_uint8, mesh_forwarding_id);

    __Proxy(adv_tx_power, uint8_t, uint8_t, uint8_t, adv_tx_power);

protected:
    virtual void register_fields() override;

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            // If we're inheriting, it's our responsibility to kick submaps and vectors with
            // complex types as well; since they're not themselves complex objects
            if (has_dot11d_vec()) {
                auto dv = get_dot11d_vec();
                for (auto d : *dv) {
                    auto din =
                        std::make_shared<dot11_11d_tracked_range_info>(dot11d_country_entry_id,
                                std::static_pointer_cast<tracker_element_map>(d));
                    // And assign it over the same key
                    d = std::static_pointer_cast<tracker_element>(din);
                }

            }
        }
    }

    std::shared_ptr<tracker_element_string_ptr> ssid;

    std::shared_ptr<tracker_element_uint32> ssid_len;

    std::shared_ptr<tracker_element_uint64> ssid_hash;

    uint16_t owe_ssid_id;
    uint16_t owe_ssid_len_id;
    uint16_t owe_bssid_id;

    std::shared_ptr<tracker_element_uint8> ssid_beacon;
    std::shared_ptr<tracker_element_uint8> ssid_probe_response;

    // Channel and optional HT center/second center
    std::shared_ptr<tracker_element_string> channel;
    std::shared_ptr<tracker_element_string> ht_mode;
    std::shared_ptr<tracker_element_uint64> ht_center_1;
    std::shared_ptr<tracker_element_uint64> ht_center_2;

    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;

    uint16_t beacon_info_id;

    std::shared_ptr<tracker_element_uint8> ssid_cloaked;
    std::shared_ptr<tracker_element_uint64> crypt_set_old;
    std::shared_ptr<tracker_element_uint64> crypt_set;

    std::shared_ptr<tracker_element_string_ptr> crypt_string;

    std::shared_ptr<tracker_element_uint8> wpa_mfp_required;
    std::shared_ptr<tracker_element_uint8> wpa_mfp_supported;
    std::shared_ptr<tracker_element_double> maxrate;
    std::shared_ptr<tracker_element_uint32> beaconrate;
    std::shared_ptr<tracker_element_uint32> beacons_sec;
    std::shared_ptr<tracker_element_uint32> ietag_checksum;

    // IE tag dot11d country / power restrictions from 802.11d; 
    // deprecated but still in use
    uint16_t dot11d_country_id;
    uint16_t dot11d_vec_id;
    uint16_t dot11d_country_entry_id;

    // WPS components
    uint16_t wps_version_id;
    uint16_t wps_state_id;
    uint16_t wps_config_methods_id;
    uint16_t wps_manuf_id;
    uint16_t wps_device_name_id;
    uint16_t wps_model_name_id;
    uint16_t wps_model_number_id;
    uint16_t wps_serial_number_id;
    uint16_t wps_uuid_e_id;

    uint16_t location_id;

    // 802.11r mobility/fast roaming advertisements
    std::shared_ptr<tracker_element_uint8> dot11r_mobility;
    std::shared_ptr<tracker_element_uint16> dot11r_mobility_domain_id;

    // 802.11e QBSS
    std::shared_ptr<tracker_element_uint8> dot11e_qbss;
    std::shared_ptr<tracker_element_uint16> dot11e_qbss_stations;
    std::shared_ptr<tracker_element_double> dot11e_qbss_channel_load;

    // Cisco CCX
    std::shared_ptr<tracker_element_uint8> ccx_txpower;
    // Cisco frame protection
    std::shared_ptr<tracker_element_uint8> cisco_client_mfp;

    // Builder to instantiate tags quickly
    std::shared_ptr<dot11_tracked_ietag> ie_tag_builder;

    // IE tags present, and order
    uint16_t ie_tag_list_id;

    // IE tag contents
    uint16_t ie_tag_content_id;
    uint16_t ie_tag_content_element_id;

    // Mesh ID
    uint16_t meshid_id;
	uint16_t mesh_gateway_id;
	uint16_t mesh_peerings_id;
	uint16_t mesh_forwarding_id;

    std::shared_ptr<tracker_element_uint8> adv_tx_power;
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

    dot11_client(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);
        }

    dot11_client(const dot11_client *p) :
        tracker_component{p} {
            __ImportField(bssid, p);
            __ImportField(bssid_key, p);

            __ImportField(first_time, p);
            __ImportField(last_time, p);

            __ImportField(client_type, p);

            __ImportId(dhcp_host_id, p);
            __ImportId(dhcp_vendor_id, p);

            __ImportId(eap_identity_id, p);

            __ImportId(cdp_device_id, p);
            __ImportId(cdp_port_id, p);

            __ImportField(decrypted, p);

            __ImportId(ipdata_id, p);

            __ImportField(datasize, p);
            __ImportField(datasize_retry, p);
            __ImportField(num_fragments, p);
            __ImportField(num_retries, p);

            __ImportId(location_id, p);

            reserve_fields(nullptr);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_client");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(bssid, mac_addr, mac_addr, mac_addr, bssid);
    __Proxy(bssid_key, device_key, device_key, device_key, bssid_key);
    __Proxy(client_type, uint32_t, uint32_t, uint32_t, client_type);

    __Proxy(first_time, uint64_t, time_t, time_t, first_time);
    __ProxySetIfLess(first_time, uint64_t, uint64_t, first_time);
    __Proxy(last_time, uint64_t, time_t, time_t, last_time);
    __ProxySetIfLess(last_time, uint64_t, uint64_t, last_time);

    __ProxyFullyDynamic(dhcp_host, std::string, std::string, std::string, tracker_element_string, dhcp_host_id);
    __ProxyFullyDynamic(dhcp_vendor, std::string, std::string, std::string, tracker_element_string, dhcp_vendor_id);

    __ProxyFullyDynamic(eap_identity, std::string, std::string, std::string, tracker_element_string, eap_identity_id);

    __ProxyFullyDynamic(cdp_device, std::string, std::string, std::string, tracker_element_string, cdp_device_id);
    __ProxyFullyDynamic(cdp_port, std::string, std::string, std::string, tracker_element_string, cdp_port_id);

    __Proxy(decrypted, uint8_t, bool, bool, decrypted);

    __ProxyFullyDynamicTrackable(ipdata, kis_tracked_ip_data, ipdata_id);

    __Proxy(datasize, uint64_t, uint64_t, uint64_t, datasize);
    __ProxyIncDec(datasize, uint64_t, uint64_t, datasize);

    __Proxy(datasize_retry, uint64_t, uint64_t, uint64_t, datasize_retry);
    __ProxyIncDec(datasize_retry, uint64_t, uint64_t, datasize_retry);

    __Proxy(num_fragments, uint64_t, uint64_t, uint64_t, num_fragments);
    __ProxyIncDec(num_fragments, uint64_t, uint64_t, num_fragments);

    __Proxy(num_retries, uint64_t, uint64_t, uint64_t, num_retries);
    __ProxyIncDec(num_retries, uint64_t, uint64_t, num_retries);

    __ProxyFullyDynamicTrackable(location, kis_tracked_location, location_id);

protected:
    virtual void register_fields() override {
        register_field("dot11.client.bssid", "bssid", &bssid);
        register_field("dot11.client.bssid_key", "key of BSSID record", &bssid_key);
        register_field("dot11.client.first_time", "first time seen", &first_time);
        register_field("dot11.client.last_time", "last time seen", &last_time);
        register_field("dot11.client.type", "type of client", &client_type);

        dhcp_host_id =
            register_dynamic_field<tracker_element_string>("dot11.client.dhcp_host", "dhcp host");
        dhcp_vendor_id =
            register_dynamic_field<tracker_element_string>("dot11.client.dhcp_vendor", "dhcp vendor");

        eap_identity_id = 
            register_dynamic_field<tracker_element_string>("dot11.client.eap_identity", "EAP identity");

        cdp_device_id = 
            register_dynamic_field<tracker_element_string>("dot11.client.cdp_device", "CDP device");
        cdp_port_id =
            register_dynamic_field<tracker_element_string>("dot11.client.cdp_port", "CDP port");

        register_field("dot11.client.decrypted", "client decrypted", &decrypted);
        
        ipdata_id =
            register_dynamic_field<kis_tracked_ip_data>("dot11.client.ipdata", "IPv4 information");

        register_field("dot11.client.datasize", "data in bytes", &datasize);
        register_field("dot11.client.datasize_retry", "retry data in bytes", &datasize_retry);
        register_field("dot11.client.num_fragments", "number of fragmented packets", &num_fragments);
        register_field("dot11.client.num_retries", "number of retried packets", &num_retries);

        location_id =
            register_dynamic_field<kis_tracked_location>("dot11.client.location", "location");

    }

    std::shared_ptr<tracker_element_mac_addr> bssid;
    std::shared_ptr<tracker_element_device_key> bssid_key;

    std::shared_ptr<tracker_element_uint64> first_time;
    std::shared_ptr<tracker_element_uint64> last_time;

    std::shared_ptr<tracker_element_uint32> client_type;

    uint16_t dhcp_host_id;
    uint16_t dhcp_vendor_id;

    uint16_t eap_identity_id;

    uint16_t cdp_device_id;
    uint16_t cdp_port_id;

    std::shared_ptr<tracker_element_uint8> decrypted;

    uint16_t ipdata_id;

    std::shared_ptr<tracker_element_uint64> datasize;
    std::shared_ptr<tracker_element_uint64> datasize_retry;
    std::shared_ptr<tracker_element_uint64> num_fragments;
    std::shared_ptr<tracker_element_uint64> num_retries;

    uint16_t location_id;
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
    friend class kis_80211_phy;
public:
    dot11_tracked_device() :
        tracker_component() {

        last_adv_ie_csum = 0;
        last_bss_invalid = 0;
        bss_invalid_count = 0;
        snapshot_next_beacon = false;

        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_device(int in_id) :
        tracker_component(in_id) { 

        last_adv_ie_csum = 0;
        last_bss_invalid = 0;
        bss_invalid_count = 0;
        snapshot_next_beacon = false;

        register_fields();
        reserve_fields(NULL);
    }

    dot11_tracked_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {

        last_adv_ie_csum = 0;
        last_bss_invalid = 0;
        bss_invalid_count = 0;
        snapshot_next_beacon = false;

        register_fields();
        reserve_fields(e);
    }

    dot11_tracked_device(const dot11_tracked_device *p) :
        tracker_component{p} {

            last_adv_ie_csum = 0;
            last_bss_invalid = 0;
            bss_invalid_count = 0;
            snapshot_next_beacon = false;

            __ImportField(type_set, p);

            __ImportId(client_map_id, p);
            __ImportId(client_map_entry_id, p);
            __ImportField(num_client_aps, p);

            __ImportId(advertised_ssid_map_id, p);
            __ImportId(advertised_ssid_map_entry_id, p);
            __ImportField(num_advertised_ssids, p);

            __ImportId(responded_ssid_map_id, p);
            __ImportId(responded_ssid_map_entry_id, p);
            __ImportField(num_responded_ssids, p);

            __ImportId(probed_ssid_map_id, p);
            __ImportId(probed_ssid_map_entry_id, p);
            __ImportField(num_probed_ssids, p);

            __ImportId(associated_client_map_id, p);
            __ImportId(associated_client_map_entry_id, p);
            __ImportField(num_associated_clients, p);
            __ImportField(client_disconnects, p);
            __ImportField(client_disconnects_last, p);

            // __ImportField(last_sequence, p);
            __ImportField(bss_timestamp, p);

            __ImportField(num_fragments, p);
            __ImportField(num_retries, p);

            __ImportField(datasize, p);
            __ImportField(datasize_retry, p);

            __ImportId(last_bssid_id, p);

            __ImportField(last_beacon_timestamp, p);

            __ImportField(wps_m3_count, p);
            __ImportField(wps_m3_last, p);

            __ImportId(wpa_key_map_id, p);
            __ImportId(wpa_key_entry_id, p);
            __ImportId(wpa_nonce_vec_id, p);
            __ImportId(wpa_anonce_vec_id, p);
            __ImportId(wpa_nonce_entry_id, p);

            __ImportId(ssid_beacon_packet_id, p);
            __ImportId(pmkid_packet_id, p);

            __ImportField(min_tx_power, p);
            __ImportField(max_tx_power, p);

            __ImportId(supported_channels_id, p);

            __ImportField(link_measurement_capable, p);
            __ImportField(neighbor_report_capable, p);

            __ImportId(extended_capabilities_list_id, p);

            __ImportField(beacon_fingerprint, p);
            __ImportField(probe_fingerprint, p);
            __ImportField(response_fingerprint, p);

            __ImportId(last_beaconed_ssid_record_id, p);
            __ImportId(last_probed_ssid_record_id, p);

            reserve_fields(nullptr);
        }


    virtual uint32_t get_signature() const override {
        return adler32_checksum("dot11_tracked_device");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    static void attach_base_parent(std::shared_ptr<dot11_tracked_device> self, 
            std::shared_ptr<kis_tracked_device_base> parent) {
        parent->insert(self);
    }

    __Proxy(type_set, uint64_t, uint64_t, uint64_t, type_set);
    __ProxyBitset(type_set, uint64_t, type_set);

    __ProxyDynamicTrackable(client_map, tracker_element_mac_map, client_map, client_map_id);

    std::shared_ptr<dot11_client> new_client() {
        return std::make_shared<dot11_client>(client_map_entry_id);
    }
    __Proxy(num_client_aps, uint64_t, uint64_t, uint64_t, num_client_aps);

    __ProxyDynamicTrackableFunc(advertised_ssid_map, tracker_element_hashkey_map, advertised_ssid_map, 
            advertised_ssid_map_id, {advertised_ssid_map->set_as_vector(true);});

    std::shared_ptr<dot11_advertised_ssid> new_advertised_ssid() {
        return std::make_shared<dot11_advertised_ssid>(advertised_ssid_map_entry_id);
    }

    __Proxy(num_advertised_ssids, uint64_t, uint64_t, uint64_t, num_advertised_ssids);

    __ProxyDynamicTrackableFunc(responded_ssid_map, tracker_element_hashkey_map, responded_ssid_map, 
            responded_ssid_map_id, {responded_ssid_map->set_as_vector(true);});

    std::shared_ptr<dot11_advertised_ssid> new_responded_ssid() {
        return std::make_shared<dot11_advertised_ssid>(responded_ssid_map_entry_id);
    }

    __Proxy(num_responded_ssids, uint64_t, uint64_t, uint64_t, num_responded_ssids);

    __ProxyDynamicTrackableFunc(probed_ssid_map, tracker_element_hashkey_map, probed_ssid_map, 
            probed_ssid_map_id, {probed_ssid_map->set_as_vector(true);});

    std::shared_ptr<dot11_probed_ssid> new_probed_ssid() {
        return std::make_shared<dot11_probed_ssid>(probed_ssid_map_entry_id);
    }

    __Proxy(num_probed_ssids, uint64_t, uint64_t, uint64_t, num_probed_ssids);

    __ProxyDynamicTrackable(associated_client_map, tracker_element_mac_map, 
            associated_client_map, associated_client_map_id);

    __Proxy(num_associated_clients, uint64_t, uint64_t, uint64_t, num_associated_clients);

    __Proxy(client_disconnects, uint64_t, uint64_t, uint64_t, client_disconnects);
    __ProxyIncDec(client_disconnects, uint64_t, uint64_t, client_disconnects);

    __Proxy(client_disconnects_last, uint64_t, uint64_t, uint64_t, client_disconnects_last);

    // __Proxy(last_sequence, uint64_t, uint64_t, uint64_t, last_sequence);
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

    __Proxy(last_beacon_timestamp, uint64_t, time_t, 
            time_t, last_beacon_timestamp);

    __Proxy(wps_m3_count, uint64_t, uint64_t, uint64_t, wps_m3_count);
    __ProxyIncDec(wps_m3_count, uint64_t, uint64_t, wps_m3_count);

    __Proxy(wps_m3_last, uint64_t, uint64_t, uint64_t, wps_m3_last);

    __ProxyDynamicTrackable(wpa_key_map, tracker_element_mac_map, wpa_key_map, wpa_key_map_id);
    std::shared_ptr<dot11_tracked_eapol> create_eapol_packet() {
        return std::make_shared<dot11_tracked_eapol>(wpa_key_entry_id);
    }

    __ProxyDynamicTrackable(ssid_beacon_packet, kis_tracked_packet, ssid_beacon_packet, ssid_beacon_packet_id);
    __ProxyDynamicTrackable(pmkid_packet, kis_tracked_packet, pmkid_packet, pmkid_packet_id);

    __ProxyDynamicTrackable(wpa_nonce_vec, tracker_element_vector, wpa_nonce_vec, wpa_nonce_vec_id);
    __ProxyDynamicTrackable(wpa_anonce_vec, tracker_element_vector, wpa_anonce_vec, wpa_anonce_vec_id);
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
        if (client_map != nullptr)
            set_num_client_aps(client_map->size());
        else
            set_num_client_aps(0);

        if (advertised_ssid_map != nullptr)
            set_num_advertised_ssids(advertised_ssid_map->size());
        else
            set_num_advertised_ssids(0);

        if (responded_ssid_map != nullptr)
            set_num_responded_ssids(responded_ssid_map->size());
        else
            set_num_responded_ssids(0);

        if (probed_ssid_map != nullptr)
            set_num_probed_ssids(probed_ssid_map->size());
        else
            set_num_probed_ssids(0);

        if (associated_client_map != nullptr)
            set_num_associated_clients(associated_client_map->size());
        else
            set_num_associated_clients(0);
    }

    __Proxy(min_tx_power, uint8_t, unsigned int, unsigned int, min_tx_power);
    __Proxy(max_tx_power, uint8_t, unsigned int, unsigned int, max_tx_power);
    __ProxyDynamicTrackable(supported_channels, tracker_element_vector_double, 
            supported_channels, supported_channels_id);

    __Proxy(link_measurement_capable, uint8_t, bool, bool, link_measurement_capable);
    __Proxy(neighbor_report_capable, uint8_t, bool, bool, neighbor_report_capable);
    __ProxyDynamicTrackable(extended_capabilities_list, tracker_element_vector_string, 
            extended_capabilities_list, extended_capabilities_list_id);

    __Proxy(beacon_fingerprint, uint32_t, uint32_t, uint32_t, beacon_fingerprint);
    __Proxy(probe_fingerprint, uint32_t, uint32_t, uint32_t, probe_fingerprint);
    __Proxy(response_fingerprint, uint32_t, uint32_t, uint32_t, response_fingerprint);

    bool get_snap_next_beacon() { return snapshot_next_beacon && ssid_beacon_packet == nullptr; }
    void set_snap_next_beacon(bool b) { snapshot_next_beacon = b; }
    bool get_beacon_packet_present() { return ssid_beacon_packet != nullptr; }

    bool get_pmkid_needed() { return pmkid_packet == nullptr; }
    bool get_pmkid_present() { return pmkid_packet != nullptr; }

    __ProxyDynamicTrackable(last_beaconed_ssid_record, tracker_element_alias, 
            last_beaconed_ssid_record, last_beaconed_ssid_record_id);

    __ProxyDynamicTrackable(last_probed_ssid_record, tracker_element_alias, 
            last_probed_ssid_record, last_probed_ssid_record_id);

protected:

    virtual void register_fields() override {
        register_field("dot11.device.typeset", "bitset of device type", &type_set);

        client_map_id =
            register_dynamic_field("dot11.device.client_map", "client behavior", &client_map);

        client_map_entry_id =
            register_field("dot11.device.client",
                    tracker_element_factory<dot11_client>(),
                    "client behavior record");

        register_field("dot11.device.num_client_aps", "number of APs connected to", &num_client_aps);

        // Advertised SSIDs keyed by ssid checksum
        advertised_ssid_map_id = 
            register_dynamic_field("dot11.device.advertised_ssid_map", "advertised SSIDs", &advertised_ssid_map);

        advertised_ssid_map_entry_id =
            register_field("dot11.device.advertised_ssid",
                    tracker_element_factory<dot11_advertised_ssid>(),
                    "advertised SSID");

        register_field("dot11.device.num_advertised_ssids", 
                "number of advertised SSIDs", &num_advertised_ssids);


        // Responded SSIDs keyed by ssid checksum, using the same structure as advertised
        responded_ssid_map_id = 
            register_dynamic_field("dot11.device.responded_ssid_map", "responded SSIDs", &responded_ssid_map);

        responded_ssid_map_entry_id =
            register_field("dot11.device.responded_ssid",
                    tracker_element_factory<dot11_advertised_ssid>(),
                    "responded SSID");

        register_field("dot11.device.num_responded_ssids", 
                "number of responded SSIDs", &num_responded_ssids);


        // Probed SSIDs keyed by int checksum
        probed_ssid_map_id =
            register_dynamic_field("dot11.device.probed_ssid_map", "probed SSIDs", &probed_ssid_map);

        probed_ssid_map_entry_id =
            register_field("dot11.device.probed_ssid",
                    tracker_element_factory<dot11_probed_ssid>(),
                    "probed ssid");

        register_field("dot11.device.num_probed_ssids", "number of probed SSIDs", &num_probed_ssids);

        associated_client_map_id =
            register_dynamic_field("dot11.device.associated_client_map", "associated clients", &associated_client_map);

        // Key of associated device, indexed by mac address
        associated_client_map_entry_id =
            register_field("dot11.device.associated_client", 
                    tracker_element_factory<tracker_element_device_key>(), "associated client");

        register_field("dot11.device.num_associated_clients", 
                "number of associated clients", &num_associated_clients);

        register_field("dot11.device.client_disconnects", 
                "client disconnects message count", 
                &client_disconnects);
        register_field("dot11.device.client_disconnects_last",
                "client disconnects last message",
                &client_disconnects_last);

        // register_field("dot11.device.last_sequence", "last sequence number", &last_sequence);
        register_field("dot11.device.bss_timestamp", "last BSS timestamp", &bss_timestamp);

        register_field("dot11.device.num_fragments", "number of fragmented packets", &num_fragments);
        register_field("dot11.device.num_retries", "number of retried packets", &num_retries);

        register_field("dot11.device.datasize", "data in bytes", &datasize);
        register_field("dot11.device.datasize_retry", "retried data in bytes", &datasize_retry);

        last_bssid_id =
            register_dynamic_field("dot11.device.last_bssid", "last BSSID", &last_bssid);

        register_field("dot11.device.last_beacon_timestamp",
                "unix timestamp of last beacon frame", 
                &last_beacon_timestamp);

        register_field("dot11.device.wps_m3_count", "WPS M3 message count", &wps_m3_count);
        register_field("dot11.device.wps_m3_last", "WPS M3 last message", &wps_m3_last);

        wpa_key_map_id =
            register_dynamic_field("dot11.device.wpa_handshake_list", "WPA handshakes per client",
                                   &wpa_key_map);

        wpa_key_entry_id =
            register_field("dot11.eapol.key",
                    tracker_element_factory<dot11_tracked_eapol>(),
                    "WPA handshake key");

        wpa_nonce_vec_id =
            register_dynamic_field("dot11.device.wpa_nonce_list", "Previous WPA Nonces", &wpa_nonce_vec);

        wpa_anonce_vec_id =
            register_dynamic_field("dot11.device.wpa_anonce_list", "Previous WPA ANonces", &wpa_anonce_vec);

        wpa_nonce_entry_id =
            register_field("dot11.device.wpa_nonce",
                    tracker_element_factory<dot11_tracked_nonce>(),
                    "WPA nonce exchange");

        ssid_beacon_packet_id =
            register_dynamic_field("dot11.device.ssid_beacon_packet",
                    "snapshotted beacon packet", &ssid_beacon_packet);

        pmkid_packet_id =
            register_dynamic_field("dot11.device.pmkid_packet",
                    "snapshotted RSN PMKID packet", &pmkid_packet);

        register_field("dot11.device.min_tx_power", "Minimum advertised TX power", &min_tx_power);
        register_field("dot11.device.max_tx_power", "Maximum advertised TX power", &max_tx_power);

        supported_channels_id =
            register_dynamic_field("dot11.device.supported_channels", "Advertised supported channels", 
                &supported_channels);

        register_field("dot11.device.link_measurement_capable", 
                "Advertised link measurement client capability", &link_measurement_capable);
        register_field("dot11.device.neighbor_report_capable",
                "Advertised neighbor report capability", &neighbor_report_capable);
        
        extended_capabilities_list_id =
            register_dynamic_field("dot11.device.extended_capabilities", 
                "Advertised extended capabilities list", &extended_capabilities_list);

        register_field("dot11.device.beacon_fingerprint", "Beacon fingerprint", &beacon_fingerprint);
        register_field("dot11.device.probe_fingerprint", "Probe (Client->AP) fingerprint", &probe_fingerprint);
        register_field("dot11.device.response_fingerprint", "Response (AP->Client) fingerprint", 
                &response_fingerprint);

        last_beaconed_ssid_record_id =
            register_dynamic_field("dot11.device.last_beaconed_ssid_record", 
                    "last beaconed ssid, complete record", &last_beaconed_ssid_record);
        last_probed_ssid_record_id =
            register_dynamic_field("dot11.device.last_probed_ssid_record", 
                    "last probed ssid, complete record", &last_probed_ssid_record);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            // If we're inheriting, it's our responsibility to kick submap and vecs with
            // complex types as well; since they're not themselves complex objects
            for (auto as : *advertised_ssid_map) {
                auto assid =
                    std::make_shared<dot11_advertised_ssid>(advertised_ssid_map_entry_id, 
                            std::static_pointer_cast<tracker_element_map>(as.second));
                as.second = assid;
            }

            if (probed_ssid_map != nullptr) {
                for (auto ps : *probed_ssid_map) {
                    auto pssid =
                        std::make_shared<dot11_probed_ssid>(probed_ssid_map_entry_id, 
                                std::static_pointer_cast<tracker_element_map>(ps.second));
                    ps.second = pssid;
                }
            }

            if (client_map != nullptr) {
                for (auto ci : *client_map) {
                    auto cli =
                        std::make_shared<dot11_client>(client_map_entry_id, 
                                std::static_pointer_cast<tracker_element_map>(ci.second));
                    ci.second = cli;
                }
            }

            // We don't have to deal with the client map because it's a map of
            // simplistic types

            if (wpa_key_map != nullptr) {
                for (auto v = wpa_key_map->begin(); v != wpa_key_map->end(); ++v) {
                    auto vec = std::static_pointer_cast<tracker_element_vector>(v->second);

                    for (auto k = vec->begin(); k != vec->end(); ++k) {
                        auto eap =
                            std::make_shared<dot11_tracked_eapol>(wpa_key_entry_id, 
                                                                  std::static_pointer_cast<tracker_element_map>(*k));
                        *k = eap;
                    }
                }
            }

            if (wpa_nonce_vec != nullptr) {
                for (auto k = wpa_nonce_vec->begin(); k != wpa_nonce_vec->end(); ++k) {
                    auto nonce =
                        std::make_shared<dot11_tracked_nonce>(wpa_nonce_entry_id, 
                                std::static_pointer_cast<tracker_element_map>(*k));
                    *k = nonce;
                }
            }

            if (wpa_anonce_vec != nullptr) {
                for (auto k = wpa_anonce_vec->begin(); k != wpa_anonce_vec->end(); ++k) {
                    auto anonce =
                        std::make_shared<dot11_tracked_nonce>(wpa_nonce_entry_id, 
                                std::static_pointer_cast<tracker_element_map>(*k));
                    *k = anonce;
                }
            }
        }
    }

    // Do we need to snap the next beacon because we're trying to add a beacon
    // record to eapol or pmkid?
    std::atomic<bool> snapshot_next_beacon;

    std::shared_ptr<tracker_element_uint64> type_set;

    std::shared_ptr<tracker_element_mac_map> client_map;
    uint16_t client_map_id;
    uint16_t client_map_entry_id;
    std::shared_ptr<tracker_element_uint64> num_client_aps;

    std::shared_ptr<tracker_element_hashkey_map> advertised_ssid_map;
    uint16_t advertised_ssid_map_id;
    uint16_t advertised_ssid_map_entry_id;
    std::shared_ptr<tracker_element_uint64> num_advertised_ssids;

    std::shared_ptr<tracker_element_hashkey_map> responded_ssid_map;
    uint16_t responded_ssid_map_id;
    uint16_t responded_ssid_map_entry_id;
    std::shared_ptr<tracker_element_uint64> num_responded_ssids;

    std::shared_ptr<tracker_element_hashkey_map> probed_ssid_map;
    uint16_t probed_ssid_map_id;
    uint16_t probed_ssid_map_entry_id;
    std::shared_ptr<tracker_element_uint64> num_probed_ssids;

    std::shared_ptr<tracker_element_mac_map> associated_client_map;
    uint16_t associated_client_map_id;
    uint16_t associated_client_map_entry_id;
    std::shared_ptr<tracker_element_uint64> num_associated_clients;
    std::shared_ptr<tracker_element_uint64> client_disconnects;
    std::shared_ptr<tracker_element_uint64> client_disconnects_last;

    // std::shared_ptr<tracker_element_uint64> last_sequence;
    std::shared_ptr<tracker_element_uint64> bss_timestamp;

    std::shared_ptr<tracker_element_uint64> num_fragments;
    std::shared_ptr<tracker_element_uint64> num_retries;

    std::shared_ptr<tracker_element_uint64> datasize;
    std::shared_ptr<tracker_element_uint64> datasize_retry;

    std::shared_ptr<tracker_element_mac_addr> last_bssid;
    uint16_t last_bssid_id;

    std::shared_ptr<tracker_element_uint64> last_beacon_timestamp;

    std::shared_ptr<tracker_element_uint64> wps_m3_count;
    std::shared_ptr<tracker_element_uint64> wps_m3_last;

    uint16_t wpa_key_map_id;
    std::shared_ptr<tracker_element_mac_map> wpa_key_map;
    uint16_t wpa_key_entry_id;

    std::shared_ptr<tracker_element_vector> wpa_nonce_vec;
    uint16_t wpa_nonce_vec_id;

    std::shared_ptr<tracker_element_vector> wpa_anonce_vec;
    uint16_t wpa_anonce_vec_id;
    uint16_t wpa_nonce_entry_id;

    std::shared_ptr<kis_tracked_packet> ssid_beacon_packet;
    uint16_t ssid_beacon_packet_id;

    std::shared_ptr<kis_tracked_packet> pmkid_packet;
    uint16_t pmkid_packet_id;

    // Un-exposed internal tracking options
    uint32_t last_adv_ie_csum;
    std::shared_ptr<dot11_advertised_ssid> last_adv_ssid;

    // Advertised in association requests but device-centric
    std::shared_ptr<tracker_element_uint8> min_tx_power;
    std::shared_ptr<tracker_element_uint8> max_tx_power;

    std::shared_ptr<tracker_element_vector_double> supported_channels;
    uint16_t supported_channels_id;

    std::shared_ptr<tracker_element_uint8> link_measurement_capable;
    std::shared_ptr<tracker_element_uint8> neighbor_report_capable;

    std::shared_ptr<tracker_element_vector_string> extended_capabilities_list;
    uint16_t extended_capabilities_list_id;

    std::shared_ptr<tracker_element_uint32> beacon_fingerprint;
    std::shared_ptr<tracker_element_uint32> probe_fingerprint;
    std::shared_ptr<tracker_element_uint32> response_fingerprint;

    uint16_t last_beaconed_ssid_record_id;
    std::shared_ptr<tracker_element_alias> last_beaconed_ssid_record;

    uint16_t last_probed_ssid_record_id;
    std::shared_ptr<tracker_element_alias> last_probed_ssid_record;
};

#endif

