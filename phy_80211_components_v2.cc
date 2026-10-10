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

#include "phy_80211_components_v2.h"

void dot11_tracked_eapol_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.eapol.timestamp", opts, eapol_time());
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.direction", opts, eapol_dir());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.eapol.replay_counter", opts, eapol_replay_counter());
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.message_num", opts, eapol_msg_num());
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.install", opts, eapol_install());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.nonce", opts, eapol_nonce());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.rsn_pmkid", opts, eapol_rsn_pmkid());
    json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, "dot11.eapol.packet", opts, packet_);

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void dot11_tracked_eapol_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.eapol.timestamp"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, eapol_time());
                break;
            case json_adapter_v2::consthash("dot11.eapol.direction"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_dir());
                break;
            case json_adapter_v2::consthash("dot11.eapol.replay_counter"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, eapol_replay_counter());
                break;
            case json_adapter_v2::consthash("dot11.eapol.message_num"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_msg_num());
                break;
            case json_adapter_v2::consthash("dot11.eapol.install"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_install());
                break;
            case json_adapter_v2::consthash("dot11.eapol.nonce"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_nonce());
                break;
            case json_adapter_v2::consthash("dot11.eapol.rsn_pmkid"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_rsn_pmkid());
                break;
            case json_adapter_v2::consthash("dot11.eapol.packet"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, f.second.rename, opts, packet_, subgroup);
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}


void dot11_tracked_nonce_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.eapol.timestamp", opts, eapol_time());
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.eapol.replay_counter", opts, eapol_replay_counter());
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.message_num", opts, eapol_msg_num());
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.install", opts, eapol_install());
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.nonce", opts, eapol_nonce());

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void dot11_tracked_nonce_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.eapol.timestamp"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, eapol_time());
                break;
            case json_adapter_v2::consthash("dot11.eapol.replay_counter"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, eapol_replay_counter());
                break;
            case json_adapter_v2::consthash("dot11.eapol.message_num"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_msg_num());
                break;
            case json_adapter_v2::consthash("dot11.eapol.install"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_install());
                break;
            case json_adapter_v2::consthash("dot11.eapol.nonce"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_nonce());
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void dot11_tracked_ssid_alert_v2::set_ssid_regex(const std::string& regex) {
#if defined(HAVE_LIBPCRE1)
    const char *compile_error, *study_error;
    int erroroffset;

    if (ssid_re_)
        pcre_free(ssid_re_);
    if (ssid_study_)
        pcre_free(ssid_study_);

    ssid_regex_ = regex;

    ssid_re_ = pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

    if (ssid_re_ == NULL) {
        throw std::runtime(fmt::format("Could not parse PCRE: {} at {}",
                    compile_error, erroroffset));
    }

    ssid_study_ = pcre_study(ssid_re_, 0, &study_error);

    if (study_error != NULL) {
        throw std::runtime_error(fmt::format("PCRE error: {}", study_error));
    }
#elif defined(HAVE_LIBPCRE2)
    PCRE2_SIZE erroroffset;
    int errornumber;

    if (ssid_match_data_)
        pcre2_match_data_free(ssid_match_data_);
    if (ssid_re_)
        pcre2_code_free(ssid_re_);

    ssid_regex_ = regex;

    ssid_re_ = pcre2_compile((PCRE2_SPTR8) regex.c_str(),
            PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

    if (ssid_re_ == nullptr) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        const auto e = fmt::format("Could not parse PCRE regex: {} at {}",
                (int) erroroffset, (char *) buffer);
        throw std::runtime_error(e);
    }

    ssid_match_data_ = pcre2_match_data_create_from_pattern(ssid_re_, NULL);
#endif
}

bool dot11_tracked_ssid_alert_v2::compare_ssid(const std::string& ssid, const mac_addr& mac) {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
    int rc;
#if defined(HAVE_LIBPCRE1)
    int ovector[128];
    rc = pcre_exec(ssid_re_, ssid_study_, ssid.c_str(), ssid.length(), 0, 0, ovector, 128);
#elif defined(HAVE_LIBPCRE2)
    rc = pcre2_match(ssid_re_, (PCRE2_SPTR8) ssid.c_str(), ssid.length(),
            0, 0, ssid_match_data_, NULL);
#endif
    if (rc > 0) {
        bool valid = false;

        for (const auto& m : allowed_macs_vec_) {
            if (m == mac) {
                valid = true;
                break;
            }
        }

        if (!valid)
            return true;
    }
#endif
    return false;
}

void dot11_tracked_ssid_alert_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.ssidalert.name", opts, ssid_group_name_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.ssidalert.regex", opts, ssid_regex_);
    json_adapter_v2::json_encode_keyed_array<allowed_macs_vec_iter_t_>{}(os, "dot11.ssidalert.allowed_macs", opts,
            allowed_macs_vec_.begin(), allowed_macs_vec_.end());

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void dot11_tracked_ssid_alert_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.ssidalert.name"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_group_name_);
                break;
            case json_adapter_v2::consthash("dot11.ssidalert.regex"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_regex_);
                break;
            case json_adapter_v2::consthash("dot11.ssidalert.allowed_macs"):
                json_adapter_v2::json_encode_keyed_array<allowed_macs_vec_iter_t_>{}(os, f.second.rename, opts,
                        allowed_macs_vec_.begin(), allowed_macs_vec_.end());
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}


void dot11_11d_tracked_range_info_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.11d.start_channel", opts, startchan_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.11d.num_channels", opts, numchan_);
    json_adapter_v2::json_encode_keyed<int32_t>{}(os, "dot11.11d.tx_power", opts, txpower_);

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void dot11_11d_tracked_range_info_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.11d.start_channel"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, startchan_);
                break;
            case json_adapter_v2::consthash("dot11.11d.num_channels"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, numchan_);
                break;
            case json_adapter_v2::consthash("dot11.11d.tx_power"):
                json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, txpower_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}


void dot11_tracked_ietag_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.ietag.uniqueid", opts, unique_tag_id_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.ietag.number", opts, tag_number_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.ietag.oui", opts, tag_oui_);
    json_adapter_v2::json_encode_keyed<std::string_view>{}(os, "dot11.ietag.oui_manuf", opts, tag_oui_manuf_);
    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.ietag.subtag", opts, tag_vendor_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.ietag.data", opts, tag_data_);

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void dot11_tracked_ietag_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.ietag.uniqueid"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, unique_tag_id_);
                break;
            case json_adapter_v2::consthash("dot11.ietag.number"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, tag_number_);
                break;
            case json_adapter_v2::consthash("dot11.ietag.oui"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, tag_oui_);
                break;
            case json_adapter_v2::consthash("dot11.ietag.oui_manuf"):
                json_adapter_v2::json_encode_keyed<std::string_view>{}(os, f.second.rename, opts, tag_oui_manuf_);
                break;
            case json_adapter_v2::consthash("dot11.ietag.subtag"):
                json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, tag_vendor_);
                break;
            case json_adapter_v2::consthash("dot11.ietag.data"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, tag_data_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}


void dot11_probed_ssid_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.ssid", opts, ssid_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.probedssid.ssidlen", opts, ssid_len_);
    json_adapter_v2::json_encode_keyed<mac_addr>{}(os, "dot11.probedssid.bssid", opts, bssid_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.probedssid.first_time", opts, first_time_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.probedssid.last_time", opts, last_time_);

    json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, "dot11.probedssid.location", opts, location_);

    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.probedssid.mobility_id", opts, dot11r_mobility_);
    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.probedssid.mobility_domain_id", opts, dot11r_mobility_domain_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.probedssid.crypt_bitfield", opts, crypt_set_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.crypt_string", opts, crypt_string_);

    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.probedssid.wpa_mfp_required", opts, wpa_mfp_required_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.probedssid.wpa_mfp_supported", opts, wpa_mfp_supported_);

    json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, "dot11.probedssid.ie_tag_list", opts,
            ie_tag_list_.begin(), ie_tag_list_.end());

    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.probedssid.wps_version", opts, wps_version_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.probedssid.wps_state", opts, wps_state_);
    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.probedssid.wps_config_methods", opts, wps_config_methods_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_manuf", opts, wps_manuf_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_device_name", opts, wps_device_name_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_model_name", opts, wps_model_name_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_model_number", opts, wps_model_number_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_serial_number", opts, wps_serial_number_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_uuid_e", opts, wps_uuid_e_);

    opts->next_key_comma = sv_comma;

    fmt::print(os, "}}");
}

void dot11_probed_ssid_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.probedssid.ssid"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.ssidlen"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, ssid_len_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.bssid"):
                json_adapter_v2::json_encode_keyed<mac_addr>{}(os, f.second.rename, opts, bssid_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.first_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, first_time_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.last_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_time_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.location"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, f.second.rename, opts, location_, subgroup);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.mobility_id"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, dot11r_mobility_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.mobility_domain_id"):
                json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, dot11r_mobility_domain_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.crypt_bitfield"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, crypt_set_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.crypt_string"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, crypt_string_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wpa_mfp_required"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, wpa_mfp_required_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wpa_mfp_supported"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, wpa_mfp_supported_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.ie_tag_list"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, f.second.rename, opts,
                        ie_tag_list_.begin(), ie_tag_list_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_version"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, wps_version_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_state"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, wps_state_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_config_methods"):
                json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, wps_config_methods_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_manuf"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_manuf_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_device_name"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_device_name_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_model_name"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_name_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_model_number"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_number_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_serial_number"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_serial_number_);
                break;
            case json_adapter_v2::consthash("dot11.probedssid.wps_uuid_e"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_uuid_e_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}


void dot11_advertised_ssid_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, "dot11.advertisedssid.location", opts, location_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.ssid", opts, ssid_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.ssidlen", opts, ssid_len_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.cloaked", opts, ssid_cloaked_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.ssid_hash", opts, ssid_hash_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.owe_ssid", opts, owe_ssid_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.owe_ssid_len", opts, owe_ssid_len_);
    json_adapter_v2::json_encode_keyed<mac_addr>{}(os, "dot11.advertisedssid.owe_bssid", opts, owe_bssid_);

    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.beacon", opts, ssid_beacon_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.probe_response", opts, ssid_probe_response_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.channel", opts, channel_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.ht_mode", opts, ht_mode_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.ht_center_1", opts, ht_center_1_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.ht_center_2", opts, ht_center_2_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.channel_width", opts, channel_width_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.first_time", opts, first_time_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.last_time", opts, last_time_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.beacon_info", opts, beacon_info_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.crypt_bitfield", opts, crypt_set_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.crypt_string", opts, crypt_string_);

    json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.advertisedssid.maxrate", opts, maxrate_);

    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.beaconrate", opts, beaconrate_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.beaconsec", opts, beacons_seen_sec_);

    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.ietag_checksum", opts, ie_tag_checksum_);

    // encode as list of tag numbers
    json_adapter_v2::json_encode_keyed_array_custom<ie_tag_list_iter_t_>{}(os, "dot11.advertisedssid.ie_tag_list", opts,
            ie_tag_list_.begin(), ie_tag_list_.end(),
            [](std::ostream& os, json_adapter_v2::opts *opts, ie_tag_list_iter_t_ first) {
            json_adapter_v2::json_encode<uint8_t>{}(os, opts, first->tag_number());
            });

    // encode as full data
    json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, "dot11.advertisedssid.ie_tag_content", opts,
            ie_tag_list_.begin(), ie_tag_list_.end());

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.dot11d_country", opts, dot11d_country_);
    json_adapter_v2::json_encode_keyed_array<dot11d_vector_iter_t_>{}(os, "dot11.advertisedssid.dot11d_list", opts,
            dot11d_vec_.begin(), dot11d_vec_.end());

    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.wps_version", opts, wps_version_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.wps_state", opts, wps_state_);
    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.advertisedssid.wps_config_methods", opts, wps_config_methods_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_manuf", opts, wps_manuf_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_device_name", opts, wps_device_name_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_model_name", opts, wps_model_name_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_model_number", opts, wps_model_number_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_serial_number", opts, wps_serial_number_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_uuid_e", opts, wps_uuid_e_);

    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11r_mobility", opts, dot11r_mobility_);
    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.advertisedssid.dot11r_mobility_domain_id", opts, dot11r_mobility_domain_);

    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11e_qbss", opts, dot11e_qbss_);
    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.advertisedssid.dot11e_qbss_stations", opts, dot11e_qbss_stations_);
    json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.advertisedssid.dot11e_channel_utilization_perc", opts, dot11e_qbss_load_);

    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.ccx_txpower", opts, ccx_txpower_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.cisco_client_mfp", opts, cisco_client_mfp_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.dot11s.meshid", opts, meshid_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11s.gateway", opts, mesh_gateway_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.dot11s.num_peerings", opts, mesh_peerings_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11s.forwarding", opts, mesh_forwarding_);

    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.advertised_txpower", opts, adv_tx_power_);

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void dot11_advertised_ssid_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.advertisedssid.location"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, f.second.rename, opts, location_, subgroup);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ssid"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ssidlen"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, ssid_len_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.cloaked"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, ssid_cloaked_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ssid_hash"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ssid_hash_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.owe_ssid"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, owe_ssid_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.owe_ssid_len"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, owe_ssid_len_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.owe_bssid"):
                json_adapter_v2::json_encode_keyed<mac_addr>{}(os, f.second.rename, opts, owe_bssid_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.beacon"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, ssid_beacon_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.probe_response"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, ssid_probe_response_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.channel"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ht_mode"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ht_mode_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ht_center_1"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ht_center_1_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ht_center_2"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ht_center_2_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.channel_width"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, channel_width_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.first_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, first_time_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.last_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_time_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.beacon_info"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, beacon_info_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.crypt_bitfield"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, crypt_set_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.crypt_string"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, crypt_string_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.maxrate"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, maxrate_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.beaconrate"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, beaconrate_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.beaconsec"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, beacons_seen_sec_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ietag_checksum"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, ie_tag_checksum_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ie_tag_list"):
                json_adapter_v2::json_encode_keyed_array_custom<ie_tag_list_iter_t_>{}(os, f.second.rename, opts, ie_tag_list_.begin(), ie_tag_list_.end(), [](std::ostream& os, json_adapter_v2::opts *opts, ie_tag_list_iter_t_ first) { json_adapter_v2::json_encode<uint8_t>{}(os, opts, first->tag_number()); });
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ie_tag_content"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, f.second.rename, opts, ie_tag_list_.begin(), ie_tag_list_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11d_country"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, dot11d_country_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11d_list"):
                json_adapter_v2::json_encode_keyed_array<dot11d_vector_iter_t_>{}(os, f.second.rename, opts, dot11d_vec_.begin(), dot11d_vec_.end());
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_version"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, wps_version_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_state"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, wps_state_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_config_methods"):
                json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, wps_config_methods_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_manuf"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_manuf_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_device_name"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_device_name_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_model_name"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_name_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_model_number"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_number_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_serial_number"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_serial_number_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.wps_uuid_e"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_uuid_e_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11r_mobility"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, dot11r_mobility_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11r_mobility_domain_id"):
                json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, dot11r_mobility_domain_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11e_qbss"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, dot11e_qbss_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11e_qbss_stations"):
                json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, dot11e_qbss_stations_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11e_channel_utilization_perc"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, dot11e_qbss_load_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.ccx_txpower"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, ccx_txpower_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.cisco_client_mfp"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, cisco_client_mfp_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.meshid"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, meshid_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.gateway"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, mesh_gateway_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.num_peerings"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, mesh_peerings_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.forwarding"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, mesh_forwarding_);
                break;
            case json_adapter_v2::consthash("dot11.advertisedssid.advertised_txpower"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, adv_tx_power_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}


void dot11_client_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.client.type", opts, client_type_);

    json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, "dot11.client.location", opts, location_);

    json_adapter_v2::json_encode_keyed<mac_addr>{}(os, "dot11.client.bssid", opts, bssid_);
    json_adapter_v2::json_encode_keyed<device_key_v2>{}(os, "dot11.client.bssid_key", opts, bssid_key_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.client.first_time", opts, first_time_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.client.last_time", opts, last_time_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.client.dhcp_host", opts, dhcp_host_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.client.dhcp_vendor", opts, dhcp_vendor_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.client.eap_identity", opts, eap_identity_);

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.client.cdp_device", opts, cdp_device_);
    json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.client.cdp_port", opts, cdp_port_);

    json_adapter_v2::json_encode_keyed<kis_tracked_ip_v4_data_v2>{}(os, "dot11.client.ipdata", opts, ip_v4_);

    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.client.decrypted", opts, decrypted_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.client.datasize", opts, datasize_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.client.datasize_retry", opts, datasize_retry_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.client.num_fragments", opts, num_fragments_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.client.num_retries", opts, num_retries_);

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void dot11_client_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.client.type"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, client_type_);
                break;

            case json_adapter_v2::consthash("dot11.client.location"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, f.second.rename, opts, location_, subgroup);
                break;

            case json_adapter_v2::consthash("dot11.client.bssid"):
                json_adapter_v2::json_encode_keyed<mac_addr>{}(os, f.second.rename, opts, bssid_);
                break;
            case json_adapter_v2::consthash("dot11.client.bssid_key"):
                json_adapter_v2::json_encode_keyed<device_key_v2>{}(os, f.second.rename, opts, bssid_key_);
                break;

            case json_adapter_v2::consthash("dot11.client.first_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, first_time_);
                break;
            case json_adapter_v2::consthash("dot11.client.last_time"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_time_);
                break;

            case json_adapter_v2::consthash("dot11.client.dhcp_host"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, dhcp_host_);
                break;
            case json_adapter_v2::consthash("dot11.client.dhcp_vendor"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, dhcp_vendor_);
                break;

            case json_adapter_v2::consthash("dot11.client.eap_identity"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eap_identity_);
                break;

            case json_adapter_v2::consthash("dot11.client.cdp_device"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, cdp_device_);
                break;
            case json_adapter_v2::consthash("dot11.client.cdp_port"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, cdp_port_);
                break;

            case json_adapter_v2::consthash("dot11.client.ipdata"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_ip_v4_data_v2>{}(os, f.second.rename, opts, ip_v4_, subgroup);
                break;

            case json_adapter_v2::consthash("dot11.client.decrypted"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, decrypted_);
                break;

            case json_adapter_v2::consthash("dot11.client.datasize"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, datasize_);
                break;
            case json_adapter_v2::consthash("dot11.client.datasize_retry"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, datasize_retry_);
                break;
            case json_adapter_v2::consthash("dot11.client.num_fragments"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, num_fragments_);
                break;
            case json_adapter_v2::consthash("dot11.client.num_retries"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, num_retries_);
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;

}


void dot11_tracked_device_v2::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    fmt::print(os, "{{");

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.typeset", opts, type_set_);

    json_adapter_v2::json_encode_keyed_map<client_map_iter_t_>{}(os, "dot11.device.client_map", opts,
            client_map_.begin(), client_map_.end());
    json_adapter_v2::json_encode_keyed<size_t>{}(os, "dot11.device.num_client_aps", opts, client_map_.size());

    json_adapter_v2::json_encode_keyed_map<advertised_ssid_map_iter_t_>{}(os, "dot11.device.advertised_ssid_map", opts,
            advertised_ssid_map_.begin(), advertised_ssid_map_.end());
    json_adapter_v2::json_encode_keyed<size_t>{}(os, "dot11.device.num_advertised_ssids", opts, advertised_ssid_map_.size());

    json_adapter_v2::json_encode_keyed_map<responded_ssid_map_iter_t_>{}(os, "dot11.device.responded_ssid_map", opts,
            responded_ssid_map_.begin(), responded_ssid_map_.end());
    json_adapter_v2::json_encode_keyed<size_t>{}(os, "dot11.device.num_responded_ssids", opts, responded_ssid_map_.size());

    json_adapter_v2::json_encode_keyed_map<probed_ssid_map_iter_t_>{}(os, "dot11.device.probed_ssid_map", opts,
            probed_ssid_map_.begin(), probed_ssid_map_.end());
    json_adapter_v2::json_encode_keyed<size_t>{}(os, "dot11.device.num_probed_ssids", opts, probed_ssid_map_.size());

    json_adapter_v2::json_encode_keyed_map<associated_client_map_iter_t_>{}(os, "dot11.device.associated_client_map", opts,
            associated_client_map_.begin(), associated_client_map_.end());
    json_adapter_v2::json_encode_keyed<size_t>{}(os, "dot11.device.num_associated_clients", opts, associated_client_map_.size());

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.client_disconnects", opts, client_disconnects_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.client_disconnects_last", opts, client_disconnect_last_time_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.bss_timestamp", opts, bss_timestamp_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.num_fragments", opts, num_fragments_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.num_retries", opts, num_retries_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.datasize", opts, datasize_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.datasize_retry", opts, datasize_retry_);

    json_adapter_v2::json_encode_keyed<mac_addr>{}(os, "dot11.device.last_bssid", opts, last_bssid_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.last_beacon_timestamp", opts, last_beacon_time_);

    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.wps_m3_count", opts, wpa_m3_count_);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.device.wps_m3_last", opts, wpa_m3_last_time_);

    json_adapter_v2::json_encode_keyed_map<wpa_key_map_iter_t_>{}(os, "dot11.device.wpa_handshake_list", opts,
            wpa_key_map_.begin(), wpa_key_map_.end());

    json_adapter_v2::json_encode_keyed_array<wpa_nonce_vec_iter_t_>{}(os, "dot11.device.wpa_nonce_list", opts,
            wpa_nonce_vec_.begin(), wpa_nonce_vec_.end());

    json_adapter_v2::json_encode_keyed_array<wpa_anonce_vec_iter_t_>{}(os, "dot11.device.wpa_anonce_list", opts,
            wpa_anonce_vec_.begin(), wpa_anonce_vec_.end());

    json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, "dot11.device.ssid_beacon_packet", opts, beacon_packet_);
    json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, "dot11.device.pmkid_packet", opts, pmkid_packet_);

    if (last_advertised_ssid_ == nullptr) {
        json_adapter_v2::json_encode_keyed_null{}(os, "dot11.device.last_beaconed_ssid_record", opts);
    } else {
        json_adapter_v2::json_encode_keyed<dot11_advertised_ssid_v2>{}(os, "dot11.device.last_beaconed_ssid_record", opts, last_advertised_ssid_);
    }

    if (last_probed_ssid_ == nullptr) {
        json_adapter_v2::json_encode_keyed_null{}(os, "dot11.device.last_probed_ssid_record", opts);
    } else {
        json_adapter_v2::json_encode_keyed<dot11_probed_ssid_v2>{}(os, "dot11.device.last_probed_ssid_record", opts, last_probed_ssid_);
    }

    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.device.min_tx_power", opts, min_tx_power_);
    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.device.max_tx_power", opts, max_tx_power_);

    json_adapter_v2::json_encode_keyed_array<supported_channels_vec_iter_t_>{}(os, "dot11.device.supported_channels", opts,
            supported_channels_vec_.begin(), supported_channels_vec_.end());

    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.device.link_measurement_capable", opts, link_measurement_capable_);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.device.neighbor_report_capable", opts, neighbor_report_capable_);

    json_adapter_v2::json_encode_keyed_array<extended_capabilities_vec_iter_t_>{}(os, "dot11.device.extended_capabilities", opts,
            extended_capabilities_vec_.begin(), extended_capabilities_vec_.end());

    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.device.beacon_fingerprint", opts, beacon_fingerprint_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.device.probe_fingerprint", opts, probe_fingerprint_);
    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.device.response_fingerprint", opts, response_fingerprint_);

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

void dot11_tracked_device_v2::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    json_adapter_v2::field_group_map subgroup;

    fmt::print(os, "{{");
    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("dot11.device.typeset"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, type_set_);
                break;

            case json_adapter_v2::consthash("dot11.device.client_map"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<client_map_iter_t_>{}(os, f.second.rename, opts, client_map_.begin(), client_map_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("dot11.device.num_client_aps"):
                json_adapter_v2::json_encode_keyed<size_t>{}(os, f.second.rename, opts, client_map_.size());
                break;

            case json_adapter_v2::consthash("dot11.device.advertised_ssid_map"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<advertised_ssid_map_iter_t_>{}(os, f.second.rename, opts, advertised_ssid_map_.begin(), advertised_ssid_map_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("dot11.device.num_advertised_ssids"):
                json_adapter_v2::json_encode_keyed<size_t>{}(os, f.second.rename, opts, advertised_ssid_map_.size());
                break;

            case json_adapter_v2::consthash("dot11.device.responded_ssid_map"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<responded_ssid_map_iter_t_>{}(os, f.second.rename, opts, responded_ssid_map_.begin(), responded_ssid_map_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("dot11.device.num_responded_ssids"):
                json_adapter_v2::json_encode_keyed<size_t>{}(os, f.second.rename, opts, responded_ssid_map_.size());
                break;

            case json_adapter_v2::consthash("dot11.device.probed_ssid_map"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<probed_ssid_map_iter_t_>{}(os, f.second.rename, opts, probed_ssid_map_.begin(), probed_ssid_map_.end(), subgroup);
                break;
            case json_adapter_v2::consthash("dot11.device.num_probed_ssids"):
                json_adapter_v2::json_encode_keyed<size_t>{}(os, f.second.rename, opts, probed_ssid_map_.size());
                break;

            case json_adapter_v2::consthash("dot11.device.associated_client_map"):
                json_adapter_v2::json_encode_keyed_map<associated_client_map_iter_t_>{}(os, f.second.rename, opts, associated_client_map_.begin(), associated_client_map_.end());
                break;
            case json_adapter_v2::consthash("dot11.device.num_associated_clients"):
                json_adapter_v2::json_encode_keyed<size_t>{}(os, f.second.rename, opts, associated_client_map_.size());
                break;

            case json_adapter_v2::consthash("dot11.device.client_disconnects"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, client_disconnects_);
                break;
            case json_adapter_v2::consthash("dot11.device.client_disconnects_last"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, client_disconnect_last_time_);
                break;

            case json_adapter_v2::consthash("dot11.device.bss_timestamp"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, bss_timestamp_);
                break;

            case json_adapter_v2::consthash("dot11.device.num_fragments"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, num_fragments_);
                break;
            case json_adapter_v2::consthash("dot11.device.num_retries"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, num_retries_);
                break;

            case json_adapter_v2::consthash("dot11.device.datasize"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, datasize_);
                break;
            case json_adapter_v2::consthash("dot11.device.datasize_retry"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, datasize_retry_);
                break;

            case json_adapter_v2::consthash("dot11.device.last_bssid"):
                json_adapter_v2::json_encode_keyed<mac_addr>{}(os, f.second.rename, opts, last_bssid_);
                break;

            case json_adapter_v2::consthash("dot11.device.last_beacon_timestamp"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_beacon_time_);
                break;

            case json_adapter_v2::consthash("dot11.device.wps_m3_count"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, wpa_m3_count_);
                break;
            case json_adapter_v2::consthash("dot11.device.wps_m3_last"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, wpa_m3_last_time_);
                break;

            case json_adapter_v2::consthash("dot11.device.wpa_handshake_list"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<wpa_key_map_iter_t_>{}(os, f.second.rename, opts, wpa_key_map_.begin(), wpa_key_map_.end(), subgroup);
                break;

            case json_adapter_v2::consthash("dot11.device.wpa_nonce_list"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<wpa_nonce_vec_iter_t_>{}(os, f.second.rename, opts, wpa_nonce_vec_.begin(), wpa_nonce_vec_.end(), subgroup);
                break;

            case json_adapter_v2::consthash("dot11.device.wpa_anonce_list"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_array<wpa_anonce_vec_iter_t_>{}(os, f.second.rename, opts, wpa_anonce_vec_.begin(), wpa_anonce_vec_.end(), subgroup);
                break;

            case json_adapter_v2::consthash("dot11.device.ssid_beacon_packet"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, f.second.rename, opts, beacon_packet_, subgroup);
                break;
            case json_adapter_v2::consthash("dot11.device.pmkid_packet"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, f.second.rename, opts, pmkid_packet_, subgroup);
                break;

            case json_adapter_v2::consthash("dot11.device.last_beaconed_ssid_record"):
                if (last_advertised_ssid_ == nullptr) {
                    json_adapter_v2::json_encode_keyed_null{}(os, f.second.rename, opts);
                } else {
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed<dot11_advertised_ssid_v2>{}(os, f.second.rename, opts, last_advertised_ssid_, subgroup);
                }

            case json_adapter_v2::consthash("dot11.device.last_probed_ssid_record"):
                if (last_probed_ssid_ == nullptr) {
                    json_adapter_v2::json_encode_keyed_null{}(os, f.second.rename, opts);
                } else {
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed<dot11_probed_ssid_v2>{}(os, f.second.rename, opts, last_probed_ssid_, subgroup);
                }

            case json_adapter_v2::consthash("dot11.device.min_tx_power"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, min_tx_power_);
                break;
            case json_adapter_v2::consthash("dot11.device.max_tx_power"):
                json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, max_tx_power_);
                break;

            case json_adapter_v2::consthash("dot11.device.supported_channels"):
                json_adapter_v2::json_encode_keyed_array<supported_channels_vec_iter_t_>{}(os, f.second.rename, opts, supported_channels_vec_.begin(), supported_channels_vec_.end());
                break;

            case json_adapter_v2::consthash("dot11.device.link_measurement_capable"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, link_measurement_capable_);
                break;
            case json_adapter_v2::consthash("dot11.device.neighbor_report_capable"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, neighbor_report_capable_);
                break;

            case json_adapter_v2::consthash("dot11.device.extended_capabilities"):
                json_adapter_v2::json_encode_keyed_array<extended_capabilities_vec_iter_t_>{}(os, f.second.rename, opts, extended_capabilities_vec_.begin(), extended_capabilities_vec_.end());
                break;

            case json_adapter_v2::consthash("dot11.device.beacon_fingerprint"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, beacon_fingerprint_);
                break;
            case json_adapter_v2::consthash("dot11.device.probe_fingerprint"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, probe_fingerprint_);
                break;
            case json_adapter_v2::consthash("dot11.device.response_fingerprint"):
                json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, response_fingerprint_);
                break;

            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;

}

