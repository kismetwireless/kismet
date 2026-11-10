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

#ifndef __WIGLECSV_CRYPT_H__
#define __WIGLECSV_CRYPT_H__

#include <stdint.h>
#include <string>

#include "packet_ieee80211.h"

// The WiGLE CSV capabilities string for a Wi-Fi crypt set, shared by the wiglecsv log and
// kismetdb_to_wiglecsv.  WiGLE classifies these as the WiGLE Android app does: WPA3 for
// "[WPA3", "SAE" or "EAP_SUITE_B_192", WPA2 for "[WPA2" or "[RSN", WPA for "[WPA-", WEP
// for "[WEP".
inline std::string wiglecsv_crypt_string(uint64_t cryptset) {
    std::string ret;

    if (cryptset & dot11_crypt_akm_wps)
        ret += "[WPS] ";

    if (cryptset & dot11_crypt_general_wep)
        ret += "[WEP] ";

    if (cryptset & dot11_crypt_general_wpa) {
        std::string cryptver;

        if ((cryptset & dot11_crypt_pairwise_tkip) || (cryptset & dot11_crypt_group_tkip)) {
            if ((cryptset & dot11_crypt_pairwise_ccmp128) || (cryptset & dot11_crypt_group_ccmp128)) {
                cryptver = "CCMP+TKIP";
            } else {
                cryptver = "TKIP";
            }
        } else if (cryptset & dot11_crypt_pairwise_ccmp128) {
            cryptver = "CCMP";
        } else if (cryptset & dot11_crypt_pairwise_gcmp256) {
            cryptver = "GCMP-256";
        } else if (cryptset & dot11_crypt_pairwise_ccmp256) {
            cryptver = "CCMP-256";
        } else if (cryptset & dot11_crypt_pairwise_gcmp128) {
            cryptver = "GCMP-128";
        }

        constexpr uint64_t akm_psk = dot11_crypt_akm_psk | dot11_crypt_akm_psk_ft |
            dot11_crypt_akm_psk_sha256 | dot11_crypt_akm_psk_sha384 | dot11_crypt_akm_psk_sha384_ft;
        constexpr uint64_t akm_sae = dot11_crypt_akm_sae | dot11_crypt_akm_sae_ft;
        constexpr uint64_t akm_eap = dot11_crypt_akm_1x | dot11_crypt_akm_1x_ft |
            dot11_crypt_akm_1x_sha256 | dot11_crypt_akm_1x_ft_sha384;
        constexpr uint64_t akm_suiteb = dot11_crypt_akm_1x_suiteb_sha256 | dot11_crypt_akm_1x_suiteb_sha384;

        // One network may offer several, such as PSK and SAE in WPA3 transition mode
        std::string authver;
        const auto add_auth = [&authver](const char *a) {
            if (!authver.empty())
                authver += "+";
            authver += a;
        };

        if (cryptset & akm_psk)
            add_auth("PSK");
        if (cryptset & akm_sae)
            add_auth("SAE");
        if (cryptset & akm_eap)
            add_auth("EAP");
        if (cryptset & akm_suiteb)
            add_auth("EAP_SUITE_B_192");
        if (cryptset & dot11_crypt_akm_owe)
            add_auth("OWE");
        if (authver.empty())
            authver = "UNKNOWN";

        // The general WPA3 bit is also set by the WPA2 management frame protection ciphers,
        // so only the key management decides a network is WPA3 alone
        const bool wpa3_only = (cryptset & (akm_sae | akm_suiteb | dot11_crypt_akm_owe)) &&
            !(cryptset & (akm_psk | akm_eap));

        if ((cryptset & dot11_crypt_general_wpa2) && (cryptset & dot11_crypt_general_wpa1)) {
            ret += "[WPA-" + authver + "-" + cryptver + "] ";
            ret += "[WPA2-" + authver + "-" + cryptver + "] ";
        } else if (wpa3_only) {
            ret += "[WPA3-" + authver + "-" + cryptver + "] ";
        } else if (cryptset & dot11_crypt_general_wpa2) {
            ret += "[WPA2-" + authver + "-" + cryptver + "] ";
        } else {
            ret += "[WPA-" + authver + "-" + cryptver + "] ";
        }
    }

    if (!ret.empty())
        ret.pop_back();

    return ret;
}

#endif
