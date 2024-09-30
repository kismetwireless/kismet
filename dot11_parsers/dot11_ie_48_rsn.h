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

#ifndef __DOT11_IE_48_RSN_H__
#define __DOT11_IE_48_RSN_H__

/* Parse dot11 IE 48 - RSN
 *
 * RSN (Robust Security Network) defines 802.11i WPA/WPA2 encryption
 *
 * Implement an additional partial record parser to extract broken RSN
 * which may be used in some exploits
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_48_rsn {
public:
    class dot11_ie_48_rsn_rsn_cipher;
    class dot11_ie_48_rsn_rsn_management;

    typedef std::vector<std::shared_ptr<dot11_ie_48_rsn_rsn_cipher> > shared_rsn_cipher_vector;
    typedef std::vector<std::shared_ptr<dot11_ie_48_rsn_rsn_management> > shared_rsn_management_vector;

    dot11_ie_48_rsn() { }
    ~dot11_ie_48_rsn() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint16_t rsn_version() const {
        return m_rsn_version;
    }

    std::shared_ptr<dot11_ie_48_rsn_rsn_cipher> group_cipher() const {
        return m_group_cipher;
    }

    constexpr17 uint16_t pairwise_count() const {
        return m_pairwise_count;
    }

    std::shared_ptr<shared_rsn_cipher_vector> pairwise_ciphers() const {
        return m_pairwise_ciphers;
    }

    constexpr17 uint16_t akm_count() const {
        return m_akm_count;
    }

    std::shared_ptr<shared_rsn_management_vector> akm_ciphers() const {
        return m_akm_ciphers;
    }

    constexpr17 uint16_t rsn_capabilities() const {
        return m_rsn_capabilities;
    }

    constexpr17 bool rsn_capability_preauth() const {
        return rsn_capabilities() & 0x01;
    }

    constexpr17 bool rsn_capability_wep_pairwise() const {
        return rsn_capabilities() & 0x02;
    }

    constexpr17 uint8_t rsn_capability_ptksa_replay() const {
        return (rsn_capabilities() & 0x0C) >> 2;
    }

    constexpr17 uint8_t rsn_capability_gtksa_replay() const {
        return (rsn_capabilities() & 0x30) >> 4;
    }

    constexpr17 bool rsn_capability_mfp_required() const {
        return (rsn_capabilities() & 0x40);
    }

    constexpr17 bool rsn_capability_mfp_supported() const {
        return (rsn_capabilities() & 0x80);
    }

    void reset() {
        m_rsn_version = 0;
        m_group_cipher.reset();
        m_pairwise_count = 0;
        m_pairwise_ciphers.reset();
        m_akm_count = 0;
        m_akm_ciphers.reset();
        m_rsn_capabilities = 0;
    }

protected:
    uint16_t m_rsn_version;
    std::shared_ptr<dot11_ie_48_rsn_rsn_cipher> m_group_cipher;
    uint16_t m_pairwise_count;
    std::shared_ptr<shared_rsn_cipher_vector> m_pairwise_ciphers;
    uint16_t m_akm_count;
    std::shared_ptr<shared_rsn_management_vector> m_akm_ciphers;
    uint16_t m_rsn_capabilities;

public:
    class dot11_ie_48_rsn_rsn_cipher {
    public:
        enum rsn_cipher_type {
            rsn_cipher_none = 0,
            rsn_wep_40 = 1,
            rsn_tkip = 2,
            rsn_aes_ocb = 3,
            rsn_aes_ccm = 4,
            rsn_wep_104 = 5,
            rsn_bip_128 = 6,
            rsn_no_group = 7,
            rsn_gcmp_128 = 8,
			rsn_gcmp_256 = 9,
			rsn_ccmp_256 = 10,
			rsn_bip_gmac_128 = 11,
			rsn_bip_gmac_256 = 12,
			rsn_bip_cmac_256 = 13
        };

        dot11_ie_48_rsn_rsn_cipher() { }
        ~dot11_ie_48_rsn_rsn_cipher() { }

        void parse(kaitai::kstream& p_io);

        const std::string& cipher_suite_oui() const {
            return m_cipher_suite_oui;
        }

        constexpr17 rsn_cipher_type cipher_type() const {
            return (rsn_cipher_type) m_cipher_type;
        }

        void reset() {
            m_cipher_suite_oui = "";
            m_cipher_type = 0;
        }

    protected:
        std::string m_cipher_suite_oui;
        uint8_t m_cipher_type;
    };

    class dot11_ie_48_rsn_rsn_management {
    public:
        enum rsn_management {
			mgmt_none = 0,
			mgmt_1x = 1,
			mgmt_psk = 2,
			mgmt_ft_dot1x = 3,
			mgmt_ft_psk = 4,
			mgmt_1x_sha256 = 5,
			mgmt_psk_sha256 = 6,
			mgmt_tdls_sha256 = 7,
			mgmt_sae_sha256 = 8,
			mgmt_ft_sae = 9,
			mgmt_ap_peerkey = 10,
			mgmt_1x_sha256_suite_b = 11,
			mgmt_1x_sha384_suite_b = 12,
			mgmt_ft_dot1x_sha384 = 13,
			mgmt_fils_sha256 = 14,
			mgmt_fils_sha384 = 15,
			mgmt_ft_fils_sha256 = 16,
			mgmt_ft_fils_sha384 = 17,
			mgmt_owe = 18,
			mgmt_ft_psk_sha384 = 19,
			mgmt_psk_sha384 = 20,
			mgmt_pasn = 21
        };

        dot11_ie_48_rsn_rsn_management() { }
        ~dot11_ie_48_rsn_rsn_management() { }

        void parse(kaitai::kstream& p_io);

        constexpr17 const std::string& management_suite_oui() const {
            return m_management_suite_oui;
        }

        constexpr17 rsn_management management_type() const {
            return (rsn_management) m_management_type;
        }

        void reset() {
            m_management_suite_oui = "";
            m_management_type = 0;
        }

    protected:
        std::string m_management_suite_oui;
        uint8_t m_management_type;
    };

};

class dot11_ie_48_rsn_partial {
public:
    dot11_ie_48_rsn_partial() { }
    ~dot11_ie_48_rsn_partial() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint16_t rsn_version() const {
        return m_rsn_version;
    }

    constexpr17 const std::string& group_cipher() const {
        return m_group_cipher;
    }

    constexpr17 uint16_t pairwise_count() const {
        return m_pairwise_count;
    }

    void reset() {
        m_rsn_version = 0;
        m_group_cipher = "";
        m_pairwise_count = 0;
    }

protected:
    uint16_t m_rsn_version;
    std::string m_group_cipher;
    uint16_t m_pairwise_count;
};


#endif

