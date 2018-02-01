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

class dot11_ie_48_rsn {
public:
    class dot11_ie_48_rsn_rsn_cipher;
    class dot11_ie_48_rsn_rsn_management;

    typedef std::vector<std::shared_ptr<dot11_ie_48_rsn_rsn_cipher> > shared_rsn_cipher_vector;
    typedef std::vector<std::shared_ptr<dot11_ie_48_rsn_rsn_management> > shared_rsn_management_vector;

    dot11_ie_48_rsn() { }
    ~dot11_ie_48_rsn() { }

    void parse(kaitai::kstream *p_io);

    uint16_t rsn_version() {
        return m_rsn_version;
    }

    std::shared_ptr<dot11_ie_48_rsn_rsn_cipher> group_cipher() {
        return m_group_cipher;
    }

    uint16_t pairwise_count() {
        return m_pairwise_count;
    }

    std::shared_ptr<shared_rsn_cipher_vector> pairwise_ciphers() {
        return m_pairwise_ciphers;
    }

    uint16_t akm_count() {
        return m_akm_count;
    }

    std::shared_ptr<shared_rsn_management_vector> akm_ciphers() {
        return m_akm_ciphers;
    }

protected:
    uint16_t m_rsn_version;
    std::shared_ptr<dot11_ie_48_rsn_rsn_cipher> m_group_cipher;
    uint16_t m_pairwise_count;
    std::shared_ptr<shared_rsn_cipher_vector> m_pairwise_ciphers;
    uint16_t m_akm_count;
    std::shared_ptr<shared_rsn_management_vector> m_akm_ciphers;

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
            rsn_bip = 6,
            rsn_no_group = 7,
            rsn_gcmp = 8
        };

        dot11_ie_48_rsn_rsn_cipher() { }

        ~dot11_ie_48_rsn_rsn_cipher() { }

        void parse(kaitai::kstream *p_io);

        std::string cipher_suite_oui() {
            return m_cipher_suite_oui;
        }

        rsn_cipher_type cipher_type() {
            return (rsn_cipher_type) m_cipher_type;
        }


    protected:
        std::string m_cipher_suite_oui;
        uint8_t m_cipher_type;
    };

    class dot11_ie_48_rsn_rsn_management {
    public:
        enum rsn_management {
            mgmt_none = 0,
            mgmt_wpa = 1,
            mgmt_psk = 2,
            mgmt_ft_dot1x = 3,
            mgmt_ft_psk = 4,
            mgmt_wpa_sha256 = 5,
            mgmt_psk_sha256 = 6,
            mgmt_tdls_tpk = 7
        };

        dot11_ie_48_rsn_rsn_management() { }
        ~dot11_ie_48_rsn_rsn_management() { }

        void parse(kaitai::kstream *p_io);

        std::string management_suite_oui() {
            return m_management_suite_oui;
        }

        rsn_management management_type() {
            return (rsn_management) m_management_type;
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

    void parse(kaitai::kstream *p_io);

    uint16_t rsn_version() {
        return m_rsn_version;
    }

    std::string group_cipher() {
        return m_group_cipher;
    }

    uint16_t pairwise_count() {
        return m_pairwise_count;
    }

protected:
    uint16_t m_rsn_version;
    std::string m_group_cipher;
    uint16_t m_pairwise_count;
};


#endif

