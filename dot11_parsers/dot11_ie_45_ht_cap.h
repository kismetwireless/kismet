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

#ifndef __DOT11_IE_45_H__
#define __DOT11_IE_45_H__

/* dot11 IE 45: HT
 *
 * 802.11n rate and capabilities
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>

class dot11_ie_45_ht_cap {
public:
    class dot11_ie_45_rx_mcs;

    dot11_ie_45_ht_cap() { }
    ~dot11_ie_45_ht_cap() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    uint16_t ht_capabilities() {
        return m_ht_capabilities;
    }

    uint8_t ampdu() {
        return m_ampdu;
    }

    std::shared_ptr<dot11_ie_45_rx_mcs> mcs() {
        return m_mcs;
    }

    uint16_t ht_extended_caps() {
        return m_ht_extended_caps;
    }

    uint32_t txbf_caps() {
        return m_txbf_caps;
    }

    uint8_t asel_caps() {
        return m_asel_caps;
    }

    unsigned int ht_cap_ldpc() {
        return ht_capabilities() & 0x01;
    }

    unsigned int ht_cap_40mhz_channel() {
        return ht_capabilities() & 0x02;
    }

    unsigned int ht_cap_sm_powersave() {
        return ht_capabilities() & 0x0C;
    }

    unsigned int ht_cap_greenfield() {
        return ht_capabilities() & 0x10;
    }

    unsigned int ht_cap_20mhz_shortgi() {
        return ht_capabilities() & 0x20;
    }

    unsigned int ht_cap_40mhz_shortgi() {
        return ht_capabilities() & 0x40;
    }

    unsigned int ht_cap_tx_stbc() {
        return ht_capabilities() & 0x80;
    }

    unsigned int ht_cap_rx_stbc() {
        return ht_capabilities() & 0x300;
    }

    unsigned int ht_cap_delayed_block_ack() {
        return ht_capabilities() & 0x400;
    }

    unsigned int ht_cap_max_amsdu_len() {
        return ht_capabilities() & 0x800;
    }

    unsigned int ht_cap_dss_40mhz() {
        return ht_capabilities() & 0x1000;
    }

    unsigned int ht_cap_psmp_intolerant() {
        return ht_capabilities() & 0x2000;
    }

    unsigned int ht_cap_40mhz_intolerant() {
        return ht_capabilities() & 0x4000;
    }

    unsigned int ht_cap_lsig_txop() {
        return ht_capabilities() & 0x8000;
    }

protected:
    uint16_t m_ht_capabilities;
    uint8_t m_ampdu;
    std::shared_ptr<dot11_ie_45_rx_mcs> m_mcs;
    uint16_t m_ht_extended_caps;
    uint32_t m_txbf_caps;
    uint8_t m_asel_caps;

public:
    class dot11_ie_45_rx_mcs {
    public:
        dot11_ie_45_rx_mcs() {

        }

        ~dot11_ie_45_rx_mcs() {

        }

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        std::string rx_mcs() {
            return m_rx_mcs;
        }

        uint16_t supported_data_rate() {
            return m_supported_data_rate;
        }

        uint32_t txflags() {
            return m_txflags;
        }


    protected:
        std::string m_rx_mcs;
        uint16_t m_supported_data_rate;
        uint32_t m_txflags;
    };

};


#endif

