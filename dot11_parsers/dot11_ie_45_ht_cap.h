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
#include "multi_constexpr.h"

class dot11_ie_45_ht_cap {
public:
    class dot11_ie_45_rx_mcs;

    dot11_ie_45_ht_cap() { }
    ~dot11_ie_45_ht_cap() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint16_t ht_capabilities() const {
        return m_ht_capabilities;
    }

    constexpr17 uint8_t ampdu() const {
        return m_ampdu;
    }

    std::shared_ptr<dot11_ie_45_rx_mcs> mcs() const {
        return m_mcs;
    }

    constexpr17 uint16_t ht_extended_caps() const {
        return m_ht_extended_caps;
    }

    constexpr17 uint32_t txbf_caps() const {
        return m_txbf_caps;
    }

    constexpr17 uint8_t asel_caps() const {
        return m_asel_caps;
    }

    constexpr17 unsigned int ht_cap_ldpc() const {
        return ht_capabilities() & 0x01;
    }

    constexpr17 unsigned int ht_cap_40mhz_channel() const {
        return ht_capabilities() & 0x02;
    }

    constexpr17 unsigned int ht_cap_sm_powersave() const {
        return ht_capabilities() & 0x0C;
    }

    constexpr17 unsigned int ht_cap_greenfield() const {
        return ht_capabilities() & 0x10;
    }

    constexpr17 unsigned int ht_cap_20mhz_shortgi() const {
        return ht_capabilities() & 0x20;
    }

    constexpr17 unsigned int ht_cap_40mhz_shortgi() const {
        return ht_capabilities() & 0x40;
    }

    constexpr17 unsigned int ht_cap_tx_stbc() const {
        return ht_capabilities() & 0x80;
    }

    constexpr17 unsigned int ht_cap_rx_stbc() const {
        return ht_capabilities() & 0x300;
    }

    unsigned int ht_cap_delayed_block_ack() {
        return ht_capabilities() & 0x400;
    }

    constexpr17 unsigned int ht_cap_max_amsdu_len() const {
        return ht_capabilities() & 0x800;
    }

    constexpr17 unsigned int ht_cap_dss_40mhz() const {
        return ht_capabilities() & 0x1000;
    }

    constexpr17 unsigned int ht_cap_psmp_intolerant() const {
        return ht_capabilities() & 0x2000;
    }

    constexpr17 unsigned int ht_cap_40mhz_intolerant() const {
        return ht_capabilities() & 0x4000;
    }

    constexpr17 unsigned int ht_cap_lsig_txop() const {
        return ht_capabilities() & 0x8000;
    }

    void reset() {
        m_ht_capabilities = 0;
        m_ampdu = 0;
        m_mcs.reset();
        m_ht_extended_caps= 0;
        m_txbf_caps = 0;
        m_asel_caps = 0;
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
        dot11_ie_45_rx_mcs() { }
        ~dot11_ie_45_rx_mcs() { }

        void parse(kaitai::kstream& p_io);

        std::string rx_mcs() const {
            return m_rx_mcs;
        }

        constexpr17 uint16_t supported_data_rate() const {
            return m_supported_data_rate;
        }

        constexpr17 uint32_t txflags() const {
            return m_txflags;
        }

        void reset() {
            m_rx_mcs = "";
            m_supported_data_rate = 0;
            m_txflags = 0;
        }

    protected:
        std::string m_rx_mcs;
        uint16_t m_supported_data_rate;
        uint32_t m_txflags;
    };

};


#endif

