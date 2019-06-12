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

#ifndef __BLUETOOTH_RADIO_INFO_H__
#define __BLUETOOTH_RADIO_INFO_H__

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "macaddr.h"
#include "multi_constexpr.h"

class bluetooth_radio_info {
public:
    bluetooth_radio_info() { }
    ~bluetooth_radio_info() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    constexpr17 uint8_t rf_channel() const {
        return m_rf_channel;
    }
    
    constexpr17 uint8_t dbm_signal() const {
        return m_dbm_signal;
    }

    constexpr17 uint8_t dbm_noise() const {
        return m_dbm_noise;
    }

    constexpr17 uint8_t address_offenses() const {
        return m_address_offenses;
    }

    mac_addr reference_access_address() const {
        return m_ref_access_address;
    }

    constexpr17 uint16_t flags() const {
        return m_flags;
    }

    constexpr17 bool flag_whitened() const {
        return flags() & 0x01;
    }

    constexpr17 bool flag_signal_valid() const {
        return flags() & 0x02;
    }

    constexpr17 bool flag_noise_valid() const {
        return flags() & 0x04;
    }

    constexpr17 bool flag_decrypted() const {
        return flags() & 0x08;
    }

    constexpr17 bool flag_access_offenses_valid() const {
        return flags() & 0x10;
    }

    constexpr17 bool flag_channel_aliased() const {
        return flags() & 0x20;
    }

    constexpr17 bool flag_crc_checked() const {
        return flags() & 0x400;
    }

    constexpr17 bool flag_crc_valid() const {
        return flags() & 0x800;
    }

    constexpr17 bool flag_mic_checked() const {
        return flags() & 0x1000;
    }

    constexpr17 bool flag_mic_valid() const {
        return flags() & 0x2000;
    }

protected:
    uint8_t m_rf_channel;
    uint8_t m_dbm_signal;
    uint8_t m_dbm_noise;
    uint8_t m_address_offenses;
    mac_addr m_ref_access_address;
    uint16_t m_flags;

};


#endif

