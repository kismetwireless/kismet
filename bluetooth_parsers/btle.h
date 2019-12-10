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

#ifndef __BLUETOOTH_BTLE_H__
#define __BLUETOOTH_BTLE_H__ 

#include <kaitai/kaitaistream.h>
#include <memory>
#include <string>
#include <vector>

#include "macaddr.h"
#include "multi_constexpr.h"

class bluetooth_btle {
public:
    class bluetooth_btle_advdata;
    typedef std::vector<std::shared_ptr<bluetooth_btle_advdata>> shared_advdata_vector;

    bluetooth_btle() { }
    ~bluetooth_btle() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    constexpr17 uint32_t access_address() const {
        return m_access_address;
    }

    constexpr17 uint16_t packet_header() const {
        return m_packet_header;
    }

    constexpr17 uint16_t pdu_type() const {
        return packet_header() & 0xF;
    }

    constexpr17 uint16_t pdu_adv_ind() const {
        return 0x0;
    }

    constexpr17 uint16_t pdu_adv_nonconn_ind() const {
        return 0x2;
    }

    constexpr17 uint16_t pdu_scan_rsp() const {
        return 0x4;
    }

    constexpr17 uint16_t pdu_adv_scan_ind() const {
        return 0x6;
    }

    constexpr17 bool is_rfu() const {
        return (packet_header() & 0x10);
    }

    constexpr17 uint8_t channel_algorithm() const {
        if (packet_header() & 0x20)
            return 2;
        return 1;
    }

    constexpr17 bool is_txaddr_random() const {
        return (packet_header() & 0x40);
    }

    constexpr17 uint8_t length() const {
        return m_length;
    }

    mac_addr advertising_address() const {
        return mac_addr(m_advertising_address.data(), 6);
    }

    std::shared_ptr<shared_advdata_vector> advertised_data() const {
        return m_advertised_data;
    }

protected:
    uint32_t m_access_address;
    uint8_t m_packet_header;
    uint8_t m_length;
    std::string m_advertising_address;

    std::shared_ptr<shared_advdata_vector> m_advertised_data;

public:
    class bluetooth_btle_advdata {
    public:
        bluetooth_btle_advdata() { }
        ~bluetooth_btle_advdata() { }

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        constexpr17 uint8_t length() const {
            return m_length;
        }

        constexpr17 uint8_t type() const {
            return m_type;
        }

        std::string data() const {
            return m_data;
        }

        std::shared_ptr<kaitai::kstream> data_stream() const {
            return m_data_stream;
        }

    protected:
        uint8_t m_length;
        uint8_t m_type;

        std::string m_data;
        std::shared_ptr<kaitai::kstream> m_data_stream;

    };
};


#endif /* ifndef BLUETOOTH_BTLE_H */
