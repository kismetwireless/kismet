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

#ifndef __DOT11_S1G_H__
#define __DOT11_S1G_H__

#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

#include "macaddr.h"

class dot11_s1g {
public:
    dot11_s1g() { }
    ~dot11_s1g() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
    void parse(kaitai::kstream& p_io);
    void parse(const std::string& data);

    constexpr uint16_t framecontrol() const {
        return m_framecontrol;
    }

    constexpr unsigned int fc_version() const {
        return (framecontrol() & 0x0300) >> 8;
    }

    constexpr unsigned int fc_type() const {
        return (framecontrol() & 0x0C00) >> 10;
    }

    constexpr unsigned int fc_subtype() const {
        return (framecontrol() & 0xF000) >> 12;
    }

    constexpr unsigned int fc_next_tbtt_present() const {
        return (framecontrol() & 0x01);
    }

    constexpr unsigned int fc_compressed_ssid_present() const {
        return (framecontrol() & 0x02) >> 1;
    }

    constexpr unsigned int fc_ano_present() const {
        return (framecontrol() & 0x04) >> 2;
    }

    constexpr unsigned int fc_bss_bw() const {
        return (framecontrol() & 0x38) >> 3;
    }

    constexpr unsigned int fc_security() const {
        return (framecontrol() & 0x40) >> 6;
    }

    constexpr unsigned int fc_ap_pm() const {
        return (framecontrol() & 0x80) >> 7;
    }

    constexpr unsigned int duration() const {
        return (m_duration & 0x7FFF);
    }

    const std::string& addr0() const {
        return m_addr0;
    }

    const std::string& addr1() const {
        return m_addr1;
    }

    const mac_addr addr0_mac() const {
        return mac_addr(m_addr0.data(), 6);
    }

    const mac_addr addr1_mac() const {
        return mac_addr(m_addr1.data(), 6);
    }

    constexpr uint32_t fixparm_ts() const {
        return m_fixparm_ts;
    }

    constexpr uint8_t fixparm_change_sequence() const {
        return m_fixparm_cs;
    }

    constexpr uint32_t fixparm_next_tbtt() const {
        return m_fixparm_next_tbtt;
    }

    constexpr uint32_t fixparm_compressed_ssid() const {
        return m_fixparm_compressed_ssid;
    }

    constexpr uint8_t fixparm_ano() const {
        return m_fixparm_ano;
    }

    const std::string& tag_data() const {
        return m_tag_data;
    }

protected:
    uint16_t m_framecontrol;
    uint16_t m_duration;

    std::string m_addr0;
    std::string m_addr1;

    uint32_t m_fixparm_ts;
    uint8_t m_fixparm_cs;
    uint32_t m_fixparm_next_tbtt;
    uint32_t m_fixparm_compressed_ssid;
    uint8_t m_fixparm_ano;

    std::string m_tag_data;
};

#endif /* __DOT11_S1G_H__ */
