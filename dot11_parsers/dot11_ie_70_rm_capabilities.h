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

#ifndef __DOT11_IE_70_RM_CAPS_H__
#define __DOT11_IE_70_RM_CAPS_H__

/* dot11 ie 70 RM capabilities 
 *
 * Measurement capabilities
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_70_rm_cap {
public:
    dot11_ie_70_rm_cap() {
        m_octet1 = 0;
        m_octet2 = 0;
        m_octet3 = 0;
        m_octet4 = 0;
        m_octet5 = 0;
    }
    ~dot11_ie_70_rm_cap() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    constexpr17 uint8_t octet1() const {
        return m_octet1;
    }

    constexpr17 uint8_t octet2() const {
        return m_octet2;
    }

    constexpr17 uint8_t octet3() const {
        return m_octet3;
    }

    constexpr17 uint8_t octet4() const {
        return m_octet4;
    }

    constexpr17 uint8_t octet5() const {
        return m_octet5;
    }

    constexpr17 bool link_measurement() const {
        return m_octet1 & 0x01;
    }

    constexpr17 bool neighbor_report() const {
        return m_octet1 & 0x02;
    }

    constexpr17 bool parallel_measurements() const {
        return m_octet1 & 0x04;
    }

    constexpr17 bool repeated_measurements() const {
        return m_octet1 & 0x08;
    }

    constexpr17 bool beacon_passive_measurement() const {
        return m_octet1 & 0x10;
    }

    constexpr17 bool beacon_active_measurement() const {
        return m_octet1 & 0x20;
    }

    constexpr17 bool beacon_table_measurement() const {
        return m_octet1 & 0x40;
    }

    constexpr17 bool beacon_measurement_reporting_conditions() const {
        return m_octet1 & 0x80;
    }

    constexpr17 bool frame_measurement() const {
        return m_octet2 & 0x01;
    }

    constexpr17 bool channel_load_measurement() const {
        return m_octet2 & 0x02;
    }

    constexpr17 bool noise_histogram_measurement() const {
        return m_octet2 & 0x04;
    }

    constexpr17 bool statistics_measurement() const {
        return m_octet2 & 0x08;
    }

    constexpr17 bool lci_measurement() const {
        return m_octet2 & 0x10;
    }

    constexpr17 bool lci_azimuth() const {
        return m_octet2 & 0x20;
    }

    constexpr17 bool transmit_stream_measurement() const {
        return m_octet2 & 0x40;
    }

    constexpr17 bool triggered_transmit_stream_measurement() const {
        return m_octet2 & 0x80;
    }

    constexpr17 bool ap_channel_report() const {
        return m_octet3 & 0x01;
    }

    constexpr17 bool rm_mib_capable() const {
        return m_octet3 & 0x02;
    }

    constexpr17 uint8_t operating_channel_max_duration() const {
        return (m_octet3 & 0x38) >> 2;
    }

    constexpr17 uint8_t nonoperating_channel_max_duration() const {
        return (m_octet3 & 0xE0) >> 5;
    }

    constexpr17 uint8_t measurement_pilot() const {
        return (m_octet4 & 7);
    }

    constexpr17 bool measurement_pilot_info() const {
        return m_octet4 & 0x08;
    }

    constexpr17 bool neighbor_report_tsf_offset() const {
        return m_octet4 & 0x10;
    }

    constexpr17 bool rcpi_measurement() const {
        return m_octet4 & 0x20;
    }

    constexpr17 bool rsni_measurement() const {
        return m_octet4 & 0x40;
    }

    constexpr17 bool bss_average_access_delay() const {
        return m_octet4 & 0x80;
    }

    constexpr17 bool bss_available_admission_capacity() const {
        return m_octet5 & 0x01;
    }

    constexpr17 bool antenna() const {
        return m_octet5 & 0x02;
    }

protected:
    uint8_t m_octet1;
    uint8_t m_octet2;
    uint8_t m_octet3;
    uint8_t m_octet4;
    uint8_t m_octet5;
};


#endif

