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

#ifndef __DOT11_IE_127_EXTENDED_CAPS_H__
#define __DOT11_IE_127_EXTENDED_CAPS_H__

/* dot11 ie 127 extended capabilities 
 *
 * Extended client capabilities
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_127_extended {
public:
    dot11_ie_127_extended() {
        m_octet1 = 0;
        m_octet2 = 0;
        m_octet3 = 0;
        m_octet4 = 0;
        m_octet5 = 0;
        m_octet6 = 0;
        m_octet7 = 0;
        m_octet8 = 0;
    }
    ~dot11_ie_127_extended() { }

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

    constexpr17 uint8_t octet6() const {
        return m_octet6;
    }

    constexpr17 uint8_t octet7() const {
        return m_octet7;
    }

    constexpr17 uint8_t octet8() const {
        return m_octet8;
    }

    constexpr17 bool coexist_management() const {
        return m_octet1 & 0x01;
    }

    constexpr17 bool extended_channel_switching() const {
        return m_octet1 & 0x04;
    }

    constexpr17 bool s_psmp() const {
        return m_octet1 & 0x40;
    }

    constexpr17 bool event() const {
        return m_octet1 & 0x80;
    }

    constexpr17 bool diagnostics() const {
        return m_octet2 & 0x01;
    }

    constexpr17 bool multicast_diagnostics() const {
        return m_octet2 & 0x02;
    }

    constexpr17 bool location_tracking() const {
        return m_octet2 & 0x04;
    }

    constexpr17 bool fms() const {
        return m_octet2 & 0x08;
    }

    constexpr17 bool proxy_arp() const {
        return m_octet2 & 0x10;
    }

    constexpr17 bool collocated_interference_reporting() const {
        return m_octet2 & 0x20;
    }

    constexpr17 bool civic_location() const {
        return m_octet2 & 0x40;
    }

    constexpr17 bool geospatial_location() const {
        return m_octet2 & 0x80;
    }

    constexpr17 bool tfs() const {
        return m_octet3 & 0x01;
    }

    constexpr17 bool wnm_sleep_mode() const {
        return m_octet3 & 0x02;
    }

    constexpr17 bool tim_broadcast() const {
        return m_octet3 & 0x04;
    }

    constexpr17 bool bss_transition() const {
        return m_octet3 & 0x08;
    }

    constexpr17 bool qos_traffic() const {
        return m_octet3 & 0x10;
    }

    constexpr17 bool ac_station_count() const {
        return m_octet3 & 0x20;
    }

    constexpr17 bool multi_bssid() const {
        return m_octet3 & 0x40;
    }

    constexpr17 bool timing_measurement() const {
        return m_octet3 & 0x80;
    }

    constexpr17 bool channel_usage() const {
        return m_octet4 & 0x01;
    }

    constexpr17 bool ssid_list() const {
        return m_octet4 & 0x02;
    }

    constexpr17 bool dms() const {
        return m_octet4 & 0x04;
    }

    constexpr17 bool utc_tsf_offset() const {
        return m_octet4 & 0x08;
    }

    constexpr17 bool tpu_buffer_sta() const {
        return m_octet4 & 0x10;
    }

    constexpr17 bool tdls_peer_psm() const {
        return m_octet4 & 0x20;
    }

    constexpr17 bool tdls_channel_switching() const {
        return m_octet4 & 0x40;
    }

    constexpr17 bool interworking() const {
        return m_octet4 & 0x80;
    }

    constexpr17 bool qos_map() const {
        return m_octet5 & 0x01;
    }

    constexpr17 bool ebr() const {
        return m_octet5 & 0x02;
    }

    constexpr17 bool sspn() const {
        return m_octet5 & 0x04;
    }

    constexpr17 bool msgcf() const {
        return m_octet5 & 0x10;
    }

    constexpr17 bool tdls_supported() const {
        return m_octet5 & 0x20;
    }

    constexpr17 bool tdls_prohibited() const {
        return m_octet5 & 0x40;
    }

    constexpr17 bool tdls_channel_switching_prohibited() const {
        return m_octet5 & 0x80;
    }

    constexpr17 bool reject_unadmitted_frame() const {
        return m_octet6 & 0x01;
    }

    constexpr17 uint8_t service_interval_granularity() const {
        return (m_octet6 & 0x0E) >> 1;
    }

    constexpr17 bool identifier_location() const {
        return m_octet6 & 0x10;
    }

    constexpr17 bool uapsd_coexistence() const {
        return m_octet6 & 0x20;
    }

    constexpr17 bool wmm_notification() const {
        return m_octet6 & 0x40;
    }

    constexpr17 bool qab() const {
        return m_octet6 & 0x80;
    }

    constexpr17 bool utf8_ssid() const {
        return m_octet7 & 0x01;
    }

    constexpr17 bool qmfactivated() const {
        return m_octet7 & 0x02;
    }

    constexpr17 bool qmfreconfigurationactivated() const {
        return m_octet7 & 0x04;
    }

    constexpr17 bool robust_av_streaming() const {
        return m_octet7 & 0x08;
    }

    constexpr17 bool advanced_gcr() const {
        return m_octet7 & 0x10;
    }

    constexpr17 bool mesh_gcr() const {
        return m_octet7 & 0x20;
    }

    constexpr17 bool scs() const {
        return m_octet7 & 0x40;
    }

    constexpr17 bool qload_report() const {
        return m_octet7 & 0x80;
    }

    constexpr17 bool alternate_ecda() const {
        return m_octet8 & 0x01;
    }

    constexpr17 bool unprotected_txop() const {
        return m_octet8 & 0x02;
    }

    constexpr17 bool protected_txop() const {
        return m_octet8 & 0x04;
    }

    constexpr17 bool protected_qload_report() const {
        return m_octet8 & 0x10;
    }

    constexpr17 bool tdls_wider_bandwidth() const {
        return m_octet8 & 0x20;
    }

    constexpr17 bool operating_mode_notification() const {
        return m_octet8 & 0x40;
    }

    constexpr17 uint8_t max_msdus() const {
        return m_octet8 & 0x80;
    }

protected:
    uint8_t m_octet1;
    uint8_t m_octet2;
    uint8_t m_octet3;
    uint8_t m_octet4;
    uint8_t m_octet5;
    uint8_t m_octet6;
    uint8_t m_octet7;
    uint8_t m_octet8;
};


#endif

