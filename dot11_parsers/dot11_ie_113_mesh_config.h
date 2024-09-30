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

#ifndef __DOT11_IE_113_MESH_CONFIG_H__
#define __DOT11_IE_113_MESH_CONFIG_H__ 

#include <string>
#include <memory>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_113_mesh_config {
public:
    dot11_ie_113_mesh_config() { }
    ~dot11_ie_113_mesh_config() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);
	void parse(const std::string& data);

    constexpr17 uint8_t path_select_pro() const {
        return m_path_select_proto;
    }

    constexpr17 uint8_t path_select_metric() const {
        return m_path_select_metric;
    }

    constexpr17 uint8_t congestion_control() const {
        return m_congestion_control;
    }

    constexpr17 uint8_t sync_method() const {
        return m_sync_method;
    }

    constexpr17 uint8_t auth_protocol() const {
        return m_auth_protocol;
    }

    constexpr17 uint8_t formation_info() const {
        return m_formation_info;
    }

    constexpr17 uint8_t capability_info() const {
        return m_capability_info;
    }
    
    constexpr17 bool connected_to_gate() const {
        return formation_info() & 0x01;
    }

    constexpr17 uint8_t num_peerings() const {
        return (formation_info() >> 1) & 0x3F;
    }

    constexpr17 bool connected_to_as() const {
        return formation_info() & 0x80;
    }

    constexpr17 bool accept_peerings() const {
        return capability_info() & 0x01;
    }

    constexpr17 bool mesh_forwarding() const {
        return capability_info() & 0x08;
    }

    void reset() {
        m_path_select_proto = 0;
        m_path_select_metric = 0;
        m_congestion_control = 0;
        m_sync_method = 0;
        m_auth_protocol = 0;
        m_formation_info = 0;
        m_capability_info = 0;
    }

protected:
    uint8_t m_path_select_proto;
    uint8_t m_path_select_metric;
    uint8_t m_congestion_control;
    uint8_t m_sync_method;
    uint8_t m_auth_protocol;

    uint8_t m_formation_info;
    uint8_t m_capability_info;

};


#endif /* ifndef DOT11_IE_113_MESH_CONFIG_H */
