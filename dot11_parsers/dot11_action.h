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

#ifndef __DOT11_ACTION_H__
#define __DOT11_ACTION_H__

/* dot11 action frame
 *
 * dot11 action frames look a lot like management frames, but with a 
 * custom frame control header.
 *
 * Some of the IE tag parsing overlaps existing IE tag parsers
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_action {
public:
    class action_frame_common;
    class action_rmm;

    enum category_code_type_e {
        category_code_spectrum_management = 0,
        category_code_qos = 1,
        category_code_dls = 2,
        category_code_block_ack = 3,
        category_code_public = 4,
        category_code_radio_measurement = 5,
        category_code_fastbss = 6,
        category_code_ht = 7,
        category_code_sa_query = 8,
        category_code_public_protected = 9,
        category_code_wnm = 10,
        category_code_unprotected_wnm = 11,
        category_code_tlds = 12,
        category_code_mesh = 13,
        category_code_multihop = 14,
        category_code_self_protected = 15,
        category_code_dmg = 16,
        category_code_mgmt_notification = 17,
        category_code_fast_session_transfer = 18,
        category_code_robust_av_stream = 19,
        category_code_ubprotected_dmg = 20,
        category_code_vht = 21,
        category_code_vendor_specific_protected = 126,
        category_code_vendor_specific = 127
    };

    dot11_action() { }
    ~dot11_action() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    constexpr17 category_code_type_e category_code() const {
        return (category_code_type_e) m_category_code;
    }

    std::string action_rmm_data() const {
        return m_action_data;
    }

    std::shared_ptr<kaitai::kstream> action_rmm_data_stream() const {
        return m_action_data_stream;
    }

    std::shared_ptr<action_frame_common> action_frame() const {
        return m_action_frame;
    }

    std::shared_ptr<action_rmm> action_frame_rmm() const {
        if (category_code() == category_code_radio_measurement) 
            return std::static_pointer_cast<action_rmm>(action_frame());
        return NULL;
    }

    void reset() {
        m_category_code = 0;
        m_action_data = "";
        m_action_data_stream.reset();
        m_action_frame.reset();
    }

protected:
    uint8_t m_category_code;
    std::string m_action_data;
    std::shared_ptr<kaitai::kstream> m_action_data_stream;
    std::shared_ptr<action_frame_common> m_action_frame;

public:
    class action_frame_common {
    public:
        action_frame_common() {}
        virtual ~action_frame_common() {}
    };

    class action_rmm : public action_frame_common {
    public:
        enum rmm_action_type_e {
            rmm_action_measurement_req = 0,
            rmm_action_measurement_report = 1,
            rmm_action_link_measurement_req = 2,
            rmm_action_link_measurement_report = 3,
            rmm_action_neighbor_req = 4,
            rmm_action_neighbor_report = 5
        };

        action_rmm() {}
        virtual ~action_rmm() {}

        void parse(std::shared_ptr<kaitai::kstream> p_io);

        constexpr17 rmm_action_type_e rmm_action_code() const {
            return (rmm_action_type_e) m_rmm_action_code;
        }

        constexpr17 uint8_t dialog_token() const {
            return m_dialog_token;
        }

        std::string tags_data() const {
            return m_tags_data;
        }

        std::shared_ptr<kaitai::kstream> tags_data_stream() const {
            return m_tags_data_stream;
        }

        void reset() {
            m_rmm_action_code = 0;
            m_dialog_token = 0;
            m_tags_data = "";
            m_tags_data_stream.reset();
        }

    protected:
        uint8_t m_rmm_action_code;
        uint8_t m_dialog_token;
        std::string m_tags_data;
        std::shared_ptr<kaitai::kstream> m_tags_data_stream;

    };


};


#endif

