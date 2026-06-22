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

#ifndef __DEVICETRACKER_COMPONENT_V2__
#define __DEVICETRACKER_COMPONENT_V2__

#include <string>

#include <stdint.h>

#include "json_adapter_v2.h"
#include "packet.h"
#include "packinfo_signal.h"

class kis_tracked_signal_data_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_signal_data_v2() :
        sig_type{0},
        last_signal{0},
        min_signal{0},
        max_signal{0},
        last_noise{0},
        min_noise{0},
        max_noise{0},
        maxseenrate{0},
        encodingset{0},
        carrierset{0} { }

    void append_signal(const kis_layer1_packinfo& lay1, bool update_rrd, time_t rrd_ts);
    void append_signal(const packinfo_sig_combo& in, bool update_rrd, time_t rrd_ts);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    std::string signal_type;
    unsigned int sig_type;
    int32_t last_signal, min_signal, max_signal;
    int32_t last_noise, min_noise, max_noise;
    double maxseenrate;
    uint64_t encodingset, carrierset;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_signal_data_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_signal_data_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

#endif /* __DEVICETRACKER_COMPONENT_V2__ */
