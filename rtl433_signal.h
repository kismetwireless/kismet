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

#ifndef __RTL433_SIGNAL_H__
#define __RTL433_SIGNAL_H__

#include "freq_bounds.h"
#include "nlohmann/json.hpp"
#include "packet.h"
#include "rtl433_json.h"

namespace rtl433_json {
    // rtl_433 -M level gives dBFS, not dBm, so it goes on as an rssi-type signal.  It
    // replaces the levels of any signal block the source sent with the record, so the
    // packet never carries dBm and rssi values together.  Without usable levels the
    // source's block, if any, is left as it came.
    inline void apply_levels(const nlohmann::json& json, kis_layer1_packinfo& sig, double freq_khz) {
        auto l = levels(json);

        if (!l)
            return;

        sig.data_ok = true;
        sig.signal_type = kis_l1_signal_type_rssi;
        sig.signal_rssi = l->rssi;
        sig.noise_rssi = l->noise;
        sig.signal_dbm = 0;
        sig.noise_dbm = 0;
        sig.antenna_signal_map.clear();

        if (freq_bounds::khz_valid(freq_khz))
            sig.freq_khz = freq_khz;
    }
}

#endif
