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

#ifndef __BATTERY_H__
#define __BATTERY_H__

#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

struct kis_battery_info {
	int percentage, charging, ac, remaining_sec;
};

int fetch_battery_info(kis_battery_info *out_info);

enum class kis_battery_state : uint8_t {
    unknown = 0,
    charging = 1,
    discharging = 2,
    full = 3,
    not_charging = 4,
};

const char *kis_battery_state_str(kis_battery_state s);

// One system battery from /sys/class/power_supply
struct kis_battery_reading {
    // power_supply name, [A-Za-z0-9_.-], at most 32 characters
    std::string name;
    // 0-100, -1 when unknown
    int percentage = -1;
    kis_battery_state state = kis_battery_state::unknown;
    // volts, 0 when unknown
    double voltage = 0;
    // seconds at the present rate, 0 when unknown
    int64_t remaining_sec = 0;

    // Charge in mAh, converted from energy when needed; -1 when unknown
    int64_t remaining_capacity = -1;
    int64_t last_capacity = -1;
    int64_t present_rate = -1;
};

// System batteries (type Battery, not scope Device) under a power_supply class
// directory, sorted by name.  ext_online is 1 when a non-battery supply is online,
// 0 when one reports offline and none online, -1 when none report.
void fetch_linux_power_supplies(const std::string& root, std::vector<kis_battery_reading>& batteries,
        int& ext_online);

// Combine the batteries into the legacy summary
void aggregate_battery_info(const std::vector<kis_battery_reading>& batteries, int ext_online,
        kis_battery_info *out);

#endif

