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

#ifndef __ENVIRONMENT_REPORT_H__
#define __ENVIRONMENT_REPORT_H__

#include "config.h"

#include <stdint.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "kis_external_packet.h"
#include "uuid.h"

// Datasource sensor reports (KIS_EXTERNAL_V3_KDS_ENVREPORT).  The parser only needs
// mpack, so it can be fuzzed on its own.

enum class env_kind : uint8_t {
    thermal = KIS_EXTERNAL_V3_ENV_KIND_THERMAL,
    fan = KIS_EXTERNAL_V3_ENV_KIND_FAN,
    battery = KIS_EXTERNAL_V3_ENV_KIND_BATTERY,
};

constexpr size_t env_max_id_len = 32;
constexpr size_t env_max_label_len = 64;
constexpr size_t env_max_readings = KIS_EXTERNAL_V3_ENV_MAX_READINGS;
constexpr uint32_t env_max_remaining_s = 30 * 24 * 60 * 60;

const char *env_kind_str(env_kind k);
const char *env_kind_units(env_kind k);

// 1-32 of [A-Za-z0-9_.-], not starting with '.'
bool env_valid_id(std::string_view id);

// Range check, and clamp a battery reading of up to 100.5 to 100; false if the
// value isn't finite or out of range for the kind
bool env_check_value(env_kind k, double& v);

// Printable ASCII only, other bytes as '?', cut to env_max_label_len
std::string env_munge_label(std::string_view s);

struct env_report_reading {
    std::string id;
    env_kind kind = env_kind::thermal;
    double value = 0;
    std::string label;

    // battery only
    uint8_t batt_state = KIS_EXTERNAL_V3_ENV_BATT_UNKNOWN;
    // -1 unknown
    int8_t ext_power = -1;
    // volts, 0 unknown
    double voltage = 0;
    // seconds, 0 unknown
    uint32_t remaining_s = 0;
};

struct env_report {
    std::vector<env_report_reading> readings;
    bool has_ts = false;
    uint64_t ts_s = 0;
    uint32_t ts_us = 0;
    // readings skipped for a bad id or value, an unknown kind or a duplicate id
    unsigned int skipped = 0;
};

// Parse a report; false, with err set, if the whole report is malformed
bool env_report_parse(std::string_view data, env_report& out, std::string& err);

// What the server does with datasource reports; the system monitor implements it.
// Registered as a global under this name so datasources need nothing else.
class env_report_sink {
public:
    static std::string global_name() { return "ENVIRONMENT_REPORT_SINK"; }

    virtual ~env_report_sink() { }

    // Report interval to ask datasources for, in ms; 0 when reports are off
    virtual uint32_t env_source_report_ms() const = 0;

    // A parsed report from a datasource.  Takes the sink's own lock; call with no
    // datasource lock held.  Returns false when the report was dropped.
    virtual bool env_source_report(const uuid& in_uuid, const std::string& in_name,
            const env_report& in_report) = 0;

    // A report which didn't parse, for the counters
    virtual void env_source_report_dropped() = 0;
};

#endif
