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

#include "config.h"

#include <cmath>

#include "environment_report.h"
#include "mpack/mpack.h"
#include "mpack/mpack_cpp.h"

const char *env_kind_str(env_kind k) {
    switch (k) {
        case env_kind::thermal:
            return "thermal";
        case env_kind::fan:
            return "fan";
        case env_kind::battery:
            return "battery";
    }

    return "unknown";
}

const char *env_kind_units(env_kind k) {
    switch (k) {
        case env_kind::thermal:
            return "C";
        case env_kind::fan:
            return "RPM";
        case env_kind::battery:
            return "%";
    }

    return "";
}

bool env_valid_id(std::string_view id) {
    if (id.empty() || id.length() > env_max_id_len || id[0] == '.')
        return false;

    for (auto ch : id) {
        const auto c = static_cast<unsigned char>(ch);
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '_' || c == '.' || c == '-'))
            return false;
    }

    return true;
}

bool env_check_value(env_kind k, double& v) {
    if (!std::isfinite(v))
        return false;

    switch (k) {
        case env_kind::thermal:
            return v >= -100.0 && v <= 400.0;
        case env_kind::fan:
            return v >= 0.0 && v <= 1000000.0;
        case env_kind::battery:
            if (v < 0.0 || v > 100.5)
                return false;
            if (v > 100.0)
                v = 100.0;
            return true;
    }

    return false;
}

std::string env_munge_label(std::string_view s) {
    std::string r(s.substr(0, env_max_label_len));

    for (auto& ch : r) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c > 0x7e)
            ch = '?';
    }

    return r;
}

bool env_report_parse(std::string_view data, env_report& out, std::string& err) {
    out = env_report();

    mpack_tree_raii tree;
    mpack_tree_init_data(&tree, data.data(), data.length());

    if (!mpack_tree_try_parse(&tree)) {
        err = "unparseable report";
        return false;
    }

    auto root = mpack_tree_root(&tree);

    if (mpack_node_type(root) != mpack_type_map) {
        err = "report is not a map";
        return false;
    }

    auto sensors = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_SENSORS);
    const size_t n = mpack_node_array_length(sensors);

    auto ts_s_n = mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_S);
    auto ts_us_n = mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_US);

    if (!mpack_node_is_missing(ts_s_n)) {
        out.has_ts = true;
        out.ts_s = mpack_node_u64(ts_s_n);
        if (!mpack_node_is_missing(ts_us_n))
            out.ts_us = mpack_node_u32(ts_us_n);
        if (out.ts_us >= 1000000)
            out.has_ts = false;
    }

    if (mpack_tree_error(&tree) != mpack_ok) {
        err = "malformed report";
        return false;
    }

    if (n > env_max_readings) {
        err = "too many readings";
        return false;
    }

    for (size_t i = 0; i < n; i++) {
        auto s = mpack_node_array_at(sensors, i);

        if (mpack_node_type(s) != mpack_type_map) {
            err = "malformed reading";
            return false;
        }

        auto id_n = mpack_node_map_uint(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_ID);
        const char *id_s = mpack_node_str(id_n);
        const size_t id_len = mpack_node_strlen(id_n);

        const uint8_t kind = mpack_node_u8(mpack_node_map_uint(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_KIND));
        double value = mpack_node_double(mpack_node_map_uint(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VALUE));

        std::string_view label;
        auto label_n = mpack_node_map_uint_optional(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_LABEL);
        if (!mpack_node_is_missing(label_n)) {
            const char *l = mpack_node_str(label_n);
            const size_t l_len = mpack_node_strlen(label_n);
            if (l != nullptr)
                label = std::string_view(l, l_len);
        }

        uint8_t batt_state = KIS_EXTERNAL_V3_ENV_BATT_UNKNOWN;
        auto bs_n = mpack_node_map_uint_optional(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_BATT_STATE);
        if (!mpack_node_is_missing(bs_n))
            batt_state = mpack_node_u8(bs_n);

        int8_t ext_power = -1;
        auto ep_n = mpack_node_map_uint_optional(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_EXT_POWER);
        if (!mpack_node_is_missing(ep_n))
            ext_power = mpack_node_bool(ep_n) ? 1 : 0;

        double voltage = 0;
        auto v_n = mpack_node_map_uint_optional(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VOLTAGE);
        if (!mpack_node_is_missing(v_n))
            voltage = mpack_node_double(v_n);

        uint32_t remaining = 0;
        auto r_n = mpack_node_map_uint_optional(s, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_REMAINING_S);
        if (!mpack_node_is_missing(r_n))
            remaining = mpack_node_u32(r_n);

        // Any wrong type or missing field fails the whole report
        if (mpack_tree_error(&tree) != mpack_ok || id_s == nullptr) {
            err = "malformed reading";
            return false;
        }

        const std::string_view id(id_s, id_len);

        if (kind < KIS_EXTERNAL_V3_ENV_KIND_THERMAL || kind > KIS_EXTERNAL_V3_ENV_KIND_BATTERY) {
            out.skipped++;
            continue;
        }

        env_report_reading r;
        r.kind = static_cast<env_kind>(kind);

        if (!env_valid_id(id) || !env_check_value(r.kind, value)) {
            out.skipped++;
            continue;
        }

        bool dup = false;
        for (const auto& e : out.readings) {
            if (e.id == id) {
                dup = true;
                break;
            }
        }

        if (dup) {
            out.skipped++;
            continue;
        }

        r.id = std::string(id);
        r.value = value;
        r.label = env_munge_label(label);

        if (r.kind == env_kind::battery) {
            r.batt_state = batt_state <= KIS_EXTERNAL_V3_ENV_BATT_NOT_CHARGING ?
                batt_state : KIS_EXTERNAL_V3_ENV_BATT_UNKNOWN;
            r.ext_power = ext_power;
            if (std::isfinite(voltage) && voltage > 0.0 && voltage <= 100.0)
                r.voltage = voltage;
            if (remaining <= env_max_remaining_s)
                r.remaining_s = remaining;
        }

        out.readings.push_back(std::move(r));
    }

    return true;
}
