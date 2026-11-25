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

#ifndef __RTL433_JSON_H__
#define __RTL433_JSON_H__

#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

#include "fmt.h"
#include "freq_bounds.h"
#include "json_number.h"
#include "nlohmann/json.hpp"

// Fields of an rtl_433 JSON record, which comes from a helper, a remote or a replayed
// log and may hold anything.  Lookups use find(): a const operator[] on a missing key
// asserts.
namespace rtl433_json {
    inline const nlohmann::json *field(const nlohmann::json& json, const char *key) {
        if (!json.is_object())
            return nullptr;

        auto i = json.find(key);

        if (i == json.end())
            return nullptr;

        return &(*i);
    }

    // This list will need to be updated as rtl_433 adds more meter types
    inline bool is_meter_model(const nlohmann::json& json) {
        auto model_j = field(json, "model");

        if (model_j == nullptr || !model_j->is_string())
            return false;

        const auto& model = model_j->get_ref<const std::string&>();

        return model == "IDM" || model == "NETIDM" || model == "ERT-SCM" ||
            model == "SCMplus" || model == "SCM+";
    }

    // The first freq, freq1 or freq2 (MHz) that is a number in range, in kHz; 0 when
    // there's none
    inline double freq_khz(const nlohmann::json& json) {
        for (const char *key : {"freq", "freq1", "freq2"}) {
            auto freq_j = field(json, key);

            if (freq_j == nullptr || !freq_j->is_number())
                continue;

            const double khz = freq_j->get<double>() * 1000;

            if (freq_bounds::khz_valid(khz))
                return khz;
        }

        return 0;
    }

    // Float ids are taken where they fit the unsigned int they were always cast to,
    // truncated as that cast did, so their device keys and names don't change
    inline std::optional<uint32_t> float_id(const nlohmann::json& j) {
        if (!j.is_number_float())
            return std::nullopt;

        if (auto v = json_number::integral(j, 0, UINT32_MAX))
            return static_cast<uint32_t>(*v);

        return std::nullopt;
    }

    // The low 16 bits of an id: any integer, or a float that fits an unsigned int
    inline std::optional<uint16_t> id_bits(const nlohmann::json& j) {
        if (j.is_number_unsigned())
            return static_cast<uint16_t>(j.get<uint64_t>());
        if (j.is_number_integer())
            return static_cast<uint16_t>(static_cast<uint64_t>(j.get<int64_t>()));
        if (auto f = float_id(j))
            return static_cast<uint16_t>(*f);
        return std::nullopt;
    }

    // An id as text: any integer, or a float that fits an unsigned int; empty otherwise
    inline std::string integer_text(const nlohmann::json& j) {
        if (j.is_number_unsigned())
            return fmt::format("{}", j.get<uint64_t>());
        if (j.is_number_integer())
            return fmt::format("{}", j.get<int64_t>());
        if (auto f = float_id(j))
            return fmt::format("{}", *f);
        return {};
    }

    // rtl_433 -M level reports rssi and noise in dB relative to full scale.  One sample
    // count is about -42 dBFS with 8-bit samples and -84 with 16-bit, so -150 leaves
    // room for float inputs.  Integer samples clip a few dB above 0, but float inputs
    // (SoapySDR CF32, replayed .cf32) don't clip: +60 is a sample 1000 times full scale,
    // past any real front end.  snr is rssi - noise.  Anything outside these is a
    // damaged or hostile record.
    constexpr double level_min_dbfs = -150.0;
    constexpr double level_max_dbfs = 60.0;
    constexpr double snr_max_db = level_max_dbfs - level_min_dbfs;
    constexpr double snr_min_db = -snr_max_db;

    // A finite number in [lo, hi]; NaN fails both compares
    inline std::optional<double> number_in(const nlohmann::json& j, double lo, double hi) {
        if (!j.is_number())
            return std::nullopt;

        const double v = j.get<double>();

        if (!(v >= lo && v <= hi))
            return std::nullopt;

        return v;
    }

    inline std::optional<double> number_in(const nlohmann::json& json, const char *key,
            double lo, double hi) {
        if (auto j = field(json, key))
            return number_in(*j, lo, hi);

        return std::nullopt;
    }

    // A number as reported; nullopt when not a number or out of range
    inline std::optional<std::string> number_text(const nlohmann::json& j, double lo, double hi) {
        if (auto v = number_in(j, lo, hi))
            return fmt::format("{}", *v);

        return std::nullopt;
    }

    // A level (rssi, snr, noise) for display: the number as reported, or a string as sent
    // for the caller to make printable.  A level thrown away (out of range, not finite, or
    // neither a number nor a string) is empty, so the last record's doesn't stay shown.
    // nullopt when the record has no such field.
    inline std::optional<std::string> level_text(const nlohmann::json& json, const char *key,
            double lo, double hi) {
        auto j = field(json, key);

        if (j == nullptr)
            return std::nullopt;

        if (j->is_string())
            return j->get<std::string>();

        if (auto t = number_text(*j, lo, hi))
            return t;

        return std::string{};
    }

    // rssi and noise as the integer the signal tracker keeps, where 0 means no value
    struct signal_levels {
        int rssi = 0;
        int noise = 0;
    };

    // floor() of any accepted level, and the -1 it may become, must fit an int
    static_assert(level_min_dbfs >= static_cast<double>(std::numeric_limits<int>::min()) &&
            level_max_dbfs < static_cast<double>(std::numeric_limits<int>::max()) &&
            level_min_dbfs <= -1.0 && level_min_dbfs < level_max_dbfs,
            "rtl_433 level bounds must keep the int conversion defined");

    // A level rounded down so one just under 0 dBFS isn't 0 ("no value"): -0.13 is -1.
    // Levels in [0, 1) round the same way, to -1; from 1 up they stay positive.
    inline int level_to_int(double dbfs) {
        const int v = static_cast<int>(std::floor(dbfs));
        return v == 0 ? -1 : v;
    }

    // The record's levels; nullopt without a usable rssi.  noise stays 0 when missing or
    // out of range.
    inline std::optional<signal_levels> levels(const nlohmann::json& json) {
        auto rssi = number_in(json, "rssi", level_min_dbfs, level_max_dbfs);

        if (!rssi)
            return std::nullopt;

        signal_levels l;
        l.rssi = level_to_int(*rssi);

        if (auto noise = number_in(json, "noise", level_min_dbfs, level_max_dbfs))
            l.noise = level_to_int(*noise);

        return l;
    }
}

#endif
