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

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "fmt.h"
#include "freq_bounds.h"
#include "json_number.h"
#include "nlohmann/json.hpp"
#include "util.h"

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

    // The field a sensor's rtl_433 id is shown from: id, else device, whichever is a
    // string or a number integer_text() takes, the same numbers id_bits() keys the
    // device on.  nullptr when neither is.
    inline const nlohmann::json *rtlid_field(const nlohmann::json& json) {
        for (const char *key : {"id", "device"}) {
            auto j = field(json, key);

            if (j != nullptr && (j->is_string() || !integer_text(*j).empty()))
                return j;
        }

        return nullptr;
    }

    // rtl_433 model names and string ids are short ("Fineoffset-WH51", "da22b333"); a
    // longer one is cut here before it becomes a device name, model, rtlid, channel or
    // log text.  Printable escaping can make the result up to 6 times this.
    constexpr size_t max_text_len = 64;

    // The first max_text_len bytes, cut back so a UTF-8 character isn't split
    constexpr std::string_view capped(std::string_view s) {
        if (s.size() <= max_text_len)
            return s;

        size_t len = max_text_len;

        // s[len] exists as len < size; back up over up to 3 continuation bytes
        for (unsigned int back = 0; back < 3 && len > 0 &&
                (static_cast<unsigned char>(s[len]) & 0xC0) == 0x80; back++)
            len--;

        return s.substr(0, len);
    }

    // Capped and made printable as munge_to_printable does.  A JSON value converts to the
    // string argument as before, throwing when it isn't a string.
    inline std::string printable(const std::string& s) {
        const auto c = capped(s);
        return munge_to_printable(c.data(), c.size());
    }

    // A meter id: an unsigned integer as it is, a signed one that isn't negative, or a
    // float that is an exact integer a double holds exactly (up to 2^53).  Negative,
    // fractional, NaN and larger floats give nullopt; get<uint64_t>() of those wrapped or
    // was undefined.
    inline std::optional<uint64_t> meter_id(const nlohmann::json& j) {
        if (auto v = json_number::unsigned_integer(j, std::numeric_limits<uint64_t>::max()))
            return v;

        if (!j.is_number_float())
            return std::nullopt;

        const double d = j.get<double>();

        if (!(d >= 0 && d <= json_number::max_exact_double) || std::trunc(d) != d)
            return std::nullopt;

        return static_cast<uint64_t>(d);
    }

    // A meter record's id: id, else ERTSerialNumber.  An id that meter_id() rejects counts
    // as missing, as a non-numeric one always did, so a valid ERTSerialNumber still names
    // the meter; nullopt (the record is skipped) when neither is valid.
    inline std::optional<uint64_t> meter_record_id(const nlohmann::json& json) {
        for (const char *key : {"id", "ERTSerialNumber"}) {
            if (auto f = field(json, key)) {
                if (auto v = meter_id(*f))
                    return v;
            }
        }

        return std::nullopt;
    }

    // splitmix64's finalizer: every bit of the input moves about half the output bits
    constexpr uint64_t mix64(uint64_t z) {
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    // The locally administered MAC a meter is keyed on.  Ids below 2^32 keep the layout
    // they always had (bytes 2-5 the id in host order, bytes 0-1 0x02 0x00), so their keys
    // don't change.  Larger ids, once cut to their low 32 bits, take 46 bits of a mix of
    // the whole id, with the 14 free bits of bytes 0-1 never all zero so they can't land
    // on a smaller id's key.  Unicast either way.
    inline std::array<uint8_t, 6> meter_mac_bytes(uint64_t id) {
        constexpr uint64_t low_mask = 0xFFFFFFFFULL;
        constexpr uint32_t high_tag_values = 0x3FFF;

        std::array<uint8_t, 6> bytes{};
        uint32_t low = static_cast<uint32_t>(id & low_mask);
        uint32_t tag = 0;

        if (id > low_mask) {
            const uint64_t m = mix64(id);
            low = static_cast<uint32_t>(m & low_mask);
            tag = 1 + static_cast<uint32_t>((m >> 32) % high_tag_values);
        }

        std::memcpy(bytes.data() + 2, &low, sizeof(low));

        bytes[0] = static_cast<uint8_t>(0x02 | ((tag & 0x3F) << 2));
        bytes[1] = static_cast<uint8_t>(tag >> 6);

        return bytes;
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
