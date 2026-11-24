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

#include <cstdint>
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
}

#endif
