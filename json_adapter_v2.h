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

#ifndef __JSON_ADAPTER_V2__
#define __JSON_ADAPTER_V2__

#include <functional>
#include <string>
#include <ostream>

#include "fmt.h"

namespace json_adapter_v2 {

    std::string sanitize_string(const std::string& in) noexcept;
    std::size_t sanitize_extra_space(const std::string& in) noexcept;

    struct default_name_permuter {
        void operator()(std::ostream& os, const std::string& s) {
            fmt::print(os, "\"{}\"", sanitize_string(s));
        }
    };

    using name_permute_fn = std::function<std::string (const std::string&)>;

    typedef struct {
        bool prettyprint;
        name_permute_fn name_permute;
        bool next_key_comma;
    } opts;

    class jsonable {
    public:
        virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) = 0;
    };

    void serialize(std::ostream& os, jsonable *object,
            name_permute_fn permute_fn =
            [](const std::string& n) { return fmt::format("\"{}\"", sanitize_string(n)); });

    template<typename E>
    void encode(std::ostream& os, json_adapter_v2::opts *opts, const E& e) {
        fmt::print(os, "{}", e);
    }

    template<typename E>
    void encode(std::ostream& os, json_adapter_v2::opts *opts, const E *e) {
        fmt::print(os, "{}", *e);
    }

    template<typename E>
    void encode(std::ostream& os, json_adapter_v2::opts *opts, E *e) {
        fmt::print(os, "{}", *e);
    }

    template<> void encode<json_adapter_v2::jsonable>(std::ostream& os, json_adapter_v2::opts *opts,
            json_adapter_v2::jsonable *e);
    template<> void encode<json_adapter_v2::jsonable&>(std::ostream& os, json_adapter_v2::opts *opts,
            json_adapter_v2::jsonable& e);
    template<> void encode<std::string>(std::ostream& os,
            json_adapter_v2::opts *opts, const std::string& e);
    template<> void encode<char>(std::ostream& os,
            json_adapter_v2::opts *opts, const char *e);

    template<class It>
    void encode(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
        fmt::print(os, "[");
        bool comma = false;
        for (; first != last; ++first) {
            if (comma) {
                fmt::print(os, ",");
            }
            comma = true;
            encode(os, opts, first);
        }
        fmt::print(os, "]");
    }

    template<typename E>
    void encode_keyed(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, const E& e) {
        if (opts->next_key_comma) {
            fmt::print(os, ",");
        }
        fmt::print(os, "{}:", opts->name_permute(field));
        encode<E>(os, opts, e);
        opts->next_key_comma = true;
    }

    template<typename E>
    void encode_keyed(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, const E *e) {
        if (opts->next_key_comma) {
            fmt::print(os, ",");
        }
        fmt::print(os, "{}:", opts->name_permute(field));
        encode<E>(os, opts, e);
        opts->next_key_comma = true;
    }

    template<typename E>
    void encode_keyed(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, E *e) {
        if (opts->next_key_comma) {
            fmt::print(os, ",");
        }
        fmt::print(os, "{}:", opts->name_permute(field));
        encode<E>(os, opts, e);
        opts->next_key_comma = true;
    }


    template<class It>
    void encode_keyed(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, It first, It last) {
        if (opts->next_key_comma) {
            fmt::print(os, ",");
        }
        fmt::print(os, "{}:", opts->name_permute(field));
        encode<It>(os, opts, first, last);
        opts->next_key_comma = true;
    }

    template<>
    void encode_keyed<json_adapter_v2::jsonable>(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, json_adapter_v2::jsonable *e);

    template<typename Ct, class It>
    void encode_map(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
        bool comma = false;
        fmt::print(os, "{{");

        for (; first != last; ++first) {
            if (comma) {
                fmt::print(os, ",");
            }
            comma = true;
            fmt::print(os, "\"{}\":", sanitize_string(fmt::format("{}", first->first)));
            encode<Ct>(os, opts, first->second);
        }

        fmt::print(os, "}}");
    }

    template<typename Ct, class It>
    void encode_keyed_map(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, It first, It last) {
        if (opts->next_key_comma) {
            fmt::print(os, ",");
        }

        fmt::print(os, "{}:", opts->name_permute(field));
        encode_map<Ct, It>(os, opts, first, last);

        opts->next_key_comma = true;
    }
}

#endif /* __JSON_ADAPTER_V2__ */
