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
#include <list>
#include <string>
#include <string_view>
#include <unordered_map>
#include <ostream>

#include "fmt.h"

namespace json_adapter_v2 {
    constexpr int consthash(const std::string_view& sv) noexcept{
        uint32_t hash = 5381;

        for(const char *c = sv.data(); c < sv.data() + sv.length(); ++c) {
            hash = ((hash << 5) + hash) + (unsigned char) *c;
        }

        return (int) hash;
    }

    // pop the front element of a field path, returning the front element and
    // modifying the passed path element.
    // Turns a.b.c/d.e.f/g.h.i into {a.b.c} {d.e.f/g.h.i}
    std::string_view pop_path(std::string_view& v);

    // peek the front element of a field path, don't modify the element
    std::string_view peek_path(const std::string_view& v);

    using raw_field_list = std::list<std::pair<std::string, std::string>>;
    using mod_field_list = std::list<std::pair<std::string_view, std::string>>;

    typedef struct _field_group {
        std::string_view field;
        std::string rename;
        mod_field_list subfields;
    } field_group;

    using field_group_map = std::unordered_map<std::string, field_group>;

    // break down a list of fields and group them by parent objects so that field
    // simplifiers can be applied to keyed maps and vectors
    void group_fields(const raw_field_list& fields, field_group_map& grouped);
    void group_fields(const mod_field_list& fields, field_group_map& grouped);

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
        std::list<std::pair<std::string, std::string>> rename_list;
    } opts;

    class jsonable {
    public:
        virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) = 0;
        virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
                const json_adapter_v2::field_group_map& fields) = 0;
    };

    void serialize(std::ostream& os, jsonable *object,
            const std::string& extension, raw_field_list& fields,
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

    template<typename E>
    void encode_filtered(std::ostream& os, json_adapter_v2::opts *opts,
            E& e, json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    template<typename E>
    void encode_filtered(std::ostream& os, json_adapter_v2::opts *opts,
            E* e, json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }

    template<>
    void encode_filtered(std::ostream& os, json_adapter_v2::opts *opts,
            json_adapter_v2::jsonable *e, json_adapter_v2::field_group_map& fields);

    template<>
    void encode_filtered(std::ostream& os, json_adapter_v2::opts *opts,
            json_adapter_v2::jsonable& e, json_adapter_v2::field_group_map& fields);

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

    void encode_filtered_keyed(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e,
            json_adapter_v2::field_group_map& fields);
    void encode_filtered_keyed(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, json_adapter_v2::jsonable* e,
            json_adapter_v2::field_group_map& fields);
    void encode_filtered_keyed(std::ostream& os, const std::string_view& field,
            json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e,
            json_adapter_v2::field_group_map& fields);
    void encode_filtered_keyed(std::ostream& os, const std::string_view& field,
            json_adapter_v2::opts *opts, json_adapter_v2::jsonable* e,
            json_adapter_v2::field_group_map& fields);

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

    template<typename Ct, class It>
    void encode_filtered_map(std::ostream& os, json_adapter_v2::opts *opts,
            json_adapter_v2::field_group_map& fields, It first, It last) {
        bool comma = false;
        fmt::print(os, "{{");

        for (; first != last; ++first) {
            if (comma) {
                fmt::print(os, ",");
            }
            comma = true;
            fmt::print(os, "\"{}\":", sanitize_string(fmt::format("{}", first->first)));
            encode_filtered<Ct>(os, opts, first->second, fields);
        }

        fmt::print(os, "}}");
    }

    template<typename Ct, class It>
    void encode_filtered_keyed_map(std::ostream& os, const std::string& field,
            json_adapter_v2::opts *opts, json_adapter_v2::field_group_map& fields,
            It first, It last) {
        if (opts->next_key_comma) {
            fmt::print(os, ",");
        }

        fmt::print(os, "{}:", opts->name_permute(field));
        encode_filtered_map<Ct, It>(os, opts, fields, first, last);

        opts->next_key_comma = true;
    }

    template<typename Ct, class It>
    void encode_filtered_keyed_map(std::ostream& os, const std::string_view& field,
            json_adapter_v2::opts *opts, json_adapter_v2::field_group_map& fields,
            It first, It last) {
        return encode_filtered_keyed_map(os, std::string(field.data(), field.length()),
                opts, fields, first, last);
    }

}

#endif /* __JSON_ADAPTER_V2__ */
