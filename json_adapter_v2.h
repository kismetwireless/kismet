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
        virtual ~jsonable() { }

		virtual void pre_serialize() { }
		virtual void post_serialize() { }

        virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) = 0;
        virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
                const json_adapter_v2::field_group_map& fields) = 0;
    };

    void serialize(std::ostream& os, jsonable *object,
            const std::string& extension, raw_field_list& fields,
            name_permute_fn permute_fn =
            [](const std::string& n) { return fmt::format("\"{}\"", sanitize_string(n)); });

    template<typename E> struct json_encode;

    template<typename E> struct json_encode {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, E& e) {
            fmt::print(os, "{}", e);
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, const E& e) {
            fmt::print(os, "{}", e);
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, E *e) {
            fmt::print(os, "{}", *e);
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, const E *e) {
            fmt::print(os, "{}", *e);
        }

        // filtered catch-all for generic jsonable objects
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e,
                json_adapter_v2::field_group_map& fields) {
            e.filtered_as_json(os, opts, fields);
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable *e,
                json_adapter_v2::field_group_map& fields) {
            e->filtered_as_json(os, opts, fields);
        }
    };

    template<> struct json_encode<char *> {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, char *e) {
            fmt::print(os, "\"{}\"", sanitize_string(e));
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, const char *e) {
            fmt::print(os, "\"{}\"", sanitize_string(e));
        }
    };

    template<> struct json_encode<std::string> {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, std::string& e) {
            fmt::print(os, "\"{}\"", sanitize_string(e));
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, const std::string& e) {
            fmt::print(os, "\"{}\"", sanitize_string(e));
        }
    };

    template<> struct json_encode<std::string_view> {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, std::string_view& e) {
            fmt::print(os, "\"{}\"", sanitize_string(std::string(e.data(), e.length())));
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, const std::string_view& e) {
            fmt::print(os, "\"{}\"", sanitize_string(std::string(e.data(), e.length())));
        }
    };

    template<> struct json_encode<json_adapter_v2::jsonable> {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e) {
            e.as_json(os, opts);
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable *e) {
            e->as_json(os, opts);
        }

        // filtered
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e,
                json_adapter_v2::field_group_map& fields) {
            e.filtered_as_json(os, opts, fields);
        }
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, json_adapter_v2::jsonable *e,
                json_adapter_v2::field_group_map& fields) {
            e->filtered_as_json(os, opts, fields);
        }
    };

    template<typename E> struct json_encode_keyed;

    template<typename E> struct json_encode_keyed {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts, E& e) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode<E>{}(os, opts, e);
            opts->next_key_comma = true;
        }
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts, const E& e) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode<E>{}(os, opts, e);
            opts->next_key_comma = true;
        }
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts, E *e) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode<E>{}(os, opts, e);
            opts->next_key_comma = true;
        }
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts, const E *e) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode<E>{}(os, opts, e);
            opts->next_key_comma = true;
        }

        // filtered catch-all for generic jsonable objects
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                json_adapter_v2::jsonable& e, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            e.filtered_as_json(os, opts, fields);
            opts->next_key_comma = true;
        }
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                json_adapter_v2::jsonable *e, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            e->filtered_as_json(os, opts, fields);
            opts->next_key_comma = true;
        }
    };

    template<typename It> struct json_encode_array {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                if (comma) {
                    fmt::print(os, ",");
                }
                comma = true;

                json_encode<std::remove_pointer_t<It>>{}(os, opts, first);
            }

            fmt::print(os, "]");
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last,
                json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                if (comma) {
                    fmt::print(os, ",");
                }
                comma = true;

                json_encode<std::remove_pointer_t<It>>{}(os, opts, first, fields);
            }

            fmt::print(os, "]");
        }
    };

    template<typename It> struct json_encode_keyed_array {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_array<It>{}(os, opts, first, last);
            opts->next_key_comma = true;
        }

        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_array<It>{}(os, opts, first, last, fields);
            opts->next_key_comma = true;
        }
    };

    template<typename It> struct json_encode_map {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
            fmt::print(os, "{{");

            bool comma = false;
            for (; first != last; ++first) {
                fmt::print(os, "{}\"{}\":", comma ? "," : "", sanitize_string(fmt::format("{}", first->first)));
                json_encode<decltype(first->second)>{}(os, opts, first->second);
                comma = true;
            }

            fmt::print(os, "}}");
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last,
                json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{{");

            bool comma = false;
            for (; first != last; ++first) {
                fmt::print(os, "{}\"{}\":", comma ? "," : "", sanitize_string(fmt::format("{}", first->first)));
                json_encode<decltype(first->second)>{}(os, opts, first->second, fields);
                comma = true;
            }

            fmt::print(os, "}}");
        }
    };

    template<typename It> struct json_encode_keyed_map {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map<It>{}(os, opts, first, last);
            opts->next_key_comma = true;
        }

        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map<It>{}(os, opts, first, last, fields);
            opts->next_key_comma = true;
        }
    };

    template<typename It, typename Enc> struct json_encode_map_custom {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
            fmt::print(os, "{{");

            bool comma = false;
            for (; first != last; ++first) {
                fmt::print(os, "{}\"{}\":", comma ? "," : "", sanitize_string(fmt::format("{}", first->first)));
                Enc{}(os, opts, first->second);
                comma = true;
            }

            fmt::print(os, "}}");
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last,
                json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{{");

            bool comma = false;
            for (; first != last; ++first) {
                fmt::print(os, "{}\"{}\":", comma ? "," : "", sanitize_string(fmt::format("{}", first->first)));
                Enc{}(os, opts, first->second, fields);
                comma = true;
            }

            fmt::print(os, "}}");
        }
    };

    template<typename It, typename Enc> struct json_encode_keyed_map_custom {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map_custom<It, Enc>{}(os, opts, first, last);
            opts->next_key_comma = true;
        }

        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map_custom<It, Enc>{}(os, opts, first, last, fields);
            opts->next_key_comma = true;
        }
    };

	// encode the keys of a map as if it were a vector or list; allows
	// for fast storage of random-access single entries
    template<typename It, typename Mt = It> struct json_encode_map_keys {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                fmt::print(os, "{}\"{}\"", comma ? "," : "", sanitize_string(fmt::format("{}", first->first)));
                comma = true;
            }

            fmt::print(os, "]");
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, Mt full) {
            operator()(os, opts, full.begin(), full.end());
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last,
                json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                fmt::print(os, "{}\"{}\"", comma ? "," : "", sanitize_string(fmt::format("{}", first->first)));
                comma = true;
            }

            fmt::print(os, "]");
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It full,
                json_adapter_v2::field_group_map& fields) {
            operator()(os, opts, full.begin(), full.end(), fields);
        }

    };

    template<typename It> struct json_encode_keyed_map_keys {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map_keys<It>{}(os, opts, first, last);
            opts->next_key_comma = true;
        }

        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map_keys<It>{}(os, opts, first, last, fields);
            opts->next_key_comma = true;
        }
    };

    template <typename TupleT, std::size_t... Is>
    void encode_tuple_imp(std::ostream& os, json_adapter_v2::opts *opts,
            const TupleT& tp, std::index_sequence<Is...>) {
        size_t index = 0;
        auto emitElem = [&index, &opts, &os](const auto& x) {
            fmt::print(os, "{}", index++ > 0 ? "," : "");
            json_encode<decltype(x)>{}(os, opts, x);
        };

        (emitElem(std::get<Is>(tp)), ...);
    }

    template <typename TupleT, std::size_t TupSize = std::tuple_size_v<TupleT>>
    struct json_encode_tuple {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, const TupleT& tp) {
            fmt::print(os, "[");
            encode_tuple_imp(os, opts, tp, std::make_index_sequence<TupSize>{});
            fmt::print(os, "]");
        }
    };

    template <typename TupleT, std::size_t TupSize = std::tuple_size_v<TupleT>>
    struct json_encode_keyed_tuple {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                const TupleT& tp) {
            fmt::print(os, "{}{}:[", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            encode_tuple_imp(os, opts, tp, std::make_index_sequence<TupSize>{});
            fmt::print(os, "]");
            opts->next_key_comma = true;
        }
    };

    template <typename T1, typename T2>
    struct json_encode_pair {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts,
                const std::pair<T1, T2>& pair) {
            fmt::print(os, "[");
            json_encode<T1>{}(os, opts, std::get<0>(pair));
            fmt::print(os, ",");
            json_encode<T2>{}(os, opts, std::get<0>(pair));
            fmt::print(os, "]");
        }
    };

    template <typename T1, typename T2>
    struct json_encode_keyed_pair {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                const std::pair<T1, T2>& pair) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_pair<T1, T2>{}(os, opts, pair);
            opts->next_key_comma = true;
        }
    };
}

#endif /* __JSON_ADAPTER_V2__ */
