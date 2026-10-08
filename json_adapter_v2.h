/*
    this file is part of kismet

    kismet is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.

    kismet is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.

    you should have received a copy of the gnu general public license
    along with kismet; if not, write to the free software
    foundation, inc., 59 temple place, suite 330, boston, ma  02111-1307  usa
*/

#ifndef __JSON_ADAPTER_V2__
#define __JSON_ADAPTER_V2__

#include <functional>
#include <iterator>
#include <list>
#include <string>
#include <string_view>
#include <unordered_map>
#include <ostream>

#include "fmt.h"

#include "kis_mutex.h"
#include "regex_adapter.h"

namespace json_adapter_v2 {
    constexpr int consthash(const std::string_view& sv) noexcept {
        uint32_t hash = 5381;

        for(const char *c = sv.data(); c < sv.data() + sv.length(); ++c) {
            hash = ((hash << 5) + hash) + (unsigned char) *c;
        }

        return (int) hash;
    }

    int hash(const std::string_view& sv) noexcept;

    // pop the front element of a field path, returning the front element and
    // modifying the passed path element.
    // Turns a.b.c/d.e.f/g.h.i into {a.b.c} {d.e.f/g.h.i}
    std::string_view pop_path(std::string_view& v);

    // peek the front element of a field path, don't modify the element
    std::string_view peek_path(const std::string_view& v);

    using single_field_list = std::list<std::string>;
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
    void group_fields(const single_field_list& fields, field_group_map& grouped);
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

        virtual bool match_regex(const kis_regex::regex& re,
                const json_adapter_v2::field_group_map& fields) { return false; }

        virtual bool match_string(const std::string& match, bool match_icase, bool match_full,
                const json_adapter_v2::field_group_map& fields) { return false; }
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

    template<> struct json_encode<bool> {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, bool e) {
            fmt::print(os, "{}", e ? "true" : "false");
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

    struct json_encode_keyed_null {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts) {
            fmt::print(os, "{}{}:null", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            opts->next_key_comma = true;
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

    template<
        typename It,
        typename Fn1 = void (std::ostream&, json_adapter_v2::opts *, It first),
        typename Fn2 = void (std::ostream&, json_adapter_v2::opts *, It first, json_adapter_v2::field_group_map&) >
            struct json_encode_array_custom {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last, const Fn1 fn) {
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                if (comma) {
                    fmt::print(os, ",");
                }
                comma = true;

                fn(os, opts, first);
                // json_encode<std::remove_pointer_t<It>>{}(os, opts, first);
            }

            fmt::print(os, "]");
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last,
                json_adapter_v2::field_group_map& fields, const Fn2 fn) {
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                if (comma) {
                    fmt::print(os, ",");
                }
                comma = true;

                fn(os, opts, first, fields);
                // json_encode<std::remove_pointer_t<It>>{}(os, opts, first, fields);
            }

            fmt::print(os, "]");
        }
    };

    template<typename It> struct json_encode_array {
        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last) {
            json_encode_array_custom<It>{}(os, opts, first, last,
                    [](std::ostream& os, json_adapter_v2::opts *opts, It first) -> void {
                        json_encode<typename std::iterator_traits<It>::value_type>{}(os, opts, *first);
                    });
            /*
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                if (comma) {
                    fmt::print(os, ",");
                }
                comma = true;

                json_encode<typename std::iterator_traits<It>::value_type>{}(os, opts, *first);
            }

            fmt::print(os, "]");
            */
        }

        void operator()(std::ostream& os, json_adapter_v2::opts *opts, It first, It last,
                json_adapter_v2::field_group_map& fields) {
            json_encode_array_custom<It>{}(os, opts, first, last, fields,
                    [](std::ostream& os, json_adapter_v2::opts *opts, It first, json_adapter_v2::field_group_map& fm) -> void {
                        json_encode<typename std::iterator_traits<It>::value_type>{}(os, opts, *first, fm);
                    });
            /*
            fmt::print(os, "[");

            bool comma = false;
            for (; first != last; ++first) {
                if (comma) {
                    fmt::print(os, ",");
                }
                comma = true;

                json_encode<typename std::iterator_traits<It>::value_type>{}(os, opts, *first, fields);
            }

            fmt::print(os, "]");
            */
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

    template<typename It,
        typename Fn1 = void (std::ostream&, json_adapter_v2::opts *, It first),
        typename Fn2 = void (std::ostream&, json_adapter_v2::opts *, It first, json_adapter_v2::field_group_map&) >
        struct json_encode_keyed_array_custom {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, Fn1 fnc) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_array_custom<It, Fn1, Fn2>{}(os, opts, first, last, fnc);
            opts->next_key_comma = true;
        }

        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, json_adapter_v2::field_group_map& fields, Fn2 fnc) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_array_custom<It, Fn1, Fn2>{}(os, opts, first, last, fields, fnc);
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

    template<typename It, typename Mt = It> struct json_encode_keyed_map_keys {
        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map_keys<It, Mt>{}(os, opts, first, last);
            opts->next_key_comma = true;
        }

        void operator()(std::ostream& os, const std::string& fn, json_adapter_v2::opts *opts,
                It first, It last, json_adapter_v2::field_group_map& fields) {
            fmt::print(os, "{}{}:", opts->next_key_comma ? "," : "", opts->name_permute(fn));
            json_encode_map_keys<It, Mt>{}(os, opts, first, last, fields);
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

    // wrapper around naked arrays of jsonable objects, so that we don't have to create
    // more stub classes just to serialize them to a URI
    template <typename At, typename Ati>
    class jsonable_array : public jsonable {
    public:
        jsonable_array(At& back, const std::string& key) :
            back_{back},
            key_{key} { }

        virtual ~jsonable_array() { };

        virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
            if (key_.length() == 0) {
                json_adapter_v2::json_encode_array<Ati>{}(os, opts, back_.begin(), back_.end());
            } else {
                fmt::print(os, "{{");
                auto sv_comma = opts->next_key_comma;
                opts->next_key_comma = false;

                json_adapter_v2::json_encode_keyed_array<Ati>{}(os, key_, opts, back_.begin(), back_.end());

                opts->next_key_comma = sv_comma;
                fmt::print(os, "}}");
            }
        }

        virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
                const json_adapter_v2::field_group_map& fields) override {
            if (fields.size() == 0) {
                return as_json(os, opts);
            }

            json_adapter_v2::field_group_map subgroup;

            if (key_.length() == 0) {
                json_adapter_v2::field_group_map fields_copy{fields};
                json_adapter_v2::json_encode_array<Ati>{}(os, opts, back_.begin(), back_.end(), fields_copy);
            } else {
                fmt::print(os, "{{");
                auto sv_comma = opts->next_key_comma;
                opts->next_key_comma = false;

                for (const auto& f : fields) {
                    if (json_adapter_v2::consthash(f.first) == json_adapter_v2::consthash(key_)) {
                        json_adapter_v2::group_fields(f.second.subfields, subgroup);
                        json_adapter_v2::json_encode_keyed_array<Ati>{}(os, key_, opts, back_.begin(), back_.end(), subgroup);
                    } else {
                        json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
                    }
                }

                opts->next_key_comma = sv_comma;
                fmt::print(os, "}}");
            }
        }

    protected:
        At &back_;
        const std::string key_;
    };

    // wrapper around naked arrays of jsonable objects, so that we don't have to create
    // more stub classes just to serialize them to a URI
    template <typename Mt, typename Mti>
    class jsonable_map : public jsonable {
    public:
        jsonable_map(Mt& back, const std::string& key) :
            back_{back},
            key_{key} { }

        jsonable_map(jsonable_map&& m) :
            back_{m.back_},
            key_{m.key_} { }

        virtual ~jsonable_map() { };

        virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
            if (key_.length() == 0) {
                json_adapter_v2::json_encode_map<Mti>{}(os, opts, back_.begin(), back_.end());
            } else {
                fmt::print(os, "{{");
                auto sv_comma = opts->next_key_comma;
                opts->next_key_comma = false;

                json_adapter_v2::json_encode_keyed_map<Mti>{}(os, key_, opts, back_.begin(), back_.end());

                opts->next_key_comma = sv_comma;
                fmt::print(os, "}}");
            }
        }

        virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
                const json_adapter_v2::field_group_map& fields) override {

            if (fields.size() == 0) {
                return as_json(os, opts);
            }

            json_adapter_v2::field_group_map subgroup;

            if (key_.length() == 0) {
                json_adapter_v2::field_group_map fields_copy{fields};
                json_adapter_v2::json_encode_map<Mti>{}(os, opts, back_.begin(), back_.end(), fields_copy);
            } else {
                fmt::print(os, "{{");
                auto sv_comma = opts->next_key_comma;
                opts->next_key_comma = false;

                for (const auto& f : fields) {
                    if (json_adapter_v2::consthash(f.first) == json_adapter_v2::consthash(key_)) {
                        json_adapter_v2::group_fields(f.second.subfields, subgroup);
                        json_adapter_v2::json_encode_keyed_map<Mti>{}(os, key_, opts, back_.begin(), back_.end(), subgroup);
                    } else {
                        json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
                    }
                }

                opts->next_key_comma = sv_comma;
                fmt::print(os, "}}");
            }

        }

    protected:
        Mt &back_;
        const std::string key_;
    };

}

namespace kis_regex {

template<> struct regex_match<json_adapter_v2::jsonable> {
    bool operator()(const regex& re, json_adapter_v2::jsonable& v,
            const json_adapter_v2::field_group_map& fg) {
        return v.match_regex(re, fg);
    }
};

template<> struct string_match<json_adapter_v2::jsonable> {
    bool operator()(const std::string& match, json_adapter_v2::jsonable& v,
            bool match_icase, bool match_full,
            const json_adapter_v2::field_group_map& fg) {
        return v.match_string(match, match_icase, match_full, fg);
    }
};

}

#endif /* __JSON_ADAPTER_V2__ */
