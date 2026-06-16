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

#include "json_adapter_v2.h"

std::string_view json_adapter_v2::pop_path(std::string_view& v) {
    const auto pos = v.find_first_of("/");
    if (pos == std::string_view::npos) {
        return v;
    }

    const auto fn = v.substr(0, pos);
    v.remove_prefix(pos + 1);

    return fn;
}

std::string_view json_adapter_v2::peek_path(const std::string_view& v) {
    const auto pos = v.find_first_of("/");
    if (pos == std::string_view::npos) {
        return v;
    }

    return v.substr(0, pos);
}

void json_adapter_v2::group_fields(const json_adapter_v2::raw_field_list& fields, field_group_map& grouped) {
    for (const auto& of : fields) {
        // get the parent object field
        std::string_view fn{of.first};
        const auto fp = json_adapter_v2::pop_path(fn);

        std::string_view rename_empty;
        if (of.second == "") {
            const auto lp = fp.find_last_of("/");
            if (lp == std::string_view::npos) {
                rename_empty = fp;
            } else {
                rename_empty = fp.substr(lp + 1, fp.length());
            }
        }

        // aggregate multiple child fields into one object
        const auto& ins = grouped.try_emplace(std::string(fp.data(), fp.length()),
                json_adapter_v2::field_group{.field = fn});

        if (ins.second) {
            // if we have more path components, append this field as a subfield immediately
            if (fp != fn) {
                ins.first->second.subfields.push_back(std::make_pair(fn, of.second));
            } else {
                ins.first->second.rename = of.second != "" ? of.second : std::string(rename_empty.data(), rename_empty.length());
            }
        } else {
            // promote a single-field entry to a nested entry
            if (ins.first->second.subfields.size() == 0) {
                ins.first->second.subfields.push_back(std::make_pair(ins.first->second.field, ins.first->second.rename));
                ins.first->second.rename = "";
            }

            ins.first->second.subfields.push_back(std::make_pair(fn, of.second));
        }
    }
}

void json_adapter_v2::group_fields(const json_adapter_v2::mod_field_list& fields, field_group_map& grouped) {
    for (const auto& of : fields) {
        // get the parent object field
        std::string_view fn{of.first};
        const auto fp = json_adapter_v2::pop_path(fn);

        std::string_view rename_empty;
        if (of.second == "") {
            const auto lp = fp.find_last_of("/");
            if (lp == std::string_view::npos) {
                rename_empty = fp;
            } else {
                rename_empty = fp.substr(lp + 1, fp.length());
            }
        }

        // aggregate multiple child fields into one object
        const auto& ins = grouped.try_emplace(std::string(fp.data(), fp.length()),
                json_adapter_v2::field_group{.field = fn});

        if (ins.second) {
            // if we have more path components, append this field as a subfield immediately
            if (fp != fn) {
                ins.first->second.subfields.push_back(std::make_pair(fn, of.second));
            } else {
                ins.first->second.rename = of.second != "" ? of.second : std::string(rename_empty.data(), rename_empty.length());
            }
        } else {
            // promote a single-field entry to a nested entry
            if (ins.first->second.subfields.size() == 0) {
                ins.first->second.subfields.push_back(std::make_pair(ins.first->second.field, ins.first->second.rename));
                ins.first->second.rename = "";
            }

            ins.first->second.subfields.push_back(std::make_pair(fn, of.second));
        }
    }
}

void json_adapter_v2::serialize(std::ostream& os, jsonable *object,
        const std::string& extension, json_adapter_v2::raw_field_list& fields,
        json_adapter_v2::name_permute_fn permute_fn) {
    json_adapter_v2::opts json_opts;

    json_opts.prettyprint = false;
    json_opts.name_permute = permute_fn;
    json_opts.next_key_comma = false;

    json_adapter_v2::field_group_map grouped;
    json_adapter_v2::group_fields(fields, grouped);

    object->filtered_as_json(os, &json_opts, grouped);
}

template<> void json_adapter_v2::encode<std::string>(std::ostream& os,
        json_adapter_v2::opts *opts, const std::string& e) {
    fmt::print(os, "\"{}\"", sanitize_string(e));
}

template<> void json_adapter_v2::encode<char>(std::ostream& os,
        json_adapter_v2::opts *opts, const char *e) {
    fmt::print(os, "\"{}\"", sanitize_string(e));
}

template<> void json_adapter_v2::encode<json_adapter_v2::jsonable>(std::ostream& os,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable *e) {
    e->as_json(os, opts);
}

template<> void json_adapter_v2::encode<json_adapter_v2::jsonable&>(std::ostream& os,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e) {
    e.as_json(os, opts);
}

template<>
void json_adapter_v2::encode_filtered(std::ostream& os, json_adapter_v2::opts *opts,
        json_adapter_v2::jsonable *e, json_adapter_v2::field_group_map& fields) {
    e->filtered_as_json(os, opts, fields);
}

template<>
void json_adapter_v2::encode_filtered(std::ostream& os, json_adapter_v2::opts *opts,
        json_adapter_v2::jsonable& e, json_adapter_v2::field_group_map& fields) {
    e.filtered_as_json(os, opts, fields);
}

template<>
void json_adapter_v2::encode_keyed<json_adapter_v2::jsonable>(std::ostream& os, const std::string& field,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable *e) {
    if (opts->next_key_comma) {
        fmt::print(os, ",");
    }

    fmt::print(os, "{}:", opts->name_permute(field));
    encode<json_adapter_v2::jsonable>(os, opts, e);

    opts->next_key_comma = true;
}

void json_adapter_v2::encode_filtered_keyed(std::ostream& os, const std::string& field,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e,
        json_adapter_v2::field_group_map& fields) {
    if (opts->next_key_comma) {
        fmt::print(os, ",");
    }

    fmt::print(os, "{}:", opts->name_permute(field));
    json_adapter_v2::encode_filtered<json_adapter_v2::jsonable>(os, opts, e, fields);

    opts->next_key_comma = true;
}

void json_adapter_v2::encode_filtered_keyed(std::ostream& os, const std::string& field,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable* e,
        json_adapter_v2::field_group_map& fields) {
    if (opts->next_key_comma) {
        fmt::print(os, ",");
    }

    fmt::print(os, "{}:", opts->name_permute(field));
    json_adapter_v2::encode_filtered<json_adapter_v2::jsonable>(os, opts, e, fields);

    opts->next_key_comma = true;
}

void json_adapter_v2::encode_filtered_keyed(std::ostream& os, const std::string_view& field,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable& e,
        json_adapter_v2::field_group_map& fields) {
    return encode_filtered_keyed(os, std::string(field.data(), field.length()), opts, e, fields);
}

void json_adapter_v2::encode_filtered_keyed(std::ostream& os, const std::string_view& field,
        json_adapter_v2::opts *opts, json_adapter_v2::jsonable* e,
        json_adapter_v2::field_group_map& fields) {
    return encode_filtered_keyed(os, std::string(field.data(), field.length()), opts, e, fields);
}

/* sanitize_extra_space and sanitize_string taken from nlohmann's jsonhpp library,
   Copyright 2013-2015 Niels Lohmann. and under the MIT license */
std::size_t json_adapter_v2::sanitize_extra_space(const std::string& s) noexcept {
    std::size_t result = 0;

    for (const auto& c : s) {
        switch (c) {
            case '"':
            case '\\':
            case '\b':
            case '\f':
            case '\n':
            case '\r':
            case '\t':
                {
                    // from c (1 byte) to \x (2 bytes)
                    result += 1;
                    break;
                }

            default:
                {
                    if (c >= 0x00 and c <= 0x1f)
                    {
                        // from c (1 byte) to \uxxxx (6 bytes)
                        result += 5;
                    }
                    break;
                }
        }
    }

    return result;
}

std::string json_adapter_v2::sanitize_string(const std::string& s) noexcept {
    const auto space = sanitize_extra_space(s);
    if (space == 0) {
        return s;
    }

    // create a result string of necessary size
    std::string result(s.size() + space, '\\');
    std::size_t pos = 0;

    for (const auto& c : s) {
        switch (c) {
            // quotation mark (0x22)
            case '"':
                {
                    result[pos + 1] = '"';
                    pos += 2;
                    break;
                }

                // reverse solidus (0x5c)
            case '\\':
                {
                    // nothing to change
                    pos += 2;
                    break;
                }

                // backspace (0x08)
            case '\b':
                {
                    result[pos + 1] = 'b';
                    pos += 2;
                    break;
                }

                // formfeed (0x0c)
            case '\f':
                {
                    result[pos + 1] = 'f';
                    pos += 2;
                    break;
                }

                // newline (0x0a)
            case '\n':
                {
                    result[pos + 1] = 'n';
                    pos += 2;
                    break;
                }

                // carriage return (0x0d)
            case '\r':
                {
                    result[pos + 1] = 'r';
                    pos += 2;
                    break;
                }

                // horizontal tab (0x09)
            case '\t':
                {
                    result[pos + 1] = 't';
                    pos += 2;
                    break;
                }

            default:
                {
                    if (c >= 0x00 and c <= 0x1f)
                    {
                        // print character c as \uxxxx
                        sprintf(&result[pos + 1], "u%04x", int(c));
                        pos += 6;
                        // overwrite trailing null character
                        result[pos] = '\\';
                    }
                    else
                    {
                        // all other characters are added as-is
                        result[pos++] = c;
                    }
                    break;
                }
        }
    }

    return result;
}

