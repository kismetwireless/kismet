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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <math.h>
#include <cmath>

#include "globalregistry.h"
#include "trackedelement.h"
#include "macaddr.h"
#include "entrytracker.h"
#include "uuid.h"
#include "devicetracker_component.h"
#include "json_adapter.h"

/* sanitize_extra_space and sanitize_string taken from nlohmann's jsonhpp library,
   Copyright 2013-2015 Niels Lohmann. and under the MIT license */
std::size_t json_adapter::sanitize_extra_space(const std::string& s) noexcept {
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

std::string json_adapter::sanitize_string(const std::string& s) noexcept {
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

void json_adapter::pack(std::ostream &stream, shared_tracker_element e, 
        std::shared_ptr<tracker_element_serializer::rename_map> name_map,
        bool prettyprint, unsigned int depth,
        std::function<std::string (const std::string&)> name_permuter) {

    std::string indent;
    std::string ppendl;

    if (e == nullptr) {
        return;
    }
    
    if (prettyprint) {
        indent = std::string(depth, ' ');
        ppendl = "\r\n";
    }

    serializer_scope s(e, name_map);
    
    uuid euuid;

    std::string tname;

    bool prepend_comma;

    bool as_vector, as_key_vector;

    // If we're serializing an alias, remap as the aliased element
    if (e->get_type() == tracker_type::tracker_alias) {
        e = std::static_pointer_cast<tracker_element_alias>(e)->get();
        if (e == nullptr) {
            return;
        }
    }

    if (e->is_stringable()) {
        if (e->needs_quotes())
            stream << "\"" << sanitize_string(e->as_string()) << "\"";
        else
            stream << sanitize_string(e->as_string());
    } else {
        switch (e->get_type()) {
            case tracker_type::tracker_vector:
                stream << ppendl << indent << "[" << ppendl;

                prepend_comma = false;

                for (auto i : *(std::static_pointer_cast<tracker_element_vector>(e))) {
                    if (i == NULL)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (prettyprint)
                        stream << indent;

                    json_adapter::pack(stream, i, name_map, prettyprint, depth + 1, name_permuter);
                }
                stream << ppendl << indent << "]";
                break;
            case tracker_type::tracker_vector_double:
                stream << ppendl << indent << "[" << ppendl;

                prepend_comma = false;

                for (auto i : *(std::static_pointer_cast<tracker_element_vector_double>(e))) {
                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (prettyprint)
                        stream << indent;

                    if (std::isnan(i) || std::isinf(i))
                        stream << "0";

                    if (floor(i) == i)
                        stream << fmt::format("{}", (long long) i);
                    else
                        stream << fmt::format("{:f}", i);
                }
                stream << ppendl << indent << "]";
                break;
            case tracker_type::tracker_vector_string:
                stream << ppendl << indent << "[" << ppendl;

                prepend_comma = false;

                for (auto i : *(std::static_pointer_cast<tracker_element_vector_string>(e))) {
                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (prettyprint)
                        stream << indent;

                    stream << i;
                }
                stream << ppendl << indent << "]";
                break;
            case tracker_type::tracker_map:
                as_vector = std::static_pointer_cast<tracker_element_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_map>(e))) {
                    if (i.second == NULL)
                        continue;

                    if (prepend_comma) {
                        stream << "," << ppendl;

                        if (prettyprint)
                            stream << ppendl;
                    }

                    prepend_comma = true;

                    if (!as_vector) {
                        bool named = false;

                        if (name_map != NULL) {
                            tracker_element_serializer::rename_map::iterator nmi = name_map->find(i.second);
                            if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                                tname = nmi->second->rename;
                                named = true;
                            }
                        }

                        if (!named) {
                            if (i.second == NULL) {
                                tname = Globalreg::globalreg->entrytracker->get_field_name(i.first);
                            } else {
                                if ((tname = i.second->get_local_name()) == "")
                                    tname = Globalreg::globalreg->entrytracker->get_field_name(i.first);
                            }
                        }

                        tname = json_adapter::sanitize_string(name_permuter(tname));

                        if (prettyprint) {
                            stream << indent << "\"description." << tname << "\": ";
                            stream << "\"";
                            if (i.second != nullptr) {
                                stream << sanitize_string(i.second->get_type_as_string());
                                stream << ", ";
                            }
                            stream << sanitize_string(Globalreg::globalreg->entrytracker->get_field_description(i.first));
                            stream << "\"," << ppendl;
                        }

                        stream << indent << "\"" << tname << "\": ";
                    }

                    json_adapter::pack(stream, i.second, name_map, prettyprint, depth + 1, name_permuter);

                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_int_map:
                as_vector = std::static_pointer_cast<tracker_element_int_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_int_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_int_map>(e))) {
                    if (i.second == nullptr && !as_key_vector)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (!as_vector) {
                        // Integer dictionary keys in json are still quoted as strings
                        stream << indent << "\"" << i.first << "\"";

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        json_adapter::pack(stream, i.second, name_map, prettyprint, depth + 1, name_permuter);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << indent << "]" << ppendl;
                else
                    stream << indent << "}" << ppendl;

                break;
            case tracker_type::tracker_mac_map:
                as_vector = std::static_pointer_cast<tracker_element_mac_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_mac_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_mac_map>(e))) {
                    if (i.second == nullptr && !as_key_vector)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (!as_vector) {
                        // Mac keys are strings and we push only the mac not the mask */
                        stream << indent << "\"" << i.first << "\"";

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        json_adapter::pack(stream, i.second, name_map, prettyprint, depth + 1, name_permuter);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_string_map:
                as_vector = std::static_pointer_cast<tracker_element_string_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_string_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_string_map>(e))) {
                    if (i.second == nullptr && !as_key_vector)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (!as_vector) {
                        stream << indent << "\"" << json_adapter::sanitize_string(i.first) << "\"";

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        json_adapter::pack(stream, i.second, name_map, prettyprint, depth + 1, name_permuter);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_double_map:
                as_vector = std::static_pointer_cast<tracker_element_double_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_double_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_double_map>(e))) {
                    if (i.second == nullptr && !as_key_vector)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (!as_vector) {
                        // Double keys are handled as strings in json
                        if (std::isnan(i.first) || std::isinf(i.first)) {
                            stream << indent << "\"0\"";
                        } else if (floor(i.first) == i.first)  {
                            auto prec = stream.precision(0);
                            stream << indent << "\"" << std::fixed << i.first << "\"";
                            stream.precision(prec);
                        } else {
                            stream << indent << "\"" << std::fixed << i.first << "\"";
                        }

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        json_adapter::pack(stream, i.second, name_map, prettyprint, depth + 1, name_permuter);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << indent << "}";

                break;
            case tracker_type::tracker_hashkey_map:
                as_vector = std::static_pointer_cast<tracker_element_hashkey_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_hashkey_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_hashkey_map>(e))) {
                    if (i.second == nullptr && !as_key_vector)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (!as_vector) {
                        // Double keys are handled as strings in json
                        if (std::isnan(i.first) || std::isinf(i.first)) {
                            stream << indent << "\"0\"";
                        } else if (floor(i.first) == i.first)  {
                            stream << indent << "\"" << (long) i.first << "\"";
                        } else {
                            stream << indent << "\"" << std::fixed << i.first << "\"";
                        }

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        json_adapter::pack(stream, i.second, name_map, prettyprint, depth + 1, name_permuter);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_double_map_double:
                as_vector = std::static_pointer_cast<tracker_element_double_map_double>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_double_map_double>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_double_map_double>(e))) {
                    if (prepend_comma)
                        stream << "," << ppendl;

                    prepend_comma = true;

                    if (!as_vector) {
                        // Double keys are handled as strings in json
                        if (std::isnan(i.first) || std::isinf(i.first)) {
                            stream << indent << "\"0\"";
                        } else if (floor(i.first) == i.first)  {
                            stream << indent << "\"" << (long) i.first << "\"";
                        } else {
                            stream << indent << "\"" << std::fixed << i.first << "\"";
                        }

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        if (std::isnan(i.second) || std::isinf(i.second)) {
                            stream << 0;
                        } else if (floor(i.second) == i.second) {
                            stream << (long) i.second;
                        } else {
                            stream << i.second;
                        }
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_key_map:
                as_vector = std::static_pointer_cast<tracker_element_device_key_map>(e)->as_vector();
                as_key_vector = std::static_pointer_cast<tracker_element_device_key_map>(e)->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *(std::static_pointer_cast<tracker_element_device_key_map>(e))) {
                    if (i.second == nullptr && !as_key_vector)
                        continue;

                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (!as_vector) {
                        // Keymap keys are handled as strings
                        stream << indent << "\"" << i.first << "\"";

                        if (!as_key_vector)
                            stream << ": ";
                    }

                    if (!as_key_vector) {
                        json_adapter::pack(stream,i.second, name_map, prettyprint, depth + 1, name_permuter);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            default:
                break;
        }
    }
}

// An unfortunate duplication of code but overloading the json/prettyjson to also do
// storage tagging would get a bit out of hand
void storage_json_adapter::pack(std::ostream &stream, shared_tracker_element e, 
        std::shared_ptr<tracker_element_serializer::rename_map> name_map) {

    if (e == nullptr) {
        stream << "0";
        return;
    }

    serializer_scope s(e, name_map);

    mac_addr mac;
    uuid euuid;
    device_key key;

    std::string tname;

    std::string bytes;
    const char* bytes_c;

    std::ios::fmtflags fflags;

    bool prepend_comma;

    double d_v;

#if 0 
    We don't really use storagejson; but if we did, I don't think we want to serialize
    out an alias at all

    // If we're serializing an alias, remap as the aliased element
    if (e->get_type() == tracker_type::tracker_alias) {
        e = std::static_pointer_cast<tracker_element_alias>(e)->get();
        if (e == nullptr)
            return;
    }
#else
    if (e->get_type() == tracker_type::tracker_alias) {
        stream << "0";
        return;
    }
#endif

    // Every record gets wrapped into it's own object export with metadata
    stream << "{";

    // Name metadata; duplicate if we're a nested field object but consistent
    stream << "\"on\": \"";
    stream << json_adapter::sanitize_string(Globalreg::globalreg->entrytracker->get_field_name(e->get_id()));
    stream << "\",";

    // Type metadata; raw element type
    stream << "\"ot\": \"";
    stream << json_adapter::sanitize_string(tracker_element::type_to_typestring(e->get_type()));
    stream << "\",";

    // Actual data blob for object
    stream << "\"od\": ";

    switch (e->get_type()) {
        case tracker_type::tracker_string:
            stream << "\"" << json_adapter::sanitize_string(get_tracker_value<std::string>(e)) << "\"";
            break;
        case tracker_type::tracker_int8:
            stream << (int) get_tracker_value<int8_t>(e);
            break;
        case tracker_type::tracker_uint8:
            stream << (unsigned int) get_tracker_value<uint8_t>(e);
            break;
        case tracker_type::tracker_int16:
            stream << (int) get_tracker_value<int16_t>(e);
            break;
        case tracker_type::tracker_uint16:
            stream << (unsigned int) get_tracker_value<uint16_t>(e);
            break;
        case tracker_type::tracker_int32:
            stream << get_tracker_value<int32_t>(e);
            break;
        case tracker_type::tracker_uint32:
            stream << get_tracker_value<uint32_t>(e);
            break;
        case tracker_type::tracker_int64:
            stream << get_tracker_value<int64_t>(e);
            break;
        case tracker_type::tracker_uint64:
            stream << get_tracker_value<uint64_t>(e);
            break;
        case tracker_type::tracker_float:
            d_v = get_tracker_value<float>(e);

            if (std::isnan(d_v) || std::isinf(d_v)) {
                stream << 0;
            } else if (floor(d_v) == d_v) {
                auto prec = stream.precision();
                stream.precision(0);
                stream << std::fixed << d_v;
                stream.precision(prec);
            } else {
                stream << std::fixed << d_v;
            }

            break;
        case tracker_type::tracker_double:
            d_v = get_tracker_value<float>(e);

            if (std::isnan(d_v) || std::isinf(d_v))
                stream << 0;
            else if (floor(d_v) == d_v) 
                stream << d_v;
            else
                stream << std::fixed << d_v;

            break;
        case tracker_type::tracker_mac_addr:
            mac = get_tracker_value<mac_addr>(e);
            // Mac is quoted as a string value, mac only
            stream << "\"" << mac << "\"";
            break;
        case tracker_type::tracker_uuid:
            euuid = get_tracker_value<uuid>(e);
            // UUID is quoted as a string value
            stream << "\"" << euuid << "\"";
            break;
        case tracker_type::tracker_key:
            stream << "\"" << get_tracker_value<device_key>(e) << "\"";
            break;
        case tracker_type::tracker_vector:
            stream << "[";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_vector>(e))) {
                if (i == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                storage_json_adapter::pack(stream, i, name_map);
            }
            stream << "]";
            break;
        case tracker_type::tracker_vector_double:
            stream << "[";

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<tracker_element_vector_double>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                if (floor(i) == i)
                    stream << i;
                else
                    stream << i;
            }
            stream << "]";
            break;
        case tracker_type::tracker_vector_string:
            stream << "[";

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<tracker_element_vector_string>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << i;
            }
            stream << "]";
            break;
        case tracker_type::tracker_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                bool named = false;

                if (name_map != NULL) {
                    tracker_element_serializer::rename_map::iterator nmi = name_map->find(i.second);
                    if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                        tname = nmi->second->rename;
                        named = true;
                    }
                }

                if (!named) {
                    if (i.second == NULL) {
                        tname = Globalreg::globalreg->entrytracker->get_field_name(i.first);
                    } else {
                        if ((tname = i.second->get_local_name()) == "")
                            tname = Globalreg::globalreg->entrytracker->get_field_name(i.first);
                    }
                }

                tname = json_adapter::sanitize_string(tname);

                stream << "\"" << tname << "\":";

                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";

            break;
        case tracker_type::tracker_int_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_int_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Integer dictionary keys in json are still quoted as strings
                stream << "\"" << i.first << "\": ";
                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case tracker_type::tracker_mac_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_mac_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Mac keys are strings and we push only the mac not the mask */
                stream << "\"" << i.first << "\": ";
                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case tracker_type::tracker_string_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_string_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << "\"" << json_adapter::sanitize_string(i.first) << "\": ";
                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case tracker_type::tracker_double_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_double_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                if (std::isnan(i.first) || std::isinf(i.first)) {
                    stream << "\"0\":";
                } else if (floor(i.first) == i.first) {
                    auto prec = stream.precision(0);
                    stream << "\"" << std::fixed << i.first << "\":";
                    stream.precision(prec);
                } else {
                    stream << "\"" << std::fixed << i.first << "\":";
                }

                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case tracker_type::tracker_hashkey_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_hashkey_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << "\"" << std::fixed << i.first << "\": ";
                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case tracker_type::tracker_double_map_double:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_double_map_double>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                if (std::isnan(i.first) || std::isinf(i.first)) {
                    stream << "\"0\":";
                } else if (floor(i.first) == i.first) {
                    auto prec = stream.precision(0);
                    stream << "\"" << std::fixed << i.first << "\":";
                    stream.precision(prec);
                } else {
                    stream << "\"" << std::fixed << i.first << "\":";
                }

                if (floor(i.second) == i.second) {
                    auto prec = stream.precision(0);
                    stream << std::fixed << i.second;
                    stream.precision(prec);
                } else {
                    stream << std::fixed << i.second;
                }
            }
            stream << "}";
            break;
        case tracker_type::tracker_key_map:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<tracker_element_device_key_map>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Keymap keys are handled as strings
                stream << "\"" << i.first << "\": ";
                storage_json_adapter::pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case tracker_type::tracker_byte_array:
            bytes = std::static_pointer_cast<tracker_element_byte_array>(e)->get();
            bytes_c = bytes.data();
           
            fflags = stream.flags();

            stream << "\"";
            for (size_t szx = 0; szx < bytes.length(); szx++) {
                stream << std::uppercase << std::setfill('0') << std::setw(2) 
                    << std::hex << (int) (bytes_c[szx] & 0xFF);
            }
            stream << "\"";
            stream.flags(fflags);

            break;


        default:
            break;
    }

    // close wrapping object
    stream << "}";
}
