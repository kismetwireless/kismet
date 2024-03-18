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

#ifndef __JSON_ADAPTER_H__
#define __JSON_ADAPTER_H__

#include "config.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "devicetracker_component.h"

// Standard JSON serialization adapter; will form complete JSON objects out
// of the input objects.  Best connected to a chainbuf output stream via a
// buffer_handler_ostream_buf or similar
namespace json_adapter {

std::string sanitize_string(const std::string& in) noexcept;
std::size_t sanitize_extra_space(const std::string& in) noexcept;

// Basic packer with some defaulted options - prettyprint and depth used for
// recursive indenting and prettifying the output
template <typename Permuter = std::string (*)(const std::string &)>
void pack(std::ostream &stream, shared_tracker_element e,
        std::shared_ptr<tracker_element_serializer::rename_map> name_map = nullptr,
        bool prettyprint = false, unsigned int depth = 0,
        Permuter name_permuter = 
            [](const std::string& s) -> std::string { return s; }) {

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

    bool prepend_comma = false;

    bool as_vector, as_key_vector;

    float_numerical_string<double> dblstr;

    // If we're serializing an alias, remap as the aliased element
    if (e->get_type() == tracker_type::tracker_alias) {
        e = static_cast<tracker_element_alias *>(e.get())->get();

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

                for (auto i : *static_cast<tracker_element_vector *>(e.get())) {
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

                for (auto i : *static_cast<tracker_element_vector_double *>(e.get())) {
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

                for (auto i : *static_cast<tracker_element_vector_string *>(e.get())) {
                    if (prepend_comma)
                        stream << "," << ppendl;
                    prepend_comma = true;

                    if (prettyprint)
                        stream << indent;

                    stream << "\"" << i << "\"";
                }
                stream << ppendl << indent << "]";
                break;
            case tracker_type::tracker_map:
                as_vector = static_cast<tracker_element_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_map *>(e.get())) {
                    bool named = false;

                    if (i.second == NULL)
                        continue;

                    if (prepend_comma) {
                        stream << "," << ppendl;

                        if (prettyprint)
                            stream << ppendl;
                    }

                    prepend_comma = true;

                    if (!as_vector) {
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
                                if (i.second->get_type() == tracker_type::tracker_placeholder_missing) {
                                    tname = static_cast<tracker_element_placeholder *>(i.second.get())->get_name();
                                } else if (i.second->get_type() == tracker_type::tracker_alias) {
                                    tname = static_cast<tracker_element_alias *>(i.second.get())->get_alias_name();
                                } else {
                                    tname = Globalreg::globalreg->entrytracker->get_field_name(i.first);
                                }

                                // Default to the defined name if we got a blank
                                if (tname == "")
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
                as_vector = static_cast<tracker_element_int_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_int_map *>(e.get())->as_key_vector();

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
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_mac_map:
                as_vector = static_cast<tracker_element_mac_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_mac_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_mac_map *>(e.get())) {
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
            case tracker_type::tracker_uuid_map:
                as_vector = static_cast<tracker_element_uuid_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_uuid_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_uuid_map *>(e.get())) {
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
                as_vector = static_cast<tracker_element_string_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_string_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_string_map *>(e.get())) {
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
                as_vector = static_cast<tracker_element_double_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_double_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_double_map *>(e.get())) {
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
                as_vector = static_cast<tracker_element_hashkey_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_hashkey_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i: *static_cast<tracker_element_hashkey_map *>(e.get())) {
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
                as_vector = static_cast<tracker_element_double_map_double *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_double_map_double *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_double_map_double *>(e.get())) {
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
                        if (std::isnan(i.second) || std::isinf(i.second))
                            stream << "0";

                        if (floor(i.second) == i.second)
                            stream << fmt::format("{}", (long long) i.second);
                        else
                            stream << fmt::format("{:f}", i.second);
                    }
                }

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "]";
                else
                    stream << ppendl << indent << "}";

                break;
            case tracker_type::tracker_key_map:
                as_vector = static_cast<tracker_element_device_key_map *>(e.get())->as_vector();
                as_key_vector = static_cast<tracker_element_device_key_map *>(e.get())->as_key_vector();

                if (as_vector || as_key_vector)
                    stream << ppendl << indent << "[" << ppendl;
                else
                    stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_device_key_map *>(e.get())) {
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
            case tracker_type::tracker_pair_double:
                stream << "[" << 
                    dblstr.as_string(std::get<0>(static_cast<tracker_element_pair_double *>(e.get())->get()))
                    << ", " << 
                    dblstr.as_string(std::get<1>(static_cast<tracker_element_pair_double *>(e.get())->get()))
                    << "]"; 
                break;
            case tracker_type::tracker_summary_mapvec:
                // _MSG_DEBUG("serializing mapvec {}", static_cast<tracker_element_mapvec*>(e.get())->size());
                stream << ppendl << indent << "{" << ppendl;

                prepend_comma = false;
                for (auto i : *static_cast<tracker_element_mapvec*>(e.get())) {
                    bool named = false;

                    if (i == NULL) {
                        // _MSG_DEBUG("mapvec skipping null");
                        continue;
                    }

                    if (prepend_comma) {
                        stream << "," << ppendl;

                        if (prettyprint)
                            stream << ppendl;
                    }

                    prepend_comma = true;

                    if (name_map != NULL) {
                        tracker_element_serializer::rename_map::iterator nmi = name_map->find(i);
                        if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                            tname = nmi->second->rename;
                            named = true;
                        }
                    }

                    if (!named) {
                        if (i->get_type() == tracker_type::tracker_placeholder_missing) {
                            tname = static_cast<tracker_element_placeholder *>(i.get())->get_name();
                        } else if (i->get_type() == tracker_type::tracker_alias) {
                            tname = static_cast<tracker_element_alias *>(i.get())->get_alias_name();
                        } else {
                            tname = Globalreg::globalreg->entrytracker->get_field_name(i->get_id());
                        }

                        // Default to the defined name if we got a blank
                        if (tname == "")
                            tname = Globalreg::globalreg->entrytracker->get_field_name(i->get_id());
                    }

                    tname = json_adapter::sanitize_string(name_permuter(tname));

                    if (prettyprint) {
                        stream << indent << "\"description." << tname << "\": ";
                        stream << "\"";

                        stream << sanitize_string(i->get_type_as_string());
                        stream << ", ";

                        stream << sanitize_string(Globalreg::globalreg->entrytracker->get_field_description(i->get_id()));
                        stream << "\"," << ppendl;
                    }

                    stream << indent << "\"" << tname << "\": ";

                    json_adapter::pack(stream, i, name_map, prettyprint, depth + 1, name_permuter);
                }

                stream << ppendl << indent << "}";

                break;
            default:
                break;
        }
    }

}

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        pack(stream, in_elem, name_map);
        return 0;
    }
};

};

namespace translated_adapter {

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        json_adapter::pack(stream, in_elem, name_map, false, 0,
                           [](const std::string& s) { 
                               return multi_replace_all(s, ".", "_");
                           });
        return 0;
    }
};

};


// "ELK-style" JSON adapter.  This will behave the same as the normal JSON
// serializer with a few important differences:  
// 1. If the top-level object *is a vector type*, it will serialize each 
// member of the vector independently as a complete JSON object separated 
// by newlines.  This allows for a 'streamed' JSON output which will not 
// require loading the entire object into RAM.
// 2. To avoid conflicts with the ELK interpretation of field names, all 
// dots are converted to underscores
namespace ek_json_adapter {

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        kis_lock_guard<kis_mutex> lk(mutex, "ek_json serialize");

        if (in_elem->get_type() == tracker_type::tracker_vector) {
            for (auto i : *(std::static_pointer_cast<tracker_element_vector>(in_elem))) {
                if (i == nullptr)
                    continue;

                json_adapter::pack(stream, i, name_map, false, 0,
                        [](const std::string& s) { 
                            return multi_replace_all(s, ".", "_");
                        });
                stream << "\n";
            }
        } else {
            json_adapter::pack(stream, in_elem, name_map, false, 0,
                    [](const std::string& s) { 
                    return multi_replace_all(s, ".", "_");
                    });
            stream << "\n";
        }

        return 0;
    }
};

}

// Iterative JSON
// The 'old' ekjson format, iterative json converts all *vector objects* into *an object per
// newline*.  This retains the existing kismet names for fields.
namespace it_json_adapter {
class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        kis_lock_guard<kis_mutex> lk(mutex, "it_json serialize");

        if (in_elem->get_type() == tracker_type::tracker_vector) {
            for (auto i : *(std::static_pointer_cast<tracker_element_vector>(in_elem))) {
                json_adapter::pack(stream, i, name_map);
                stream << "\n";
            }
        } else {
            json_adapter::pack(stream, in_elem, name_map);
            stream << "\n";
        }

        return 1;
    }
};

}

// "Pretty" JSON adapter.  This will include metadata about the fields, and format
// it to be human readable.
namespace pretty_json_adapter {

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        // Call the packer in pretty mode
        json_adapter::pack(stream, in_elem, name_map, true, 1);

        return 1;
    }

};

}

#endif
