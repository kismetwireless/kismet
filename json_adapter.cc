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

/* StringExtraSpace and SanitizeString taken from nlohmann's jsonhpp library,
   Copyright 2013-2015 Niels Lohmann. and under the MIT license */
std::size_t JsonAdapter::StringExtraSpace(const std::string& s) noexcept {
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

std::string JsonAdapter::SanitizeString(const std::string& s) noexcept {
    const auto space = StringExtraSpace(s);
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

void JsonAdapter::Pack(std::ostream &stream, SharedTrackerElement e, 
        std::shared_ptr<TrackerElementSerializer::rename_map> name_map,
        bool prettyprint, unsigned int depth) {

    std::string indent;
    std::string ppendl;
    
    if (prettyprint) {
        indent = std::string(depth, ' ');
        ppendl = "\r\n";
    }

    if (e == NULL) {
        return;
    }

    SerializerScope s(e, name_map);

    mac_addr mac;
    uuid euuid;

    std::string tname;

    std::string bytes;
    const char* bytes_c;

    bool prepend_comma;

    std::ios::fmtflags fflags;

    switch (e->get_type()) {
        case TrackerType::TrackerString:
            stream << "\"" << SanitizeString(GetTrackerValue<std::string>(e)) << "\"";
            break;
        case TrackerType::TrackerInt8:
            stream << (int) GetTrackerValue<int8_t>(e);
            break;
        case TrackerType::TrackerUInt8:
            stream << (unsigned int) GetTrackerValue<uint8_t>(e);
            break;
        case TrackerType::TrackerInt16:
            stream << (int) GetTrackerValue<int16_t>(e);
            break;
        case TrackerType::TrackerUInt16:
            stream << (unsigned int) GetTrackerValue<uint16_t>(e);
            break;
        case TrackerType::TrackerInt32:
            stream << GetTrackerValue<int32_t>(e);
            break;
        case TrackerType::TrackerUInt32:
            stream << GetTrackerValue<uint32_t>(e);
            break;
        case TrackerType::TrackerInt64:
            stream << GetTrackerValue<int64_t>(e);
            break;
        case TrackerType::TrackerUInt64:
            stream << GetTrackerValue<uint64_t>(e);
            break;
        case TrackerType::TrackerFloat:
            if (std::isnan(GetTrackerValue<float>(e)) || std::isinf(GetTrackerValue<float>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<float>(e);
            break;
        case TrackerType::TrackerDouble:
            if (std::isnan(GetTrackerValue<double>(e)) || std::isinf(GetTrackerValue<double>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<double>(e);
            break;
        case TrackerType::TrackerMac:
            mac = GetTrackerValue<mac_addr>(e);
            // Mac is quoted as a string value, mac only
            stream << "\"" << mac << "\"";
            break;
        case TrackerType::TrackerUuid:
            euuid = GetTrackerValue<uuid>(e);
            // UUID is quoted as a string value
            stream << "\"" << euuid << "\"";
            break;
        case TrackerType::TrackerKey:
            stream << "\"" << GetTrackerValue<device_key>(e) << "\"";
            break;
        case TrackerType::TrackerVector:
            stream << ppendl << indent << "[" << ppendl;

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<TrackerElementVector>(e))) {
                if (i == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                if (prettyprint)
                    stream << indent;

                JsonAdapter::Pack(stream, i, name_map, prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "]";
            break;
        case TrackerType::TrackerVectorDouble:
            stream << ppendl << indent << "[" << ppendl;

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<TrackerElementVectorDouble>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                if (prettyprint)
                    stream << indent;

                stream << i;

                stream << ppendl;
            }
            stream << indent << "]";
            break;
        case TrackerType::TrackerVectorString:
            stream << ppendl << indent << "[" << ppendl;

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<TrackerElementVectorString>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                if (prettyprint)
                    stream << indent;

                stream << i;

                stream << ppendl;
            }
            stream << indent << "]";
            break;
        case TrackerType::TrackerMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                bool named = false;

                if (name_map != NULL) {
                    TrackerElementSerializer::rename_map::iterator nmi = name_map->find(i.second);
                    if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                        tname = nmi->second->rename;
                        named = true;
                    }
                }

                if (!named) {
                    if (i.second == NULL) {
                        tname = Globalreg::globalreg->entrytracker->GetFieldName(i.first);
                    } else {
                        if ((tname = i.second->get_local_name()) == "")
                            tname = Globalreg::globalreg->entrytracker->GetFieldName(i.first);
                    }
                }

                tname = SanitizeString(tname);

                if (prettyprint) {
                    stream << indent << "\"description." << tname << "\": ";
                    stream << "\"";
                    if (i.second != nullptr) {
                        stream << SanitizeString(i.second->get_type_as_string());
                        stream << ", ";
                    }
                    stream << SanitizeString(Globalreg::globalreg->entrytracker->GetFieldDescription(i.first));
                    stream << "\",";
                    stream << ppendl;
                }

                stream << indent << "\"" << tname << "\": ";

                JsonAdapter::Pack(stream, i.second, name_map, prettyprint, depth + 1);

                stream << ppendl << ppendl;
            }
            stream << indent << "}";

            break;
        case TrackerType::TrackerIntMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementIntMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Integer dictionary keys in json are still quoted as strings
                stream << indent << "\"" << i.first << "\": ";
                JsonAdapter::Pack(stream, i.second, name_map, prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerMacMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementMacMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Mac keys are strings and we push only the mac not the mask */
                stream << indent << "\"" << i.first << "\": ";
                JsonAdapter::Pack(stream, i.second, name_map, prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerStringMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementStringMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << indent << "\"" << JsonAdapter::SanitizeString(i.first) << "\": ";
                JsonAdapter::Pack(stream, i.second, name_map, prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerDoubleMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementDoubleMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << indent << "\"" << std::fixed << i.first << "\": ";
                JsonAdapter::Pack(stream, i.second, name_map, prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerHashkeyMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementHashkeyMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << indent << "\"" << std::fixed << i.first << "\": ";
                JsonAdapter::Pack(stream, i.second, name_map, prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerDoubleMapDouble:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementDoubleMapDouble>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << indent << "\"" << std::fixed << i.first << "\": ";
                stream << i.second;
                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerKeyMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementDeviceKeyMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Keymap keys are handled as strings
                stream << indent << "\"" << i.first << "\": ";
                JsonAdapter::Pack(stream,i.second, name_map, prettyprint, depth + 1);
                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerType::TrackerByteArray:
            bytes = std::static_pointer_cast<TrackerElementByteArray>(e)->get();
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
}

// An unfortunate duplication of code but overloading the json/prettyjson to also do
// storage tagging would get a bit out of hand
void StorageJsonAdapter::Pack(std::ostream &stream, SharedTrackerElement e, 
        std::shared_ptr<TrackerElementSerializer::rename_map> name_map) {

    if (e == nullptr) {
        stream << "0";
        return;
    }

    SerializerScope s(e, name_map);

    mac_addr mac;
    uuid euuid;
    device_key key;

    std::string tname;

    std::string bytes;
    const char* bytes_c;

    std::ios::fmtflags fflags;

    bool prepend_comma;

    // Every record gets wrapped into it's own object export with metadata
    stream << "{";

    // Name metadata; duplicate if we're a nested field object but consistent
    stream << "\"on\": \"";
    stream << JsonAdapter::SanitizeString(Globalreg::globalreg->entrytracker->GetFieldName(e->get_id()));
    stream << "\",";

    // Type metadata; raw element type
    stream << "\"ot\": \"";
    stream << JsonAdapter::SanitizeString(TrackerElement::type_to_typestring(e->get_type()));
    stream << "\",";

    // Actual data blob for object
    stream << "\"od\": ";

    switch (e->get_type()) {
        case TrackerType::TrackerString:
            stream << "\"" << JsonAdapter::SanitizeString(GetTrackerValue<std::string>(e)) << "\"";
            break;
        case TrackerType::TrackerInt8:
            stream << (int) GetTrackerValue<int8_t>(e);
            break;
        case TrackerType::TrackerUInt8:
            stream << (unsigned int) GetTrackerValue<uint8_t>(e);
            break;
        case TrackerType::TrackerInt16:
            stream << (int) GetTrackerValue<int16_t>(e);
            break;
        case TrackerType::TrackerUInt16:
            stream << (unsigned int) GetTrackerValue<uint16_t>(e);
            break;
        case TrackerType::TrackerInt32:
            stream << GetTrackerValue<int32_t>(e);
            break;
        case TrackerType::TrackerUInt32:
            stream << GetTrackerValue<uint32_t>(e);
            break;
        case TrackerType::TrackerInt64:
            stream << GetTrackerValue<int64_t>(e);
            break;
        case TrackerType::TrackerUInt64:
            stream << GetTrackerValue<uint64_t>(e);
            break;
        case TrackerType::TrackerFloat:
            if (std::isnan(GetTrackerValue<float>(e)) || std::isinf(GetTrackerValue<float>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<float>(e);
            break;
        case TrackerType::TrackerDouble:
            if (std::isnan(GetTrackerValue<double>(e)) || std::isinf(GetTrackerValue<double>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<double>(e);
            break;
        case TrackerType::TrackerMac:
            mac = GetTrackerValue<mac_addr>(e);
            // Mac is quoted as a string value, mac only
            stream << "\"" << mac << "\"";
            break;
        case TrackerType::TrackerUuid:
            euuid = GetTrackerValue<uuid>(e);
            // UUID is quoted as a string value
            stream << "\"" << euuid << "\"";
            break;
        case TrackerType::TrackerKey:
            stream << "\"" << GetTrackerValue<device_key>(e) << "\"";
            break;
        case TrackerType::TrackerVector:
            stream << "[";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementVector>(e))) {
                if (i == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                StorageJsonAdapter::Pack(stream, i, name_map);
            }
            stream << "]";
            break;
        case TrackerType::TrackerVectorDouble:
            stream << "[";

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<TrackerElementVectorDouble>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << i;
            }
            stream << "]";
            break;
        case TrackerType::TrackerVectorString:
            stream << "[";

            prepend_comma = false;

            for (auto i : *(std::static_pointer_cast<TrackerElementVectorString>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << i;
            }
            stream << "]";
            break;
        case TrackerType::TrackerMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                bool named = false;

                if (name_map != NULL) {
                    TrackerElementSerializer::rename_map::iterator nmi = name_map->find(i.second);
                    if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                        tname = nmi->second->rename;
                        named = true;
                    }
                }

                if (!named) {
                    if (i.second == NULL) {
                        tname = Globalreg::globalreg->entrytracker->GetFieldName(i.first);
                    } else {
                        if ((tname = i.second->get_local_name()) == "")
                            tname = Globalreg::globalreg->entrytracker->GetFieldName(i.first);
                    }
                }

                tname = JsonAdapter::SanitizeString(tname);

                stream << "\"" << tname << "\":";

                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";

            break;
        case TrackerType::TrackerIntMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementIntMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Integer dictionary keys in json are still quoted as strings
                stream << "\"" << i.first << "\": ";
                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerType::TrackerMacMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementMacMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Mac keys are strings and we push only the mac not the mask */
                stream << "\"" << i.first << "\": ";
                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerType::TrackerStringMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementStringMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << "\"" << JsonAdapter::SanitizeString(i.first) << "\": ";
                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerType::TrackerDoubleMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementDoubleMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << "\"" << std::fixed << i.first << "\": ";
                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerType::TrackerHashkeyMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementHashkeyMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << "\"" << std::fixed << i.first << "\": ";
                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerType::TrackerDoubleMapDouble:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementDoubleMapDouble>(e))) {
                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << "\"" << std::fixed << i.first << "\": ";
                stream << i.second;
            }
            stream << "}";
            break;
        case TrackerType::TrackerKeyMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(std::static_pointer_cast<TrackerElementDeviceKeyMap>(e))) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Keymap keys are handled as strings
                stream << "\"" << i.first << "\": ";
                StorageJsonAdapter::Pack(stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerType::TrackerByteArray:
            bytes = std::static_pointer_cast<TrackerElementByteArray>(e)->get();
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

    // Close wrapping object
    stream << "}";
}
