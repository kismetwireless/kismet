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


std::string JsonAdapter::SanitizeString(std::string in) {
    std::string itr = MultiReplaceAll(in, "\\", "\\\\");
    itr = MultiReplaceAll(itr, "\"", "\\\"");
    return itr;
}

void JsonAdapter::Pack(GlobalRegistry *globalreg, std::ostream &stream,
    SharedTrackerElement e, TrackerElementSerializer::rename_map *name_map,
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

    std::shared_ptr<uint8_t> bytes;

    bool prepend_comma;

    size_t sz;
    std::ios::fmtflags fflags;

    switch (e->get_type()) {
        case TrackerString:
            stream << "\"" << SanitizeString(GetTrackerValue<std::string>(e)) << "\"";
            break;
        case TrackerInt8:
            stream << (int) GetTrackerValue<int8_t>(e);
            break;
        case TrackerUInt8:
            stream << (unsigned int) GetTrackerValue<uint8_t>(e);
            break;
        case TrackerInt16:
            stream << (int) GetTrackerValue<int16_t>(e);
            break;
        case TrackerUInt16:
            stream << (unsigned int) GetTrackerValue<uint16_t>(e);
            break;
        case TrackerInt32:
            stream << GetTrackerValue<int32_t>(e);
            break;
        case TrackerUInt32:
            stream << GetTrackerValue<uint32_t>(e);
            break;
        case TrackerInt64:
            stream << GetTrackerValue<int64_t>(e);
            break;
        case TrackerUInt64:
            stream << GetTrackerValue<uint64_t>(e);
            break;
        case TrackerFloat:
            if (std::isnan(GetTrackerValue<float>(e)) || std::isinf(GetTrackerValue<float>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<float>(e);
            break;
        case TrackerDouble:
            if (std::isnan(GetTrackerValue<double>(e)) || std::isinf(GetTrackerValue<double>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<double>(e);
            break;
        case TrackerMac:
            mac = GetTrackerValue<mac_addr>(e);
            // Mac is quoted as a string value, mac only
            stream << "\"" << mac.Mac2String() << "\"";
            break;
        case TrackerUuid:
            euuid = GetTrackerValue<uuid>(e);
            // UUID is quoted as a string value
            stream << "\"" << euuid.UUID2String() << "\"";
            break;
        case TrackerKey:
            stream << "\"" << GetTrackerValue<TrackedDeviceKey>(e).as_string() << "\"";
            break;
        case TrackerVector:
            stream << ppendl << indent << "[" << ppendl;

            prepend_comma = false;

            for (auto i : *(e->get_vector())) {
                if (i == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                if (prettyprint)
                    stream << indent;

                JsonAdapter::Pack(globalreg, stream, i, name_map,
                        prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "]";
            break;
        case TrackerMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(e->get_map())) {
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
                        tname = globalreg->entrytracker->GetFieldName(i.first);
                    } else {
                        if ((tname = i.second->get_local_name()) == "")
                            tname = globalreg->entrytracker->GetFieldName(i.first);
                    }
                }

                tname = SanitizeString(tname);

                if (prettyprint) {
                    stream << indent << "\"description." << tname << "\": ";
                    stream << "\"";
                    stream << SanitizeString(TrackerElement::type_to_string(globalreg->entrytracker->GetFieldType(i.first)));
                    stream << ", ";
                    stream << SanitizeString(globalreg->entrytracker->GetFieldDescription(i.first));
                    stream << "\",";
                    stream << ppendl;
                }

                stream << indent << "\"" << tname << "\": ";

                JsonAdapter::Pack(globalreg, stream, i.second, name_map, 
                        prettyprint, depth + 1);

                stream << ppendl << ppendl;
            }
            stream << indent << "}";

            break;
        case TrackerIntMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(e->get_intmap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Integer dictionary keys in json are still quoted as strings
                stream << indent << "\"" << i.first << "\": ";
                JsonAdapter::Pack(globalreg, stream, i.second, name_map,
                        prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerMacMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(e->get_macmap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Mac keys are strings and we push only the mac not the mask */
                stream << indent << "\"" << i.first.Mac2String() << "\": ";
                JsonAdapter::Pack(globalreg, stream, i.second, name_map,
                        prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerStringMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(e->get_stringmap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << indent << "\"" << JsonAdapter::SanitizeString(i.first) << "\": ";
                JsonAdapter::Pack(globalreg, stream, i.second, name_map,
                        prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerDoubleMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(e->get_doublemap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << indent << "\"" << std::fixed << i.first << "\": ";
                JsonAdapter::Pack(globalreg, stream, i.second, name_map,
                        prettyprint, depth + 1);

                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerKeyMap:
            stream << ppendl << indent << "{" << ppendl;

            prepend_comma = false;
            for (auto i : *(e->get_keymap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Keymap keys are handled as strings
                stream << indent << "\"" << i.first << "\": ";
                JsonAdapter::Pack(globalreg, stream,i.second, name_map,
                        prettyprint, depth + 1);
                stream << ppendl;
            }
            stream << indent << "}";
            break;
        case TrackerByteArray:
            bytes = e->get_bytearray();
            sz = e->get_bytearray_size();
           
            fflags = stream.flags();

            stream << "\"";
            for (size_t szx = 0; szx < sz; szx++) {
                stream << std::uppercase << std::setfill('0') << std::setw(2) 
                    << std::hex << (int) (bytes.get()[szx] & 0xFF);
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
void StorageJsonAdapter::Pack(GlobalRegistry *globalreg, std::ostream &stream,
    SharedTrackerElement e, TrackerElementSerializer::rename_map *name_map) {

    if (e == NULL) {
        stream << "0";
        return;
    }

    SerializerScope s(e, name_map);

    mac_addr mac;
    uuid euuid;
    TrackedDeviceKey key;

    std::string tname;

    std::shared_ptr<uint8_t> bytes;

    size_t sz;
    std::ios::fmtflags fflags;

    bool prepend_comma;

    // Every record gets wrapped into it's own object export with metadata
    stream << "{";

    // Name metadata; duplicte if we're a nested field object but consistent
    stream << "\"on\": \"";
    stream << JsonAdapter::SanitizeString(globalreg->entrytracker->GetFieldName(e->get_id()));
    stream << "\",";

    // Type metadata; raw element type
    stream << "\"ot\": \"";
    stream << JsonAdapter::SanitizeString(TrackerElement::type_to_typestring(e->get_type()));
    stream << "\",";

    // Actual data blob for object
    stream << "\"od\": ";

    switch (e->get_type()) {
        case TrackerString:
            stream << "\"" << JsonAdapter::SanitizeString(GetTrackerValue<std::string>(e)) << "\"";
            break;
        case TrackerInt8:
            stream << (int) GetTrackerValue<int8_t>(e);
            break;
        case TrackerUInt8:
            stream << (unsigned int) GetTrackerValue<uint8_t>(e);
            break;
        case TrackerInt16:
            stream << (int) GetTrackerValue<int16_t>(e);
            break;
        case TrackerUInt16:
            stream << (unsigned int) GetTrackerValue<uint16_t>(e);
            break;
        case TrackerInt32:
            stream << GetTrackerValue<int32_t>(e);
            break;
        case TrackerUInt32:
            stream << GetTrackerValue<uint32_t>(e);
            break;
        case TrackerInt64:
            stream << GetTrackerValue<int64_t>(e);
            break;
        case TrackerUInt64:
            stream << GetTrackerValue<uint64_t>(e);
            break;
        case TrackerFloat:
            if (std::isnan(GetTrackerValue<float>(e)) || std::isinf(GetTrackerValue<float>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<float>(e);
            break;
        case TrackerDouble:
            if (std::isnan(GetTrackerValue<double>(e)) || std::isinf(GetTrackerValue<double>(e)))
                stream << 0;
            else
                stream << std::fixed << GetTrackerValue<double>(e);
            break;
        case TrackerMac:
            mac = GetTrackerValue<mac_addr>(e);
            // Mac is quoted as a string value, mac only
            stream << "\"" << mac.Mac2String() << "\"";
            break;
        case TrackerUuid:
            euuid = GetTrackerValue<uuid>(e);
            // UUID is quoted as a string value
            stream << "\"" << euuid.UUID2String() << "\"";
            break;
        case TrackerKey:
            key = GetTrackerValue<TrackedDeviceKey>(e);
            stream << "\"" << key << "\"";
            break;
        case TrackerVector:
            stream << "[";

            prepend_comma = false;
            for (auto i : *(e->get_vector())) {
                if (i == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                StorageJsonAdapter::Pack(globalreg, stream, i, name_map);
            }
            stream << "]";
            break;
        case TrackerMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(e->get_map())) {
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
                        tname = globalreg->entrytracker->GetFieldName(i.first);
                    } else {
                        if ((tname = i.second->get_local_name()) == "")
                            tname = 
                                globalreg->entrytracker->GetFieldName(i.first);
                    }
                }

                tname = JsonAdapter::SanitizeString(tname);

                stream << "\"" << tname << "\":";

                StorageJsonAdapter::Pack(globalreg, stream, i.second, name_map);
            }
            stream << "}";

            break;
        case TrackerIntMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(e->get_intmap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Integer dictionary keys in json are still quoted as strings
                stream << "\"" << i.first << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerMacMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(e->get_macmap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Mac keys are strings and we push only the mac not the mask */
                stream << "\"" << i.first.Mac2String() << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerStringMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(e->get_stringmap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                stream << "\"" << JsonAdapter::SanitizeString(i.first) << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerDoubleMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(e->get_doublemap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Double keys are handled as strings in json
                stream << "\"" << std::fixed << i.first << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerKeyMap:
            stream << "{";

            prepend_comma = false;
            for (auto i : *(e->get_keymap())) {
                if (i.second == NULL)
                    continue;

                if (prepend_comma)
                    stream << ",";
                prepend_comma = true;

                // Keymap keys are handled as strings
                stream << "\"" << i.first << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, i.second, name_map);
            }
            stream << "}";
            break;
        case TrackerByteArray:
            bytes = e->get_bytearray();
            sz = e->get_bytearray_size();
           
            fflags = stream.flags();

            stream << "\"";
            for (size_t szx = 0; szx < sz; szx++) {
                stream << std::uppercase << std::setfill('0') << std::setw(2) 
                    << std::hex << (int) (bytes.get()[szx] & 0xFF);
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
