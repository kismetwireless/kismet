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

#include "globalregistry.h"
#include "trackedelement.h"
#include "macaddr.h"
#include "entrytracker.h"
#include "uuid.h"
#include "devicetracker_component.h"
#include "json_adapter.h"


string JsonAdapter::SanitizeString(string in) {
    string itr = MultiReplaceAll(in, "\\", "\\\\");
    itr = MultiReplaceAll(itr, "\"", "\\\"");
    return itr;
}

void JsonAdapter::Pack(GlobalRegistry *globalreg, std::ostream &stream,
    SharedTrackerElement e, TrackerElementSerializer::rename_map *name_map,
    bool prettyprint, unsigned int depth) {

    std::string indent;
    std::string endl;
    
    if (prettyprint) {
        indent = std::string(depth, ' ');
        endl = "\r\n";
    }

    if (e == NULL) {
        stream << "0";
        return;
    }

    // If we have a rename map, find out if we've got a pathed element that needs
    // to be custom-serialized
    if (name_map != NULL) {
        TrackerElementSerializer::rename_map::iterator nmi = name_map->find(e);
        if (nmi != name_map->end()) {
            TrackerElementSerializer::pre_serialize_path(nmi->second);
        } else {
            e->pre_serialize();
        } 
    } else {
        e->pre_serialize();
    }

    TrackerElement::tracked_vector *tvec;
    TrackerElement::vector_iterator vec_iter;

    TrackerElement::tracked_map *tmap;
    TrackerElement::map_iterator map_iter;

    TrackerElement::tracked_int_map *tintmap;
    TrackerElement::int_map_iterator int_map_iter;

    TrackerElement::tracked_mac_map *tmacmap;
    TrackerElement::mac_map_iterator mac_map_iter;

    TrackerElement::tracked_string_map *tstringmap;
    TrackerElement::string_map_iterator string_map_iter;

    TrackerElement::tracked_double_map *tdoublemap;
    TrackerElement::double_map_iterator double_map_iter;

    mac_addr mac;
    uuid euuid;

    string tname;

    shared_ptr<uint8_t> bytes;

    size_t sz;
    ios::fmtflags fflags;

    switch (e->get_type()) {
        case TrackerString:
            stream << "\"" << SanitizeString(GetTrackerValue<string>(e)) << "\"";
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
            stream << fixed << GetTrackerValue<float>(e);
            break;
        case TrackerDouble:
            stream << fixed << GetTrackerValue<double>(e);
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
        case TrackerVector:
            tvec = e->get_vector();
            stream << endl << indent << "[" << endl;
            for (vec_iter = tvec->begin(); vec_iter != tvec->end(); /* */ ) {
                if (prettyprint)
                    stream << indent;

                JsonAdapter::Pack(globalreg, stream, *vec_iter, name_map,
                        prettyprint, depth + 1);

                if (++vec_iter != tvec->end())
                    stream << ",";

                stream << endl;
            }
            stream << indent << "]";
            break;
        case TrackerMap:
            tmap = e->get_map();
            
            stream << endl << indent << "{" << endl;

            for (map_iter = tmap->begin(); map_iter != tmap->end(); /* */) {
                bool named = false;

                if (name_map != NULL) {
                    TrackerElementSerializer::rename_map::iterator nmi = 
                        name_map->find(map_iter->second);
                    if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                        tname = nmi->second->rename;
                        named = true;
                    }
                }

                if (!named) {
                    if (map_iter->second == NULL) {
                        tname = globalreg->entrytracker->GetFieldName(map_iter->first);
                    } else {
                        if ((tname = map_iter->second->get_local_name()) == "")
                            tname = 
                                globalreg->entrytracker->GetFieldName(map_iter->first);
                    }
                }

                tname = SanitizeString(tname);

                if (prettyprint) {
                    stream << indent << "\"description." << tname << "\": ";
                    stream << "\"";
                    stream << SanitizeString(TrackerElement::type_to_string(globalreg->entrytracker->GetFieldType(map_iter->first)));
                    stream << ", ";
                    stream << SanitizeString(globalreg->entrytracker->GetFieldDescription(map_iter->first));
                    stream << "\",";
                    stream << endl;
                }

                stream << indent << "\"" << tname << "\": ";

                JsonAdapter::Pack(globalreg, stream, map_iter->second, name_map, 
                        prettyprint, depth + 1);

                if (++map_iter != tmap->end()) // Increment iter in loop
                    stream << ",";

                stream << std::endl << std::endl;
            }
            stream << indent << "}";

            break;
        case TrackerIntMap:
            tintmap = e->get_intmap();

            stream << endl << indent << "{" << endl;

            for (int_map_iter = tintmap->begin(); int_map_iter != tintmap->end(); /* */) {
                // Integer dictionary keys in json are still quoted as strings
                stream << indent << "\"" << int_map_iter->first << "\": ";
                JsonAdapter::Pack(globalreg, stream, int_map_iter->second, name_map,
                        prettyprint, depth + 1);

                if (++int_map_iter != tintmap->end()) // Increment iter in loop
                    stream << ",";

                stream << endl;
            }
            stream << indent << "}";
            break;
        case TrackerMacMap:
            tmacmap = e->get_macmap();

            stream << endl << indent << "{" << endl;

            for (mac_map_iter = tmacmap->begin(); 
                    mac_map_iter != tmacmap->end(); /* */) {
                // Mac keys are strings and we push only the mac not the mask */
                stream << indent << "\"" << mac_map_iter->first.Mac2String() << "\": ";
                JsonAdapter::Pack(globalreg, stream, mac_map_iter->second, name_map,
                        prettyprint, depth + 1);

                if (++mac_map_iter != tmacmap->end())
                    stream << ",";

                stream << endl;
            }
            stream << indent << "}";
            break;
        case TrackerStringMap:
            tstringmap = e->get_stringmap();

            stream << endl << indent << "{" << endl;

            for (string_map_iter = tstringmap->begin();
                    string_map_iter != tstringmap->end(); /* */) {

                stream << indent << "\"" << string_map_iter->first << "\": ";
                JsonAdapter::Pack(globalreg, stream, string_map_iter->second, name_map,
                        prettyprint, depth + 1);

                if (++string_map_iter != tstringmap->end())
                    stream << ",";

                stream << endl;
            }
            stream << indent << "}";
            break;
        case TrackerDoubleMap:
            tdoublemap = e->get_doublemap();

            stream << endl << indent << "{" << endl;

            for (double_map_iter = tdoublemap->begin();
                    double_map_iter != tdoublemap->end(); /* */) {
                // Double keys are handled as strings in json
                stream << indent << "\"" << fixed << double_map_iter->first << "\": ";
                JsonAdapter::Pack(globalreg, stream, double_map_iter->second, name_map,
                        prettyprint, depth + 1);
                if (++double_map_iter != tdoublemap->end())
                    stream << ",";

                stream << endl;
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

    // If we have a rename map, find out if we've got a pathed element that needs
    // to be custom-serialized
    if (name_map != NULL) {
        TrackerElementSerializer::rename_map::iterator nmi = name_map->find(e);
        if (nmi != name_map->end()) {
            TrackerElementSerializer::pre_serialize_path(nmi->second);
        } else {
            e->pre_serialize();
        } 
    } else {
        e->pre_serialize();
    }

    TrackerElement::tracked_vector *tvec;
    TrackerElement::vector_iterator vec_iter;

    TrackerElement::tracked_map *tmap;
    TrackerElement::map_iterator map_iter;

    TrackerElement::tracked_int_map *tintmap;
    TrackerElement::int_map_iterator int_map_iter;

    TrackerElement::tracked_mac_map *tmacmap;
    TrackerElement::mac_map_iterator mac_map_iter;

    TrackerElement::tracked_string_map *tstringmap;
    TrackerElement::string_map_iterator string_map_iter;

    TrackerElement::tracked_double_map *tdoublemap;
    TrackerElement::double_map_iterator double_map_iter;

    mac_addr mac;
    uuid euuid;

    string tname;

    shared_ptr<uint8_t> bytes;

    size_t sz;
    ios::fmtflags fflags;

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
            stream << "\"" << JsonAdapter::SanitizeString(GetTrackerValue<string>(e)) << "\"";
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
            stream << fixed << GetTrackerValue<float>(e);
            break;
        case TrackerDouble:
            stream << fixed << GetTrackerValue<double>(e);
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
        case TrackerVector:
            tvec = e->get_vector();
            stream << "[";
            for (vec_iter = tvec->begin(); vec_iter != tvec->end(); /* */ ) {
                StorageJsonAdapter::Pack(globalreg, stream, *vec_iter, name_map);

                if (++vec_iter != tvec->end())
                    stream << ",";
            }
            stream << "]";
            break;
        case TrackerMap:
            tmap = e->get_map();
            
            stream << "{";

            for (map_iter = tmap->begin(); map_iter != tmap->end(); /* */) {
                bool named = false;

                if (name_map != NULL) {
                    TrackerElementSerializer::rename_map::iterator nmi = 
                        name_map->find(map_iter->second);
                    if (nmi != name_map->end() && nmi->second->rename.length() != 0) {
                        tname = nmi->second->rename;
                        named = true;
                    }
                }

                if (!named) {
                    if (map_iter->second == NULL) {
                        tname = globalreg->entrytracker->GetFieldName(map_iter->first);
                    } else {
                        if ((tname = map_iter->second->get_local_name()) == "")
                            tname = 
                                globalreg->entrytracker->GetFieldName(map_iter->first);
                    }
                }

                tname = JsonAdapter::SanitizeString(tname);

                stream << "\"" << tname << "\":";

                StorageJsonAdapter::Pack(globalreg, stream, map_iter->second, name_map);

                if (++map_iter != tmap->end()) // Increment iter in loop
                    stream << ",";
            }
            stream << "}";

            break;
        case TrackerIntMap:
            tintmap = e->get_intmap();

            stream << "{";

            for (int_map_iter = tintmap->begin(); int_map_iter != tintmap->end(); /* */) {
                // Integer dictionary keys in json are still quoted as strings
                stream << "\"" << int_map_iter->first << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, int_map_iter->second, name_map);

                if (++int_map_iter != tintmap->end()) // Increment iter in loop
                    stream << ",";
            }
            stream << "}";
            break;
        case TrackerMacMap:
            tmacmap = e->get_macmap();

            stream << "{";

            for (mac_map_iter = tmacmap->begin(); 
                    mac_map_iter != tmacmap->end(); /* */) {
                // Mac keys are strings and we push only the mac not the mask */
                stream << "\"" << mac_map_iter->first.Mac2String() << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, mac_map_iter->second, name_map);

                if (++mac_map_iter != tmacmap->end())
                    stream << ",";
            }
            stream << "}";
            break;
        case TrackerStringMap:
            tstringmap = e->get_stringmap();

            stream << "{";

            for (string_map_iter = tstringmap->begin();
                    string_map_iter != tstringmap->end(); /* */) {

                stream << "\"" << string_map_iter->first << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, string_map_iter->second, name_map);

                if (++string_map_iter != tstringmap->end())
                    stream << ",";
            }
            stream << "}";
            break;
        case TrackerDoubleMap:
            tdoublemap = e->get_doublemap();

            stream << "{";

            for (double_map_iter = tdoublemap->begin();
                    double_map_iter != tdoublemap->end(); /* */) {
                // Double keys are handled as strings in json
                stream << "\"" << fixed << double_map_iter->first << "\": ";
                StorageJsonAdapter::Pack(globalreg, stream, double_map_iter->second, name_map);
                if (++double_map_iter != tdoublemap->end())
                    stream << ",";
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
