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

void JsonAdapter::Pack(GlobalRegistry *globalreg, std::stringstream &stream, 
        tracker_component *c) {
    Pack(globalreg, stream, (TrackerElement *) c);
}

string JsonAdapter::SanitizeString(string in) {
    return MultiReplaceAll(in, "\\", "\\\\");
}


void JsonAdapter::Pack(GlobalRegistry *globalreg, std::stringstream &stream,
    TrackerElement *e) {

    e->pre_serialize();

    // XXX no, they don't, this only happens when we're a map of some sort,
    // vectors etc get normal treatment.  Delete this after confirmation.
    /*
    // All fields get "name": [value]
    stream << "\"" << globalreg->entrytracker->GetFieldName(e->get_id()) <<
        "\":";
    */

    TrackerElement::tracked_vector *tvec;
    TrackerElement::vector_iterator vec_iter;

    TrackerElement::tracked_map *tmap;
    TrackerElement::map_iterator map_iter;

    TrackerElement::tracked_mac_map *tmacmap;
    TrackerElement::mac_map_iterator mac_map_iter;

    TrackerElement::tracked_string_map *tstringmap;
    TrackerElement::string_map_iterator string_map_iter;

    TrackerElement::tracked_double_map *tdoublemap;
    TrackerElement::double_map_iterator double_map_iter;

    mac_addr mac;
    uuid euuid;

    string tname;

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
            stream << GetTrackerValue<float>(e);
            break;
        case TrackerDouble:
            stream << GetTrackerValue<double>(e);
            break;
        case TrackerMac:
            mac = GetTrackerValue<mac_addr>(e);
            // Mac is quoted as a string value
            stream << "\"" << mac.MacFull2String() << "\"";
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
                JsonAdapter::Pack(globalreg, stream, *vec_iter);
                if (++vec_iter != tvec->end())
                    stream << ",";
            }
            stream << "]";
            break;
        case TrackerMap:
            tmap = e->get_map();
            stream << "{";
            for (map_iter = tmap->begin(); map_iter != tmap->end(); /* */) {
                if ((tname = map_iter->second->get_local_name()) == "")
                    tname = globalreg->entrytracker->GetFieldName(map_iter->first);

                // JSON is special, and considers '.' to be a path separator, so
                // change all our '.' to '_'.
                std::replace(tname.begin(), tname.end(), '.', '_');

                tname = SanitizeString(tname);

                stream << "\"" << 
                    tname <<
                    "\": ";
                JsonAdapter::Pack(globalreg, stream, map_iter->second);
                if (++map_iter != tmap->end()) // Increment iter in loop
                    stream << ",";
            }
            stream << "}";
            break;
        case TrackerIntMap:
            tmap = e->get_intmap();
            stream << "{";
            for (map_iter = tmap->begin(); map_iter != tmap->end(); /* */) {
                // Integer dictionary keys in json are still quoted as strings
                stream << "\"" << map_iter->first << "\": ";
                JsonAdapter::Pack(globalreg, stream, map_iter->second);
                if (++map_iter != tmap->end()) // Increment iter in loop
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
                JsonAdapter::Pack(globalreg, stream, mac_map_iter->second);
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
                JsonAdapter::Pack(globalreg, stream, string_map_iter->second);
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
                stream << "\"" << double_map_iter->first << "\": ";
                JsonAdapter::Pack(globalreg, stream, double_map_iter->second);
                if (++double_map_iter != tdoublemap->end())
                    stream << ",";
            }
            stream << "}";
            break;
        default:
            break;

    }
}
