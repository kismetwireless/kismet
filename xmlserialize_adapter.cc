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

#include "util.h"
#include "xmlserialize_adapter.h"

XmlserializeAdapter::~XmlserializeAdapter() {
    map<string, Xmladapter *>::iterator i;

    for (i = field_adapter_map.begin(); i != field_adapter_map.end(); ++i) {
        delete i->second;
    }
}

void XmlserializeAdapter::XmlSerialize(TrackerElement *v, 
        std::stringstream &stream) {
    v->pre_serialize();

    TrackerElement::tracked_map *tmap;
    TrackerElement::map_iterator map_iter;

    TrackerElement::tracked_mac_map *tmacmap;
    TrackerElement::mac_map_iterator mac_map_iter;

    vector<TrackerElement *> *tvec;
    unsigned int tvi;

    string name = globalreg->entrytracker->GetFieldName(v->get_id());

    map<string, Xmladapter *>::iterator mi = 
        field_adapter_map.find(StrLower(name));

    if (mi == field_adapter_map.end()) {
        fprintf(stderr, "debug - xmlserialize no xml field for %s\n", name.c_str());
        return;
    }

    Xmladapter *adapter = mi->second;

    string xsi;

    if (adapter->xml_xsi != "")
        xsi += " xsi:type=\"" + adapter->xml_xsi + "\"";

    stream << "<" << adapter->xml_entity << xsi << ">";

    switch (v->get_type()) {
        case TrackerString:
        case TrackerInt8:
        case TrackerUInt8:
        case TrackerInt16:
        case TrackerUInt16:
        case TrackerInt32:
        case TrackerUInt32:
        case TrackerInt64:
        case TrackerUInt64:
        case TrackerFloat:
        case TrackerDouble:
        case TrackerMac:
        case TrackerUuid:
            StreamSimpleValue(v, stream);
            break;
        case TrackerVector:
            tvec = v->get_vector();
            for (tvi = 0; tvi < tvec->size(); tvi++) {
                XmlSerialize((*tvec)[tvi], stream);
            }
            break;
        case TrackerMap:
            tmap = v->get_map();
            for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                    ++map_iter) {
                XmlSerialize(map_iter->second, stream);
            }
            break;
        case TrackerIntMap:
            tmap = v->get_intmap();

            if (adapter->map_entries) {
                // Assumes our children are simple types
                // TODO be smarter
                for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                        ++map_iter) {
                    stream << "<" << adapter->map_entry_element <<
                        " " << adapter->map_key_attribute << "=\"" <<
                        map_iter->first << "\" " <<
                        adapter->map_value_attribute << "=\"";
                    StreamSimpleValue(map_iter->second, stream);
                    stream << "\" />";
                }
            }
            break;
        case TrackerMacMap:
            tmacmap = v->get_macmap();
            if (adapter->map_entries) {
                // Assumes our children are simple types
                // TODO be smarter
                for (mac_map_iter = tmacmap->begin(); mac_map_iter != tmacmap->end(); 
                        ++mac_map_iter) {
                    stream << "<" << adapter->map_entry_element <<
                        " " << adapter->map_key_attribute << "=\"" <<
                        mac_map_iter->first.MacFull2String() << "\" " <<
                        adapter->map_value_attribute << "=\"";
                    StreamSimpleValue(mac_map_iter->second, stream);
                    stream << "\" />";
                }
            }
        default:
            break;
    }

    stream << "</" << adapter->xml_entity << ">";

}

bool XmlserializeAdapter::StreamSimpleValue(TrackerElement *v,
        std::stringstream &stream) {
    switch (v->get_type()) {
        case TrackerString:
            stream << SanitizeXML(GetTrackerValue<string>(v));
            break;
        case TrackerInt8:
            stream << GetTrackerValue<int8_t>(v);
            break;
        case TrackerUInt8:
            stream << GetTrackerValue<uint8_t>(v);
            break;
        case TrackerInt16:
            stream << GetTrackerValue<int16_t>(v);
            break;
        case TrackerUInt16:
            stream << GetTrackerValue<uint16_t>(v);
            break;
        case TrackerInt32:
            stream << GetTrackerValue<int32_t>(v);
            break;
        case TrackerUInt32:
            stream << GetTrackerValue<uint32_t>(v);
            break;
        case TrackerInt64:
            stream << GetTrackerValue<int64_t>(v);
            break;
        case TrackerUInt64:
            stream << GetTrackerValue<uint64_t>(v);
            break;
        case TrackerFloat:
            stream << GetTrackerValue<float>(v);
            break;
        case TrackerDouble:
            stream << GetTrackerValue<double>(v);
            break;
        case TrackerMac:
            stream << GetTrackerValue<mac_addr>(v).MacFull2String();
            break;
        case TrackerUuid:
            stream << GetTrackerValue<uuid>(v).UUID2String();
            break;
        default:
            return false;
    }

    return true;
}

void XmlserializeAdapter::RegisterField(string in_field, string in_entity) {
    Xmladapter *adapter;

    map<string, Xmladapter *>::iterator mi = 
        field_adapter_map.find(StrLower(in_field));
    if (mi == field_adapter_map.end()) {
        adapter = new Xmladapter();
        field_adapter_map[StrLower(in_field)] = adapter;
    }  else {
        adapter = mi->second;
    }

    adapter->kis_field = in_field;
    adapter->xml_entity = in_entity;
}

void XmlserializeAdapter::RegisterFieldAttr(string in_field, string in_path,
        string in_attr) {
    Xmladapter *adapter;
    map<string, Xmladapter *>::iterator mi =
        field_adapter_map.find(StrLower(in_field));

    if (mi == field_adapter_map.end())
        return;

    adapter = mi->second;

    adapter->kis_path_xml_element_map[StrLower(in_path)] = in_attr;
}

void XmlserializeAdapter::RegisterFieldXsitype(string in_field, string in_xsi) {
    Xmladapter *adapter;
    map<string, Xmladapter *>::iterator mi =
        field_adapter_map.find(StrLower(in_field));

    if (mi == field_adapter_map.end())
        return;

    adapter = mi->second;

    adapter->xml_xsi = in_xsi;
}

void XmlserializeAdapter::RegisterMapField(string in_field, string in_entity, 
        string in_map_entity, string in_map_key_attr, string in_map_value_attr) {

    Xmladapter *adapter;
    map<string, Xmladapter *>::iterator mi =
        field_adapter_map.find(StrLower(in_field));

    if (mi != field_adapter_map.end()) {
        adapter = mi->second;
    } else {
        adapter = new Xmladapter();
        field_adapter_map[StrLower(in_field)] = adapter;
    }

    adapter->kis_field = in_field;
    adapter->xml_entity = in_entity;
    adapter->map_entries = true;
    adapter->map_entry_element = in_map_entity;
    adapter->map_key_attribute = in_map_key_attr;
    adapter->map_value_attribute = in_map_value_attr;

}

