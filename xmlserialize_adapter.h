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

#ifndef __XMLSERIALIZE_ADAPTER_H__
#define __XMLSERIALIZE_ADAPTER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>

#include "globalregistry.h"
#include "trackedelement.h"
#include "entrytracker.h"
#include "devicetracker_component.h"

/* XML serialization
 *
 * If a record exists to map a field name to a tag, create that tag and insert the
 * data.
 *
 * If the record also contains paths to insert attributes, generate and insert
 * those.
 *
 * For instance:
 * kismet.device.base.freq_mhz_map -> frequencies
 * map_entry_element -> frequency
 * map_key_attribute -> freq
 * map_entry_attribute -> packets
 *
 * would generate
 * <frequencies>
 *  <frequency freq="1234" packets="5678"/>
 * </frequencies>
 *
 */

class XmlserializeAdapter {
public:
    XmlserializeAdapter(GlobalRegistry *in_globalreg) {
        globalreg = in_globalreg;
    }

    ~XmlserializeAdapter();

    void XmlSerialize(TrackerElement *v, std::stringstream &steam);

    void RegisterField(string in_field, string in_entity);
    void RegisterFieldAttr(string in_field, string in_path, string in_attr);
    void RegisterFieldXsitype(string in_field, string in_xsi);
    void RegisterMapField(string in_field, string in_entity, 
            string in_map_entity, string in_map_key_attr, 
            string in_map_value_attr);

    void RegisterFieldNamespace(string in_field, string in_ns,
            string in_nsloc, string in_url);
    void RegisterFieldSchema(string in_field, string in_ns, 
            string in_nslocation, string in_url);

protected:
    GlobalRegistry *globalreg;

    class Schemaimportlocation {
    public:
        string ns;
        string nslocation;
        string url;
    };

    class Xmladapter {
    public:
        ~Xmladapter() {
            for (unsigned int i = 0; i < schema_import_vector.size(); i++) {
                delete schema_import_vector[i];
            }
        }

        // Map a kismet record to a XML tag
        string kis_field;
        string xml_entity;

        // Local namespace for this tag
        string local_namespace;
        string namespace_location;
        string xsi_schema_location;

        string xml_xsi_type;

        // Map child elements to attributes
        map<string, string> kis_path_xml_element_map;

        // If we represent an int or mac map, the element and attribute
        // values.  Nested values must be simple types - a nested map cannot
        // be summarized as an attribute
        bool map_entries = false;
        string map_entry_element;
        string map_key_attribute;
        string map_value_attribute;

       
        // List of items to be included in the xs:schema tag
        vector<Schemaimportlocation *> schema_import_vector;
    };

    bool StreamSimpleValue(TrackerElement *v, std::stringstream &stream);

    map<string, Xmladapter *> field_adapter_map;
};

#endif

