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

#include <string>
#include <sstream>

#include "util.h"

#include "entrytracker.h"

EntryTracker::EntryTracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Stream_Handler(in_globalreg) {
    globalreg = in_globalreg;

    globalreg->InsertGlobal("ENTRY_TRACKER", this);

    next_field_num = 1;
}

EntryTracker::~EntryTracker() {
    globalreg->RemoveGlobal("ENTRY_TRACKER");
}

int EntryTracker::RegisterField(string in_name, TrackerType in_type, string in_desc) {
    string mod_name = StrLower(in_name);

    map<string, reserved_field *>::iterator iter = field_name_map.find(mod_name);

    if (iter != field_name_map.end()) {
        if (iter->second->builder != NULL) {
            fprintf(stderr, "debug - %s:%s %u tried to register field %s of type %s, but "
                    "already registered with a builder.\n", __FILE__, __func__, __LINE__,
                    mod_name.c_str(), TrackerElement::type_to_string(in_type).c_str());
            return -1;
        }

        if (iter->second->track_type != in_type) {
            fprintf(stderr, "debug - %s:%s %u tried to register field %s of type %s, but "
                    "already registered with type %s.\n", __FILE__, __func__, __LINE__,
                    mod_name.c_str(), TrackerElement::type_to_string(in_type).c_str(),
                    TrackerElement::type_to_string(iter->second->track_type).c_str());
            return -1;
        }

        return iter->second->field_id;
    }

    reserved_field *definition = new reserved_field();

    definition->field_id = next_field_num++;
    definition->field_name = in_name;

    definition->track_type = in_type;
    definition->builder = NULL;

    definition->field_description = in_desc;

    field_name_map[mod_name] = definition;
    field_id_map[definition->field_id] = definition;

    return definition->field_id;
}

int EntryTracker::RegisterField(string in_name, TrackerElement *in_builder, 
        string in_desc) {
    string mod_name = StrLower(in_name);

    map<string, reserved_field *>::iterator iter = field_name_map.find(mod_name);

    if (iter != field_name_map.end()) {
        if (iter->second->builder == NULL) {
            fprintf(stderr, "debug - %s:%s %u tried to register field %s with builder "
                    "but already registered with type %s.\n", __FILE__, 
                    __func__, __LINE__,
                    mod_name.c_str(), 
                    TrackerElement::type_to_string(iter->second->track_type).c_str());
            return -1;
        }

        return iter->second->field_id;
    }

    reserved_field *definition = new reserved_field();

    definition->field_id = next_field_num++;
    definition->field_name = in_name;

    definition->builder = in_builder->clone_type();

    definition->field_description = in_desc;

    field_name_map[mod_name] = definition;
    field_id_map[definition->field_id] = definition;

    // Set the builders ID now that we know it
    definition->builder->set_id(definition->field_id);

    return definition->field_id;
}

int EntryTracker::GetFieldId(string in_name) {
    string mod_name = StrLower(in_name);

    map<string, reserved_field *>::iterator itr = field_name_map.find(mod_name);

    if (itr == field_name_map.end()) {
        return -1;
    }

    return itr->second->field_id;
}

string EntryTracker::GetFieldName(int in_id) {
    map<int, reserved_field *>::iterator itr = field_id_map.find(in_id);

    if (itr == field_id_map.end()) {
        return "field.unknown.not.registered";
    }

    return itr->second->field_name;
}

TrackerElement *EntryTracker::RegisterAndGetField(string in_name, TrackerType in_type, 
        string in_desc) {

    int fn = GetFieldId(in_name);

    if (fn >= 0) {
        return GetTrackedInstance(fn);
    }

    fn = RegisterField(in_name, in_type, in_desc);

    return new TrackerElement(in_type, fn);
}

TrackerElement *EntryTracker::RegisterAndGetField(string in_name, 
        TrackerElement *in_builder, string in_desc) {
    int fn = GetFieldId(in_name);

    if (fn >= 0) {
        return GetTrackedInstance(fn);
    }

    fn = RegisterField(in_name, in_builder, in_desc);

    TrackerElement *clone = in_builder->clone_type(fn);

    return clone;
}


TrackerElement *EntryTracker::GetTrackedInstance(int in_id) {
    map<int, reserved_field *>::iterator itr = field_id_map.find(in_id);

    if (itr == field_id_map.end()) {
        return NULL;
    }

    reserved_field *definition;
    TrackerElement *ret;

    definition = itr->second;

    if (definition->builder == NULL)
        ret = new TrackerElement(definition->track_type, definition->field_id);
    else
        ret = definition->builder->clone_type(definition->field_id);

    return ret;

}

TrackerElement *EntryTracker::GetTrackedInstance(string in_name) {
    string mod_name = StrLower(in_name);

    map<string, reserved_field *>::iterator itr = field_name_map.find(mod_name);

    reserved_field *definition;
    TrackerElement *ret;

    // We don't know this
    if (itr == field_name_map.end()) {
        return NULL;
    }

    definition = itr->second;

    if (definition->builder == NULL)
        ret = new TrackerElement(definition->track_type, definition->field_id);
    else
        ret = definition->builder->clone_type(definition->field_id);

    return ret;
}

bool EntryTracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/system/tracked_fields.html") == 0)
        return true;

    return false;
}

void EntryTracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(path, "/system/tracked_fields.html") == 0) {
        stream << "<html><head><title>Kismet Server - Tracked Fields</title></head>";
        stream << "<body>";
        stream << "<h2>Kismet field descriptions</h2>";
        stream << "<table padding=\"5\">";
        stream << "<tr><td><b>Name</b></td><td><b>Type</b></td><td><b>Description</b></td></tr>";

        for (map<int, reserved_field *>::iterator i = field_id_map.begin();
                i != field_id_map.end(); ++i) {

            stream << "<tr>";

            stream << "<td>" << i->second->field_name << "</td>";
            if (i->second->builder == NULL) {
                stream << "<td>" << 
                    TrackerElement::type_to_string(i->second->track_type) << "</td>";
            } else {
                stream << "<td>Complex</td>";
            }

            stream << "<td>" << i->second->field_description << "</td>";

            stream << "</tr>";

        }

        stream << "</table>";
        stream << "</body></html>";

        return;
    }

}

