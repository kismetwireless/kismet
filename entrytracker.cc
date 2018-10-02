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
#include "messagebus.h"

EntryTracker::EntryTracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler() {
    globalreg = in_globalreg;

    next_field_num = 1;

    Bind_Httpd_Server();
}

EntryTracker::~EntryTracker() {
    local_locker eolock(&entry_mutex);

    globalreg->RemoveGlobal("ENTRYTRACKER");
}

int EntryTracker::RegisterField(const std::string& in_name,
        std::unique_ptr<TrackerElement> in_builder,
        const std::string& in_desc) {
    local_locker lock(&entry_mutex);

    std::string lname = StrLower(in_name);

    auto field_iter = field_name_map.find(lname);

    if (field_iter != field_name_map.end()) {
        if (field_iter->second->builder->get_signature() != in_builder->get_signature()) 
            throw std::runtime_error(fmt::format("tried to register field {} of type {}/{} "
                        "but field already exists with conflicting type/signature {}/{}",
                        in_name, in_builder->get_type_as_string(), in_builder->get_signature(),
                        field_iter->second->builder->get_type_as_string(),
                        field_iter->second->builder->get_signature()));

        return field_iter->second->field_id;
    }

    auto definition = std::make_shared<reserved_field>();
    definition->field_id = next_field_num++;
    definition->field_name = in_name;
    definition->field_description = in_desc;
    definition->builder = std::move(in_builder);

    field_name_map[lname] = definition;
    field_id_map[definition->field_id] = definition;

    return definition->field_id;
}

std::shared_ptr<TrackerElement> EntryTracker::RegisterAndGetField(const std::string& in_name,
        std::unique_ptr<TrackerElement> in_builder,
        const std::string& in_desc) {
    local_locker lock(&entry_mutex);

    std::string lname = StrLower(in_name);

    auto field_iter = field_name_map.find(lname);

    if (field_iter != field_name_map.end()) {
        if (field_iter->second->builder->get_signature() != in_builder->get_signature()) 
            throw std::runtime_error(fmt::format("tried to register field {} of type {}/{} "
                        "but field already exists with conflicting type/signature {}/{}",
                        in_name, in_builder->get_type_as_string(), in_builder->get_signature(),
                        field_iter->second->builder->get_type_as_string(),
                        field_iter->second->builder->get_signature()));

        return field_iter->second->builder->clone_type(field_iter->second->field_id);
    }

    auto definition = std::make_shared<reserved_field>();
    definition->field_id = next_field_num++;
    definition->field_name = in_name;
    definition->field_description = in_desc;
    definition->builder = std::move(in_builder);

    field_name_map[lname] = definition;
    field_id_map[definition->field_id] = definition;

    return definition->builder->clone_type(definition->field_id);
}


int EntryTracker::GetFieldId(const std::string& in_name) {
    local_locker lock(&entry_mutex);

    std::string mod_name = StrLower(in_name);

    auto iter = field_name_map.find(mod_name);
    if (iter == field_name_map.end()) 
        return -1;

    return iter->second->field_id;
}

std::string EntryTracker::GetFieldName(int in_id) {
    local_locker lock(&entry_mutex);

    auto iter = field_id_map.find(in_id);
    if (iter == field_id_map.end()) 
        return "field.unknown.not.registered";

    return iter->second->field_name;
}

std::string EntryTracker::GetFieldDescription(int in_id) {
    local_locker lock(&entry_mutex);

    auto iter = field_id_map.find(in_id);

    if (iter == field_id_map.end()) {
        return "untracked field, description not available";
    }

    return iter->second->field_description;
}


std::shared_ptr<TrackerElement> EntryTracker::GetSharedInstance(int in_id) {
    local_locker lock(&entry_mutex);

    auto iter = field_id_map.find(in_id);

    if (iter == field_id_map.end()) 
        return nullptr;

    return iter->second->builder->clone_type(iter->second->field_id);
}

std::shared_ptr<TrackerElement> EntryTracker::GetSharedInstance(const std::string& in_name) {
    local_locker lock(&entry_mutex);

    auto lname = StrLower(in_name);

    auto iter = field_name_map.find(lname);

    if (iter == field_name_map.end()) 
        return nullptr;

    return iter->second->builder->clone_type(iter->second->field_id);
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
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    local_locker lock(&entry_mutex);

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(path, "/system/tracked_fields.html") == 0) {
        stream << "<html><head><title>Kismet Server - Tracked Fields</title></head>";
        stream << "<body>";
        stream << "<h2>Kismet field descriptions</h2>";
        stream << "<table padding=\"5\">";
        stream << "<tr><td><b>Name</b></td><td><b>ID</b></td><td><b>Type</b></td><td><b>Description</b></td></tr>";

        for (auto i : field_id_map) {
            stream << "<tr>";

            stream << "<td>" << i.second->field_name << "</td>";

            stream << "<td>" << i.first << "</td>";

            stream << "<td>" << 
                i.second->builder->get_type_as_string() << "/" << 
                i.second->builder->get_signature() << "</td>"; 

            stream << "<td>" << i.second->field_description << "</td>";

            stream << "</tr>";

        }

        stream << "</table>";
        stream << "</body></html>";

        return;
    }

}

void EntryTracker::RegisterSerializer(const std::string& in_name, 
        std::shared_ptr<TrackerElementSerializer> in_ser) {
    local_locker lock(&serializer_mutex);
    
    std::string mod_type = StrLower(in_name);

    if (serializer_map.find(mod_type) != serializer_map.end()) {
        _MSG("Attempt to register two serializers for type " + in_name,
                MSGFLAG_ERROR);
        return;
    }

    serializer_map[mod_type] = in_ser;
}

void EntryTracker::RemoveSerializer(const std::string& in_name) {
    local_locker lock(&serializer_mutex);

    std::string mod_type = StrLower(in_name);
    auto i = serializer_map.find(in_name);

    if (i != serializer_map.end()) {
        serializer_map.erase(i);
    }
}

bool EntryTracker::CanSerialize(const std::string& in_name) {
    local_locker lock(&serializer_mutex);

    std::string mod_type = StrLower(in_name);
    auto i = serializer_map.find(in_name);

    if (i != serializer_map.end()) {
        return true;
    }

    return false;
}

bool EntryTracker::Serialize(const std::string& in_name, std::ostream &stream,
        SharedTrackerElement e,
        std::shared_ptr<TrackerElementSerializer::rename_map> name_map) {

    local_demand_locker lock(&serializer_mutex);

    // Only lock for the scope of the lookup
    lock.lock();
    auto i = serializer_map.find(in_name);

    if (i == serializer_map.end()) {
        return false;
    }
    lock.unlock();

    // Call the serializer
    i->second->serialize(e, stream, name_map);

    return true;
}


