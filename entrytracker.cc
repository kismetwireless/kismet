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
#include "kis_net_beast_httpd.h"

entry_tracker::entry_tracker() {
    entry_mutex.set_name("entry_tracker");
    // serializer_mutex.set_name("entry_tracker_serializer");

    next_field_num = 1;

    Globalreg::enable_pool_type<tracker_element_alias>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_string>([](auto *s) { s->reset(); });
    Globalreg::enable_pool_type<tracker_element_byte_array>([](auto *b) { b->reset(); });
    Globalreg::enable_pool_type<tracker_element_device_key>([](auto *d) { d->reset(); });
    Globalreg::enable_pool_type<tracker_element_uuid>([](auto *u) { u->reset(); });
    Globalreg::enable_pool_type<tracker_element_mac_addr>([](auto *m) { m->reset(); });
    // We don't actually use ipv4 anywhere in the base codebase and that makes this
    // a compile error; re-enable once we use it somewhere
    // Globalreg::enable_pool_type<tracker_element_ipv4_addr>();
    Globalreg::enable_pool_type<tracker_element_map>([](auto *m) { m->reset(); });
    Globalreg::enable_pool_type<tracker_element_int_map>([](auto *i) { i->reset(); });
    Globalreg::enable_pool_type<tracker_element_hashkey_map>([](auto *h) { h->reset(); });
    Globalreg::enable_pool_type<tracker_element_double_map>([](auto *d) { d->reset(); });
    Globalreg::enable_pool_type<tracker_element_mac_map>([](auto *m) { m->reset(); });
    Globalreg::enable_pool_type<tracker_element_macfilter_map>([](auto *m) { m->reset(); });
    Globalreg::enable_pool_type<tracker_element_string_map>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_device_key_map>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_uuid_map>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_double_map_double>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_vector>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_vector_double>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_vector_string>([](auto *a) { a->reset(); });
    Globalreg::enable_pool_type<tracker_element_placeholder>([](auto *a) { a->reset(); });

    Globalreg::enable_pool_type<tracker_element_summary>([](auto *a) { a->reset(); });

    Globalreg::enable_pool_type<tracker_element_serializer::rename_map>([](auto *a) { a->clear(); });
}

entry_tracker::~entry_tracker() {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "~entrytracker");

    Globalreg::globalreg->remove_global("ENTRYTRACKER");
}

void entry_tracker::trigger_deferred_startup() {
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/system/tracked_fields", {"GET"}, httpd->RO_ROLE, {"html"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return tracked_fields_endp_handler(con);
                }));
}

void entry_tracker::trigger_deferred_shutdown() {

}

void entry_tracker::tracked_fields_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker tracked_fields_endp_handler");

    std::ostream stream(&con->response_stream());

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
}


int entry_tracker::register_field(const std::string& in_name,
        std::shared_ptr<tracker_element> in_builder,
        const std::string& in_desc) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker register_field");

    // std::string lname = str_lower(in_name);

    auto field_iter = field_name_map.find(in_name);

    if (field_iter != field_name_map.end()) {
        if (field_iter->second->builder->get_signature() != in_builder->get_signature())  {
            const auto e = fmt::format("tried to register field {} of type {}/{} "
                    "but field already exists with conflicting type/signature {}/{}",
                    in_name, in_builder->get_type_as_string(), in_builder->get_signature(),
                    field_iter->second->builder->get_type_as_string(),
                    field_iter->second->builder->get_signature());
            throw std::runtime_error(e);
        }

        return field_iter->second->field_id;
    }

    auto definition = std::make_shared<reserved_field>();
    definition->field_id = next_field_num++;
    definition->field_name = in_name;
    definition->field_description = in_desc;
    definition->builder = in_builder;
    definition->builder->set_id(definition->field_id);

    field_name_map[in_name] = definition;
    field_id_map[definition->field_id] = definition;

    return definition->field_id;
}

std::shared_ptr<tracker_element> entry_tracker::register_and_get_field(const std::string& in_name,
        std::shared_ptr<tracker_element> in_builder,
        const std::string& in_desc) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker register_and_get_field");

    // std::string lname = str_lower(in_name);

    auto field_iter = field_name_map.find(in_name);

    if (field_iter != field_name_map.end()) {
        if (field_iter->second->builder->get_signature() != in_builder->get_signature()) {
            const auto e = fmt::format("tried to register field {} of type {}/{} "
                    "but field already exists with conflicting type/signature {}/{}",
                    in_name, in_builder->get_type_as_string(), in_builder->get_signature(),
                    field_iter->second->builder->get_type_as_string(),
                    field_iter->second->builder->get_signature());
            throw std::runtime_error(e);
        }

        return field_iter->second->builder->clone_type();
    }

    auto definition = std::make_shared<reserved_field>();
    definition->field_id = next_field_num++;
    definition->field_name = in_name;
    definition->field_description = in_desc;
    definition->builder = in_builder;
    definition->builder->set_id(definition->field_id);

    field_name_map[in_name] = definition;
    field_id_map[definition->field_id] = definition;

    return definition->builder->clone_type();
}


uint16_t entry_tracker::get_field_id(const std::string& in_name) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker get_field_id");

    // std::string mod_name = str_lower(in_name);

    auto iter = field_name_map.find(in_name);
    if (iter == field_name_map.end()) 
        return -1;

    return iter->second->field_id;
}

std::string entry_tracker::get_field_name(uint16_t in_id) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker get_field_name");

    auto iter = field_id_map.find(in_id);
    if (iter == field_id_map.end()) 
        return "field.unknown.not.registered";

    return iter->second->field_name;
}

std::string entry_tracker::get_field_description(uint16_t in_id) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker get_field_description");

    auto iter = field_id_map.find(in_id);

    if (iter == field_id_map.end()) {
        return "untracked field, description not available";
    }

    return iter->second->field_description;
}

std::shared_ptr<tracker_element> entry_tracker::get_shared_instance(uint16_t in_id) {
    kis_unique_lock<kis_mutex> lock(entry_mutex, std::defer_lock, "entry_tracker get_shared_instance id");

    lock.lock();
    auto iter = field_id_map.find(in_id);
    lock.unlock();

    if (iter == field_id_map.end()) 
        return nullptr;

    return iter->second->builder->clone_type();
}

std::shared_ptr<tracker_element> entry_tracker::get_shared_instance(const std::string& in_name) {
    kis_unique_lock<kis_mutex> lock(entry_mutex, std::defer_lock, "entry_tracker get_shared_instance name");

    lock.lock();
    auto iter = field_name_map.find(in_name);
    lock.unlock();

    if (iter == field_name_map.end()) 
        return nullptr;

    return iter->second->builder->clone_type();
}

void entry_tracker::register_serializer(const std::string& in_name, 
        std::shared_ptr<tracker_element_serializer> in_ser) {
    // kis_lock_guard<kis_mutex> lk(serializer_mutex, "entry_tracker register_serializer");
    
    if (serializer_map.find(in_name) != serializer_map.end()) {
        _MSG_ERROR("Attempted to register two serializers to type {}", in_name);
        return;
    }

    serializer_map[in_name] = in_ser;
}

void entry_tracker::remove_serializer(const std::string& in_name) {
    // kis_lock_guard<kis_mutex> lk(serializer_mutex, "entry_tracker remove_serializer");

    auto i = serializer_map.find(in_name);

    if (i != serializer_map.end()) {
        serializer_map.erase(i);
    }
}

bool entry_tracker::can_serialize(const std::string& in_name) {
    // kis_lock_guard<kis_mutex> lk(serializer_mutex, "entry_tracker can_serialize");

    auto i = serializer_map.find(in_name);

    if (i != serializer_map.end()) {
        return true;
    }

    return false;
}

int entry_tracker::serialize(const std::string& in_name, std::ostream &stream,
        shared_tracker_element e,
        std::shared_ptr<tracker_element_serializer::rename_map> name_map) {

    // kis_unique_lock<kis_mutex> lock(serializer_mutex, std::defer_lock, "entry_tracker serialize");

    // lock.lock();
    auto dpos = in_name.find_last_of(".");
    if (dpos == std::string::npos) {
        auto i = serializer_map.find(in_name);

        if (i == serializer_map.end()) 
            return -1;
        // lock.unlock();

        return i->second->serialize(e, stream, name_map);
    } else {
        auto i = serializer_map.find(in_name.substr(dpos + 1, in_name.length()));

        if (i == serializer_map.end()) 
            return -1;
        // lock.unlock();

        return i->second->serialize(e, stream, name_map);

    }

    return -1;
}

int entry_tracker::serialize_with_json_summary(const std::string& type, std::ostream& stream, 
        shared_tracker_element elem, const nlohmann::json& json_summary) {
    auto name_map = Globalreg::new_from_pool<tracker_element_serializer::rename_map>();

    auto sumelem = 
        summarize_tracker_element_with_json(elem, json_summary, name_map);

    return serialize(type, stream, sumelem, name_map);
}

void entry_tracker::register_search_xform(uint16_t in_field_id, std::function<void (std::shared_ptr<tracker_element>,
            std::string& mapped_str)> in_xform) {

    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker register_search_xform");
    search_xform_map[in_field_id] = in_xform;
}

void entry_tracker::remove_search_xform(uint16_t in_field_id) {
    kis_lock_guard<kis_mutex> lk(entry_mutex, "entry_tracker remove_search_xform");

    auto i = search_xform_map.find(in_field_id);

    if (i != search_xform_map.end())
        search_xform_map.erase(i);

    return;
}

bool entry_tracker::search_xform(std::shared_ptr<tracker_element> elem, std::string& mapped_str) {
    kis_unique_lock<kis_mutex> lk(entry_mutex, std::defer_lock, "entry_tracker search_xform");

    lk.lock();

    auto i = search_xform_map.find(elem->get_id());

    if (i == search_xform_map.end())
        return false;

    // Copy the function out of the iterator and release the lock while we do the computation

    auto fn = i->second;

    lk.unlock();

    fn(elem, mapped_str);

    return true;
}
