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

#ifndef __ENTRYTRACKER_H__
#define __ENTRYTRACKER_H__

#include "config.h"

#include <stdio.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "robin_hood.h"
#include "trackedelement.h"

class kis_net_beast_httpd_connection;

// Allocate and track named fields and give each one a custom int
class entry_tracker : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "ENTRYTRACKER"; }

    static std::shared_ptr<entry_tracker> create_entrytracker() {
        std::shared_ptr<entry_tracker> mon(new entry_tracker());
        Globalreg::globalreg->entrytracker = mon.get();
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    entry_tracker();

public:
    virtual ~entry_tracker();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

    // Register a field name; field names are plain strings, and must be unique for
    // each type; Using namespaces is recommended, ie "plugin.foo.some_field".
    //
    // A builder instance must be provided as a std::unique_ptr, this instance
    // will be used to construct the field based on the ID in the future.
    //
    // The description is a human-readable description which is published in the field
    // listing system and is intended to assist consumers of the API.
    //
    // Return: Registered field number, or negative on error (such as field exists with
    // conflicting type)
    int register_field(const std::string& in_name, 
            std::unique_ptr<tracker_element> in_builder,
            const std::string& in_desc);

    // Reserve a field name, and return an instance.  If the field ALREADY EXISTS, return
    // an instance.
    std::shared_ptr<tracker_element> register_and_get_field(const std::string& in_name, 
            std::unique_ptr<tracker_element> in_builder,
            const std::string& in_desc);

    template<typename TE> 
    std::shared_ptr<TE> register_and_get_field_as(const std::string& in_name,
            std::unique_ptr<tracker_element> in_builder,
            const std::string& in_desc) {
        return std::static_pointer_cast<TE>(register_and_get_field(in_name, std::move(in_builder),
                    in_desc));
    }

    int get_field_id(const std::string& in_name);
    std::string get_field_name(int in_id);
    std::string get_field_description(int in_id);

    // Generate a shared field instance, using the builder
    template<class T> std::shared_ptr<T> get_shared_instance_as(const std::string& in_name) {
        return std::static_pointer_cast<T>(get_shared_instance(in_name));
    }
    std::shared_ptr<tracker_element> get_shared_instance(const std::string& in_name);

    template<class T> std::shared_ptr<T> get_shared_instance_as(int in_id) {
        return std::static_pointer_cast<T>(get_shared_instance(in_id));
    }
    std::shared_ptr<tracker_element> get_shared_instance(int in_id);

    // Register a serializer for auto-serialization based on type
    void register_serializer(const std::string& type, std::shared_ptr<tracker_element_serializer> in_ser);
    void remove_serializer(const std::string& type);
    bool can_serialize(const std::string& type);

    int serialize(const std::string& type, std::ostream& stream, shared_tracker_element elem,
            std::shared_ptr<tracker_element_serializer::rename_map> name_map = nullptr);

    int serialize_with_json_summary(const std::string& type, std::ostream& stream, shared_tracker_element elem,
            const Json::Value& json_summary);

protected:
    kis_shared_mutex entry_mutex;
    kis_shared_mutex serializer_mutex;

    int next_field_num;

    struct reserved_field {
        // ID we assigned
        int field_id;

        // Readable metadata
        std::string field_name;
        std::string field_description;

        // Builder instance
        std::unique_ptr<tracker_element> builder;
    };

    robin_hood::unordered_node_map<std::string, std::shared_ptr<reserved_field> > field_name_map;
    robin_hood::unordered_node_map<int, std::shared_ptr<reserved_field> > field_id_map;
    robin_hood::unordered_node_map<std::string, std::shared_ptr<tracker_element_serializer> > serializer_map;

    void tracked_fields_endp_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);
};

class serializer_scope {
public:
    serializer_scope(shared_tracker_element e, 
            std::shared_ptr<tracker_element_serializer::rename_map> name_map) {
        elem = e;
        rnmap = name_map;

        if (rnmap != NULL) {
            auto nmi = rnmap->find(elem);
            if (nmi != rnmap->end()) {
                tracker_element_serializer::pre_serialize_path(nmi->second);
            } else {
                elem->pre_serialize();
            } 
        } else {
            elem->pre_serialize();
        }
    }

    virtual ~serializer_scope() {
        if (rnmap != NULL) {
            auto nmi = rnmap->find(elem);
            if (nmi != rnmap->end()) {
                tracker_element_serializer::post_serialize_path(nmi->second);
            } else {
                elem->post_serialize();
            } 
        } else {
            elem->post_serialize();
        }

    }

protected:
    shared_tracker_element elem;
    std::shared_ptr<tracker_element_serializer::rename_map> rnmap;
};

#endif
