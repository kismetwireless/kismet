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

#include <memory>
#include <string>
#include <map>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"

// Allocate and track named fields and give each one a custom int
class EntryTracker : public Kis_Net_Httpd_CPPStream_Handler, public LifetimeGlobal {
public:
    static std::string global_name() { return "ENTRYTRACKER"; }

    static std::shared_ptr<EntryTracker> create_entrytracker(GlobalRegistry *in_globalreg) {
        std::shared_ptr<EntryTracker> mon(new EntryTracker(in_globalreg));
        in_globalreg->entrytracker = mon.get();
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
    EntryTracker(GlobalRegistry *in_globalreg);

public:
    virtual ~EntryTracker();

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
    int RegisterField(const std::string& in_name, 
            std::unique_ptr<TrackerElement> in_builder,
            const std::string& in_desc);

    // Reserve a field name, and return an instance.  If the field ALREADY EXISTS, return
    // an instance.
    std::shared_ptr<TrackerElement> RegisterAndGetField(const std::string& in_name, 
            std::unique_ptr<TrackerElement> in_builder,
            const std::string& in_desc);

    template<typename TE> 
    std::shared_ptr<TE> RegisterAndGetFieldAs(const std::string& in_name,
            std::unique_ptr<TrackerElement> in_builder,
            const std::string& in_desc) {
        return std::static_pointer_cast<TE>(RegisterAndGetField(in_name, std::move(in_builder),
                    in_desc));
    }

    int GetFieldId(const std::string& in_name);
    std::string GetFieldName(int in_id);
    std::string GetFieldDescription(int in_id);

    // Generate a shared field instance, using the builder
    template<class T> std::shared_ptr<T> GetSharedInstanceAs(const std::string& in_name) {
        return std::static_pointer_cast<T>(GetSharedInstance(in_name));
    }
    std::shared_ptr<TrackerElement> GetSharedInstance(const std::string& in_name);

    template<class T> std::shared_ptr<T> GetSharedInstanceAs(int in_id) {
        return std::static_pointer_cast<T>(GetSharedInstance(in_id));
    }
    std::shared_ptr<TrackerElement> GetSharedInstance(int in_id);

    // Register a serializer for auto-serialization based on type
    void RegisterSerializer(const std::string& type, std::shared_ptr<TrackerElementSerializer> in_ser);
    void RemoveSerializer(const std::string& type);
    bool CanSerialize(const std::string& type);
    bool Serialize(const std::string& type, std::ostream &stream, SharedTrackerElement elem,
            std::shared_ptr<TrackerElementSerializer::rename_map> name_map = nullptr);

    // HTTP api
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

protected:
    GlobalRegistry *globalreg;

    kis_recursive_timed_mutex entry_mutex;
    kis_recursive_timed_mutex serializer_mutex;

    int next_field_num;

    struct reserved_field {
        // ID we assigned
        int field_id;

        // Readable metadata
        std::string field_name;
        std::string field_description;

        // Builder instance
        std::unique_ptr<TrackerElement> builder;
    };

    std::map<std::string, std::shared_ptr<reserved_field> > field_name_map;
    std::map<int, std::shared_ptr<reserved_field> > field_id_map;
    std::map<std::string, std::shared_ptr<TrackerElementSerializer> > serializer_map;
};

class SerializerScope {
public:
    SerializerScope(SharedTrackerElement e, 
            std::shared_ptr<TrackerElementSerializer::rename_map> name_map) {
        elem = e;
        rnmap = name_map;

        if (rnmap != NULL) {
            auto nmi = rnmap->find(elem);
            if (nmi != rnmap->end()) {
                TrackerElementSerializer::pre_serialize_path(nmi->second);
            } else {
                elem->pre_serialize();
            } 
        } else {
            elem->pre_serialize();
        }
    }

    virtual ~SerializerScope() {
        if (rnmap != NULL) {
            auto nmi = rnmap->find(elem);
            if (nmi != rnmap->end()) {
                TrackerElementSerializer::post_serialize_path(nmi->second);
            } else {
                elem->post_serialize();
            } 
        } else {
            elem->post_serialize();
        }

    }

protected:
    SharedTrackerElement elem;
    std::shared_ptr<TrackerElementSerializer::rename_map> rnmap;
};

#endif
