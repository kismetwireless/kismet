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

#include "datasourcetracker.h"

DST_DataSourcePrototype::DST_DataSourcePrototype(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0) {

    globalreg = in_globalreg;

    register_fields();
    reserve_fields(NULL);
}

DST_DataSourcePrototype::~DST_DataSourcePrototype() {

}

void DST_DataSourcePrototype::register_fields() {
    proto_type_id = 
        RegisterField("kismet.datasourcetracker.protosource.type", TrackerString,
                "Prototype source type", (void **) &proto_type);
    proto_description_id =
        RegisterField("kismet.datasourcetracker.protosource.description", TrackerString,
                "Prototype source description", (void **) &proto_description);
}

void DST_DataSourcePrototype::set_proto_builder(KisDataSource *in_builder) {
    proto_builder = in_builder;
}

DataSourceTracker::DataSourceTracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    entrytracker = (EntryTracker *) globalreg->FetchGlobal("ENTRY_TRACKER");

    if (entrytracker == NULL)
        throw std::runtime_error("entrytracker not initialized before "
                "datasourcetracker");

    globalreg->InsertGlobal("DATA_SOURCE_TRACKER", this);
    
    pthread_mutex_init(&dst_lock, NULL);

    DST_DataSourcePrototype *dst_builder =
        new DST_DataSourcePrototype(globalreg);
    dst_proto_entry_id = 
        entrytracker->RegisterField("kismet.datasourcetracker.protosource.entry",
                dst_builder, "Protosource definition entry");

    KisDataSource *datasource_builder = new KisDataSource(globalreg);
    dst_source_entry_id =
        entrytracker->RegisterField("kismet.datasourcetracker.datasource.entry",
                datasource_builder, "Datasource entry");

    proto_vec =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.protosources",
                TrackerVector, "Prototype datasources");
    datasource_vec =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.datasources",
                TrackerVector, "Datasources");
}

DataSourceTracker::~DataSourceTracker() {
    pthread_mutex_destroy(&dst_lock);

    globalreg->RemoveGlobal("DATA_SOURCE_TRACKER");

}

void DataSourceTracker::iterate_datasources(DST_Worker *in_worker) {
    local_locker lock(&dst_lock);

    for (unsigned int x = 0; x < datasource_vec->size(); x++) {
        KisDataSource *kds = (KisDataSource *) datasource_vec->get_vector_value(x);
        in_worker->handle_datasource(this, kds);
    }

    in_worker->finalize(this);
}

int DataSourceTracker::register_datasource_builder(string in_type, 
        string in_description, KisDataSource *in_builder) {
    local_locker lock(&dst_lock);

    // Don't allow 2 sources registering the same type
    for (unsigned int x = 0; x < proto_vec->size(); x++) {
        DST_DataSourcePrototype *dstp =
                (DST_DataSourcePrototype *) proto_vec->get_vector_value(x);

        if (StrLower(dstp->get_proto_type()) == StrLower(in_type)) {
            _MSG("Already registered a datasource for '" + in_type + "', cannot "
                 "register it twice", MSGFLAG_ERROR);
            return -1;
        }
    }

    DST_DataSourcePrototype *proto = new DST_DataSourcePrototype(globalreg);
    proto->set_id(dst_proto_entry_id);
    proto->set_proto_type(in_type);
    proto->set_proto_description(in_description);
    proto->set_proto_builder(in_builder);

    proto_vec->add_vector(proto);

    return 1;
}

bool DataSourceTracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/datasource/all_sources.msgpack") == 0) {
            return true;
        }

        if (strcmp(path, "/datasource/supported_sources.msgpack") == 0) {
            return true;
        }
    }

    return false;
}

void DataSourceTracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
       struct MHD_Connection *connection,
       const char *url, const char *method, const char *upload_data,
       size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(url, "/datasource/all_sources.msgpack") == 0) {
        MsgpackAdapter::Pack(globalreg, stream, datasource_vec);
        return;
    }

    if (strcmp(url, "/datasource/supported_sources.msgpack") == 0) {
        MsgpackAdapter::Pack(globalreg, stream, proto_vec);
        return;
    }

}

int DataSourceTracker::Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
      const char *filename, const char *content_type, const char *transfer_encoding,
      const char *data, uint64_t off, size_t size) {

    return 0;
}

