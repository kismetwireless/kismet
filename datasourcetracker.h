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

#ifndef __DATASOURCETRACKER_H__
#define __DATASOURCETRACKER_H__

#include "config.h"

#include <pthread.h>
#include <string>
#include <vector>
#include <map>

#include "globalregistry.h"
#include "util.h"
#include "kis_datasource.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "entrytracker.h"

/* Data source tracker
 *
 * Core of the new capture management system.
 *
 * This code replaces the old packetsource tracker.
 *
 * Data sources are registered passing a builder instance which is used to
 * instantiate the final versions of the data sources.  
 *
 * Data sources communicate via the protocol defined in simple_cap_proto.h 
 * and may communicate packets or complete device objects.
 */

class DataSourceTracker;
class KisDataSource;

// Worker class used to perform work on the list of packet-sources in a thread
// safe / continuity safe context.
class DST_Worker {
public:
    DST_Worker() { };

    // Handle a data source when working on iterate_datasources
    virtual void handle_datasource(DataSourceTracker *in_tracker, 
            KisDataSource *in_src) { };

    // All data sources have been processed in iterate_datasources
    virtual void finalize(DataSourceTracker *in_tracker) { };
};

// Datasource prototype for easy tracking and exporting
class DST_DataSourcePrototype : public tracker_component {
public:
    DST_DataSourcePrototype(GlobalRegistry *in_globalreg);
    virtual ~DST_DataSourcePrototype();

    KisDataSource *get_proto_builder() { return proto_builder; }
    void set_proto_builder(KisDataSource *in_builder);

    __Proxy(proto_type, string, string, string, proto_type);
    __Proxy(proto_description, string, string, string, proto_description);

protected:
    GlobalRegistry *globalreg;

    virtual void register_fields();

    int proto_type_id;
    TrackerElement *proto_type;

    int proto_description_id;
    TrackerElement *proto_description;

    // Builder used for probe and building the valid source
    KisDataSource *proto_builder;
};

// Probing record
class DST_DataSourceProbe {
public:
    DST_DataSourceProbe(time_t in_time, string in_definition, KisDataSource *in_proto);
    virtual ~DST_DataSourceProbe();

    string get_type() { return srctype; }
    string get_time() { return start_time; }

    bool get_complete() { return complete; }

    void cancel();

protected:
    KisDataSource *protosrc;

    time_t start_time;
    string definition;
    bool complete;

    string srctype;
};

class DataSourceTracker : public Kis_Net_Httpd_Stream_Handler {
public:
    DataSourceTracker(GlobalRegistry *in_globalreg);
    virtual ~DataSourceTracker();

    // Add a datasource builder, with type and description.  Returns 0 or positive on
    // success, negative on failure
    int register_datasource_builder(string in_type, string in_description,
            KisDataSource *in_builder);

    // Operate on all data sources currently defined.  The datasource tracker is locked
    // during this operation, making it thread safe.
    void iterate_datasources(DST_Worker *in_worker);

    // Launch a source.  If there is no type defined or the type is 'auto', attempt to
    // find the source.  When the source is opened or there is a failure, in_open_handler
    // will be called
    int open_datasource(string in_source, KisDataSource::open_handler in_open_handler,
            void *in_aux);

    // Close a source which has been created
    int close_datasource(uuid in_src_uuid);

    // HTTP api
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
            const char *key, const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, 
            uint64_t off, size_t size);

protected:
    GlobalRegistry *globalreg;
    EntryTracker *entrytracker;

    pthread_mutex_t dst_lock;

    int dst_proto_entry_id;
    int dst_source_entry_id;

    // Lists of proto and active sources
    TrackerElement *proto_vec;
    TrackerElement *datasource_vec;

    // Currently probing
    vector<KisDataSource *> probing_vec;

    // Callbacks for source async operations
    static void probe_handler(KisDataSource *in_src, void *in_aux, bool in_success);
    static void open_handler(KisDataSource *in_src, void *in_aux, bool in_success);
    static void error_handler(KisDataSource *in_src, void *in_aux);

};


#endif

