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
#include "messagebus.h"
#include "globalregistry.h"

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
        RegisterField("kismet.Datasourcetracker.protosource.type", TrackerString,
                "Prototype source type", (void **) &proto_type);
    proto_description_id =
        RegisterField("kismet.Datasourcetracker.protosource.description", TrackerString,
                "Prototype source description", (void **) &proto_description);
}

void DST_DataSourcePrototype::set_proto_builder(KisDataSource *in_builder) {
    proto_builder = in_builder;
}

DST_DataSourceProbe::DST_DataSourceProbe(time_t in_time, string in_definition,
     Datasourcetracker *in_tracker, vector<KisDataSource *> in_protovec) {

    pthread_mutex_init(&probe_lock, NULL);

    protosrc = NULL;
    tracker = in_tracker;
    start_time = in_time;
    definition = in_definition;
    protosrc_vec = in_protovec;
}

DST_DataSourceProbe::~DST_DataSourceProbe() {
    {
        // Make sure no-one is pending on us
        local_locker lock(&probe_lock);
    }

    pthread_mutex_destroy(&probe_lock);

    // Cancel any probing sources and delete them
    for (vector<KisDataSource *>::iterator i = protosrc_vec.begin();
            i != protosrc_vec.end(); ++i) {

        // Protosrc is special if it's in there for some reason still
        if ((*i) == protosrc)
            continue;

        (*i)->cancel_probe_source();
        delete(*i);
    }

    // Kill the protosrc if it's still around
    if (protosrc != NULL) {
        delete(protosrc);
    }
}

void DST_DataSourceProbe::cancel() {
    local_locker lock(&probe_lock);

    // Cancel any probing sources and delete them
    for (vector<KisDataSource *>::iterator i = protosrc_vec.begin();
         i != protosrc_vec.end(); ++i) {

        // Don't delete the successful source!
        if ((*i) == protosrc)
            continue;

        (*i)->cancel_probe_source();
        delete(*i);
    }

    protosrc_vec.clear();
}

KisDataSource *DST_DataSourceProbe::get_proto() {
    local_locker lock(&probe_lock);
    return protosrc;
}

void DST_DataSourceProbe::set_proto(KisDataSource *in_proto) {
    local_locker lock(&probe_lock);
    protosrc = in_proto;
}

size_t DST_DataSourceProbe::remove_failed_proto(KisDataSource *in_src) {
    local_locker lock(&probe_lock);

    for (vector<KisDataSource *>::iterator i = protosrc_vec.begin();
            i != protosrc_vec.end(); ++i) {
        if ((*i) == in_src) {
            protosrc_vec.erase(i);
            delete((*i));
            break;
        }
    }

    return protosrc_vec.size();
}

Datasourcetracker::Datasourcetracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    entrytracker = (EntryTracker *) globalreg->FetchGlobal("ENTRY_TRACKER");

    if (entrytracker == NULL)
        throw std::runtime_error("entrytracker not initialized before "
                "Datasourcetracker");

    globalreg->InsertGlobal("DATA_SOURCE_TRACKER", this);
    
    pthread_mutex_init(&dst_lock, NULL);

    DST_DataSourcePrototype *dst_builder =
        new DST_DataSourcePrototype(globalreg);
    dst_proto_entry_id = 
        entrytracker->RegisterField("kismet.Datasourcetracker.protosource.entry",
                dst_builder, "Protosource definition entry");

    KisDataSource *datasource_builder = new KisDataSource(globalreg);
    dst_source_entry_id =
        entrytracker->RegisterField("kismet.Datasourcetracker.datasource.entry",
                datasource_builder, "Datasource entry");

    // Make sure to link class-constant values
    proto_vec =
        entrytracker->RegisterAndGetField("kismet.Datasourcetracker.protosources",
                TrackerVector, "Prototype datasources");
    proto_vec->link();

    datasource_vec =
        entrytracker->RegisterAndGetField("kismet.Datasourcetracker.datasources",
                TrackerVector, "Datasources");
    datasource_vec->link();

    error_vec =
        entrytracker->RegisterAndGetField("kismet.Datasourcetracker.errordatasources",
                TrackerVector, "Errored Datasources");
    error_vec->link();

}

Datasourcetracker::~Datasourcetracker() {
    pthread_mutex_destroy(&dst_lock);

    globalreg->RemoveGlobal("DATA_SOURCE_TRACKER");

    proto_vec->unlink();
    datasource_vec->unlink();
    error_vec->unlink();

}

void Datasourcetracker::iterate_datasources(DST_Worker *in_worker) {
    local_locker lock(&dst_lock);

    for (unsigned int x = 0; x < datasource_vec->size(); x++) {
        KisDataSource *kds = (KisDataSource *) datasource_vec->get_vector_value(x);
        in_worker->handle_datasource(kds);
    }

    in_worker->finalize();
}

int Datasourcetracker::register_datasource_builder(string in_type,
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

int Datasourcetracker::open_datasource(string in_source) {
    string interface;
    string options;
    vector<opt_pair> opt_vec;
    string type;

    size_t cpos = in_source.find(":");

    // Parse basic options and interface, extract type
    if (cpos == string::npos) {
        interface = in_source;
        type = "auto";
    } else {
        interface = in_source.substr(0, cpos);
        options = in_source.substr(cpos);

        StringToOpts(options, ",", &opt_vec);

        type = StrLower(FetchOpt("type", &opt_vec));

        if (type == "")
            type = "auto";
    }

    // If type isn't autodetect, we're looking for a specific driver
    if (type != "auto") {
        KisDataSource *proto;

        {
            local_locker lock(&dst_lock);
            bool proto_found = false;

            for (TrackerElement::vector_const_iterator i = proto_vec->vec_begin();
                    i != proto_vec->vec_end(); ++i) {
                proto = (KisDataSource *) *i;

                if (StrLower(proto->get_source_name()) == StrLower(type)) {
                    proto_found = true;
                    break;
                }
            }

            if (!proto_found) {
                stringstream ss;
                ss << "Unable to find datasource for '" << type << "'.  Make sure "
                    "that any plugins required are loaded.";
                _MSG(ss.str(), MSGFLAG_ERROR);
                return -1;
            }
        }

        // Start opening source
        launch_source(proto, in_source);
        return 1;
    }

    // Otherwise build a probe lookup record
    {
        local_locker lock(&dst_lock);

        _MSG("Probing for datasource type for '" + interface + "'", MSGFLAG_INFO);

        vector<KisDataSource *> probe_vec;

        // Build instances to actually do the probes
        for (TrackerElement::vector_const_iterator i = proto_vec->vec_begin();
                i != proto_vec->vec_end(); ++i) {
            KisDataSource *proto = (KisDataSource *) (*i);
            probe_vec.push_back(proto->build_data_source());
        }

        // Make the probe handler entry
        DST_DataSourceProbe *dst_probe = 
            new DST_DataSourceProbe(globalreg->timestamp.tv_sec, in_source, 
                    this, probe_vec);

        // Save it in the vec
        probing_vec.push_back(dst_probe);

        // Now initiate a probe on every source
        for (vector<KisDataSource *>::iterator i = probe_vec.begin(); 
                i != probe_vec.end(); ++i) {
            printf("debug - sending probe command to datasource %s\n", 
                    ((KisDataSource *) (*i))->get_source_type().c_str());
            ((KisDataSource *) (*i))->probe_source(in_source, probe_handler, dst_probe);
        }
    }

    return 1;
}

bool Datasourcetracker::Httpd_VerifyPath(const char *path, const char *method) {
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

void Datasourcetracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
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

int Datasourcetracker::Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type, 
        const char *transfer_encoding, const char *data, uint64_t off, size_t size) {

    return 0;
}

void Datasourcetracker::probe_handler(KisDataSource *in_src, void *in_aux, 
        bool in_success) {

    DST_DataSourceProbe *dstproto = (DST_DataSourceProbe *) in_aux;
    Datasourcetracker *tracker = dstproto->get_tracker();

    // If we've succeeded, set the source and cancel the rest, then continue opening the
    // source
    if (in_success) {
        // Mark the good source
        dstproto->set_proto(in_src);
        // Cancel the rest immediately, clearing the callbacks even if they trigger
        // while we're still cleaning up
        dstproto->cancel();

        // We've found the protosrc, so start launching that
        fprintf(stderr, "debug - found protosrc, launching for src '%s'\n", dstproto->get_definition().c_str());
        tracker->launch_source(in_src, dstproto->get_definition()); 

        // Get rid of the prototype, we're done; this will also clean up the
        // protosrc we used to build and open the new src
        fprintf(stderr, "debug - dst finished with prototype group %p deleting after success\n", dstproto);
        delete(dstproto);

    } else {
        // Cancel out if we have no sources left & finish our failure of opening sources
        if (dstproto->remove_failed_proto(in_src) <= 0) {
            GlobalRegistry *globalreg = tracker->globalreg;

            // Cancel out to be sure
            dstproto->cancel();

            // in_src already deleted
            
            std::stringstream ss;
            ss << "Unable to find any source to handle '" <<
                dstproto->get_definition() << "'";
            _MSG(ss.str(), MSGFLAG_ERROR);

            // Nuke the tracker
            fprintf(stderr, "debug - dst finished with prototype group %p deleting after failure\n", dstproto);
            delete(dstproto);
        }
    }

    // Otherwise nothing to do
}

void Datasourcetracker::open_handler(KisDataSource *in_src, void *in_aux, 
        bool in_success) {

    Datasourcetracker *tracker = (Datasourcetracker *) in_aux;

    // Devices are already in the datasource vec even if they haven't 
    // completed opening so we just add them into the error vec
    
    if (!in_success) {
        local_locker lock(&(tracker->dst_lock));

        TrackerElementVector err_vec(tracker->error_vec);
        bool found = false;

        // Bail if this source is still in error somehow
        for (TrackerElementVector::const_iterator i = err_vec.begin();
                i != err_vec.end(); ++i) {
            if ((*i) == in_src) {
                found = true;
            }
        }

        if (!found)
            err_vec.push_back(in_src);
    }
}

void Datasourcetracker::error_handler(KisDataSource *in_src, void *in_aux) {
    // Same logic as the open handler
    Datasourcetracker *tracker = (Datasourcetracker *) in_aux;
    
    {
        local_locker lock(&(tracker->dst_lock));
        TrackerElementVector err_vec(tracker->error_vec);
        bool found = false;

        for (TrackerElementVector::const_iterator i = err_vec.begin();
                i != err_vec.end(); ++i) {
            if ((*i) == in_src) {
                found = true;
            }
        }

        if (!found)
            err_vec.push_back(in_src);
    }
}

void Datasourcetracker::launch_source(KisDataSource *in_proto, string in_source) {
    local_locker lock(&dst_lock);

    TrackerElementVector vec(datasource_vec);

    // Clone the src and add it to the vec immediately
    KisDataSource *new_src = in_proto->build_data_source();
    vec.push_back(new_src);

    new_src->set_error_handler(Datasourcetracker::error_handler, this);

    // Try to open it, referencing our open handler
    new_src->open_source(in_source, open_handler, this);
    
}

int Datasourcetracker::timetracker_event(int eventid) {
    if (eventid == error_timer_id) {
        // Annoying
        vector<KisDataSource *> error_vec_copy;

        {
            // We have to lock and copy the array
            local_locker lock(&dst_lock);

            TrackerElementVector err_vec(error_vec);

            for (TrackerElementVector::const_iterator i = err_vec.begin();
                    i != err_vec.end(); ++i) {
                error_vec_copy.push_back((KisDataSource *) (*i));
            }

            // Then clear it
            err_vec.clear();
        }

        // Re-launch all the sources
        for (vector<KisDataSource *>::const_iterator i = error_vec_copy.begin();
                i != error_vec_copy.end(); ++i) {
            stringstream ss;
            KisDataSource *src = (KisDataSource *) (*i);
            
            ss << "Attempting to re-open source '" <<
                src->get_source_name() << "'";
            _MSG(ss.str(), MSGFLAG_INFO);

            launch_source(src, src->get_source_definition());
        }
    }

    // Repeat
    return 1;
}

