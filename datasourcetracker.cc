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
#include "msgpack_adapter.h"
#include "timetracker.h"

DST_DatasourceProbe::DST_DatasourceProbe(GlobalRegistry *in_globalreg, 
        string in_definition, SharedTrackerElement in_protovec) {

    globalreg = in_globalreg;

    timetracker =
        static_pointer_cast<Timetracker>(globalreg->FetchGlobal("TIMETRACKER"));

    // Make a recursive mutex that the owning thread can lock multiple times;
    // Required to allow a timer event to reschedule itself on completion
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&probe_lock, &mutexattr);

    definition = in_definition;
    proto_vec = in_protovec;

    transaction_id = 0;

    cancelled = false;
    cancel_timer = -1;
}

DST_DatasourceProbe::~DST_DatasourceProbe() {
    local_eol_locker lock(&probe_lock);

    // Cancel any probing sources and delete them
    for (auto i = probe_vec.begin(); i != probe_vec.end(); ++i) {
        (*i)->close_source();
    }

    probe_vec.clear();

    pthread_mutex_destroy(&probe_lock);
}

void DST_DatasourceProbe::cancel() {
    // Cancels any running sources and triggers the completion callback

    local_locker lock(&probe_lock);

    cancelled = true;

    // Cancel any pending timer
    if (cancel_timer) {
        timetracker->RemoveTimer(cancel_timer);
        cancel_timer = 0;
    }

    // Cancel any other competing probing sources; this may trigger the callbacks
    // which will call the completion function, but we'll ignore them because
    // we're already cancelled
    for (auto i = ipc_probe_map.begin(); i != ipc_probe_map.end(); ++i) {
        i->second->close_source();
    }

    ipc_probe_map.clear();

    // Call our cb with whatever we know about our builder; null if we didn't 
    // find something
    if (probe_cb) 
        probe_cb(source_builder);
}

SharedDatasourceBuilder DST_DatasourceProbe::get_proto() {
    local_locker lock(&probe_lock);
    return source_builder;
}

void DST_DatasourceProbe::complete_probe(bool in_success, unsigned int in_transaction,
        string in_reason __attribute__((unused))) {
    local_locker lock(&probe_lock);

    // If we're already in cancelled state these callbacks mean nothing, ignore them
    if (cancelled)
        return;

    auto v = ipc_probe_map.find(in_transaction);
    if (v != ipc_probe_map.end()) {
        if (in_success) {
            source_builder = v->second->get_source_builder();
        }

        // Remove from the map regardless of success
        ipc_probe_map.erase(v);
    }

    // If we've succeeded, cancel any others, cancel will take care of our
    // callback for completion
    if (in_success) {
        cancel();
        return;
    } else {
        // If we've exhausted everything in the map, we're also done
        if (ipc_probe_map.size() == 0) {
            cancel();
            return;
        }
    }
}

void DST_DatasourceProbe::probe_sources(
        function<void (SharedDatasourceBuilder)> in_cb) {
    // Lock while we generate all of the probes; 
    local_locker lock(&probe_lock);

    probe_cb = in_cb;

    TrackerElementVector vec(proto_vec);

    vector<SharedDatasourceBuilder> remote_builders;

    for (auto i = vec.begin(); i != vec.end(); ++i) {
        SharedDatasourceBuilder b = static_pointer_cast<KisDatasourceBuilder>(*i);

        if (!b->get_probe_capable())
            continue;
       
        unsigned int transaction = transaction_id++;

        // Instantiate a local prober
        SharedDatasource pds = b->build_datasource(b);
        pds->probe_interface(definition, transaction, 
            [this] (unsigned int transaction, bool success, string reason) {
                complete_probe(success, transaction, reason);
            });

        ipc_probe_map[transaction] = pds;
    }

    // We've done all we can; if we haven't gotten an answer yet and we
    // have nothing in our transactional map, we've failed
    if (ipc_probe_map.size() == 0) {
        cancel();
        return;
    }

    // Otherwise we're probing; set a cancel timeout of 5 seconds, for now
    cancel_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5,
            NULL, 0, 
            [this] (int) -> int {
                cancel();
                return 0;
            });
}

Datasourcetracker::Datasourcetracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_Stream_Handler(in_globalreg),
    TcpServerV2(in_globalreg) {
    globalreg = in_globalreg;

    entrytracker = 
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    if (entrytracker == NULL)
        throw std::runtime_error("entrytracker not initialized before "
                "Datasourcetracker");

    // Make a recursive mutex that the owning thread can lock multiple times;
    // Required to allow a timer event to reschedule itself on completion
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&dst_lock, &mutexattr);
    pthread_mutex_init(&dst_lock, NULL);


    dst_proto_builder =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.driver", 
                SharedDatasourceBuilder(new KisDatasourceBuilder(globalreg, 0)), 
                    "Datasource driver");

    dst_source_builder =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.datasource",
                SharedDatasource(new KisDatasource(globalreg, 0)),
                "Datasource");

    proto_vec =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.drivers",
                TrackerVector, "Known drivers");

    datasource_vec =
        entrytracker->RegisterAndGetField("kismet.datasourcetracker.sources",
                TrackerVector, "Configured sources");

}

Datasourcetracker::~Datasourcetracker() {
    local_eol_locker lock(&dst_lock);

    globalreg->RemoveGlobal("DATA_SOURCE_TRACKER");

    for (auto i = probing_vec.begin(); i != probing_vec.end(); ++i) {
        (*i)->cancel();
    }

    for (auto i = listing_vec.begin(); i != listing_vec.end(); ++i) {
        // TODO implement these
        // (*i)->cancel();
    }

    pthread_mutex_destroy(&dst_lock);
}

void Datasourcetracker::iterate_datasources(DST_Worker *in_worker) {
    local_locker lock(&dst_lock);

    for (unsigned int x = 0; x < datasource_vec->size(); x++) {
        shared_ptr<KisDatasource> kds = 
            static_pointer_cast<KisDatasource>(datasource_vec->get_vector_value(x));
        in_worker->handle_datasource(kds);
    }

    in_worker->finalize();
}

bool Datasourcetracker::remove_datasource(uuid in_uuid) {
    local_locker lock(&dst_lock);

    TrackerElementVector dsv(datasource_vec);

    // Look for it in the sources vec and fully close it and get rid of it
    for (auto i = dsv.begin(); i != dsv.end(); ++i) {
        SharedDatasource kds = static_pointer_cast<KisDatasource>(*i);

        if (kds->get_source_uuid() == in_uuid) {
            stringstream ss;

            ss << "Closing source '" << kds->get_source_name() << "' and removing "
                "from list of sources.";
            _MSG(ss.str(), MSGFLAG_INFO);

            // Close it
            kds->close_source();

            // Remove it
            dsv.erase(i);

            // Done
            return true;
        }
    }

    return false;
}

int Datasourcetracker::register_datasource(SharedDatasourceBuilder in_builder) {
    local_locker lock(&dst_lock);

    TrackerElementVector vec(proto_vec);

    for (auto i = vec.begin(); i != vec.end(); ++i) {
        SharedDatasourceBuilder b = static_pointer_cast<KisDatasourceBuilder>(*i);

        if (StrLower(b->get_source_type()) == StrLower(in_builder->get_source_type())) {
            _MSG("A datasource driver has already been registered for '" + 
                    b->get_source_type() + "', cannot register it twice.",
                    MSGFLAG_ERROR);
            return -1;
        }
    }

    vec.push_back(in_builder);

    return 1;
}

void Datasourcetracker::open_datasource(string in_source, 
        function<void (bool, string)> in_cb) {

    // Open a datasource only from the string definition

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

    // So long as we have a type - that is, an explicitly defined type which
    // is not "auto" - we know what driver is supposed to open it.  We look
    // for that driver in the prototype vector, confirm it can open it, and fire
    // the launch command at it
    if (type != "auto") {
        local_locker lock(&dst_lock);

        SharedDatasourceBuilder proto;

        bool proto_found = false;

        TrackerElementVector vec(proto_vec);

        for (auto i = vec.begin(); i != vec.end(); ++i) {
            proto = static_pointer_cast<KisDatasourceBuilder>(*i);

            if (StrLower(proto->get_source_type()) == StrLower(type)) {
                proto_found = true;
                break;
            }
        }

        if (!proto_found) {
            stringstream ss;
            ss << "Unable to find driver for '" << type << "'.  Make sure "
                "that any plugins required are loaded.";

            if (in_cb != NULL) {
                in_cb(false, ss.str());
            }
            return;
        }

        // Open the source with the processed options
        open_datasource(in_source, proto, in_cb);
        return;
    }

    // Otherwise we have to initiate a probe, which is async itself, and 
    // tell it to call our CB when it completes.  The probe will find if there 
    // is a driver that can claim the source string we were given, and 
    // we'll initiate opening it if there is
    {
        local_locker lock(&dst_lock);

        _MSG("Probing for datasource type for '" + interface + "'", MSGFLAG_INFO);

        // Create a DSTProber to handle the probing
        SharedDSTProbe 
            dst_probe(new DST_DatasourceProbe(globalreg, in_source, proto_vec));

        // Record it
        probing_vec.push_back(dst_probe);

        // Initiate the probe
        dst_probe->probe_sources([this, dst_probe, in_cb](SharedDatasourceBuilder builder) {
            // Lock on completion
            local_locker lock(&dst_lock);

            // Remove this entry from the probe list
            for (auto i = probing_vec.begin(); i != probing_vec.end(); ++i) {
                if (*i == dst_probe) {
                    probing_vec.erase(i);
                }
            }

            stringstream ss;

            if (builder == NULL) {
                // We couldn't find a type, return an error to our initial open CB
                ss << "Unable to find driver for '" << dst_probe->get_definition() << 
                     "'.  Make sure that any plugins required are loaded.";
                _MSG(ss.str(), MSGFLAG_ERROR);
                in_cb(false, ss.str());
            } else {
                ss << "Found type '" << builder->get_source_type() << "' for '" <<
                dst_probe->get_definition() << "'";
                _MSG(ss.str(), MSGFLAG_INFO);

                // Initiate an open w/ a known builder
                open_datasource(dst_probe->get_definition(), builder, in_cb);
            }

        });

    }

    return;
}

void Datasourcetracker::open_datasource(string in_source, 
        SharedDatasourceBuilder in_proto,
        function<void (bool, string)> in_cb) {
    local_locker lock(&dst_lock);

    // Make a data source from the builder
    SharedDatasource ds = in_proto->build_datasource(in_proto);

    TrackerElementVector vec(datasource_vec);
    vec.push_back(ds);

    ds->open_interface(in_source, 0, 
        [this, ds, in_cb] (unsigned int, bool success, string reason) {
            // Whenever we succeed (or fail) at opening a deferred open source,
            // call our callback w/ whatever we know
            if (success) {
                in_cb(true, "");
            } else {
                in_cb(false, reason);
            }
        });
}

void Datasourcetracker::NewConnection(shared_ptr<RingbufferHandler> conn_handler) {

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
        Kis_Net_Httpd_Connection *connection,
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

