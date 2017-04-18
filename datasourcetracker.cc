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

#include "config.hpp"

#include "configfile.h"
#include "getopt.h"
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

    // fprintf(stderr, "debug - ~DSTprobe %p\n", this);

    // Cancel any probing sources and delete them
    for (auto i = probe_vec.begin(); i != probe_vec.end(); ++i) {
        (*i)->close_source();
    }

    pthread_mutex_destroy(&probe_lock);
}

void DST_DatasourceProbe::cancel() {
    // Cancels any running sources and triggers the completion callback

    local_locker lock(&probe_lock);

    // fprintf(stderr, "debug - dstprobe cancelling search for %s\n", definition.c_str());

    cancelled = true;

    // Cancel any pending timer
    if (cancel_timer >= 0) {
        // fprintf(stderr, "debug - dstprobe cancelling completion timer %d\n", cancel_timer);
        timetracker->RemoveTimer(cancel_timer);
    }

    // Cancel any other competing probing sources; this may trigger the callbacks
    // which will call the completion function, but we'll ignore them because
    // we're already cancelled
    for (auto i = ipc_probe_map.begin(); i != ipc_probe_map.end(); ++i) {
        i->second->close_source();
    }

    // We don't delete sources now because we might be inside the loop somehow
    // and deleting references to ourselves

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
            // fprintf(stderr, "debug - dstp - complete_probe - found transaction id, setting builder\n");
            source_builder = v->second->get_source_builder();
        }

        // Move them to the completed vec
        complete_vec.push_back(v->second);

        // Remove them from the map
        ipc_probe_map.erase(v);
    } else {
        // fprintf(stderr, "debug - dstp - complete_probe - couldn't find transaction record for transaction %u\n", in_transaction);
    }

    // If we've succeeded, cancel any others, cancel will take care of our
    // callback for completion
    if (in_success) {
        // fprintf(stderr, "debug - dstp - completed with success! Calling cancel?\n");
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

    // fprintf(stderr, "debug - dstprobe probing sources for %s\n", definition.c_str());

    cancel_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5, NULL, 0, 
            [this] (int) -> int {
                // fprintf(stderr, "debug - dstprobe timer expired for %s\n", definition.c_str());
                cancel();
                return 0;
            });

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

        // fprintf(stderr, "debug - kdsp - probe_sources - emplacing transaction %u\n", transaction);
        ipc_probe_map.emplace(transaction, pds);

        pds->probe_interface(definition, transaction, 
            [this] (unsigned int transaction, bool success, string reason) {
                // fprintf(stderr, "debug - dstprobe probe_sources callback complete\n");
                complete_probe(success, transaction, reason);
            });
    }

    // We've done all we can; if we haven't gotten an answer yet and we
    // have nothing in our transactional map, we've failed
    if (ipc_probe_map.size() == 0) {
        // fprintf(stderr, "debug - dstprobe probe map 0\n");
        cancel();
        return;
    }

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

    timetracker =
        static_pointer_cast<Timetracker>(globalreg->FetchGlobal("TIMETRACKER"));
    if (timetracker == NULL)
        throw std::runtime_error("timetracker not initialized before "
                "Datasourcetracker");


    // Make a recursive mutex that the owning thread can lock multiple times;
    // Required to allow a timer event to reschedule itself on completion
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&dst_lock, &mutexattr);

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

    completion_cleanup_id = -1;
    next_probe_id = 0;
    next_list_id = 0;

    next_source_num = 0;

    config_defaults = 
        static_pointer_cast<datasourcetracker_defaults>(
                entrytracker->RegisterAndGetField("kismet.datasourcetracker.defaults", 
                    shared_ptr<datasourcetracker_defaults>(new 
                        datasourcetracker_defaults(globalreg, 0)), 
                    "Datasource default values"));

    if (globalreg->kismet_config->FetchOptBoolean("channel_hop", true)) {
        _MSG("Enabling channel hopping by default on sources which support channel "
                "control.", MSGFLAG_INFO);
        config_defaults->set_hop(true);
    }

    string optval;
    if ((optval = globalreg->kismet_config->FetchOpt("channel_hop_speed")) != "") {
        unsigned int v;
        double dv;

        if (sscanf(optval.c_str(), "%u/sec", &v) == 1) {
            _MSG("Setting default channel hop rate to " + IntToString(v) + 
                    " channels per second", MSGFLAG_INFO);
            config_defaults->set_hop_rate(v);
        } else if (sscanf(optval.c_str(), "%u/min", &v) == 1) {
            // Channel hop is # of hops a second, timed in usec, so to get hops per
            // minute we get a minutes worth of usecs (60m), divide by the number
            // of hops per minute, then divide a second by that.
            dv = (double) 1000000 / (double) ((double) (1000000 * 60) / (double) v);
            _MSG("Setting dfault channel hop rate to " + IntToString(v) + 
                    " channels per minute", MSGFLAG_INFO);
            config_defaults->set_hop_rate(dv);
        } else {
            _MSG("Unable to parse channel_hop_speed= from kismet config, expected "
                    "value/sec or value/minute, defaulting to 1/sec", MSGFLAG_ERROR);
            config_defaults->set_hop_rate(1);
        }
    } else {
        _MSG("No channel_hop_speed= in kismet config, setting hop "
                "rate to 1/sec", MSGFLAG_INFO);
        config_defaults->set_hop_rate(1);
    }

    if (globalreg->kismet_config->FetchOptBoolean("split_source_hopping", true)) {
        _MSG("Enabling channel list splitting on sources which share the same list "
                "of channels", MSGFLAG_INFO);
        config_defaults->set_split_same_sources(true);
    }

    if (globalreg->kismet_config->FetchOptBoolean("randomized_hopping", true)) {
        _MSG("Enabling channel list shuffling to optimize overlaps", MSGFLAG_INFO);
        config_defaults->set_random_channel_order(true);
    }

}

Datasourcetracker::~Datasourcetracker() {
    local_eol_locker lock(&dst_lock);

    globalreg->RemoveGlobal("DATA_SOURCE_TRACKER");

    if (completion_cleanup_id >= 0)
        timetracker->RemoveTimer(completion_cleanup_id);

    for (auto i = probing_map.begin(); i != probing_map.end(); ++i) {
        i->second->cancel();
    }

    for (auto i = listing_map.begin(); i != listing_map.end(); ++i) {
        // TODO implement these
        // i->second->cancel();
    }

    pthread_mutex_destroy(&dst_lock);
}

int Datasourcetracker::system_startup() {
    bool used_args = false;

    vector<string> src_vec;

    int option_idx = 0;

	static struct option packetsource_long_options[] = {
		{ "capture-source", required_argument, 0, 'c' },
		{ 0, 0, 0, 0 }
	};

    optind = 0;

    while (1) {
        int r = getopt_long(globalreg->argc, globalreg->argv, "-c:",
                packetsource_long_options, &option_idx);

        if (r < 0) break;

        if (r == 'c') {
            used_args = true;
            src_vec.push_back(string(optarg));
        }
    }

    if (used_args) {
        _MSG("Data sources passed on the command line (via -c source), ignoring "
                "source= definitions in the Kismet config file.", MSGFLAG_INFO);
    } else {
        src_vec = globalreg->kismet_config->FetchOptVec("source");
    }

    if (src_vec.size() == 0) {
        _MSG("No data sources defined; Kismet will not capture anything until "
                "a source is added.", MSGFLAG_INFO);
        return 1;
    }

    for (unsigned int i = 0; i < src_vec.size(); i++) {
        open_datasource(src_vec[i], [this, src_vec, i](bool success, string reason) {
            if (success) {
                _MSG("Data source '" + src_vec[i] + "' launched successfully.", 
                        MSGFLAG_INFO);
            } else {
                if (reason.length() != 0) {
                    _MSG("Data source '" + src_vec[i] + "' failed to launch: " + reason,
                            MSGFLAG_ERROR);
                } else {
                    _MSG("Data source '" + src_vec[i] + "' failed to launch, "
                            "no error given.", MSGFLAG_ERROR);
                }
            }
        });
    }


    return 1;
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
    // fprintf(stderr, "debug - DST open source %s\n", in_source.c_str());

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
        options = in_source.substr(cpos + 1, in_source.size() - cpos);

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
            ss << "Unable to find datasource for '" << type << "'.  Make sure "
                "that any plugins required are loaded and that the capture "
                "interface is available.";

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
    _MSG("Probing for datasource type for '" + interface + "'", MSGFLAG_INFO);

    // Create a DSTProber to handle the probing
    SharedDSTProbe dst_probe(new DST_DatasourceProbe(globalreg, 
                in_source, proto_vec));
    unsigned int probeid = next_probe_id++;

    // Record it
    probing_map.emplace(probeid, dst_probe);

    // fprintf(stderr, "debug - pushed probe %u raw %p\n", probeid, dst_probe.get());

    // Initiate the probe
    dst_probe->probe_sources([this, probeid, in_cb](SharedDatasourceBuilder builder) {
        // Lock on completion
        local_locker lock(&dst_lock);

        // fprintf(stderr, "debug - moving probe to completed vec\n");

        auto i = probing_map.find(probeid);

        if (i != probing_map.end()) {
            // fprintf(stderr, "debug - dst - calling callback\n");
            stringstream ss;
            if (builder == NULL) {
                // fprintf(stderr, "debug - DST - callback with fail\n");

                // We couldn't find a type, return an error to our initial open CB
                ss << "Unable to find driver for '" << i->second->get_definition() << 
                    "'.  Make sure that any plugins required are loaded.";
                _MSG(ss.str(), MSGFLAG_ERROR);
                in_cb(false, ss.str());
            } else {
                ss << "Found type '" << builder->get_source_type() << "' for '" <<
                    i->second->get_definition() << "'";
                _MSG(ss.str(), MSGFLAG_INFO);

                // Initiate an open w/ a known builder
                open_datasource(i->second->get_definition(), builder, in_cb);
            }

            probing_complete_vec.push_back(i->second);
            probing_map.erase(i);
            schedule_cleanup();
        } else {
            // fprintf(stderr, "debug - DST couldn't find response %u\n", probeid);
        }
    });


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
                local_locker lock(&dst_lock);

                // Get the UUID and compare it to our map; re-use a UUID if we knew
                // it before, otherwise add a new one
                uuid u = ds->get_source_uuid();

                auto i = uuid_source_num_map.find(u);
                if (i != uuid_source_num_map.end()) {
                    ds->set_source_number(i->second);
                } else {
                    ds->set_source_number(next_source_num++);
                    uuid_source_num_map.emplace(u, ds->get_source_number());
                }

                // Figure out channel hopping
                calculate_source_hopping(ds);

                in_cb(true, "");
            } else {
                in_cb(false, reason);
            }
        });
}

void Datasourcetracker::schedule_cleanup() {
    local_locker lock(&dst_lock);

    if (completion_cleanup_id >= 0)
        return;

    completion_cleanup_id = 
        timetracker->RegisterTimer(1, NULL, 0, [this] (int) -> int {
            local_locker lock(&dst_lock);

            completion_cleanup_id = -1;

            // fprintf(stderr, "debug - dst cleanup scheduler - emptying complete vecs\n");

            probing_complete_vec.clear();
            listing_complete_vec.clear();

            return 0;
        });
    //fprintf(stderr, "debug - dst scheduling cleanup as %d\n", completion_cleanup_id);
}

void Datasourcetracker::NewConnection(shared_ptr<RingbufferHandler> conn_handler) {

}

// Basic DST worker for figuring out how many sources of the same type
// exist, and are hopping
class dst_chansplit_worker : public DST_Worker {
public:
    dst_chansplit_worker(GlobalRegistry *in_globalreg, 
            shared_ptr<datasourcetracker_defaults> in_defaults, 
            SharedDatasource in_ds) {
        globalreg = in_globalreg;
        defaults = in_defaults;
        target_sources.push_back(in_ds);
        initial_ds = in_ds;
        match_type = in_ds->get_source_builder()->get_source_type();
    }

    virtual void handle_datasource(SharedDatasource in_src) {
        // Don't dupe ourselves
        if (in_src == initial_ds)
            return;

        // Don't look at ones we don't care about
        if (in_src->get_source_builder()->get_source_type() != match_type)
            return;

        // Don't look at ones that aren't hopping b/c of manual config
        if (!in_src->get_source_hopping())
            return;

        target_sources.push_back(in_src);
    }

    virtual void finalize() {
        if (target_sources.size() <= 1) {
            initial_ds->set_channel_hop(defaults->get_hop_rate(),
                    initial_ds->get_source_hop_vec(),
                    defaults->get_random_channel_order(),
                    0, 0, NULL);
            return;
        }

        _MSG("Splitting channels for interfaces using '" + match_type + "' among " +
                IntToString(target_sources.size()) + " interfaces", MSGFLAG_INFO);

        int nintf = 0;
        for (auto ds = target_sources.begin(); ds != target_sources.end(); ++ds) {
            int offt_count = target_sources.size();

            SharedTrackerElement ds_hopchans = (*ds)->get_source_hop_vec();
            TrackerElementVector ds_hopvec(ds_hopchans);

            int ds_offt = (ds_hopvec.size() / offt_count) * nintf;

            (*ds)->set_channel_hop(defaults->get_hop_rate(), ds_hopchans, 
                    defaults->get_random_channel_order(),
                    ds_offt, 0, NULL);

            nintf++;
        }

    }

protected:
    string match_type;

    GlobalRegistry *globalreg;

    SharedDatasource initial_ds;
    vector<SharedDatasource> target_sources;

    shared_ptr<datasourcetracker_defaults> defaults;

};

void Datasourcetracker::calculate_source_hopping(SharedDatasource in_ds) {

    // Turn on channel hopping with our defaults
    if (config_defaults->get_hop()) {
        if (config_defaults->get_split_same_sources()) {
            dst_chansplit_worker worker(globalreg, config_defaults, in_ds);

            iterate_datasources(&worker);

        } else {
            in_ds->set_channel_hop(config_defaults->get_hop_rate(),
                    in_ds->get_source_hop_vec(),
                    config_defaults->get_random_channel_order(),
                    0, 0, NULL);
        }
    }
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

