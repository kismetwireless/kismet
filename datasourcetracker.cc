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

#include <string.h>

#include "configfile.h"
#include "getopt.h"
#include "datasourcetracker.h"
#include "messagebus.h"
#include "globalregistry.h"
#include "msgpack_adapter.h"
#include "alertracker.h"
#include "kismet_json.h"
#include "timetracker.h"
#include "structured.h"
#include "base64.h"
#include "pcapng_stream_ringbuf.h"
#include "streamtracker.h"
#include "kis_httpd_registry.h"
#include "endian_magic.h"

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
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
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

DST_DatasourceList::DST_DatasourceList(GlobalRegistry *in_globalreg,
        SharedTrackerElement in_protovec) {
    globalreg = in_globalreg;

    timetracker =
        static_pointer_cast<Timetracker>(globalreg->FetchGlobal("TIMETRACKER"));

    // Make a recursive mutex that the owning thread can lock multiple times;
    // Required to allow a timer event to reschedule itself on completion
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&list_lock, &mutexattr);

    proto_vec = in_protovec;

    transaction_id = 0;

    cancelled = false;
    cancel_timer = -1;
}

DST_DatasourceList::~DST_DatasourceList() {
    local_eol_locker lock(&list_lock);

    // Cancel any probing sources and delete them
    for (auto i = list_vec.begin(); i != list_vec.end(); ++i) {
        (*i)->close_source();
    }

    pthread_mutex_destroy(&list_lock);
}

void DST_DatasourceList::cancel() {
    local_locker lock(&list_lock);

    cancelled = true;

    // Cancel any pending timer
    if (cancel_timer >= 0) {
        timetracker->RemoveTimer(cancel_timer);
    }
    for (auto i = ipc_list_map.begin(); i != ipc_list_map.end(); ++i) {
        i->second->close_source();
    }

    if (list_cb) 
        list_cb(listed_sources);
}

void DST_DatasourceList::complete_list(vector<SharedInterface> in_list, 
        unsigned int in_transaction) {
    local_locker lock(&list_lock);

    // If we're already in cancelled state these callbacks mean nothing, ignore them
    if (cancelled)
        return;

    for (auto i = in_list.begin(); i != in_list.end(); ++i) {
        listed_sources.push_back(*i);
    }

    auto v = ipc_list_map.find(in_transaction);
    if (v != ipc_list_map.end()) {
        complete_vec.push_back(v->second);
        ipc_list_map.erase(v);
    } else {
    }

    if (ipc_list_map.size() == 0) {
        cancel();
        return;
    }
}

void DST_DatasourceList::list_sources(
        function<void (vector<SharedInterface>)> in_cb) {
    local_locker lock(&list_lock);

    cancel_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
            [this] (int) -> int {
                cancel();
                return 0;
            });

    list_cb = in_cb;

    TrackerElementVector vec(proto_vec);

    vector<SharedDatasourceBuilder> remote_builders;

    for (auto i = vec.begin(); i != vec.end(); ++i) {
        SharedDatasourceBuilder b = static_pointer_cast<KisDatasourceBuilder>(*i);

        if (!b->get_list_capable())
            continue;
       
        unsigned int transaction = transaction_id++;

        // Instantiate a local lister 
        SharedDatasource pds = b->build_datasource(b);

        ipc_list_map.emplace(transaction, pds);

        pds->list_interfaces(transaction, 
            [this] (unsigned int transaction, vector<SharedInterface> interfaces) {
                complete_list(interfaces, transaction);
            });
    }

    if (ipc_list_map.size() == 0) {
        cancel();
        return;
    }
}


Datasourcetracker::Datasourcetracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg),
    TcpServerV2(in_globalreg) {
    globalreg = in_globalreg;

    entrytracker = 
        globalreg->FetchGlobalAs<EntryTracker>("ENTRY_TRACKER");
    if (entrytracker == NULL)
        throw std::runtime_error("entrytracker not initialized before Datasourcetracker");

    timetracker =
        globalreg->FetchGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker == NULL)
        throw std::runtime_error("timetracker not initialized before Datasourcetracker");

    // Create an alert for source errors
    shared_ptr<Alertracker> alertracker =
        globalreg->FetchGlobalAs<Alertracker>("ALERTTRACKER");
    if (alertracker == NULL)
        throw std::runtime_error("alertracker not initialized before Datasourcetracker");

    alertracker->DefineAlert("SOURCEERROR", sat_second, 1, sat_second, 10);
    alertracker->ActivateConfiguredAlert("SOURCEERROR",
            "A data source encountered an error.  Depending on the source configuration "
            "Kismet may automatically attempt to re-open the source.");

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
        double dv = string_to_rate(optval, 1);
        config_defaults->set_hop_rate(dv);
        _MSG("Setting default channel hop rate to " + optval, MSGFLAG_INFO);
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

    if (globalreg->kismet_config->FetchOptBoolean("retry_on_source_error", true)) {
        _MSG("Sources will be re-opened if they encounter an error", MSGFLAG_INFO);
        config_defaults->set_retry_on_error(true);
    }

    string listen = globalreg->kismet_config->FetchOpt("remote_capture_listen");
    uint32_t listenport = 
        globalreg->kismet_config->FetchOptUInt("remote_capture_port", 0);

    if (listen.length() == 0) {
        _MSG("No remote_capture_listen= line found in kismet.conf; no remote "
                "capture will be enabled.", MSGFLAG_INFO);
    }

    if (listenport == 0) {
        _MSG("No remote_capture_port= line found in kismet.conf; no remote "
                "capture will be enabled.", MSGFLAG_INFO);
    }

    config_defaults->set_remote_cap_listen(listen);
    config_defaults->set_remote_cap_port(listenport);

    if (listen.length() != 0 && listenport != 0) {
        _MSG("Launching remote capture server on " + listen + ":" + 
                UIntToString(listenport), MSGFLAG_INFO);
        if (ConfigureServer(listenport, 1024, listen, vector<string>()) < 0) {
            _MSG("Failed to launch remote capture TCP server, check your "
                    "remote_capture_listen= and remote_capture_port= lines in "
                    "kismet.conf", MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
        }
    }

    remote_complete_timer = -1;

    httpd_pcap.reset(new Datasourcetracker_Httpd_Pcap(globalreg));

    // Register js module for UI
    shared_ptr<Kis_Httpd_Registry> httpregistry = 
        globalreg->FetchGlobalAs<Kis_Httpd_Registry>("WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_datasources", 
            "/js/kismet.ui.datasources.js");
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

shared_ptr<datasourcetracker_defaults> Datasourcetracker::get_config_defaults() {
    return config_defaults;
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
        open_datasource(src_vec[i], 
                [this, src_vec, i](bool success, string reason, SharedDatasource) {
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

void Datasourcetracker::system_shutdown() {
    local_locker lock(&dst_lock);

    TrackerElementVector dvec(datasource_vec);

    for (auto i = dvec.begin(); i != dvec.end(); ++i) {
        SharedDatasource ds = static_pointer_cast<KisDatasource>(*i);

        ds->close_source();
    }
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

SharedDatasource Datasourcetracker::find_datasource(uuid in_uuid) {
    local_locker lock(&dst_lock);

    TrackerElementVector dsv(datasource_vec);

    // Look for it in the sources vec and fully close it and get rid of it
    for (auto i = dsv.begin(); i != dsv.end(); ++i) {
        SharedDatasource kds = static_pointer_cast<KisDatasource>(*i);

        if (kds->get_source_uuid() == in_uuid) {
            return kds;
        }
    }

    return NULL;
}

bool Datasourcetracker::close_datasource(uuid in_uuid) {
    local_locker lock(&dst_lock);

    TrackerElementVector dsv(datasource_vec);

    // Look for it in the sources vec and fully close it and get rid of it
    for (auto i = dsv.begin(); i != dsv.end(); ++i) {
        SharedDatasource kds = static_pointer_cast<KisDatasource>(*i);

        if (kds->get_source_uuid() == in_uuid) {
            stringstream ss;

            ss << "Closing source '" << kds->get_source_name() << "'";
            _MSG(ss.str(), MSGFLAG_INFO);

            // Close it
            kds->close_source();

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
        function<void (bool, string, SharedDatasource)> in_cb) {
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
                in_cb(false, ss.str(), NULL);
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
                in_cb(false, ss.str(), NULL);
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

void Datasourcetracker::open_datasource(string in_source, SharedDatasourceBuilder in_proto,
        function<void (bool, string, SharedDatasource)> in_cb) {
    local_locker lock(&dst_lock);

    // Make a data source from the builder
    SharedDatasource ds = in_proto->build_datasource(in_proto);

    ds->open_interface(in_source, 0, 
        [this, ds, in_cb] (unsigned int, bool success, string reason) {
            // Whenever we succeed (or fail) at opening a deferred open source,
            // call our callback w/ whatever we know
            if (success) {
                merge_source(ds);
                in_cb(true, "", ds);
            } else {
                // It's 'safe' to put them in the broken source vec because all we do is
                // clear that vector on a timer; if the source is in error state but
                // bound elsewhere in the system it won't be removed.
                local_locker lock(&dst_lock);
                broken_source_vec.push_back(ds);
                in_cb(false, reason, ds);
                schedule_cleanup();
            }
        });
}

void Datasourcetracker::merge_source(SharedDatasource in_source) {
    local_locker lock(&dst_lock);

    // Get the UUID and compare it to our map; re-use a UUID if we knew
    // it before, otherwise add a new one
    uuid u = in_source->get_source_uuid();

    auto i = uuid_source_num_map.find(u);
    if (i != uuid_source_num_map.end()) {
        in_source->set_source_number(i->second);
    } else {
        in_source->set_source_number(next_source_num++);
        uuid_source_num_map.emplace(u, in_source->get_source_number());
    }

    // Figure out channel hopping
    calculate_source_hopping(in_source);

    TrackerElementVector vec(datasource_vec);
    vec.push_back(in_source);
}

void Datasourcetracker::list_interfaces(function<void (vector<SharedInterface>)> in_cb) {
    local_locker lock(&dst_lock);

    // Create a DSTProber to handle the probing
    SharedDSTList dst_list(new DST_DatasourceList(globalreg, proto_vec));
    unsigned int listid = next_list_id++;

    // Record it
    listing_map.emplace(listid, dst_list);

    // Initiate the probe
    dst_list->list_sources([this, listid, in_cb](vector<SharedInterface> interfaces) {
        // Lock on completion
        local_locker lock(&dst_lock);

        // Figure out what interfaces are in use by active sources and amend their
        // UUID records in the listing
        TrackerElementVector dsv(datasource_vec);
        for (auto il = interfaces.begin(); il != interfaces.end(); ++il) {
            for (auto s = dsv.begin(); s != dsv.end(); ++s) {
                SharedDatasource sds =
                    static_pointer_cast<KisDatasource>(*s);
                if ((*il)->get_interface() == sds->get_source_interface() ||
                        (*il)->get_interface() == sds->get_source_cap_interface()) {
                    (*il)->set_in_use_uuid(sds->get_source_uuid());
                    break;
                }
            }
        }

        in_cb(interfaces);

        auto i = listing_map.find(listid);

        if (i != listing_map.end()) {
            listing_complete_vec.push_back(i->second);
            listing_map.erase(i);
            schedule_cleanup();
        } else {
            // fprintf(stderr, "debug - DST couldn't find response %u\n", probeid);
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
            broken_source_vec.clear();

            return 0;
        });
    //fprintf(stderr, "debug - dst scheduling cleanup as %d\n", completion_cleanup_id);
}

void Datasourcetracker::NewConnection(shared_ptr<RingbufferHandler> conn_handler) {
    dst_incoming_remote *incoming = new dst_incoming_remote(globalreg, conn_handler, 
                [this] (string in_type, string in_def, uuid in_uuid,
                    shared_ptr<RingbufferHandler> in_handler) {
            in_handler->RemoveReadBufferInterface();
            open_remote_datasource(in_type, in_def, in_uuid, in_handler);
        });

    conn_handler->SetReadBufferInterface(incoming);
}

void Datasourcetracker::open_remote_datasource(string in_type, string in_definition,
        uuid in_uuid, shared_ptr<RingbufferHandler> in_handler) {
    local_locker lock(&dst_lock);

    // Look for an existing datasource with the same UUID
    TrackerElementVector ds_vector(datasource_vec);

    for (auto p : ds_vector) {
        SharedDatasource d = static_pointer_cast<KisDatasource>(p);

        if (!d->get_source_builder()->get_remote_capable())
            continue;

        if (d->get_source_uuid() == in_uuid) {
            _MSG("Matching remote source '" + in_definition + "' with existing source "
                    "with UUID " + in_uuid.UUID2String(), MSGFLAG_INFO);

            // Generate a detached thread for joining the ring buffer
            std::thread t([this, d, in_handler, in_definition]{
                d->connect_ringbuffer(in_handler, in_definition, NULL);
                calculate_source_hopping(d);
            });
            t.detach();

            return;
        }
    }

    // Otherwise look for a prototype that can handle it

    TrackerElementVector proto_vector(proto_vec);

    for (auto p : proto_vector) {
        SharedDatasourceBuilder b = static_pointer_cast<KisDatasourceBuilder>(p);

        if (!b->get_remote_capable())
            continue;

        if (b->get_source_type() == in_type) {
            // Make a data source from the builder
            SharedDatasource ds = b->build_datasource(b);
            ds->connect_ringbuffer(in_handler, in_definition,
                [this, ds](unsigned int, bool success, string msg) {
                    if (success)
                        merge_source(ds); 
                });

            return;
        }
    }

    _MSG("Datasourcetracker could not find local handler for remote source type '" +
            in_type + "' definition '" + in_definition + "', closing connection.",
            MSGFLAG_ERROR);
    in_handler->ProtocolError();

}

// Basic DST worker for figuring out how many sources of the same type
// exist, and are hopping
class dst_chansplit_worker : public DST_Worker {
public:
    dst_chansplit_worker(GlobalRegistry *in_globalreg, 
            Datasourcetracker *in_dst,
            shared_ptr<datasourcetracker_defaults> in_defaults, 
            SharedDatasource in_ds) {
        globalreg = in_globalreg;
        dst = in_dst;
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

        // Don't look at ones that aren't open yet
        if (!in_src->get_source_running()) 
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

            double rate = dst->string_to_rate((*ds)->get_definition_opt("hoprate"), -1);

            if (rate < 0) {
                rate = defaults->get_hop_rate();
            }

            (*ds)->set_channel_hop(rate, ds_hopchans, 
                    defaults->get_random_channel_order(),
                    ds_offt, 0, NULL);

            nintf++;
        }

    }

protected:
    string match_type;

    GlobalRegistry *globalreg;

    Datasourcetracker *dst;

    SharedDatasource initial_ds;
    vector<SharedDatasource> target_sources;

    shared_ptr<datasourcetracker_defaults> defaults;

};

void Datasourcetracker::calculate_source_hopping(SharedDatasource in_ds) {
    if (!in_ds->get_definition_opt_bool("channel_hop", true)) {
        // Source doesn't hop regardless of defaults
        return;
    }

    // Turn on channel hopping if we do that
    if (config_defaults->get_hop()) {
        // Do we split sources?
        if (config_defaults->get_split_same_sources()) {
            dst_chansplit_worker worker(globalreg, this, config_defaults, in_ds);
            iterate_datasources(&worker);
        } else {
            in_ds->set_channel_hop(config_defaults->get_hop_rate(),
                    in_ds->get_source_hop_vec(),
                    config_defaults->get_random_channel_order(),
                    0, 0, NULL);
        }
    }
}

void Datasourcetracker::queue_dead_remote(dst_incoming_remote *in_dead) {
    local_locker lock(&dst_lock);

    fprintf(stderr, "debug - queueing dead remote\n");

    for (auto x : dst_remote_complete_vec) {
        if (x == in_dead)
            return;
    }

    if (remote_complete_timer <= 0) {
        remote_complete_timer =
            timetracker->RegisterTimer(1, NULL, 0, 
                [this] (int) -> int {
                    local_locker lock(&dst_lock);

                    fprintf(stderr, "debug - cleaning up remote connections\n");
                    
                    for (auto x : dst_remote_complete_vec) {
                        delete(x);
                    }

                    dst_remote_complete_vec.clear();

                    return 0;
                });
    }

}


bool Datasourcetracker::Httpd_VerifyPath(const char *path, const char *method) {
    string stripped = Httpd_StripSuffix(path);

    if (strcmp(method, "POST") == 0) {
        if (stripped == "/datasource/add_source")
            return true;

        vector<string> tokenurl = StrTokenize(path, "/");

        if (tokenurl.size() < 5)
            return false;

        // /datasource/by-uuid/aaa-bbb-cc-dd/source.json | .msgpack
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "by-uuid") {
                uuid u(tokenurl[3]);

                if (u.error)
                    return false;

                local_locker lock(&dst_lock);

                if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                    return false;

                if (Httpd_StripSuffix(tokenurl[4]) == "set_channel") {
                    return true;
                }

                if (Httpd_StripSuffix(tokenurl[4]) == "set_hop") {
                    return true;
                }

                return false;
            }
        }
    }

    if (strcmp(method, "GET") == 0) {
        
        if (!Httpd_CanSerialize(path))
            return false;

        if (stripped == "/datasource/all_sources")
            return true;

        if (stripped == "/datasource/types")
            return true;

        if (stripped == "/datasource/defaults")
            return true;

        if (stripped == "/datasource/list_interfaces")
            return true;

        vector<string> tokenurl = StrTokenize(path, "/");

        if (tokenurl.size() < 5)
            return false;

        // /datasource/by-uuid/aaa-bbb-cc-dd/source.json | .msgpack
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "by-uuid") {
                uuid u(tokenurl[3]);

                if (u.error)
                    return false;

                local_locker lock(&dst_lock);

                if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                    return false;

                if (Httpd_StripSuffix(tokenurl[4]) == "source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "close_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "disable_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "open_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "enable_source")
                    return true;


                return true;
            }
        }

    }

    return false;
}

void Datasourcetracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
       const char *path, const char *method, const char *upload_data,
       size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    string stripped = Httpd_StripSuffix(path);

    if (!Httpd_CanSerialize(path))
        return;

    if (stripped == "/datasource/all_sources") {
        local_locker lock(&dst_lock);
        Httpd_Serialize(path, stream, datasource_vec);
        return;
    }

    if (stripped == "/datasource/types") {
        local_locker lock(&dst_lock);
        Httpd_Serialize(path, stream, proto_vec);
        return;
    }

    if (stripped == "/datasource/defaults") {
        local_locker lock(&dst_lock);
        Httpd_Serialize(path, stream, config_defaults);
        return;
    }

    if (stripped == "/datasource/list_interfaces") {
        // Require a login for doing an interface list
        if (!httpd->HasValidSession(connection, true)) {
            return;
        }

        // Locker for waiting for the list callback
        shared_ptr<conditional_locker<string> > cl(new conditional_locker<string>());

        cl->lock();

        // Initiate the open
        list_interfaces(
                [this, cl, path, &stream](vector<SharedInterface> iflist) {
                    SharedTrackerElement il(new TrackerElement(TrackerVector));
                    TrackerElementVector iv(il);

                    for (auto i = iflist.begin(); i != iflist.end(); ++i) {
                        iv.push_back(*i);
                    }

                    Httpd_Serialize(path, stream, il);

                    // Unlock the locker so we unblock below
                    cl->unlock("done");
                });

        // Block until the list cmd unlocks us
        cl->block_until();

        return;
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 5) {
        return;
    }

    // /datasource/by-uuid/aaa-bbb-cc-dd/source.json | .msgpack
    if (tokenurl[1] == "datasource") {
        if (tokenurl[2] == "by-uuid") {
            uuid u(tokenurl[3]);

            if (u.error) {
                return;
            }

            SharedDatasource ds;

            TrackerElementVector svec(datasource_vec);

            {
                local_locker lock(&dst_lock);
                for (auto i = svec.begin(); i != svec.end(); ++i) {
                    SharedDatasource dsi = static_pointer_cast<KisDatasource>(*i);

                    if (dsi->get_source_uuid() == u) {
                        ds = dsi;
                        break;
                    }
                }
            }

            if (ds == NULL) {
                stream << "Error";
                return;
            }

            if (Httpd_StripSuffix(tokenurl[4]) == "source") {
                Httpd_Serialize(path, stream, ds);
                return;
            }

            if (Httpd_StripSuffix(tokenurl[4]) == "close_source" ||
                    Httpd_StripSuffix(tokenurl[4]) == "disable_source") {
                if (ds->get_source_running()) {
                    _MSG("Closing source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->disable_source();
                    stream << "Closing source " << ds->get_uuid().UUID2String();
                    return;
                } else {
                    stream << "Source already closed, disabling source " <<
                        ds->get_uuid().UUID2String();
                    ds->disable_source();
                    return;
                }
            }

            if (Httpd_StripSuffix(tokenurl[4]) == "open_source") {
                if (!ds->get_source_running()) {
                    _MSG("Re-opening source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->open_interface(ds->get_source_definition(), 0, NULL);
                    stream << "Re-opening source";
                    return;
                } else {
                    stream << "Source already open";
                    connection->httpcode = 500;
                    return;
                }
            }
            
            return;
        }
    }

}

int Datasourcetracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    if (!Httpd_CanSerialize(concls->url)) {
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
        return 1;
    }

    // All the posts require login
    if (!httpd->HasValidSession(concls, true)) {
        return 1;
    }

    string stripped = Httpd_StripSuffix(concls->url);

    SharedStructured structdata;

    try {

        // Parse the msgpack or json paramaters, we'll need them later
        if (concls->variable_cache.find("msgpack") != concls->variable_cache.end()) {
            structdata.reset(new StructuredMsgpack(Base64::decode(concls->variable_cache["msgpack"]->str())));
        } else if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            throw std::runtime_error("unable to find data");
        }

        // Locker for waiting for the open callback
        shared_ptr<conditional_locker<string> > cl(new conditional_locker<string>());

        if (stripped == "/datasource/add_source") {
            string r; 

            if (!structdata->hasKey("definition")) {
                throw std::runtime_error("Missing source definition");
            }

            cl->lock();

            // Initiate the open
            open_datasource(structdata->getKeyAsString("definition"),
                    [this, cl, concls](bool success, string reason, 
                        SharedDatasource ds) {
                        if (success) {
                            concls->response_stream << 
                                ds->get_source_uuid().UUID2String();
                            concls->httpcode = 200;
                        } else {
                            concls->response_stream << reason;
                            concls->httpcode = 500;
                        }
                       
                        // Unlock the locker so we unblock below
                        cl->unlock(reason);
                    });

            // Block until the open cmd unlocks us
            r = cl->block_until();
            return 1;
        } 

        // No single url we liked, split and look at the path
        vector<string> tokenurl = StrTokenize(concls->url, "/");

        if (tokenurl.size() < 5) {
            throw std::runtime_error("Unknown URI");
        }


        // /datasource/by-uuid/aaa-bbb-cc-dd/command.cmd / .jcmd
        if (tokenurl[1] == "datasource" && tokenurl[2] == "by-uuid") {
            uuid u(tokenurl[3]);

            if (u.error) 
                throw std::runtime_error("Invalid UUID");

            SharedDatasource ds;

            {
                local_locker lock(&dst_lock);

                if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                    throw std::runtime_error("Unknown source");

                TrackerElementVector dsvec(datasource_vec);
                for (auto i = dsvec.begin(); i != dsvec.end(); ++i) {
                    SharedDatasource dsi = static_pointer_cast<KisDatasource>(*i);

                    if (dsi->get_source_uuid() == u) {
                        ds = dsi;
                        break;
                    }
                }

                if (ds == NULL) {
                    throw std::runtime_error("Unknown source");
                }
            }

            if (Httpd_StripSuffix(tokenurl[4]) == "set_channel") {
                if (structdata->hasKey("channel")) {
                    string ch = structdata->getKeyAsString("channel", "");

                    if (ch.length() == 0) {
                        throw std::runtime_error("could not parse channel");
                    }

                    cl->lock();

                    _MSG("Setting source '" + ds->get_source_name() + "' channel '" +
                            ch + "'", MSGFLAG_INFO);

                    // Initiate the channel set
                    ds->set_channel(ch, 0, 
                            [this, cl, concls](unsigned int, bool success, 
                                string reason) {

                                if (success) {
                                    concls->response_stream << "Success";
                                    concls->httpcode = 200;
                                } else {
                                    concls->response_stream << reason;
                                    concls->httpcode = 500;
                                }
                                
                                cl->unlock(reason);
                            });

                    // Block until the open cmd unlocks us
                    cl->block_until();
                    return 1;

                } else {
                    // We need at least a channels or a rate to kick into
                    // hopping mode
                    if (!structdata->hasKey("channels") &&
                            !structdata->hasKey("rate")) {
                        throw std::runtime_error("expected channel, channels, "
                                "or rate");
                    }

                    // Get the channels as a vector, default to the source 
                    // default if the CGI doesn't define them
                    SharedStructured chstruct;
                    vector<string> converted_channels;

                    if (structdata->hasKey("channels")) {
                        chstruct = structdata->getStructuredByKey("channels");
                        converted_channels = chstruct->getStringVec();
                    } else {
                        TrackerElementVector dscv(ds->get_source_hop_vec());
                        for (auto c : dscv)
                            converted_channels.push_back(c->get_string());
                    }

                    // Get the hop rate and the shuffle; default to the source
                    // state if we don't have them provided
                    double rate = 
                        structdata->getKeyAsNumber("rate", ds->get_source_hop_rate());

                    unsigned int shuffle = 
                        structdata->getKeyAsNumber("shuffle",
                                ds->get_source_hop_shuffle());

                    _MSG("Source '" + ds->get_source_name() + "' setting hopping "
                            "pattern and rate", MSGFLAG_INFO);

                    // Initiate the channel set
                    ds->set_channel_hop(rate, converted_channels, shuffle, 
                            ds->get_source_hop_offset(),
                            0, [this, cl, concls](unsigned int, bool success, 
                                string reason) {

                                if (success) {
                                    concls->response_stream << "Success";
                                    concls->httpcode = 200;
                                } else {
                                    concls->response_stream << reason;
                                    concls->httpcode = 500;
                                }
                                
                                cl->unlock(reason);
                            });

                    // Block until the open cmd unlocks us
                    cl->block_until();
                    return 1;
                }
            } else if (Httpd_StripSuffix(tokenurl[4]) == "set_hop") {
                cl->lock();

                _MSG("Setting source '" + ds->get_source_name() + "' channel hopping", 
                        MSGFLAG_INFO);

                // Set it to channel hop using all the current hop attributes
                ds->set_channel_hop(ds->get_source_hop_rate(),
                        ds->get_source_hop_vec(),
                        ds->get_source_hop_shuffle(),
                        ds->get_source_hop_offset(), 0,
                        [this, cl, concls](unsigned int, bool success, 
                            string reason) {

                            if (success) {
                                concls->response_stream << "Success";
                                concls->httpcode = 200;
                            } else {
                                concls->response_stream << reason;
                                concls->httpcode = 500;
                            }
                            cl->unlock(reason);
                        });
                // Block until the open cmd unlocks us
                cl->block_until();
                return 1;
            }
        }

        // Otherwise no URL path we liked
        concls->response_stream << "Invalid request";
        concls->httpcode = 400;
        return 1;
    
    } catch (const std::exception& e) {
        concls->response_stream << "Invalid request " << e.what();
        concls->httpcode = 400;
        return 1;
    }

    return 0;
}

double Datasourcetracker::string_to_rate(string in_str, double in_default) {
    unsigned int v;
    double dv;

    if (sscanf(in_str.c_str(), "%u/sec", &v) == 1) {
        return v;
    } else if (sscanf(in_str.c_str(), "%u/min", &v) == 1) {
        // Channel hop is # of hops a second, timed in usec, so to get hops per
        // minute we get a minutes worth of usecs (60m), divide by the number
        // of hops per minute, then divide a second by that.
        dv = (double) 1000000 / (double) ((double) (1000000 * 60) / (double) v);

        return dv;
    } else {
        return in_default;
    }
}

Datasourcetracker_Httpd_Pcap::Datasourcetracker_Httpd_Pcap(GlobalRegistry *in_globalreg) : Kis_Net_Httpd_Ringbuf_Stream_Handler(in_globalreg) {
}


bool Datasourcetracker_Httpd_Pcap::Httpd_VerifyPath(const char *path, 
        const char *method) {
    if (strcmp(method, "GET") == 0) {
        datasourcetracker =
            static_pointer_cast<Datasourcetracker>(http_globalreg->FetchGlobal("DATASOURCETRACKER"));

        shared_ptr<Packetchain> packetchain = 
            static_pointer_cast<Packetchain>(http_globalreg->FetchGlobal("PACKETCHAIN"));
        pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

        // Total pcap of all data; we put it in 2 locations
        if (strcmp(path, "/pcap/all_packets.pcapng") == 0) 
            return true;

        if (strcmp(path, "/datasource/pcap/all_sources.pcapng") == 0)
            return true;


        // Alternately, per-source capture:
        // /datasource/pcap/by-uuid/aa-bb-cc-dd/aa-bb-cc-dd.pcapng

        vector<string> tokenurl = StrTokenize(path, "/");

        if (tokenurl.size() < 6) {
            return false;
        }
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "pcap") {
                if (tokenurl[3] == "by-uuid") {
                    uuid u(tokenurl[4]);

                    if (u.error) {
                        return false;
                    }

                    SharedDatasource ds = datasourcetracker->find_datasource(u);
                    
                    if (ds != NULL)
                        return true;;
                }
            }
        }
    }

    return false;
}

void Datasourcetracker_Httpd_Pcap::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    shared_ptr<StreamTracker> streamtracker =
        static_pointer_cast<StreamTracker>(http_globalreg->FetchGlobal("STREAMTRACKER"));

    if (strcmp(url, "/pcap/all_packets.pcapng") == 0 ||
            strcmp(url, "/datasource/pcap/all_sources.pcapng") == 0) {
        if (!httpd->HasValidSession(connection)) {
            connection->httpcode = 503;
            return;
        }

        // At this point we're logged in and have an aux pointer for the
        // ringbuf aux; We can create our pcap ringbuf stream and attach it.
        // We need to close down the pcapringbuf during teardown.
        
        Kis_Net_Httpd_Ringbuf_Stream_Aux *saux = 
            (Kis_Net_Httpd_Ringbuf_Stream_Aux *) connection->custom_extension;
       
        Pcap_Stream_Ringbuf *psrb = new Pcap_Stream_Ringbuf(http_globalreg,
                saux->get_rbhandler(), NULL, NULL);

        saux->set_aux(psrb, 
            [psrb, streamtracker](Kis_Net_Httpd_Ringbuf_Stream_Aux *aux) {
                streamtracker->remove_streamer(psrb->get_stream_id());
                if (aux->aux != NULL) {
                    delete (Kis_Net_Httpd_Ringbuf_Stream_Aux *) (aux->aux);
                }
            });

        streamtracker->register_streamer(psrb, "all_sources.pcapng",
                "pcapng", "httpd", "pcapng of all packets on all sources");

        return;
    }

    // Find per-uuid and make a filtering pcapng
    vector<string> tokenurl = StrTokenize(url, "/");

    if (tokenurl.size() < 6) {
        return;
    }

    if (tokenurl[1] == "datasource") {
        if (tokenurl[2] == "pcap") {
            if (tokenurl[3] == "by-uuid") {
                uuid u(tokenurl[4]);

                if (u.error) {
                    return;
                }

                datasourcetracker =
                    static_pointer_cast<Datasourcetracker>(http_globalreg->FetchGlobal("DATASOURCETRACKER"));

                shared_ptr<Packetchain> packetchain = 
                    static_pointer_cast<Packetchain>(http_globalreg->FetchGlobal("PACKETCHAIN"));
                pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

                SharedDatasource ds = datasourcetracker->find_datasource(u);

                if (ds == NULL)
                    return;

                if (!httpd->HasValidSession(connection)) {
                    connection->httpcode = 503;
                    return;
                }

                // Get the number of this source for fast compare
                unsigned int dsnum = ds->get_source_number();

                // Create the pcap stream and attach it to our ringbuf
                Kis_Net_Httpd_Ringbuf_Stream_Aux *saux = 
                    (Kis_Net_Httpd_Ringbuf_Stream_Aux *) connection->custom_extension;

                // Fetch the datasource component and compare *source numbers*, not
                // actual UUIDs - a UUID compare is expensive, a numeric compare is not!
                Pcap_Stream_Ringbuf *psrb = new Pcap_Stream_Ringbuf(http_globalreg,
                        saux->get_rbhandler(), 
                        [this, dsnum] (kis_packet *packet) -> bool {
                            packetchain_comp_datasource *datasrcinfo = 
                                (packetchain_comp_datasource *) 
                                packet->fetch(pack_comp_datasrc);
                        
                            if (datasrcinfo == NULL)
                                return false;

                            if (datasrcinfo->ref_source->get_source_number() == dsnum)
                                return true;

                        return false; 
                        }, NULL);


                saux->set_aux(psrb, 
                    [psrb, streamtracker](Kis_Net_Httpd_Ringbuf_Stream_Aux *aux) {
                        streamtracker->remove_streamer(psrb->get_stream_id());
                        if (aux->aux != NULL) {
                            delete (Kis_Net_Httpd_Ringbuf_Stream_Aux *) (aux->aux);
                        }
                    });

                streamtracker->register_streamer(psrb, 
                        ds->get_source_name() + ".pcapng",
                        "pcapng", "httpd", 
                        "pcapng of " + ds->get_source_name() + " (" + 
                        ds->get_source_cap_interface());

            }
        }
    }

}

dst_incoming_remote::dst_incoming_remote(GlobalRegistry *in_globalreg,
        shared_ptr<RingbufferHandler> in_rbufhandler,
        function<void (string, string, uuid, shared_ptr<RingbufferHandler>)> in_cb) {
    
    globalreg = in_globalreg;
    rbuf_handler = in_rbufhandler;
    cb = in_cb;

    shared_ptr<Timetracker> timetracker = globalreg->FetchGlobalAs<Timetracker>("TIMETRACKER");

    timerid =
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
            [this] (int) -> int {
                _MSG("Remote source connected but didn't send a NEWSOURCE control, "
                        "closing connection.", MSGFLAG_ERROR);

                kill();

                return 0;
            });
}

dst_incoming_remote::~dst_incoming_remote() {
    shared_ptr<Timetracker> timetracker = globalreg->FetchGlobalAs<Timetracker>("TIMETRACKER");
  
    // Kill the error timer
    if (timetracker != NULL && timerid > 0)
        timetracker->RemoveTimer(timerid);

    // Remove ourselves as a handler
    if (rbuf_handler != NULL)
        rbuf_handler->RemoveReadBufferInterface();
}

void dst_incoming_remote::kill() {
    // Kill the error timer
    shared_ptr<Timetracker> timetracker = globalreg->FetchGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker != NULL && timerid > 0)
        timetracker->RemoveTimer(timerid);

    if (rbuf_handler != NULL) {
        // fprintf(stderr, "debug - dst incoming kill() sending protocol error\n");
        rbuf_handler->RemoveReadBufferInterface();
        rbuf_handler->ProtocolError();
        rbuf_handler = NULL;
    } else {
        // fprintf(stderr, "debug - dst incoming rbuf handler null\n");
    }

    shared_ptr<Datasourcetracker> datasourcetracker =
        globalreg->FetchGlobalAs<Datasourcetracker>("DATASOURCETRACKER");

    if (datasourcetracker != NULL) 
        datasourcetracker->queue_dead_remote(this);
}

void dst_incoming_remote::BufferAvailable(size_t in_amt) {
    // Handle reading raw frames off the incoming buffer, but we only look for the
    // NEWSOURCE command; any other frame is an error.
  
    simple_cap_proto_frame_t *frame;
    uint8_t *buf;
    uint32_t frame_sz;
    uint32_t header_checksum, data_checksum, calc_checksum;

    string definition;
    string srctype;
    uuid srcuuid;
   
    while (1) {
        if (rbuf_handler == NULL)
            return;

        size_t buffamt = rbuf_handler->GetReadBufferUsed();
        if (buffamt < sizeof(simple_cap_proto_t)) {
            return;
        }

        // Allocate as much as we can and peek it from the buffer
        buf = new uint8_t[buffamt];
        rbuf_handler->PeekReadBufferData(buf, buffamt);

        // Turn it into a frame header
        frame = (simple_cap_proto_frame_t *) buf;

        if (kis_ntoh32(frame->header.signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
            delete[] buf;
            _MSG("Got an invalid remote data source connection, disconnecting.",
                    MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();
            return;
        }

        // Get the frame header checksum and validate it; to validate we need to clear
        // both the frame and the data checksum fields so remember them both now
        header_checksum = kis_ntoh32(frame->header.header_checksum);
        data_checksum = kis_ntoh32(frame->header.data_checksum);

        // Zero the checksum field in the packet
        frame->header.header_checksum = 0;
        frame->header.data_checksum = 0;

        // Calc the checksum of the header
        calc_checksum = Adler32Checksum((const char *) frame, 
                sizeof(simple_cap_proto_t));

        // Compare to the saved checksum
        if (calc_checksum != header_checksum) {
            delete[] buf;

            _MSG("Got an invalid remote data source connection, invalid checksum, "
                    "disconnecting.", MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();

            return;
        }

        // Get the size of the frame
        frame_sz = kis_ntoh32(frame->header.packet_sz);

        if (frame_sz > buffamt) {
            // Nothing we can do right now, not enough data to 
            // make up a complete packet.
            delete[] buf;
            return;
        }

        // Calc the checksum of the rest
        calc_checksum = Adler32Checksum((const char *) buf, frame_sz);

        // Compare to the saved checksum
        if (calc_checksum != data_checksum) {
            delete[] buf;

            _MSG("Got an invalid remote data source connection, invalid checksum, "
                    "disconnecting.", MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();

            return;
        }

        // Consume the packet in the ringbuf 
        rbuf_handler->GetReadBufferData(NULL, frame_sz);

        // Check the header type
        if (strncmp(frame->header.type, "NEWSOURCE", 16) != 0) {
            delete[] buf;

            _MSG("Got an invalid remote data source connection, invalid frame "
                    "(expected NEWSOURCE), disconnecting.", MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();

            return;
        }

        size_t data_offt = 0;
        for (unsigned int kvn = 0; kvn < kis_ntoh32(frame->header.num_kv_pairs); kvn++) {
            if (frame_sz < sizeof(simple_cap_proto_t) + 
                    sizeof(simple_cap_proto_kv_t) + data_offt) {
                delete[] buf;

                _MSG("Got an invalid remote data source connection, invalid frame "
                        "(KV too long for frame), disconnecting.", MSGFLAG_ERROR);
                rbuf_handler->ProtocolError();

                return;
            }

            simple_cap_proto_kv_t *pkv =
                (simple_cap_proto_kv_t *) &((frame->data)[data_offt]);

            data_offt += 
                sizeof(simple_cap_proto_kv_h_t) + kis_ntoh32(pkv->header.obj_sz);

            // We only care about 2 KV types but will skip the rest
            if (strncmp(pkv->header.key, "DEFINITION", 16) == 0) {
                definition = string((char *) pkv->object, kis_ntoh32(pkv->header.obj_sz));
            } else if (strncmp(pkv->header.key, "SOURCETYPE", 16) == 0) {
                srctype = string((char *) pkv->object, kis_ntoh32(pkv->header.obj_sz));
            } else if (strncmp(pkv->header.key, "UUID", 16) == 0) {
                string inu = string((char *) pkv->object, kis_ntoh32(pkv->header.obj_sz));
                srcuuid = uuid(string((char *) pkv->object, kis_ntoh32(pkv->header.obj_sz)));
            }
        }

        delete[] buf;

        if (definition == "") {
            _MSG("Got an invalid remote data source connection, invalid frame "
                    "(missing DEFINITION kv), disconnecting.", MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();

            return;
        }

        if (srctype == "") {
            _MSG("Got an invalid remote data source connection, invalid frame "
                    "(missing DEFINITION kv), disconnecting.", MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();

            return;

        }

        if (srcuuid == uuid()) {
            _MSG("Got an invalid remote data source connection, invalid frame "
                    "(missing UUID kv), disconnecting.", MSGFLAG_ERROR);
            rbuf_handler->ProtocolError();

            return;
        }

        if (cb != NULL)
            cb(srctype, definition, srcuuid, rbuf_handler);

        // Zero out the rbuf handler so that it doesn't get closed
        rbuf_handler = NULL;

        kill();

        return;
    }
}

void dst_incoming_remote::BufferError(string in_error) {
    _MSG("Incoming remote source failed: " + in_error, MSGFLAG_ERROR);
    kill();
    return;
}

