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
#include "alertracker.h"
#include "kismet_json.h"
#include "timetracker.h"
#include "structured.h"
#include "base64.h"
#include "pcapng_stream_ringbuf.h"
#include "streamtracker.h"
#include "kis_httpd_registry.h"
#include "endian_magic.h"
#include "kis_databaselogfile.h"

DST_DatasourceProbe::DST_DatasourceProbe(std::string in_definition, 
        std::shared_ptr<TrackerElementVector> in_protovec) {

    timetracker = Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");

    definition = in_definition;
    proto_vec = in_protovec;

    transaction_id = 0;

    cancelled = false;
}

DST_DatasourceProbe::~DST_DatasourceProbe() {
    // Cancel any timers
    for (auto i : cancel_timer_vec)
        timetracker->RemoveTimer(i);

    // Cancel any existing transactions
    for (auto i : ipc_probe_map)
        i.second->close_source();
}

void DST_DatasourceProbe::cancel() {
    {
        local_locker lock(&probe_lock);

        cancelled = true;

        // Cancel any timers
        for (auto i : cancel_timer_vec)
            timetracker->RemoveTimer(i);

        // Cancel any other competing probing sources; this may trigger the callbacks
        // which will call the completion function, but we'll ignore them because
        // we're already cancelled
        for (auto i : ipc_probe_map)
            i.second->close_source();

        // Defer deleting sources until the probe map is cleared
    }

    // Unlock just before we call the CB so that we're not callbacked inside a thread lock;
    // call back with whatever we found - if we got something, great, otherwise we callback a 
    // nullptr
    if (probe_cb) 
        probe_cb(source_builder);
}

SharedDatasourceBuilder DST_DatasourceProbe::get_proto() {
    local_locker lock(&probe_lock);
    return source_builder;
}

void DST_DatasourceProbe::complete_probe(bool in_success, unsigned int in_transaction,
        std::string in_reason __attribute__((unused))) {
    local_locker lock(&probe_lock);

    // If we're already in cancelled state these callbacks mean nothing, ignore them, we're going
    // to be torn down so we don't even need to find our transaction
    if (cancelled)
        return;

    auto v = ipc_probe_map.find(in_transaction);

    if (v != ipc_probe_map.end()) {
        if (in_success) {
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

void DST_DatasourceProbe::probe_sources(std::function<void (SharedDatasourceBuilder)> in_cb) {
    {
        local_locker lock(&probe_lock);
        probe_cb = in_cb;
    }

    std::vector<SharedDatasourceBuilder> remote_builders;

    unsigned int ncreated = 0;

    // Do some basic validation on the definition
    // If there's a comma in the interface name and no colon, someone probably typoed; 
    // if there's a comma before the colon, also probably a typo
    auto comma_pos = definition.find(",");
    auto colon_pos = definition.find(":");

    if ((comma_pos != std::string::npos && colon_pos == std::string::npos) || comma_pos < colon_pos) {
        _MSG_ERROR("Found a ',' in the source definition '{}'.  Sources should be defined as "
                "interface:option1,option2,... this is likely a typo in your 'source=' config "
                "or in your '-c' option on the command line.", definition);
        cancel();
        return;
    }

    for (auto i : *proto_vec) {
        auto b = std::static_pointer_cast<KisDatasourceBuilder>(i);

        if (!b->get_probe_capable())
            continue;
       
        unsigned int transaction = ++transaction_id;

        // Instantiate a local prober datasource
        SharedDatasource pds = b->build_datasource(b);

        {
            local_locker lock(&probe_lock);
            ipc_probe_map[transaction] = pds;
            ncreated++;
        }

        // Set up the cancellation timer
        int cancel_timer = 
            timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
                    [this] (int) -> int {
                        _MSG_ERROR("Datasource {} cancelling source probe due to timeout", definition);
                        cancel();
                        return 0;
                    });

        // Log the cancellation timer
        cancel_timer_vec.push_back(cancel_timer);

        pds->probe_interface(definition, transaction, 
                [cancel_timer, this](unsigned int transaction, bool success, std::string reason) {
                    timetracker->RemoveTimer(cancel_timer);
                    complete_probe(success, transaction, reason);
                });
    }

    // We've done all we can; if we haven't gotten an answer yet and we
    // have nothing in our transactional map, we've failed
    if (ncreated == 0) {
        cancel();
        return;
    }

}

DST_DatasourceList::DST_DatasourceList(std::shared_ptr<TrackerElementVector> in_protovec) {
    timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>();

    proto_vec = in_protovec;

    transaction_id = 0;

    cancelled = false;
}

DST_DatasourceList::~DST_DatasourceList() {
    cancelled = true;

    // Cancel any probing sources and delete them
    for (auto i = list_vec.begin(); i != list_vec.end(); ++i) {
        (*i)->close_source();
    }
}

void DST_DatasourceList::cancel() {
    local_locker lock(&list_lock);

    if (cancelled)
        return;

    // Abort anything already underway
    for (auto i : ipc_list_map) {
        i.second->close_source();
    }

    cancelled = true;

    // Trigger the callback
    if (list_cb) 
        list_cb(listed_sources);
}

void DST_DatasourceList::complete_list(std::vector<SharedInterface> in_list, unsigned int in_transaction) {
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
    }

    // If we've emptied the vec, end
    if (ipc_list_map.size() == 0) {
        cancel();
        return;
    }
}

void DST_DatasourceList::list_sources(std::function<void (std::vector<SharedInterface>)> in_cb) {
    list_cb = in_cb;

    std::vector<SharedDatasourceBuilder> remote_builders;

    bool created_ipc = false;

    for (auto i : *proto_vec) {
        SharedDatasourceBuilder b = std::static_pointer_cast<KisDatasourceBuilder>(i);

        if (!b->get_list_capable())
            continue;
       
        unsigned int transaction = ++transaction_id;

        // Instantiate a local lister 
        SharedDatasource pds = b->build_datasource(b);

        {
            local_locker lock(&list_lock);
            ipc_list_map[transaction] = pds;
            created_ipc = true;
        }

        pds->list_interfaces(transaction, 
            [this] (unsigned int transaction, std::vector<SharedInterface> interfaces) {
                complete_list(interfaces, transaction);
            });
    }

    // If we didn't create any IPC events we'll never complete; call cancel directly
    if (!created_ipc)
        cancel();
}


Datasourcetracker::Datasourcetracker() :
    Kis_Net_Httpd_CPPStream_Handler(),
    TcpServerV2(Globalreg::globalreg) {

    timetracker = Globalreg::FetchMandatoryGlobalAs<Timetracker>();
    eventbus = Globalreg::FetchMandatoryGlobalAs<Eventbus>();

    proto_id = 
        Globalreg::globalreg->entrytracker->RegisterField("kismet.datasourcetracker.driver",
                TrackerElementFactory<KisDatasourceBuilder>(),
                "Datasource driver information");

    source_id =
        Globalreg::globalreg->entrytracker->RegisterField("kismet.datasourcetracker.datasource",
                TrackerElementFactory<KisDatasource>(nullptr),
                "Datasource");

    proto_vec =
        Globalreg::globalreg->entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("kismet.datasourcetracker.drivers",
                TrackerElementFactory<TrackerElementVector>(), "Known drivers");

    datasource_vec =
        Globalreg::globalreg->entrytracker->RegisterAndGetFieldAs<TrackerElementVector>("kismet.datasourcetracker.sources",
                TrackerElementFactory<TrackerElementVector>(), "Configured sources");

    all_sources_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/datasource/all_sources",
                [this]() -> std::shared_ptr<TrackerElement> {
                    local_shared_locker sl(&dst_lock);
                    auto serial_vec = std::make_shared<TrackerElementVector>(datasource_vec);
                    return serial_vec;
                });

    defaults_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/datasource/defaults",
                config_defaults, &dst_lock);

    types_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/datasource/types", 
                proto_vec, &dst_lock);

    list_interfaces_endp =
        std::make_shared<Kis_Net_Httpd_Simple_Tracked_Endpoint>("/datasource/list_interfaces", 
                [this]() -> std::shared_ptr<TrackerElement> {
                    // Locker for waiting for the list callback
                    auto cl = std::make_shared<conditional_locker<std::vector<SharedInterface> >>();

                    cl->lock();

                    // Initiate the open
                    list_interfaces(
                        [cl](std::vector<SharedInterface> iflist) {
                            cl->unlock(iflist);
                        });

                    // Block until the list cmd unlocks us
                    auto iflist = cl->block_until();

                    auto iv = std::make_shared<TrackerElementVector>();

                    for (auto li : iflist)
                        iv->push_back(li);

                    return iv;
                });

    Bind_Httpd_Server();
}

Datasourcetracker::~Datasourcetracker() {
    Globalreg::globalreg->RemoveGlobal("DATASOURCETRACKER");

    if (completion_cleanup_id >= 0)
        timetracker->RemoveTimer(completion_cleanup_id);

    if (database_log_timer >= 0) {
        timetracker->RemoveTimer(database_log_timer);
        databaselog_write_datasources();
    }

    for (auto i : probing_map)
        i.second->cancel();

    for (auto i : listing_map)
        i.second->cancel();
}

void Datasourcetracker::databaselog_write_datasources() {
    if (!database_log_enabled)
        return;

    std::shared_ptr<KisDatabaseLogfile> dbf =
        Globalreg::FetchGlobalAs<KisDatabaseLogfile>("DATABASELOG");
    
    if (dbf == NULL)
        return;

    // Fire off a database log, using a copy of the datasource vec
    std::shared_ptr<TrackerElementVector> v;

    {
        local_shared_locker l(&dst_lock);
        v = std::make_shared<TrackerElementVector>(datasource_vec);
    }

    dbf->log_datasources(v);
}

std::shared_ptr<datasourcetracker_defaults> Datasourcetracker::get_config_defaults() {
    return config_defaults;
}

void Datasourcetracker::Deferred_Startup() {
    bool used_args = false;

    completion_cleanup_id = -1;
    next_probe_id = 0;
    next_list_id = 0;

    next_source_num = 0;

    config_defaults = 
        Globalreg::globalreg->entrytracker->RegisterAndGetFieldAs<datasourcetracker_defaults>("kismet.datasourcetracker.defaults",
                TrackerElementFactory<datasourcetracker_defaults>(),
                "Datasource default values");

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("channel_hop", true)) {
        _MSG("Enabling channel hopping by default on sources which support channel "
                "control.", MSGFLAG_INFO);
        config_defaults->set_hop(true);
    }

    std::string optval;
    if ((optval = Globalreg::globalreg->kismet_config->FetchOpt("channel_hop_speed")) != "") {
        try {
            double dv = string_to_rate(optval, 1);
            config_defaults->set_hop_rate(dv);
            _MSG("Setting default channel hop rate to " + optval, MSGFLAG_INFO);
        } catch (const std::exception& e) {
            _MSG_FATAL("Could not parse channel_hop_speed= config: {}", e.what());
            globalreg->fatal_condition = 1;
            return;
        }
    } else {
        _MSG("No channel_hop_speed= in kismet config, setting hop "
                "rate to 1/sec", MSGFLAG_INFO);
        config_defaults->set_hop_rate(1);
    }

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("split_source_hopping", true)) {
        _MSG("Enabling channel list splitting on sources which share the same list "
                "of channels", MSGFLAG_INFO);
        config_defaults->set_split_same_sources(true);
    }

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("randomized_hopping", true)) {
        _MSG("Enabling channel list shuffling to optimize overlaps", MSGFLAG_INFO);
        config_defaults->set_random_channel_order(true);
    }

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("retry_on_source_error", true)) {
        _MSG("Sources will be re-opened if they encounter an error", MSGFLAG_INFO);
        config_defaults->set_retry_on_error(true);
    }

    std::string listen = Globalreg::globalreg->kismet_config->FetchOpt("remote_capture_listen");
    uint32_t listenport = 
        Globalreg::globalreg->kismet_config->FetchOptUInt("remote_capture_port", 0);

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

    config_defaults->set_remote_cap_timestamp(Globalreg::globalreg->kismet_config->FetchOptBoolean("override_remote_timestamp", true));

    httpd_pcap = std::make_shared<Datasourcetracker_Httpd_Pcap>();

    // Register js module for UI
    std::shared_ptr<Kis_Httpd_Registry> httpregistry = 
        Globalreg::FetchMandatoryGlobalAs<Kis_Httpd_Registry>("WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_datasources", 
            "js/kismet.ui.datasources.js");

    database_log_enabled = false;

    if (Globalreg::globalreg->kismet_config->FetchOptBoolean("kis_log_datasources", true)) {
        unsigned int lograte =
            Globalreg::globalreg->kismet_config->FetchOptUInt("kis_log_datasource_rate", 30);

        _MSG("Saving datasources to the Kismet database log every " + UIntToString(lograte) + 
                " seconds.", MSGFLAG_INFO);

        database_log_enabled = true;
        database_logging = false;

        database_log_timer =
            timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * lograte, NULL, 1, 
                    [this](int) -> int {

                        {
                            local_locker l(&dst_lock);

                            if (database_logging) {
                                _MSG("Attempting to log datasources, but datasources are still "
                                        "being saved from the last logging attempt.  It's possible "
                                        "your system is extremely over capacity; try increasing the "
                                        "delay in 'kis_log_datasource_rate' in kismet_logging.conf",
                                        MSGFLAG_ERROR);
                                return 1;
                            }

                            database_logging = true;
                        }

                        std::thread t([this] {
                            databaselog_write_datasources();

                            {
                                local_locker l(&dst_lock);
                                database_logging = false;
                            }

                        });

                        t.detach();

                        return 1;
                    });

    } else {
        database_log_timer = -1;
    }


    // Create an alert for source errors
    auto alertracker = Globalreg::FetchMandatoryGlobalAs<Alertracker>("ALERTTRACKER");

    alertracker->DefineAlert("SOURCEERROR", sat_second, 1, sat_second, 10);
    alertracker->ActivateConfiguredAlert("SOURCEERROR",
            "A data source encountered an error.  Depending on the source configuration "
            "Kismet may automatically attempt to re-open the source.");

    std::vector<std::string> src_vec;

    int option_idx = 0;

	static struct option packetsource_long_options[] = {
		{ "capture-source", required_argument, 0, 'c' },
		{ 0, 0, 0, 0 }
	};

    optind = 0;

    // Activate remote capture
    listen = config_defaults->get_remote_cap_listen();
    listenport = config_defaults->get_remote_cap_port();

    if (config_defaults->get_remote_cap_listen().length() != 0 && 
            config_defaults->get_remote_cap_port() != 0) {
        _MSG("Launching remote capture server on " + listen + ":" + 
                UIntToString(listenport), MSGFLAG_INFO);
        if (ConfigureServer(listenport, 1024, listen, std::vector<std::string>()) < 0) {
            _MSG("Failed to launch remote capture TCP server, check your "
                    "remote_capture_listen= and remote_capture_port= lines in "
                    "kismet.conf", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
        }
    }

    remote_complete_timer = -1;

    while (1) {
        int r = getopt_long(Globalreg::globalreg->argc, Globalreg::globalreg->argv, "-c:",
                packetsource_long_options, &option_idx);

        if (r < 0) break;

        if (r == 'c') {
            used_args = true;
            src_vec.push_back(std::string(optarg));
        }
    }

    if (used_args) {
        _MSG("Data sources passed on the command line (via -c source), ignoring "
                "source= definitions in the Kismet config file.", MSGFLAG_INFO);
    } else {
        src_vec = Globalreg::globalreg->kismet_config->FetchOptVec("source");
    }

    if (src_vec.size() == 0) {
        _MSG("No data sources defined; Kismet will not capture anything until "
                "a source is added.", MSGFLAG_INFO);
        return;
    }

    auto stagger_thresh = 
        Globalreg::globalreg->kismet_config->FetchOptUInt("source_stagger_threshold", 16);
    auto simul_open = 
        Globalreg::globalreg->kismet_config->FetchOptUInt("source_launch_group", 10);
    auto simul_open_delay = 
        Globalreg::globalreg->kismet_config->FetchOptUInt("source_launch_delay", 10);

    auto launch_func = [](Datasourcetracker *dst, std::string src) {
            dst->open_datasource(src, 
                    [src](bool success, std::string reason, SharedDatasource) {
                if (success) {
                    _MSG_INFO("Data source '{}' launched successfully", src);
                } else {
                    if (reason.length() != 0) {
                        _MSG_ERROR("Data source '{}' failed to launch: {}", src, reason);
                    } else {
                        _MSG_ERROR("Data source '{}' failed to launch, no error provided.", src);
                    }
                }
            });
    };

    if (stagger_thresh == 0 || src_vec.size() <= stagger_thresh) {
        auto source_t = std::thread([launch_func](Datasourcetracker *dst, 
                    const std::vector<std::string>& src_vec) {
                for (auto i : src_vec) {
                    launch_func(dst, i);
                }
                }, this, src_vec);
        source_t.detach();
    } else {
        std::vector<std::string> work_vec;
        unsigned int group_number = 0;

        for (auto i : src_vec) {
            work_vec.push_back(i);

            if (work_vec.size() > simul_open) {
                // Pass a copy of the work vec so that we can immediately clear it
                auto launch_t = std::thread([launch_func, simul_open_delay](Datasourcetracker *dst,
                            const std::vector<std::string> src_vec, unsigned int gn) {

                    // All the threads launch more or less at once, so each thread sleeps for
                    // its allocated amount of time before launching the vector
                    sleep(gn * simul_open_delay);
                    _MSG_INFO("Launching local source group {}", gn + 1);

                    for (auto i : src_vec) {
                        launch_func(dst, i);
                    }
                }, this, work_vec, group_number);
                launch_t.detach();

                work_vec.clear();
                group_number++;
            }
        }

        // Launch the last of the group
        auto launch_t = std::thread([launch_func, simul_open_delay](Datasourcetracker *dst,
                    const std::vector<std::string> src_vec, unsigned int gn) {

                    sleep(gn * simul_open_delay);
                    _MSG_INFO("Launching local source group {}", gn);

                    for (auto i : src_vec) {
                        launch_func(dst, i);
                    }
                }, this, work_vec, group_number);
                launch_t.detach();
    }

    return;
}

void Datasourcetracker::Deferred_Shutdown() {
    local_locker lock(&dst_lock);

    for (auto i : *datasource_vec) {
        std::static_pointer_cast<KisDatasource>(i)->close_source();
    }
}

void Datasourcetracker::iterate_datasources(DST_Worker *in_worker) {
    local_locker lock(&dst_lock);

    for (auto kds : *datasource_vec) {
        in_worker->handle_datasource(std::static_pointer_cast<KisDatasource>(kds));
    }

    in_worker->finalize();
}

bool Datasourcetracker::remove_datasource(const uuid& in_uuid) {
    local_locker lock(&dst_lock);

    // Look for it in the sources vec and fully close it and get rid of it
    for (auto i = datasource_vec->begin(); i != datasource_vec->end(); ++i) {
        SharedDatasource kds = std::static_pointer_cast<KisDatasource>(*i);

        if (kds->get_source_uuid() == in_uuid) {
            std::stringstream ss;

            _MSG_INFO("Closing source '{}' and removing it from the list of available "
                    "datasources.", kds->get_source_name());

            // Close it
            kds->close_source();

            // Remove it
            datasource_vec->erase(i);

            // Done
            return true;
        }
    }

    return false;
}

SharedDatasource Datasourcetracker::find_datasource(const uuid& in_uuid) {
    local_shared_locker lock(&dst_lock);

    for (auto i : *datasource_vec) {
        SharedDatasource kds = std::static_pointer_cast<KisDatasource>(i);

        if (kds->get_source_uuid() == in_uuid) 
            return kds;
    }

    return nullptr;
}

bool Datasourcetracker::close_datasource(const uuid& in_uuid) {
    local_locker lock(&dst_lock);

    for (auto i : *datasource_vec) {
        SharedDatasource kds = std::static_pointer_cast<KisDatasource>(i);

        if (kds->get_source_uuid() == in_uuid) {
            _MSG_INFO("Closing source '{}'", kds->get_source_name());

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

    for (auto i : *proto_vec) {
        SharedDatasourceBuilder b = std::static_pointer_cast<KisDatasourceBuilder>(i);

        if (StrLower(b->get_source_type()) == StrLower(in_builder->get_source_type())) {
            _MSG_ERROR("Already registered a data source for type '{}', check that you don't have "
                    "two copies of the same plugin installed in different locations or under "
                    "different names.", b->get_source_type());
            return -1;
        }
    }

    proto_vec->push_back(in_builder);

    return 1;
}

void Datasourcetracker::open_datasource(const std::string& in_source, 
        const std::function<void (bool, std::string, SharedDatasource)>& in_cb) {
    // fprintf(stderr, "debug - DST open source %s\n", in_source.c_str());

    // Open a datasource only from the string definition

    std::string interface;
    std::string options;
    std::vector<opt_pair> opt_vec;
    std::string type;

    size_t cpos = in_source.find(":");

    // Parse basic options and interface, extract type
    if (cpos == std::string::npos) {
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
        local_demand_locker lock(&dst_lock);
        lock.lock();

        SharedDatasourceBuilder proto;

        bool proto_found = false;

        for (auto i : *proto_vec) {
            proto = std::static_pointer_cast<KisDatasourceBuilder>(i);

            if (StrLower(proto->get_source_type()) == StrLower(type)) {
                proto_found = true;
                break;
            }
        }

        if (!proto_found) {
            auto ss = fmt::format("Unable to find datasource for '{}'.  Make sure that any "
                    "required plugins are installed, that the capture interface is available, "
                    "and that you installed all the Kismet helper packages.", type);

            if (in_cb != NULL) {
                lock.unlock();
                in_cb(false, ss, NULL);
                lock.lock();
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
    _MSG_INFO("Probing interface '{}' to find datasource type", interface);

    // Create a DSTProber to handle the probing
    SharedDSTProbe dst_probe(new DST_DatasourceProbe(in_source, proto_vec));
    unsigned int probeid = ++next_probe_id;

    // Record and initiate it
    {
        local_locker dl(&dst_lock);
        probing_map[probeid] = dst_probe;
    }

    // Initiate the probe
    dst_probe->probe_sources([this, probeid, in_cb](SharedDatasourceBuilder builder) {
        // Lock on completion
        local_demand_locker lock(&dst_lock);
        lock.lock();

        // fprintf(stderr, "debug - moving probe to completed vec\n");

        auto i = probing_map.find(probeid);

        if (i != probing_map.end()) {
            if (builder == nullptr) {
                // We couldn't find a type, return an error to our initial open CB
                auto ss = fmt::format("Unable to find driver for '{}'.  Make sure that any required plugins "
                        "are loaded, the interface is available, and any required Kismet helper packages are "
                        "installed.", i->second->get_definition());
                _MSG(ss, MSGFLAG_ERROR);
                lock.unlock();
                in_cb(false, ss, NULL);
                lock.lock();
            } else {
                // We got a builder
                auto ss = fmt::format("Found type '{}' for '{}'", builder->get_source_type(), i->second->get_definition());
                _MSG(ss, MSGFLAG_INFO);

                // Initiate an open w/ a known builder, associate the prototype definition with it
                open_datasource(i->second->get_definition(), builder, in_cb);
            }

            // Mark this object for completion when the callback triggers
            probing_complete_vec.push_back(i->second);

            // Remove us from the active vec
            probing_map.erase(i);

            // Schedule a cleanup 
            schedule_cleanup();
        } else {
            // fprintf(stderr, "debug - DST couldn't find response %u\n", probeid);
        }
    });

    return;
}

void Datasourcetracker::open_datasource(const std::string& in_source, 
        SharedDatasourceBuilder in_proto,
        const std::function<void (bool, std::string, SharedDatasource)>& in_cb) {
    local_locker lock(&dst_lock);

    // Make a data source from the builder
    SharedDatasource ds = in_proto->build_datasource(in_proto);

    ds->open_interface(in_source, 0, 
        [this, ds, in_cb] (unsigned int, bool success, std::string reason) {
            // Always merge it so that it gets scheduled for re-opening; when we
            // know the type we know how to keep trying
            merge_source(ds);

            // Whenever we succeed (or fail) at opening a deferred open source,
            // call our callback w/ whatever we know
            if (success) {
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
        in_source->set_source_number(++next_source_num);
        uuid_source_num_map[u] = in_source->get_source_number();
        eventbus->publish(std::make_shared<EventNewDatasource>(in_source));
    }

    // Figure out channel hopping
    calculate_source_hopping(in_source);

    if (database_log_enabled) {
        std::shared_ptr<KisDatabaseLogfile> dbf =
            Globalreg::FetchGlobalAs<KisDatabaseLogfile>("DATABASELOG");

        if (dbf != NULL) {
            dbf->log_datasource(in_source);
        }
    }

    datasource_vec->push_back(in_source);
}

void Datasourcetracker::list_interfaces(const std::function<void (std::vector<SharedInterface>)>& in_cb) {
    // Create a DSTProber to handle the probing
    auto dst_list = std::make_shared<DST_DatasourceList>(proto_vec);
    unsigned int listid = 0;
   
    {
        local_locker lock(&dst_lock);
        listid = ++next_list_id;

        // Record it
        listing_map[listid] = dst_list;
    }

    // Set up a cancellation timer
    int cancel_timer = 
        timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
            [dst_list] (int) -> int {
                dst_list->cancel();
                return 0;
            });


    // Initiate the probe
    dst_list->list_sources([this, cancel_timer, listid, in_cb](std::vector<SharedInterface> interfaces) {
        // We're complete; cancel the timer if it's still around.
        timetracker->RemoveTimer(cancel_timer);

        local_demand_locker lock(&dst_lock);
        lock.lock();

        // Figure out what interfaces are in use by active sources and amend their
        // UUID records in the listing
        for (auto il = interfaces.begin(); il != interfaces.end(); ++il) {
            for (auto s : *datasource_vec) {
                SharedDatasource sds = std::static_pointer_cast<KisDatasource>(s);
                if (!sds->get_source_remote() &&
                        ((*il)->get_interface() == sds->get_source_interface() ||
                         (*il)->get_interface() == sds->get_source_cap_interface())) {
                    (*il)->set_in_use_uuid(sds->get_source_uuid());
                    break;
                }
            }
        }

        lock.unlock();
        in_cb(interfaces);
        lock.lock();

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
        timetracker->RegisterTimer(2, NULL, 0, [this] (int) -> int {
            local_demand_locker lock(&dst_lock);
           
            lock.lock();
            auto d_pcv = probing_complete_vec;
            auto d_lcv = listing_complete_vec;
            auto d_bsv = broken_source_vec;

            completion_cleanup_id = -1;

            probing_complete_vec.clear();
            listing_complete_vec.clear();
            broken_source_vec.clear();
            lock.unlock();

            // Actually purge them outside of lockdown
            d_pcv.clear();
            d_lcv.clear();
            d_bsv.clear();

            return 0;
        });
    //fprintf(stderr, "debug - dst scheduling cleanup as %d\n", completion_cleanup_id);
}

void Datasourcetracker::NewConnection(std::shared_ptr<BufferHandlerGeneric> conn_handler) {
    dst_incoming_remote *incoming = new dst_incoming_remote(conn_handler, 
                [this] (dst_incoming_remote *i, std::string in_type, std::string in_def, 
                    uuid in_uuid, std::shared_ptr<BufferHandlerGeneric> in_handler) {
            in_handler->RemoveReadBufferInterface();
            open_remote_datasource(i, in_type, in_def, in_uuid, in_handler);
        });

    conn_handler->SetReadBufferInterface(incoming);
}

void Datasourcetracker::open_remote_datasource(dst_incoming_remote *incoming,
        const std::string& in_type, const std::string& in_definition, const uuid& in_uuid, 
        std::shared_ptr<BufferHandlerGeneric> in_handler) {
    SharedDatasource merge_target_device;
     
    local_locker lock(&dst_lock);

    // Look for an existing datasource with the same UUID
    for (auto p : *datasource_vec) {
        SharedDatasource d = std::static_pointer_cast<KisDatasource>(p);

        if (!d->get_source_builder()->get_remote_capable())
            continue;

        if (d->get_source_uuid() == in_uuid) {
            merge_target_device = d;
            break;
        }
    }

    if (merge_target_device != NULL) {
        if (merge_target_device->get_source_running()) {
            _MSG_ERROR("Incoming remote connection for source '{}' matches existing source '{}', "
                    "which is still running.  The running instance will be closed; make sure "
                    "that multiple remote captures are not running for the same source.",
                    in_uuid.UUID2String(), merge_target_device->get_source_name());
            merge_target_device->close_source();
        } else {
            _MSG_INFO("Matching new remote source '{}' with known source with UUID '{}'",
                    in_definition, in_uuid.UUID2String());
        }
                    
        // Explicitly unlock our mutex before running a thread
        lock.unlock();

        // Generate a detached thread for joining the ring buffer; it acts as a blocking
        // wait for the buffer to be filled
        incoming->handshake_rb(std::thread([this, merge_target_device, in_handler, 
                    in_definition]  {
                    merge_target_device->connect_remote(in_handler, in_definition, NULL);
                    calculate_source_hopping(merge_target_device);
                }));

        return;
    }

    // Otherwise look for a prototype that can handle it
    for (auto p : *proto_vec) {
        SharedDatasourceBuilder b = std::static_pointer_cast<KisDatasourceBuilder>(p);

        if (!b->get_remote_capable())
            continue;

        if (b->get_source_type() == in_type) {
            // Explicitly unlock the mutex before we fire the connection handler
            lock.unlock();

            // Make a data source from the builder
            SharedDatasource ds = b->build_datasource(b);
            ds->connect_remote(in_handler, in_definition,
                [this, ds](unsigned int, bool success, std::string msg) {
                    if (success)
                        merge_source(ds); 
                    else
                        broken_source_vec.push_back(ds);
                });

            return;
        }
    }

    _MSG_ERROR("Kismet could not find a datasource driver for incoming remote source "
            "'{}' defined as '{}'; make sure that Kismet was compiled with all the "
            "data source drivers and that any necessary plugins have been loaded.",
            in_type, in_definition);
    in_handler->ProtocolError();

}

// Basic DST worker for figuring out how many sources of the same type
// exist, and are hopping
class dst_chansplit_worker : public DST_Worker {
public:
    dst_chansplit_worker(Datasourcetracker *in_dst,
            std::shared_ptr<datasourcetracker_defaults> in_defaults, 
            SharedDatasource in_ds) {
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

        bool match_list = true;

        auto initial_channels = initial_ds->get_source_channels_vec();
        auto compare_channels = in_src->get_source_channels_vec();

        if (initial_channels->size() != compare_channels->size())
            return;

        for (auto first_chan : *initial_channels) {
            bool matched_cur_chan = false;

            for (auto comp_chan : *compare_channels) {
                if (GetTrackerValue<std::string>(first_chan) == 
                        GetTrackerValue<std::string>(comp_chan)) {
                    matched_cur_chan = true;
                    break;
                }
            }

            if (!matched_cur_chan) {
                match_list = false;
                break;
            }
        }

        if (match_list)
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

        _MSG_INFO("Splitting channels for interfaces using '{}' among {} interfaces",
                match_type, target_sources.size());

        int nintf = 0;
        for (auto ds : target_sources) {
            int offt_count = target_sources.size();

            auto ds_hopchans = (ds)->get_source_hop_vec();

            int ds_offt = (ds_hopchans->size() / offt_count) * nintf;

            double rate = defaults->get_hop_rate();

            if (ds->get_definition_opt("channel_hoprate") != "") {
                try {
                    rate = dst->string_to_rate(ds->get_definition_opt("channel_hoprate"), -1);
                } catch (const std::exception& e) {
                    _MSG_ERROR("Source '{}' could not parse channel_hoprate= option: {}, using default "
                            "channel rate.", ds->get_source_name(), e.what());
                    rate = -1;
                }
            }

            if (rate < 0) {
                rate = defaults->get_hop_rate();
            }

            ds->set_channel_hop(rate, ds_hopchans, defaults->get_random_channel_order(),
                    ds_offt, 0, NULL);

            nintf++;
        }

    }

protected:
    std::string match_type;

    Datasourcetracker *dst;

    SharedDatasource initial_ds;
    std::vector<SharedDatasource> target_sources;

    std::shared_ptr<datasourcetracker_defaults> defaults;

};

void Datasourcetracker::calculate_source_hopping(SharedDatasource in_ds) {
    if (!in_ds->get_definition_opt_bool("channel_hop", true)) {
        // Source doesn't hop regardless of defaults
        return;
    }

    // Turn on channel hopping if we do that
    if (config_defaults->get_hop() && in_ds->get_source_builder()->get_tune_capable()) {
        // Do we split sources?
        if (config_defaults->get_split_same_sources()) {
            dst_chansplit_worker worker(this, config_defaults, in_ds);
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

    for (auto x : dst_remote_complete_vec) {
        if (x == in_dead)
            return;
    }

    if (remote_complete_timer <= 0) {
        remote_complete_timer =
            timetracker->RegisterTimer(1, NULL, 0, 
                [this] (int) -> int {
                    local_locker lock(&dst_lock);

                    for (auto x : dst_remote_complete_vec) {
                        delete(x);
                    }

                    dst_remote_complete_vec.clear();

                    remote_complete_timer = 0;
                    return 0;
                });
    }

}


bool Datasourcetracker::Httpd_VerifyPath(const char *path, const char *method) {
    std::string stripped = Httpd_StripSuffix(path);

    if (strcmp(method, "POST") == 0) {
        if (stripped == "/datasource/add_source")
            return true;

        std::vector<std::string> tokenurl = StrTokenize(path, "/");

        if (tokenurl.size() < 5)
            return false;

        // /datasource/by-uuid/aaa-bbb-cc-dd/source.json 
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "by-uuid") {
                uuid u(tokenurl[3]);

                if (u.error)
                    return false;

                local_shared_locker lock(&dst_lock);

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

        return false;
    }

    if (strcmp(method, "GET") == 0) {
        
        if (!Httpd_CanSerialize(path))
            return false;

        std::vector<std::string> tokenurl = StrTokenize(path, "/");

        if (tokenurl.size() < 5)
            return false;

        // /datasource/by-uuid/aaa-bbb-cc-dd/source.json 
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "by-uuid") {
                uuid u(tokenurl[3]);

                if (u.error)
                    return false;

                {
                    local_shared_locker l(&dst_lock);
                    if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                        return false;
                }

                if (Httpd_StripSuffix(tokenurl[4]) == "source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "close_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "open_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "disable_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "enable_source")
                    return true;

                if (Httpd_StripSuffix(tokenurl[4]) == "pause_source")
                    return true;
                
                if (Httpd_StripSuffix(tokenurl[4]) == "resume_source")
                    return true;

                return false;
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

    std::string stripped = Httpd_StripSuffix(path);

    if (!Httpd_CanSerialize(path))
        return;


    std::vector<std::string> tokenurl = StrTokenize(path, "/");

    if (tokenurl.size() < 5) {
        return;
    }

    // /datasource/by-uuid/aaa-bbb-cc-dd/source.json 
    if (tokenurl[1] == "datasource") {
        if (tokenurl[2] == "by-uuid") {
            uuid u(tokenurl[3]);

            if (u.error) {
                return;
            }

            SharedDatasource ds;

            {
                local_shared_locker lock(&dst_lock);
                for (auto i : *datasource_vec) {
                    SharedDatasource dsi = std::static_pointer_cast<KisDatasource>(i);

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
                    stream << "Closing source " << ds->get_source_uuid().UUID2String();
                    return;
                } else {
                    stream << "Source already closed, disabling source " <<
                        ds->get_source_uuid().UUID2String();
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

            if (Httpd_StripSuffix(tokenurl[4]) == "pause_source") {
                if (!ds->get_source_paused()) {
                    _MSG("Pausing source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->set_source_paused(true);
                    stream << "Pausing source";
                    return;
                } else {
                    stream << "Source already paused";
                    connection->httpcode = 500;
                    return;
                }
            }

            if (Httpd_StripSuffix(tokenurl[4]) == "resume_source") {
                if (ds->get_source_paused()) {
                    _MSG("Resuming source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->set_source_paused(false);
                    stream << "Resuming source";
                    return;
                } else {
                    stream << "Source already running";
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
        concls->response_stream << "Invalid request, cannot serialize URL";
        concls->httpcode = 400;
        return MHD_YES;
    }

    // All the posts require login
    if (!httpd->HasValidSession(concls, true)) {
        return MHD_YES;
    }

    std::string stripped = Httpd_StripSuffix(concls->url);

    SharedStructured structdata;

    try {
        if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            throw std::runtime_error("unable to find POST data");
        }

        if (stripped == "/datasource/add_source") {
            // Locker for waiting for the open callback
            std::shared_ptr<conditional_locker<SharedDatasource> > cl(new conditional_locker<SharedDatasource>());

            SharedDatasource r;
            std::string error_reason;

            if (!structdata->hasKey("definition")) {
                throw std::runtime_error("POST data missing source definition");
            }

            cl->lock();

            bool cmd_complete_success = false;

            // Initiate the open
            open_datasource(structdata->getKeyAsString("definition"),
                    [&error_reason, cl, &cmd_complete_success](bool success, std::string reason, 
                        SharedDatasource ds) {

                        cmd_complete_success = success;

                        // Unlock the locker so we unblock below
                        if (success) {
                            cl->unlock(ds);
                        } else {
                            error_reason = reason;
                            cl->unlock(NULL);
                        }
                    });

            // Block until the open cmd unlocks us
            r = cl->block_until();

            if (cmd_complete_success) {
                Httpd_Serialize(concls->url, concls->response_stream, r);
                concls->httpcode = 200;
            } else {
                concls->response_stream << error_reason;
                concls->httpcode = 500;
            }

            return MHD_YES;
        } 

        // No single url we liked, split and look at the path
        std::vector<std::string> tokenurl = StrTokenize(concls->url, "/");

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
                local_shared_locker lock(&dst_lock);

                if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                    throw std::runtime_error("Could not find a source with that UUID");

                for (auto i : *datasource_vec) {
                    SharedDatasource dsi = std::static_pointer_cast<KisDatasource>(i);

                    if (dsi->get_source_uuid() == u) {
                        ds = dsi;
                        break;
                    }
                }

                if (ds == NULL) {
                    throw std::runtime_error("Could not find a source with that UUID");
                }
            }

            if (Httpd_StripSuffix(tokenurl[4]) == "set_channel") {
                if (structdata->hasKey("channel")) {
                    std::shared_ptr<conditional_locker<std::string> > cl(new conditional_locker<std::string>());
                    std::string ch = structdata->getKeyAsString("channel", "");

                    if (ch.length() == 0) {
                        throw std::runtime_error("Invalid channel, could not parse as string");
                    }

                    _MSG_INFO("Setting data source '{}' channel '{}'",
                            ds->get_source_name(), ch);

                    bool cmd_complete_success = false;

                    cl->lock();

                    // Initiate the channel set
                    ds->set_channel(ch, 0, 
                            [cl, &cmd_complete_success](unsigned int, bool success, 
                                std::string reason) {

                                cmd_complete_success = success;

                                cl->unlock(reason);
                            });

                    // Block until the open cmd unlocks us
                    std::string reason = cl->block_until();

                    if (cmd_complete_success) {
                        concls->response_stream << "Success";
                        concls->httpcode = 200;
                    } else {
                        concls->response_stream << reason;
                        concls->httpcode = 500;
                    }
                                
                    return MHD_YES;

                } else {
                    // We need at least a channels or a rate to kick into
                    // hopping mode
                    if (!structdata->hasKey("channels") &&
                            !structdata->hasKey("rate")) {
                        throw std::runtime_error("invalid hop command, expected channel, channels, or rate");
                    }

                    // Get the channels as a vector, default to the source 
                    // default if the CGI doesn't define them
                    SharedStructured chstruct;
                    std::vector<std::string> converted_channels;

                    if (structdata->hasKey("channels")) {
                        chstruct = structdata->getStructuredByKey("channels");
                        converted_channels = chstruct->getStringVec();
                    } else {
                        for (auto c : *(ds->get_source_hop_vec()))
                            converted_channels.push_back(GetTrackerValue<std::string>(c));
                    }

                    std::shared_ptr<conditional_locker<std::string> > cl(new conditional_locker<std::string>());

                    // Get the hop rate and the shuffle; default to the source
                    // state if we don't have them provided
                    double rate = 
                        structdata->getKeyAsNumber("rate", ds->get_source_hop_rate());

                    unsigned int shuffle = 
                        structdata->getKeyAsNumber("shuffle",
                                ds->get_source_hop_shuffle());

                    _MSG_INFO("Source '{}' setting new hop rate and channel pattern.",
                            ds->get_source_name());

                    bool cmd_complete_success = false;

                    cl->lock();

                    // Initiate the channel set
                    ds->set_channel_hop(rate, converted_channels, shuffle, 
                            ds->get_source_hop_offset(),
                            0, [cl, &cmd_complete_success](unsigned int, bool success, 
                                std::string reason) {

                                cmd_complete_success = success;

                                cl->unlock(reason);
                            });

                    // Block until the open cmd unlocks us
                    std::string reason = cl->block_until();

                    if (cmd_complete_success) {
                        concls->response_stream << "Success";
                        concls->httpcode = 200;
                    } else {
                        concls->response_stream << reason;
                        concls->httpcode = 500;
                    }

                    return MHD_YES;
                }
            } else if (Httpd_StripSuffix(tokenurl[4]) == "set_hop") {
                _MSG("Setting source '" + ds->get_source_name() + "' channel hopping", 
                        MSGFLAG_INFO);

                bool cmd_complete_success = false;
                std::shared_ptr<conditional_locker<std::string> > cl(new conditional_locker<std::string>());

                cl->lock();

                // Set it to channel hop using all the current hop attributes
                ds->set_channel_hop(ds->get_source_hop_rate(),
                        ds->get_source_hop_vec(),
                        ds->get_source_hop_shuffle(),
                        ds->get_source_hop_offset(), 0,
                        [cl, &cmd_complete_success](unsigned int, bool success, 
                            std::string reason) {

                            cmd_complete_success = success;

                            cl->unlock(reason);
                        });

                // Block until the open cmd unlocks us
                std::string reason = cl->block_until();

                if (cmd_complete_success) {
                    concls->response_stream << "Success";
                    concls->httpcode = 200;
                } else {
                    concls->response_stream << reason;
                    concls->httpcode = 500;
                }

                return MHD_YES;
            }
        }

        // Otherwise no URL path we liked
        concls->response_stream << "Invalid request, invalid URL";
        concls->httpcode = 400;
        return MHD_YES;
    
    } catch (const std::exception& e) {
        concls->response_stream << "Invalid request " << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    return MHD_YES;
}

double Datasourcetracker::string_to_rate(std::string in_str, double in_default) {
    double v, dv;

    std::vector<std::string> toks = StrTokenize(in_str, "/");

    if (toks.size() != 2)
        throw std::runtime_error("Expected [value]/sec or [value]/min or [value]/dwell");

    v = StringTo<double>(toks[0]);

    if (toks[1] == "sec") {
        return v;
    } else if (toks[1] == "dwell") {
        // Channel dwell is # of *seconds per hop* for very long hop intervals; so to get
        // hops per minute it's dwell seconds.  We convert to a double # of hops per minute,
        // then apply the formula below to turn that into the double value; simplified to:
        dv = 1.0f / v;

        return dv;
    } else if (toks[1] == "min") {
        // Channel hop is # of hops a second, timed in usec, so to get hops per
        // minute we get a minutes worth of usecs (60m), divide by the number
        // of hops per minute, then divide a second by that.
        // dv = (double) 1000000 / (double) ((double) (1000000 * 60) / (double) v);
        // simplified to:
        dv = v / 60.0f;

        return dv;
    } else {
        throw std::runtime_error("Expected [value]/sec or [value]/min");
    }
}

bool Datasourcetracker_Httpd_Pcap::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {

        // Total pcap of all data; we put it in 2 locations
        if (strcmp(path, "/pcap/all_packets.pcapng") == 0) 
            return true;

        if (strcmp(path, "/datasource/pcap/all_sources.pcapng") == 0)
            return true;

        // Alternately, per-source capture:
        // /datasource/pcap/by-uuid/aa-bb-cc-dd/aa-bb-cc-dd.pcapng

        std::vector<std::string> tokenurl = StrTokenize(path, "/");

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

                    if (datasourcetracker == NULL) {
                        datasourcetracker =
                            Globalreg::FetchMandatoryGlobalAs<Datasourcetracker>("DATASOURCETRACKER");
                    }

                    if (packetchain == NULL) {
                        std::shared_ptr<Packetchain> packetchain = 
                            Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");
                        pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");
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

int Datasourcetracker_Httpd_Pcap::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return MHD_YES;
    }

    auto streamtracker = Globalreg::FetchMandatoryGlobalAs<StreamTracker>("STREAMTRACKER");

    if (strcmp(url, "/pcap/all_packets.pcapng") == 0 ||
            strcmp(url, "/datasource/pcap/all_sources.pcapng") == 0) {
        if (!httpd->HasValidSession(connection)) {
            connection->httpcode = 503;
            return MHD_YES;
        }

        // At this point we're logged in and have an aux pointer for the
        // ringbuf aux; We can create our pcap ringbuf stream and attach it.
        // We need to close down the pcapringbuf during teardown.
        
        Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
            (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;
       
        auto *psrb = new Pcap_Stream_Packetchain(Globalreg::globalreg,
                saux->get_rbhandler(), NULL, NULL);

        saux->set_aux(psrb, 
            [psrb, streamtracker](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                streamtracker->remove_streamer(psrb->get_stream_id());
                if (aux->aux != NULL) {
                    delete (Kis_Net_Httpd_Buffer_Stream_Aux *) (aux->aux);
                }
            });

        streamtracker->register_streamer(psrb, "all_sources.pcapng",
                "pcapng", "httpd", "pcapng of all packets on all sources");

        return MHD_NO;
    }

    // Find per-uuid and make a filtering pcapng
    std::vector<std::string> tokenurl = StrTokenize(url, "/");

    if (tokenurl.size() < 6) {
        return MHD_YES;
    }

    if (tokenurl[1] == "datasource") {
        if (tokenurl[2] == "pcap") {
            if (tokenurl[3] == "by-uuid") {
                uuid u(tokenurl[4]);

                if (u.error) {
                    return MHD_YES;
                }

                datasourcetracker =
                    Globalreg::FetchMandatoryGlobalAs<Datasourcetracker>("DATASOURCETRACKER");

                std::shared_ptr<Packetchain> packetchain = 
                    Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");
                pack_comp_datasrc = packetchain->RegisterPacketComponent("KISDATASRC");

                SharedDatasource ds = datasourcetracker->find_datasource(u);

                if (ds == NULL)
                    return MHD_YES;

                if (!httpd->HasValidSession(connection)) {
                    connection->httpcode = 503;
                    return MHD_YES;
                }

                // Get the number of this source for fast compare
                unsigned int dsnum = ds->get_source_number();

                // Create the pcap stream and attach it to our ringbuf
                Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
                    (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;

                // Fetch the datasource component and compare *source numbers*, not
                // actual UUIDs - a UUID compare is expensive, a numeric compare is not!
                auto *psrb = new Pcap_Stream_Packetchain(Globalreg::globalreg,
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
                    [psrb, streamtracker](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                        streamtracker->remove_streamer(psrb->get_stream_id());
                        if (aux->aux != NULL) {
                            delete (Kis_Net_Httpd_Buffer_Stream_Aux *) (aux->aux);
                        }
                    });

                streamtracker->register_streamer(psrb, 
                        ds->get_source_name() + ".pcapng",
                        "pcapng", "httpd", 
                        "pcapng of " + ds->get_source_name() + " (" + 
                        ds->get_source_cap_interface());

                return MHD_NO;

            }
        }
    }

    return MHD_YES;
}

dst_incoming_remote::dst_incoming_remote(std::shared_ptr<BufferHandlerGeneric> in_rbufhandler,
        std::function<void (dst_incoming_remote *, std::string, std::string, 
            uuid, std::shared_ptr<BufferHandlerGeneric>)> in_cb) :
    KisExternalInterface() {
    
    cb = in_cb;

    connect_buffer(in_rbufhandler);

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
    // Kill the error timer
    timetracker->RemoveTimer(timerid);

    // Remove ourselves as a handler
    if (ringbuf_handler != NULL)
        ringbuf_handler->RemoveReadBufferInterface();

    // Wait for the thread to finish
    handshake_thread.join();
}

bool dst_incoming_remote::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) { if (KisExternalInterface::dispatch_rx_packet(c))
        return true;

    // Simple dispatch override, all we do is look for the new source
    if (c->command() == "KDSNEWSOURCE") {
        handle_packet_newsource(c->seqno(), c->content());
        return true;
    }

    return false;
}


void dst_incoming_remote::kill() {
    // Kill the error timer
    timetracker->RemoveTimer(timerid);

    close_external();

    std::shared_ptr<Datasourcetracker> datasourcetracker =
        Globalreg::FetchGlobalAs<Datasourcetracker>("DATASOURCETRACKER");

    if (datasourcetracker != NULL) 
        datasourcetracker->queue_dead_remote(this);
}

void dst_incoming_remote::handle_packet_newsource(uint32_t in_seqno, std::string in_content) {
    local_locker lock(ext_mutex);

    KismetDatasource::NewSource c;

    if (!c.ParseFromString(in_content)) {
        _MSG("Could not process incoming remote datsource announcement", MSGFLAG_ERROR);
        kill();

        return;
    }

    if (cb != NULL)
        cb(this, c.sourcetype(), c.definition(), c.uuid(), ringbuf_handler);

    // Zero out the rbuf handler so that it doesn't get closed
    ringbuf_handler.reset();

    kill();
}

void dst_incoming_remote::BufferError(std::string in_error) {
    _MSG("Incoming remote source failed: " + in_error, MSGFLAG_ERROR);
    kill();
    return;
}

