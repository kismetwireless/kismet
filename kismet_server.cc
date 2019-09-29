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

#define KISMET_SERVER

#include "version.h"

#include "backward_wrapper.h"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "getopt.h"
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include <string>
#include <vector>
#include <sstream>

#include <sys/resource.h>

#include "util.h"

#include "globalregistry.h"

#include "configfile.h"
#include "messagebus.h"

#include "plugintracker.h"

#include "kis_dlt_ppi.h"
#include "kis_dlt_radiotap.h"

#include "kis_dissector_ipdata.h"

#include "dlttracker.h"
#include "antennatracker.h"
#include "kis_datasource.h"
#include "datasourcetracker.h"
#include "datasource_pcapfile.h"
#include "datasource_kismetdb.h"
#include "datasource_linux_wifi.h"
#include "datasource_linux_bluetooth.h"
#include "datasource_osx_corewlan_wifi.h"
#include "datasource_rtl433.h"
#include "datasource_rtlamr.h"
#include "datasource_rtladsb.h"
#include "datasource_freaklabs_zigbee.h"
#include "datasource_nrf_mousejack.h"

#include "logtracker.h"
#include "kis_ppilogfile.h"
#include "kis_databaselogfile.h"
#include "kis_pcapnglogfile.h"

#include "timetracker.h"
#include "alertracker.h"

#include "kis_net_microhttpd.h"
#include "system_monitor.h"
#include "channeltracker2.h"
#include "kis_httpd_websession.h"
#include "kis_httpd_registry.h"
#include "messagebus_restclient.h"
#include "streamtracker.h"
#include "eventbus.h"

#include "gpstracker.h"

#include "devicetracker.h"
#include "devicetracker_httpd_pcap.h"
#include "phy_80211.h"
#include "phy_rtl433.h"
#include "phy_rtlamr.h"
#include "phy_rtladsb.h"
#include "phy_zwave.h"
#include "phy_bluetooth.h"
#include "phy_uav_drone.h"
#include "phy_nrf_mousejack.h"

#include "ipc_remote2.h"
#include "manuf.h"
#include "entrytracker.h"
#include "json_adapter.h"

#ifndef exec_name
char *exec_name;
#endif

// Daemonize?
int daemonize = 0;

// Plugins?
int plugins = 1;

// One of our few globals in this file
int glob_linewrap = 1;
int glob_silent = 0;

// Message clients that are attached at the master level
// Smart standard out client that understands the silence options
class SmartStdoutMessageClient : public message_client {
public:
    SmartStdoutMessageClient(global_registry *in_globalreg, void *in_aux) :
        message_client(in_globalreg, in_aux) { }
    virtual ~SmartStdoutMessageClient() { }
    void process_message(std::string in_msg, int in_flags);
};

void SmartStdoutMessageClient::process_message(std::string in_msg, int in_flags) {
    if (glob_silent)
        return;

    if ((in_flags & MSGFLAG_DEBUG)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", in_line_wrap("DEBUG: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "DEBUG: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_LOCAL)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", in_line_wrap("LOCAL: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "LOCAL: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_INFO)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", in_line_wrap("INFO: " + in_msg, 6, 75).c_str());
        else
            fprintf(stdout, "INFO: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_ERROR)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", in_line_wrap("ERROR: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "ERROR: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_ALERT)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", in_line_wrap("ALERT: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "ALERT: %s\n", in_msg.c_str());
    } else if (in_flags & MSGFLAG_FATAL) {
        if (glob_linewrap)
            fprintf(stderr, "%s", in_line_wrap("FATAL: " + in_msg, 7, 75).c_str());
        else
            fprintf(stderr, "FATAL: %s\n", in_msg.c_str());
    }

    fflush(stdout);
    fflush(stderr);
    
    return;
}

// Queue of fatal alert conditions to spew back out at the end
class FatalQueueMessageClient : public message_client {
public:
    FatalQueueMessageClient(global_registry *in_globalreg, void *in_aux) :
        message_client(in_globalreg, in_aux) { }
    virtual ~FatalQueueMessageClient() { }
    void process_message(std::string in_msg, int in_flags);
    void DumpFatals();
protected:
    std::vector<std::string> fatalqueue;
};

void FatalQueueMessageClient::process_message(std::string in_msg, int in_flags) {
    // Queue PRINT forced errors differently than fatal conditions
    if (in_flags & MSGFLAG_PRINT) {
        fatalqueue.push_back("ERROR: " + in_msg);
    } else if (in_flags & MSGFLAG_FATAL) {
        fatalqueue.push_back("FATAL: " + in_msg);
    }

    if (fatalqueue.size() > 50) {
        fatalqueue.erase(fatalqueue.begin(), fatalqueue.begin() + (fatalqueue.size() - 50));
    }
}

void FatalQueueMessageClient::DumpFatals() {
    for (unsigned int x = 0; x < fatalqueue.size(); x++) {
        if (glob_linewrap)
            fprintf(stderr, "%s", in_line_wrap(fatalqueue[x], 7, 80).c_str());
        else
            fprintf(stderr, "%s\n", fatalqueue[x].c_str());
    }
}

const char *config_base = "kismet.conf";
const char *pid_base = "kismet_server.pid";

// This needs to be a global but nothing outside of this main file will
// use it, so we don't have to worry much about putting it in the globalreg.
FatalQueueMessageClient *fqmescli = NULL;

// Some globals for command line options
char *configfile = NULL;

int packnum = 0, localdropnum = 0;

// Ultimate registry of global components
global_registry *globalregistry = NULL;

void SpindownKismet(std::shared_ptr<pollable_tracker> pollabletracker) {
    // Shut down the webserver first
    auto httpd = Globalreg::FetchGlobalAs<kis_net_httpd>("HTTPD_SERVER");
    if (httpd != NULL)
        httpd->stop_httpd();

    auto devicetracker =
        Globalreg::FetchGlobalAs<device_tracker>("DEVICETRACKER");
    if (devicetracker != NULL) {
        devicetracker->store_all_devices();
        devicetracker->databaselog_write_devices();
    }

    // shutdown everything
    globalregistry->Shutdown_Deferred();
    globalregistry->spindown = 1;

    // Start a short shutdown cycle for 2 seconds
    if (daemonize == 0)
        fprintf(stderr, "\n*** KISMET IS SHUTTING DOWN ***\n");

    if (pollabletracker != nullptr)
        pollabletracker->select_loop(true);

    // Be noisy
    if (globalregistry->fatal_condition) {
        fprintf(stderr, "\n*** KISMET HAS ENCOUNTERED A FATAL ERROR AND CANNOT "
                "CONTINUE.  ***\n");
    }

    fprintf(stderr, "Shutting down plugins...\n");
    std::shared_ptr<plugin_tracker> plugintracker =
        Globalreg::FetchGlobalAs<plugin_tracker>(globalregistry, "PLUGINTRACKER");
    if (plugintracker != NULL)
        plugintracker->shutdown_plugins();

    // Dump fatal errors again
    if (fqmescli != NULL) //  && globalregistry->fatal_condition) 
        fqmescli->DumpFatals();

    if (daemonize == 0) {
        fprintf(stderr, "WARNING: Kismet changes the configuration of network devices.\n"
                "         In most cases you will need to restart networking for\n"
                "         your interface (varies per distribution/OS, but \n"
                "         typically one of:\n"
                "         sudo service networking restart\n"
                "         sudo /etc/init.d/networking restart\n"
                "         or\n"
                "         nmcli device set [device] managed true\n"
                "\n");

        fprintf(stderr, "Kismet exiting.\n");
    }

    globalregistry->Deletelifetime_globals();

    globalregistry->complete = true;

    // Send a kick to unlock our service thread
    kill(getpid(), SIGTERM);

    if (globalregistry->signal_service_thread.joinable())
        globalregistry->signal_service_thread.join();

    exit(globalregistry->fatal_condition ? 1 : 0);
}

int usage(char *argv) {
    printf("usage: %s [OPTION]\n", argv);
    printf("Nearly all of these options are run-time overrides for values in the\n"
           "kismet.conf configuration file.  Permanent changes should be made to\n"
           "the configuration file.\n");

    printf(" *** Generic Options ***\n");
    printf(" -v, --version                Show version\n"
           "     --no-console-wrapper     Disable server console wrapper\n"
           "     --no-ncurses-wrapper     Disable server console wrapper\n"
           "     --debug                  Disable the console wrapper and the crash\n"
           "                              handling functions, for debugging\n"
           " -f, --config-file <file>     Use alternate configuration file\n"
           "     --no-line-wrap           Turn of linewrapping of output\n"
           "                              (for grep, speed, etc)\n"
           " -s, --silent                 Turn off stdout output after setup phase\n"
           "     --daemonize              Spawn detatched in the background\n"
           "     --no-plugins             Do not load plugins\n"
           "     --homedir <path>         Use an alternate path as the home \n"
           "                               directory instead of the user entry\n"
           "     --confdir <path>         Use an alternate path as the base \n"
           "                               config directory instead of the default \n"
           "                               set at compile time\n"
           "     --datadir <path>         Use an alternate path as the data\n"
           "                               directory instead of the default set at \n"
           "                               compile time.\n"
           );

    log_tracker::usage(argv);

    for (std::vector<global_registry::usage_func>::iterator i = 
            globalregistry->usage_func_vec.begin();
            i != globalregistry->usage_func_vec.end(); ++i) {
        (*i)(argv);
    }

    exit(1);
}

// Libbackward termination handler
std::mutex backward_dump_mutex;
void TerminationHandler() {
    signal(SIGKILL, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);

    backward_dump_mutex.lock();

    std::exception_ptr exc = std::current_exception();
    std::exception last_exception;

    try {
        if (exc) {
            std::rethrow_exception(exc);
        }
    } catch(const std::exception& e) {
        last_exception = e;
        std::cout << "Uncaught exception \"" << e.what() << "\"\n";
    }

#ifndef DISABLE_BACKWARD
    using namespace backward;
    StackTrace st; st.load_here(32);
    Printer p; p.print(st);
#endif

    std::cout << "Uncaught exception \"" << last_exception.what() << "\"\n";

    backward_dump_mutex.unlock();

    std::abort();
}

// Load a UUID
void Load_Kismet_UUID(global_registry *globalreg) {
    // Look for a global override
    uuid confuuid(globalreg->kismet_config->fetch_opt("server_uuid"));

    if (!confuuid.error) {
        _MSG("Setting server UUID " + confuuid.uuid_to_string() + " from kismet.conf "
                "(or included file)", MSGFLAG_INFO);

        globalreg->server_uuid = confuuid;
        globalreg->server_uuid_hash = adler32_checksum((const char *) confuuid.uuid_block, 16);
        return;
    }

    // Make a custom config
    std::string conf_dir_path_raw = globalreg->kismet_config->fetch_opt("configdir");
    std::string config_dir_path = 
        globalreg->kismet_config->expand_log_path(conf_dir_path_raw, "", "", 0, 1);

    std::string uuidconfpath = config_dir_path + "/" + "kismet_server_id.conf";

    config_file uuidconf(globalreg);
    uuidconf.parse_config(uuidconfpath.c_str());

    // Look for a saved uuid
    confuuid = uuid(uuidconf.fetch_opt("server_uuid"));
    if (confuuid.error) {
        confuuid.generate_time_uuid((uint8_t *) "KISMET");
        _MSG("Generated server UUID " + confuuid.uuid_to_string() + " and storing in " +
                uuidconfpath, MSGFLAG_INFO);
        uuidconf.set_opt("server_uuid", confuuid.uuid_to_string(), true);
        uuidconf.save_config(uuidconfpath.c_str());
    }

    _MSG_INFO("Setting server UUID {}", confuuid.uuid_to_string());
    globalreg->server_uuid = confuuid;
    globalreg->server_uuid_hash = adler32_checksum((const char *) confuuid.uuid_block, 16);
}

static sigset_t core_signal_mask;
void signal_thread_handler() {
    int sig_caught;
    int r;

    while (!Globalreg::globalreg->complete) {
        r = sigwait(&core_signal_mask, &sig_caught);

        if (r != 0) {
            fprintf(stderr, "ERROR - Failure waiting for signal in signal service thread: %s\n", strerror(errno));
            Globalreg::globalreg->fatal_condition = true;
            Globalreg::globalreg->spindown = true;
            break;
        }

        switch (sig_caught) {
            case SIGSEGV:
                // Print termination if we can and bail
                TerminationHandler();
                exit(-11);
                break;

            case SIGINT:
            case SIGTERM:
            case SIGHUP:
            case SIGQUIT:
                // All of these are indicators it's time to shut down
                Globalreg::globalreg->spindown = true;
                break;

            case SIGPIPE:
                // We ignore sigpipes
                break;

            case SIGCHLD:
                // Flag that we need to do a waitpid to reap child processes
                Globalreg::globalreg->reap_child_procs = true;
                break;
        }
    }

    Globalreg::globalreg->fatal_condition = true;
    Globalreg::globalreg->spindown = true;
    Globalreg::globalreg->complete = true;
}

int main(int argc, char *argv[], char *envp[]) {
    exec_name = argv[0];
    std::string configfilename;
    config_file *conf;
    int option_idx = 0;
    global_registry *globalreg;

    bool debug_mode = false;

    static struct option wrapper_longopt[] = {
        { "no-ncurses-wrapper", no_argument, 0, 'w' },
        { "no-console-wrapper", no_argument, 0, 'w' },
        { "show-admin-password", no_argument, 0, 'p' },
        { "daemonize", no_argument, 0, 'D' },
        { "debug", no_argument, 0, 'd' },
        { 0, 0, 0, 0 }
    };

    // Reset the options index
    optind = 0;
    option_idx = 0;
    opterr = 0;

    bool wrapper = true;
    bool show_pass = false;

    while (1) {
        int r = getopt_long(argc, argv, "-", wrapper_longopt, &option_idx);
        if (r < 0) break;

        if (r == 'w') {
            wrapper = false; 
            glob_linewrap = false;
        } else if (r == 'p') {
            show_pass = true;
        } else if (r == 'd') {
            debug_mode = true;
            wrapper = false;
            glob_linewrap = false;
        } else if (r == 'D') {
            wrapper = false;
            glob_linewrap = false;
        }
    }

    optind = 0;
    option_idx = 0;

    // Timer for silence
    int local_silent = 0;

    // Set a backtrace on C++ terminate errors
    if (!debug_mode) {
#ifndef DISABLE_BACKWARD
        backward::SignalHandling sh;

        // Catch C++ exceptions and print a stacktrace
        std::set_terminate(&TerminationHandler);
#endif
        /*
        signal(SIGSEGV, SegVHandler);
        */
    }

    // Build the globalregistry
    Globalreg::globalreg = new global_registry;
    globalregistry = Globalreg::globalreg;
    globalreg = globalregistry;

    // Block all signals across all threads, then set up a signal handling service thread
    // to deal with them
    sigemptyset(&core_signal_mask);

    // Don't mask int and quit if we're in debug mode
    if (!debug_mode) {
        sigaddset(&core_signal_mask, SIGINT);
        sigaddset(&core_signal_mask, SIGQUIT);
    }
    
    sigaddset(&core_signal_mask, SIGTERM);
    sigaddset(&core_signal_mask, SIGHUP);
    sigaddset(&core_signal_mask, SIGQUIT);
    sigaddset(&core_signal_mask, SIGCHLD);
    sigaddset(&core_signal_mask, SIGSEGV);
    sigaddset(&core_signal_mask, SIGPIPE);

    // Set thread mask for all new threads
    pthread_sigmask(SIG_BLOCK, &core_signal_mask, nullptr);

    // Launch signal catching thread that bypasses the block
    Globalreg::globalreg->signal_service_thread = std::thread(signal_thread_handler);

    // Fill in base globalreg elements
    globalregistry->version_major = VERSION_MAJOR;
    globalregistry->version_minor = VERSION_MINOR;
    globalregistry->version_tiny = VERSION_TINY;
    globalregistry->version_git_rev = VERSION_GIT_COMMIT;
    globalregistry->build_date = VERSION_BUILD_TIME;

    // Copy for modules
    globalregistry->argc = argc;
    globalregistry->argv = argv;
    globalregistry->envp = envp;

    // Set up usage functions
    globalregistry->RegisterUsageFunc(device_tracker::usage);

    const int nlwc = globalregistry->getopt_long_num++;
    const int dwc = globalregistry->getopt_long_num++;
    const int npwc = globalregistry->getopt_long_num++;
    const int hdwc = globalregistry->getopt_long_num++;
    const int cdwc = globalregistry->getopt_long_num++;
    const int ddwc = globalregistry->getopt_long_num++;

    // Standard getopt parse run
    static struct option main_longopt[] = {
        { "version", no_argument, 0, 'v' },
        { "config-file", required_argument, 0, 'f' },
        { "no-line-wrap", no_argument, 0, nlwc },
        { "silent", no_argument, 0, 's' },
        { "help", no_argument, 0, 'h' },
        { "daemonize", no_argument, 0, dwc },
        { "no-plugins", no_argument, 0, npwc },
        { "homedir", required_argument, 0, hdwc },
        { "confdir", required_argument, 0, cdwc },
        { "datadir", required_argument, 0, ddwc },
        { 0, 0, 0, 0 }
    };

    // Reset the options index
    optind = 0;
    option_idx = 0;

    // Turn off the getopt error reporting
    opterr = 0;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-f:sp:hv", 
                            main_longopt, &option_idx);
        if (r < 0) break;

        if (r == 'v') {
            printf("Kismet %s-%s-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
            exit(1);
        } else if (r == 'h') {
            usage(argv[0]);
            exit(1);
        } else if (r == 'f') {
            configfilename = std::string(optarg);
        } else if (r == nlwc) {
            glob_linewrap = 0;
        } else if (r == 's') {
            local_silent = 1;
        } else if (r == dwc) {
            daemonize = 1;
            local_silent = 1;
        } else if (r == npwc) {
            plugins = 0;
        } else if (r == hdwc) {
            globalregistry->homepath = std::string(optarg);
        } else if (r == cdwc) {
            globalregistry->etc_dir = std::string(optarg);
        } else if (r == ddwc) {
            globalregistry->data_dir = std::string(optarg);
        }
    }

    if (daemonize) {
        int pid = fork();
        if (pid < 0) {
            fprintf(stderr, "FATAL: Unable to fork child process: %s\n",
              strerror(errno));
            exit(1);
        } else if (pid > 0) {
            fprintf(stderr, "Silencing output and entering daemon mode...\n");
            exit(0);
        }
    }

    // First order - create our message bus and our client for outputting
    message_bus::create_messagebus(globalregistry);

    // Create a smart stdout client and allocate the fatal message client, 
    // add them to the messagebus
    SmartStdoutMessageClient *smartmsgcli = 
        new SmartStdoutMessageClient(globalregistry, NULL);
    fqmescli = new FatalQueueMessageClient(globalregistry, NULL);

    // Register the fatal queue with fatal and error messages
    globalregistry->messagebus->register_client(fqmescli, MSGFLAG_FATAL | MSGFLAG_ERROR);
    // Register the smart msg printer for everything
    globalregistry->messagebus->register_client(smartmsgcli, MSGFLAG_ALL);

	// Create the event bus
	event_bus::create_eventbus();

    // We need to create the pollable system near the top of execution as well
    auto pollabletracker(pollable_tracker::create_pollabletracker());

    // Open, initial parse, and assign the config file
    if (configfilename == "") {
        configfilename = fmt::format("{}/{}",
                getenv("KISMET_CONF") != NULL ? getenv("KISMET_CONF") : SYSCONF_LOC,
                config_base);
    }

    conf = new config_file(globalregistry);
    if (conf->parse_config(configfilename) < 0) {
        exit(1);
    }
    globalregistry->kismet_config = conf;

    struct stat fstat;
    std::string configdir;

    if (conf->fetch_opt("configdir") != "") {
        configdir = conf->expand_log_path(conf->fetch_opt("configdir"), "", "", 0, 1);
    } else {
        _MSG("No 'configdir' option in the config file; make sure that the "
                "Kismet config files are installed and up to date.", MSGFLAG_FATAL);
        SpindownKismet(pollabletracker);
    }

    auto etcdir = 
        globalreg->kismet_config->expand_log_path("%E", "", "", 0, 1);
    setenv("KISMET_ETC", etcdir.c_str(), 1);

    if (stat(configdir.c_str(), &fstat) == -1) {
        _MSG_INFO("Local config and cache directory '{}' does not exist; creating it.", configdir);
        if (mkdir(configdir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
            _MSG_FATAL("Could not create config and cache directory '{}': {}",
                    configdir, strerror(errno));
            SpindownKismet(pollabletracker);
        }
    } else if (! S_ISDIR(fstat.st_mode)) {
        _MSG_FATAL("Local config and cache directory '{}' exists, but is a file (or otherwise not "
                "a directory)", configdir);
        SpindownKismet(pollabletracker);
    }

    // Set a terminal margin via raw ncurses code
    if (wrapper) {
        // Direct ansi calls to set the top margin and invert colors
        std::string banner_ansi = "\u001b[2J\u001b[2;r\u001b[1m\u001b[7m";
        std::string banner = "KISMET - Point your browser to http://localhost:2501 (or the address of this system) "
            "for the Kismet UI";
        std::string banner_tail_ansi = "\u001b[0m";

        // Print the banner and ascii tail to set a top margin
        printf("%s%s%s\n", banner_ansi.c_str(), banner.c_str(), banner_tail_ansi.c_str());
    }

    Load_Kismet_UUID(globalregistry);

    // Set up ulimits if we define any
    std::string limits = globalregistry->kismet_config->fetch_opt("ulimit_mbytes");
    if (limits != "") {
        long limitb;
        if (sscanf(limits.c_str(), "%ld", &limitb) != 1) {
            fprintf(stderr, "WARNING:  Could not parse byte value from ulimit_mbytes\n");
        } else {
            limitb = limitb * 1024 * 1024;

            struct rlimit limit;
            limit.rlim_max = limitb;
            limit.rlim_cur = limitb;

            if (setrlimit(RLIMIT_DATA, &limit) != 0) {
                fprintf(stderr, "WARNING:  Could not set memory limit to %sMb: %s\n",
                        limits.c_str(), strerror(errno));
            } else {
                fprintf(stderr, "INFO: Set Kismet memory limit to %sMb\n", limits.c_str());
            }
        }
    }

    // Make the timetracker
    auto timetracker = time_tracker::create_timetracker();

    // HTTP BLOCK
    // Create the HTTPD server, it needs to exist before most things
    kis_net_httpd::create_httpd();

    if (globalregistry->fatal_condition) 
        SpindownKismet(pollabletracker);

    // Allocate some other critical stuff like the entry tracker and the
    // serializers
    std::shared_ptr<entry_tracker> entrytracker =
        entry_tracker::create_entrytracker(Globalreg::globalreg);

    // Create the manuf db
    globalregistry->manufdb = new kis_manuf();
    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Base serializers
    entrytracker->register_serializer("json", std::make_shared<json_adapter::serializer>());
    entrytracker->register_serializer("ekjson", std::make_shared<ek_json_adapter::serializer>());
    entrytracker->register_serializer("prettyjson", std::make_shared<pretty_json_adapter::serializer>());
    entrytracker->register_serializer("storagejson", std::make_shared<storage_json_adapter::serializer>());

    entrytracker->register_serializer("jcmd", std::make_shared<json_adapter::serializer>());
    entrytracker->register_serializer("cmd", std::make_shared<json_adapter::serializer>());

    if (daemonize) {
        // remove messagebus clients so we stop printing
        globalregistry->messagebus->remove_client(fqmescli);
        globalregistry->messagebus->remove_client(smartmsgcli);
    }

    if (conf->fetch_opt("servername") == "") {
        char hostname[64];
        if (gethostname(hostname, 64) < 0)
            globalregistry->servername = "Kismet";
        else
            globalregistry->servername = std::string(hostname);
    } else {
        globalregistry->servername = munge_to_printable(conf->fetch_opt("servername"));
    }

    // Create the IPC handler
    ipc_remote_v2_tracker::create_ipcremote(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the stream tracking
    stream_tracker::create_streamtracker(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add the messagebus REST interface
    rest_message_client::create_messageclient(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add login session
    kis_httpd_websession::create_websession();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add module registry
    kis_httpd_registry::create_http_registry(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the packet chain
    packet_chain::create_packetchain();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the DLT tracker
    auto dlttracker = dlt_tracker::create_dltt();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create antenna mapper
    auto anttracker = Antennatracker::create_at();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add the datasource tracker
    auto datasourcetracker = datasource_tracker::create_dst();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the alert tracker
    auto alertracker = alert_tracker::create_alertracker();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the device tracker
    auto devicetracker = 
        device_tracker::create_device_tracker(globalregistry);

    // Create the pcap tracker
    auto devicetracker_pcap =
        std::make_shared<device_tracker_httpd_pcap>();

    // Add channel tracking
    channel_tracker_v2::create_channeltracker(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Register the DLT handlers
    kis_dlt_ppi::create_dlt();
    kis_dlt_radiotap::create_dlt();

    new kis_dissector_ip_data(globalregistry);

    // Register the base PHYs
    devicetracker->register_phy_handler(new kis_80211_phy(globalregistry));
    devicetracker->register_phy_handler(new Kis_RTL433_Phy(globalregistry));
    devicetracker->register_phy_handler(new Kis_Zwave_Phy(globalregistry));
    devicetracker->register_phy_handler(new Kis_Bluetooth_Phy(globalregistry));
    devicetracker->register_phy_handler(new Kis_UAV_Phy(globalregistry));
    devicetracker->register_phy_handler(new Kis_Mousejack_Phy(globalregistry));
    devicetracker->register_phy_handler(new Kis_RTLAMR_Phy(globalregistry));
    devicetracker->register_phy_handler(new kis_rtladsb_phy(globalregistry));

    if (globalregistry->fatal_condition) 
        SpindownKismet(pollabletracker);

    // Add the datasources
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_pcapfile_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_kismetdb_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_linux_wifi_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_linux_bluetooth_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_osx_corewlan_wifi_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_rtl433_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new DatasourceRtl433MqttBuilder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_rtlamr_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new DatasourceRtlamrMqttBuilder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_rtladsb_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new DatasourceRtladsbMqttBuilder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_freaklabs_zigbee_builder()));
    datasourcetracker->register_datasource(shared_datasource_builder(new datasource_nrf_mousejack_builder()));

    // Create the database logger as a global because it's a special case
    kis_database_logfile::create_kisdatabaselog();

    auto logtracker = 
        log_tracker::create_logtracker();

    logtracker->register_log(shared_log_builder(new ppi_logfile_builder()));
    logtracker->register_log(shared_log_builder(new kis_database_logfile_builder()));
    logtracker->register_log(shared_log_builder(new pcapng_logfile_builder()));

    std::shared_ptr<plugin_tracker> plugintracker;

    // Start the plugin handler
    if (plugins) {
        plugintracker = plugin_tracker::create_plugintracker(globalregistry);
    } else {
        globalregistry->messagebus->inject_message(
            "Plugins disabled on the command line, plugins will NOT be loaded...",
            MSGFLAG_INFO);
    }


    // Process plugins and activate them
    if (plugintracker != nullptr) {
        plugintracker->scan_plugins();
        plugintracker->activate_plugins();

        if (globalregistry->fatal_condition) {
            _MSG_FATAL("Failure activating Kismet plugins, make sure that all your plugins "
                    "are built against the same version of Kismet.");
            SpindownKismet(pollabletracker);
        }
    }

    // Create the GPS components
    gps_tracker::create_gpsmanager();

    // Add system monitor 
    Systemmonitor::create_systemmonitor();

    // Start up any code that needs everything to be loaded
    globalregistry->Start_Deferred();

    // Set the global silence now that we're set up
    glob_silent = local_silent;

    // Finalize any plugins which were waiting for other code to load
    plugintracker->finalize_plugins();

    // We can't call this as a deferred because we don't want to mix
    devicetracker->load_devices();

    // Complain about running as root
    if (getuid() == 0) {
        alertracker->define_alert("ROOTUSER", sat_second, 1, sat_second, 1);
        auto userref = alertracker->activate_configured_alert("ROOTUSER",
                "Kismet is running as root; this is less secure than running Kismet "
                "as an unprivileged user and installing it as suidroot.  Please consult "
                "the Kismet README for more information about securely installing Kismet. "
                "If you're starting Kismet on boot via systemd, be sure to use "
                "'systemctl edit kismet.service' to configure the user.");
        alertracker->raise_alert(userref, NULL, mac_addr(), mac_addr(), mac_addr(), mac_addr(), "",
                "Kismet is running as root; this is less secure.  If you are running "
                "Kismet at boot via systemd, make sure to use `systemctl edit kismet.service` to "
                "change the user.  For more information, see the Kismet README for setting up "
                "Kismet with minimal privileges.");
    }
    
    _MSG("Starting Kismet web server...", MSGFLAG_INFO);
    Globalreg::fetch_mandatory_global_as<kis_net_httpd>()->start_httpd();

    // Independent time and select threads, which has had problems with timing conflicts
    timetracker->SpawnTimetrackerThread();
    pollabletracker->select_loop(false);

    SpindownKismet(pollabletracker);
}

