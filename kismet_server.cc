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
class SmartStdoutMessageClient : public MessageClient {
public:
    SmartStdoutMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
        MessageClient(in_globalreg, in_aux) { }
    virtual ~SmartStdoutMessageClient() { }
    void ProcessMessage(std::string in_msg, int in_flags);
};

void SmartStdoutMessageClient::ProcessMessage(std::string in_msg, int in_flags) {
    if (glob_silent)
        return;

    if ((in_flags & MSGFLAG_DEBUG)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", InLineWrap("DEBUG: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "DEBUG: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_LOCAL)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", InLineWrap("LOCAL: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "LOCAL: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_INFO)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", InLineWrap("INFO: " + in_msg, 6, 75).c_str());
        else
            fprintf(stdout, "INFO: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_ERROR)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", InLineWrap("ERROR: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "ERROR: %s\n", in_msg.c_str());
    } else if ((in_flags & MSGFLAG_ALERT)) {
        if (glob_linewrap)
            fprintf(stdout, "%s", InLineWrap("ALERT: " + in_msg, 7, 75).c_str());
        else
            fprintf(stdout, "ALERT: %s\n", in_msg.c_str());
    } else if (in_flags & MSGFLAG_FATAL) {
        if (glob_linewrap)
            fprintf(stderr, "%s", InLineWrap("FATAL: " + in_msg, 7, 75).c_str());
        else
            fprintf(stderr, "FATAL: %s\n", in_msg.c_str());
    }

    fflush(stdout);
    fflush(stderr);
    
    return;
}

// Queue of fatal alert conditions to spew back out at the end
class FatalQueueMessageClient : public MessageClient {
public:
    FatalQueueMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
        MessageClient(in_globalreg, in_aux) { }
    virtual ~FatalQueueMessageClient() { }
    void ProcessMessage(std::string in_msg, int in_flags);
    void DumpFatals();
protected:
    std::vector<std::string> fatalqueue;
};

void FatalQueueMessageClient::ProcessMessage(std::string in_msg, int in_flags) {
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
            fprintf(stderr, "%s", InLineWrap(fatalqueue[x], 7, 80).c_str());
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
GlobalRegistry *globalregistry = NULL;

void SpindownKismet(std::shared_ptr<PollableTracker> pollabletracker) {
    // Eat the child signal handler
    signal(SIGCHLD, SIG_DFL);

    // Shut down the webserver first
    auto httpd = Globalreg::FetchGlobalAs<Kis_Net_Httpd>("HTTPD_SERVER");
    if (httpd != NULL)
        httpd->StopHttpd();

    auto devicetracker =
        Globalreg::FetchGlobalAs<Devicetracker>("DEVICETRACKER");
    if (devicetracker != NULL) {
        devicetracker->store_all_devices();
        devicetracker->databaselog_write_devices();
    }

    // Shutdown everything
    globalregistry->Shutdown_Deferred();
    globalregistry->spindown = 1;

    // Start a short shutdown cycle for 2 seconds
    if (daemonize == 0)
        fprintf(stderr, "\n*** KISMET IS SHUTTING DOWN ***\n");

    if (pollabletracker != nullptr)
        pollabletracker->Selectloop(true);

    // Be noisy
    if (globalregistry->fatal_condition) {
        fprintf(stderr, "\n*** KISMET HAS ENCOUNTERED A FATAL ERROR AND CANNOT "
                "CONTINUE.  ***\n");
    }

    fprintf(stderr, "Shutting down plugins...\n");
    std::shared_ptr<Plugintracker> plugintracker =
        Globalreg::FetchGlobalAs<Plugintracker>(globalregistry, "PLUGINTRACKER");
    if (plugintracker != NULL)
        plugintracker->ShutdownPlugins();

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

    globalregistry->DeleteLifetimeGlobals();

    exit(globalregistry->fatal_condition ? 1 : 0);
}


// Catch our interrupt
void CatchShutdown(int sig) {
    if (sig == 0) {
        kill(getpid(), SIGTERM);
        return;
    }

    globalregistry->spindown = 1;

    return;
}

void CatchChild(int sig) {
    int status;
    pid_t pid;

    sigset_t mask, oldmask;

    sigemptyset(&mask);
    sigemptyset(&oldmask);

    sigaddset(&mask, SIGCHLD);

    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    // Only process signals if we have room to
    if (globalregistry->sigchild_vec_pos < 1024) {
        while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
            globalregistry->sigchild_vec[globalregistry->sigchild_vec_pos++] = pid;
        }
    }

    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
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

    LogTracker::Usage(argv);

    for (std::vector<GlobalRegistry::usage_func>::iterator i = 
            globalregistry->usage_func_vec.begin();
            i != globalregistry->usage_func_vec.end(); ++i) {
        (*i)(argv);
    }

    exit(1);
}

void TerminationHandler() {
    signal(SIGKILL, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);

    std::exception_ptr exc = std::current_exception();

    try {
        if (exc) {
            std::rethrow_exception(exc);
        }
    } catch(const std::exception& e) {
        std::cout << "Uncaught exception \"" << e.what() << "\"\n";
    }

#ifndef DISABLE_BACKWARD
    using namespace backward;
    StackTrace st; st.load_here(32);
    Printer p; p.print(st);
#endif

    std::abort();
}

void SegVHandler(int sig __attribute__((unused))) {
    signal(SIGKILL, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);

    exit(-11);
}

// Load a UUID
void Load_Kismet_UUID(GlobalRegistry *globalreg) {
    // Look for a global override
    uuid confuuid(globalreg->kismet_config->FetchOpt("server_uuid"));

    if (!confuuid.error) {
        _MSG("Setting server UUID " + confuuid.UUID2String() + " from kismet.conf "
                "(or included file)", MSGFLAG_INFO);

        globalreg->server_uuid = confuuid;
        globalreg->server_uuid_hash = Adler32Checksum((const char *) confuuid.uuid_block, 16);
        return;
    }

    // Make a custom config
    std::string conf_dir_path_raw = globalreg->kismet_config->FetchOpt("configdir");
    std::string config_dir_path = 
        globalreg->kismet_config->ExpandLogPath(conf_dir_path_raw, "", "", 0, 1);

    std::string uuidconfpath = config_dir_path + "/" + "kismet_server_id.conf";

    ConfigFile uuidconf(globalreg);
    uuidconf.ParseConfig(uuidconfpath.c_str());

    // Look for a saved uuid
    confuuid = uuid(uuidconf.FetchOpt("server_uuid"));
    if (confuuid.error) {
        confuuid.GenerateTimeUUID((uint8_t *) "KISMET");
        _MSG("Generated server UUID " + confuuid.UUID2String() + " and storing in " +
                uuidconfpath, MSGFLAG_INFO);
        uuidconf.SetOpt("server_uuid", confuuid.UUID2String(), true);
        uuidconf.SaveConfig(uuidconfpath.c_str());
    }

    _MSG_INFO("Setting server UUID {}", confuuid.UUID2String());
    globalreg->server_uuid = confuuid;
    globalreg->server_uuid_hash = Adler32Checksum((const char *) confuuid.uuid_block, 16);
}

int main(int argc, char *argv[], char *envp[]) {
    exec_name = argv[0];
    std::string configfilename;
    ConfigFile *conf;
    int option_idx = 0;
    GlobalRegistry *globalreg;

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
        } else if (r == 'p') {
            show_pass = true;
        } else if (r == 'd') {
            debug_mode = true;
            wrapper = false;
        } else if (r == 'D') {
            wrapper = false;
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

    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGQUIT, CatchShutdown);
    signal(SIGCHLD, CatchChild);
    signal(SIGPIPE, SIG_IGN);

    // Build the globalregistry
    Globalreg::globalreg = new GlobalRegistry;
    globalregistry = Globalreg::globalreg;
    globalreg = globalregistry;

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
    globalregistry->RegisterUsageFunc(Devicetracker::usage);

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
            Usage(argv[0]);
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
    MessageBus::create_messagebus(globalregistry);

    // Create a smart stdout client and allocate the fatal message client, 
    // add them to the messagebus
    SmartStdoutMessageClient *smartmsgcli = 
        new SmartStdoutMessageClient(globalregistry, NULL);
    fqmescli = new FatalQueueMessageClient(globalregistry, NULL);

    // Register the fatal queue with fatal and error messages
    globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL | MSGFLAG_ERROR);
    // Register the smart msg printer for everything
    globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);

	// Create the event bus
	Eventbus::create_eventbus();

    // We need to create the pollable system near the top of execution as well
    auto pollabletracker(PollableTracker::create_pollabletracker());

    // Open, initial parse, and assign the config file
    if (configfilename == "") {
        configfilename = fmt::format("{}/{}",
                getenv("KISMET_CONF") != NULL ? getenv("KISMET_CONF") : SYSCONF_LOC,
                config_base);
    }

    conf = new ConfigFile(globalregistry);
    if (conf->ParseConfig(configfilename) < 0) {
        exit(1);
    }
    globalregistry->kismet_config = conf;

    struct stat fstat;
    std::string configdir;

    if (conf->FetchOpt("configdir") != "") {
        configdir = conf->ExpandLogPath(conf->FetchOpt("configdir"), "", "", 0, 1);
    } else {
        _MSG("No 'configdir' option in the config file; make sure that the "
                "Kismet config files are installed and up to date.", MSGFLAG_FATAL);
        SpindownKismet(pollabletracker);
    }

    auto etcdir = 
        globalreg->kismet_config->ExpandLogPath("%E", "", "", 0, 1);
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
        std::string banner = "KISMET - Point your browser to http://localhost:2501 "
            "for the Kismet UI";
        std::string banner_tail_ansi = "\u001b[0m";

        // Print the banner and ascii tail to set a top margin
        printf("%s%s%s\n", banner_ansi.c_str(), banner.c_str(), banner_tail_ansi.c_str());
    }

    Load_Kismet_UUID(globalregistry);

    // Set up ulimits if we define any
    std::string limits = globalregistry->kismet_config->FetchOpt("ulimit_mbytes");
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
    auto timetracker = Timetracker::create_timetracker();

    // HTTP BLOCK
    // Create the HTTPD server, it needs to exist before most things
    Kis_Net_Httpd::create_httpd();

    if (globalregistry->fatal_condition) 
        SpindownKismet(pollabletracker);

    // Allocate some other critical stuff like the entry tracker and the
    // serializers
    std::shared_ptr<EntryTracker> entrytracker =
        EntryTracker::create_entrytracker(Globalreg::globalreg);

    // Create the manuf db
    globalregistry->manufdb = new Manuf();
    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Base serializers
    entrytracker->RegisterSerializer("json", std::make_shared<JsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("ekjson", std::make_shared<EkJsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("prettyjson", std::make_shared<PrettyJsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("storagejson", std::make_shared<StorageJsonAdapter::Serializer>());

    entrytracker->RegisterSerializer("jcmd", std::make_shared<JsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("cmd", std::make_shared<JsonAdapter::Serializer>());

    if (daemonize) {
        // remove messagebus clients so we stop printing
        globalregistry->messagebus->RemoveClient(fqmescli);
        globalregistry->messagebus->RemoveClient(smartmsgcli);
    }

    if (conf->FetchOpt("servername") == "") {
        char hostname[64];
        if (gethostname(hostname, 64) < 0)
            globalregistry->servername = "Kismet";
        else
            globalregistry->servername = std::string(hostname);
    } else {
        globalregistry->servername = MungeToPrintable(conf->FetchOpt("servername"));
    }

    // Create the IPC handler
    IPCRemoteV2Tracker::create_ipcremote(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the stream tracking
    StreamTracker::create_streamtracker(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add the messagebus REST interface
    RestMessageClient::create_messageclient(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add login session
    Kis_Httpd_Websession::create_websession();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add module registry
    Kis_Httpd_Registry::create_http_registry(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the packet chain
    Packetchain::create_packetchain(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the DLT tracker
    auto dlttracker = DltTracker::create_dltt();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create antenna mapper
    auto anttracker = Antennatracker::create_at();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Add the datasource tracker
    auto datasourcetracker = Datasourcetracker::create_dst();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the alert tracker
    auto alertracker = Alertracker::create_alertracker();

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Create the device tracker
    auto devicetracker = 
        Devicetracker::create_devicetracker(globalregistry);

    // Create the pcap tracker
    auto devicetracker_pcap =
        std::make_shared<Devicetracker_Httpd_Pcap>();

    // Add channel tracking
    Channeltracker_V2::create_channeltracker(globalregistry);

    if (globalregistry->fatal_condition)
        SpindownKismet(pollabletracker);

    // Register the DLT handlers
    Kis_DLT_PPI::create_dlt();
    Kis_DLT_Radiotap::create_dlt();

    new Kis_Dissector_IPdata(globalregistry);

    // Register the base PHYs
    devicetracker->RegisterPhyHandler(new Kis_80211_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_RTL433_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_Zwave_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_Bluetooth_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_UAV_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_Mousejack_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_RTLAMR_Phy(globalregistry));
    devicetracker->RegisterPhyHandler(new Kis_RTLADSB_Phy(globalregistry));

    if (globalregistry->fatal_condition) 
        SpindownKismet(pollabletracker);

    // Add the datasources
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourcePcapfileBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceKismetdbBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceLinuxWifiBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceLinuxBluetoothBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceOsxCorewlanWifiBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtl433Builder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtl433MqttBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtlamrBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtlamrMqttBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtladsbBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtladsbMqttBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceFreaklabsZigbeeBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceNrfMousejackBuilder()));

    // Create the database logger as a global because it's a special case
    KisDatabaseLogfile::create_kisdatabaselog();

    auto logtracker = 
        LogTracker::create_logtracker();

    logtracker->register_log(SharedLogBuilder(new KisPPILogfileBuilder()));
    logtracker->register_log(SharedLogBuilder(new KisDatabaseLogfileBuilder()));
    logtracker->register_log(SharedLogBuilder(new KisPcapNGLogfileBuilder()));

    std::shared_ptr<Plugintracker> plugintracker;

    // Start the plugin handler
    if (plugins) {
        plugintracker = Plugintracker::create_plugintracker(globalregistry);
    } else {
        globalregistry->messagebus->InjectMessage(
            "Plugins disabled on the command line, plugins will NOT be loaded...",
            MSGFLAG_INFO);
    }


    // Process plugins and activate them
    if (plugintracker != nullptr) {
        plugintracker->ScanPlugins();
        plugintracker->ActivatePlugins();

        if (globalregistry->fatal_condition) {
            _MSG_FATAL("Failure activating Kismet plugins, make sure that all your plugins "
                    "are built against the same version of Kismet.");
            SpindownKismet(pollabletracker);
        }
    }

    // Create the GPS components
    GpsTracker::create_gpsmanager();

    // Add system monitor 
    Systemmonitor::create_systemmonitor();

    // Start up any code that needs everything to be loaded
    globalregistry->Start_Deferred();

    // Set the global silence now that we're set up
    glob_silent = local_silent;

    // Finalize any plugins which were waiting for other code to load
    plugintracker->FinalizePlugins();

    // We can't call this as a deferred because we don't want to mix
    devicetracker->load_devices();

    // Complain about running as root
    if (getuid() == 0) {
        alertracker->DefineAlert("ROOTUSER", sat_second, 1, sat_second, 1);
        auto userref = alertracker->ActivateConfiguredAlert("ROOTUSER",
                "Kismet is running as root; this is less secure than running Kismet "
                "as an unprivileged user and installing it as suidroot.  Please consult "
                "the Kismet README for more information about securely installing Kismet. "
                "If you're starting Kismet on boot via systemd, be sure to use "
                "'systemctl edit kismet.service' to configure the user.");
        alertracker->RaiseAlert(userref, NULL, mac_addr(), mac_addr(), mac_addr(), mac_addr(), "",
                "Kismet is running as root; this is less secure.  If you are running "
                "Kismet at boot via systemd, make sure to use `systemctl edit kismet.service` to "
                "change the user.  For more information, see the Kismet README for setting up "
                "Kismet with minimal privileges.");
    }
    
    _MSG("Starting Kismet web server...", MSGFLAG_INFO);
    Globalreg::FetchMandatoryGlobalAs<Kis_Net_Httpd>()->StartHttpd();

#if 0
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigemptyset(&oldmask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);

    int max_fd;
    fd_set rset, wset;
    struct timeval tm;
    int consec_badfd = 0;

    // Core loop
    while (1) {
        if (Globalreg::globalreg->spindown || Globalreg::globalreg->fatal_condition) 
            break;

        pollabletracker->Maintenance();

        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        max_fd = pollabletracker->MergePollableFds(&rset, &wset);

        // Block signals while doing io loops */
        sigprocmask(SIG_BLOCK, &mask, &oldmask);

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == EBADF) {
                    consec_badfd++;

                    if (consec_badfd > 20) 
                        throw std::runtime_error(fmt::format("select() > 20 consecutive badfd errors, latest {} {}",
                                    errno, strerror(errno)));
                } else {
                    throw std::runtime_error(fmt::format("select() failed: {} {}", errno, strerror(errno)));
                }
            }
        }

        consec_badfd = 0;

        // Run maintenance again so we don't gather purged records after the select()
        pollabletracker->Maintenance();

        pollabletracker->ProcessPollableSelect(rset, wset);

        sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

        // Tick the timetracker
        timetracker->Tick();
    }
#endif

#if 1
    // Independent time and select threads, which has had problems with timing conflicts
    timetracker->SpawnTimetrackerThread();
    pollabletracker->Selectloop(false);
#endif

    SpindownKismet(pollabletracker);
}

