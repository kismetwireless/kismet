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

#ifdef HAVE_LIBNCURSES
#include <ncurses.h>
#endif

#include "util.h"

#include "globalregistry.h"

#include "configfile.h"
#include "messagebus.h"

#include "plugintracker.h"

#include "kis_dlt_ppi.h"
#include "kis_dlt_radiotap.h"

#include "kis_dissector_ipdata.h"

#include "kis_datasource.h"
#include "datasourcetracker.h"
#include "datasource_pcapfile.h"
#include "datasource_linux_wifi.h"
#include "datasource_linux_bluetooth.h"
#include "datasource_osx_corewlan_wifi.h"
#include "datasource_rtl433.h"
#include "datasource_freaklabs_zigbee.h"

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

#include "gpstracker.h"

#include "devicetracker.h"
#include "phy_80211.h"
#include "phy_rtl433.h"
#include "phy_zwave.h"
#include "phy_bluetooth.h"
#include "phy_uav_drone.h"

#include "ipc_remote2.h"

#include "statealert.h"

#include "manuf.h"

#include "entrytracker.h"

#include "json_adapter.h"

#include "streamtracker.h"

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
    std::shared_ptr<Kis_Net_Httpd> httpd = 
        Globalreg::FetchGlobalAs<Kis_Net_Httpd>(globalregistry, "HTTPD_SERVER");
    if (httpd != NULL)
        httpd->StopHttpd();

    auto devicetracker =
        Globalreg::FetchGlobalAs<Devicetracker>("DEVICETRACKER");
    if (devicetracker != NULL) {
        devicetracker->store_all_devices();
        devicetracker->databaselog_write_all_devices();
    }

    // Shutdown everything
    globalregistry->Shutdown_Deferred();

    globalregistry->spindown = 1;

    // Start a short shutdown cycle for 2 seconds
    if (daemonize == 0)
        fprintf(stderr, "\n*** KISMET IS SHUTTING DOWN ***\n");
    time_t shutdown_target = time(0) + 2;
    int max_fd = 0;
    fd_set rset, wset;
    struct timeval tm;

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigemptyset(&oldmask);
    sigaddset(&mask, SIGCHLD);

    while (1) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);

        if (globalregistry->fatal_condition) {
            break;
        }

        if (time(0) >= shutdown_target) {
            break;
        }

        // Collect all the pollable descriptors
        max_fd = pollabletracker->MergePollableFds(&rset, &wset);

        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }
        }

        // Block signals while doing io loops */
        sigprocmask(SIG_BLOCK, &mask, &oldmask);

        pollabletracker->ProcessPollableSelect(rset, wset);

        sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

        if (globalregistry->fatal_condition) {
            break;
        }

    }

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
                "         usually:  /etc/init.d/networking restart\n\n");

        fprintf(stderr, "Kismet exiting.\n");
    }

    globalregistry->DeleteLifetimeGlobals();

    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

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
           "     --no-ncurses-wrapper     Disable ncurses wrapper\n"
           "     --debug                  Disable the ncurses wrapper and the crash\n"
           "                              handling functions, for debugging\n"
           " -f, --config-file <file>     Use alternate configuration file\n"
           "     --no-line-wrap           Turn of linewrapping of output\n"
           "                              (for grep, speed, etc)\n"
           " -s, --silent                 Turn off stdout output after setup phase\n"
           "     --daemonize              Spawn detatched in the background\n"
           "     --no-plugins             Do not load plugins\n"
           "     --homedir <path>         Use an alternate path as the home \n"
           "                               directory instead of the user entry\n"
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

#ifdef HAVE_LIBNCURSES
std::vector<std::string> ncurses_exitbuf;

pid_t ncurses_kismet_pid = 0;

bool ncurses_die = false;

void NcursesKillHandler(int sig __attribute__((unused))) {
    ncurses_die = true;
}

// Handle cancel events - kill kismet, and then catch sigchild
// when it exits
void NcursesCancelHandler(int sig __attribute__((unused))) {
    if (ncurses_kismet_pid != 0) 
        kill(ncurses_kismet_pid, SIGQUIT);
    else
        NcursesKillHandler(sig);
}

void ncurses_wrapper_fork() {
    int pipefd[2];
    
    if (pipe(pipefd) < 0) {
        fprintf(stderr, "FATAL: Could not make pipe to fork ncurses: %s\n", 
                strerror(errno));
        exit(1);
    }

    if ((ncurses_kismet_pid = fork()) == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], 1);
        dup2(pipefd[1], 2);

        setbuf(stdout, NULL);
        setbuf(stderr, NULL);

        close(pipefd[1]);

        // Jump back to the main function that called us
        return;
    } else {
        close(pipefd[1]);

        // Catch all the ways we die and bail out of ncurses mode &
        // print the last output cleanly
        signal(SIGKILL, NcursesCancelHandler);
        signal(SIGQUIT, NcursesCancelHandler);
        signal(SIGINT, NcursesCancelHandler);
        signal(SIGTERM, NcursesCancelHandler);
        signal(SIGHUP, NcursesCancelHandler);

        signal(SIGABRT, NcursesKillHandler);
        signal(SIGCHLD, NcursesKillHandler);

        // Ignore WINCH and have a wrong-sized screen
        signal(SIGWINCH, SIG_IGN);

        signal(SIGPIPE, SIG_IGN);

        fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);

        WINDOW *top_bar, *main_text, *bottom_bar;

        initscr();

        top_bar = newwin(1, COLS, 0, 0);
        main_text = newwin(LINES - 2, COLS, 1, 0);
        bottom_bar = newwin(1, COLS, LINES - 1, 0);

        scrollok(main_text, true);

        wattron(top_bar, A_REVERSE);
        wattron(bottom_bar, A_REVERSE);

        // Cheesy fill
        for (int x = 0; x < COLS; x += 5) {
            wprintw(top_bar, "     ");
        }
        mvwprintw(top_bar, 0, 0, "Kismet Server");
        wrefresh(top_bar);

        for (int x = 0; x < COLS; x += 5) {
            wprintw(bottom_bar, "     ");
        }
        mvwprintw(bottom_bar, 0, 0, "Visit http://localhost:2501 to view the Kismet UI");
        wrefresh(bottom_bar);

        int nread;
        size_t len = 2048;
        char *buf = new char[len];

        sigset_t mask, oldmask;
        sigemptyset(&mask);
        sigemptyset(&oldmask);
        sigaddset(&mask, SIGCHLD);

        while (1) {
            if (ncurses_die) {
                endwin();

                printf("Kismet server terminated.  Last output:\n");

                for (unsigned int x = 0; x < ncurses_exitbuf.size(); x++) {
                    printf("%s", ncurses_exitbuf[x].c_str());
                }

                printf("Kismet exited.\n");

                exit(1);
            }

            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(pipefd[0], &rset);

            struct timeval tm;
            tm.tv_sec = 0;
            tm.tv_usec = 100000;

            if (select(pipefd[0] + 1, &rset, NULL, NULL, &tm) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    break;
                }
            }

            // Block signals while doing io loops */
            sigprocmask(SIG_BLOCK, &mask, &oldmask);

            while ((nread = read(pipefd[0], buf, len - 1)) > 0) {
                buf[nread] = 0;
                waddstr(main_text, buf);
                wrefresh(main_text);

                ncurses_exitbuf.push_back(std::string(buf));
                if (ncurses_exitbuf.size() > 10)
                    ncurses_exitbuf.erase(ncurses_exitbuf.begin());
            }

            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }

            sigprocmask(SIG_UNBLOCK, &mask, &oldmask);
        }

        sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

        delete[] buf;
    
        endwin();

        for (unsigned int x = 0; x < ncurses_exitbuf.size(); x++) {
            printf("%s", ncurses_exitbuf[x].c_str());
        }

        printf("Kismet exited");

        exit(1);
    }
}
#endif

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
    char errstr[STATUS_MAX];
    char *configfilename = NULL;
    ConfigFile *conf;
    int option_idx = 0;
    GlobalRegistry *globalreg;

    bool debug_mode = false;

    static struct option wrapper_longopt[] = {
        { "no-ncurses-wrapper", no_argument, 0, 'w' },
        { "daemonize", no_argument, 0, 'D' },
        { "debug", no_argument, 0, 'd' },
        { 0, 0, 0, 0 }
    };

    // Reset the options index
    optind = 0;
    option_idx = 0;
    opterr = 0;

    bool wrapper = true;

    while (1) {
        int r = getopt_long(argc, argv, "-", wrapper_longopt, &option_idx);
        if (r < 0) break;

        if (r == 'w') {
            wrapper = false; 
        } else if (r == 'd') {
            debug_mode = true;
            wrapper = false;
        } else if (r == 'D') {
            wrapper = false;
        }
    }

    optind = 0;
    option_idx = 0;

#ifdef HAVE_LIBNCURSES
    if (wrapper)
        ncurses_wrapper_fork();
#endif

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
    globalregistry->revision = REVISION;
    globalregistry->revdate = REVDATE;

    // Copy for modules
    globalregistry->argc = argc;
    globalregistry->argv = argv;
    globalregistry->envp = envp;

    // Set up usage functions
    globalregistry->RegisterUsageFunc(Devicetracker::usage);

    int max_fd = 0;
    fd_set rset, wset;
    struct timeval tm;

    const int nlwc = globalregistry->getopt_long_num++;
    const int dwc = globalregistry->getopt_long_num++;
    const int npwc = globalregistry->getopt_long_num++;
    const int hdwc = globalregistry->getopt_long_num++;

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
            configfilename = strdup(optarg);
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

    // We need to create the pollable system near the top of execution as well
    std::shared_ptr<PollableTracker> pollabletracker(PollableTracker::create_pollabletracker(globalregistry));

    // Open, initial parse, and assign the config file
    if (configfilename == NULL) {
        configfilename = new char[1024];
        snprintf(configfilename, 1024, "%s/%s", 
                 getenv("KISMET_CONF") != NULL ? getenv("KISMET_CONF") : SYSCONF_LOC,
                 config_base);
    }

    snprintf(errstr, STATUS_MAX, "Reading from config file %s", configfilename);
    globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    
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
        globalregistry->messagebus->InjectMessage("No 'configdir' option in the config file",
                MSGFLAG_FATAL);
        CatchShutdown(-1);
    }

    if (stat(configdir.c_str(), &fstat) == -1) {
        snprintf(errstr, STATUS_MAX, "Local config and cache directory '%s' does not exist, making it",
                configdir.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
        if (mkdir(configdir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) < 0) {
            snprintf(errstr, STATUS_MAX, "Could not create config and cache directory: %s",
                    strerror(errno));
            globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            CatchShutdown(-1);
        }
    } else if (! S_ISDIR(fstat.st_mode)) {
        snprintf(errstr, STATUS_MAX, "Local config and cache directory '%s' exists but is not a directory",
                configdir.c_str());
        globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        CatchShutdown(-1);
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
    Timetracker::create_timetracker(globalregistry);

    // HTTP BLOCK
    // Create the HTTPD server, it needs to exist before most things
    Kis_Net_Httpd::create_httpd(globalregistry);

    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    // Allocate some other critical stuff like the entry tracker and the
    // serializers
    std::shared_ptr<EntryTracker> entrytracker =
        EntryTracker::create_entrytracker(Globalreg::globalreg);

    // Base serializers
    entrytracker->RegisterSerializer("json", std::make_shared<JsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("ekjson", std::make_shared<EkJsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("prettyjson", std::make_shared<PrettyJsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("storagejson", std::make_shared<StorageJsonAdapter::Serializer>());

    entrytracker->RegisterSerializer("jcmd", std::make_shared<JsonAdapter::Serializer>());
    entrytracker->RegisterSerializer("cmd", std::make_shared<JsonAdapter::Serializer>());

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

        // remove messagebus clients
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

    // Create the stream tracking
    StreamTracker::create_streamtracker(globalregistry);

    // Add the messagebus REST interface
    RestMessageClient::create_messageclient(globalregistry);

    // Add login session
    Kis_Httpd_Websession::create_websession(globalregistry);

    // Add module registry
    Kis_Httpd_Registry::create_http_registry(globalregistry);

    // Create the packet chain
    Packetchain::create_packetchain(globalregistry);

    // Add the datasource tracker
    std::shared_ptr<Datasourcetracker> datasourcetracker;
    datasourcetracker = Datasourcetracker::create_dst();

    // Create the alert tracker
    Alertracker::create_alertracker(globalregistry);

    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    // Create the device tracker
    std::shared_ptr<Devicetracker> devicetracker = 
        Devicetracker::create_devicetracker(globalregistry);

    // Add channel tracking
    Channeltracker_V2::create_channeltracker(globalregistry);

    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    // Register the DLT handlers
    new Kis_DLT_PPI(globalregistry);
    new Kis_DLT_Radiotap(globalregistry);

    new Kis_Dissector_IPdata(globalregistry);

    // Register the base PHYs
    Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER")->RegisterPhyHandler(new Kis_80211_Phy(globalregistry));

    Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER")->RegisterPhyHandler(new Kis_RTL433_Phy(globalregistry));

    Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER")->RegisterPhyHandler(new Kis_Zwave_Phy(globalregistry));

    Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER")->RegisterPhyHandler(new Kis_Bluetooth_Phy(globalregistry));

    Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER")->RegisterPhyHandler(new Kis_UAV_Phy(globalregistry));

    if (globalregistry->fatal_condition) 
        CatchShutdown(-1);

    // Add the datasources
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourcePcapfileBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceLinuxWifiBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceLinuxBluetoothBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceOsxCorewlanWifiBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtl433Builder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceRtl433MqttBuilder()));
    datasourcetracker->register_datasource(SharedDatasourceBuilder(new DatasourceFreaklabsZigbeeBuilder()));

    // Create the database logger as a global because it's a special case
    KisDatabaseLogfile::create_kisdatabaselog();

    LogTracker::create_logtracker();

    Globalreg::FetchMandatoryGlobalAs<LogTracker>("LOGTRACKER")->register_log(SharedLogBuilder(new KisPPILogfileBuilder()));
    Globalreg::FetchMandatoryGlobalAs<LogTracker>("LOGTRACKER")->register_log(SharedLogBuilder(new KisDatabaseLogfileBuilder()));
    Globalreg::FetchMandatoryGlobalAs<LogTracker>("LOGTRACKER")->register_log(SharedLogBuilder(new KisPcapNGLogfileBuilder()));


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
    if (plugintracker != NULL) {
        plugintracker->ScanPlugins();
        plugintracker->ActivatePlugins();

        if (globalregistry->fatal_condition) {
            globalregistry->messagebus->InjectMessage(
                        "Failure during activating plugins", MSGFLAG_FATAL);
            CatchShutdown(-1);
        }
    }

    // Create the GPS components
    GpsTracker::create_gpsmanager();

    // Create the manuf db
    globalregistry->manufdb = new Manuf(globalregistry);
    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    // Start stateful alert systems
    BSSTSStateAlert *bsstsa;
    bsstsa = new BSSTSStateAlert(globalregistry);
    if (globalregistry->fatal_condition)
        CatchShutdown(-1);

    // Add system monitor 
    Systemmonitor::create_systemmonitor();

    // Set the global silence now that we're set up
    glob_silent = local_silent;

    // Finalize any plugins which were waiting for other code to load
    plugintracker->FinalizePlugins();

    // We can't call this as a deferred because we don't want to mix
    devicetracker->load_devices();
    
    _MSG("Starting Kismet web server...", MSGFLAG_INFO);
    Globalreg::FetchMandatoryGlobalAs<Kis_Net_Httpd>(globalregistry, "HTTPD_SERVER")->StartHttpd();

    // Blab about starting
    globalregistry->messagebus->InjectMessage("Kismet starting to gather packets",
            MSGFLAG_INFO);

    // Start up any code that needs everything to be loaded
    globalregistry->Start_Deferred();

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigemptyset(&oldmask);
    sigaddset(&mask, SIGCHLD);

    // Core loop
    while (1) {
        if (globalregistry->spindown || globalregistry->fatal_condition) {
            break;
        }

        max_fd = pollabletracker->MergePollableFds(&rset, &wset);

        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "Main select failed: %s\n", strerror(errno));
                snprintf(errstr, STATUS_MAX, "Main select loop failed: %s",
                         strerror(errno));
                CatchShutdown(-1);
            }
        }

        // Block signals while doing io loops */
        sigprocmask(SIG_BLOCK, &mask, &oldmask);

        globalregistry->timetracker->Tick();

        pollabletracker->ProcessPollableSelect(rset, wset);

        sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

        if (globalregistry->fatal_condition || globalregistry->spindown) {
            break;
        }
    }

    SpindownKismet(pollabletracker);
}

