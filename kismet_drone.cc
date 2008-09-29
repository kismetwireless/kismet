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

#define KISMET_DRONE

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

#include "util.h"

#include "globalregistry.h"

#include "configfile.h"
#include "messagebus.h"

#include "plugintracker.h"

#include "packetsource.h"
#include "packetsource_bsdrt.h"
#include "packetsource_pcap.h"
#include "packetsource_wext.h"
#include "packetsource_drone.h"
#include "packetsource_ipwlive.h"
#include "packetsource_airpcap.h"
#include "packetsourcetracker.h"

#include "timetracker.h"

#include "netframework.h"
#include "tcpserver.h"
// Include the stubbed empty netframe code
#include "kis_netframe.h"
#include "kis_droneframe.h"

#include "gpswrapper.h"

#include "ipc_remote.h"

#ifndef exec_name
char *exec_name;
#endif

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
    void ProcessMessage(string in_msg, int in_flags);
};

void SmartStdoutMessageClient::ProcessMessage(string in_msg, int in_flags) {
	if (glob_silent)
		return;

    if ((in_flags & MSGFLAG_DEBUG)) {
		if (glob_linewrap)
			fprintf(stdout, "%s", InLineWrap("DEBUG: " + in_msg, 7, 80).c_str());
		else
			fprintf(stdout, "DEBUG: %s\n", in_msg.c_str());
	} else if ((in_flags & MSGFLAG_LOCAL)) {
		if (glob_linewrap)
			fprintf(stdout, "%s", InLineWrap("LOCAL: " + in_msg, 7, 80).c_str());
		else
			fprintf(stdout, "LOCAL: %s\n", in_msg.c_str());
	} else if ((in_flags & MSGFLAG_INFO)) {
		if (glob_linewrap)
			fprintf(stdout, "%s", InLineWrap("INFO: " + in_msg, 6, 80).c_str());
		else
			fprintf(stdout, "INFO: %s\n", in_msg.c_str());
	} else if ((in_flags & MSGFLAG_ERROR)) {
		if (glob_linewrap)
			fprintf(stdout, "%s", InLineWrap("ERROR: " + in_msg, 7, 80).c_str());
		else
			fprintf(stdout, "ERROR: %s\n", in_msg.c_str());
	} else if ((in_flags & MSGFLAG_ALERT)) {
		if (glob_linewrap)
			fprintf(stdout, "%s", InLineWrap("ALERT: " + in_msg, 7, 80).c_str());
		else
			fprintf(stdout, "ALERT: %s\n", in_msg.c_str());
	} else if (in_flags & MSGFLAG_FATAL) {
		if (glob_linewrap)
			fprintf(stderr, "%s", InLineWrap("FATAL: " + in_msg, 7, 80).c_str());
		else
			fprintf(stderr, "FATAL: %s\n", in_msg.c_str());
	}
    
    return;
}

// Queue of fatal alert conditions to spew back out at the end
class FatalQueueMessageClient : public MessageClient {
public:
    FatalQueueMessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
        MessageClient(in_globalreg, in_aux) { }
    virtual ~FatalQueueMessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
    void DumpFatals();
protected:
    vector<string> fatalqueue;
};

void FatalQueueMessageClient::ProcessMessage(string in_msg, int in_flags) {
    // We only get passed fatal stuff so save a test
    fatalqueue.push_back(in_msg);
}

void FatalQueueMessageClient::DumpFatals() {
    for (unsigned int x = 0; x < fatalqueue.size(); x++) {
		if (glob_linewrap)
			fprintf(stderr, "%s", InLineWrap("FATAL: " + fatalqueue[x], 
											 7, 80).c_str());
		else
			fprintf(stderr, "FATAL: %s\n", fatalqueue[x].c_str());
    }
}

const char *config_base = "kismet_drone.conf";
const char *pid_base = "kismet_drone.pid";

// This needs to be a global but nothing outside of this main file will
// use it, so we don't have to worry much about putting it in the globalreg.
FatalQueueMessageClient *fqmescli = NULL;

// Some globals for command line options
char *configfile = NULL;

// Ultimate registry of global components
GlobalRegistry *globalregistry = NULL;

// Quick shutdown to clean up from a fatal config after we opened the child
void ErrorShutdown() {
    // Shut down the packet sources
    if (globalregistry->sourcetracker != NULL) {
        globalregistry->sourcetracker->StopSource(0);

    }

	// Shut down the root IPC process
	if (globalregistry->rootipc != NULL) {
		globalregistry->rootipc->ShutdownIPC(NULL);
	}

    // Shouldn't need to requeue fatal errors here since error shutdown means 
    // we just printed something about fatal errors.  Probably.

    fprintf(stderr, "Kismet drone exiting.\n");
    exit(1);
}

// Catch our interrupt
void CatchShutdown(int sig) {
    string termstr = "Kismet drone terminating.";

	if (globalregistry->sourcetracker != NULL) {
		// Shut down the packet sources
		globalregistry->sourcetracker->StopSource(0);
	}

	if (globalregistry->plugintracker != NULL)
		globalregistry->plugintracker->ShutdownPlugins();

	// Start a short shutdown cycle for 2 seconds
	fprintf(stderr, "\n*** KISMET DRONE IS FLUSHING BUFFERS AND SHUTTING DOWN ***\n");
	globalregistry->spindown = 1;
	time_t shutdown_target = time(0) + 2;
	int max_fd = 0;
	fd_set rset, wset;
	struct timeval tm;
	while (1) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		max_fd = 0;

		if (globalregistry->fatal_condition) {
			break;
		}

		if (time(0) >= shutdown_target) {
			break;
		}

		// Collect all the pollable descriptors
		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); x++) 
			max_fd = 
				globalregistry->subsys_pollable_vec[x]->MergeSet(max_fd, &rset, 
																 &wset);

		tm.tv_sec = 0;
		tm.tv_usec = 100000;

		if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
			if (errno != EINTR) {
				break;
			}
		}

		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); 
			 x++) {
			if (globalregistry->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
				globalregistry->fatal_condition) {
				break;
			}
		}
	}

	if (globalregistry->rootipc != NULL) {
		// Shut down the channel control child
		globalregistry->rootipc->ShutdownIPC(NULL);
	}

	// Be noisy
	if (globalregistry->fatal_condition) {
		fprintf(stderr, "\n*** KISMET DRONE HAS ENCOUNTERED A FATAL ERROR AND CANNOT "
				"CONTINUE.  ***\n");
	}
    
    // Dump fatal errors again
    if (fqmescli != NULL) 
        fqmescli->DumpFatals();

    fprintf(stderr, "Kismet drone exiting.\n");
    exit(0);
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
	printf("Nearly all of these options are run-time overrides for values in the\n"
		   "kismet.conf configuration file.  Permanent changes should be made to\n"
		   "the configuration file.\n");

	printf(" *** Generic Options ***\n");
	printf(" -f, --config-file            Use alternate configuration file\n"
		   "     --no-line-wrap           Turn of linewrapping of output\n"
		   "                              (for grep, speed, etc)\n"
		   " -s, --silent                 Turn off stdout output after setup phase\n"
		   );

	printf("\n");
	KisDroneFramework::Usage(argv);
	printf("\n");
	Packetsourcetracker::Usage(argv);

	exit(1);
}

int main(int argc, char *argv[], char *envp[]) {
	exec_name = argv[0];
	char errstr[STATUS_MAX];
	char *configfilename = NULL;
	ConfigFile *conf;
	int option_idx = 0;

	// ------ WE MAY BE RUNNING AS ROOT ------
	
	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

	// Start filling in key components of the globalregistry
	globalregistry = new GlobalRegistry;

	// Copy for modules
	globalregistry->argc = argc;
	globalregistry->argv = argv;
	globalregistry->envp = envp;
	
	// First order - create our message bus and our client for outputting
	globalregistry->messagebus = new MessageBus;

	// Create a smart stdout client and allocate the fatal message client, 
	// add them to the messagebus
	SmartStdoutMessageClient *smartmsgcli = 
		new SmartStdoutMessageClient(globalregistry, NULL);
	fqmescli = new FatalQueueMessageClient(globalregistry, NULL);

	globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL);
	globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);

	// Generate the root ipc packet capture and spawn it immediately, then register
	// and sync the packet protocol stuff
	if (getuid() != 0) {
		globalregistry->rootipc = new IPCRemote(globalregistry, "root capture control");
		globalregistry->rootipc->SetChildCmd(string(BIN_LOC) + "/kismet_capture");
		globalregistry->rootipc->SpawnIPC();
		globalregistry->messagebus->InjectMessage("Spawned root IPC capture control",
												  MSGFLAG_INFO);
	} else {
		globalregistry->messagebus->InjectMessage("NOT spawning suid-root IPC capture "
		   	"control, because we are ALREADY running as root.  This is not the "
			"preferred method of running Kismet because it prevents certain security "
			"features from operating.", MSGFLAG_ERROR);
	}

	// Allocate some other critical stuff
	globalregistry->timetracker = new Timetracker(globalregistry);

	// Turn off the getopt error reporting
	opterr = 0;

	// Timer for silence
	int local_silent = 0;

	const int nlwc = globalregistry->getopt_long_num++;

	// Standard getopt parse run
	static struct option main_longopt[] = {
		{ "config-file", required_argument, 0, 'f' },
		{ "no-line-wrap", no_argument, 0, nlwc },
		{ "silent", no_argument, 0, 's' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while (1) {
		int r = getopt_long(argc, argv, 
							"-f:sh", 
							main_longopt, &option_idx);
		if (r < 0) break;
		if (r == 'h') {
			Usage(argv[0]);
			exit(1);
		} else if (r == 'f') {
			configfilename = strdup(optarg);
		} else if (r == nlwc) {
			glob_linewrap = 0;
		} else if (r == 's') {
			local_silent = 1;
		}
	}

	// Open, initial parse, and assign the config file
	if (configfilename == NULL) {
		configfilename = new char[1024];
		snprintf(configfilename, 1024, "%s/%s", 
				 getenv("KISMETDRONE_CONF") != NULL ? 
				 getenv("KISMETDRONE_CONF") : SYSCONF_LOC,
				 config_base);
	}

	snprintf(errstr, STATUS_MAX, "Reading from config file %s", configfilename);
	globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
	
	conf = new ConfigFile;
	if (conf->ParseConfig(configfilename) < 0) {
		exit(1);
	}
	globalregistry->kismet_config = conf;
 
	if (conf->FetchOpt("servername") == "") {
		globalregistry->servername = "Unnamed Drone";
	} else {
		globalregistry->servername = MungeToPrintable(conf->FetchOpt("servername"));
	}

	// Create the stubbed network/protocol server
	globalregistry->kisnetserver = new KisNetFramework(globalregistry);	

	// Start the plugin handler
	globalregistry->plugintracker = new Plugintracker(globalregistry);

	// Build the plugin list for root plugins
	globalregistry->plugintracker->ScanRootPlugins();

	// Create the packet chain
	globalregistry->packetchain = new Packetchain(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the packetsourcetracker
	globalregistry->sourcetracker = new Packetsourcetracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the basic drone server
	globalregistry->kisdroneserver = new KisDroneFramework(globalregistry);
	if (globalregistry->fatal_condition || 
		globalregistry->kisdroneserver->Valid() == 0)
		CatchShutdown(-1);

	// Add the packet sources
#ifdef USE_PACKETSOURCE_PCAPFILE
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Pcapfile(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_WEXT
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Wext(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_MADWIFI
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Madwifi(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_MADWIFING
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_MadwifiNG(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_WRT54PRISM
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Wrt54Prism(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_DRONE
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Drone(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_BSDRT
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_BSDRT(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_IPWLIVE
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Ipwlive(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_AIRPCAP
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_AirPcap(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif

	// Enable cards from config/cmdline
	if (globalregistry->sourcetracker->LoadConfiguration() < 0)
		CatchShutdown(-1);

	// Create the basic network/protocol server
	globalregistry->kisdroneserver->Activate();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Once the packet source and channel control is opened, we shouldn't need special
	// Process userspace plugins
	globalregistry->plugintracker->ScanUserPlugins();

	// Create the GPS components
	GpsWrapper *gpswrapper;
	globalregistry->messagebus->InjectMessage("Starting GPS components...",
											  MSGFLAG_INFO);
	gpswrapper = new GpsWrapper(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Kick the plugin system one last time.  This will try to kick any plugins
	// that aren't activated yet, and then bomb out if we can't turn them on at
	// all.
	globalregistry->plugintracker->LastChancePlugins();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Blab about starting
	globalregistry->messagebus->InjectMessage("Kismet drone starting to gather "
											  "packets", MSGFLAG_INFO);
	
	// Set the global silence now that we're set up
	glob_silent = local_silent;

	int max_fd = 0;
	fd_set rset, wset;
	struct timeval tm;

	// Core loop
	while (1) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		max_fd = 0;

		if (globalregistry->fatal_condition)
			CatchShutdown(-1);

		// Collect all the pollable descriptors
		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); x++) 
			max_fd = 
				globalregistry->subsys_pollable_vec[x]->MergeSet(max_fd, &rset, 
																 &wset);

		tm.tv_sec = 0;
		tm.tv_usec = 100000;

		if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
			if (errno != EINTR) {
				snprintf(errstr, STATUS_MAX, "Main select loop failed: %s",
						 strerror(errno));
				CatchShutdown(-1);
			}
		}

		globalregistry->timetracker->Tick();

		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); 
			 x++) {
			if (globalregistry->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
				globalregistry->fatal_condition) {
				CatchShutdown(-1);
			}
		}
	}

	CatchShutdown(-1);
}
