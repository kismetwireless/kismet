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

#include "version.h"

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
#include "packetsource_darwin.h"
#include "packetsource_macusb.h"
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

// Daemonize?
int daemonize = 0;

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
	if (daemonize == 0)
		fprintf(stderr, 
				"\n*** KISMET DRONE IS FLUSHING BUFFERS AND SHUTTING DOWN ***\n");
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
			if (errno != EINTR && errno != EAGAIN) {
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
	if (globalregistry->fatal_condition && daemonize == 0) {
		fprintf(stderr, "\n*** KISMET DRONE HAS ENCOUNTERED A FATAL ERROR AND CANNOT "
				"CONTINUE.  ***\n");
	}
    
    // Dump fatal errors again
    if (fqmescli != NULL) 
        fqmescli->DumpFatals();

	if (daemonize == 0)
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
		   "     --daemonize              Spawn detatched in the background\n"
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

	GlobalRegistry *globalreg = NULL;

	int startup_ipc_id = -1;

	int max_fd = 0;
	fd_set rset, wset;
	struct timeval tm;


	// ------ WE MAY BE RUNNING AS ROOT ------
	
	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

	// Start filling in key components of the globalregistry
	globalregistry = new GlobalRegistry;

	globalreg = globalregistry;

	globalregistry->version_major = VERSION_MAJOR;
	globalregistry->version_minor = VERSION_MINOR;
	globalregistry->version_tiny = VERSION_TINY;
	globalregistry->revision = REVISION;
	globalregistry->revdate = REVDATE;

	globalregistry->kismet_instance = KISMET_INSTANCE_DRONE;

	// Copy for modules
	globalregistry->argc = argc;
	globalregistry->argv = argv;
	globalregistry->envp = envp;

	// Turn off the getopt error reporting
	opterr = 0;

	// Timer for silence
	int local_silent = 0;

	const int nlwc = globalregistry->getopt_long_num++;
	const int dwc = globalregistry->getopt_long_num++;
	const int npwc = globalregistry->getopt_long_num++;

	// Standard getopt parse run
	static struct option main_longopt[] = {
		{ "config-file", required_argument, 0, 'f' },
		{ "no-line-wrap", no_argument, 0, nlwc },
		{ "silent", no_argument, 0, 's' },
		{ "help", no_argument, 0, 'h' },
		{ "daemonize", no_argument, 0, dwc },
		{ "no-plugins", no_argument, 0, npwc },
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
		} else if (r == npwc) {
			plugins = 0;
		} else if (r == dwc) {
			daemonize = 1;
			local_silent = 1;
		}
	}

	
	// First order - create our message bus and our client for outputting
	globalregistry->messagebus = new MessageBus;

	// Create a smart stdout client and allocate the fatal message client, 
	// add them to the messagebus
	SmartStdoutMessageClient *smartmsgcli = 
		new SmartStdoutMessageClient(globalregistry, NULL);
	fqmescli = new FatalQueueMessageClient(globalregistry, NULL);

	globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL);
	globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);

#ifndef SYS_CYGWIN
	if (getuid() != 0) {
		globalregistry->messagebus->InjectMessage("Not running as root - will try to "
			"launch root control binary (" + string(BIN_LOC) + "/kismet_capture) to "
			"control cards.", MSGFLAG_INFO);

		globalregistry->rootipc = new RootIPCRemote(globalregistry, "kismet_root");
		globalregistry->rootipc->SpawnIPC();

		startup_ipc_id = 
			globalregistry->rootipc->RegisterIPCCmd(NULL, NULL, NULL, "STARTUP");

		time_t ipc_spin_start = time(0);

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
				if (errno != EINTR && errno != EAGAIN) {
					snprintf(errstr, STATUS_MAX, "Main select loop failed: %s",
							 strerror(errno));
					CatchShutdown(-1);
				}
			}

			for (unsigned int x = 0; 
				 x < globalregistry->subsys_pollable_vec.size(); x++) {

				if (globalregistry->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
					globalregistry->fatal_condition) {
					CatchShutdown(-1);
				}
			}

			if (globalregistry->rootipc->FetchRootIPCSynced() > 0) {
				// printf("debug - kismet server startup got root sync\n");
				break;
			}

			if (time(0) - ipc_spin_start > 2) {
				// printf("debug - kismet server startup timed out\n");
				break;
			}
		}

		if (globalregistry->rootipc->FetchRootIPCSynced() <= 0) {
			critical_fail cf;
			cf.fail_time = time(0);
			cf.fail_msg = "Failed to start kismet_capture control binary.  Make sure "
				"that kismet_capture is installed, is suid-root, and that your user "
				"is in the 'kismet' group, or run Kismet as root.  See the "
				"README for more information.";

			int ipc_errno = globalregistry->rootipc->FetchErrno();

			if (ipc_errno == EPERM || ipc_errno == EACCES) {
				cf.fail_msg = "Could not launch kismet_capture control binary, "
					"due to permission errors.  To run Kismet suid-root your user "
					"MUST BE IN THE 'kismet' GROUP.  Use the 'groups' command to show "
					"what groups your user is in, and consult the Kismet README for "
					"more information.";
			}

			globalreg->critfail_vec.push_back(cf);

			_MSG(cf.fail_msg, MSGFLAG_FATAL);
		} else {
			_MSG("Started kismet_capture control binary successfully, pid " +
				 IntToString(globalreg->rootipc->FetchSpawnPid()), MSGFLAG_INFO);
		}

	} else {
		globalregistry->messagebus->InjectMessage(
			"Kismet was started as root, NOT launching external control binary.  "
			"This is NOT the preferred method of starting Kismet as Kismet will "
			"continue to run as root the entire time.  Please read the README "
			"file section about Installation & Security and be sure this is "
			"what you want to do.", MSGFLAG_ERROR);
	}
#endif

	// Allocate some other critical stuff
	globalregistry->timetracker = new Timetracker(globalregistry);

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
	
	conf = new ConfigFile(globalregistry);
	if (conf->ParseConfig(configfilename) < 0) {
		exit(1);
	}
	globalregistry->kismet_config = conf;

	if (daemonize) {
		if (fork() != 0) {
			fprintf(stderr, "Silencing output and entering daemon mode...\n");
			exit(1);
		}

		// remove messagebus clients
		globalregistry->messagebus->RemoveClient(fqmescli);
		globalregistry->messagebus->RemoveClient(smartmsgcli);
	}
 
	if (conf->FetchOpt("servername") == "") {
		char hostname[64];
		if (gethostname(hostname, 64) < 0)
			globalregistry->servername = "Kismet Drone";
		else
			globalregistry->servername = string(hostname);
	} else {
		globalregistry->servername = MungeToPrintable(conf->FetchOpt("servername"));
	}

	// Create the stubbed network/protocol server
	globalregistry->kisnetserver = new KisNetFramework(globalregistry);	

	// Create the packet chain
	globalregistry->packetchain = new Packetchain(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the packetsourcetracker
	globalregistry->sourcetracker = new Packetsourcetracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Register the IPC
	if (globalregistry->rootipc != NULL) {
		globalregistry->sourcetracker->RegisterIPC(globalregistry->rootipc, 0);

		globalregistry->rootipc->SyncRoot();
		globalregistry->rootipc->SyncIPC();

		ipc_packet *ipc = (ipc_packet *) malloc(sizeof(ipc_packet));
		ipc->data_len = 0;
		ipc->ipc_ack = 0;
		ipc->ipc_cmdnum = startup_ipc_id;

		globalreg->rootipc->SendIPC(ipc);
	}

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
#ifdef USE_PACKETSOURCE_DARWIN
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_Darwin(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_MACUSB
	if (globalregistry->sourcetracker->RegisterPacketSource(new PacketSource_MacUSB(globalregistry)) < 0 || globalregistry->fatal_condition) 
		CatchShutdown(-1);
#endif

	// Start the plugin handler
	if (plugins) {
		globalregistry->plugintracker = new Plugintracker(globalregistry);
	} else {
		globalregistry->messagebus->InjectMessage(
			"Plugins disabled on the command line, plugins will NOT be loaded...",
			MSGFLAG_INFO);
	}


	// Process userspace plugins
	if (globalregistry->plugintracker != NULL) {
		globalregistry->plugintracker->ScanUserPlugins();
		globalregistry->plugintracker->ActivatePlugins();
		if (globalregistry->fatal_condition) {
			globalregistry->messagebus->InjectMessage(
						"Failure during activating plugins", MSGFLAG_FATAL);
			CatchShutdown(-1);
		}
	}


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

	// Initialize the crc tables
	crc32_init_table_80211(globalregistry->crc32_table);

	// Blab about starting
	globalregistry->messagebus->InjectMessage("Kismet drone starting to gather "
											  "packets", MSGFLAG_INFO);

	// Start sources
	globalregistry->sourcetracker->StartSource(0);
	
	// Set the global silence now that we're set up
	glob_silent = local_silent;

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
			if (errno != EINTR && errno != EAGAIN) {
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
