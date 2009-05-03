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
#include "packetsourcetracker.h"

#include "timetracker.h"
#include "alertracker.h"

#include "netframework.h"
#include "tcpserver.h"
#include "kis_netframe.h"
#include "kis_droneframe.h"

#include "soundcontrol.h"

#include "gpswrapper.h"

#include "packetdissectors.h"
#include "netracker.h"
#include "channeltracker.h"

#include "dumpfile.h"
#include "dumpfile_pcap.h"
#include "dumpfile_netxml.h"
#include "dumpfile_nettxt.h"
#include "dumpfile_gpsxml.h"
#include "dumpfile_tuntap.h"
#include "dumpfile_string.h"
#include "dumpfile_alert.h"

#include "ipc_remote.h"

#include "statealert.h"

#include "spectool_netclient.h"

#include "manuf.h"

#ifndef exec_name
char *exec_name;
#endif

// One of our few globals in this file
int glob_linewrap = 1;
int glob_silent = 0;

// The info protocol lives in here for lack of anywhere better to live
enum INFO_fields {
	INFO_networks, INFO_packets, INFO_cryptpackets,
	INFO_noisepackets, INFO_droppedpackets, INFO_packetrate, 
	INFO_filteredpackets, INFO_clients, INFO_llcpackets, INFO_datapackets,
	INFO_numsources,
	INFO_maxfield
};

const char *INFO_fields_text[] = {
	"networks", "packets", "crypt", "noise", "dropped", "rate", 
	"filtered", "clients", "llcpackets", "datapackets", "numsources",
	NULL
};

int Protocol_INFO(PROTO_PARMS) {
	ostringstream osstr;

	// Alloc the cache quickly
	cache->Filled(field_vec->size());

    for (unsigned int x = 0; x < field_vec->size(); x++) {
        unsigned int fnum = (*field_vec)[x];
        if (fnum >= INFO_maxfield) {
            out_string = "Unknown field requested.";
            return -1;
		}

		osstr.str("");

		// Shortcut test the cache once and print/bail immediately
		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		// Fill in the cached element
		switch(fnum) {
			case INFO_networks:
				osstr << globalreg->netracker->FetchNumNetworks();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_clients:
				osstr << globalreg->netracker->FetchNumClients();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_packets:
				osstr << globalreg->netracker->FetchNumPackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_cryptpackets:
				osstr << globalreg->netracker->FetchNumCryptpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_llcpackets:
				osstr << globalreg->netracker->FetchNumLLCpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_datapackets:
				osstr << globalreg->netracker->FetchNumDatapackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_noisepackets:
				osstr << globalreg->netracker->FetchNumErrorpackets();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_droppedpackets:
				osstr << (globalreg->netracker->FetchNumErrorpackets() +
						  globalreg->netracker->FetchNumFiltered());
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_packetrate:
				osstr << globalreg->netracker->FetchPacketRate();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_filteredpackets:
				osstr << globalreg->netracker->FetchNumFiltered();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_numsources:
				osstr << globalreg->sourcetracker->FetchSourceVec()->size();
				cache->Cache(fnum, osstr.str());
				break;
		}

		// print the newly filled in cache
		out_string += cache->GetCache(fnum) + " ";
    }

    return 1;
}

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
    void ProcessMessage(string in_msg, int in_flags);
    void DumpFatals();
protected:
    vector<string> fatalqueue;
};

void FatalQueueMessageClient::ProcessMessage(string in_msg, int in_flags) {
	// Queue PRINT forced errors differently than fatal conditions
	if (in_flags & MSGFLAG_PRINT) {
		fatalqueue.push_back("ERROR: " + in_msg);
	} else if (in_flags & MSGFLAG_FATAL) {
		fatalqueue.push_back("FATAL: " + in_msg);
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

// Quick shutdown to clean up from a fatal config after we opened the child
void ErrorShutdown() {
	// Eat the child signal handler
	signal(SIGCHLD, SIG_DFL);

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

    fprintf(stderr, "Kismet exiting.\n");
    exit(1);
}

// Catch our interrupt
void CatchShutdown(int sig) {
    string termstr = "Kismet server terminating.";

	// Eat the child signal handler
	signal(SIGCHLD, SIG_DFL);

	if (globalregistry->kisnetserver != NULL) {
		globalregistry->kisnetserver->SendToAll(globalregistry->netproto_map[PROTO_REF_TERMINATE], (void *) &termstr);
	}

	if (globalregistry->sourcetracker != NULL) {
		// Shut down the packet sources
		globalregistry->sourcetracker->StopSource(0);
	}

	globalregistry->spindown = 1;

	if (globalregistry->plugintracker != NULL)
		globalregistry->plugintracker->ShutdownPlugins();

	// Start a short shutdown cycle for 2 seconds
	fprintf(stderr, "\n*** KISMET IS SHUTTING DOWN ***\n");
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
		globalregistry->rootipc->ShutdownIPC(NULL);;
	}

	if (globalregistry->kisnetserver != NULL) {
		globalregistry->kisnetserver->Shutdown();
	}

	// Be noisy
	if (globalregistry->fatal_condition) {
		fprintf(stderr, "\n*** KISMET HAS ENCOUNTERED A FATAL ERROR AND CANNOT "
				"CONTINUE.  ***\n");
	}

	// Kill all the logfiles
	fprintf(stderr, "Shutting down log files...\n");
	for (unsigned int x = 0; x < globalregistry->subsys_dumpfile_vec.size(); x++) {
		delete globalregistry->subsys_dumpfile_vec[x];
	}
    
    // Dump fatal errors again
    if (fqmescli != NULL && globalregistry->fatal_condition) 
        fqmescli->DumpFatals();

	fprintf(stderr, "WARNING: Kismet changes the configuration of network devices.\n"
					"         In most cases you will need to restart networking for\n"
					"         your interface (varies per distribution/OS, but \n"
					"         usually:  /etc/init.d/networking restart\n\n");

    fprintf(stderr, "Kismet exiting.\n");
    exit(0);
}

void CatchChild(int sig) {
	int status;
	pid_t pid;

	if (globalregistry->spindown)
		return;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);

		if (pid != 0)
			break;
	}

	if (pid < 0) {
		return;
	}

	pid_fail frec;

	frec.pid = pid;
	frec.status = status;

	globalregistry->sigchild_vec.push_back(frec);
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
	printf("Nearly all of these options are run-time overrides for values in the\n"
		   "kismet.conf configuration file.  Permanent changes should be made to\n"
		   "the configuration file.\n");

	printf(" *** Generic Options ***\n");
	printf(" -f, --config-file <file>     Use alternate configuration file\n"
		   "     --no-line-wrap           Turn of linewrapping of output\n"
		   "                              (for grep, speed, etc)\n"
		   " -s, --silent                 Turn off stdout output after setup phase\n"
		   );

	printf("\n");
	KisNetFramework::Usage(argv);
	printf("\n");
	KisDroneFramework::Usage(argv);
	printf("\n");
	Dumpfile::Usage(argv);
	printf("\n");
	Packetsourcetracker::Usage(argv);

	exit(1);
}

int FlushDatafilesEvent(TIMEEVENT_PARMS) {
	if (globalreg->subsys_dumpfile_vec.size() == 0)
		return 1;

	_MSG("Saving data files", MSGFLAG_INFO);

	for (unsigned int x = 0; x < globalreg->subsys_dumpfile_vec.size(); x++) {
		globalreg->subsys_dumpfile_vec[x]->Flush();
	}

	return 1;
}

int InfoTimerEvent(TIMEEVENT_PARMS) {
	// Send the info frame to everyone
	globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_INFO), NULL);

	return 1;
}

int cmd_SHUTDOWN(CLIENT_PARMS) {
	_MSG("Received SHUTDOWN command", MSGFLAG_FATAL);
	CatchShutdown(0);

	return 1;
}

int main(int argc, char *argv[], char *envp[]) {
	exec_name = argv[0];
	char errstr[STATUS_MAX];
	char *configfilename = NULL;
	ConfigFile *conf;
	int option_idx = 0;
	int data_dump = 0;
	GlobalRegistry *globalreg;

	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGQUIT, CatchShutdown);
	signal(SIGCHLD, CatchChild);
    signal(SIGPIPE, SIG_IGN);

	// Turn off the getopt error reporting
	opterr = 0;
	optind = 0;

	// Look for "help"
	for (int x = 1; x < argc; x++) {
		if (strcmp(argv[x], "-h") == 0 ||
			strcmp(argv[x], "--help") == 0) {
			Usage(argv[0]);
			exit(1);
		}
	}

	// Start filling in key components of the globalregistry
	globalregistry = new GlobalRegistry;
	globalreg = globalregistry;

	globalregistry->version_major = VERSION_MAJOR;
	globalregistry->version_minor = VERSION_MINOR;
	globalregistry->version_tiny = VERSION_TINY;
	globalregistry->revision = REVISION;
	globalregistry->revdate = REVDATE;

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

	// Register the fatal queue with fatal and error messages
	globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL | MSGFLAG_ERROR);
	// Register the smart msg printer for everything
	globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);

#ifndef SYS_CYGWIN
	// Generate the root ipc packet capture and spawn it immediately, then register
	// and sync the packet protocol stuff
	if (getuid() != 0) {
		globalregistry->messagebus->InjectMessage("Not running as root - will try to "
			"launch root control binary (" + string(BIN_LOC) + "/kismet_capture) to "
			"control cards.", MSGFLAG_INFO);

		globalregistry->rootipc = new RootIPCRemote(globalregistry, "kismet_root");
		globalregistry->rootipc->SpawnIPC();
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

	// Reset the options index
	optind = 0;
	option_idx = 0;

	while (1) {
		int r = getopt_long(argc, argv, 
							"-f:sp:", 
							main_longopt, &option_idx);
		if (r < 0) break;

		if (r == 'f') {
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

	if (conf->FetchOpt("servername") == "") {
		globalregistry->servername = "Kismet";
	} else {
		globalregistry->servername = MungeToPrintable(conf->FetchOpt("servername"));
	}

	// Create the basic network/protocol server
	globalregistry->kisnetserver = new KisNetFramework(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	globalregistry->kisnetserver->RegisterClientCommand("SHUTDOWN",
														&cmd_SHUTDOWN,
														NULL);

	// Start the plugin handler
	globalregistry->plugintracker = new Plugintracker(globalregistry);

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

	}

#ifndef SYS_CYGWIN
	// Prep the tuntap device
	Dumpfile_Tuntap *dtun = new Dumpfile_Tuntap(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
#endif

	// Sync the IPC system -- everything that needs to be registered with the root 
	// IPC needs to be registered before now
	if (globalregistry->rootipc != NULL)
		globalregistry->rootipc->SyncIPC();

#ifndef SYS_CYGWIN
	// Fire the tuntap device setup now that we've sync'd the IPC system
	dtun->OpenTuntap();
#endif

	// Create the basic drone server
	globalregistry->kisdroneserver = new KisDroneFramework(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the alert tracker
	globalregistry->alertracker = new Alertracker(globalregistry);
	if (globalregistry->fatal_condition)
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

	// Process userspace plugins
	globalregistry->plugintracker->ScanUserPlugins();
	globalregistry->plugintracker->ActivatePlugins();
	if (globalregistry->fatal_condition) {
		globalregistry->messagebus->InjectMessage(
			"Failure during activating plugins\n", MSGFLAG_FATAL);
		CatchShutdown(-1);
	}

	// Enable cards from config/cmdline
	if (globalregistry->sourcetracker->LoadConfiguration() < 0)
		CatchShutdown(-1);

	// Create the basic network/protocol server
	globalregistry->kisnetserver->Activate();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the basic drone server
	globalregistry->kisdroneserver->Activate();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Register basic chain elements...  This is just instantiating a util class.
	// Nothing else talks to it, so we don't have to care about following it
	globalregistry->messagebus->InjectMessage("Inserting basic packet dissectors...",
											  MSGFLAG_INFO);
	globalregistry->builtindissector = new KisBuiltinDissector(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Assign the speech and sound handlers
	globalregistry->soundctl = new SoundControl(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the GPS components
	GpsWrapper *gpswrapper;
	globalregistry->messagebus->InjectMessage("Starting GPS components...",
											  MSGFLAG_INFO);
	gpswrapper = new GpsWrapper(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the spectools server
	SpectoolsClient *speccli;
	speccli = new SpectoolsClient(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the manuf db
	globalregistry->manufdb = new Manuf(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the network tracker
	globalregistry->messagebus->InjectMessage("Creating network tracker...",
											  MSGFLAG_INFO);
	globalregistry->netracker = new Netracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the channel tracker
	globalregistry->messagebus->InjectMessage("Creating channel tracker...",
											  MSGFLAG_INFO);
	Channeltracker *chantracker;
	chantracker = new Channeltracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the dumpfiles.  We don't have to assign the new dumpfile anywhere
	// because it puts itself in the global vector
	globalregistry->messagebus->InjectMessage("Registering dumpfiles...",
											  MSGFLAG_INFO);
#ifdef HAVE_LIBPCAP
	new Dumpfile_Pcap(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
#endif
	new Dumpfile_Netxml(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
	new Dumpfile_Nettxt(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
	new Dumpfile_Gpsxml(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
	new Dumpfile_String(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
	new Dumpfile_Alert(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	if (conf->FetchOpt("writeinterval") != "") {
		if (sscanf(conf->FetchOpt("writeinterval").c_str(), "%d", &data_dump) != 1) {
			data_dump = 0;
			globalregistry->messagebus->InjectMessage("Failed to parse data write "
													  "interval from config file",
													  MSGFLAG_ERROR);
		}
	}

	// Set the timer event to flush dumpfiles
	if (data_dump != 0 &&
		globalregistry->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * data_dump,
												   NULL, 1, 
												   &FlushDatafilesEvent, NULL) < 0) {
		globalregistry->messagebus->InjectMessage("Failed to register timer event to "
												  "sync data files for some reason.", 
												  MSGFLAG_FATAL);
		CatchShutdown(-1);
	}

	// Start stateful alert systems
	BSSTSStateAlert *bsstsa;
	bsstsa = new BSSTSStateAlert(globalregistry);
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

	/* Register the info protocol */
	_NPM(PROTO_REF_INFO) =
		globalregistry->kisnetserver->RegisterProtocol("INFO", 0, 1,
												  INFO_fields_text, 
												  &Protocol_INFO, NULL, NULL);

	globalregistry->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC,
											   NULL, 1, 
											   &InfoTimerEvent, NULL);

	// Blab about starting
	globalregistry->messagebus->InjectMessage("Kismet starting to gather packets",
											  MSGFLAG_INFO);

	// Start sources
	globalregistry->sourcetracker->StartSource(0);

	if (globalregistry->sourcetracker->FetchSourceVec()->size() == 0) {
		_MSG("No packet sources defined.  You MUST ADD SOME using the Kismet "
			 "client, or by placing them in the Kismet config file (" + 
			 string(SYSCONF_LOC) + "/" + config_base + ")", MSGFLAG_INFO);
	}
	
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

		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); x++) {
			if (globalregistry->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
				globalregistry->fatal_condition) {
				CatchShutdown(-1);
			}
		}
	}

	CatchShutdown(-1);
}
