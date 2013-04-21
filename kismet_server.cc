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

#include "kis_dlt_ppi.h"
#include "kis_dlt_radiotap.h"
#include "kis_dlt_prism2.h"

#include "kis_dissector_ipdata.h"

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
#include "alertracker.h"

#include "netframework.h"
#include "tcpserver.h"
#include "kis_netframe.h"
#include "kis_droneframe.h"

#include "soundcontrol.h"

#include "gpswrapper.h"

#include "netracker.h"
#include "devicetracker.h"
#include "phy_80211.h"

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

#include "manuf.h"

#include "battery.h"

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

int battery_proto_ref = -1;
int critfail_proto_ref = -1;

// The info protocol lives in here for lack of anywhere better to live
enum INFO_fields {
	INFO_networks, INFO_packets, INFO_cryptpackets,
	INFO_noisepackets, INFO_droppedpackets, INFO_packetrate, 
	INFO_filteredpackets, INFO_clients, INFO_llcpackets, INFO_datapackets,
	INFO_numsources, INFO_numerrorsources,
	INFO_maxfield
};

const char *INFO_fields_text[] = {
	"networks", "packets", "crypt", "noise", "dropped", "rate", 
	"filtered", "clients", "llcpackets", "datapackets", "numsources",
	"numerrorsources",
	NULL
};

enum BATTERY_fields {
	BATTERY_percentage, BATTERY_charging, BATTERY_ac, BATTERY_remaining,
	BATTERY_maxfield
};

const char *BATTERY_fields_text[] = {
	"percentage", "charging", "ac", "remaining", NULL
};

enum CRITFAIL_fields {
	CRITFAIL_id, CRITFAIL_time, CRITFAIL_message, 
	CRITFAIL_maxfield
};

const char *CRITFAIL_fields_text[] = {
	"id", "time", "message", NULL
};

int Protocol_INFO(PROTO_PARMS) {
	ostringstream osstr;
	int num_error;
	vector<pst_packetsource *> *sourcevec = globalreg->sourcetracker->FetchSourceVec();

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
				osstr << sourcevec->size();
				cache->Cache(fnum, osstr.str());
				break;
			case INFO_numerrorsources:
				num_error = 0;
				for (unsigned int e = 0; e < sourcevec->size(); e++) {
					if ((*sourcevec)[e]->error)
						num_error++;
				}
				osstr << num_error;
				cache->Cache(fnum, osstr.str());
				break;
		}

		// print the newly filled in cache
		out_string += cache->GetCache(fnum) + " ";
    }

    return 1;
}

int Protocol_BATTERY(PROTO_PARMS) {
	kis_battery_info *b = (kis_battery_info *) data;

	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		if (fnum >= BATTERY_maxfield) {
			out_string += "Unknown field requested.";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		switch (fnum) {
			case BATTERY_percentage:
				scratch = IntToString(b->percentage);
				break;
			case BATTERY_charging:
				scratch = IntToString(b->charging);
				break;
			case BATTERY_ac:
				scratch = IntToString(b->ac);
				break;
			case BATTERY_remaining:
				scratch = IntToString(b->remaining_sec);
				break;
		}

		out_string += scratch;
		cache->Cache(fnum, scratch);

		out_string += " ";
	}

	return 1;
}

void Protocol_CRITFAIL_enable(PROTO_ENABLE_PARMS) {
	for (unsigned int x = 0; x < globalreg->critfail_vec.size(); x++) {
		kis_protocol_cache cache;

		if (in_fd == -1) {
			if (globalreg->kisnetserver->SendToAll(critfail_proto_ref, (void *) x) < 0)
				break;
		} else {
			if (globalreg->kisnetserver->SendToClient(in_fd, critfail_proto_ref,
													  (void *) x, &cache) < 0)
				break;
		}

		// Often enough to be really obvious
		if (time(0) % 5 == 0) 
			_MSG("!!! CRITICAL ERROR !!! - " + globalreg->critfail_vec[x].fail_msg + 
				 " - Kismet will not operate correctly.", MSGFLAG_FATAL);
	}
}

int Protocol_CRITFAIL(PROTO_PARMS) {
	// This is stupid but it makes gcc shut up.  Maybe.
	unsigned long int cf_lnum = (unsigned long int) data;
	unsigned int cf_num = (unsigned int) cf_lnum;

	if (cf_num >= globalreg->critfail_vec.size())
		cf_num = 0;

	string scratch;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		if (fnum >= CRITFAIL_maxfield) {
			out_string += "Unknown field requested.";
			return -1;
		}

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		switch (fnum) {
			case CRITFAIL_id:
				scratch = IntToString(cf_num);
				break;
			case CRITFAIL_time:
				scratch = IntToString(globalreg->critfail_vec[cf_num].fail_time);
				break;
			case CRITFAIL_message:
				scratch = "\001" + globalreg->critfail_vec[cf_num].fail_msg + "\001";
				break;
		}

		out_string += scratch;
		cache->Cache(fnum, scratch);

		out_string += " ";
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

// Catch our interrupt
void CatchShutdown(int sig) {
	if (sig == 0) {
		kill(getpid(), SIGTERM);
		return;
	}

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

	// Start a short shutdown cycle for 2 seconds
	if (daemonize == 0)
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

	globalregistry->pcapdump = NULL;

	if (globalregistry->netracker != NULL) {
		delete globalregistry->netracker;
		globalregistry->netracker = NULL;
	}

	if (globalregistry->devicetracker != NULL) {
		delete globalregistry->devicetracker;
		globalregistry->devicetracker = NULL;
	}

	if (globalregistry->plugintracker != NULL)
		globalregistry->plugintracker->ShutdownPlugins();

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

    exit(0);
}

void CatchChild(int sig) {
	int status;
	pid_t pid;

	if (globalregistry->spindown)
		return;

	// printf("debug - sigchild\n");

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);

		// printf("debug - pid %d status %d exit %d\n", pid, status, WEXITSTATUS(status));

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
	printf(" -v, --version                Show version\n"
		   " -f, --config-file <file>     Use alternate configuration file\n"
		   "     --no-line-wrap           Turn of linewrapping of output\n"
		   "                              (for grep, speed, etc)\n"
		   " -s, --silent                 Turn off stdout output after setup phase\n"
		   "     --daemonize              Spawn detatched in the background\n"
		   "     --no-plugins             Do not load plugins\n"
		   "     --no-root				  Do not start the kismet_capture binary \n"
		   "                               when not running as root.  For no-priv \n"
		   "                               remote capture ONLY.\n"
		   "     --homedir <path>         Use an alternate path as the home \n"
		   "                               directory instead of the user entry\n"
		   );

	printf("\n");
	KisNetFramework::Usage(argv);
	printf("\n");
	KisDroneFramework::Usage(argv);
	printf("\n");
	Dumpfile::Usage(argv);
	printf("\n");
	Packetsourcetracker::Usage(argv);
	printf("\n");
	Netracker::Usage(argv);
	printf("\n");
	GpsWrapper::Usage(argv);

	exit(1);
}

int FlushDatafilesEvent(TIMEEVENT_PARMS) {
	if (globalreg->subsys_dumpfile_vec.size() == 0)
		return 1;

	int r = 0;

	for (unsigned int x = 0; x < globalreg->subsys_dumpfile_vec.size(); x++) {
		if (globalreg->subsys_dumpfile_vec[x]->Flush())
			r = 1;
	}

	if (r)
		_MSG("Saved data files", MSGFLAG_INFO);

	return 1;
}

int BaseTimerEvent(TIMEEVENT_PARMS) {
	// Send the info frame to everyone
	globalreg->kisnetserver->SendToAll(_NPM(PROTO_REF_INFO), NULL);

	// Send the battery frame
	kis_battery_info batinfo;
	Fetch_Battery_Info(&batinfo);
	globalreg->kisnetserver->SendToAll(battery_proto_ref, &batinfo);

	// Send critfails to everyone and print out as messages
	Protocol_CRITFAIL_enable(-1, globalreg, NULL);

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

	// Timer for silence
	int local_silent = 0;
	int startroot = 1;

	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGQUIT, CatchShutdown);
	signal(SIGCHLD, CatchChild);
    signal(SIGPIPE, SIG_IGN);

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

	int startup_ipc_id = -1;

	int max_fd = 0;
	fd_set rset, wset;
	struct timeval tm;

	// Turn off the getopt error reporting
	opterr = 0;
	optind = 0;

	const int nlwc = globalregistry->getopt_long_num++;
	const int dwc = globalregistry->getopt_long_num++;
	const int npwc = globalregistry->getopt_long_num++;
	const int nrwc = globalregistry->getopt_long_num++;
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
		{ "no-root", no_argument, 0, nrwc },
		{ "homedir", required_argument, 0, hdwc },
		{ 0, 0, 0, 0 }
	};

	// Reset the options index
	optind = 0;
	option_idx = 0;

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
		} else if (r == nrwc) {
			startroot = 0;
		} else if (r == hdwc) {
			globalregistry->homepath = string(optarg);
		}
	}

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
	if (getuid() != 0 && startroot == 0) {
		globalregistry->messagebus->InjectMessage("Not running as root, and --no-root "
			"was requested.  Will not attempt to spawn Kismet capture binary.  This "
			"will make it impossible to add sources which require root.", 
			MSGFLAG_INFO | MSGFLAG_PRINTERROR);
	} else if (getuid() != 0) {
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
			globalregistry->servername = "Kismet";
		else
			globalregistry->servername = string(hostname);
	} else {
		globalregistry->servername = MungeToPrintable(conf->FetchOpt("servername"));
	}

	// Create the packet chain
	globalregistry->packetchain = new Packetchain(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the basic network/protocol server
	globalregistry->kisnetserver = new KisNetFramework(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	globalregistry->kisnetserver->RegisterClientCommand("SHUTDOWN",
														&cmd_SHUTDOWN,
														NULL);

	// Create the packetsourcetracker
	globalregistry->sourcetracker = new Packetsourcetracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Register the IPC
	if (globalregistry->rootipc != NULL) {
		globalregistry->sourcetracker->RegisterIPC(globalregistry->rootipc, 0);

	}

#if !defined(SYS_CYGWIN) && !defined(SYS_ANDROID)
	// Prep the tuntap device
	Dumpfile_Tuntap *dtun = new Dumpfile_Tuntap(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
#endif

	// Sync the IPC system -- everything that needs to be registered with the root 
	// IPC needs to be registered before now
	if (globalregistry->rootipc != NULL) {
		globalregistry->rootipc->SyncRoot();
		globalregistry->rootipc->SyncIPC();

#if 0
		// Another startup spin to make sure the sync flushes through
		time_t ipc_spin_start = time(0);

		while (1) {
			printf("debug - sync spin\n");

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

			if (globalregistry->rootipc->FetchReadyState() > 0) {
				printf("debug - ready\n");
				break;
			}

			if (time(0) - ipc_spin_start > 2) {
				printf("debug - timed out on sync spin\n");
				break;
			}
		}

		printf("debug - out of sync spin\n");
#endif
	}

#if !defined(SYS_CYGWIN) && !defined(SYS_ANDROID)
	// Fire the tuntap device setup now that we've sync'd the IPC system
	dtun->OpenTuntap();
#endif

	// Fire the startup command to IPC, we're done and it can drop privs
	if (globalregistry->rootipc != NULL) {
		ipc_packet *ipc = (ipc_packet *) malloc(sizeof(ipc_packet));
		memset(ipc, 0, sizeof(ipc_packet));
		ipc->data_len = 0;
		ipc->ipc_ack = 0;
		ipc->ipc_cmdnum = startup_ipc_id;

		globalreg->rootipc->SendIPC(ipc);
	}

	// Create the basic drone server
	globalregistry->kisdroneserver = new KisDroneFramework(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the alert tracker
	globalregistry->alertracker = new Alertracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the device tracker
	_MSG("Creating device tracker...", MSGFLAG_INFO);
	globalregistry->devicetracker = new Devicetracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Register the DLT handlers
	new Kis_DLT_PPI(globalregistry);
	new Kis_DLT_Radiotap(globalregistry);
	new Kis_DLT_Prism2(globalregistry);

	new Kis_Dissector_IPdata(globalregistry);

	// Register the base PHYs
	if (globalregistry->devicetracker->RegisterPhyHandler(new Kis_80211_Phy(globalregistry)) < 0 || globalregistry->fatal_condition) 
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
	globalregistry->kisnetserver->Activate();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the basic drone server
	globalregistry->kisdroneserver->Activate();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

#if 0
	// Register basic chain elements...  This is just instantiating a util class.
	// Nothing else talks to it, so we don't have to care about following it
	globalregistry->messagebus->InjectMessage("Inserting basic packet dissectors...",
											  MSGFLAG_INFO);
	globalregistry->builtindissector = new KisBuiltinDissector(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
#endif

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

	// Create the manuf db
	globalregistry->manufdb = new Manuf(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the network tracker
	if (conf->FetchOptBoolean("disablenettracker", 0) == 0) {
		globalregistry->messagebus->InjectMessage("Creating network tracker...",
												  MSGFLAG_INFO);
		globalregistry->netracker = new Netracker(globalregistry);
		if (globalregistry->fatal_condition)
			CatchShutdown(-1);
	} else {
		_MSG("Disabling deprecated nettracker core; this will disable some "
			 "protocols and log files.", MSGFLAG_INFO);
	}

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
	// Pcapdump is special since plugins might hook it
	globalreg->pcapdump = new Dumpfile_Pcap(globalregistry);
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
	if (globalregistry->plugintracker != NULL) {
		globalregistry->plugintracker->LastChancePlugins();
		if (globalregistry->fatal_condition)
			CatchShutdown(-1);
	}

	// Initialize the crc tables
	crc32_init_table_80211(globalregistry->crc32_table);

	/* Register the info protocol */
	if (globalreg->netracker != NULL) {
		_NPM(PROTO_REF_INFO) =
			globalregistry->kisnetserver->RegisterProtocol("INFO", 0, 1,
														   INFO_fields_text, 
														   &Protocol_INFO, NULL, NULL);
	} else {
		_MSG("Old nettracker core disabled, disabling deprecated *INFO sentence",
			 MSGFLAG_INFO);
	}

	battery_proto_ref =
		globalregistry->kisnetserver->RegisterProtocol("BATTERY", 0, 1,
												  BATTERY_fields_text, 
												  &Protocol_BATTERY, NULL, NULL);

	critfail_proto_ref =
		globalregistry->kisnetserver->RegisterProtocol("CRITFAIL", 0, 1,
													   CRITFAIL_fields_text,
													   &Protocol_CRITFAIL,
													   &Protocol_CRITFAIL_enable,
													   NULL);

	globalregistry->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC,
											   NULL, 1, 
											   &BaseTimerEvent, NULL);

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

	// Core loop
	while (1) {
		// printf("debug - %d - main loop tick\n", getpid());

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

		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); x++) {
			if (globalregistry->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
				globalregistry->fatal_condition) {
				CatchShutdown(-1);
			}
		}
	}

	CatchShutdown(-1);
}

// vim: ts=4:sw=4
