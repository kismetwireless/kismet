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

#include "macaddr.h"
#include "packet.h"

#include "packetsourcetracker.h"

#include "timetracker.h"
#include "alertracker.h"

#include "netframework.h"
#include "tcpserver.h"
#include "kis_netframe.h"

#include "speechcontrol.h"
#include "soundcontrol.h"

#include "gpsdclient.h"

#include "packetdissectors.h"
#include "netracker.h"

#ifndef exec_name
char *exec_name;
#endif

// Message clients that are attached at the master level
// Smart standard out client that understands the silence options
class SmartStdoutMessageClient : public MessageClient {
public:
    SmartStdoutMessageClient(GlobalRegistry *in_globalreg) :
        MessageClient(in_globalreg) { }
    virtual ~SmartStdoutMessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
};

void SmartStdoutMessageClient::ProcessMessage(string in_msg, int in_flags) {
    if ((in_flags & MSGFLAG_DEBUG))
        fprintf(stdout, "DEBUG: %s\n", in_msg.c_str());
    else if ((in_flags & MSGFLAG_INFO))
        fprintf(stdout, "INFO: %s\n", in_msg.c_str());
    else if ((in_flags & MSGFLAG_ERROR))
        fprintf(stdout, "ERROR: %s\n", in_msg.c_str());
    else if (in_flags & MSGFLAG_FATAL)
        fprintf(stderr, "FATAL: %s\n", in_msg.c_str());
    
    return;
}

// Queue of fatal alert conditions to spew back out at the end
class FatalQueueMessageClient : public MessageClient {
public:
    FatalQueueMessageClient(GlobalRegistry *in_globalreg) :
        MessageClient(in_globalreg) { }
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
        fprintf(stderr, "FATAL: %s\n", fatalqueue[x].c_str());
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
    // Shut down the packet sources
    if (globalregistry->sourcetracker != NULL) {
        globalregistry->sourcetracker->CloseSources();

        // Shut down the channel control child
        globalregistry->sourcetracker->ShutdownChannelChild();
    }

    // Shouldn't need to requeue fatal errors here since error shutdown means 
    // we just printed something about fatal errors.  Probably.

    fprintf(stderr, "Kismet exiting.\n");
    exit(1);
}

// Catch our interrupt
void CatchShutdown(int sig) {
    if (sig == SIGPIPE)
        fprintf(stderr, "FATAL: A pipe closed unexpectedly, trying to shut down "
                "cleanly...\n");

    string termstr = "Kismet server terminating.";
	if (globalregistry->kisnetserver != NULL) {
		globalregistry->kisnetserver->SendToAll(globalregistry->netproto_map[PROTO_REF_TERMINATE], (void *) &termstr);

		// Shutdown and flush all the ring buffers
		fprintf(stderr, "Shutting down Kismet server and flushing "
                "client buffers...\n");
		globalregistry->kisnetserver->Shutdown();
	}

	if (globalregistry->sourcetracker != NULL) {
		// Shut down the packet sources
		globalregistry->sourcetracker->CloseSources();

		// Shut down the channel control child
		globalregistry->sourcetracker->ShutdownChannelChild();
	}

	// Be noisy
	if (globalregistry->fatal_condition) {
		fprintf(stderr, "\n*** KISMET HAS ENCOUNTERED A FATAL ERROR AND CANNOT "
				"CONTINUE.  THE FATAL \n    CONDITIONS WILL BE LISTED. ***\n");
	}
    
    // Dump fatal errors again
    if (fqmescli != NULL) 
        fqmescli->DumpFatals();

    fprintf(stderr, "Kismet exiting.\n");
    exit(0);
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
    printf("Most (or all) of these options can (and should) be configured via the\n"
           "kismet.conf global config file, but can be overridden here.\n");
    printf("  -I, --initial-channel <n:c>  Initial channel to monitor on (default: 6)\n"
           "                                Format capname:channel\n"
           "  -x, --force-channel-hop      Forcibly enable the channel hopper\n"
           "  -X, --force-no-channel-hop   Forcibly disable the channel hopper\n"
           "  -t, --log-title <title>      Custom log file title\n"
           "  -n, --no-logging             No logging (only process packets)\n"
           "  -f, --config-file <file>     Use alternate config file\n"
           "  -c, --capture-source <src>   Packet capture source line (type,interface,name)\n"
           "  -C, --enable-capture-sources Comma separated list of named packet sources to use.\n"
           "  -l, --log-types <types>      Comma separated list of types to log,\n"
           "                                (ie, dump,cisco,weak,network,gps)\n"
           "  -d, --dump-type <type>       Dumpfile type (wiretap)\n"
           "  -m, --max-packets <num>      Maximum number of packets before starting new dump\n"
           "  -g, --gps <host:port>        GPS server (host:port or off)\n"
           "  -p, --port <port>            TCPIP server port for GUI connections\n"
           "  -a, --allowed-hosts <hosts>  Comma separated list of hosts allowed to connect\n"
           "  -s, --silent                 Don't send any output to console.\n"
           "  -N, --server-name            Server name\n"
           "  -v, --version                Kismet version\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

int FindSuidTarget(string in_username, GlobalRegistry *globalreg,
				   uid_t *ret_uid, gid_t *ret_gid) {
	struct passwd *pwordent;
	char *suid_user;
	uid_t suid_uid, real_uid;
	gid_t suid_gid;
	char errstr[1024];

	real_uid = getuid();

	suid_user = strdup(in_username.c_str());

	if ((pwordent = getpwnam(suid_user)) == NULL) {
		snprintf(errstr, 1024, "Could not find user '%s' for priv-drop.  Make sure "
				 "you have a valid user set for the 'suiduser' configuration entry "
				 "and that /etc/passwd is readable.  See the 'Installation & "
				 "Security' and 'Configuration' sections of the README file for "
				 "more information.", suid_user);
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		free(suid_user);
		return -1;
	}

	free(suid_user);

	suid_uid = pwordent->pw_uid;
	suid_gid = pwordent->pw_gid;

	if (suid_uid == 0) {
		snprintf(errstr, 1024, "Specifying a UID-0 user for the priv-drop is "
				 "pointless.  See the 'Installation & Security' and "
				 "'Configuration' sections of the README file for information "
				 "on how to properly configure Kismet for priv-drop.");
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	} else if (suid_uid != real_uid && real_uid != 0) {
		snprintf(errstr, 1024, "Kismet must be started as root (or as the "
				 "priv-drop target user) for priv-drop to work properly. "
				 "See the 'Installation & Security' and 'Configuration' sections "
				 "of the README file for more information.");
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	(*ret_uid) = suid_uid;
	(*ret_gid) = suid_gid;

	return 1;
}

int main(int argc,char *argv[]) {
	exec_name = argv[0];
	char errstr[STATUS_MAX];
	char *configfilename = NULL;
	ConfigFile *conf;
	uid_t suid_uid;
	gid_t suid_gid;
	string suiduser;
	int option_idx = 0;

	// ------ WE MAY BE RUNNING AS ROOT ------
	
	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, CatchShutdown);

	// Start filling in key components of the globalregistry
	globalregistry = new GlobalRegistry;

	// Copy for modules
	globalregistry->argc = argc;
	globalregistry->argv = argv;
	
	// First order - create our message bus and our client for outputting
	globalregistry->messagebus = new MessageBus;

	// Create a smart stdout client and allocate the fatal message client, 
	// add them to the messagebus
	SmartStdoutMessageClient *smartmsgcli = 
		new SmartStdoutMessageClient(globalregistry);
	fqmescli = new FatalQueueMessageClient(globalregistry);

	globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL);
	globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);

	// Allocate some other critical stuff
	globalregistry->timetracker = new Timetracker(globalregistry);

	globalregistry->start_time = time(0);
	globalregistry->timestamp = time(0);

	// Turn off the getopt error reporting
	opterr = 0;

	// Standard getopt parse run
	static struct option main_longopt[] = {
		{ "config-file", required_argument, 0, 'f' },
		{ 0, 0, 0, 0 }
	};

	while (1) {
		int r = getopt_long(argc, argv, 
							"-f:", 
							main_longopt, &option_idx);
		if (r < 0) break;
		switch (r) {
			case 'c':
				configfilename = strdup(optarg);
				break;
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
	
	conf = new ConfigFile;
	if (conf->ParseConfig(configfilename) < 0) {
		exit(1);
	}
	globalregistry->kismet_config = conf;

#ifdef HAVE_SUID
	// Process privdrop critical stuff
	if ((suiduser = conf->FetchOpt("suiduser")) == "") {
		snprintf(errstr, 1024, "No 'suiduser' directive found in the configuration "
				 "file.  Please refer to the 'Installation & Security' and "
				 "'Configuration' sections of the README file for more "
				 "information.");
		globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalregistry->fatal_condition = 1;
		CatchShutdown(-1);
	}

	if (FindSuidTarget(suiduser, globalregistry,
					   &suid_uid, &suid_gid) < 0 || globalregistry->fatal_condition) {
		CatchShutdown(-1);
	}

#else
	snprintf(errstr, 1024, "SUID priv-dropping has been DISABLED at compile time. "
			 "This is NOT reccomended as it may increase the risk to your system "
			 "from hostile remote data.  Please consult the 'Installation & "
			 "Security' and 'Configuration' sections of your README file.");
	globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_WARNING);
	sleep(1);
#endif

	// Assign the speech and sound handlers
	globalregistry->soundctl = new SoundControl(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);
	globalregistry->speechctl = new SpeechControl(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the basic network/protocol server
	globalregistry->kisnetserver = new KisNetFramework(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the packet chain
	globalregistry->packetchain = new Packetchain(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the packetsourcetracker
	globalregistry->sourcetracker = new Packetsourcetracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Bind sources as root
	globalregistry->sourcetracker->BindSources(1);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the channel process if necessary
	globalregistry->sourcetracker->SpawnChannelChild();
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Once the packet source and channel control is opened, we shouldn't need special
	// privileges anymore so lets drop to a normal user.  We also don't want to open 
	// our logfiles as root if we can avoid it.  Once we've dropped, we'll 
	// investigate our sources again and open any defered
#ifdef HAVE_SUID
	if (setgid(suid_gid) < 0) {
		snprintf(errstr, 1024, "Priv-drop to GID %d failed", suid_gid);
		globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		CatchShutdown(-1);
	}

	if (setuid(suid_uid) < 0) {
		snprintf(errstr, 1024, "Priv-drop to UID %d failed", suid_uid);
		globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		CatchShutdown(-1);
	} 

	snprintf(errstr, 1024, "Dropped privs to %s (%d) gid %d", suiduser.c_str(), 
			 suid_uid, suid_gid);
	globalregistry->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
#endif

	// ------ WE ARE NOW RUNNING AS THE TARGET (MAYBE) ------

	// Bind sources as non-root
	globalregistry->sourcetracker->BindSources(0);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Register basic chain elements
	globalregistry->messagebus->InjectMessage("Inserting basic packet dissectors...",
											  MSGFLAG_INFO);
	globalregistry->packetchain->RegisterHandler(&kis_80211_dissector, NULL, 
												 CHAINPOS_LLCDISSECT, -100);
	globalregistry->packetcomp_map[PACK_COMP_80211] = 
		globalregistry->packetchain->RegisterPacketComponent("80211_info");
	
	// Create the GPS server
	globalregistry->messagebus->InjectMessage("Starting GPSD client...",
											  MSGFLAG_INFO);
	globalregistry->gpsd = new GPSDClient(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the network tracker
	globalregistry->messagebus->InjectMessage("Creating network tracker...",
											  MSGFLAG_INFO);
	globalregistry->netracker = new Netracker(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

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

		for (unsigned int x = 0; x < globalregistry->subsys_pollable_vec.size(); 
			 x++) {
			if (globalregistry->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
				globalregistry->fatal_condition) {
				CatchShutdown(-1);
			}
		}

		globalregistry->timetracker->Tick();
	}

	CatchShutdown(-1);
}
