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

#define KISMET_CLIENT

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
#include <errno.h>

#include "util.h"

#include "globalregistry.h"

#include "configfile.h"
#include "messagebus.h"

#include "timetracker.h"

#include "soundcontrol.h"

#include "ipc_remote.h"

#include "kis_clinetframe.h"

#include "kis_panel_widgets.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"

#include "kis_client_devicetracker.h"
#include "kis_client_phy80211.h"

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
	return;
#if 0
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
#endif
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

// This needs to be a global but nothing outside of this main file will
// use it, so we don't have to worry much about putting it in the globalreg.
FatalQueueMessageClient *fqmescli = NULL;

// Ultimate registry of global components
GlobalRegistry *globalregistry = NULL;

void CatchChild(int sig) {
	int status;
	pid_t pid;

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

// Catch our interrupt
void CatchShutdown(int sig) {
	/*
    if (sig == SIGPIPE)
        fprintf(stderr, "FATAL: A pipe closed unexpectedly, trying to shut down "
                "cleanly...\n");
	*/

	// Start a short shutdown cycle for 2 seconds
	fprintf(stderr, "\n*** KISMET CLIENT IS SHUTTING DOWN ***\n");
	globalregistry->spindown = 1;

	// Kill the sound entirely
	globalregistry->soundctl->Shutdown();
	
	time_t shutdown_target = time(0) + 5;
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

		if (max_fd == 0)
			break;

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

	// This kicks off the curses teardown entirely
	if (globalregistry->panel_interface != NULL) {
		globalregistry->panel_interface->Shutdown();
		delete globalregistry->panel_interface;
	}

	// Be noisy
	if (globalregistry->fatal_condition) {
		fprintf(stderr, "\n*** KISMET CLIENT SHUTTING DOWN.  ***\n");
	}
    
    // Dump fatal errors again
    if (fqmescli != NULL) 
        fqmescli->DumpFatals();

    fprintf(stderr, "Kismet client exiting.\n");
    exit(0);
}

void CatchWinch(int sig) {
	globalregistry->winch = true;
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION]\n", argv);
	printf(" *** Generic Options ***\n");
	printf(" -h, --help                   The obvious\n");

	exit(1);
}

int main(int argc, char *argv[], char *envp[]) {
	exec_name = argv[0];
	char errstr[STATUS_MAX];
	int option_idx = 0;

	// ------ WE MAY BE RUNNING AS ROOT ------
	
	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGQUIT, CatchShutdown);
	signal(SIGCHLD, CatchChild);
    signal(SIGPIPE, SIG_IGN);

	// Start filling in key components of the globalregistry
	globalregistry = new GlobalRegistry;

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

	globalregistry->messagebus->RegisterClient(fqmescli, MSGFLAG_FATAL);
	globalregistry->messagebus->RegisterClient(smartmsgcli, MSGFLAG_ALL);

	// Allocate some other critical stuff
	globalregistry->timetracker = new Timetracker(globalregistry);

	// Turn off the getopt error reporting
	opterr = 0;

	// Standard getopt parse run
	static struct option main_longopt[] = {
		{ "version", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while (1) {
		int r = getopt_long(argc, argv, 
							"-hv", 
							main_longopt, &option_idx);
		if (r < 0) break;
		if (r == 'h') {
			Usage(argv[0]);
			exit(1);
		} else if (r == 'v') {
			printf("Kismet %s-%s-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY);
			exit(1);
		}
	}

	// Create the sound control
	globalregistry->soundctl = new SoundControl(globalregistry);

	// Create the panel interface
	globalregistry->panel_interface = new KisPanelInterface(globalregistry);
	if (globalregistry->fatal_condition)
		CatchShutdown(-1);

	// Create the client-side devicetracker
	Client_Devicetracker *cdt = new Client_Devicetracker(globalregistry);
	cdt->RegisterPhyHandler(new Client_Phy80211(globalregistry));

	// Make the main panel and assign it to the interface
	Kis_Main_Panel *mainp = new Kis_Main_Panel(globalregistry, 
											   globalregistry->panel_interface);
	mainp->Position(0, 0, LINES, COLS);
	globalregistry->panel_interface->AddPanel(mainp);
	mainp->Startup();

	// Kickstart our saved plugins
	globalregistry->panel_interface->LoadPlugins();

#if 0
	KisNetClient *kcli = new KisNetClient(globalregistry);
	kcli->Connect("tcp://localhost:2501", 1);
#endif

	signal(SIGWINCH, CatchWinch);

	globalregistry->messagebus->InjectMessage("Welcome to the Kismet Newcore "
											  "Client... Press '`' or '~' to "
											  "activate menus.", 
											  MSGFLAG_INFO);

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
			if (errno != EINTR && errno != EAGAIN) {
				snprintf(errstr, STATUS_MAX, "Main select loop failed: %s",
						 strerror(errno));
				CatchShutdown(-1);
			}

			continue;
		}

		if (globalregistry->winch) {
			globalregistry->winch = false;
			if (globalregistry->panel_interface != NULL) 
				globalregistry->panel_interface->ResizeInterface();
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
