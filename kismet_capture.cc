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

#include "messagebus.h"

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

#include "netframework.h"
#include "tcpserver.h"
// Include the stubbed empty netframe code
#include "kis_netframe.h"
#include "kis_droneframe.h"

#include "gpswrapper.h"

#include "ipc_remote.h"

#ifdef HAVE_CAPABILITY
#include <sys/capability.h>
#include <sys/prctl.h>
#endif


#ifndef exec_name
char *exec_name;
#endif

// One of our few globals in this file
int glob_linewrap = 1;
int glob_silent = 0;

// Ultimate registry of global components
GlobalRegistry *globalreg = NULL;

int Usage(char *argv) {
    printf("Usage: None\n");
	printf("This is a helper binary meant to be integrated with kismet_server for\n"
		   "controlling packet sources.  It is not useful when called directly.\n");
	exit(1);
}

void CatchShutdown(int) {
	exit(1);
}

void DropPrivCapabilities() {
#ifdef HAVE_CAPABILITY
	// Modeled from wireshark dumpcap
	// Enable NET_ADMIN and NET_RAW to get some control and capture abilities,
	// then drop our SUID privs

	cap_value_t cap_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };
	int cl_len = sizeof(cap_list) / sizeof(cap_value_t);

	cap_t caps = cap_init(); 

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
		_MSG("kismet_capture prctl() failed " + string(strerror(errno)),
			 MSGFLAG_ERROR);
	}

	cap_set_flag(caps, CAP_PERMITTED,   cl_len, cap_list, CAP_SET);
	cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET);

	if (cap_set_proc(caps)) {
		_MSG("kismet_capture cap_set_proc() failed: " + string(strerror(errno)),
			 MSGFLAG_ERROR);
	}

	cap_set_flag(caps, CAP_EFFECTIVE,   cl_len, cap_list, CAP_SET);
	if (cap_set_proc(caps)) {
		_MSG("kismet_capture cap_set_proc() failed: " + string(strerror(errno)),
			 MSGFLAG_ERROR);
	}

	cap_free(caps);
#endif
}

int main(int argc, char *argv[], char *envp[]) {
	exec_name = argv[0];
	char errstr[STATUS_MAX];

	// Catch the interrupt handler to shut down
    signal(SIGINT, CatchShutdown);
    signal(SIGTERM, CatchShutdown);
    signal(SIGHUP, CatchShutdown);
    signal(SIGPIPE, SIG_IGN);

	// Start filling in key components of the globalregistry
	globalreg = new GlobalRegistry;

	// Copy for modules
	globalreg->argc = argc;
	globalreg->argv = argv;
	globalreg->envp = envp;

	// Create the message bus
	globalreg->messagebus = new MessageBus;

	// Create the IPC system
	globalreg->rootipc = new IPCRemote(globalreg, "root capture control");

	if (globalreg->rootipc->SetChildExecMode(argc, argv) < 0) {
		fprintf(stderr, "FATAL:  Failed to attach to parent IPC.  Do not run this "
				"directly from the command line, it is meant to be run inside the "
				"Kismet IPC framework.\n");
		exit(1);
	}

	// Add the IPC messagebus
	IPC_MessageClient *ipccli =
		new IPC_MessageClient(globalreg, globalreg->rootipc);
	globalreg->messagebus->RegisterClient(ipccli, MSGFLAG_ALL);

	DropPrivCapabilities();
	
	// Allocate some other critical stuff
	globalreg->timetracker = new Timetracker(globalreg);

	// Create the stubbed network/protocol server
	globalreg->kisnetserver = new KisNetFramework(globalreg);	

	// Create the packet chain - PST uses it to grab frames to send to IPC
	globalreg->packetchain = new Packetchain(globalreg);
	if (globalreg->fatal_condition)
		CatchShutdown(-1);

	// Create the packetsourcetracker
	globalreg->sourcetracker = new Packetsourcetracker(globalreg);
	if (globalreg->fatal_condition)
		CatchShutdown(-1);

	globalreg->sourcetracker->RegisterIPC(globalreg->rootipc, 1);

	// Add the packet sources
#ifdef USE_PACKETSOURCE_PCAPFILE
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Pcapfile(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_WEXT
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Wext(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_MADWIFI
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Madwifi(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_MADWIFING
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_MadwifiNG(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_WRT54PRISM
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Wrt54Prism(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_DRONE
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Drone(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_BSDRT
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_BSDRT(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_IPWLIVE
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Ipwlive(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_AIRPCAP
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_AirPcap(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif
#ifdef USE_PACKETSOURCE_DARWIN
	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_Darwin(globalreg)) < 0 || globalreg->fatal_condition) 
		CatchShutdown(-1);
#endif

	if (globalreg->fatal_condition)
		CatchShutdown(-1);

	int max_fd = 0;
	fd_set rset, wset;
	struct timeval tm;

	// Core loop
	while (1) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		max_fd = 0;

		if (globalreg->fatal_condition)
			CatchShutdown(-1);

		// Collect all the pollable descriptors
		for (unsigned int x = 0; x < globalreg->subsys_pollable_vec.size(); x++) 
			max_fd = 
				globalreg->subsys_pollable_vec[x]->MergeSet(max_fd, &rset, 
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

		globalreg->timetracker->Tick();

		for (unsigned int x = 0; x < globalreg->subsys_pollable_vec.size(); 
			 x++) {
			if (globalreg->subsys_pollable_vec[x]->Poll(rset, wset) < 0 &&
				globalreg->fatal_condition) {
				CatchShutdown(-1);
			}
		}
	}

	CatchShutdown(-1);
}
