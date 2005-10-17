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

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include <sys/types.h>
#include <unistd.h>

#include "ipc_remote.h"

void IPC_MessageClient::ProcessMessage(string in_msg, int in_flags) {
	// Push it via the IPC
	((IPCRemote *) auxptr)->PushMessage(int_msg, in_flags);
}

int ipc_msg_callback(IPC_CMD_PARMS) {
	// Child IPC does nothing with a MSG frame
	if (parent == 0)
		return 0;

	// Blow up on short IPC
	if (len < 5) {
		_MSG("IPC messagebus handler got a short message block",
			 MSGFLAG_ERROR);
		return -1;
	}

	// Strip it apart and inject it into the message bus
	ipc_msgbus_pass *pass = (ipc_msgbus_pass *) data;

	_MSG(pass->msg, pass->msg_flags);

	return 1;
}

IPCRemote::IPCRemote() {
	fprintf(stderr, "FATAL OOPS:  IPCRemote called w/ no globalreg\n");
	exit(1);
}

IPCRemote::IPCRemote(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	next_cmdid = 0;
	buf = NULL;
	ipc_pid = 0;
	ipc_spawned = 0;

	// Register builtin commands
	msg_cmd_id = RegisterIPCCmd(ipc_msg_callback);
}

int IPCRemote::RegisterIPCCmd(IPCmdCallback in_callback) {
	if (ipc_spawned) {
		_MSG("IPC_Remote - Tried to register a command after the IPC agent has "
			 "been spawned.  Commands must be registered before Spawn().",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	next_cmdid++;

	ipc_cmd_map[next_cmdid] = in_callback;

	return next_cmdid;
}

int IPCRemote::SpawnIPC() {
	// Fill in our state stuff
	spawneduid = getuid();
	
	// Generate the socket pair before the split
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sockpair) < 0) {
		_MSG("Unable to great socket pair for IPC communication: " +
			 strerror(errno), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Fork and launch the child control loop & set up the rest of our internal
	// info.
	if ((ipc_pid = fork()) < 0) {
		_MSG("Unable to fork() and create child process for IPC communication: " +
			 strerror(errno), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Split into the IPC child control loop if we've forked
	if (ipc_pid == 0) {
		IPC_Child_Loop();
		exit(0);
	}

	// We've spawned, can't set new commands anymore
	ipc_spawned = 1;

	// Make a ring buffer for the parent side
	buf = new RingBuffer(8192);

	// Close half the socket pair
	close(sockpair[0]);
}

void IPCRemote::IPC_Child_Loop() {
	fd_set rset, wset;

	// Close the other half of the socket pair
	close(sockpair[1]);

	// Kluge in a new message bus to talk to our parent and give it only
	// the IPC client to replicate messages
	globalreg->messagebus = new MessageBus;
	IPC_MessageClient *ipcmc = new IPC_MessageClient(globalreg, this);
	globalreg->messagebus->RegisterMessageClient(ipcmc, MSGFLAG_ALL);

	// Make a new child ringbuffer
	buf = new RingBuffer(8192);

	// ignore a bunch of signals
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	while (1) {
		int max_fd = 0;

		FD_ZERO(&rset);
		FD_ZERO(&wset);

		FD_SET(sockpair[0], &rset);
		max_fd = sockpair[0];

		// Do we have data to send?
		if (buf->FetchLen() > 0)
			FD_SET(sockpair[0], &wset);

		struct timeval tm;
		tm.tv_sec = 1;
		tm.tv_usec = 0;

		// Timeout after 1 second if we stopped getting commands
		if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
			// Die violently
			fprintf(stderr, "FATAL OOPS:  IPC command child %d got select() "
					"error and cannot continue cleanly: %s\n",
					getpid(), strerror(errno));
			exit(1);
		}

		// Handle in/out data

	}
}

