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
#include <sstream>

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "ipc_remote.h"

void IPC_MessageClient::ProcessMessage(string in_msg, int in_flags) {
	// Build it into a msgbus ipc block ... is there a smarter way to
	// build these things?
	ipc_packet *pack = 
		(ipc_packet *) malloc(sizeof(ipc_packet) + 8 + in_msg.length() + 1);
	ipc_msgbus_pass *msgb = (ipc_msgbus_pass *) pack->data;

	msgb->msg_flags = in_flags;
	msgb->msg_len = in_msg.length() + 1;
	snprintf(msgb->msg, msgb->msg_len, in_msg.c_str());

	pack->data_len = 8 + in_msg.length() + 1;

	pack->ipc_cmdnum = ((IPCRemote *) auxptr)->msg_cmd_id;

	// Push it via the IPC
	((IPCRemote *) auxptr)->SendIPC(pack);

	// It gets freed once its sent so don't free it ourselves here
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

int ipc_die_callback(IPC_CMD_PARMS) {
	// Child receiving DIE command shuts down
	if (parent == 0) {
		// Call the internal shutdown process
		((IPCRemote *) auxptr)->IPCDie();
		// Exit entirely, if we didn't already
		exit(1);
	}

	// Parent receiving DIE command knows child is dieing for some
	// reason, send a message note, we'll figure out later if this is
	// fatal
	ostringstream osstr;
	
	osstr << "IPC controller got notification that IPC child process " <<
		(int) ((IPCRemote *) auxptr)->FetchSpawnPid() << " is shutting down.";
	_MSG(osstr.str(), MSGFLAG_INFO);

	// Call the internal die sequence to make sure the child pid goes down
	((IPCRemote *) auxptr)->IPCDie();
	
	return 1;
}

IPCRemote::IPCRemote() {
	fprintf(stderr, "FATAL OOPS:  IPCRemote called w/ no globalreg\n");
	exit(1);
}

IPCRemote::IPCRemote(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	next_cmdid = 0;
	ipc_pid = 0;
	ipc_spawned = 0;

	// Register builtin commands
	die_cmd_id = RegisterIPCCmd(ipc_die_callback, this);
	msg_cmd_id = RegisterIPCCmd(ipc_msg_callback, this);
}

int IPCRemote::RegisterIPCCmd(IPCmdCallback in_callback, void *in_aux) {
	if (ipc_spawned) {
		_MSG("IPC_Remote - Tried to register a command after the IPC agent has "
			 "been spawned.  Commands must be registered before Spawn().",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	next_cmdid++;

	ipc_cmd_rec *rec = new ipc_cmd_rec;
	rec->auxptr = in_aux;
	rec->callback = in_callback;

	ipc_cmd_map[next_cmdid] = rec;

	return next_cmdid;
}

int IPCRemote::SpawnIPC() {
	// Fill in our state stuff
	spawneduid = getuid();
	
	// Generate the socket pair before the split
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sockpair) < 0) {
		_MSG("Unable to great socket pair for IPC communication: " +
			 string(strerror(errno)), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Fork and launch the child control loop & set up the rest of our internal
	// info.
	if ((ipc_pid = fork()) < 0) {
		_MSG("Unable to fork() and create child process for IPC communication: " +
			 string(strerror(errno)), MSGFLAG_FATAL);
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

	// Close half the socket pair
	close(sockpair[0]);

	return 1;
}

int IPCRemote::ShutdownIPC() {
	if (ipc_spawned == 0) 
		return 0;

	// Nothing special here, just a die frame.  Beauty is, we don't care
	// if we're the parent of the child, a clean shutdown will signal the other
	// side it's time to shuffle off
	ipc_packet *pack = (ipc_packet *) malloc(sizeof(ipc_packet));
	pack->data_len = 0;
	pack->ipc_cmdnum = die_cmd_id;

	SendIPC(pack);

	return 1;
}

int IPCRemote::SendIPC(ipc_packet *pack) {
	// This is really just an enqueue system
	pack->sentinel = IPCRemoteSentinel;
	cmd_buf.push_back(pack);

	return 1;
}

void IPCRemote::IPC_Child_Loop() {
	fd_set rset, wset;

	// Obviously we're spawned
	ipc_spawned = 1;

	// Close the other half of the socket pair
	close(sockpair[1]);

	// Kluge in a new message bus to talk to our parent and give it only
	// the IPC client to replicate messages
	globalreg->messagebus = new MessageBus;
	IPC_MessageClient *ipcmc = new IPC_MessageClient(globalreg, this);
	globalreg->messagebus->RegisterClient(ipcmc, MSGFLAG_ALL);

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
		if (cmd_buf.size() > 0)
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

void IPCRemote::IPCDie() {
	// If we're the child...
	if (ipc_pid == 0 && ipc_spawned) {
		// Shut down the child socket fd
		close(sockpair[0]);
		// and exit, we're done
		exit(0);
	} else if (ipc_spawned) {
		// otherwise if we're the parent...
		// Shut down the socket
		close(sockpair[1]);

		// Wait for the child process to be dead

		ostringstream osstr;

		osstr << "IPC controller waiting for IPC child process " <<
			(int) ipc_pid << " to end.";
		_MSG(osstr.str(), MSGFLAG_INFO);

		wait4(ipc_pid, NULL, 0, NULL);

		ipc_pid = 0;
		ipc_spawned = 0;
	}
}

unsigned int IPCRemote::MergeSet(unsigned int in_max_fd, fd_set *out_rset,
								 fd_set *out_wset) {
	// Don't call this on the child, we have a micro-select loop in the child
	// process... also do nothing if we haven't spawned yet
	if (ipc_pid == 0 || ipc_spawned == 0)
		return in_max_fd;

	// Set the socket to be read
	FD_SET(sockpair[1], out_rset);
	
	// Set the write if we have data queued
	if (cmd_buf.size() > 0)
		FD_SET(sockpair[1], out_wset);

	if (in_max_fd < (unsigned int) sockpair[1])
		return sockpair[1];

	return in_max_fd;
}

int IPCRemote::Poll(fd_set& in_rset, fd_set& in_wset) {
	// This CAN be called by the parent or the child.  In the parent it's called
	// by the normal pollable architecture.  In the child we manually call it
	// from our micro-select loop.

	ostringstream osstr;

	// Process packets in
	if (FD_ISSET(sockpair[1], &in_rset)) {
		ipc_packet ipchdr;
		ipc_packet *fullpack;
		int ret;

		// Peek at the packet header
		if ((ret = recv(sockpair[1], &ipchdr, 
						sizeof(ipc_packet), MSG_PEEK)) < (int) sizeof(ipc_packet)) {
			if (ret < 0) {
				if (ipc_pid == 0) 
					osstr << "IPC child got error receiving packet header "
						"from controller: " << strerror(errno);
				else
					osstr << "IPC controller got error receiving packet header "
						"from IPC child pid " << ipc_pid << ": " << strerror(errno);
				_MSG(osstr.str(), MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			} else {
				return 0;
			}
		}

		// validate the ipc header
		if (ipchdr.sentinel != IPCRemoteSentinel) {
			if (ipc_pid == 0) 
				osstr << "IPC child got error receiving packet header from "
					"controller: Invalid IPC sentinel value";
			else
				osstr << "IPC controller got error receiving packet header "
					"from IPC child pid " << ipc_pid << ": Invalid IPC "
					"sentinel value";
			_MSG(osstr.str(), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		// See if its a command we understand
		map<unsigned int, ipc_cmd_rec *>::iterator cbitr = 
			ipc_cmd_map.find(ipchdr.ipc_cmdnum);
		if (cbitr == ipc_cmd_map.end()) {
			if (ipc_pid == 0) 
				osstr << "IPC child got error receiving packet header from "
					"controller: Unknown IPC command";
			else
				osstr << "IPC controller got error receiving packet header "
					"from IPC child pid " << ipc_pid << ": Unknown IPC command";
			_MSG(osstr.str(), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		// Get the full packet
		fullpack = (ipc_packet *) malloc(sizeof(ipc_packet) + ipchdr.data_len);

		if ((ret = recv(sockpair[1], &fullpack, sizeof(ipc_packet), 0)) < 
			(int) sizeof(ipc_packet) + (int) ipchdr.data_len) {
			if (ret < 0) {
				if (ipc_pid == 0) 
					osstr << "IPC child got error receiving packet "
						"from controller: " << strerror(errno);
				else
					osstr << "IPC controller got error receiving packet "
						"from IPC child pid " << ipc_pid << ": " << strerror(errno);
				_MSG(osstr.str(), MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			} else {
				return 0;
			}
		}

		// We "know" the rest is valid, so call the handler w/ this function.
		// giving it the ipc pid lets us cheat and tell if its the parent or not,
		// since the child has a 0 pid
		ret = (cbitr->second->callback)(globalreg, fullpack->data, 
										fullpack->data_len, cbitr->second->auxptr,
										ipc_pid);
		if (ret < 0) {
			if (ipc_pid == 0) 
				osstr << "IPC child got error executing command from controller.";
			else
				osstr << "IPC controller got error executing command "
					"from IPC child pid " << ipc_pid;
			_MSG(osstr.str(), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		free(fullpack);
	}

	if (FD_ISSET(sockpair[1], &in_wset)) {
		// Send as many frames as we have room for
		while (cmd_buf.size() > 0) {
			ipc_packet *pack = cmd_buf.front();

			// Send the frame
			if (send(sockpair[1], pack, 
					 sizeof(ipc_packet) + pack->data_len, 0) < 0) {
				if (errno == ENOBUFS)
					break;

				if (ipc_pid == 0) {
					// Blow up messily and spew into stderr
					fprintf(stderr, "IPC child %d got error writing packet to "
							"IPC socket: %s\n", getpid(), strerror(errno));
					globalreg->fatal_condition = 1;
					return -1;
				} else {
					osstr << "IPC controller got error writing data to IPC socket "
						"for IPC child pid " << ipc_pid << ": " << strerror(errno);
					_MSG(osstr.str(), MSGFLAG_FATAL);
					globalreg->fatal_condition = 1;
				}
			}

			// Finally delete it
			cmd_buf.pop_front();
			free(pack);
		}

	}
	
	return 1;
}

