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

	pack->ipc_cmdnum = MSG_CMD_ID;
	pack->ipc_ack = 0;

	// If it's a fatal frame, push it as a shutdown
	if ((in_flags & MSGFLAG_FATAL)) {
		((IPCRemote *) auxptr)->ShutdownIPC(pack);
		return;
	}
	
	// Push it via the IPC
	((IPCRemote *) auxptr)->SendIPC(pack);

	// It gets freed once its sent so don't free it ourselves here
}

int ipc_msg_callback(IPC_CMD_PARMS) {
	(void) auxptr;

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

	return 0;
}

int ipc_die_callback(IPC_CMD_PARMS) {
	(void) data;
	(void) len;

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
	
	return 0;
}

int ipc_sync_callback(IPC_CMD_PARMS) {
	// Parent does nothing
	if (parent == 1)
		return 0;

	if (len < (int) sizeof(ipc_sync)) {
		_MSG("IPC sync handler got a short sync block", MSGFLAG_ERROR);
		return -1;
	}

	return ((IPCRemote *) auxptr)->SyncIPCCmd((ipc_sync *) data);
}

IPCRemote::IPCRemote() {
	fprintf(stderr, "FATAL OOPS:  IPCRemote called w/ no globalreg\n");
	exit(1);
}

IPCRemote::IPCRemote(GlobalRegistry *in_globalreg, string in_procname) {
	globalreg = in_globalreg;
	procname = in_procname;

	if (globalreg->messagebus == NULL) {
		fprintf(stderr, "FATAL OOPS:  IPCRemote called before messagebus\n");
		exit(1);
	}

	child_exec_mode = 0;

	next_cmdid = 0;
	ipc_pid = 0;
	ipc_spawned = 0;
	last_ack = 1; // Our "last" command was ack'd

	// Register builtin commands (in proper order!)
	RegisterIPCCmd(&ipc_die_callback, NULL, this, "DIE");
	RegisterIPCCmd(&ipc_msg_callback, NULL, this, "MSG");
	RegisterIPCCmd(&ipc_sync_callback, NULL, this, "SYNC");

	globalreg->RegisterPollableSubsys(this);
}

IPCRemote::~IPCRemote() {
	globalreg->RemovePollableSubsys(this);
}

int IPCRemote::CheckPidVec() {
	if (ipc_pid == 0)
		return 0;

	for (unsigned int x = 0; x < globalreg->sigchild_vec.size(); x++) {
		if (globalreg->sigchild_vec[x].pid == ipc_pid) {
			CatchSigChild(globalreg->sigchild_vec[x].status);
			globalreg->sigchild_vec.erase(globalreg->sigchild_vec.begin() + x);
			return -1;
		}
	}

	return 0;
}

int IPCRemote::SyncIPCCmd(ipc_sync *data) {
	// Handle the end-of-sync command
	if (data->ipc_cmdnum == 0) {
		for (map<unsigned int, ipc_cmd_rec *>::iterator x = ipc_sync_map.begin();
			 x != ipc_sync_map.end(); ++x) {

			IPCmdCallback cback = x->second->callback;
			(*cback)(globalreg, NULL, 0, x->second->auxptr, 0);
		}

		return 1;
	}

	// Search the map for something of this name
	for (map<unsigned int, ipc_cmd_rec *>::iterator x = ipc_cmd_map.begin();
		 x != ipc_cmd_map.end(); ++x) {
		ipc_cmd_rec *cr = x->second;
		string name = (char *) data->name;

		if (cr->name == name) {
			cr->id = data->ipc_cmdnum;
			ipc_cmd_map[data->ipc_cmdnum] = cr;
			ipc_cmd_map.erase(x);

			return 1;
		}
	}

	return 1;
}

int IPCRemote::SetChildExecMode(int argc, char *argv[]) {
	int tint;

	// Set us to child mode
	ipc_pid = 0;
	// Set our next cmd id to something big and negative, so that we can
	// stock cmds prior to a sync, but not interfere once the sync begins
	next_cmdid = -4098;

	child_exec_mode = 1;

	// Parse the FD out
	if (argc < 2) {
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (sscanf(argv[1], "%d", &tint) != 1) {
		globalreg->fatal_condition = 1;
		return -1;
	}

	child_cmd = string(argv[0]);

	sockpair[0] = tint;

	ipc_spawned = 1;
	ipc_pid = 0;

	return 1;
}

int IPCRemote::RegisterIPCCmd(IPCmdCallback in_callback, 
							  IPCmdCallback in_ackcallback,
							  void *in_aux, string in_name) {
	// Allow registering commands after spawning if we're running a child command
	// since we can post-spawn sync
	if (ipc_spawned && child_cmd == "") {
		_MSG("IPC_Remote - Tried to register a command after the IPC agent has "
			 "been spawned.  Commands must be registered before Spawn().",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Look for the callback already in the system
	for (map<unsigned int, ipc_cmd_rec *>::iterator x = ipc_cmd_map.begin();
		 x != ipc_cmd_map.end(); ++x) {
		if (x->second->callback == in_callback &&
			x->second->name == in_name)
			return x->first;
	}

	next_cmdid++;

	ipc_cmd_rec *rec = new ipc_cmd_rec;
	rec->auxptr = in_aux;
	rec->callback = in_callback;
	rec->ack_callback = in_ackcallback;
	rec->name = in_name;
	rec->id = next_cmdid;

	// Push the sync complete callbacks into their own map
	if (in_name == "SYNCCOMPLETE") {
		ipc_sync_map[next_cmdid] = rec;
	} else {
		ipc_cmd_map[next_cmdid] = rec;
	}

	return next_cmdid;
}

int IPCRemote::SpawnIPC() {
	// Don't build the socket pair if we're in exec child mode
	if (child_exec_mode == 0) {
		// Generate the socket pair before the split
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockpair) < 0) {
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
			signal(SIGINT, SIG_DFL);
			signal(SIGKILL, SIG_DFL);
			signal(SIGHUP, SIG_IGN);
			signal(SIGPIPE, SIG_IGN);
			signal(SIGCHLD, SIG_IGN);

			// Close our copy of the other half
			close(sockpair[1]);

			// Write a single byte on the FD to sync us
			write(sockpair[0], &(sockpair[0]), 1);

			// Run the client binary if we have one
			if (child_cmd != "") {
				char **cmdarg = new char *[3];
				cmdarg[0] = strdup(child_cmd.c_str());
				cmdarg[1] = new char[4];
				cmdarg[2] = NULL;

				snprintf(cmdarg[1], 4, "%d", sockpair[0]);

				if (execve(cmdarg[0], cmdarg, NULL) < 0) {
					int status = errno;
					fprintf(stderr, "Failed to exec as IPC child: %s\n", 
							strerror(status));
					exit(status);
				}
			}

			IPC_Child_Loop();
			exit(0);
		}

		// Close the parent half of the socket pair
		close(sockpair[0]);

		// Blocking read the sync byte
		char sync;
		read(sockpair[1], &sync, 1);
	}

	// We've spawned, can't set new commands anymore
	ipc_spawned = 1;

	return 1;
}

int IPCRemote::SyncIPC() {
	// If we spawned something that needs to be synced, send all our protocols
	if (child_cmd != "") {
		for (map<unsigned int, ipc_cmd_rec *>::iterator x = ipc_cmd_map.begin();
			 x != ipc_cmd_map.end(); ++x) {

			if (x->first < LAST_BUILTIN_CMD_ID)
				continue;

			ipc_packet *pack = 
				(ipc_packet *) malloc(sizeof(ipc_packet) + sizeof(ipc_sync));

			ipc_sync *sync = (ipc_sync *) pack->data;

			sync->ipc_cmdnum = x->first;
			snprintf((char *) sync->name, 32, "%s", x->second->name.c_str());

			pack->data_len = sizeof(ipc_sync);
			pack->ipc_cmdnum = SYNC_CMD_ID;
			pack->ipc_ack = 0;

			// Push it via the IPC
			SendIPC(pack);
		}
	}

	// Send a cmdid 0 to indicate the end of sync
	ipc_packet *pack = 
		(ipc_packet *) malloc(sizeof(ipc_packet) + sizeof(ipc_sync));
	ipc_sync *sync = (ipc_sync *) pack->data;
	sync->ipc_cmdnum = 0;
	sync->name[0] = '\0';
	pack->data_len = sizeof(ipc_sync);
	pack->ipc_cmdnum = SYNC_CMD_ID;
	pack->ipc_ack = 0;
	SendIPC(pack);

	return 1;
}

int IPCRemote::ShutdownIPC(ipc_packet *pack) {
	if (ipc_spawned <= 0) 
		return 0;

	int sock;
	if (ipc_pid == 0) {
		sock = sockpair[0];
	} else {
		sock = sockpair[1];
#if 0
		r = waitpid(ipc_pid, &s, WNOHANG);
		if (WIFEXITED(s) || r < 0) {
			ipc_spawned = -1;
			IPCDie();
			return 0;
		}
#endif
	}

	// If we have a last frame, send it
	if (pack != NULL) {
		pack->sentinel = IPCRemoteSentinel;
		send(sock, pack, sizeof(ipc_packet) + pack->data_len, 0);
	}

	// Nothing special here, just a die frame.  Beauty is, we don't care
	// if we're the parent of the child, a clean shutdown will signal the other
	// side it's time to shuffle off
	ipc_packet *dpack = (ipc_packet *) malloc(sizeof(ipc_packet));
	dpack->data_len = 0;
	dpack->ipc_cmdnum = DIE_CMD_ID;
	dpack->ipc_ack = 0;
	dpack->sentinel = IPCRemoteSentinel;

	// Send it immediately
	send(sock, dpack, sizeof(ipc_packet) + dpack->data_len, 0);

	// Die fully
	IPCDie();

	return 1;
}

int IPCRemote::SendIPC(ipc_packet *pack) {
	// This is really just an enqueue system
	pack->sentinel = IPCRemoteSentinel;
	cmd_buf.push_back(pack);

	return 1;
}

int IPCRemote::FetchReadyState() {
	if (ipc_spawned == 0)
		return 0;

	if (last_ack == 0)
		return 0;

	if (cmd_buf.size() != 0)
		return 0;

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
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	// Set the process title
	init_proc_title(globalreg->argc, globalreg->argv, globalreg->envp);
	set_proc_title("%s", procname.c_str());

	while (1) {
		int max_fd = 0;

		FD_ZERO(&rset);
		FD_ZERO(&wset);

		FD_SET(sockpair[0], &rset);
		max_fd = sockpair[0];

		// Do we have data to send?
		if (cmd_buf.size() > 0) {
			FD_SET(sockpair[0], &wset);
		}

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
		if (Poll(rset, wset) < 0 || globalreg->fatal_condition) {
			exit(0);
		}

	}
}

void IPCRemote::IPCDie() {
	// If we're the child...
	if (ipc_pid == 0 && ipc_spawned > 0) {
		// Shut down the child socket fd
		close(sockpair[0]);
		// and exit, we're done
		exit(0);
	}  else if (ipc_pid == 0) {
		_MSG("IPC Die called on tracker with no child", MSGFLAG_ERROR);
		return;
	}

	// otherwise if we're the parent...
	// Shut down the socket
	if (sockpair[1] >= 0) {
		close(sockpair[1]);
		sockpair[1] = -1;
	}

	// Wait for the child process to be dead
	_MSG("IPC controller waiting for IPC child process " + 
		 IntToString((int) ipc_pid) + " to end.", MSGFLAG_INFO);

	int dead = 0;
	int res = 0;
	for (unsigned int x = 0; x < 10; x++) {
		if (waitpid(ipc_pid, &res, WNOHANG) > 0 && WIFEXITED(res)) {
			dead = 1;
			break;
		}
		usleep(100000);
	}

	if (!dead) {
		_MSG("Child process " + IntToString((int) ipc_pid) + " didn't die "
			 "cleanly, killing it.", MSGFLAG_ERROR);
		kill(ipc_pid, SIGKILL);
		waitpid(ipc_pid, NULL, 0);
	}

	// Flush all the queued packets
	while (cmd_buf.size() > 0) {
		ipc_packet *pack = cmd_buf.front();
		free(pack);
		cmd_buf.pop_front();
	}

	_MSG("IPC controller IPC child process " + 
		 IntToString((int) ipc_pid) + " has ended.", MSGFLAG_INFO);

	ipc_pid = 0;
	ipc_spawned = 0;
}

unsigned int IPCRemote::MergeSet(unsigned int in_max_fd, fd_set *out_rset,
								 fd_set *out_wset) {
	int sock;

	// Don't call this on the child, we have a micro-select loop in the child
	// process... also do nothing if we haven't spawned yet.
	//
	// Let a forked child operate normally
	if ((ipc_pid == 0 && child_exec_mode == 0) || ipc_spawned <= 0 || CheckPidVec() < 0)
		return in_max_fd;

	if (child_exec_mode)
		sock = sockpair[0];
	else
		sock = sockpair[1];

	// Set the socket to be read
	FD_SET(sock, out_rset);
	
	// Set the write if we have data queued and our last command was
	// ack'd.  If it wasn't, rate limit ourselves down until it is.
	if (cmd_buf.size() > 0)
		FD_SET(sock, out_wset);

	if (in_max_fd < (unsigned int) sock)
		return sock;

	return in_max_fd;
}

int IPCRemote::Poll(fd_set& in_rset, fd_set& in_wset) {
	// This CAN be called by the parent or the child.  In the parent it's called
	// by the normal pollable architecture.  In the child we manually call it
	// from our micro-select loop.
	
	if (ipc_spawned <= 0 || CheckPidVec() < 0)
		return -1;

	ostringstream osstr;
	int sock;

	if (ipc_pid == 0)
		sock = sockpair[0];
	else
		sock = sockpair[1];

	// Process packets out
	if (FD_ISSET(sock, &in_wset)) {
		// Send as many frames as we have room for
		while (cmd_buf.size() > 0) {
			ipc_packet *pack = cmd_buf.front();

			// Send the frame
			if (send(sock, pack, sizeof(ipc_packet) + pack->data_len, 0) < 0) {
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
					ipc_spawned = -1;
				}
			}

			// ACK frames themselves, msg frames, and death commands are not
			// expected to ack back that the command is done.  everything else
			// should.
			if (pack->ipc_cmdnum != DIE_CMD_ID &&
				pack->ipc_cmdnum != MSG_CMD_ID &&
				pack->ipc_ack == 0) {
				last_ack = 0;
			}

			// Finally delete it
			cmd_buf.pop_front();
			free(pack);
		}

	}

	// Process packets in
	if (FD_ISSET(sock, &in_rset)) {
		ipc_packet ipchdr;
		ipc_packet *fullpack = NULL;
		int ret;

		// Peek at the packet header
		if ((ret = recv(sock, &ipchdr, 
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
					"from IPC child pid " << ipc_pid << ": Unknown IPC command " <<
					ipchdr.ipc_cmdnum;
			_MSG(osstr.str(), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}
		IPCmdCallback cback = cbitr->second->callback;
		IPCmdCallback ackcback = cbitr->second->ack_callback;
		void *cbackaux = cbitr->second->auxptr;

		// Get the full packet
		fullpack = (ipc_packet *) malloc(sizeof(ipc_packet) + ipchdr.data_len);

		if ((ret = recv(sock, fullpack, sizeof(ipc_packet) + ipchdr.data_len, 0)) < 
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

		// If we've got an ack frame, and there is an ack callback for this 
		// command type, we send it on to them
		if (ipchdr.ipc_ack) {
			if (ackcback != NULL) {
				ret = (*ackcback)(globalreg, fullpack->data, fullpack->data_len,
								  cbackaux, ipc_pid);
			}
			last_ack = 1;
		} else {
			// We "know" the rest is valid, so call the handler w/ this function.
			// giving it the ipc pid lets us cheat and tell if its the parent or not,
			// since the child has a 0 pid
			ret = (*cback)(globalreg, fullpack->data, fullpack->data_len, 
						   cbackaux, ipc_pid);
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

			// Queue a return ack frame that the command was received and processed
			// if it's not die, msg, or ack, and ret == 0, ie, send a generic ack
			if (ipchdr.ipc_cmdnum != DIE_CMD_ID &&
				ipchdr.ipc_cmdnum != MSG_CMD_ID &&
				ret == 0) {
				ipc_packet *ackpack = (ipc_packet *) malloc(sizeof(ipc_packet));
				ackpack->ipc_ack = 1;
				ackpack->ipc_cmdnum = ipchdr.ipc_cmdnum;
				ackpack->data_len = 0;
				SendIPC(ackpack);
			}
		}
	}

	
	return 1;
}

int ipc_fdpass_callback(IPC_CMD_PARMS) {
	if (parent == 1)
		return 0;

	return ((RootIPCRemote *) auxptr)->OpenFDPassSock();
}

RootIPCRemote::RootIPCRemote(GlobalRegistry *in_globalreg, string procname) : 
	IPCRemote(in_globalreg, procname) { 

	SetChildCmd(string(BIN_LOC) + "/kismet_capture");
	RegisterIPCCmd(&ipc_fdpass_callback, NULL, this, "FDPASS");

}

int RootIPCRemote::ShutdownIPC(ipc_packet *packet) {
	ShutdownIPCPassFD();
	return IPCRemote::ShutdownIPC(packet);
}

void RootIPCRemote::ShutdownIPCPassFD() {
	char sockpath[32];

#ifdef SYS_LINUX
	if (ipc_pid == 0) {
		// Clean up the socket if it exists
		if (ipc_fd_fd >= 0) {
			snprintf(sockpath, 32, "/tmp/kisfdsock_%u", getpid());
			close(ipc_fd_fd);
			ipc_fd_fd = -1;
			unlink(sockpath);
		}
	} else if (ipc_fd_fd >= 0) {
		close(ipc_fd_fd);
	}
#endif
}

void RootIPCRemote::IPCDie() {
	if (!globalreg->spindown) {
		_MSG("Root IPC control binary has died, shutting down", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
	}

	ShutdownIPCPassFD();

	return IPCRemote::IPCDie();
}


int RootIPCRemote::OpenFDPassSock() {
#ifdef SYS_LINUX
	char sockpath[32];

	memset(&unixsock, 0, sizeof(struct sockaddr_un));

	// Child creates it, since child probably has more privs
	if (ipc_pid == 0) {
		snprintf(sockpath, 32, "/tmp/kisfdsock_%u", getpid());

		// Unlink if it exists
		unlink(sockpath);

		unixsock.sun_family = AF_UNIX;
		strcpy(unixsock.sun_path, sockpath);

		if ((ipc_fd_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
			_MSG("Failed to open socket to pass file descriptors: " +
				 string(strerror(errno)), MSGFLAG_ERROR);
			return -1;
		}

		if (bind(ipc_fd_fd, (const struct sockaddr *) &unixsock, sizeof(unixsock))) {
			close(ipc_fd_fd);
			_MSG("Failed to bind socket to pass file descriptors: " + 
				 string(strerror(errno)), MSGFLAG_ERROR);
			return -1;
		}

		return ipc_fd_fd;
	}

	// Otherwise try to open it a few times
	for (int x = 0; x < 10; x++) {
		unixsock.sun_family = AF_UNIX;
		snprintf(sockpath, 32, "/tmp/kisfdsock_%u", ipc_pid);
		strcpy(unixsock.sun_path, sockpath);
		if ((ipc_fd_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
			struct timeval tm;

			tm.tv_sec = 0;
			tm.tv_usec = 1000;

			select(0, NULL, NULL, NULL, &tm);
		}

		return ipc_fd_fd;
	}
#endif

	return -1;
}

int RootIPCRemote::SendDescriptor(int in_fd) {
#ifdef SYS_LINUX
	struct msghdr msg;
	char ccmsg[CMSG_SPACE(sizeof(in_fd))];
	struct cmsghdr *cmsg;
	struct iovec vec;
	char str[] = {"x"};

	msg.msg_name = (struct sockaddr *) &unixsock;
	msg.msg_namelen = sizeof(unixsock);

	/* we have to send at least one byte */
	vec.iov_base = str;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;

	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(in_fd));
	
	(*(int *) CMSG_DATA(cmsg)) = in_fd;

	msg.msg_flags = 0;

	return sendmsg(ipc_fd_fd, &msg, 0);
#endif

	return -1;
}

int RootIPCRemote::ReceiveDescriptor() {
#ifdef SYS_LINUX
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	int connfd = -1;
	char ccmsg[CMSG_SPACE(sizeof(connfd))];
	struct cmsghdr *cmsg;

	if (ipc_fd_fd < 0)
		return -1;

	iov.iov_base = buf;
	iov.iov_len = 1;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	if (recvmsg(ipc_fd_fd, &msg, 0) < 0) {
		_MSG("IPC failed to receive file descriptor: " + string(strerror(errno)),
			 MSGFLAG_ERROR);
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg->cmsg_type == SCM_RIGHTS) {
		_MSG("IPC got unknown control msg " + IntToString(cmsg->cmsg_type) + " on "
			 "FD exchange", MSGFLAG_ERROR);
		return -1;
	}

	return (*(int *) CMSG_DATA(cmsg));
#endif

	return -1;
}

int RootIPCRemote::SyncIPC() {
	if (ipc_pid != 0) {
		// Open the passing socket we made when we spawned the child
		if (OpenFDPassSock() < 0) {
			_MSG("Failed to open file descriptor passing socket during root IPC "
				 "synchronization, may cause problems in the future", MSGFLAG_ERROR);
		}
	}

	return IPCRemote::SyncIPC();
}

