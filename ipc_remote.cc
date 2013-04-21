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
	snprintf(msgb->msg, msgb->msg_len, "%s", in_msg.c_str());

	pack->data_len = 8 + in_msg.length() + 1;

	pack->ipc_cmdnum = MSG_CMD_ID;
	pack->ipc_ack = 0;

#if 0
	// Don't treat fatal as shutdown
	//
	// If it's a fatal frame, push it as a shutdown
	if ((in_flags & MSGFLAG_FATAL)) {
		((IPCRemote *) auxptr)->ShutdownIPC(pack);
		return;
	}
#endif

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
		exit(0);
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

	((IPCRemote *) auxptr)->SyncIPCCmd((ipc_sync *) data);

	return 0;
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
	ipc_pid = -1;
	ipc_spawned = 0;
	ipc_synced = 0;

	exit_errno = 0;

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
	// printf("debug - checkpidvec ipc_pid %d\n", ipc_pid);
	if (ipc_pid == 0)
		return 0;

	for (unsigned int x = 0; x < globalreg->sigchild_vec.size(); x++) {
		if (globalreg->sigchild_vec[x].pid == ipc_pid) {
			// printf("debug - check pid vec found pid %d status %d\n", ipc_pid, globalreg->sigchild_vec[x].status);
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
			if (cback != NULL)
				(*cback)(globalreg, NULL, 0, x->second->auxptr, 0);
		}

		ipc_synced = 1;

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
							  IPCmdCallback discard_ackback,
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
	rec->name = in_name;
	rec->id = next_cmdid;

	// Push the sync complete callbacks into their own map
	if (in_name == "SYNCCOMPLETE") {
		ipc_sync_map[next_cmdid] = rec;
	} else {
		ipc_cmd_map[next_cmdid] = rec;
	}

	// printf("debug - %d registered cmd %s %d\n", getpid(), in_name.c_str(), next_cmdid);

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

		unsigned int socksize = 32768;
		setsockopt(sockpair[0], SOL_SOCKET, SO_SNDBUF, &socksize, sizeof(socksize));
		setsockopt(sockpair[1], SOL_SOCKET, SO_SNDBUF, &socksize, sizeof(socksize));

		// Fork and launch the child control loop & set up the rest of our internal
		// info.
		if ((ipc_pid = fork()) < 0) {
			// If we fail we're still in the pid-space of the starting process and 
			// we can set this cleanly
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
			if (write(sockpair[0], &(sockpair[0]), 1) < 1) {
				exit(1);
			}

			// Run the client binary if we have one
			if (child_cmd != "") {
				char **cmdarg = new char *[3];
				cmdarg[0] = strdup(child_cmd.c_str());
				cmdarg[1] = new char[4];
				cmdarg[2] = NULL;

				snprintf(cmdarg[1], 4, "%d", sockpair[0]);

				// We're running as the child here, we have to pass this failure
				// up in the return value and this doesn't cause an immediate exit
				// with error for the caller...
				if (execve(cmdarg[0], cmdarg, NULL) < 0) {
					int status = errno;

					string fail = "Failed to launch IPC child: " +
						string(strerror(status));

					ipc_packet *pack = 
						(ipc_packet *) malloc(sizeof(ipc_packet) + 8 + 
											  fail.length() + 1);
					ipc_msgbus_pass *msgb = (ipc_msgbus_pass *) pack->data;

					msgb->msg_flags = MSGFLAG_FATAL;
					msgb->msg_len = fail.length() + 1;
					snprintf(msgb->msg, msgb->msg_len, "%s", fail.c_str());

					pack->data_len = 8 + fail.length() + 1;

					pack->ipc_cmdnum = MSG_CMD_ID;
					pack->ipc_ack = 0;

					exit_errno = status;

					ShutdownIPC(pack);
				}
			}

			IPC_Child_Loop();
			exit(0);
		}

		// Close the parent half of the socket pair
		close(sockpair[0]);

		// Blocking read the sync byte
		char sync;
		if (read(sockpair[1], &sync, 1) < 1)
			return -1;
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
			memset(pack, 0, sizeof(ipc_packet) + sizeof(ipc_sync));

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
	memset(pack, 0, sizeof(ipc_packet) + sizeof(ipc_sync));
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
	/*
	if (ipc_spawned <= 0) 
		return 0;
		*/

	int sock;
	if (ipc_pid == 0) {
		sock = sockpair[0];
	} else {
		sock = sockpair[1];
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
	memset(dpack, 0, sizeof(ipc_packet));
	dpack->data_len = 0;
	dpack->ipc_cmdnum = DIE_CMD_ID;
	dpack->ipc_ack = 0;
	dpack->sentinel = IPCRemoteSentinel;

	// Send it immediately
	send(sock, dpack, sizeof(ipc_packet) + dpack->data_len, 0);

  free (dpack);

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
	int p = CheckPidVec();

	if (p < 0) {
		return p;
	}

	if (ipc_spawned == 0) {
		// printf("debug - %d not spawned\n", getpid());
		return -1;
	}

	if (cmd_buf.size() != 0) {
		// printf("debug - %d buf size\n", getpid());
		return 0;
	}

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
			if (errno != EINTR && errno != EAGAIN) {
				// Die violently
				fprintf(stderr, "FATAL OOPS:  IPC command child %d got select() "
						"error and cannot continue cleanly: %s\n",
						getpid(), strerror(errno));
				exit(1);
			}
		}

		// Handle in/out data
		if (Poll(rset, wset) < 0 || globalreg->fatal_condition) {
			exit(0);
		}

	}
}

void IPCRemote::IPCDie() {
	if (ipc_pid < 0)
		return;

	// If we're the child...
	if (ipc_pid == 0) {
		if (sockpair[0] >= 0) {
			// Shut down the child socket fd
			close(sockpair[0]);
			sockpair[0] = -1;
		}

		// and exit, we're done
		exit(exit_errno);
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
		int w = waitpid(ipc_pid, &res, WNOHANG);
		// printf("debug - waitpid got %d wifexited %d\n", w, WIFEXITED(res));
		if (w >= 0 && WIFEXITED(res)) {
			dead = 1;
			break;
		}
		usleep(100000);
	}

	if (!dead && ipc_pid > 0) {
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

	ipc_spawned = 0;
}

int IPCRemote::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
	int sock;

	// Don't call this on the child, we have a micro-select loop in the child
	// process... also do nothing if we haven't spawned yet.
	//
	
	int p = CheckPidVec();

	// Let a forked child operate normally
	if ((ipc_pid == 0 && child_exec_mode == 0) || ipc_spawned <= 0 || p < 0) {
		// printf("debug - %d %p bailing on merge, ipc pid %d child mode %d spawned %d checkpid %d\n", getpid(), this, ipc_pid, child_exec_mode, ipc_spawned, p);
		return in_max_fd;
	}

	if (child_exec_mode)
		sock = sockpair[0];
	else
		sock = sockpair[1];

	// Set the socket to be read
	FD_SET(sock, out_rset);

	if (cmd_buf.size() > 0) {
		// printf("debug - %d cmd_buf set, flaggig write in merge\n", getpid());
		FD_SET(sock, out_wset);
	}

	if (in_max_fd < sock)
		return sock;

	return in_max_fd;
}

int IPCRemote::Poll(fd_set& in_rset, fd_set& in_wset) {
	// This CAN be called by the parent or the child.  In the parent it's called
	// by the normal pollable architecture.  In the child we manually call it
	// from our micro-select loop.
	
	// printf("debug - %d poll queue %d\n", getpid(), cmd_buf.size());

	int p = CheckPidVec();
	
	if (ipc_spawned <= 0 || p < 0) {
		// printf("debug - %d %p not spawned / checkpid fail checkpid %d ipc %d\n", getpid(), this, p, ipc_spawned);
		return -1;
	}

	ostringstream osstr;
	int sock;

	if (ipc_pid == 0)
		sock = sockpair[0];
	else
		sock = sockpair[1];

	// Process packets out
	if (FD_ISSET(sock, &in_wset)) {
		if (CheckPidVec() < 0)
			return -1;

		// printf("debug - %d %p poll wset\n", getpid(), this);
		// Send as many frames as we have room for if we're not waiting for an ack
		while (cmd_buf.size() > 0 && ipc_spawned > 0) {
			ipc_packet *pack = cmd_buf.front();

			// printf("debug - %d %p sending %d\n", getpid(), this, pack->ipc_cmdnum);

			// Send the frame
			if (send(sock, pack, sizeof(ipc_packet) + pack->data_len, 0) < 0) {
				if (errno == ENOBUFS || errno == EINTR || errno == EAGAIN)
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
					ipc_spawned = -1;
				}
			}

			// Finally delete it
			cmd_buf.pop_front();
			free(pack);
		}
	} else {
		// printf("debug - %d %p write not set in fd\n", getpid(), this);
	}

	// printf("dbeug - %d %p to rset\n", getpid(), this);

	// Process packets in
	if (FD_ISSET(sock, &in_rset)) {
		ipc_packet ipchdr;
		ipc_packet *fullpack = NULL;
		int ret = 0;

		// Peek at the packet header
		if ((ret = recv(sock, &ipchdr, 
						sizeof(ipc_packet), MSG_PEEK)) < (int) sizeof(ipc_packet)) {
			if (ret < 0) {
				if (errno != EAGAIN && errno != EINTR) {
					// printf("debug - %d - failed recv %s\n", getpid(), strerror(errno));
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
					// printf("debug - %d - failed recv non-fatal - %s\n", getpid(), strerror(errno));
					return 0;
				}
			} else {
				return 0;
			}
		}

		// Runt frame that's too small
		if (ret < (int) sizeof(ipc_packet))
			return 0;

		// validate the ipc header
		if (ipchdr.sentinel != IPCRemoteSentinel) {
			// printf("debug - %d ipchdr sentiel ivalid %x != %x\n", getpid(), ipchdr.sentinel, IPCRemoteSentinel);
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

		// printf("debug - IPC %d got ipc cmd %d ack %d\n", getpid(), ipchdr.ipc_cmdnum, ipchdr.ipc_ack);

		if (cbitr == ipc_cmd_map.end()) {
			// printf("debug - %d unknown cmd\n", getpid());
			if (ipc_pid == 0) 
				osstr << "IPC child got error receiving packet header from "
					"controller: Unknown IPC command";
			else
				osstr << "IPC controller got error receiving packet header "
					"from IPC child pid " << ipc_pid << ": Unknown IPC command " <<
					(int) ipchdr.ipc_cmdnum << " len " << ipchdr.data_len;
			_MSG(osstr.str(), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}
		IPCmdCallback cback = cbitr->second->callback;
		void *cbackaux = cbitr->second->auxptr;

		// Get the full packet
		fullpack = (ipc_packet *) malloc(sizeof(ipc_packet) + ipchdr.data_len);
		memset(fullpack, 0, sizeof(ipc_packet) + ipchdr.data_len);

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
				// printf("debug - %d got 0 reading full packet\n", getpid());
				return 0;
			}
		}

		// If we've got a callback, process it
		if (cback != NULL) {
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
		}

		free(fullpack);
	}

	return 1;
}

int ipc_fdpass_callback(IPC_CMD_PARMS) {
	if (parent == 1)
		return 0;

	return ((RootIPCRemote *) auxptr)->OpenFDPassSock();
}

int ipc_rootipc_sync(IPC_CMD_PARMS) {
	((RootIPCRemote *) auxptr)->RootIPCSynced();

	return 1;
}

RootIPCRemote::RootIPCRemote(GlobalRegistry *in_globalreg, string procname) : 
	IPCRemote(in_globalreg, procname) { 

	root_ipc_synced = 0;

	SetChildCmd(string(BIN_LOC) + "/kismet_capture");
	fdpass_cmd = RegisterIPCCmd(&ipc_fdpass_callback, NULL, this, "FDPASS");
	rootipcsync_cmd = RegisterIPCCmd(&ipc_rootipc_sync, NULL, this, "ROOTSYNCED");
}

int RootIPCRemote::FetchReadyState() {
	if (ipc_pid != 0 && root_ipc_synced == 0) {
		return 0;
	}

	return IPCRemote::FetchReadyState();
}

int RootIPCRemote::ShutdownIPC(ipc_packet *packet) {
	ShutdownIPCPassFD();
	return IPCRemote::ShutdownIPC(packet);
}

void RootIPCRemote::ShutdownIPCPassFD() {
#ifdef SYS_LINUX
	char sockpath[32];

	if (ipc_pid >= 0) {
		// Clean up the socket if it exists
		if (ipc_fd_fd >= 0) {
			snprintf(sockpath, 32, "/tmp/kisfdsock_%u", ipc_pid);
			close(ipc_fd_fd);
			ipc_fd_fd = -1;
			unlink(sockpath);
		}
	}

	ipc_fd_fd = -1;
#endif
}

void RootIPCRemote::IPCDie() {
	if (ipc_pid != 0 && ipc_spawned > 0) {
		if (!globalreg->spindown) {
			_MSG("Root IPC control binary has died", MSGFLAG_FATAL);
			// globalreg->fatal_condition = 1;
		}
	}

	ShutdownIPCPassFD();

	IPCRemote::IPCDie();
}


int RootIPCRemote::OpenFDPassSock() {
#ifdef SYS_LINUX
	char sockpath[32];

	// Child creates it, since child probably has more privs
	if (ipc_pid != 0) {
		// printf("debug - %d - child creating ipc fdfd\n", getpid());

		snprintf(sockpath, 32, "/tmp/kisfdsock_%d", ipc_pid);

		// Unlink if it exists
		unlink(sockpath);

		unixsock.sun_family = AF_UNIX;
		strncpy(unixsock.sun_path, sockpath, sizeof(unixsock.sun_path));

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

	if ((ipc_fd_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		_MSG("Failed to open socket to pass file descriptors: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	unixsock.sun_family = AF_UNIX;
	snprintf(sockpath, 32, "/tmp/kisfdsock_%u", getpid());
	strcpy(unixsock.sun_path, sockpath);

	return ipc_fd_fd;
#endif

	return -1;
}

typedef struct {
	struct cmsghdr header;
	int            fd;
} __attribute__((packed)) cmsg_fd;

int RootIPCRemote::SendDescriptor(int in_fd) {
#ifdef SYS_LINUX
	struct msghdr msg;
	struct iovec vec[1];
	cmsg_fd cm;
	struct msghdr m;
	char str[1] = {'x'};

	/* we have to send at least one byte */
	vec[0].iov_base = str;
	vec[0].iov_len = sizeof(str);

	msg.msg_name = (struct sockaddr *) &unixsock;
	msg.msg_namelen = sizeof(unixsock);

	msg.msg_iov = vec;
	msg.msg_iovlen = 1;

	msg.msg_control = &cm;
	msg.msg_controllen = sizeof(cm);

	m.msg_flags = 0;

	cm.header.cmsg_len = sizeof(cm);
	cm.header.cmsg_level = SOL_SOCKET;
	cm.header.cmsg_type = SCM_RIGHTS;

	cm.fd = in_fd;

	// printf("debug - %d child sending fd over fdfd\n", getpid());

	if (sendmsg(ipc_fd_fd, &msg, 0) < 0) {
		_MSG("Root IPC file descriptor sendmsg() failed: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	return 1;
#endif

	return -1;
}

int RootIPCRemote::ReceiveDescriptor() {
#ifdef SYS_LINUX
	char buf[1];
	struct msghdr m;
	struct iovec iov[1];
	cmsg_fd cm;

	// printf("debug - %d receive descriptor\n", getpid());

	if (ipc_fd_fd < 0)
		return -1;

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

	memset(&m, 0, sizeof(m));
	
	cm.header.cmsg_len = sizeof(cm);
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	m.msg_control = &cm;
	m.msg_controllen = sizeof(cm);

	if (recvmsg(ipc_fd_fd, &m, 0) < 0) {
		_MSG("Root IPC failed to receive passed file descriptor: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	return cm.fd;

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

