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

/*
 * IPC remote
 *
 * Handles commands that can't/won't/shouldn't be handled by the main
 * Kismet process.  The primary example of this is the root-level 
 * control process used by the unprivileged Kismet to drive channel set
 * events.
 *
 * All commands and pointers MUST be set up BEFORE the IPC fork.
 *
 * An alternate child command can be specified.  It MUST take as the first argument
 * an integer indicating the file descriptor number of the IPC pipe, and it MUST 
 * understand the IPC protocol over this descriptor.
 *
 * The child binary must call SetChildExecMode(argc, argv) prior to filling in the
 * registered protocols, then call SpawnIPC() to kickstart processing.
 *
 */

#ifndef __IPC_REMOTE_H__
#define __IPC_REMOTE_H__

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

#include "globalregistry.h"
#include "pollable.h"
#include "messagebus.h"

#define IPC_CMD_PARMS GlobalRegistry *globalreg, const void *data, int len, \
	const void *auxptr, int parent
typedef int (*IPCmdCallback)(IPC_CMD_PARMS);

// Builtin command IDs we force (added before assign, so start at 1)
#define DIE_CMD_ID			1
#define MSG_CMD_ID			2
#define SYNC_CMD_ID			3

// Message client to redirect messages over the IPC link
class IPC_MessageClient : public MessageClient {
public:
    IPC_MessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
		MessageClient(in_globalreg, in_aux) { };
	virtual ~IPC_MessageClient() { }
	void ProcessMessage(string in_msg, int in_flags);
};

// Message frame to go over IPC
struct ipc_msgbus_pass {
	uint32_t msg_flags;
	uint32_t msg_len; // Redundant but simpler to read
	char msg[0];
};

// Super-generic IPC packet.  This never sees outside of a unix dgram
// frame, so we don't have to armor or protect it.  Just a handy method for
// tossing simple chunks of data.  Commands are responsible for filling in
// reasonable structs for *data
struct ipc_packet {
	uint32_t sentinel;
	uint8_t ipc_ack;
	uint32_t ipc_cmdnum;
	uint32_t data_len;
	uint8_t data[0];
};

// Sync frame the link names and numbers with spawned ipc children
struct ipc_sync {
	uint32_t ipc_cmdnum;
	uint8_t name[32];
};

// IPC sentinel
const uint32_t IPCRemoteSentinel = 0xDECAFBAD;

class IPCRemote : public Pollable {
public:
	IPCRemote();
	IPCRemote(GlobalRegistry *in_globalreg, string procname);

	virtual void SetChildCmd(string in_cmd) {
		child_cmd = in_cmd;
	}

	virtual int SetChildExecMode(int argc, char *argv[]); 

	virtual int SpawnIPC();

	// Shutdown takes an optional final packet to send before sending the
	// death packet
	virtual int ShutdownIPC(ipc_packet *pack);

	// IPC commands are integers, which means we get away without having to care
	// at all if they duplicate commands or whatever, so we don't even really
	// care about unique callbacks.  Makes life easy for us.  If ackcallback
	// is not null, the caller will get the ackframe called to their function
	virtual int RegisterIPCCmd(IPCmdCallback in_callback, 
							   IPCmdCallback in_ackcallback, 
							   void *in_aux,
							   string name);

	virtual int SyncIPCCmd(ipc_sync *data);

	// Kick a command across (either direction)
	virtual int SendIPC(ipc_packet *pack);

	// Is the IPC ready for more commands?  This would mean that the last
	// command was ack'd and that we don't have any queued up to still send.
	// Some uses might want to defer sending a command until the IPC is
	// settled.
	virtual int FetchReadyState();

	pid_t FetchSpawnPid() {
		return ipc_pid;
	}

	// Pollable system
	virtual unsigned int MergeSet(unsigned int in_max_fd, fd_set *out_rset,
								  fd_set *out_wset);
	virtual int Poll(fd_set& in_rset, fd_set& in_wset);

	struct ipc_cmd_rec {
		void *auxptr;
		IPCmdCallback callback;
		IPCmdCallback ack_callback;
		string name;
		int id;
	};

protected:
	// Child process that never returns
	virtual void IPC_Child_Loop();

	// Internal die functions
	virtual void IPCDie();
	
	GlobalRegistry *globalreg;

	// This isn't a ringbuf since it's dgram single-tx frames
	list<ipc_packet *> cmd_buf;

	// Name of the process we'll use in the child
	string procname;

	int next_cmdid;

	// Pair used to talk to the Other Half
	int sockpair[2];

	// PID of the child process
	pid_t ipc_pid;

	// Have we spawned a subproc?  Blow up on setup commands if
	// we have.
	int ipc_spawned;

	map<unsigned int, ipc_cmd_rec *> ipc_cmd_map;

	// Has the last command been acknowledged as complete?
	int last_ack;

	// Cmd to run instead of a copy of ourself. 
	string child_cmd;
	int child_exec_mode;

	friend class IPC_MessageClient;
	friend int ipc_die_callback(IPC_CMD_PARMS);
	friend int ipc_ack_callback(IPC_CMD_PARMS);
};

#endif

