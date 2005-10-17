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
#include "ringbuf.h"
#include "messagebus.h"

#define IPC_CMD_PARMS GlobalRegistry *globalreg, const void *data, int len, \
	const void *auxptr, int parent
typedef int (*IPCmdCallback)(IPC_CMD_PARMS);

// Message client to redirect messages over the IPC link
class IPC_MessageClient : public MessageClient {
public:
    IPC_MessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
		MessageClient(in_globalreg, in_aux) { };
	void ProcessMessage(string in_msg, int in_flags);
};

// Message frame to go over IPC
typedef struct ipc_msgbus_pass {
	uint32_t msg_flags;
	char msg[2048];
};


// Super-generic IPC packet.  This never sees outside of a unix dgram
// frame, so we don't have to armor or protect it.  Just a handy method for
// tossing simple chunks of data.  Commands are responsible for filling in
// reasonable structs for *data
typedef struct ipc_packet {
	uint32_t ipc_cmdnum;
	uint32_t data_len;
	void *data;
};

class IPCRemote : public Pollable {
public:
	IPCRemote();
	IPCRemote(GlobalRegistry *in_globalreg);

	virtual int SpawnIPC();

	// IPC commands are integers, which means we get away without having to care
	// at all if they duplicate commands or whatever, so we don't even really
	// care about unique callbacks.  Makes life easy for us.
	virtual int RegisterIPCCmd(IPCmdCallback in_callback);

	// Kick a command across (either direction)
	virtual int SendIPC(ipc_packet *pack);

	uid_t FetchSpawnUid() {
		return spawneduid;
	}

protected:
	// Child process that never returns
	void IPC_Child_Loop();
	
	GlobalRegistry *globalreg;

	RingBuffer *buf;

	int next_cmdid;

	// Pair used to talk to the Other Half
	int sockpair[2];

	// PID of the child process
	pid_t ipc_pid;

	// UID we were when we spawned the IPC drone.  Doesn't mean
	// this is the UID it's under anymore, but the best we can do
	uid_t spawneduid;

	// Have we spawned a subproc?  Blow up on setup commands if
	// we have.
	int ipc_spawned;

	map<int, IPCmdCallback> ipc_cmd_map;

	// Builtin mandatory command IDs
	int msg_cmd_id;
};

#endif

