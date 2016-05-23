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

#ifndef __IPC_REMOTE_V2_H__
#define __IPC_REMOTE_V2_H__

#include "config.h"

#include <sys/types.h>
#include <signal.h>
#include <pthread.h>

#include "globalregistry.h"
#include "ringbuf_handler.h"
#include "pipeclient.h"
#include "timetracker.h"

/* IPC remote v2
 *
 * Used to spawn and interact with sub-processes for capture or other actions.
 *
 * The most common use of this is the capturesource engine which needs
 * to communicate with external capture binaries.
 *
 * Automatically creates a pipeclient to interface the IPC binary with the
 * ringbuffer handler.
 *
 * Automatically registers the IPC process with the IPC handler for process
 * lifecycle maintenance.
 *
 */

class IPCRemoteV2Tracker;

class IPCRemoteV2 {
public:
    IPCRemoteV2(GlobalRegistry *in_globalreg, RingbufferHandler *in_rbhandler);
    virtual ~IPCRemoteV2();

    // Add paths to look for binary in.  Paths are searched in the order
    // they are added
    void add_path(string in_path);

    // Close down IPC (but don't issue a kill)
    void close_ipc();

    // Launch a binary with specified arguments.
    //
    // When launching kismet compatible binaries, IPCRemote will make a 
    // pipe and pass it to the binary via --in-fd= and --out-fd= arguments.
    //
    // When launching standard binaries, IPCRemote will map stdin and stdout
    // to the binary.
    //
    // returns negative on failure
    int launch_kis_binary(string cmd, vector<string> args);
    int launch_kis_explicit_binary(string cmdpath, vector<string> args);
    int launch_standard_binary(string cmd, vector<string> args);
    int launch_standard_explicit_binary(string cmdpath, vector<string> args);

    // Soft-kill a binary (send a sigterm)
    int soft_kill();

    //  Hard-kill a binary (send a kill -9 )
    int hard_kill();

    pid_t get_pid();

    // Does the ipc tracker free us when we die?  This should be set to true when
    // we are destroying something that uses an IPC context, and we need the IPC
    // context deleted once the process is reaped.
    bool get_tracker_free() { return tracker_free; }
    void set_tracker_free(bool in_free);

protected:
    pthread_mutex_t ipc_locker;

    GlobalRegistry *globalreg;
    RingbufferHandler *ipchandler;
    PipeClient *pipeclient;
    IPCRemoteV2Tracker *remotehandler;

    bool tracker_free;

    vector<string> path_vec;

    pid_t child_pid;

    string FindBinaryPath(string in_cmd);

    string binary_path;
    vector<string> binary_args;

};

/* IPC remote handler / coordinator
 *
 * Maintains a list of opened child processes and allows centralized management
 * and shutdown.
 *
 */
class IPCRemoteV2Tracker : public TimetrackerEvent {
public:
    IPCRemoteV2Tracker(GlobalRegistry *in_globalreg);
    ~IPCRemoteV2Tracker();

    // Add an IPC handler to tracking
    void add_ipc(IPCRemoteV2 *in_remote);
    // Remove an IPC handler from tracking.  Does NOT destroy or close the IPC
    // handler.  Return the handler which was removed.
    IPCRemoteV2 *remove_ipc(IPCRemoteV2 *in_remote);
    // Remove an IPC handler from tracking by PID.  Does NOT destroy or close
    // the IPC handler.  Return the handler which was removed.
    IPCRemoteV2 *remove_ipc(pid_t in_pid);

    // Kill all spawned processes
    void kill_all_ipc(bool in_hardkill);

    // Ensure all processes are down.  Give processes a maximum of in_soft_delay
    // seconds to terminate cleanly before sending a SIGKILL.  Do not delay 
    // more than in_max_delay.
    int ensure_all_ipc_killed(int in_soft_delay, int in_max_delay);

    // Timetracker API
    virtual int timetracker_event(int event_id);

protected:
    pthread_mutex_t ipc_locker;

    GlobalRegistry *globalreg;

    vector<IPCRemoteV2 *> process_vec;

    int timer_id;
};

#endif

