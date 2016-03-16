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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>

#include "util.h"
#include "messagebus.h"
#include "ipc_remote2.h"

IPCRemoteV2::IPCRemoteV2(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    pthread_mutex_init(&ipc_locker, NULL);

    pipeclient = NULL;
    ipchandler = NULL;

    child_pid = -1;
}

IPCRemoteV2::~IPCRemoteV2() {
    {
        local_locker lock(&ipc_locker);
        if (pipeclient != NULL)
            delete(pipeclient);
        if (ipchandler != NULL)
            delete(ipchandler);
    }

    pthread_mutex_destroy(&ipc_locker);
}

void IPCRemoteV2::AddPath(string in_path) {
    local_locker lock(&ipc_locker);
    path_vec.push_back(in_path);
}

string IPCRemoteV2::FindBinaryPath(string in_cmd) {
    local_locker lock(&ipc_locker);

    for (unsigned int x = 0; x < path_vec.size(); x++) {
        stringstream path;
        struct stat buf;

        path << path_vec[x] << "/" << in_cmd;

        if (stat(path.str().c_str(), &buf) < 0)
            continue;

        if (buf.st_mode & S_IXUSR)
            return path.str();
    }

    return "";
}

void IPCRemoteV2::Close() {
    if (pipeclient != NULL) {
        delete(pipeclient);
        pipeclient = NULL;
    }

    if (ipchandler != NULL) {
        delete(ipchandler);
        ipchandler = NULL;
    }
}

int IPCRemoteV2::LaunchKisBinary(string cmd, vector<string> args) {
    string fullcmd = FindBinaryPath(cmd);

    if (fullcmd == "") {
        _MSG("IPC could not find binary '" + cmd + "'", MSGFLAG_ERROR);
        return -1;
    }

    return LaunchKisExplicitBinary(fullcmd, args);
}

int IPCRemoteV2::LaunchKisExplicitBinary(string cmdpath, vector<string> args) {
    struct stat buf;
    char **cmdarg;
    stringstream arg;

    if (pipeclient != NULL) {
        delete(pipeclient);
        pipeclient = NULL;
    }

    if (stat(cmdpath.c_str(), &buf) < 0) {
        _MSG("IPC could not find binary '" + cmdpath + "'", MSGFLAG_ERROR);
        return -1;
    }

    if (!(buf.st_mode & S_IXUSR)) {
        _MSG("IPC could not find binary '" + cmdpath + "'", MSGFLAG_ERROR);
        return -1;
    }

    // We can't use a local_locker here because we can't let it unlock
    // inside the child thread, because the mutex doesn't survive across
    // forking
    pthread_mutex_lock(&ipc_locker);

    // 'in' to the spawned process, [0] belongs to us, [1] to them
    int inpipepair[2];
    // 'out' from the spawned process, [1] belongs to us, [0] to them
    int outpipepair[2];

    if (pipe(inpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        pthread_mutex_unlock(&ipc_locker);
        return -1;
    }

    if (pipe(outpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        close(inpipepair[0]);
        close(inpipepair[1]);
        pthread_mutex_unlock(&ipc_locker);
        return -1;
    }

    if ((child_pid = fork()) < 0) {
        _MSG("IPC could not fork()", MSGFLAG_ERROR);
        pthread_mutex_unlock(&ipc_locker);
    } else if (child_pid == 0) {
        // We're the child process
        
        // argv[0], "--in-fd" "--out-fd" ... NULL
        cmdarg = new char*[args.size() + 4];
        cmdarg[0] = strdup(cmdpath.c_str());

        // FD we read from is the read end of the in pair
        arg << "--in-fd=" << inpipepair[1];
        cmdarg[1] = strdup(arg.str().c_str());
        arg.str("");

        // FD we write to is the write end of the out pair
        arg << "--out-fd=" << outpipepair[0];
        cmdarg[2] = strdup(arg.str().c_str());

        for (unsigned int x = 0; x < args.size(); x++)
            cmdarg[x+3] = strdup(args[x].c_str());

        cmdarg[args.size() + 3] = NULL;

        // Close the remote side of the pipes
        close(inpipepair[0]);
        close(outpipepair[1]);

        execvp(cmdarg[0], cmdarg);

        exit(255);
    } 

    // Only reach here if we're the parent process
    
    // Close the remote side of the pipes
    close(inpipepair[1]);
    close(outpipepair[0]);

    // Build the handler with generous default buffers.  A raw packet can be
    // at least 1500 bytes, plus framing, plus metadata, and so on.  For extra
    // safety, just make the buffer 64k
    ipchandler = new RingbufferHandler(65536UL, 65536UL);
    pipeclient = new PipeClient(globalreg, ipchandler);

    // We read from the read end of the out pair, and write to the write end of the in
    // pair.  Confused?
    pipeclient->OpenPipes(outpipepair[0], inpipepair[1]);

    binary_path = cmdpath;
    binary_args = args;

    pthread_mutex_unlock(&ipc_locker);

    return 1;
}

int IPCRemoteV2::LaunchStdBinary(string cmd, vector<string> args) {
    string fullcmd = FindBinaryPath(cmd);

    if (fullcmd == "") {
        _MSG("IPC could not find binary '" + cmd + "'", MSGFLAG_ERROR);
        return -1;
    }

    return LaunchStdExplicitBinary(fullcmd, args);
}

int IPCRemoteV2::LaunchStdExplicitBinary(string cmdpath, vector<string> args) {
    struct stat buf;
    char **cmdarg;
    stringstream arg;

    if (pipeclient != NULL) {
        delete(pipeclient);
        pipeclient = NULL;
    }

    if (stat(cmdpath.c_str(), &buf) < 0) {
        _MSG("IPC could not find binary '" + cmdpath + "'", MSGFLAG_ERROR);
        return -1;
    }

    if (!(buf.st_mode & S_IXUSR)) {
        _MSG("IPC could not find binary '" + cmdpath + "'", MSGFLAG_ERROR);
        return -1;
    }

    // We can't use a local_locker here because we can't let it unlock
    // inside the child thread, because the mutex doesn't survive across
    // forking
    pthread_mutex_lock(&ipc_locker);

    // 'in' to the spawned process, [0] belongs to us, [1] to them
    int inpipepair[2];
    // 'out' from the spawned process, [1] belongs to us, [0] to them
    int outpipepair[2];

    if (pipe(inpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        pthread_mutex_unlock(&ipc_locker);
        return -1;
    }

    if (pipe(outpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        close(inpipepair[0]);
        close(inpipepair[1]);
        pthread_mutex_unlock(&ipc_locker);
        return -1;
    }

    if ((child_pid = fork()) < 0) {
        _MSG("IPC could not fork()", MSGFLAG_ERROR);
        pthread_mutex_unlock(&ipc_locker);
    } else if (child_pid == 0) {
        // We're the child process
        
        // argv[0], "--in-fd" "--out-fd" ... NULL
        cmdarg = new char*[args.size() + 1];
        cmdarg[0] = strdup(cmdpath.c_str());

        for (unsigned int x = 0; x < args.size(); x++)
            cmdarg[x+3] = strdup(args[x].c_str());

        cmdarg[args.size() + 1] = NULL;

        // Clone over the stdin/stdout
        dup2(inpipepair[0], STDIN_FILENO);
        dup2(outpipepair[1], STDOUT_FILENO);

        // Close the remote side of the pipes
        close(inpipepair[0]);
        close(outpipepair[1]);

        execvp(cmdarg[0], cmdarg);

        exit(255);
    } 

    // Only reach here if we're the parent process
    
    // Close the remote side of the pipes
    close(inpipepair[1]);
    close(outpipepair[0]);

    // Might as well leave them as a generous 64k buffer
    ipchandler = new RingbufferHandler(65536UL, 65536UL);
    pipeclient = new PipeClient(globalreg, ipchandler);

    // We read from the read end of the out pair, and write to the write end of the in
    // pair.  Confused?
    pipeclient->OpenPipes(outpipepair[0], inpipepair[1]);

    binary_path = cmdpath;
    binary_args = args;

    pthread_mutex_unlock(&ipc_locker);

    return 1;
}

pid_t IPCRemoteV2::GetPid() {
    local_locker lock(&ipc_locker);
    return child_pid;
}

int IPCRemoteV2::Kill() {
    if (child_pid <= 0)
        return -1;

    return kill(child_pid, SIGTERM);
}

int IPCRemoteV2::HardKill() {
    if (child_pid <= 0)
        return -1;

    return kill(child_pid, SIGKILL);
}

IPCRemoteHandler::IPCRemoteHandler(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    globalreg->InsertGlobal("IPCHANDLER", this);

    pthread_mutex_init(&ipc_locker, NULL);

    timer_id = 
        globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, this);
}

IPCRemoteHandler::~IPCRemoteHandler() {
    globalreg->RemoveGlobal("IPCHANDLER");

    globalreg->timetracker->RemoveTimer(timer_id);

    pthread_mutex_destroy(&ipc_locker);
}

void IPCRemoteHandler::AddIPC(IPCRemoteV2 *in_remote) {
    local_locker lock(&ipc_locker);

    process_vec.push_back(in_remote);
}

IPCRemoteV2 *IPCRemoteHandler::RemoveIPC(IPCRemoteV2 *in_remote) {
    local_locker lock(&ipc_locker);

    IPCRemoteV2 *ret = NULL;

    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (process_vec[x] == in_remote) {
            ret = process_vec[x];
            process_vec.erase(process_vec.begin() + x);
            break;
        }
    }

    return ret;
}

IPCRemoteV2 *IPCRemoteHandler::RemoveIPC(pid_t in_pid) {
    local_locker lock(&ipc_locker);

    IPCRemoteV2 *ret = NULL;

    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (process_vec[x]->GetPid() == in_pid) {
            ret = process_vec[x];
            process_vec.erase(process_vec.begin() + x);
            break;
        }
    }

    return ret;
}

void IPCRemoteHandler::KillAllIPC(bool in_hardkill) {
    local_locker lock(&ipc_locker);

    // Leave everything in the vec until we properly reap it, we might
    // need to go back and kill it again
    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (in_hardkill)
            process_vec[x]->HardKill();
        else
            process_vec[x]->Kill();
    }
}

int IPCRemoteHandler::EnsureAllKilled(int in_soft_delay, int in_max_delay) {
    // We can't immediately lock since killall will need to

    // Soft-kill every process
    KillAllIPC(false);

    time_t start_time = time(0);

    // It would be more efficient to hijack the signal handler here and
    // use our own timer, but that's a hassle and this only happens during
    // shutdown.  We do a spin on waitpid instead.
    while (1) {
        int pid_status;
        pid_t caught_pid;
        IPCRemoteV2 *killed_remote = NULL;

        caught_pid = waitpid(-1, &pid_status, WNOHANG);

        // If we caught a pid, blindly remove it from the vec, we don't
        // care if we caught a pid we don't know about I suppose
        if (caught_pid > 0) {
            killed_remote = RemoveIPC(caught_pid);

            // TODO decide if we're going to delete the IPC handler too
            if (killed_remote != NULL)
                killed_remote->Close();
        } else {
            // Sleep if we haven't caught anything, otherwise spin to catch all
            // pending processes
            usleep(1000);
        }

        if (time(0) - start_time > in_soft_delay)
            break;
    }

    bool vector_empty = true;

    {
        local_locker lock(&ipc_locker);
        if (process_vec.size() > 0)
            vector_empty = false;
    }

    // If we've run out of time, stop
    if (time(0) - start_time > in_max_delay) {
        if (vector_empty)
            return 0;
        return -1;
    }

    // If we need to kill things the hard way
    if (!vector_empty) {
        KillAllIPC(true);

        while (1) {
            int pid_status;
            pid_t caught_pid;
            IPCRemoteV2 *killed_remote = NULL;

            caught_pid = waitpid(-1, &pid_status, WNOHANG);

            // If we caught a pid, blindly remove it from the vec, we don't
            // care if we caught a pid we don't know about I suppose
            if (caught_pid > 0) {
                killed_remote = RemoveIPC(caught_pid);

                // TODO decide if we're going to delete the IPC handler too
                if (killed_remote != NULL)
                    killed_remote->Close();
            } else {
                // Sleep if we haven't caught anything, otherwise spin to catch all
                // pending processes
                usleep(1000);
            }

            if (in_max_delay != 0 && time(0) - start_time > in_max_delay)
                break;
        }
    }

    {
        local_locker lock(&ipc_locker);
        if (process_vec.size() > 0)
            vector_empty = false;
    }

    if (vector_empty)
        return 0;

    return -1;
}

int IPCRemoteHandler::timetracker_event(int event_id __attribute__((unused))) {
    while (1) {
        int pid_status;
        pid_t caught_pid;
        IPCRemoteV2 *dead_remote = NULL;
        stringstream str;

        caught_pid = waitpid(-1, &pid_status, WNOHANG);

        if (caught_pid > 0) {
            dead_remote = RemoveIPC(caught_pid);

            if (dead_remote != NULL) {
                str << "IPC child pid " << dead_remote->GetPid() << " exited with " <<
                    "status " << WEXITSTATUS(pid_status);
                _MSG(str.str(), MSGFLAG_ERROR);
                dead_remote->Close();
            }
        } else {
            break;
        }
    }

    return 1;
}

