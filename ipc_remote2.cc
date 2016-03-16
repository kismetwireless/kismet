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

