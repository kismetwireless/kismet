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
#include "pollabletracker.h"

IPCRemoteV2::IPCRemoteV2(GlobalRegistry *in_globalreg, 
        std::shared_ptr<BufferHandlerGeneric> in_rbhandler) :
        globalreg {Globalreg::globalreg},
        ipc_mutex {std::make_shared<kis_recursive_timed_mutex>()},
        tracker_free {false},
        child_pid {0} {

    pollabletracker =
        Globalreg::FetchMandatoryGlobalAs<PollableTracker>();

    remotehandler = 
        Globalreg::FetchMandatoryGlobalAs<IPCRemoteV2Tracker>();

    tracker_free = false;

    ipchandler = in_rbhandler;

    ipchandler->SetProtocolErrorCb([this]() {
        close_ipc();
    });

}

void IPCRemoteV2::SetMutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    local_locker l(ipc_mutex);

    if (in_parent != nullptr)
        ipc_mutex = in_parent;
    else
        ipc_mutex = std::make_shared<kis_recursive_timed_mutex>();

    if (pipeclient != nullptr)
        pipeclient->SetMutex(in_parent);
}

IPCRemoteV2::~IPCRemoteV2() {
    if (pipeclient != nullptr) {
        pollabletracker->RemovePollable(pipeclient);
        pipeclient->ClosePipes();
    }

    if (ipchandler != nullptr) {
        ipchandler->SetProtocolErrorCb([]() { });
        ipchandler->BufferError("IPC process has closed");
    }

    hard_kill();
    child_pid = 0;
}

void IPCRemoteV2::add_path(std::string in_path) {
    local_locker lock(ipc_mutex);
    path_vec.push_back(in_path);
}

std::string IPCRemoteV2::FindBinaryPath(std::string in_cmd) {
    local_locker lock(ipc_mutex);

    for (unsigned int x = 0; x < path_vec.size(); x++) {
        std::stringstream path;
        struct stat buf;

        path << path_vec[x] << "/" << in_cmd;

        if (stat(path.str().c_str(), &buf) < 0)
            continue;

        if (buf.st_mode & S_IXUSR)
            return path.str();
    }

    return "";
}

void IPCRemoteV2::close_ipc() {
    local_locker lock(ipc_mutex);

    if (remotehandler != nullptr) {
        remotehandler->remove_ipc(this);
    }

    hard_kill();
}

int IPCRemoteV2::launch_kis_binary(std::string cmd, std::vector<std::string> args) {
    std::string fullcmd = FindBinaryPath(cmd);

    if (fullcmd == "") {
        _MSG("IPC could not find binary '" + cmd + "'", MSGFLAG_ERROR);
        return -1;
    }

    return launch_kis_explicit_binary(fullcmd, args);
}

int IPCRemoteV2::launch_kis_explicit_binary(std::string cmdpath, std::vector<std::string> args) {
    struct stat buf;
    char **cmdarg;
    std::stringstream arg;

    if (stat(cmdpath.c_str(), &buf) < 0) {
        _MSG("IPC could not find binary '" + cmdpath + "'", MSGFLAG_ERROR);
        return -1;
    }

    if (!(buf.st_mode & S_IXOTH)) {
        if (getuid() != buf.st_uid && getuid() != 0) {
            bool group_ok = false;
            gid_t *groups;
            int ngroups;

            if (getgid() != buf.st_gid) {
                ngroups = getgroups(0, NULL);

                if (ngroups > 0) {
                    groups = new gid_t[ngroups];
                    ngroups = getgroups(ngroups, groups);

                    for (int g = 0; g < ngroups; g++) {
                        if (groups[g] == buf.st_gid) {
                            group_ok = true;
                            break;
                        }
                    }

                    delete[] groups;
                }

                if (!group_ok) {
                    _MSG("IPC cannot run binary '" + cmdpath + "', Kismet was installed "
                            "setgid and you are not in that group. If you recently added your "
                            "user to the kismet group, you will need to log out and back in to "
                            "activate it.  You can check your groups with the 'groups' command.",
                            MSGFLAG_ERROR);
                    return -1;
                }
            }
        }
    }

    // We can't use a local_locker here because we can't let it unlock
    // inside the child thread, because the mutex doesn't survive across
    // forking
    local_eol_locker ilock(ipc_mutex);

    // 'in' to the spawned process, write to the server process, 
    // [1] belongs to us, [0] to them
    int inpipepair[2];
    // 'out' from the spawned process, read to the server process, 
    // [0] belongs to us, [1] to them
    int outpipepair[2];

#ifdef HAVE_PIPE2
    if (pipe2(inpipepair, O_NONBLOCK) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }

    if (pipe2(outpipepair, O_NONBLOCK) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        close(inpipepair[0]);
        close(inpipepair[1]);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }
#else
    if (pipe(inpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }
    fcntl(inpipepair[0], F_SETFL, fcntl(inpipepair[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(inpipepair[1], F_SETFL, fcntl(inpipepair[1], F_GETFL, 0) | O_NONBLOCK);

    if (pipe(outpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        close(inpipepair[0]);
        close(inpipepair[1]);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }
    fcntl(outpipepair[0], F_SETFL, fcntl(outpipepair[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(outpipepair[1], F_SETFL, fcntl(outpipepair[1], F_GETFL, 0) | O_NONBLOCK);

#endif
    
    // Mask sigchild until we're done and it's in the list
    sigset_t mask, oldmask;

    sigemptyset(&mask);
    sigemptyset(&oldmask);

    sigaddset(&mask, SIGCHLD);

    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    if ((child_pid = fork()) < 0) {
        _MSG("IPC could not fork()", MSGFLAG_ERROR);
        local_unlocker ulock(ipc_mutex);
    } else if (child_pid == 0) {
        // We're the child process
      
        // argv[0], "--in-fd" "--out-fd" ... NULL
        cmdarg = new char*[args.size() + 4];
        cmdarg[0] = strdup(cmdpath.c_str());

        // Child reads from inpair
        arg << "--in-fd=" << inpipepair[0];
        cmdarg[1] = strdup(arg.str().c_str());
        arg.str("");

        // Child writes to writepair
        arg << "--out-fd=" << outpipepair[1];
        cmdarg[2] = strdup(arg.str().c_str());

        for (unsigned int x = 0; x < args.size(); x++)
            cmdarg[x+3] = strdup(args[x].c_str());

        cmdarg[args.size() + 3] = NULL;

        // Close the unused half of the pairs on the child
        close(inpipepair[1]);
        close(outpipepair[0]);

        // Un-mask the child signals
        sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

        // fprintf(stderr, "debug - ipcremote2 - exec %s\n", cmdarg[0]);
        execvp(cmdarg[0], cmdarg);

        exit(255);
    } 

    // fprintf(stderr, "forked, child pid %d\n", child_pid);
   
    // Parent process
   
    // fprintf(stderr, "debug - ipcremote2 creating pipeclient\n");
    
    
    // Close the remote side of the pipes from the parent, they're open in the child
    close(inpipepair[0]);
    close(outpipepair[1]);

    if (pipeclient != NULL) {
        soft_kill();
    }

    pipeclient.reset(new PipeClient(globalreg, ipchandler));
    pipeclient->SetMutex(ipc_mutex);

    // Read from the child write pair, write to the child read pair
    pipeclient->OpenPipes(outpipepair[0], inpipepair[1]);

    pollabletracker->RegisterPollable(pipeclient);

    binary_path = cmdpath;
    binary_args = args;

    {
        local_unlocker ulock(ipc_mutex);
    }

    // Unmask the child signal now that we're done
    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

    return 1;
}

int IPCRemoteV2::launch_standard_binary(std::string cmd, std::vector<std::string> args) {
    std::string fullcmd = FindBinaryPath(cmd);

    if (fullcmd == "") {
        _MSG("IPC could not find binary '" + cmd + "'", MSGFLAG_ERROR);
        return -1;
    }

    return launch_standard_explicit_binary(fullcmd, args);
}

int IPCRemoteV2::launch_standard_explicit_binary(std::string cmdpath, std::vector<std::string> args) {
    struct stat buf;
    char **cmdarg;
    std::stringstream arg;

    if (pipeclient != NULL) {
        soft_kill();
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
    local_eol_locker elock(ipc_mutex);

    // 'in' to the spawned process, [0] belongs to us, [1] to them
    int inpipepair[2];
    // 'out' from the spawned process, [1] belongs to us, [0] to them
    int outpipepair[2];

    if (pipe(inpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }

    if (pipe(outpipepair) < 0) {
        _MSG("IPC could not create pipe", MSGFLAG_ERROR);
        close(inpipepair[0]);
        close(inpipepair[1]);
        local_unlocker ulock(ipc_mutex);
        return -1;
    }

    // Mask sigchild until we're done and it's in the list
    sigset_t mask, oldmask;

    sigemptyset(&mask);
    sigemptyset(&oldmask);

    sigaddset(&mask, SIGCHLD);

    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    if ((child_pid = fork()) < 0) {
        _MSG("IPC could not fork()", MSGFLAG_ERROR);
        local_unlocker ulock(ipc_mutex);
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

    pipeclient.reset(new PipeClient(globalreg, ipchandler));
    pipeclient->SetMutex(ipc_mutex);

    pollabletracker->RegisterPollable(pipeclient);

    // We read from the read end of the out pair, and write to the write end of the in
    // pair.  Confused?
    pipeclient->OpenPipes(outpipepair[0], inpipepair[1]);

    binary_path = cmdpath;
    binary_args = args;

    {
        local_unlocker ulock(ipc_mutex);
    }

    // Unmask the child signal now that we're done
    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

    return 1;
}

pid_t IPCRemoteV2::get_pid() {
    local_locker lock(ipc_mutex);
    return child_pid;
}

void IPCRemoteV2::set_tracker_free(bool in_free) {
    local_locker lock(ipc_mutex);
    tracker_free = in_free;
}

int IPCRemoteV2::soft_kill() {
    local_locker lock(ipc_mutex);

    if (pipeclient != nullptr) {
        pollabletracker->RemovePollable(pipeclient);
        pipeclient->ClosePipes();
    }

    if (child_pid <= 0)
        return -1;

    return kill(child_pid, SIGTERM);
}

int IPCRemoteV2::hard_kill() {
    local_locker lock(ipc_mutex);

    if (pipeclient != nullptr) {
        pollabletracker->RemovePollable(pipeclient);
        pipeclient->ClosePipes();
    }

    if (child_pid <= 0) {
        return -1;
    }

    return kill(child_pid, SIGKILL);
}

void IPCRemoteV2::notify_killed(int in_exit) {
    std::stringstream ss;

    // Pull anything left in the buffer and process it
    if (pipeclient != nullptr) {
        pipeclient->FlushRead();
    }

    if (ipchandler != nullptr) {
        ss << "IPC process '" << binary_path << "' " << child_pid << " exited, " << in_exit;
        ipchandler->BufferError(ss.str());
    }

    child_pid = 0;
    close_ipc();
}

IPCRemoteV2Tracker::IPCRemoteV2Tracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    timer_id = 
        globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1, this);
    cleanup_timer_id = -1;
}

IPCRemoteV2Tracker::~IPCRemoteV2Tracker() {
    globalreg->RemoveGlobal("IPCHANDLER");

    globalreg->timetracker->RemoveTimer(timer_id);
    globalreg->timetracker->RemoveTimer(cleanup_timer_id);
}

void IPCRemoteV2Tracker::add_ipc(std::shared_ptr<IPCRemoteV2> in_remote) {
    local_locker lock(&ipc_mutex);

    for (auto r : process_vec) {
        if (r == in_remote) {
            return;
        }
    }

    process_vec.push_back(in_remote);
}

std::shared_ptr<IPCRemoteV2> IPCRemoteV2Tracker::remove_ipc(IPCRemoteV2 *in_remote) {
    local_locker lock(&ipc_mutex);

    std::shared_ptr<IPCRemoteV2> ret;

    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (process_vec[x].get() == in_remote) {
            ret = process_vec[x];
            cleanup_vec.push_back(ret);
            process_vec.erase(process_vec.begin() + x);
            break;
        }
    }

    schedule_cleanup();

    return ret;
}

void IPCRemoteV2Tracker::schedule_cleanup() {
    if (cleanup_timer_id > 0)
        return;

    cleanup_timer_id = 
        Globalreg::globalreg->timetracker->RegisterTimer(2, NULL, 0, 
                [this] (int) -> int {
                    local_locker lock(&ipc_mutex);

                    cleanup_vec.clear();

                    cleanup_timer_id = 0;
                    return 0;
                });

}

std::shared_ptr<IPCRemoteV2> IPCRemoteV2Tracker::remove_ipc(pid_t in_pid) {
    local_locker lock(&ipc_mutex);

    std::shared_ptr<IPCRemoteV2> ret;

    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (process_vec[x]->get_pid() == in_pid) {
            ret = process_vec[x];
            cleanup_vec.push_back(ret);
            process_vec.erase(process_vec.begin() + x);
            break;
        }
    }

    schedule_cleanup();

    return ret;
}

void IPCRemoteV2Tracker::kill_all_ipc(bool in_hardkill) {
    local_locker lock(&ipc_mutex);

    // Leave everything in the vec until we properly reap it, we might
    // need to go back and kill it again
    for (unsigned int x = 0; x < process_vec.size(); x++) {
        if (in_hardkill)
            process_vec[x]->hard_kill();
        else
            process_vec[x]->soft_kill();
    }
}

int IPCRemoteV2Tracker::ensure_all_ipc_killed(int in_soft_delay, int in_max_delay) {
    // We can't immediately lock since killall will need to

    // Soft-kill every process
    kill_all_ipc(false);

    time_t start_time = time(0);

    // It would be more efficient to hijack the signal handler here and
    // use our own timer, but that's a hassle and this only happens during
    // shutdown.  We do a spin on waitpid instead.

    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigemptyset(&oldmask);

    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    while (1) {
        int pid_status;
        pid_t caught_pid;
        std::shared_ptr<IPCRemoteV2> killed_remote;

        caught_pid = waitpid(-1, &pid_status, WNOHANG);

        // If we caught a pid, blindly remove it from the vec, we don't
        // care if we caught a pid we don't know about I suppose
        if (caught_pid > 0) {
            killed_remote = remove_ipc(caught_pid);

            // TODO decide if we're going to delete the IPC handler too
            if (killed_remote != nullptr) {
                killed_remote->notify_killed(WEXITSTATUS(pid_status)); 
            }
        } else {
            // Sleep if we haven't caught anything, otherwise spin to catch all
            // pending processes
            usleep(100);
        }

        if (time(0) - start_time > in_soft_delay)
            break;
    }

    bool vector_empty = true;

    {
        local_locker lock(&ipc_mutex);
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
        kill_all_ipc(true);

        while (1) {
            int pid_status;
            pid_t caught_pid;
            std::shared_ptr<IPCRemoteV2> killed_remote;

            caught_pid = waitpid(-1, &pid_status, WNOHANG);

            // If we caught a pid, blindly remove it from the vec, we don't
            // care if we caught a pid we don't know about I suppose
            if (caught_pid > 0) {
                killed_remote = remove_ipc(caught_pid);

                // TODO decide if we're going to delete the IPC handler too
                if (killed_remote != NULL)
                    killed_remote->notify_killed(WEXITSTATUS(pid_status));
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
        local_locker lock(&ipc_mutex);
        if (process_vec.size() > 0)
            vector_empty = false;
    }

    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    if (vector_empty)
        return 0;

    return -1;
}

int IPCRemoteV2Tracker::timetracker_event(int event_id __attribute__((unused))) {
    local_locker l(&ipc_mutex);

    std::stringstream str;
    std::shared_ptr<IPCRemoteV2> dead_remote;

    // Turn off sigchild while we process the list
    sigset_t mask, oldmask;

    sigemptyset(&mask);
    sigemptyset(&oldmask);

    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    for (unsigned int x = 0; x < 1024 && x < globalreg->sigchild_vec_pos; x++) {
        pid_t caught_pid = globalreg->sigchild_vec[x];

        // fprintf(stderr, "debug - sigchild - %u\n", caught_pid);

        dead_remote = remove_ipc(caught_pid);

        // printf("dead remote %p\n", dead_remote.get());

        if (dead_remote != nullptr) {
            dead_remote->notify_killed(0);
            dead_remote->close_ipc();

            if (dead_remote->get_tracker_free()) {
                str.str("");
                str << "Deleting tracked IPC for " << dead_remote->get_pid();
                _MSG(str.str(), MSGFLAG_INFO);
            }
        } else {
            /* We don't care, and having initiated a shutdown we'll already have
             * removed the source.
             *
            str << "IPC child pid " << caught_pid << " exited with status " <<
                WEXITSTATUS(pid_status) << " but was not tracked";
            _MSG(str.str(), MSGFLAG_INFO);
            */
        }

    }

    globalreg->sigchild_vec_pos = 0;

    sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

    return 1;
}

