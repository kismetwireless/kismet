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

    What a waitpid() report on an IPC helper MEANS.

    Split out of ipctracker_v2.cc, header-only and free of the server's
    headers, for the same reason phy_cell_decisions is: the decision is
    separable from the syscall that feeds it, and a test can feed it REAL wait
    statuses from forked children without linking a Kismet server.

    The reaper waits with WUNTRACED, so a report is one of three things:

    * the helper EXITED -- WEXITSTATUS is its exit code;
    * the helper was KILLED by a signal -- WEXITSTATUS is meaningless (0 for a
      SIGKILL), so "Process exited with status {WEXITSTATUS}" would read a
      helper killed by signal 9 as "exited with status 0";
    * the helper merely STOPPED (SIGSTOP, SIGTSTP, a debugger) -- it has not
      ended at all. Treated as a death, a stopped helper would be erased from
      the tracker, so no SIGTERM or hard kill of the server's would reach it
      again, and a closing source would be told "Process exited with status
      19": the stop signal, reported as a clean close.
*/

#ifndef __IPCTRACKER_CHILD_STATUS_H__
#define __IPCTRACKER_CHILD_STATUS_H__

#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#include <string>

/* True when the report is a STOP: the helper is alive and must stay tracked. */
inline bool ipc_child_only_stopped(int pid_status) {
    return WIFSTOPPED(pid_status);
}

/* How a helper that waitpid() reported has ENDED, in words. Keeps the old
 * "Process exited with status N" wording for a real exit, which operators and
 * docs already quote. */
inline std::string ipc_child_end_text(int pid_status) {
    char buf[160];
    if (WIFEXITED(pid_status)) {
        snprintf(buf, sizeof(buf), "Process exited with status %d",
                 WEXITSTATUS(pid_status));
    } else if (WIFSIGNALED(pid_status)) {
        int sig = WTERMSIG(pid_status);
        snprintf(buf, sizeof(buf), "Process killed by signal %d (%s)", sig,
                 strsignal(sig));
    } else {
        snprintf(buf, sizeof(buf), "Process ended with wait status %#x",
                 (unsigned) pid_status);
    }
    return buf;
}

#endif /* __IPCTRACKER_CHILD_STATUS_H__ */
