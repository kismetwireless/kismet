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

#include "ipctracker_v2.h"

#include "messagebus.h"
#include "timetracker.h"

ipc_tracker_v2::ipc_tracker_v2() :
    lifetime_global{} {
    mutex.set_name("ipc_tracker_v2");

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

    dead_reaper_event_id = 
        timetracker->register_timer(std::chrono::seconds(1), true, 
                [this](int) -> int {
                    dead_ipc_reaper_event();
                    return 1;
                });
}

ipc_tracker_v2::~ipc_tracker_v2() {
    auto timetracker = 
        Globalreg::fetch_global_as<time_tracker>();

    if (timetracker != nullptr) {
        timetracker->remove_timer(dead_reaper_event_id);
    }
}

void ipc_tracker_v2::register_ipc(const kis_ipc_record& ipc) {
    kis_lock_guard<kis_mutex> lk(mutex, "ipc_tracker_v2 register_ipc");

    auto ik = ipc_map.find(ipc.pid);

    if (ik != ipc_map.end()) {
        _MSG_ERROR("Attempted to register IPC PID {}, but it already exists.", ipc.pid);
        return;
    }

    ipc_map[ipc.pid] = ipc;
}

void ipc_tracker_v2::remove_ipc(pid_t pid) {
    kis_lock_guard<kis_mutex> lk(mutex, "ipc_tracker_v2 remove_ipc");

    auto ik = ipc_map.find(pid);

    if (ik != ipc_map.end())
        ipc_map.erase(ik);
}

void ipc_tracker_v2::soft_kill_all() {
    kis_lock_guard<kis_mutex> lk(mutex, "ipc_tracker_v2 soft_kill_all");

    for (const auto& p : ipc_map) {
        if (p.second.close_func != nullptr)
            p.second.close_func("Shutting down all IPC connections");
        kill(p.second.pid, SIGTERM);
    }
}

void ipc_tracker_v2::hard_kill_all() {
    kis_lock_guard<kis_mutex> lk(mutex, "ipc_tracker_v2 hard_kill_all");

    for (const auto& p : ipc_map) {
        if (p.second.close_func != nullptr)
            p.second.close_func("Shutting down all IPC connections");
        kill(p.second.pid, SIGKILL);
    }
}

void ipc_tracker_v2::shutdown_all(int in_soft_delay, int in_max_delay) {
    // Remove the dead reaper task
    auto timetracker = Globalreg::fetch_global_as<time_tracker>();

    _MSG_DEBUG("tracker v2 shutdown_all");
    
    if (timetracker != nullptr)
        timetracker->remove_timer(dead_reaper_event_id);

    auto start_time = time(0);
    bool hardkilled = false;

    // Spin waiting for them to exit
    while (1) {
        int pid_status;
        pid_t caught_pid;
        kis_ipc_record::close_func_t close_cb;

        if ((caught_pid = waitpid(-1, &pid_status, WNOHANG | WUNTRACED)) > 0) {
            {
                kis_lock_guard<kis_mutex> lk(mutex, "ipc_tracker_v2 shutdown_all");

                auto pk = ipc_map.find(caught_pid);

                if (pk != ipc_map.end()) {
                    auto close_cb = pk->second.close_func;
                    ipc_map.erase(pk);
                }
            }

            if (close_cb != nullptr)
                close_cb("Shutting down all IPC...");
        } else {
            usleep(100);
        }

        if (time(0) - start_time > in_soft_delay && ipc_map.size() > 0 && !hardkilled) {
            hard_kill_all();
            hardkilled = true;
        }

        if (time(0) - start_time > in_max_delay)
            break;
    }
}

int ipc_tracker_v2::dead_ipc_reaper_event() {
    int pid_status;
    pid_t caught_pid;

    while ((caught_pid = waitpid(-1, &pid_status, WNOHANG | WUNTRACED)) > 0) {
        kis_ipc_record::error_func_t err_cb;

        {
            kis_lock_guard<kis_mutex> lk(mutex, "ipc_tracker_v2 dead_ipc_reaper_event");
            auto pk = ipc_map.find(caught_pid);
            if (pk != ipc_map.end()) {
                err_cb = pk->second.error_func;
                ipc_map.erase(pk);
            }
        }

        if (err_cb != nullptr)
            err_cb(fmt::format("Process exited with status {}", WEXITSTATUS(pid_status)));
    }

    return 1;
}

