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

#ifndef __IPCTRACKER_V2_H__
#define __IPCTRACKER_V2_H__ 

#include "config.h"

#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <unordered_map>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"

// Simple tracker that gives us a callback if an ipc launched child gets an event; generally this
// should also trigger a pipe close which would yield the same result.
class kis_ipc_record {
public:
    using error_func_t = std::function<void (const std::string& errmsg)>;
    using close_func_t = std::function<void (const std::string& reason)>;

    kis_ipc_record() :
        pid{-1},
        close_func{nullptr},
        error_func{nullptr} { }

    kis_ipc_record(pid_t pid, close_func_t closecb, error_func_t errorcb) :
        pid{pid},
        close_func{closecb},
        error_func{errorcb} { }

    pid_t pid;
    close_func_t close_func;
    error_func_t error_func;
};

class ipc_tracker_v2 : public lifetime_global {
public:
    static std::string global_name() { return "IPCTRACKER"; }

    static std::shared_ptr<ipc_tracker_v2> create_ipctracker() {
        std::shared_ptr<ipc_tracker_v2> mon(new ipc_tracker_v2());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    ipc_tracker_v2();

public:
    virtual ~ipc_tracker_v2();

    void register_ipc(const kis_ipc_record& ipc);
    void remove_ipc(pid_t pid);

    void soft_kill_all();
    void hard_kill_all();

    void shutdown_all(int in_soft_delay, int in_max_delay);

protected:
    kis_mutex mutex;
    
    std::unordered_map<pid_t, kis_ipc_record> ipc_map;

    int dead_reaper_event_id;
    int dead_ipc_reaper_event();
};



#endif /* ifndef IPCTRACKER_V2_H */
