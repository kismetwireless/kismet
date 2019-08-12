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

#ifndef __POLLABLETRACKER_H__
#define __POLLABLETRACKER_H__

#include "config.h"

#include <queue>
#include <vector>

#include <sys/time.h>

#include "kis_mutex.h"
#include "globalregistry.h"

/* kis_pollable subsystem tracker
 *
 * Monitors pollable events and wraps them into a single select() loop
 * and handles erroring out sources after their events have been processed.
 *
 * Add/remove from the pollable vector is handled asynchronously to protect the
 * integrity of the pollable object itself and the internal pollable vectors;
 * adds and removes are synced at the next descriptor or poll event.
 */

class kis_pollable;

class pollable_tracker : public lifetime_global {
public:
    static std::string global_name() { return "POLLABLETRACKER"; }

    static std::shared_ptr<pollable_tracker> 
        create_pollabletracker() {
        std::shared_ptr<pollable_tracker> mon(new pollable_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    pollable_tracker();

public:
    virtual ~pollable_tracker();

    // Add a pollable item
    void register_pollable(std::shared_ptr<kis_pollable> in_pollable);

    // Schedule a pollable item to be removed as soon as the current
    // operation completes (or the next one begins); This allows errored sources
    // to remove themselves once their tasks are complete.
    void remove_pollable(std::shared_ptr<kis_pollable> in_pollable);

    // Perform a select loop; blocks until polling exits
    void select_loop(bool spindown_loop);

    // Perform a cleanup of any operations, like adding a pollable to the list or removing it
    void maintenance();

    // populate the FD sets for polling, populates rset and wset
    //
    // returns:
    // 0+   Maximum FD to be passed to select()
    // -1   Error
    int merge_pollable_fds(fd_set *rset, fd_set *wset);
   
    // pollable_poll each item in a set
    //
    // returns:
    // 0+   Number of pollable items processed
    // -1   Error
    int process_pollable_select(fd_set rset, fd_set wset);

protected:
    void poll_queue_processor();

    class pollable_event {
        public:
            pollable_event(fd_set in_rset, fd_set in_wset, std::shared_ptr<kis_pollable> in_pollable) :
                rset {in_rset},
                wset {in_wset},
                pollable {in_pollable} { }

            fd_set rset, wset;
            std::shared_ptr<kis_pollable> pollable;
    };

    std::queue<pollable_event> pollable_queue;
    bool pollable_shutdown;

    std::vector<std::thread> pollable_threads;

    // Poll notification cv
    std::mutex pollqueue_cv_mutex;
    std::condition_variable pollqueue_cv;

    // We don't need as complex a synchronization method because we don't modify
    // ta callback chain like we do for the packet chain; we just don't dispatch 
    // a pollable.  Pollable items should engage a mutex during poll so it shouldn't
    // be a problem to just remove them from the main pollable vector through
    // the normal method of placing it into a queue that gets cleaned up by the 
    // maintenance cycle

    kis_recursive_timed_mutex pollable_mutex, maintenance_mutex;

    std::vector<std::shared_ptr<kis_pollable>> pollable_vec;
    std::vector<std::shared_ptr<kis_pollable>> add_vec;
    std::map<std::shared_ptr<kis_pollable>, int> remove_map;

};

#endif
