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

#include "pollabletracker.h"
#include "pollable.h"

#undef KIS_USE_POLLABLE_QUEUE

pollable_tracker::pollable_tracker() {
#ifdef KIS_USE_POLLABLE_QUEUE
    pollable_shutdown = false;

    for (unsigned int i = 0; i < std::thread::hardware_concurrency(); i++) {
        pollable_threads.push_back(std::thread([this]() {
            thread_set_process_name("pollhandler");
            poll_queue_processor();
        }));
	}
#endif
}

pollable_tracker::~pollable_tracker() {
#ifdef KIS_USE_POLLABLE_QUEUE
    // Cancel, wake up, and collect all the service threads
    pollable_shutdown = true;
    pollqueue_cv.notify_all();

    for (auto& t : pollable_threads)
        t.join();
#endif
}

void pollable_tracker::register_pollable(std::shared_ptr<kis_pollable> in_pollable) {
    if (in_pollable == nullptr)
        return;

    local_locker lock(&pollable_mutex);

    add_vec.push_back(in_pollable);
}

void pollable_tracker::remove_pollable(std::shared_ptr<kis_pollable> in_pollable) {
    if (in_pollable == nullptr)
        return;

    local_locker lock(&pollable_mutex);

    remove_map[in_pollable] = 1;
}

void pollable_tracker::maintenance() {
    local_locker lock(&pollable_mutex);

    for (auto r : remove_map) {
        for (auto i = pollable_vec.begin(); i != pollable_vec.end(); ++i) {
            if (r.first == *i) {
                pollable_vec.erase(i);
                break;
            }
        }
    }

    for (auto i = add_vec.begin(); i != add_vec.end(); ++i) {
        pollable_vec.push_back(*i);
    }

    remove_map.clear();
    add_vec.clear();
}

void pollable_tracker::select_loop(bool spindown_mode) {
    int max_fd;
    fd_set rset, wset;
    struct timeval tm;
    int consec_badfd = 0;

    time_t shutdown_time = time(0) + 3;

    // Core loop
    while (1) {
        if (spindown_mode && time(0) > shutdown_time)
            break;

        if ((!spindown_mode && Globalreg::globalreg->spindown) || 
                Globalreg::globalreg->fatal_condition ||
                Globalreg::globalreg->complete) 
            break;

        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        maintenance();

        max_fd = merge_pollable_fds(&rset, &wset);

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno == EBADF) {
                    consec_badfd++;

                    if (consec_badfd > 20) 
                        throw std::runtime_error(fmt::format("select() > 20 consecutive badfd errors, latest {} {}",
                                    errno, strerror(errno)));

                    continue;
                } else {
                    throw std::runtime_error(fmt::format("select() failed: {} {}", errno, strerror(errno)));
                }
            }
        }

        consec_badfd = 0;

        // Run maintenance again so we don't gather purged records after the select()
        maintenance();

        process_pollable_select(rset, wset);
    }
}

int pollable_tracker::merge_pollable_fds(fd_set *rset, fd_set *wset) {
    int max_fd = 0;

    FD_ZERO(rset);
    FD_ZERO(wset);

    for (auto i : pollable_vec) {
        int r = i->pollable_merge_set(max_fd, rset, wset);

        if (r < 0) {
            remove_pollable(i);
            continue;
        }

        max_fd = r;
    }

    return max_fd;
}

int pollable_tracker::process_pollable_select(fd_set rset, fd_set wset) {
#ifdef KIS_USE_POLLABLE_QUEUE
    // Push all into the pollable vector and let the service threads do the work
    
    std::unique_lock<std::mutex> lock(pollqueue_cv_mutex);

    for (auto p : pollable_vec) 
        pollable_queue.push(pollable_event(rset, wset, p));

    lock.unlock();
    pollqueue_cv.notify_all();
#else
    int r;

    for (auto i : pollable_vec) {
        r = i->pollable_poll(rset, wset);

        if (r < 0) {
            remove_pollable(i);
            continue;
        }
    }
#endif

    return 1;
}

void pollable_tracker::poll_queue_processor() {
    std::unique_lock<std::mutex> lock(pollqueue_cv_mutex);

    // We only monitor our own shutdown and global complete; we need to continue doing
    // IO to do a graceful spindown
    while (!pollable_shutdown && !Globalreg::globalreg->complete) {

        pollqueue_cv.wait(lock, [this] {
            return (pollable_queue.size() || pollable_shutdown);
            });

        // We own the lock; make sure to re-lock it as we leave the loop
        
        if (pollable_queue.size() != 0) {
            // Get the pollable, unlock the queue
            auto pollable = pollable_queue.front();
            pollable_queue.pop();

            lock.unlock();

            // Perform the IO and handling
            pollable.pollable->pollable_poll(pollable.rset, pollable.wset);

            lock.lock();

            continue;
        }

        lock.lock();
    }
}

