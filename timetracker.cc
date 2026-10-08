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

#include <chrono>
#include <thread>

#include <sys/time.h>

#include "timetracker.h"

#include "messagebus.h"

time_tracker::time_tracker() {
    time_mutex.set_name("time_tracker");
    removed_id_mutex.set_name("time_tracker_removed_id");

    next_timer_id = 1;

    timer_sort_required = true;

    struct timeval cur_tm;
    gettimeofday(&cur_tm, NULL);

    Globalreg::globalreg->start_time = cur_tm.tv_sec;
    Globalreg::globalreg->last_tv_sec = cur_tm.tv_sec;
    Globalreg::globalreg->last_tv_usec = cur_tm.tv_usec;

    shutdown = false;
    workers_shutdown = false;

    auto n_worker_threads = std::max(4U, std::thread::hardware_concurrency());

    for (unsigned int x = 0; x < n_worker_threads; x++) {
        time_workers.emplace_back([this]() {
                thread_set_process_name("TIME_EVT");
                time_worker();
            });
    }

    /*
    time_dispatch_t =
        std::thread([this]() {
                thread_set_process_name("timers");
                time_dispatcher();
            });
            */

}

void time_tracker::spawn_timetracker_thread() {
    time_dispatch_t =
        std::thread([this]() {
                thread_set_process_name("timers");
                time_dispatcher();
            });
}

time_tracker::~time_tracker() {
    shutdown = true;

    if (time_dispatch_t.joinable())
        time_dispatch_t.join();

    // Running callbacks finish; anything still queued is dropped
    {
        std::lock_guard<std::mutex> lk(work_mutex);
        workers_shutdown = true;
        work_queue.clear();
    }

    work_cv.notify_all();

    for (auto& w : time_workers) {
        if (w.joinable())
            w.join();
    }

    Globalreg::globalreg->remove_global("TIMETRACKER");
    Globalreg::globalreg->timetracker = NULL;
}

void time_tracker::time_dispatcher() {
    unsigned int interval = 0;

    auto start = time(0);
    auto then = std::chrono::system_clock::from_time_t(start + 1);

    std::this_thread::sleep_until(then);

    while (!shutdown && !Globalreg::globalreg->spindown && !Globalreg::globalreg->fatal_condition) {
        auto now = time(0);
        std::chrono::system_clock::time_point next;

        switch (++interval % 10) {
            case 0:
                next = std::chrono::system_clock::from_time_t(now + 1);
                break;
            default:
                next = std::chrono::system_clock::from_time_t(now) +
                    std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) *
                            (interval % SERVER_TIMESLICES_SEC));
                break;
        }

        kis_unique_lock<kis_mutex> lock(time_mutex, std::defer_lock, "time_tracker time_dispatcher");

        // Handle scheduled events
        struct timeval cur_tm;
        gettimeofday(&cur_tm, NULL);

        auto chrono_now = std::chrono::system_clock::now();

        Globalreg::globalreg->last_tv_sec = cur_tm.tv_sec;
        Globalreg::globalreg->last_tv_usec = cur_tm.tv_usec;

        // Collect due timers under the lock; a timer whose last run hasn't finished is
        // skipped and picked up again once it reschedules itself
        std::vector<std::shared_ptr<timer_event>> due;

        lock.lock();

        if (timer_sort_required)
            std::stable_sort(sorted_timers.begin(), sorted_timers.end(), sort_timer_events_trigger());

        timer_sort_required = false;

        for (const auto& evt : sorted_timers) {
            if (chrono_now < evt->trigger_tm)
                break;

            // Cancelled timers are already queued for removal
            if (evt->timer_cancelled || evt->running)
                continue;

            evt->running = true;
            due.push_back(evt);
        }

        lock.unlock();

        if (!due.empty()) {
            {
                std::lock_guard<std::mutex> lk(work_mutex);
                for (auto& evt : due)
                    work_queue.emplace_back(std::move(evt), chrono_now);
            }

            work_cv.notify_all();
        }

        {
            // Actually remove the timers under dual lock
            std::lock(time_mutex, removed_id_mutex);
            kis_lock_guard<kis_mutex> l(time_mutex, std::adopt_lock);
            kis_lock_guard<kis_mutex> rl(removed_id_mutex, std::adopt_lock);

            for (auto x : removed_timer_ids) {
                auto itr = timer_map.find(x);

                if (itr != timer_map.end()) {
                    for (auto sorted_itr = sorted_timers.begin(); sorted_itr != sorted_timers.end(); ++sorted_itr) {
                        if ((*sorted_itr)->timer_id == x) {
                            sorted_timers.erase(sorted_itr);
                            break;
                        }
                    }

                    timer_map.erase(itr);
                }
            }

            removed_timer_ids.clear();
        }

        std::this_thread::sleep_until(next);
    }
}

void time_tracker::time_worker() {
    while (true) {
        std::pair<std::shared_ptr<timer_event>, std::chrono::system_clock::time_point> work;

        {
            std::unique_lock<std::mutex> lk(work_mutex);
            work_cv.wait(lk, [this]() { return workers_shutdown || !work_queue.empty(); });

            if (workers_shutdown)
                return;

            work = std::move(work_queue.front());
            work_queue.pop_front();
        }

        run_timer(work.first, work.second);
    }
}

namespace {
    // Timer whose callback this worker thread is running
    thread_local int current_timer_id = -1;
}

void time_tracker::run_timer(const std::shared_ptr<timer_event>& evt,
        std::chrono::system_clock::time_point dispatch_tm) {
    int ret = 0;

    // Marked before checking for cancellation; remove_timer cancels before checking this,
    // so either the callback is skipped or remove_timer waits for it
    evt->in_callback = true;

    if (!evt->timer_cancelled) {
        current_timer_id = evt->timer_id;

        if (evt->callback != NULL) {
            ret = (*evt->callback)(evt.get(), evt->callback_parm, Globalreg::globalreg);
        } else if (evt->event != NULL) {
            ret = evt->event->timetracker_event(evt->timer_id);
        } else if (evt->event_func != NULL) {
            ret = evt->event_func(evt->timer_id);
        }

        current_timer_id = -1;
    }

    {
        std::lock_guard<std::mutex> lk(done_mutex);
        evt->in_callback = false;
    }

    done_cv.notify_all();

    if (ret > 0 && evt->timeslices != -1 && evt->recurring && !evt->timer_cancelled) {
        kis_lock_guard<kis_mutex> tl(time_mutex, "event rescheduler");

        evt->schedule_tm = dispatch_tm;
        evt->trigger_tm = dispatch_tm +
            std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) * evt->timeslices);

        timer_sort_required = true;
        evt->running = false;
    } else {
        // Left marked running so it can't be dispatched again before it's removed
        kis_lock_guard<kis_mutex> rl(removed_id_mutex, "event remover");
        removed_timer_ids.push_back(evt->timer_id);
    }
}

int time_tracker::register_timer(int in_timeslices, struct timeval *in_trigger,
                               int in_recurring,
                               int (*in_callback)(TIMEEVENT_PARMS),
                               void *in_parm) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_id = next_timer_id++;

    evt->schedule_tm = std::chrono::system_clock::now();

    if (in_trigger != NULL) {
        evt->trigger_tm =
            std::chrono::system_clock::from_time_t(in_trigger->tv_sec) +
            std::chrono::microseconds(in_trigger->tv_usec);
        evt->timeslices = -1;
    } else {
        evt->trigger_tm = evt->schedule_tm +
            std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) * in_timeslices);
        evt->timeslices = in_timeslices;
    }


    evt->recurring = in_recurring;
    evt->callback = in_callback;
    evt->callback_parm = in_parm;
    evt->event = NULL;

    timer_map[evt->timer_id] = evt;
    sorted_timers.push_back(evt);

    // Resort the list
    timer_sort_required = true;

    return evt->timer_id;
}

int time_tracker::register_timer(int in_timeslices, struct timeval *in_trigger,
        int in_recurring, time_tracker_event *in_event) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_cancelled = false;
    evt->timer_id = next_timer_id++;

    evt->schedule_tm = std::chrono::system_clock::now();

    if (in_trigger != NULL) {
        evt->trigger_tm =
            std::chrono::system_clock::from_time_t(in_trigger->tv_sec) +
            std::chrono::microseconds(in_trigger->tv_usec);
        evt->timeslices = -1;
    } else {
        evt->trigger_tm = evt->schedule_tm +
            std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) * in_timeslices);
        evt->timeslices = in_timeslices;
    }

    evt->recurring = in_recurring;
    evt->callback = NULL;
    evt->callback_parm = NULL;
    evt->event = in_event;

    timer_map[evt->timer_id] = evt;
    sorted_timers.push_back(evt);

    // Resort the list
    timer_sort_required = true;

    return evt->timer_id;
}

int time_tracker::register_timer(int in_timeslices, struct timeval *in_trigger,
        int in_recurring, std::function<int (int)> in_event) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_cancelled = false;
    evt->timer_id = next_timer_id++;

    evt->schedule_tm = std::chrono::system_clock::now();

    if (in_trigger != NULL) {
        evt->trigger_tm =
            std::chrono::system_clock::from_time_t(in_trigger->tv_sec) +
            std::chrono::microseconds(in_trigger->tv_usec);
        evt->timeslices = -1;
    } else {
        evt->trigger_tm = evt->schedule_tm +
            std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) * in_timeslices);
        evt->timeslices = in_timeslices;
    }

    evt->recurring = in_recurring;
    evt->callback = NULL;
    evt->callback_parm = NULL;
    evt->event = NULL;

    evt->event_func = in_event;

    timer_map[evt->timer_id] = evt;
    sorted_timers.push_back(evt);

    // Resort the list
    timer_sort_required = true;

    return evt->timer_id;
}

int time_tracker::register_timer(const slice& in_timeslices,
                               int in_recurring,
                               int (*in_callback)(TIMEEVENT_PARMS),
                               void *in_parm) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_id = next_timer_id++;

    evt->schedule_tm = std::chrono::system_clock::now();

    evt->timeslices = in_timeslices.count();

    evt->trigger_tm = evt->schedule_tm +
        std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) * evt->timeslices);

    evt->recurring = in_recurring;
    evt->callback = in_callback;
    evt->callback_parm = in_parm;
    evt->event = NULL;

    timer_map[evt->timer_id] = evt;
    sorted_timers.push_back(evt);

    // Resort the list
    timer_sort_required = true;

    return evt->timer_id;
}

int time_tracker::register_timer(const slice& in_timeslices,
        int in_recurring, std::function<int (int)> in_event) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_cancelled = false;
    evt->timer_id = next_timer_id++;

    evt->schedule_tm = std::chrono::system_clock::now();

    evt->timeslices = in_timeslices.count();

    evt->trigger_tm = evt->schedule_tm +
        std::chrono::milliseconds((1000 / SERVER_TIMESLICES_SEC) * evt->timeslices);

    evt->recurring = in_recurring;
    evt->callback = NULL;
    evt->callback_parm = NULL;
    evt->event = NULL;

    evt->event_func = in_event;

    timer_map[evt->timer_id] = evt;
    sorted_timers.push_back(evt);

    // Resort the list
    timer_sort_required = true;

    return evt->timer_id;
}

std::shared_ptr<time_tracker::timer_event> time_tracker::cancel_timer_event(int in_timerid) {
    // Cancel and queue for removal from the main list on the next dispatch pass
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto itr = timer_map.find(in_timerid);

    if (itr == timer_map.end())
        return nullptr;

    itr->second->timer_cancelled = true;

    kis_lock_guard<kis_mutex> rl(removed_id_mutex);
    removed_timer_ids.push_back(in_timerid);

    return itr->second;
}

int time_tracker::cancel_timer(int in_timerid) {
    return cancel_timer_event(in_timerid) != nullptr;
}

int time_tracker::remove_timer(int in_timerid) {
    auto evt = cancel_timer_event(in_timerid);

    if (evt == nullptr)
        return 0;

    // A timer removing itself is still inside its callback
    if (in_timerid == current_timer_id)
        return 1;

    std::unique_lock<std::mutex> lk(done_mutex);

    if (!evt->in_callback)
        return 1;

    if (current_timer_id >= 0) {
        // Don't wait on a timer which is itself waiting, directly or through others, on
        // the timer we're running in
        for (auto w = waits_on.find(in_timerid); w != waits_on.end(); w = waits_on.find(w->second)) {
            if (w->second == current_timer_id)
                return 1;
        }

        waits_on[current_timer_id] = in_timerid;
    }

    done_cv.wait(lk, [&evt]() { return !evt->in_callback; });

    if (current_timer_id >= 0)
        waits_on.erase(current_timer_id);

    return 1;
}

