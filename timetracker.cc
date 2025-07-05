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

    // Allocate workers and fill them with joinable threads
    auto n_worker_threads = static_cast<unsigned int>(std::thread::hardware_concurrency());
    time_workers.resize(n_worker_threads);

    for (unsigned int x = 0; x < time_workers.size(); x++) {
        time_workers[x] = std::thread([]() { });
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

    // time_dispatch_t.join();

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

        Globalreg::globalreg->last_tv_sec = cur_tm.tv_sec;
        Globalreg::globalreg->last_tv_usec = cur_tm.tv_usec;

        // Sort and duplicate the vector to a safe list; we have to re-sort
        // timers from recurring events
        lock.lock();

        if (timer_sort_required)
            sort(sorted_timers.begin(), sorted_timers.end(), sort_timer_events_trigger());

        timer_sort_required = false;

        // Sort the timers
        auto action_timers = std::vector<std::shared_ptr<timer_event>>(sorted_timers.begin(), sorted_timers.end());
        lock.unlock();

        for (auto evt : action_timers) {
            // If we're pending cancellation, throw us out
            if (evt->timer_cancelled) {
                kis_lock_guard<kis_mutex> rl(removed_id_mutex);
                removed_timer_ids.push_back(evt->timer_id);
                continue;
            }

            // We're into the future, bail
            if ((cur_tm.tv_sec < evt->trigger_tm.tv_sec) ||
                    ((cur_tm.tv_sec == evt->trigger_tm.tv_sec) && (cur_tm.tv_usec < evt->trigger_tm.tv_usec))) {
                break;
            }

            // Find a usable worker slot; this is a fast-burn while loop for now
            // to see how it performs, if we need to add a sleep we will
            bool launched = false;
            time_t started_looking = time(0);
            while (!launched) {
                // Catch an unwinnable situation for timers; 5 seconds is actually excessively long for
                // timers that could be executing at 10Hz.
                if (started_looking - time(0) > 5) {
                    throw std::runtime_error("Couldn't find a slot in the timer handlers in 5 seconds; something "
                                             "has gone wrong, most likely thread deadlocks.");
                }

                for (unsigned int t = 0; t < time_workers.size(); t++) {
                    // Found a worker slot
                    if (time_workers[t].joinable()) {
                        time_workers[t].join();

                        time_workers[t] = std::thread([evt, this]() {
                            thread_set_process_name("TIME_EVT");

                            // Call the function with the given parameters
                            int ret = 0;
                            if (evt->callback != NULL) {
                                ret = (*evt->callback)(evt.get(), evt->callback_parm, Globalreg::globalreg);
                            } else if (evt->event != NULL) {
                                ret = evt->event->timetracker_event(evt->timer_id);
                            } else if (evt->event_func != NULL) {
                                ret = evt->event_func(evt->timer_id);
                            }

                            if (ret > 0 && evt->timeslices != -1 && evt->recurring) {
                                kis_lock_guard<kis_mutex> tl(time_mutex, "event rescheduler");

                                struct timeval cur_tm;
                                gettimeofday(&cur_tm, NULL);

                                evt->schedule_tm.tv_sec = cur_tm.tv_sec;
                                evt->schedule_tm.tv_usec = cur_tm.tv_usec;
                                evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (evt->timeslices / SERVER_TIMESLICES_SEC);
                                evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + 
                                    ((evt->timeslices % SERVER_TIMESLICES_SEC) * (1000000L / SERVER_TIMESLICES_SEC));

                                if (evt->trigger_tm.tv_usec >= 999999L) {
                                    evt->trigger_tm.tv_sec++;
                                    evt->trigger_tm.tv_usec %= 1000000L;
                                }

                                timer_sort_required = true;
                            } else {
                                kis_lock_guard<kis_mutex> rl(removed_id_mutex);
                                removed_timer_ids.push_back(evt->timer_id);
                            }
                        });

                        launched = true;
                        break;
                    }
                }
            }
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

int time_tracker::register_timer(int in_timeslices, struct timeval *in_trigger,
                               int in_recurring, 
                               int (*in_callback)(TIMEEVENT_PARMS),
                               void *in_parm) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_id = next_timer_id++;
    gettimeofday(&(evt->schedule_tm), NULL);

    if (in_trigger != NULL) {
        evt->trigger_tm.tv_sec = in_trigger->tv_sec;
        evt->trigger_tm.tv_usec = in_trigger->tv_usec;
        evt->timeslices = -1;
    } else {
        evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (in_timeslices / 10);
        evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + (in_timeslices % 10);
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

    gettimeofday(&(evt->schedule_tm), NULL);

    if (in_trigger != NULL) {
        evt->trigger_tm.tv_sec = in_trigger->tv_sec;
        evt->trigger_tm.tv_usec = in_trigger->tv_usec;
        evt->timeslices = -1;
    } else {
        evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + 
            (in_timeslices / SERVER_TIMESLICES_SEC);
        evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + 
            ((in_timeslices % SERVER_TIMESLICES_SEC) *
             (1000000L / SERVER_TIMESLICES_SEC));

        if (evt->trigger_tm.tv_usec >= 999999L) {
            evt->trigger_tm.tv_sec++;
            evt->trigger_tm.tv_usec %= 1000000L;
        }
            
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

    gettimeofday(&(evt->schedule_tm), NULL);

    if (in_trigger != NULL) {
        evt->trigger_tm.tv_sec = in_trigger->tv_sec;
        evt->trigger_tm.tv_usec = in_trigger->tv_usec;
        evt->timeslices = -1;
    } else {
        evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + 
            (in_timeslices / SERVER_TIMESLICES_SEC);
        evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + 
            ((in_timeslices % SERVER_TIMESLICES_SEC) * 
             (1000000L / SERVER_TIMESLICES_SEC));
        evt->timeslices = in_timeslices;

        if (evt->trigger_tm.tv_usec >= 999999L) {
            evt->trigger_tm.tv_sec++;
            evt->trigger_tm.tv_usec %= 1000000L;
        }
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
    gettimeofday(&(evt->schedule_tm), NULL);

    evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + (in_timeslices.count() / 10);
    evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + (in_timeslices.count() % 10);
    evt->timeslices = in_timeslices.count();

    if (evt->trigger_tm.tv_usec >= 999999L) {
        evt->trigger_tm.tv_sec++;
        evt->trigger_tm.tv_usec %= 1000000L;
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

int time_tracker::register_timer(const slice& in_timeslices,
        int in_recurring, std::function<int (int)> in_event) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto evt = std::make_shared<timer_event>();

    evt->total_ms = 0;
    evt->last_ms = 0;

    evt->timer_cancelled = false;
    evt->timer_id = next_timer_id++;

    gettimeofday(&(evt->schedule_tm), NULL);

    evt->trigger_tm.tv_sec = evt->schedule_tm.tv_sec + 
        (in_timeslices.count() / SERVER_TIMESLICES_SEC);
    evt->trigger_tm.tv_usec = evt->schedule_tm.tv_usec + 
        ((in_timeslices.count() % SERVER_TIMESLICES_SEC) * 
         (1000000L / SERVER_TIMESLICES_SEC));
    evt->timeslices = in_timeslices.count();

    if (evt->trigger_tm.tv_usec >= 999999L) {
        evt->trigger_tm.tv_sec++;
        evt->trigger_tm.tv_usec %= 1000000L;
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

int time_tracker::remove_timer(int in_timerid) {
    // Removing a timer sets the atomic cancelled and puts us on the abort list;
    // we'll get cleaned out of the main list the next iteration through the main code.
    
    kis_lock_guard<kis_mutex> lk(time_mutex);

    auto itr = timer_map.find(in_timerid);

    if (itr != timer_map.end()) {
        itr->second->timer_cancelled = true;

        kis_lock_guard<kis_mutex> lk(removed_id_mutex);
        removed_timer_ids.push_back(in_timerid);
    } else {
        return 0;
    }

    return 1;
}

