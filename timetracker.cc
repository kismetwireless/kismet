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

    // Free the events
    for (std::map<int, timer_event *>::iterator x = timer_map.begin();
         x != timer_map.end(); ++x)
        delete x->second;
}

void time_tracker::time_dispatcher() {
    while (!shutdown && !Globalreg::globalreg->spindown && !Globalreg::globalreg->fatal_condition) {
        kis_unique_lock<kis_mutex> lock(time_mutex, std::defer_lock, "time_tracker time_dispatcher");

        // Calculate the next tick
        auto start = std::chrono::system_clock::now();
        auto end = start + std::chrono::milliseconds(1000 / SERVER_TIMESLICES_SEC);

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
        auto action_timers = std::vector<timer_event *>(sorted_timers.begin(), sorted_timers.end());
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

            // Call the function with the given parameters
            int ret = 0;
            if (evt->callback != NULL) {
                ret = (*evt->callback)(evt, evt->callback_parm, Globalreg::globalreg);
            } else if (evt->event != NULL) {
                ret = evt->event->timetracker_event(evt->timer_id);
            } else if (evt->event_func != NULL) {
                ret = evt->event_func(evt->timer_id);
            }

            if (ret > 0 && evt->timeslices != -1 && evt->recurring) {
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
                continue;
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

                    delete itr->second;
                    timer_map.erase(itr);
                }
            }

            removed_timer_ids.clear();
        }

        /*
        if (std::chrono::system_clock::now() >= end) {
            fmt::print("debug - timetracker missed time slot by {} ms\n",
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - end).count());
        }
        */


        std::this_thread::sleep_until(end);
    }
}

int time_tracker::register_timer(int in_timeslices, struct timeval *in_trigger,
                               int in_recurring, 
                               int (*in_callback)(TIMEEVENT_PARMS),
                               void *in_parm) {
    kis_lock_guard<kis_mutex> lk(time_mutex);

    timer_event *evt = new timer_event;

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

    timer_event *evt = new timer_event;

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

    timer_event *evt = new timer_event;

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

    timer_event *evt = new timer_event;

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

    timer_event *evt = new timer_event;

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

