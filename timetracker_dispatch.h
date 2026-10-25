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

/* timetracker_dispatch.h - which timers one dispatcher tick launches, and what
 * a finished callback does to its timer.
 *
 * Header-only and framework-free, for the same reason datasource_probe_reason.h
 * is: time_tracker::time_dispatcher() needs a global registry, worker threads
 * and a wall clock, so the rule inside it could not be tested. Lifted out, the
 * dispatcher calls exactly this code and test_timetracker_dispatch.cc drives it
 * tick by tick.
 *
 * The hazard.  A launched timer stays in the sorted list, with its trigger time
 * unchanged, until its callback RETURNS: a one-shot's id reaches the removal list
 * only then, and is pruned at the END of a later tick; a recurring timer's next
 * trigger is set only then. Any tick that comes round in between sees the timer
 * still due and launches it AGAIN. The window opens whenever a callback outlives
 * the tick that launched it -- the datasource retry callback takes the source's
 * mutex and spawns a helper, which takes milliseconds -- and it is widest when
 * ticks run back to back, which they do after a stall while the dispatcher's
 * 100 ms phase catches up with the wall clock.  After a server SIGSTOP, for
 * example, a one-shot retry timer can fire twice a few ms apart, and the two
 * re-opens collide and cost the source another retry interval.
 *
 * The rule.  A timer is marked in flight when a tick launches it, and a tick never
 * launches a timer that is in flight. A recurring timer is cleared when its
 * callback has set its next trigger; a one-shot never is, so nothing can launch
 * it again before it is removed.
 */

#ifndef __TIMETRACKER_DISPATCH_H__
#define __TIMETRACKER_DISPATCH_H__

#include <chrono>

/* Walk one tick's snapshot of the sorted timers, in trigger order. `Timer` needs
 * `timer_cancelled` and `in_flight` (both std::atomic<bool>) and `trigger_tm`.
 *   on_cancelled(evt)  -- a cancelled timer, for the removal list
 *   launch(evt)        -- a due timer that is not already running
 * Returns how many timers were launched. */
template <class Timers, class OnCancelled, class Launch>
int timetracker_dispatch_tick(const Timers& timers,
        std::chrono::system_clock::time_point now,
        OnCancelled on_cancelled, Launch launch) {
    int launched = 0;

    for (const auto& evt : timers) {
        // If we're pending cancellation, throw us out
        if (evt->timer_cancelled) {
            on_cancelled(evt);
            continue;
        }

        // We're into the future, bail
        if (now < evt->trigger_tm)
            break;

        // Still running from an earlier tick: its callback has not
        // returned, so neither its removal nor its next trigger has happened
        // yet. Launching it again is the double fire.
        bool expected = false;
        if (!evt->in_flight.compare_exchange_strong(expected, true))
            continue;

        // Re-read the trigger now the timer is ours. A recurring callback that
        // returned between the due check above and the claim has already moved
        // it; the claim acquired that store, so this read sees the new trigger.
        if (now < evt->trigger_tm) {
            evt->in_flight = false;
            continue;
        }

        launch(evt);
        launched++;
    }

    return launched;
}

/* What a worker does once a timer's callback has returned `ret`. Called with the
 * time_tracker's time mutex NOT held; `reschedule` runs under it.
 *   reschedule(evt)  -- a recurring timer that wants to run again: set its next
 *                       trigger (the caller does it under the time mutex)
 *   remove(evt)      -- anything else: onto the removal list
 * Returns true when the timer was rescheduled. */
template <class TimerPtr, class Reschedule, class Remove>
bool timetracker_dispatch_finish(const TimerPtr& evt, int ret,
        Reschedule reschedule, Remove remove) {
    if (ret > 0 && evt->timeslices != -1 && evt->recurring) {
        reschedule(evt);
        // Only now may a tick launch it again: its trigger is the NEXT one.
        evt->in_flight = false;
        return true;
    }

    // A one-shot (or a recurring timer that asked to stop) stays in flight until
    // it is pruned, so no tick before the prune can launch it again.
    remove(evt);
    return false;
}

#endif
