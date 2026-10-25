/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Framework-free selftest for the timer dispatch rule.
 *
 * Builds and runs with a bare `c++ -std=c++17 -I. test_timetracker_dispatch.cc`
 * on any host, like test_datasource_probe_reason.cc: the rule lives in
 * timetracker_dispatch.h, which time_tracker::time_dispatcher() calls, and this
 * drives it one tick at a time with a callback that has NOT returned -- the state
 * no test could hold the real dispatcher in.
 *
 * What this CANNOT prove: that time_dispatcher() calls the header. That wiring
 * is a few lines of timetracker.cc; the live check is a server stall (SIGSTOP,
 * then SIGCONT), which must show one re-open per source.
 */

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <memory>
#include <vector>

#include "timetracker_dispatch.h"

using clk = std::chrono::system_clock;

static int failures = 0;

static void check(bool cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        printf("PASS: %s\n", what);
    }
}

/* The fields of time_tracker::timer_event the rule reads, spelled the same. */
struct fake_timer {
    int timer_id = 0;
    std::atomic<bool> timer_cancelled{false};
    std::atomic<bool> in_flight{false};
    clk::time_point trigger_tm;
    int timeslices = 50;
    int recurring = 0;
};
using timer_ptr = std::shared_ptr<fake_timer>;

static const clk::time_point T0 = clk::time_point(std::chrono::seconds(1000000));

static timer_ptr one_shot(int id, clk::time_point trigger) {
    auto t = std::make_shared<fake_timer>();
    t->timer_id = id;
    t->trigger_tm = trigger;
    t->timeslices = -1;
    return t;
}

static timer_ptr recurring(int id, clk::time_point trigger, int slices) {
    auto t = std::make_shared<fake_timer>();
    t->timer_id = id;
    t->trigger_tm = trigger;
    t->timeslices = slices;
    t->recurring = 1;
    return t;
}

/* One tick over a snapshot; returns the ids launched and cancelled. */
struct tick_result {
    std::vector<int> launched, cancelled;
};

template <class Timers>
static tick_result tick(const Timers& timers, clk::time_point now) {
    tick_result r;
    timetracker_dispatch_tick(timers, now,
        [&](const typename Timers::value_type& e) { r.cancelled.push_back(e->timer_id); },
        [&](const typename Timers::value_type& e) { r.launched.push_back(e->timer_id); });
    return r;
}

/* A worker finishing a callback: reschedule sets the next trigger from `now`,
 * exactly as timetracker.cc's reschedule lambda does. */
static bool finish(const timer_ptr& e, int ret, clk::time_point now,
        std::vector<int> *removed) {
    return timetracker_dispatch_finish(e, ret,
        [&](const timer_ptr& t) {
            t->trigger_tm = now + std::chrono::milliseconds(100 * t->timeslices);
        },
        [&](const timer_ptr& t) { removed->push_back(t->timer_id); });
}

/* A trigger whose FIRST comparison answers from the old value and THEN runs a
 * hook -- so a callback's return lands exactly between the due check and the
 * claim. (Hook first would make the due check itself see the new trigger and
 * the walk would stop there, never reaching the claim: a vacuous test.) */
struct racy_trigger {
    clk::time_point tp;
    std::function<void()> on_first_read;
    mutable int reads = 0;
};
static bool operator<(clk::time_point now, const racy_trigger& t) {
    bool before = now < t.tp;
    if (t.reads++ == 0 && t.on_first_read)
        t.on_first_read();
    return before;
}
struct racy_timer {
    int timer_id = 0;
    std::atomic<bool> timer_cancelled{false};
    std::atomic<bool> in_flight{false};
    racy_trigger trigger_tm;
};

int main(void) {
    const auto ms = [](int n) { return std::chrono::milliseconds(n); };

    /* 1. THE BUG: a one-shot whose callback has not returned by the next tick.
     * The datasource retry: launched at 974.000, still spawning its helper at
     * the next tick. Before the fix the second tick launched it again. */
    {
        std::vector<timer_ptr> sorted = { one_shot(7, T0) };
        std::vector<int> removed;
        auto t1 = tick(sorted, T0 + ms(1));
        check(t1.launched == std::vector<int>{7}, "one-shot: the first due tick launches it");
        auto t2 = tick(sorted, T0 + ms(3));
        check(t2.launched.empty(),
              "one-shot: a tick while its callback is still running does NOT launch it again");

        /* The callback returns; the removal list has it, but the prune happens at
         * the END of a later tick -- so the snapshot still holds it. */
        check(!finish(sorted[0], 0, T0 + ms(5), &removed) &&
              removed == std::vector<int>{7}, "one-shot: finishing puts it on the removal list");
        auto t3 = tick(sorted, T0 + ms(6));
        check(t3.launched.empty(),
              "one-shot: a tick after it returned but before the prune does NOT launch it");
        check(sorted[0]->in_flight, "one-shot: it stays in flight until pruned");
    }

    /* 2. Back-to-back catch-up ticks after a stall: many ticks at ~the same time,
     * one launch. This is the 2 ms double re-open, generalised. */
    {
        std::vector<timer_ptr> sorted = { one_shot(1, T0), one_shot(2, T0 + ms(1)) };
        int n1 = 0, n2 = 0;
        for (int i = 0; i < 20; i++) {
            auto r = tick(sorted, T0 + ms(2) + ms(i / 10));
            for (int id : r.launched)
                (id == 1 ? n1 : n2)++;
        }
        check(n1 == 1 && n2 == 1, "20 back-to-back ticks launch each one-shot exactly once");
    }

    /* 3. A recurring timer is held the same way while it runs, and runs again
     * at -- and only at -- the trigger its callback set. */
    {
        std::vector<timer_ptr> sorted = { recurring(3, T0, 10) };
        std::vector<int> removed;
        check(tick(sorted, T0).launched == std::vector<int>{3}, "recurring: launched when due");
        check(tick(sorted, T0 + ms(100)).launched.empty(),
              "recurring: not relaunched while its callback runs");
        check(finish(sorted[0], 1, T0 + ms(150), &removed) && removed.empty(),
              "recurring: a positive return reschedules it");
        check(!sorted[0]->in_flight, "recurring: rescheduled -> no longer in flight");
        check(tick(sorted, T0 + ms(200)).launched.empty(),
              "recurring: not launched before its NEW trigger");
        check(tick(sorted, T0 + ms(1150)).launched == std::vector<int>{3},
              "recurring: launched again at its new trigger");
    }

    /* 4. A recurring timer that returns 0 asked to stop: removed, and held. */
    {
        std::vector<timer_ptr> sorted = { recurring(4, T0, 10) };
        std::vector<int> removed;
        tick(sorted, T0);
        check(!finish(sorted[0], 0, T0 + ms(10), &removed) &&
              removed == std::vector<int>{4} && sorted[0]->in_flight,
              "recurring returning 0 -> removed and held in flight");
        check(tick(sorted, T0 + ms(20)).launched.empty(), "...and never relaunched");
    }

    /* 5. A cancelled timer goes to the removal list and is never launched, even
     * if it is due -- upstream's behaviour, unchanged. */
    {
        std::vector<timer_ptr> sorted = { one_shot(5, T0) };
        sorted[0]->timer_cancelled = true;
        auto r = tick(sorted, T0 + ms(1));
        check(r.launched.empty() && r.cancelled == std::vector<int>{5},
              "cancelled -> on_cancelled, not launched");
    }

    /* 6. The walk still stops at the first timer that is not due (the list is in
     * trigger order) -- unchanged. */
    {
        std::vector<timer_ptr> sorted = { one_shot(6, T0 + ms(500)), one_shot(8, T0) };
        check(tick(sorted, T0 + ms(1)).launched.empty(),
              "a not-yet-due timer stops the walk");
    }

    /* 7. A timer in flight must NOT stop the walk: the due timers behind it
     * still launch. A `break` here would starve every timer queued behind a slow
     * callback. */
    {
        std::vector<timer_ptr> sorted = { one_shot(9, T0), one_shot(10, T0 + ms(1)) };
        tick(sorted, T0);                       // launches 9 only (10 not due yet)
        auto r = tick(sorted, T0 + ms(2));      // 9 still running
        check(r.launched == std::vector<int>{10},
              "an in-flight timer is skipped, and the due timer behind it launches");
    }

    /* 8. The race the claim closes: a recurring callback returns BETWEEN the due
     * check and the claim, moving the trigger and clearing in_flight. The claim
     * then succeeds -- but the timer is no longer due, so it must not launch and
     * must not be left marked in flight. */
    {
        auto rt = std::make_shared<racy_timer>();
        rt->timer_id = 11;
        rt->trigger_tm.tp = T0;
        rt->in_flight = true;                   // running from an earlier tick
        rt->trigger_tm.on_first_read = [rt]() {
            rt->trigger_tm.tp = T0 + std::chrono::seconds(1);   // its next trigger
            rt->in_flight = false;                              // finish() cleared it
        };
        std::vector<std::shared_ptr<racy_timer>> sorted = { rt };
        auto r = tick(sorted, T0 + ms(1));
        check(rt->trigger_tm.reads >= 2,
              "race: the trigger was read again after the claim (the re-check ran)");
        check(r.launched.empty(),
              "race: a timer whose callback returned between check and claim is not relaunched");
        check(!rt->in_flight, "race: ...and is not left marked in flight");
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nPASS: all timetracker dispatch tests\n");
    return 0;
}
